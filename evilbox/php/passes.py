from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from evilbox.decode import (
    b64decode,
    bytes_to_text,
    format_php_number,
    gzip_bytes,
    hex_decode,
    parse_quoted_string,
    php_quote,
    raw_inflate,
    rc4_crypt,
    rot13,
    unescape_html_entities,
    xor_bytes,
    xor_strings,
    zlib_bytes,
)
from evilbox.parsers import parse_php
from evilbox.rewrite import apply_replacements, node_text, walk

PHP_JUNK_RE = re.compile(r"^_0x[0-9a-fA-F]+$")
PHP_HEX_VAR_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)

PHP_SUPERGLOBALS = {
    "this",
    "GLOBALS",
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_SERVER",
    "_FILES",
    "_ENV",
    "_SESSION",
}


@dataclass
class Value:
    py: Any
    splice_raw: bool = False


def transform_php(source: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    tree = parse_php(source)
    env = collect_const_arrays(tree, source)
    replacements: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        rendered = _render_if_simplified(node, source, env)
        if rendered is None:
            continue
        original = node_text(source, node)
        if rendered != original:
            replacements.append((node.start_byte, node.end_byte, rendered))
    text = apply_replacements(source, replacements)
    text = _rename_junk(text)
    return text, warnings


def collect_const_arrays(tree, source: str) -> dict[str, list[Value]]:
    env: dict[str, list[Value]] = {}
    for node in walk(tree.root_node):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        if left.type != "variable_name" or right.type != "array_creation_expression":
            continue
        elems: list[Value] = []
        ok = True
        for el in right.named_children:
            if el.type != "array_element_initializer":
                continue
            inner = el.named_children[0] if el.named_children else el
            item = const_eval(inner, source, None)
            if item is None:
                ok = False
                break
            elems.append(item)
        if ok and elems:
            env[node_text(source, left).lstrip("$")] = elems
    return env


def _render_if_simplified(node, source: str, env: dict[str, list[Value]] | None = None) -> str | None:
    if node.type == "string":
        return _simplified_string(node, source)
    if node.type in {
        "unary_op_expression",
        "unary_expression",
        "binary_expression",
        "encapsed_string",
        "parenthesized_expression",
        "function_call_expression",
        "eval_expression",
        "subscript_expression",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }:
        val = const_eval(node, source, env)
        if val is None:
            return None
        text = _format_value(val)
        if val.splice_raw:
            text = _strip_php_tags(text)
        return text
    return None


def _strip_php_tags(code: str) -> str:
    stripped = code.strip()
    if stripped.startswith("<?php"):
        stripped = stripped[5:]
    elif stripped.startswith("<?="):
        stripped = "echo " + stripped[3:]
    elif stripped.startswith("<?"):
        stripped = stripped[2:]
    if stripped.endswith("?>"):
        stripped = stripped[:-2]
    return stripped.strip()


def _simplified_string(node, source: str) -> str | None:
    raw = node_text(source, node)
    parsed = _php_string_value(node, source)
    if parsed is None:
        return None
    unescaped = unescape_html_entities(parsed)
    quoted = php_quote(unescaped)
    if quoted == raw:
        return None
    if unescaped == parsed and "\\" not in raw and "&#" not in raw:
        return None
    return quoted


def _php_string_value(node, source: str) -> str | None:
    raw = node_text(source, node)
    if raw.startswith("b'") or raw.startswith('b"'):
        raw = raw[1:]
    parsed = parse_quoted_string(raw)
    if parsed is not None:
        if raw.startswith('"'):
            return parsed
        return parsed
    contents = []
    for child in node.children:
        if child.type in {"string_content", "encapsed_string_content"}:
            contents.append(node_text(source, child))
    if contents:
        return "".join(contents)
    return None


def _format_value(val: Value) -> str:
    if val.splice_raw and isinstance(val.py, str):
        return val.py
    if isinstance(val.py, bytes):
        text = bytes_to_text(val.py)
        if text is None:
            return php_quote(val.py.decode("latin-1"))
        return php_quote(text)
    if isinstance(val.py, str):
        return php_quote(val.py)
    if isinstance(val.py, bool):
        return "true" if val.py else "false"
    if val.py is None:
        return "null"
    if isinstance(val.py, (int, float)):
        return format_php_number(val.py)
    return php_quote(str(val.py))


def const_eval(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    t = node.type
    if t == "string":
        parsed = _php_string_value(node, source)
        if parsed is None:
            return None
        return Value(unescape_html_entities(parsed))
    if t in {"integer", "float"}:
        return _parse_php_number(node_text(source, node))
    if t == "name" and node_text(source, node).lower() in {"true", "false", "null"}:
        word = node_text(source, node).lower()
        if word == "true":
            return Value(True)
        if word == "false":
            return Value(False)
        return Value(None)
    if t == "boolean":
        return Value(node_text(source, node).lower() == "true")
    if t == "null":
        return Value(None)
    if t == "parenthesized_expression":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t in {"unary_op_expression", "unary_expression"}:
        return _eval_unary(node, source, env)
    if t == "binary_expression":
        return _eval_binary(node, source, env)
    if t == "encapsed_string":
        parts: list[str] = []
        for child in node.named_children:
            if child.type in {"string_content", "encapsed_string_content"}:
                parts.append(node_text(source, child))
            else:
                val = const_eval(child, source, env)
                if val is None or not isinstance(val.py, (str, int, float)) or isinstance(val.py, bool):
                    if val is not None and isinstance(val.py, str):
                        parts.append(val.py)
                    else:
                        return None
                else:
                    parts.append(str(val.py))
        if parts:
            return Value("".join(parts))
        raw = node_text(source, node)
        parsed = parse_quoted_string(raw)
        return Value(parsed) if parsed is not None else None
    if t == "argument":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t == "function_call_expression":
        return _eval_call(node, source, env)
    if t == "eval_expression":
        return _eval_eval(node, source, env)
    if t == "subscript_expression":
        return _eval_subscript(node, source, env)
    if t in {
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }:
        return _eval_include(node, source, env)
    return None


def _parse_php_number(text: str) -> Value | None:
    text = text.replace("_", "").strip()
    try:
        if text.lower().startswith("0x"):
            return Value(int(text, 16))
        if "." in text or "e" in text.lower():
            return Value(float(text))
        if text.startswith("0") and len(text) > 1 and text[1] not in "xX.":
            try:
                return Value(int(text, 8))
            except ValueError:
                pass
        return Value(int(text, 10))
    except ValueError:
        try:
            return Value(float(text))
        except ValueError:
            return None


def _eval_unary(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    op = None
    arg = None
    for child in node.children:
        if not child.is_named and child.type in {"!", "+", "-"}:
            op = child.type
        elif child.is_named:
            arg = child
    if arg is None and node.named_children:
        arg = node.named_children[0]
        text = node_text(source, node).strip()
        if text.startswith("!"):
            op = "!"
        elif text.startswith("-"):
            op = "-"
        elif text.startswith("+"):
            op = "+"
    if arg is None or op is None:
        return None
    val = const_eval(arg, source, env)
    if val is None:
        return None
    if op == "!":
        return Value(not bool(val.py))
    if op in {"+", "-"} and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(val.py if op == "+" else -val.py)
    return None


def _eval_binary(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    op_node = node.child_by_field_name("operator")
    op = op_node.type if op_node is not None else None
    if op is None:
        for child in node.children:
            if not child.is_named:
                op = child.type
                break
    if left is None or right is None or op is None:
        return None
    lv = const_eval(left, source, env)
    rv = const_eval(right, source, env)
    if lv is None or rv is None:
        return None
    if op == "^" and isinstance(lv.py, str) and isinstance(rv.py, str):
        return Value(xor_strings(lv.py, rv.py))
    if op == "^" and _is_num(lv.py) and _is_num(rv.py):
        return Value(int(lv.py) ^ int(rv.py))
    if op == ".":
        return Value(_as_php_string(lv.py) + _as_php_string(rv.py))
    if op in {"+", "-", "*", "/", "%"} and _is_num(lv.py) and _is_num(rv.py):
        try:
            if op == "+":
                return Value(lv.py + rv.py)
            if op == "-":
                return Value(lv.py - rv.py)
            if op == "*":
                return Value(lv.py * rv.py)
            if op == "/":
                if rv.py == 0:
                    return None
                result = lv.py / rv.py
                if isinstance(lv.py, int) and isinstance(rv.py, int) and lv.py % rv.py == 0:
                    return Value(lv.py // rv.py)
                return Value(result)
            if op == "%":
                return Value(lv.py % rv.py)
        except Exception:
            return None
    return None


def _as_php_string(value: Any) -> str:
    if isinstance(value, bytes):
        return bytes_to_text(value) or value.decode("latin-1")
    if value is True:
        return "1"
    if value is False or value is None:
        return ""
    return str(value)


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _call_name(node, source: str) -> str | None:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return None
    return node_text(source, fn).lstrip("\\").lower()


def _call_args(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        for child in node.children:
            if child.type in {"arguments", "argument_list"}:
                args = child
                break
    if args is None:
        return []
    out = []
    for child in args.named_children:
        if child.type == "argument" and child.named_children:
            out.append(child.named_children[0])
        else:
            out.append(child)
    return out


def _eval_call(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    name = _call_name(node, source)
    if not name:
        return None
    args = _call_args(node)
    values: list[Value] = []
    for arg in args:
        val = const_eval(arg, source, env)
        if val is None:
            return None
        values.append(val)

    def as_bytes(val: Value) -> bytes | None:
        if isinstance(val.py, bytes):
            return val.py
        if isinstance(val.py, str):
            return val.py.encode("latin-1", errors="replace")
        return None

    def as_str(val: Value) -> str | None:
        if isinstance(val.py, str):
            return val.py
        if isinstance(val.py, bytes):
            return bytes_to_text(val.py) or val.py.decode("latin-1")
        return None

    if name == "base64_decode" and values:
        raw = as_str(values[0])
        if raw is None:
            return None
        data = b64decode(raw)
        return Value(data) if data is not None else None

    if name == "gzinflate" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = raw_inflate(data)
        return Value(out) if out is not None else None

    if name == "gzuncompress" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = zlib_bytes(data)
        return Value(out) if out is not None else None

    if name == "gzdecode" and values:
        data = as_bytes(values[0])
        if data is None:
            return None
        out = gzip_bytes(data)
        return Value(out) if out is not None else None

    if name == "str_rot13" and values:
        s = as_str(values[0])
        return Value(rot13(s)) if s is not None else None

    if name == "hex2bin" and values:
        s = as_str(values[0])
        if s is None:
            return None
        data = hex_decode(s)
        return Value(data) if data is not None else None

    if name == "pack" and len(values) >= 2:
        fmt = as_str(values[0])
        payload = as_str(values[1])
        if fmt is None or payload is None:
            return None
        if fmt.replace("'", "") in {"H*", "H"}:
            data = hex_decode(payload)
            return Value(data) if data is not None else None

    if name == "chr" and values and _is_num(values[0].py):
        return Value(chr(int(values[0].py) & 0xFF))

    if name == "strtr" and len(values) >= 3:
        hay = as_str(values[0])
        frm = as_str(values[1])
        to = as_str(values[2])
        if hay is None or frm is None or to is None:
            return None
        table = str.maketrans(frm[: len(to)], to[: len(frm)])
        return Value(hay.translate(table))

    if name == "str_repeat" and len(values) >= 2:
        s = as_str(values[0])
        if s is None or not _is_num(values[1].py):
            return None
        n = int(values[1].py)
        if n < 0 or n > 1_000_000 or len(s) * n > 2_000_000:
            return None
        return Value(s * n)

    if name in {"xor", "str_xor"} and len(values) >= 2:
        data = as_bytes(values[0])
        key = as_bytes(values[1])
        if data is None or key is None:
            return None
        out = xor_bytes(data, key)
        return Value(out) if out is not None else None

    if name in {"rc4", "rc4crypt"} and len(values) >= 2:
        data = as_bytes(values[0])
        key = as_bytes(values[1])
        if data is None or key is None:
            return None
        out = rc4_crypt(data, key)
        return Value(out) if out is not None else None

    if name in {"eval", "assert"} and values:
        s = as_str(values[0])
        if s is None:
            return None
        return Value(s, splice_raw=True)

    if name == "create_function" and len(values) >= 2:
        body = as_str(values[1])
        if body is None:
            return None
        return Value(body, splice_raw=True)

    if name == "preg_replace" and len(values) >= 2:
        pattern = as_str(values[0])
        replacement = as_str(values[1])
        if pattern and replacement and _preg_eval_modifier(pattern):
            return Value(replacement, splice_raw=True)

    return None


def _preg_eval_modifier(pattern: str) -> bool:
    if len(pattern) < 3:
        return False
    delim = pattern[0]
    end = pattern.rfind(delim)
    if end <= 0:
        return False
    return "e" in pattern[end + 1 :].lower()


def _looks_like_php_source(text: str) -> bool:
    sample = text.lstrip()
    if sample.startswith("<?"):
        return True
    lowered = text.lower()
    return any(token in lowered for token in ("$_get", "$_post", "$_cookie", "eval(", "function ", "system("))


def _eval_include(node, source: str, env: dict[str, list[Value]] | None) -> Value | None:
    inner = node.named_children[0] if node.named_children else None
    if inner is None:
        return None
    val = const_eval(inner, source, env)
    if val is None:
        return None
    text = val.py
    if isinstance(text, bytes):
        text = bytes_to_text(text) or text.decode("latin-1")
    if not isinstance(text, str) or not _looks_like_php_source(text):
        return None
    return Value(text, splice_raw=True)


def _eval_subscript(node, source: str, env: dict[str, list[Value]] | None) -> Value | None:
    named = node.named_children
    if len(named) < 2:
        return None
    obj, index = named[0], named[1]
    idx_val = const_eval(index, source, env)
    if idx_val is None or not _is_num(idx_val.py):
        return None
    idx = int(idx_val.py)
    elems = None
    if obj.type == "variable_name" and env is not None:
        elems = env.get(node_text(source, obj).lstrip("$"))
    elif obj.type == "array_creation_expression":
        elems = []
        for el in obj.named_children:
            if el.type != "array_element_initializer":
                continue
            inner = el.named_children[0] if el.named_children else el
            item = const_eval(inner, source, env)
            if item is None:
                return None
            elems.append(item)
    if elems is None or idx < 0 or idx >= len(elems):
        return None
    return elems[idx]


def _eval_eval(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    inner = node.named_children[0] if node.named_children else None
    if inner is None:
        return None
    val = const_eval(inner, source, env)
    if val is None:
        return None
    if isinstance(val.py, bytes):
        text = bytes_to_text(val.py)
        if text is None:
            return None
        return Value(text, splice_raw=True)
    if isinstance(val.py, str):
        return Value(val.py, splice_raw=True)
    return None


def _rename_junk(source: str) -> str:
    tree = parse_php(source)
    mapping: dict[str, str] = {}
    order = 0
    replacements: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        if node.type != "variable_name":
            continue
        raw = node_text(source, node)
        name = raw[1:] if raw.startswith("$") else raw
        if name in PHP_SUPERGLOBALS:
            continue
        if not (PHP_JUNK_RE.match(name) or PHP_HEX_VAR_RE.match(name)):
            continue
        if name not in mapping:
            mapping[name] = f"v{order}"
            order += 1
        replacements.append((node.start_byte, node.end_byte, "$" + mapping[name]))
    return apply_replacements(source, replacements)
