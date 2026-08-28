from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from deobfuscator.decode import (
    b64decode,
    bytes_to_text,
    format_js_number,
    js_quote,
    parse_quoted_string,
    percent_decode,
    unescape_html_entities,
    unescape_js_string_body,
)
from deobfuscator.parsers import parse_js
from deobfuscator.rewrite import apply_replacements, node_text, walk

JS_JUNK_RE = re.compile(r"^_0x[0-9a-fA-F]+$")
JS_HEX_NAME_RE = re.compile(r"^_?[a-f0-9]{6,}$", re.I)

JS_RESERVED = {
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "enum",
    "await",
    "arguments",
    "eval",
    "undefined",
    "NaN",
    "Infinity",
    "console",
    "window",
    "document",
    "String",
    "Number",
    "Array",
    "Object",
    "Math",
    "JSON",
    "Function",
    "Boolean",
    "RegExp",
    "Date",
    "Error",
    "parseInt",
    "parseFloat",
    "isNaN",
    "atob",
    "btoa",
    "unescape",
    "escape",
    "decodeURIComponent",
    "encodeURIComponent",
    "decodeURI",
    "encodeURI",
}


@dataclass
class Value:
    py: Any
    splice_raw: bool = False


def transform_js(source: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    tree = parse_js(source)
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
    """Map `var name = [literals...]` so later `name[i]` can be folded."""
    env: dict[str, list[Value]] = {}
    for node in walk(tree.root_node):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None or value.type != "array":
            continue
        elems: list[Value] = []
        ok = True
        for el in value.named_children:
            item = _array_element(el, source)
            if item is None:
                ok = False
                break
            elems.append(item)
        if ok and name_node.type == "identifier":
            env[node_text(source, name_node)] = elems
    return env


def _array_element(node, source: str) -> Value | None:
    if node.type == "identifier":
        return Value(node_text(source, node), splice_raw=True)
    if node.type == "spread_element":
        return None
    return const_eval(node, source, env=None)


def _render_if_simplified(node, source: str, env: dict[str, list[Value]] | None = None) -> str | None:
    if node.type in {"string", "string_fragment"}:
        if node.type == "string":
            return _simplified_string(node, source)
        return None
    if node.type in {
        "unary_expression",
        "binary_expression",
        "parenthesized_expression",
        "call_expression",
        "subscript_expression",
    }:
        val = const_eval(node, source, env)
        if val is None:
            return None
        if node.type == "unary_expression" and val.splice_raw:
            return None
        return _format_value(val)
    return None


def _simplified_string(node, source: str) -> str | None:
    raw = node_text(source, node)
    parsed = parse_quoted_string(raw)
    if parsed is None:
        return None
    unescaped = unescape_html_entities(parsed)
    quoted = js_quote(unescaped)
    if quoted == raw:
        return None
    # Only rewrite if we actually expanded escapes / entities
    if unescaped == parsed and "\\" not in raw and "&#" not in raw:
        return None
    return quoted


def _format_value(val: Value) -> str:
    if val.splice_raw and isinstance(val.py, str):
        return val.py
    if isinstance(val.py, str):
        return js_quote(val.py)
    if isinstance(val.py, bool):
        return "true" if val.py else "false"
    if val.py is None:
        return "null"
    if isinstance(val.py, (int, float)):
        return format_js_number(val.py)
    return js_quote(str(val.py))


def const_eval(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    t = node.type
    if t == "string":
        parsed = parse_quoted_string(node_text(source, node))
        if parsed is None:
            return None
        return Value(unescape_html_entities(parsed))
    if t == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        raw = node_text(source, node)
        if len(raw) >= 2 and raw[0] == "`" and raw[-1] == "`":
            return Value(unescape_js_string_body(raw[1:-1]))
        return None
    if t == "number":
        return _parse_js_number(node_text(source, node))
    if t == "true":
        return Value(True)
    if t == "false":
        return Value(False)
    if t == "null":
        return Value(None)
    if t == "identifier" and env is not None:
        return None
    if t == "parenthesized_expression":
        inner = node.named_children[0] if node.named_children else None
        return const_eval(inner, source, env) if inner is not None else None
    if t == "unary_expression":
        return _eval_unary(node, source, env)
    if t == "binary_expression":
        return _eval_binary(node, source, env)
    if t == "call_expression":
        return _eval_call(node, source, env)
    if t == "subscript_expression":
        return _eval_subscript(node, source, env)
    if t == "array":
        return None
    if t == "arguments":
        return None
    return None


def _eval_subscript(node, source: str, env: dict[str, list[Value]] | None) -> Value | None:
    obj = node.child_by_field_name("object")
    index = node.child_by_field_name("index")
    if obj is None or index is None:
        return None
    idx_val = const_eval(index, source, env)
    if idx_val is None or not isinstance(idx_val.py, int) or isinstance(idx_val.py, bool):
        return None
    idx = idx_val.py
    elems: list[Value] | None = None
    if obj.type == "array":
        elems = []
        for el in obj.named_children:
            item = _array_element(el, source)
            if item is None:
                return None
            elems.append(item)
    elif obj.type == "identifier" and env is not None:
        elems = env.get(node_text(source, obj))
    if elems is None or idx < 0 or idx >= len(elems):
        return None
    return elems[idx]


def _parse_js_number(text: str) -> Value | None:
    text = text.replace("_", "").strip()
    try:
        if text.lower().startswith("0x"):
            return Value(int(text, 16))
        if text.lower().startswith("0b"):
            return Value(int(text, 2))
        if text.lower().startswith("0o"):
            return Value(int(text, 8))
        if "." in text or "e" in text.lower():
            return Value(float(text))
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
        if not child.is_named and child.type in {"!", "+", "-", "~", "typeof", "void"}:
            op = child.type
        elif child.is_named:
            arg = child
    if op is None or arg is None:
        text = node_text(source, node).strip()
        if text.startswith("!") or text.startswith("+") or text.startswith("-"):
            op = text[0]
            if node.named_children:
                arg = node.named_children[0]
    if arg is None:
        return None
    val = const_eval(arg, source, env)
    if val is None:
        return None
    if op == "!":
        return Value(not bool(val.py))
    if op == "+" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(+val.py)
    if op == "-" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(-val.py)
    if op == "~" and isinstance(val.py, (int, float)) and not isinstance(val.py, bool):
        return Value(~int(val.py))
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
    if lv is None or rv is None or lv.splice_raw or rv.splice_raw:
        return None
    if op == "+" and isinstance(lv.py, str) and isinstance(rv.py, str):
        return Value(lv.py + rv.py)
    if op == "+" and _is_num(lv.py) and _is_num(rv.py):
        return Value(lv.py + rv.py)
    if op in {"-", "*", "/", "%"} and _is_num(lv.py) and _is_num(rv.py):
        try:
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


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not (isinstance(value, float) and math.isnan(value))


def _call_name(node, source: str) -> tuple[str | None, str | None]:
    fn = node.child_by_field_name("function")
    if fn is None and node.named_children:
        fn = node.named_children[0]
    if fn is None:
        return None, None
    if fn.type == "identifier":
        return node_text(source, fn), None
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        if obj is None or prop is None:
            return None, None
        return node_text(source, obj), node_text(source, prop)
    return None, None


def _call_args(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        for child in node.children:
            if child.type == "arguments":
                args = child
                break
    if args is None:
        return []
    return [c for c in args.named_children]


def _eval_call(node, source: str, env: dict[str, list[Value]] | None = None) -> Value | None:
    obj, prop = _call_name(node, source)
    args = _call_args(node)
    values: list[Value] = []
    for arg in args:
        val = const_eval(arg, source, env)
        if val is None:
            return None
        values.append(val)

    def str_arg(i: int = 0) -> str | None:
        if i >= len(values) or not isinstance(values[i].py, str):
            return None
        return values[i].py

    name = (prop or obj or "").lower() if obj else ""
    callee = (obj or "").lower()

    if obj == "eval" and prop is None:
        s = str_arg(0)
        if s is None:
            return None
        return Value(s, splice_raw=True)

    if obj == "atob" and prop is None:
        s = str_arg(0)
        if s is None:
            return None
        data = b64decode(s)
        if data is None:
            return None
        text = bytes_to_text(data)
        return Value(text) if text is not None else None

    if obj in {"unescape", "decodeURIComponent", "decodeURI"} and prop is None:
        s = str_arg(0)
        if s is None:
            return None
        decoded = percent_decode(s)
        return Value(decoded if decoded is not None else s)

    if (obj == "String" and prop == "fromCharCode") or (obj == "fromCharCode"):
        chars: list[str] = []
        for val in values:
            if not _is_num(val.py):
                return None
            chars.append(chr(int(val.py) & 0xFFFF))
        return Value("".join(chars))

    if callee == "string" and (prop or "") == "fromCharCode":
        chars = []
        for val in values:
            if not _is_num(val.py):
                return None
            chars.append(chr(int(val.py) & 0xFFFF))
        return Value("".join(chars))

    # eval(atob(...)) already handled by evaluating inner call then eval.
    # String.fromCharCode via computed member not supported.
    _ = name
    return None


def _rename_junk(source: str) -> str:
    tree = parse_js(source)
    mapping: dict[str, str] = {}
    order = 0
    replacements: list[tuple[int, int, str]] = []
    for node in walk(tree.root_node):
        if node.type not in {"identifier", "property_identifier", "shorthand_property_identifier"}:
            continue
        name = node_text(source, node)
        if name in JS_RESERVED:
            continue
        if not (JS_JUNK_RE.match(name) or (JS_HEX_NAME_RE.match(name) and name.lower().startswith("_0x"))):
            continue
        if name not in mapping:
            mapping[name] = f"v{order}"
            order += 1
        replacements.append((node.start_byte, node.end_byte, mapping[name]))
    return apply_replacements(source, replacements)
