"""Language-agnostic codecs. Never executes JS or PHP."""

from __future__ import annotations

import base64
import codecs
import gzip
import html
import re
import zlib

_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")


def b64decode(text: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return None
    pad = (-len(cleaned)) % 4
    cleaned += "=" * pad
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(cleaned)
        except Exception:
            continue
    return None


def hex_decode(text: str) -> bytes | None:
    cleaned = re.sub(r"[\s:]", "", text)
    if len(cleaned) < 2 or len(cleaned) % 2 or not _HEX_RE.match(cleaned):
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def gzip_bytes(data: bytes) -> bytes | None:
    try:
        return gzip.decompress(data)
    except Exception:
        return None


def zlib_bytes(data: bytes) -> bytes | None:
    try:
        return zlib.decompress(data)
    except zlib.error:
        return None


def raw_inflate(data: bytes) -> bytes | None:
    try:
        return zlib.decompress(data, -15)
    except zlib.error:
        return None


def gzip_zlib_or_inflate(data: bytes) -> bytes | None:
    for fn in (gzip_bytes, zlib_bytes, raw_inflate):
        out = fn(data)
        if out is not None:
            return out
    try:
        return zlib.decompress(data, 32 + zlib.MAX_WBITS)
    except zlib.error:
        return None


def bytes_to_text(data: bytes) -> str | None:
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def unescape_js_string_body(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        simple = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "v": "\v",
            "0": "\0",
            "\\": "\\",
            "'": "'",
            '"': '"',
            "/": "/",
        }
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
            continue
        if nxt == "x" and i + 3 < len(body):
            hexpart = body[i + 2 : i + 4]
            if re.fullmatch(r"[0-9a-fA-F]{2}", hexpart):
                out.append(chr(int(hexpart, 16)))
                i += 4
                continue
        if nxt == "u":
            if i + 2 < len(body) and body[i + 2] == "{":
                end = body.find("}", i + 3)
                if end != -1:
                    hexpart = body[i + 3 : end]
                    if re.fullmatch(r"[0-9a-fA-F]+", hexpart):
                        out.append(chr(int(hexpart, 16)))
                        i = end + 1
                        continue
            elif i + 5 < len(body):
                hexpart = body[i + 2 : i + 6]
                if re.fullmatch(r"[0-9a-fA-F]{4}", hexpart):
                    out.append(chr(int(hexpart, 16)))
                    i += 6
                    continue
        if nxt in "01234567":
            j = i + 1
            while j < len(body) and j < i + 4 and body[j] in "01234567":
                j += 1
            out.append(chr(int(body[i + 1 : j], 8)))
            i = j
            continue
        out.append(nxt)
        i += 2
    return "".join(out)


def parse_quoted_string(literal: str) -> str | None:
    if len(literal) < 2:
        return None
    quote = literal[0]
    if quote not in "'\"" or literal[-1] != quote:
        return None
    body = literal[1:-1]
    if quote == "'":
        return body.replace("\\'", "'").replace("\\\\", "\\")
    return unescape_js_string_body(body)


def unescape_html_entities(text: str) -> str:
    if "&#" not in text and "&" not in text:
        return text
    return html.unescape(text)


def percent_decode(text: str) -> str | None:
    try:
        return _percent_decode(text)
    except Exception:
        return None


def _percent_decode(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "%" and i + 2 < len(text) and re.fullmatch(r"[0-9a-fA-F]{2}", text[i + 1 : i + 3]):
            out.append(chr(int(text[i + 1 : i + 3], 16)))
            i += 3
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def js_quote(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def php_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def format_js_number(value: float | int) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def format_php_number(value: float | int) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
