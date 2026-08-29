from __future__ import annotations

import re

_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("eval+base64", re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.I)),
    ("eval+gzinflate", re.compile(r"eval\s*\(\s*gzinflate\s*\(", re.I)),
    ("eval+gzuncompress", re.compile(r"eval\s*\(\s*gzuncompress\s*\(", re.I)),
    ("eval+gzdecode", re.compile(r"eval\s*\(\s*gzdecode\s*\(", re.I)),
    ("eval+str_rot13", re.compile(r"eval\s*\(\s*str_rot13\s*\(", re.I)),
    ("eval+atob", re.compile(r"eval\s*\(\s*atob\s*\(", re.I)),
    ("fromCharCode", re.compile(r"fromCharCode\s*\(")),
    ("preg_replace/e", re.compile(r"preg_replace\s*\([^;]{0,120}e['\"]\s*,", re.I)),
    ("create_function", re.compile(r"create_function\s*\(", re.I)),
    ("assert+decode", re.compile(r"assert\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)", re.I)),
    ("include+decode", re.compile(r"(?:include|require)(?:_once)?\s*\(\s*(?:base64_decode|gzinflate)", re.I)),
    ("pack-H*", re.compile(r"pack\s*\(\s*['\"]H\*", re.I)),
    ("string-xor", re.compile(r"""['"][^'"]{4,}['"]\s*\^\s*['"]""")),
    ("goto-labels", re.compile(r"\bgoto\s+\w+", re.I)),
)


def packer_hints(source: str) -> list[str]:
    found: list[str] = []
    for label, pattern in _HINTS:
        if pattern.search(source):
            found.append(label)
    return found
