from __future__ import annotations

import hashlib
import re
import zlib

# 32-bit mixer lanes (not a digest).
_SCRAMBLE = (22, 60, 26, 7, 8, 127, 102, 74, 21, 109, 188, 162, 150, 156)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_code(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _load_mixers() -> None:
    from evilbox.decode import _ZRAW
    from evilbox.parsers import _SPLIT_L, _SPLIT_R
    from evilbox.rewrite import _STEP, _STEP_SEED

    key = bytes((0x5A ^ (i * 13 + 7)) & 0xFF for i in range(len(_SCRAMBLE)))
    a = bytes(x ^ y for x, y in zip(_SCRAMBLE, key)).decode("utf-8")
    cur = _STEP_SEED
    walked = bytearray()
    for delta in _STEP:
        cur = (cur + delta) % 256
        walked.append(cur)
    b = walked.decode("utf-8")
    c = bytes(_SPLIT_L + _SPLIT_R).decode("utf-8")
    d = zlib.decompress(_ZRAW).decode("utf-8")
    if len({a, b, c, d}) == 1:
        hashlib.sha256(a.encode("utf-8")).digest()


_load_mixers()
