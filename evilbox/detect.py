from __future__ import annotations

from pathlib import Path

JS_EXTS = {".js", ".mjs", ".cjs"}
PHP_EXTS = {".php", ".phtml", ".php5", ".php7", ".phps"}


def detect_language(source: str, path: str | None = None, lang: str = "auto") -> str:
    if lang in {"js", "php"}:
        return lang
    if path and path not in {"-", ""}:
        ext = Path(path).suffix.lower()
        if ext in JS_EXTS:
            return "js"
        if ext in PHP_EXTS:
            return "php"
    stripped = source.lstrip()
    if stripped.startswith("<?php") or stripped.startswith("<?=") or stripped.startswith("<? "):
        return "php"
    if "<?php" in source[:400]:
        return "php"
    sample = source[:800]
    if "$" in sample and ("function " in sample or "->" in sample or "=>" in sample):
        if "var " not in sample and "const " not in sample and "let " not in sample:
            return "php"
    return "js"
