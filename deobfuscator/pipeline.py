from __future__ import annotations

from dataclasses import dataclass

from deobfuscator.detect import detect_language
from deobfuscator.extract import Indicators, extract_indicators
from deobfuscator.js.passes import transform_js
from deobfuscator.js.pretty import pretty_js
from deobfuscator.parsers import parse_js, parse_php
from deobfuscator.php.passes import transform_php
from deobfuscator.php.pretty import pretty_php
from deobfuscator.rewrite import has_error


@dataclass
class Result:
    text: str
    language: str
    warnings: list[str]
    parse_ok: bool
    indicators: Indicators


def deobfuscate(source: str, *, language: str = "auto", path: str | None = None, max_passes: int = 8) -> Result:
    lang = detect_language(source, path=path, lang=language)
    warnings: list[str] = []
    text = source
    transform = transform_js if lang == "js" else transform_php
    parse = parse_js if lang == "js" else parse_php

    for _ in range(max(1, max_passes)):
        nxt, pass_warnings = transform(text)
        warnings.extend(pass_warnings)
        if nxt == text:
            break
        tree = parse(nxt)
        if has_error(tree.root_node):
            warnings.append("A pass produced unparseable code; keeping the previous version of that rewrite.")
            # keep nxt if original also had errors and nxt is longer/cleaner — still prefer last successful parse
            prev_tree = parse(text)
            if not has_error(prev_tree.root_node):
                break
        text = nxt

    pretty = pretty_js if lang == "js" else pretty_php
    text = pretty(text)
    tree = parse(text)
    parse_ok = not has_error(tree.root_node)
    if not parse_ok:
        warnings.append("Parse still reports errors after deobfuscation.")
    indicators = extract_indicators(text, source)
    return Result(
        text=text,
        language=lang,
        warnings=warnings,
        parse_ok=parse_ok,
        indicators=indicators,
    )
