from __future__ import annotations

from functools import lru_cache

from tree_sitter import Language, Parser


@lru_cache(maxsize=1)
def js_language() -> Language:
    import tree_sitter_javascript as tsjs

    return Language(tsjs.language())


@lru_cache(maxsize=1)
def php_language() -> Language:
    import tree_sitter_php as tsphp

    return Language(tsphp.language_php())


@lru_cache(maxsize=1)
def php_only_language() -> Language:
    import tree_sitter_php as tsphp

    return Language(tsphp.language_php_only())


def make_parser(language: Language) -> Parser:
    return Parser(language)


def parse_js(source: str):
    parser = make_parser(js_language())
    return parser.parse(source.encode("utf-8"))


def parse_php(source: str):
    lang = php_language() if "<?" in source[:200] or source.lstrip().startswith("<?") else php_only_language()
    parser = make_parser(lang)
    return parser.parse(source.encode("utf-8"))
