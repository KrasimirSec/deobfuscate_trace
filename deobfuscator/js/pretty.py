from __future__ import annotations

import jsbeautifier


def pretty_js(source: str) -> str:
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.end_with_newline = True
    return jsbeautifier.beautify(source, opts)
