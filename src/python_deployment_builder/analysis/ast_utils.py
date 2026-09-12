"""Small bounded helpers for non-executing AST analysis."""

from __future__ import annotations

import ast


def call_argument(
    node: ast.Call,
    *,
    position: int,
    keyword: str,
) -> ast.AST | None:
    """Return one API argument without attempting general signature binding.

    The supported APIs use an equivalent positional-or-keyword form for this
    argument.  Positional syntax deliberately wins if a syntactically valid
    call supplies both forms: that call is runtime-invalid, and this bounded
    static analysis must neither invent a second value nor evaluate it.
    """

    if len(node.args) > position:
        return node.args[position]
    return next(
        (item.value for item in node.keywords if item.arg == keyword),
        None,
    )
