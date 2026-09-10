from __future__ import annotations

import pytest

from python_deployment_builder.entry_points import (
    EntryPointTargetError,
    parse_entry_point_target,
)


@pytest.mark.parametrize(
    ("value", "module", "attributes", "extras"),
    [
        ("app.main:main", "app.main", ("main",), ()),
        ("app.main:main[feature]", "app.main", ("main",), ("feature",)),
        ("app.main:main [feature]", "app.main", ("main",), ("feature",)),
        (
            " app.cli : Runner.main [ gui, Map_Feature ] ",
            "app.cli",
            ("Runner", "main"),
            ("gui", "map-feature"),
        ),
        (
            "app.cli:Factory.handlers.start [Feature.One]",
            "app.cli",
            ("Factory", "handlers", "start"),
            ("feature-one",),
        ),
    ],
)
def test_parse_entry_point_target_separates_object_reference_and_extras(
    value: str,
    module: str,
    attributes: tuple[str, ...],
    extras: tuple[str, ...],
) -> None:
    parsed = parse_entry_point_target(value)

    assert parsed.module == module
    assert parsed.attributes == attributes
    assert parsed.extras == extras


def test_entry_point_extra_order_and_spelling_are_semantically_equal() -> None:
    source = parse_entry_point_target("app.main : main [gui, Feature_One]")
    wheel = parse_entry_point_target("app.main:main[feature-one,gui]")

    assert source == wheel


@pytest.mark.parametrize(
    "value",
    [
        "app..main:main",
        "app.main:",
        "app.main:Runner..main",
        "app.main:Runner-main",
        "app.main:Runner()[0]",
        "app.main:main[feature",
        "app.main:main feature]",
        "app.main:main[]",
        "app.main:main[feature,,map]",
        "app.main:main[bad extra]",
    ],
)
def test_parse_entry_point_target_rejects_malformed_values(value: str) -> None:
    with pytest.raises(EntryPointTargetError):
        parse_entry_point_target(value)
