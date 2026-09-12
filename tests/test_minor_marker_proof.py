"""Minor-invariant full-version markers are proofs, not invented patch values."""

from types import SimpleNamespace

import pytest
from packaging.markers import Marker
from packaging.version import Version
from test_generation import _plan

from python_deployment_builder.generation.acquisition import PreparationError
from python_deployment_builder.generation.artifacts import (
    _direct_dependency_presence_proven,
    validate_application_requires_dist,
    validate_approved_requires_dist,
)
from python_deployment_builder.planning.index import (
    TargetMarkerApplicability as State,
)
from python_deployment_builder.planning.index import (
    target_marker_applicability,
    target_marker_environment,
)
from python_deployment_builder.planning.lockfile import inspect_uv_lock


def test_minor_boundary_is_provable_but_patch_boundary_is_not():
    assert (
        target_marker_applicability("python_full_version >= '3.12.1'", "3.12", "x86_64")
        == State.UNPROVABLE
    )
    assert (
        target_marker_applicability("python_full_version >= '3.12'", "3.12", "x86_64")
        == State.APPLIES
    )


def test_sgg_numpy_root_edge_presence():
    graph = SimpleNamespace(
        selected_extras=[],
        edges=[
            SimpleNamespace(
                from_package="simple-georef-gui",
                to_package="numpy",
                selected_extra=None,
                marker=f"python_full_version {condition}",
            )
            for condition in ["< '3.11'", "== '3.11.*'", ">= '3.12'"]
        ],
    )
    _direct_dependency_presence_proven(graph, _plan(), "simple-georef-gui", "numpy")


@pytest.mark.parametrize(
    ("comparison", "expected"),
    [
        (">= '3.12'", State.APPLIES),
        ("< '3.13'", State.APPLIES),
        ("== '3.12.*'", State.APPLIES),
        ("!= '3.11.*'", State.APPLIES),
        ("< '3.12'", State.DOES_NOT_APPLY),
        (">= '3.13'", State.DOES_NOT_APPLY),
        ("== '3.11.*'", State.DOES_NOT_APPLY),
        ("!= '3.12.*'", State.DOES_NOT_APPLY),
        (">= '3.12.1'", State.UNPROVABLE),
        ("< '3.12.1'", State.UNPROVABLE),
        ("< '3.12.5'", State.UNPROVABLE),
        ("== '3.12.0'", State.UNPROVABLE),
        ("!= '3.12.0'", State.UNPROVABLE),
        ("> '3.11'", State.APPLIES),
        ("<= '3.13'", State.APPLIES),
        ("> '3.13'", State.DOES_NOT_APPLY),
        ("<= '3.11'", State.DOES_NOT_APPLY),
        ("> '3.12'", State.UNPROVABLE),
        ("<= '3.12'", State.UNPROVABLE),
        ("== '3.11.9'", State.DOES_NOT_APPLY),
        ("!= '3.11.9'", State.APPLIES),
        ("== '3.13.0'", State.DOES_NOT_APPLY),
        ("== '3.*'", State.APPLIES),
        ("== '03.012.*'", State.APPLIES),
        ("== '3.12.0.*'", State.UNPROVABLE),
        ("!= '3.12.0.*'", State.UNPROVABLE),
        ("in '3.12'", State.UNPROVABLE),
        ("not in '3.11'", State.UNPROVABLE),
        ("~= '3.12'", State.UNPROVABLE),
        ("=== '3.12.0'", State.UNPROVABLE),
        (">= '3.12rc1'", State.UNPROVABLE),
        ("== 'nonsense'", State.UNPROVABLE),
    ],
)
def test_atomic_full_version_matrix(comparison, expected):
    assert (
        target_marker_applicability(f"python_full_version {comparison}", "3.12", "x86_64")
        == expected
    )


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ('"3.12" <= python_full_version', State.APPLIES),
        ('"3.13" > python_full_version', State.APPLIES),
        ('"3.12" > python_full_version', State.DOES_NOT_APPLY),
        ('"3.13" <= python_full_version', State.DOES_NOT_APPLY),
        ('"3.12.1" <= python_full_version', State.UNPROVABLE),
        ('"3.12.0" == python_full_version', State.UNPROVABLE),
        ('"3.12.0" != python_full_version', State.UNPROVABLE),
        ('"3.12.*" == python_full_version', State.UNPROVABLE),
    ],
)
def test_packaging_right_hand_variable(marker, expected):
    assert Marker(marker)._markers[0][2].value == "python_full_version"
    assert target_marker_applicability(marker, "3.12", "x86_64") == expected


@pytest.mark.parametrize("operator", ["and", "or"])
@pytest.mark.parametrize("left", list(State))
@pytest.mark.parametrize("right", list(State))
def test_all_tristate_boolean_combinations(operator, left, right):
    atoms = {
        State.APPLIES: "python_full_version >= '3.12'",
        State.DOES_NOT_APPLY: "sys_platform == 'linux'",
        State.UNPROVABLE: "python_full_version >= '3.12.1'",
    }
    pair = {left, right}
    if operator == "and":
        expected = (
            State.DOES_NOT_APPLY
            if State.DOES_NOT_APPLY in pair
            else State.APPLIES
            if pair == {State.APPLIES}
            else State.UNPROVABLE
        )
    else:
        expected = (
            State.APPLIES
            if State.APPLIES in pair
            else State.DOES_NOT_APPLY
            if pair == {State.DOES_NOT_APPLY}
            else State.UNPROVABLE
        )
    assert (
        target_marker_applicability(f"{atoms[left]} {operator} {atoms[right]}", "3.12", "x86_64")
        == expected
    )


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("python_full_version >= '3.12' and python_full_version < '3.13'", State.APPLIES),
        ("python_full_version >= '3.12' and sys_platform == 'win32'", State.APPLIES),
        ("python_full_version >= '3.12.1' or sys_platform == 'win32'", State.APPLIES),
        ("python_full_version >= '3.12.1' or sys_platform == 'linux'", State.UNPROVABLE),
        (
            "(python_full_version >= '3.12.1' or sys_platform == 'win32') "
            "and sys_platform == 'linux'",
            State.DOES_NOT_APPLY,
        ),
        (
            "python_full_version >= '3.12.1' or sys_platform == 'win32' "
            "and sys_platform == 'linux'",
            State.UNPROVABLE,
        ),
    ],
)
def test_grouping_and_platform_context(marker, expected):
    assert target_marker_applicability(marker, "3.12", "x86_64") == expected


@pytest.mark.parametrize(
    "field", ["platform_release", "platform_version", "implementation_version"]
)
def test_unselected_fields_remain_unknown(field):
    assert field not in target_marker_environment("3.12", "x86_64")
    marker = f"{field} >= '3.12'"
    assert target_marker_applicability(marker, "3.12", "x86_64") == State.UNPROVABLE
    assert (
        target_marker_applicability(marker + " and sys_platform == 'linux'", "3.12", "x86_64")
        == State.DOES_NOT_APPLY
    )
    assert (
        target_marker_applicability(marker + " or sys_platform == 'win32'", "3.12", "x86_64")
        == State.APPLIES
    )


def lock_plan(root, branches):
    edges = ",".join(
        f'{{name="helper", version="{version}", marker="python_full_version {condition}"}}'
        for version, condition in branches
    )
    packages = "\n".join(
        f'[[package]]\nname="helper"\nversion="{version}"\n'
        f'wheels=[{{url="https://example.invalid/helper-{version}-py3-none-any.whl"}}]'
        for version, _ in branches
    )
    (root / "uv.lock").write_text(
        'version=1\n[[package]]\nname="app"\nversion="1"\n'
        f'source={{virtual="."}}\ndependencies=[{edges}]\n{packages}\n',
        encoding="utf-8",
    )
    plan = _plan().model_copy(deep=True)
    plan.lock_graph = inspect_uv_lock(root, "app", "3.12", "x86_64", [])
    return plan


@pytest.mark.parametrize(
    "proof", [validate_application_requires_dist, validate_approved_requires_dist]
)
def test_invariant_lock_branches_prove_wheel_requirements(tmp_path, proof):
    plan = lock_plan(
        tmp_path, [("2.2.6", "< '3.11'"), ("2.4.6", "== '3.11.*'"), ("2.5.2", ">= '3.12'")]
    )
    assert [(d.name, d.version) for d in plan.lock_graph.dependencies] == [("helper", "2.5.2")]
    proof(["helper>=2.5", "helper>=2.5; python_full_version >= '3.12'"], plan, "app", Version("1"))
    with pytest.raises(PreparationError, match="target-possible"):
        proof(["helper<2.5"], plan, "app", Version("1"))


@pytest.mark.parametrize(
    "proof", [validate_application_requires_dist, validate_approved_requires_dist]
)
def test_patch_sensitive_forks_remain_possible_and_unproven(tmp_path, proof):
    plan = lock_plan(tmp_path, [("1", "< '3.12.5'"), ("2", ">= '3.12.5'")])
    assert {d.version for d in plan.lock_graph.dependencies} == {"1", "2"}
    with pytest.raises(PreparationError, match="definitely applicable"):
        proof(["helper>=1"], plan, "app", Version("1"))
    # Even a separate unconditional presence proof cannot bless a bad possible version.
    plan.lock_graph.edges[0].marker = None
    with pytest.raises(PreparationError, match="target-possible"):
        proof(["helper>=2"], plan, "app", Version("1"))


@pytest.mark.parametrize(
    "proof", [validate_application_requires_dist, validate_approved_requires_dist]
)
def test_patch_sensitive_wheel_requirement_marker_is_not_guessed(tmp_path, proof):
    plan = lock_plan(tmp_path, [("1", ">= '3.12'")])
    with pytest.raises(PreparationError, match="cannot be proven"):
        proof(["helper; python_full_version >= '3.12.1'"], plan, "app", Version("1"))


@pytest.mark.parametrize("minor", ["3.11", "3.12", "3.13", "3.14"])
def test_all_policy_minors_use_interval_proof_not_a_patch(minor):
    for marker in [f"python_full_version >= '{minor}'", f"python_full_version == '{minor}.*'"]:
        assert target_marker_applicability(marker, minor, "x86_64") == State.APPLIES
    for marker in [f"python_full_version >= '{minor}.1'", f"python_full_version == '{minor}.0'"]:
        assert target_marker_applicability(marker, minor, "x86_64") == State.UNPROVABLE


def test_sgg_pyproj_minor_boundary_graph(tmp_path):
    plan = lock_plan(tmp_path, [("3.7.1", "< '3.11'"), ("3.7.2", ">= '3.11'")])
    assert {d.version for d in plan.lock_graph.dependencies} == {"3.7.2"}
    validate_application_requires_dist(["helper==3.7.2"], plan, "app", Version("1"))
