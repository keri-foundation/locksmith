"""Dependency-contract guard for packages that Keripy pins exactly.

Locksmith consumes ``keri`` directly from the WebOfTrust/keripy main branch, so
Keripy is the authority for the concrete version of every package Keripy pins
exactly. If Locksmith independently exact-pins one of those packages at a
different version, the combined requirement set is unsatisfiable and
installation fails before a single test can run.

That is what happened with falcon: Locksmith tracked Keripy main while pinning
``falcon==4.2.0``, and Keripy moved to ``falcon==4.3.1``, so ``pip install -e .``
aborted with a resolution error on every platform.

These tests are hermetic. They read only this repository's ``pyproject.toml``
using the standard library, and they never resolve, install, or import project
dependencies.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT_PATH = Path(__file__).resolve().parents[1] / "pyproject.toml"

KERIPY_GIT_URL = "git+https://github.com/WebOfTrust/keripy.git"

# A compatible floor is fine; an independent exact pin is not. Keripy decides
# the concrete falcon version that must actually be installed.
FALCON_FLOOR = (4, 2, 0)

_SPECIFIER_DELIMITERS = "[<>=!~@ \t;"


def _split_requirement(requirement: str) -> tuple[str, str]:
    """Split a requirement into its normalized project name and specifier."""
    for index, character in enumerate(requirement):
        if character in _SPECIFIER_DELIMITERS:
            return requirement[:index].strip().lower(), requirement[index:].strip()
    return requirement.strip().lower(), ""


def _numeric_version(specifier: str) -> tuple[int, ...]:
    """Extract the leading numeric version from a specifier such as ``>=4.2.0``."""
    digits = ""
    for character in specifier:
        if character.isdigit() or character == ".":
            digits += character
        elif digits:
            break
    parts = [part for part in digits.strip(".").split(".") if part.isdigit()]
    return tuple(int(part) for part in parts)


def project_dependencies() -> list[str]:
    """Return the declared runtime dependencies from this repository metadata."""
    with PYPROJECT_PATH.open("rb") as pyproject:
        return list(tomllib.load(pyproject)["project"]["dependencies"])


def keripy_requirements(dependencies: list[str]) -> list[str]:
    """Return the requirements that reference the Keripy project."""
    return [requirement for requirement in dependencies if "keripy" in requirement]


def falcon_specifiers(dependencies: list[str]) -> list[str]:
    """Return the version specifiers bound to the falcon distribution."""
    return [
        specifier
        for name, specifier in map(_split_requirement, dependencies)
        if name == "falcon"
    ]


def falcon_contract_violations(dependencies: list[str]) -> list[str]:
    """Return the reasons a dependency set violates the falcon contract.

    The contract has two halves: Keripy must be tracked from its git main branch
    without a revision pin, and falcon must not be independently exact-pinned
    while that is true.
    """
    violations: list[str] = []

    keripy = keripy_requirements(dependencies)
    if len(keripy) != 1:
        violations.append(
            f"expected exactly one keripy requirement, found {len(keripy)}"
        )
    elif not keripy[0].rstrip().endswith(KERIPY_GIT_URL):
        violations.append(
            "keripy requirement must track "
            f"{KERIPY_GIT_URL} without a revision pin, found {keripy[0]!r}"
        )

    falcon = falcon_specifiers(dependencies)
    if len(falcon) != 1:
        violations.append(
            f"expected exactly one falcon requirement, found {len(falcon)}"
        )
    else:
        specifier = falcon[0]
        if specifier.startswith("=="):
            violations.append(
                "falcon must not be exact-pinned while keripy is tracked from "
                f"main, found {specifier!r}"
            )
        elif not specifier.startswith(">="):
            violations.append(
                f"falcon must be expressed as a lower bound, found {specifier!r}"
            )
        elif _numeric_version(specifier) < FALCON_FLOOR:
            violations.append(
                f"falcon lower bound must be at least {'.'.join(map(str, FALCON_FLOOR))}, "
                f"found {specifier!r}"
            )

    return violations


def test_project_tracks_keripy_from_git_without_a_revision_pin() -> None:
    """Keripy is followed from main, so it stays the version authority."""
    keripy = keripy_requirements(project_dependencies())
    assert len(keripy) == 1, f"expected exactly one keripy requirement, found {keripy}"
    assert keripy[0].rstrip().endswith(KERIPY_GIT_URL)


def test_falcon_requirement_is_not_exact_pinned_while_tracking_keripy_main() -> None:
    """A second exact falcon pin would reproduce the resolution failure."""
    specifiers = falcon_specifiers(project_dependencies())
    assert len(specifiers) == 1, f"expected one falcon pin, found {specifiers}"
    assert not specifiers[0].startswith("=="), (
        "falcon must not be exact-pinned while keripy is tracked from main, "
        f"found {specifiers[0]!r}"
    )
    assert specifiers[0].startswith(
        ">="
    ), f"falcon must be expressed as a lower bound, found {specifiers[0]!r}"
    assert _numeric_version(specifiers[0]) >= FALCON_FLOOR


def test_project_metadata_satisfies_the_falcon_contract() -> None:
    """The shipped metadata must satisfy the contract end to end."""
    assert falcon_contract_violations(project_dependencies()) == []


def test_contract_rejects_the_regression_that_broke_the_install() -> None:
    """Negative control: the historical ``falcon==4.2.0`` form must be rejected."""
    broken = [
        requirement
        for requirement in project_dependencies()
        if _split_requirement(requirement)[0] != "falcon"
    ]
    broken.append("falcon==4.2.0")

    violations = falcon_contract_violations(broken)

    assert violations, "an independent exact falcon pin must be reported"
    assert any("exact-pinned" in violation for violation in violations), violations


def test_contract_rejects_a_revision_pinned_keripy() -> None:
    """Negative control: pinning keripy to a revision would break the premise."""
    revision_pinned = [
        requirement.replace(KERIPY_GIT_URL, f"{KERIPY_GIT_URL}@1.2.3")
        for requirement in project_dependencies()
    ]

    violations = falcon_contract_violations(revision_pinned)

    assert violations, "a revision-pinned keripy must be reported"
    assert any("revision pin" in violation for violation in violations), violations
