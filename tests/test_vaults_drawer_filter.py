# -*- encoding: utf-8 -*-
"""
Focused regression tests for the vault drawer search filter (issue #68).

These tests drive the real ``VaultDrawer`` object rather than a re-implemented
helper, and they exercise the lifecycle the user actually performs: opening the
drawer with ``toggle()``, typing, closing it, and opening it again. An earlier
attempt cleared the filter in ``show_drawer_widgets()`` instead, which is the
navigation-level lifecycle method, so its tests stayed green while the product
behaviour stayed broken. These tests must fail if that mistake is reintroduced.

Item visibility is asserted with ``isHidden()`` rather than ``isVisible()``.
Offscreen Qt builds do not make ancestor widgets visible, so ``isVisible()`` is
misleading here while ``isHidden()`` reflects only explicit hide/show calls.
"""
from __future__ import annotations

import logging

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget

from locksmith.ui.vaults import drawer as drawer_module
from locksmith.ui.vaults.drawer import VaultDrawer


class _FakeConfig:
    """Minimal stand-in for the application config object."""

    def __init__(self) -> None:
        self.base = ""


class _FakeApp:
    """Minimal stand-in for ``LocksmithApplication``.

    ``environments()`` mirrors the real method's contract: it returns the vault
    names in a deterministic order, and callers must not rely on this test double
    sorting for them.
    """

    def __init__(self, vaults: list[str]) -> None:
        self._vaults = list(vaults)
        self.config = _FakeConfig()

    def environments(self) -> list[str]:
        return list(self._vaults)

    def set_vaults(self, vaults: list[str]) -> None:
        self._vaults = list(vaults)


class _FakeToolbar(QWidget):
    """Stand-in for the toolbar; the drawer only needs its height."""


class _FakeParent(QWidget):
    """Stand-in for the main window; the drawer needs ``app`` and a size."""

    def __init__(self, vaults: list[str]) -> None:
        super().__init__()
        self.app = _FakeApp(vaults)


@pytest.fixture
def make_drawer(qapp):
    """Build a real ``VaultDrawer`` on a fake parent, and clean it up after."""
    created: list[tuple[VaultDrawer, _FakeParent, _FakeToolbar]] = []

    def _make(vaults: list[str]) -> VaultDrawer:
        parent = _FakeParent(vaults)
        parent.resize(1200, 800)
        toolbar = _FakeToolbar(parent)
        toolbar.setFixedHeight(60)
        created.append((VaultDrawer(parent, toolbar), parent, toolbar))
        return created[-1][0]

    yield _make

    for drawer, parent, toolbar in created:
        drawer.deleteLater()
        toolbar.deleteLater()
        parent.deleteLater()
    qapp.processEvents()


@pytest.fixture
def log_records():
    """Capture everything the drawer module logs, at DEBUG and above."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector(level=logging.DEBUG)
    previous_level = drawer_module.logger.level
    drawer_module.logger.addHandler(handler)
    drawer_module.logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        drawer_module.logger.removeHandler(handler)
        drawer_module.logger.setLevel(previous_level)


def _visible_names(drawer: VaultDrawer) -> list[str]:
    return [
        drawer.vault_list.item(position).text()
        for position in range(drawer.vault_list.count())
        if not drawer.vault_list.item(position).isHidden()
    ]


def _hidden_map(drawer: VaultDrawer) -> dict[str, bool]:
    return {
        drawer.vault_list.item(position).text(): drawer.vault_list.item(position).isHidden()
        for position in range(drawer.vault_list.count())
    }


def _info_messages(records: list[logging.LogRecord]) -> list[str]:
    return [record.getMessage() for record in records if record.levelno == logging.INFO]


# ---------------------------------------------------------------------------
# A - search field contract
# ---------------------------------------------------------------------------


def test_search_field_contract(make_drawer):
    drawer = make_drawer(["alpha"])

    assert drawer.search_field is not None
    assert drawer.search_field.isClearButtonEnabled() is True
    assert drawer.search_field.placeholderText() == "Search vaults"
    assert (
        getattr(drawer.search_field, "_leading_icon", None)
        == ":/assets/material-icons/search.svg"
    )


# ---------------------------------------------------------------------------
# B - inactive behaviour preserves the baseline order
# ---------------------------------------------------------------------------


def test_inactive_filter_shows_all_in_baseline_order(make_drawer):
    # Deliberately not alphabetical, so an unexpected global sort is visible.
    vaults = ["zeta", "Alpha", "midl", "balanced", "CHARLIE"]
    drawer = make_drawer(vaults)

    assert drawer.search_field.text() == ""
    assert _visible_names(drawer) == vaults
    assert drawer.empty_state_label.isHidden() is True
    assert drawer.vault_list.isHidden() is False


# ---------------------------------------------------------------------------
# C - case-insensitive substring matching
# ---------------------------------------------------------------------------


def test_case_insensitive_substring_match(make_drawer):
    drawer = make_drawer(["Alpha", "balanced", "CHARLIE", "delta"])

    drawer.search_field.setText("AL")

    assert _visible_names(drawer) == ["Alpha", "balanced"]


# ---------------------------------------------------------------------------
# D / E - prefix-first ordering, alphabetical inside each group
# ---------------------------------------------------------------------------


def test_prefix_matches_precede_substring_matches(make_drawer):
    # "al" is a prefix of two names and an interior substring of one.
    drawer = make_drawer(["zeta", "balanced", "alpine", "alpha", "gamma"])

    drawer.search_field.setText("al")

    assert _visible_names(drawer) == ["alpha", "alpine", "balanced"]


def test_alphabetical_order_within_each_match_group(make_drawer):
    drawer = make_drawer(["shallow", "galley", "Alpine", "alpha"])

    drawer.search_field.setText("al")

    # Prefix group first, then substring group, each alphabetical and
    # case-insensitive.
    assert _visible_names(drawer) == ["alpha", "Alpine", "galley", "shallow"]


# ---------------------------------------------------------------------------
# F - non-matches are hidden rather than removed
# ---------------------------------------------------------------------------


def test_non_matches_are_hidden_but_retained(make_drawer):
    drawer = make_drawer(["alpha", "galley", "zeta"])

    drawer.search_field.setText("al")

    assert _hidden_map(drawer) == {"alpha": False, "galley": False, "zeta": True}
    assert drawer.vault_list.count() == 3


# ---------------------------------------------------------------------------
# G - empty state
# ---------------------------------------------------------------------------


def test_empty_state_replaces_list_with_exact_text(make_drawer):
    drawer = make_drawer(["alpha", "beta"])

    drawer.search_field.setText("zzz")

    assert drawer.empty_state_label.isHidden() is False
    assert drawer.empty_state_label.text() == "No vaults match 'zzz'"
    assert drawer.vault_list.isHidden() is True
    # The create action lives in its own widget and is not hidden by this.
    assert drawer.empty_state_label.textFormat() == Qt.TextFormat.PlainText


def test_empty_state_treats_query_as_plain_text(make_drawer):
    drawer = make_drawer(["alpha"])

    drawer.search_field.setText("<b>zzz</b>")

    assert drawer.empty_state_label.textFormat() == Qt.TextFormat.PlainText
    assert drawer.empty_state_label.text() == "No vaults match '<b>zzz</b>'"


# ---------------------------------------------------------------------------
# H - clearing the query restores everything
# ---------------------------------------------------------------------------


def test_clearing_query_restores_baseline_order(make_drawer):
    vaults = ["zeta", "alpha", "galley"]
    drawer = make_drawer(vaults)

    drawer.search_field.setText("al")
    assert _visible_names(drawer) == ["alpha", "galley"]

    drawer.search_field.clear()

    assert _visible_names(drawer) == vaults
    assert all(
        not drawer.vault_list.item(position).isHidden()
        for position in range(drawer.vault_list.count())
    )
    assert drawer.empty_state_label.isHidden() is True
    assert drawer.vault_list.isHidden() is False


# ---------------------------------------------------------------------------
# I - the real close/reopen lifecycle regression
# ---------------------------------------------------------------------------


def test_toggle_close_reopen_clears_filter(make_drawer, qapp):
    """The regression that closed the previous attempt.

    This drives ``toggle()``, the path a toolbar close/reopen actually takes.
    ``show_drawer_widgets()`` is a navigation-level method and must not be
    substituted here.
    """
    vaults = ["zeta", "alpha", "galley"]
    drawer = make_drawer(vaults)

    drawer.toggle()
    qapp.processEvents()
    assert drawer.is_visible() is True

    drawer.search_field.setText("gal")
    assert _visible_names(drawer) == ["galley"]

    drawer.toggle()
    qapp.processEvents()
    assert drawer.is_visible() is False

    drawer.toggle()
    qapp.processEvents()
    assert drawer.is_visible() is True

    assert drawer.search_field.text() == ""
    assert _visible_names(drawer) == vaults
    assert drawer.empty_state_label.isHidden() is True
    assert drawer.vault_list.isHidden() is False

    drawer.toggle()
    qapp.processEvents()


# ---------------------------------------------------------------------------
# J / K - refresh semantics
# ---------------------------------------------------------------------------


def test_refresh_reapplies_active_filter(make_drawer):
    drawer = make_drawer(["alpha", "alpine", "zeta"])
    drawer.toggle()

    drawer.search_field.setText("al")
    assert _visible_names(drawer) == ["alpha", "alpine"]

    drawer.parent.app.set_vaults(["alpine", "zeta"])
    drawer._refresh_vault_list()

    assert drawer.search_field.text() == "al"
    assert _visible_names(drawer) == ["alpine"]

    drawer.parent.app.set_vaults(["alpine", "zeta", "alto"])
    drawer._refresh_vault_list()

    assert drawer.search_field.text() == "al"
    assert _visible_names(drawer) == ["alpine", "alto"]


def test_refresh_transitions_into_and_out_of_empty_state(make_drawer):
    drawer = make_drawer(["alpha", "zeta"])
    drawer.toggle()

    drawer.search_field.setText("alpha")
    assert _visible_names(drawer) == ["alpha"]

    drawer.parent.app.set_vaults(["zeta"])
    drawer._refresh_vault_list()

    assert _visible_names(drawer) == []
    assert drawer.empty_state_label.isHidden() is False
    assert drawer.vault_list.isHidden() is True

    drawer.parent.app.set_vaults(["zeta", "alpha"])
    drawer._refresh_vault_list()

    assert _visible_names(drawer) == ["alpha"]
    assert drawer.empty_state_label.isHidden() is True
    assert drawer.vault_list.isHidden() is False


# ---------------------------------------------------------------------------
# L - logging contract
# ---------------------------------------------------------------------------


def test_info_logging_is_transition_based_not_per_keystroke(make_drawer, log_records):
    """The second regression that closed the previous attempt.

    Typing must produce exactly one INFO record, for the transition into an
    active filter, and none for subsequent characters.
    """
    drawer = make_drawer(["secret", "opensesame", "alpha"])
    drawer.toggle()
    log_records.clear()

    for fragment in ("s", "se", "sec", "secret-fragment"):
        drawer.search_field.setText(fragment)

    assert _info_messages(log_records) == ["Vault drawer filter enabled: matches=2 total=3"]

    drawer.search_field.clear()

    assert _info_messages(log_records) == [
        "Vault drawer filter enabled: matches=2 total=3",
        "Vault drawer filter cleared: total=3",
    ]


def test_raw_query_never_reaches_info_log(make_drawer, log_records):
    drawer = make_drawer(["secret-fragment", "alpha"])
    drawer.toggle()
    log_records.clear()

    drawer.search_field.setText("secret-fragment")

    at_or_above_info = [
        record.getMessage() for record in log_records if record.levelno >= logging.INFO
    ]
    assert at_or_above_info == ["Vault drawer filter enabled: matches=1 total=2"]
    assert all("secret-fragment" not in message for message in at_or_above_info)

    # DEBUG may carry counts, but still not the raw query text.
    debug_messages = [
        record.getMessage() for record in log_records if record.levelno == logging.DEBUG
    ]
    assert debug_messages
    assert all("secret-fragment" not in message for message in debug_messages)


def test_reopen_emits_single_cleared_transition(make_drawer, log_records, qapp):
    drawer = make_drawer(["alpha", "beta"])
    drawer.toggle()

    log_records.clear()
    drawer.search_field.setText("alph")
    drawer.toggle()
    drawer.toggle()
    qapp.processEvents()

    assert _info_messages(log_records) == [
        "Vault drawer filter enabled: matches=1 total=2",
        "Vault drawer filter cleared: total=2",
    ]
    assert drawer.search_field.text() == ""

    drawer.toggle()
    qapp.processEvents()
