# -*- encoding: utf-8 -*-
"""
Behavioural tests for the vault drawer search filter (issue #68).

These drive the real ``VaultDrawer``. Besides the issue's contract they cover
the two defects that closed the earlier attempt: the filter was cleared on the
navigation-level path instead of in ``toggle()``, and the raw query was logged
at INFO on every keystroke.
"""
from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PySide6.QtWidgets import QWidget

from locksmith.ui.vaults import drawer as drawer_module
from locksmith.ui.vaults.drawer import VaultDrawer

# Deliberately not alphabetical: unfiltered, the list keeps the order the
# application reports, and the filter imposes its own order on the matches.
VAULTS = ["zeta", "megalith", "Gamma", "alpine", "gallium"]


@pytest.fixture
def drawer(qapp):
    """A real ``VaultDrawer`` whose app reports ``VAULTS``, mutable in place."""
    vaults = list(VAULTS)
    window = QWidget()
    window.resize(1200, 800)
    window.app = SimpleNamespace(environments=lambda: list(vaults))
    toolbar = QWidget(window)
    toolbar.setFixedHeight(60)

    widget = VaultDrawer(window, toolbar)
    yield widget, vaults

    widget.deleteLater()
    window.deleteLater()
    qapp.processEvents()


@pytest.fixture
def logs():
    """Drawer log records. Keri loggers do not propagate, so capture directly."""
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    previous_level = drawer_module.logger.level
    drawer_module.logger.addHandler(handler)
    drawer_module.logger.setLevel(logging.INFO)
    yield records
    drawer_module.logger.setLevel(previous_level)
    drawer_module.logger.removeHandler(handler)


def _vault_names(drawer: VaultDrawer) -> list[str]:
    """Vault names the user can currently see, in display order."""
    return [
        drawer.vault_list.item(row).text()
        for row in range(drawer.vault_list.count())
    ]


def test_filter_hides_non_matches_and_puts_prefix_matches_first(drawer):
    widget, _ = drawer

    widget.search_field.setText("ga")

    # Case-insensitive match. "gallium" and "Gamma" are prefixes, so they sort
    # alphabetically ahead of the "megalith" substring match. "alpine" and
    # "zeta" do not match and are gone.
    assert _vault_names(widget) == ["gallium", "Gamma", "megalith"]


def test_no_match_shows_empty_state(drawer):
    widget, _ = drawer

    widget.search_field.setText("zzz")

    assert _vault_names(widget) == []
    assert widget.empty_state_label.isHidden() is False
    assert widget.empty_state_label.text() == "No vaults match 'zzz'"
    assert widget.vault_list.isHidden() is True


def test_toggle_close_and_reopen_clears_filter(drawer, qapp):
    """The regression from the earlier attempt: ``toggle()`` owns the reset."""
    widget, vaults = drawer

    widget.toggle()  # open
    widget.search_field.setText("gam")
    assert _vault_names(widget) == ["Gamma"]

    widget.toggle()  # close
    widget.toggle()  # open again

    assert widget.search_field.text() == ""
    assert _vault_names(widget) == vaults
    assert widget.empty_state_label.isHidden() is True

    widget.toggle()
    qapp.processEvents()


def test_refresh_reapplies_active_filter(drawer):
    widget, vaults = drawer

    environments = Mock(side_effect=lambda: list(vaults))
    widget.app.environments = environments

    widget.search_field.setText("g")
    widget.search_field.setText("ga")

    # Typing filters the cached list, not the filesystem.
    assert environments.call_count == 0
    assert _vault_names(widget) == ["gallium", "Gamma", "megalith"]

    vaults[:] = ["megalith", "gantry", "zeta"]
    widget._refresh_vault_list()

    assert environments.call_count == 1
    assert widget.search_field.text() == "ga"
    assert _vault_names(widget) == ["gantry", "megalith"]


def test_filter_logs_one_info_transition_per_state_change(drawer, logs):
    widget, _ = drawer

    for fragment in ("ga", "gam", "gamm"):
        widget.search_field.setText(fragment)

    assert [record.getMessage() for record in logs] == ["Vault drawer filter enabled"]

    widget.search_field.clear()

    assert [record.getMessage() for record in logs] == [
        "Vault drawer filter enabled",
        "Vault drawer filter cleared",
    ]
    assert all("gamm" not in record.getMessage() for record in logs)
