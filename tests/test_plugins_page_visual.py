"""Visual + structural smoke test for the PluginsPage.

Pattern follows tests/test_create_role_dialog_visual.py:
- render, structurally assert, screenshot to tests/_screenshots/.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from PySide6.QtTest import QTest

from locksmith.plugins.manager import PluginState
from locksmith.ui.plugins.page import PluginsPage


SCREENSHOT_DIR = Path(__file__).parent / "_screenshots"


@pytest.fixture
def fake_app_with_states():
    states = [
        PluginState(
            plugin_id="kerifoundation",
            status="loaded",
            manifest_snapshot={"name": "KERI Foundation", "version": "0.3.1",
                                "description": "Onboarding, witnesses, watchers"},
            in_tree=True,
        ),
        PluginState(
            plugin_id="echo_app",
            status="loaded",
            source={"type": "github", "user_repo": "acme/echo", "ref": None},
            manifest_snapshot={"name": "Echo App", "version": "0.1.0",
                                "description": "Logs lifecycle events"},
        ),
        PluginState(
            plugin_id="future",
            status="incompatible",
            error="requires Locksmith >=0.5 (you have 0.4)",
            manifest_snapshot={"name": "Future Plugin", "version": "0.2.0",
                                "description": "From the future"},
        ),
    ]
    app = MagicMock()
    app.plugin_manager.all_states.return_value = states
    return app


def test_page_renders_all_states(qapp, fake_app_with_states):
    page = PluginsPage(fake_app_with_states)
    page.resize(900, 700)
    page.show()
    QTest.qWait(250)
    qapp.processEvents()

    # Structural: one row per state, each showing the plugin's name.
    rendered_names = [w.text() for w in page.findChildren(type(page).PluginNameLabel)]
    assert "KERI Foundation" in rendered_names
    assert "Echo App" in rendered_names
    assert "Future Plugin" in rendered_names

    # In-tree badge present on kerifoundation only.
    in_tree_labels = [
        w for w in page.findChildren(type(page).InTreeBadge) if w.isVisible()
    ]
    assert len(in_tree_labels) == 1

    # Status badge text correct.
    statuses = [b.text() for b in page.findChildren(type(page).StatusBadge)]
    assert any("Loaded" in s for s in statuses)
    assert any("Incompatible" in s for s in statuses)

    # Visual.
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    page.grab().save(str(SCREENSHOT_DIR / "plugins_page_mixed_states.png"))


def test_empty_state(qapp):
    app = MagicMock()
    app.plugin_manager.all_states.return_value = []
    page = PluginsPage(app)
    page.resize(900, 700)
    page.show()
    QTest.qWait(250)
    qapp.processEvents()
    assert page.findChild(type(page).EmptyStateLabel) is not None
    page.grab().save(str(SCREENSHOT_DIR / "plugins_page_empty.png"))


def test_install_button_emits_signal(qapp, fake_app_with_states):
    page = PluginsPage(fake_app_with_states)
    page.show()
    QTest.qWait(250)
    qapp.processEvents()

    fired = {"count": 0}
    page.install_clicked.connect(lambda: fired.update(count=fired["count"] + 1))
    page._install_button.click()
    qapp.processEvents()
    assert fired["count"] == 1


from locksmith.plugins.installer import SourceDescriptor
from locksmith.ui.plugins.install_dialog import InstallSourceDialog


def test_install_dialog_default_state(qapp):
    dlg = InstallSourceDialog()
    dlg.show()
    QTest.qWait(200)
    qapp.processEvents()
    # GitHub radio selected by default.
    assert dlg.github_radio.isChecked()
    assert not dlg.local_radio.isChecked()
    # Fetch button starts disabled (no input yet).
    assert not dlg.fetch_button.isEnabled()
    dlg.grab().save(str(SCREENSHOT_DIR / "install_dialog_default.png"))


def test_github_userrepo_validation(qapp):
    dlg = InstallSourceDialog()
    dlg.show()
    QTest.qWait(150)

    # Bad format.
    dlg.user_repo_input.setText("not a valid format")
    qapp.processEvents()
    assert not dlg.fetch_button.isEnabled()
    err = dlg.error_label.text().lower()
    assert "must be" in err or "format" in err

    # Good format.
    dlg.user_repo_input.setText("acme/echo")
    qapp.processEvents()
    assert dlg.fetch_button.isEnabled()
    assert dlg.error_label.text() == ""


def test_local_path_validation(qapp, tmp_path):
    dlg = InstallSourceDialog()
    dlg.show()
    QTest.qWait(150)
    dlg.local_radio.setChecked(True)
    qapp.processEvents()

    # Path doesn't exist.
    dlg.local_path_input.setText(str(tmp_path / "nope"))
    qapp.processEvents()
    assert not dlg.fetch_button.isEnabled()

    # Path exists but no manifest.
    (tmp_path / "no-manifest").mkdir()
    dlg.local_path_input.setText(str(tmp_path / "no-manifest"))
    qapp.processEvents()
    assert not dlg.fetch_button.isEnabled()
    assert "locksmith-plugin.toml" in dlg.error_label.text()

    # Path with manifest.
    plug = tmp_path / "with-manifest"
    plug.mkdir()
    (plug / "locksmith-plugin.toml").write_text("placeholder\n")
    dlg.local_path_input.setText(str(plug))
    qapp.processEvents()
    assert dlg.fetch_button.isEnabled()


def test_fetch_emits_source_descriptor(qapp):
    dlg = InstallSourceDialog()
    dlg.show()
    QTest.qWait(150)
    captured = {}
    dlg.source_chosen.connect(lambda src: captured.update(src=src))

    dlg.user_repo_input.setText("acme/echo")
    dlg.ref_input.setText("main")
    qapp.processEvents()
    dlg.fetch_button.click()
    qapp.processEvents()

    assert captured["src"] == SourceDescriptor(
        type="github", user_repo="acme/echo", ref="main",
    )
