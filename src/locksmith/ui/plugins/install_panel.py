# -*- encoding: utf-8 -*-
"""
locksmith.ui.plugins.install_panel module

Inline two-step install widget embedded directly in PluginsPage.
Replaces the modal InstallSourceDialog + PluginTrustDialog pair so that
the dev-control harness can drive the install flow end-to-end without
blocking on dlg.exec().

Internal state:
  _mode ∈ {"source", "trust"}   — tracked to support set_source_mode() reset.

Public signals:
  cancelled       — user clicked Cancel (either mode).
  source_chosen   — user clicked Fetch in source mode; arg is SourceDescriptor.
  trusted         — user clicked Trust & install in trust mode; arg is plugin_id.

Public attributes exposed for tests (keep stable):
  -- source mode --
  github_radio, local_radio
  user_repo_input, local_path_input, ref_input
  error_label, fetch_button, cancel_button

  -- trust mode --
  trust_headline, trust_source_line
  trust_capability_block
  trust_accept_button
  (cancel_button is shared across both modes; it lives on the source stack page
   and the trust stack page has its own trust_cancel_button, but cancel_button
   is the one on the source page — tests only call it in source mode)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from locksmith.plugins.installer import SourceDescriptor
from locksmith.ui.toolkit.widgets.buttons import LocksmithRadioButton


_GITHUB_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_CAPABILITY_COPY = {
    "app.shortcut":       "install global keyboard shortcuts",
    "app.service":        "run background services",
    "window.full_access": "inspect / control the full main window",
    "vault.full_access":  "access vault internals and credentials",
    "fs.write":           "write to disk",
    "fs.read":            "read from disk",
    "net.listen":         "open a local listening socket",
    "net.connect":        "make outbound network connections",
}


class InstallPanel(QWidget):
    """Inline install widget: source picker (mode='source') → trust confirm (mode='trust')."""

    cancelled = Signal()
    source_chosen = Signal(SourceDescriptor)
    trusted = Signal(str)           # plugin_id

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("InstallPanel")
        self._mode = "source"
        self._pending_plugin_id: str | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_source_mode(self) -> None:
        """Switch to source picker and reset all inputs."""
        self._mode = "source"
        self.user_repo_input.clear()
        self.local_path_input.clear()
        self.ref_input.clear()
        self.github_radio.setChecked(True)
        self.error_label.setText("")
        self.fetch_button.setEnabled(False)
        self._stack.setCurrentIndex(0)

    def set_trust_mode(
        self,
        *,
        manifest_snapshot: dict[str, Any],
        source: dict[str, Any],
        commit: str,
    ) -> None:
        """Switch to trust confirm view, populating from the manifest and source."""
        self._mode = "trust"

        name = manifest_snapshot.get("name", manifest_snapshot.get("plugin_id", "<unnamed>"))
        version = manifest_snapshot.get("version", "")
        self._pending_plugin_id = manifest_snapshot.get("plugin_id", "")

        self.trust_headline.setText(f"── Trust '{name}' v{version}? ──")

        if source.get("type") == "github":
            src_text = f"From: github.com/{source.get('user_repo')} @ {commit[:7]}"
        else:
            src_text = f"From: {source.get('path', '')}"
        self.trust_source_line.setText(src_text)

        # Author label — show only if present
        author = manifest_snapshot.get("author", "")
        if author:
            self._trust_author_label.setText(f"Author: {author}")
            self._trust_author_label.setVisible(True)
        else:
            self._trust_author_label.setVisible(False)

        # Description
        desc = manifest_snapshot.get("description", "")
        if desc:
            self._trust_desc_label.setText(f"“{desc}”")
            self._trust_desc_label.setVisible(True)
        else:
            self._trust_desc_label.setVisible(False)

        # Capabilities
        self.trust_capability_block.setHtml(
            self._capabilities_html(manifest_snapshot)
        )

        self._stack.setCurrentIndex(1)

    def set_inline_error(self, text: str) -> None:
        """Render a red error message above the buttons in source mode."""
        self.error_label.setText(text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Outer frame with top separator visual
        frame = QFrame()
        frame.setObjectName("InstallPanelFrame")
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("""
    QFrame#InstallPanelFrame {
        border: 1px solid #DDDDDD;
        border-radius: 6px;
        background: #FAFAFA;
    }
    QFrame#InstallPanelFrame QLineEdit {
        background: #FFFFFF;
        color: #2D2F33;
        border: 1px solid #D0D5DD;
        border-radius: 4px;
        padding: 6px 8px;
        min-height: 24px;
    }
    QFrame#InstallPanelFrame QLineEdit:focus {
        border: 1px solid #007AFF;
    }
    QFrame#InstallPanelFrame QLineEdit:disabled {
        background: #EEEEEE;
        color: #888888;
    }
    QFrame#InstallPanelFrame QLabel {
        color: #2D2F33;
        background: transparent;
    }
""")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(20, 16, 20, 16)
        frame_layout.setSpacing(12)

        self._stack = QStackedWidget()
        frame_layout.addWidget(self._stack)

        self._stack.addWidget(self._build_source_page())
        self._stack.addWidget(self._build_trust_page())
        self._stack.setCurrentIndex(0)

        outer.addWidget(frame)

    def _build_source_page(self) -> QWidget:
        page = QWidget()
        vbox = QVBoxLayout(page)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(10)

        header = QLabel("── Install plugin ──")
        header.setStyleSheet("font-size:16px; font-weight:600; color:#333;")
        vbox.addWidget(header)

        # GitHub radio + input
        self.github_radio = LocksmithRadioButton("GitHub  user/repo")
        self.github_radio.setChecked(True)
        self.github_radio.toggled.connect(self._on_source_kind_changed)
        vbox.addWidget(self.github_radio)

        gh_row = QHBoxLayout()
        gh_row.addSpacing(28)
        self.user_repo_input = QLineEdit()
        self.user_repo_input.setPlaceholderText("e.g. seriouscoderone/locksmith-dev-control")
        self.user_repo_input.textChanged.connect(self._revalidate)
        gh_row.addWidget(self.user_repo_input)
        vbox.addLayout(gh_row)

        # Local radio + input
        self.local_radio = LocksmithRadioButton("Local path")
        self.local_radio.toggled.connect(self._on_source_kind_changed)
        vbox.addWidget(self.local_radio)

        loc_row = QHBoxLayout()
        loc_row.addSpacing(28)
        self.local_path_input = QLineEdit()
        self.local_path_input.setPlaceholderText("/path/to/plugin/clone")
        self.local_path_input.setEnabled(False)
        self.local_path_input.textChanged.connect(self._revalidate)
        loc_row.addWidget(self.local_path_input)
        vbox.addLayout(loc_row)

        # Branch/ref form row
        ref_form = QFormLayout()
        ref_form.setContentsMargins(0, 0, 0, 0)
        self.ref_input = QLineEdit()
        self.ref_input.setPlaceholderText("(defaults to default branch HEAD)")
        ref_form.addRow("Branch/ref (optional):", self.ref_input)
        vbox.addLayout(ref_form)

        # Error label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color:#c8341c;")
        self.error_label.setWordWrap(True)
        vbox.addWidget(self.error_label)

        # Button row
        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self._on_cancel)
        button_row.addWidget(self.cancel_button)
        self.fetch_button = QPushButton("Fetch")
        self.fetch_button.setEnabled(False)
        self.fetch_button.clicked.connect(self._on_fetch)
        button_row.addWidget(self.fetch_button)
        vbox.addLayout(button_row)

        return page

    def _build_trust_page(self) -> QWidget:
        page = QWidget()
        vbox = QVBoxLayout(page)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(10)

        self.trust_headline = QLabel("")
        self.trust_headline.setStyleSheet("font-size:16px; font-weight:600; color:#333;")
        self.trust_headline.setWordWrap(True)
        vbox.addWidget(self.trust_headline)

        self.trust_source_line = QLabel("")
        self.trust_source_line.setStyleSheet("color:#444;")
        vbox.addWidget(self.trust_source_line)

        self._trust_author_label = QLabel("")
        self._trust_author_label.setVisible(False)
        vbox.addWidget(self._trust_author_label)

        self._trust_desc_label = QLabel("")
        self._trust_desc_label.setWordWrap(True)
        self._trust_desc_label.setStyleSheet("color:#222; padding:6px 0;")
        self._trust_desc_label.setVisible(False)
        vbox.addWidget(self._trust_desc_label)

        vbox.addWidget(QLabel("This plugin declares it will:"))

        self.trust_capability_block = QTextBrowser()
        self.trust_capability_block.setReadOnly(True)
        self.trust_capability_block.setOpenLinks(False)
        self.trust_capability_block.setStyleSheet(
            "QTextBrowser { background: #FFFFFF; color: #2D2F33; "
            "border: 1px solid #D0D5DD; border-radius: 4px; padding: 8px; }"
        )
        self.trust_capability_block.document().setDefaultStyleSheet(
            "li { color: #2D2F33; margin: 4px 0; } "
            ".detail { color: #666666; padding-left: 18px; display: block; }"
        )
        self.trust_capability_block.setMaximumHeight(160)
        self.trust_capability_block.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )
        vbox.addWidget(self.trust_capability_block)

        warn = QLabel(
            "Plugins run with full wallet permissions.  "
            "Only install plugins you trust."
        )
        warn.setStyleSheet("color:#a8770a; font-style:italic; padding:4px 0;")
        warn.setWordWrap(True)
        vbox.addWidget(warn)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        trust_cancel = QPushButton("Cancel")
        trust_cancel.clicked.connect(self._on_cancel)
        button_row.addWidget(trust_cancel)
        self.trust_accept_button = QPushButton("Trust && install")
        self.trust_accept_button.clicked.connect(self._on_trust_accept)
        button_row.addWidget(self.trust_accept_button)
        vbox.addLayout(button_row)

        return page

    # ------------------------------------------------------------------
    # Source-mode validation
    # ------------------------------------------------------------------

    def _on_source_kind_changed(self) -> None:
        gh_active = self.github_radio.isChecked()
        self.user_repo_input.setEnabled(gh_active)
        self.local_path_input.setEnabled(not gh_active)
        self._revalidate()

    def _revalidate(self) -> None:
        ok, err = self._validate()
        self.error_label.setText(err)
        self.fetch_button.setEnabled(ok)

    def _validate(self) -> tuple[bool, str]:
        if self.github_radio.isChecked():
            text = self.user_repo_input.text().strip()
            if not text:
                return False, ""
            if not _GITHUB_RE.match(text):
                return False, (
                    "user/repo must be in the format owner/name "
                    "(letters, digits, dot, underscore, dash)."
                )
            return True, ""
        text = self.local_path_input.text().strip()
        if not text:
            return False, ""
        path = Path(text)
        if not path.exists():
            return False, f"path does not exist: {path}"
        if not (path / "locksmith-plugin.toml").exists():
            return False, f"no locksmith-plugin.toml in {path}"
        return True, ""

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _on_fetch(self) -> None:
        ref = self.ref_input.text().strip() or None
        if self.github_radio.isChecked():
            src = SourceDescriptor(
                type="github",
                user_repo=self.user_repo_input.text().strip(),
                ref=ref,
            )
        else:
            src = SourceDescriptor(
                type="local",
                path=self.local_path_input.text().strip(),
            )
        self.source_chosen.emit(src)

    def _on_trust_accept(self) -> None:
        pid = self._pending_plugin_id or ""
        self.trusted.emit(pid)

    def _on_cancel(self) -> None:
        self.cancelled.emit()

    # ------------------------------------------------------------------
    # Capability HTML (shared copy from old trust_dialog)
    # ------------------------------------------------------------------

    def _capabilities_html(self, snap: dict[str, Any]) -> str:
        caps = snap.get("capabilities", []) or []
        detail = snap.get("capabilities_detail", {}) or {}
        if not caps:
            return "<i>No capabilities declared.</i>"
        rows = []
        for cap in caps:
            copy = _CAPABILITY_COPY.get(cap, f"{cap} <i>(unrecognized)</i>")
            rows.append(f"<li>{copy}")
            if cap in detail:
                rows[-1] += (
                    f"<br><span class='detail'>"
                    f"&#x21B3; {detail[cap]}</span>"
                )
            rows[-1] += "</li>"
        return "<ul style='margin:0; padding-left:18px;'>" + "".join(rows) + "</ul>"
