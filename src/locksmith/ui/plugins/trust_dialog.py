# -*- encoding: utf-8 -*-
"""
locksmith.ui.plugins.trust_dialog module

Step 2 of the install wizard: show the parsed manifest and ask the user
to confirm. Capability strings are translated to human copy; unknown
strings are shown verbatim with "(unrecognized)" appended.
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)


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


class PluginTrustDialog(QDialog):
    """Confirmation dialog before a plugin is installed."""

    trusted = Signal()

    def __init__(
        self,
        *,
        manifest_snapshot: dict[str, Any],
        source: dict[str, Any],
        commit: str,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Trust this plugin?")
        self.setMinimumWidth(560)

        name = manifest_snapshot.get("name", manifest_snapshot.get("plugin_id", "<unnamed>"))
        version = manifest_snapshot.get("version", "")

        outer = QVBoxLayout(self)
        outer.setSpacing(12)
        outer.setContentsMargins(20, 20, 20, 20)

        self.headline = QLabel(f"Trust '{name}' v{version}?")
        self.headline.setStyleSheet("font-size:18px; font-weight:600;")
        outer.addWidget(self.headline)

        if source.get("type") == "github":
            src_text = f"From: github.com/{source.get('user_repo')} @ {commit[:7]}"
        else:
            src_text = f"From: {source.get('path')}"
        self.source_line = QLabel(src_text)
        self.source_line.setStyleSheet("color:#444;")
        outer.addWidget(self.source_line)

        if manifest_snapshot.get("author"):
            outer.addWidget(QLabel(f"Author: {manifest_snapshot['author']}"))

        desc = manifest_snapshot.get("description", "")
        if desc:
            desc_label = QLabel(f"“{desc}”")
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color:#222; padding: 6px 0;")
            outer.addWidget(desc_label)

        outer.addWidget(QLabel("This plugin declares it will:"))
        self.capability_block = QTextBrowser()
        self.capability_block.setReadOnly(True)
        self.capability_block.setOpenLinks(False)
        self.capability_block.setStyleSheet(
            "QTextBrowser { background:#fafafa; border:1px solid #ddd; padding:8px; }"
        )
        self.capability_block.setHtml(self._capabilities_html(manifest_snapshot))
        self.capability_block.setMaximumHeight(160)
        outer.addWidget(self.capability_block)

        warn = QLabel(
            "Plugins run with full wallet permissions.  "
            "Only install plugins you trust."
        )
        warn.setStyleSheet("color:#a8770a; font-style:italic; padding:4px 0;")
        warn.setWordWrap(True)
        outer.addWidget(warn)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_row.addWidget(self.cancel_button)
        self.accept_button = QPushButton("Trust && install")
        self.accept_button.clicked.connect(self._on_accept)
        button_row.addWidget(self.accept_button)
        outer.addLayout(button_row)

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
                    f"<br><span style='padding-left:18px; color:#666;'>"
                    f"&#x21B3; {detail[cap]}</span>"
                )
            rows[-1] += "</li>"
        return "<ul style='margin:0; padding-left:18px;'>" + "".join(rows) + "</ul>"

    def _on_accept(self) -> None:
        self.trusted.emit()
        self.accept()
