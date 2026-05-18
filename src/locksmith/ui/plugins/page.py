# -*- encoding: utf-8 -*-
"""
locksmith.ui.plugins.page module

Top-level Plugins page (Pages.PLUGINS). Lists installed plugins with
state badges; exposes Install / Uninstall / Exclude affordances.

Install and Uninstall both surface signals; the LocksmithWindow wires
those signals to dialogs and to PluginInstaller calls (Task 13).
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)
from keri import help

logger = help.ogler.getLogger(__name__)


_STATUS_COPY = {
    "loaded":         ("● Loaded",                "#1c8a3a"),
    "excluded":       ("○ Excluded (this wallet)", "#777"),
    "incompatible":   ("⚠ Incompatible",          "#a8770a"),
    "files_missing":  ("⚠ Files missing",         "#a8770a"),
    "failed":         ("⚠ Failed to load",        "#c8341c"),
}


class PluginsPage(QWidget):
    """The Plugins management page."""

    install_clicked = Signal()
    uninstall_clicked = Signal(str)            # plugin_id
    exclude_toggled = Signal(str, bool)         # plugin_id, now_excluded

    class PluginNameLabel(QLabel):
        pass

    class StatusBadge(QLabel):
        pass

    class InTreeBadge(QLabel):
        pass

    class EmptyStateLabel(QLabel):
        pass

    def __init__(self, app: Any, parent: QWidget | None = None):
        super().__init__(parent)
        self.app = app
        self.setObjectName("PluginsPage")
        self._build_ui()
        self._refresh()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        header = QLabel("Plugins")
        header.setStyleSheet("font-size: 22px; font-weight: 600;")
        outer.addWidget(header)

        self._restart_banner = QLabel(
            "⚠ Restart required to finish applying changes."
        )
        self._restart_banner.setStyleSheet(
            "background:#fff4d6; padding:8px 12px; border:1px solid #d6b15a;"
        )
        self._restart_banner.setVisible(False)
        outer.addWidget(self._restart_banner)

        self._list_scroll = QScrollArea()
        self._list_scroll.setWidgetResizable(True)
        self._list_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._list_container = QWidget()
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setSpacing(12)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._list_scroll.setWidget(self._list_container)
        outer.addWidget(self._list_scroll, stretch=1)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self._install_button = QPushButton("+ Install plugin")
        self._install_button.setObjectName("plugins_install_button")
        self._install_button.clicked.connect(self.install_clicked.emit)
        button_row.addWidget(self._install_button)
        outer.addLayout(button_row)

    def _refresh(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

        states = list(self.app.plugin_manager.all_states())
        if not states:
            empty = self.EmptyStateLabel(
                "No plugins installed yet.\nClick + Install plugin to add one."
            )
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setStyleSheet("color:#777; padding:32px;")
            self._list_layout.addWidget(empty)
            return

        for state in states:
            self._list_layout.addWidget(self._make_row(state))

    def _make_row(self, state) -> QWidget:
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.setStyleSheet(
            "QFrame { border:1px solid #ddd; border-radius:6px; "
            "background:#fff; padding:12px; }"
        )
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        v = QVBoxLayout(card)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(6)

        snap = state.manifest_snapshot or {}
        name = snap.get("name", state.plugin_id)
        version = snap.get("version", "")
        desc = snap.get("description", "")

        top_row = QHBoxLayout()
        name_label = self.PluginNameLabel(name)
        name_label.setStyleSheet("font-weight:600; font-size:15px;")
        top_row.addWidget(name_label)
        if version:
            v_label = QLabel(f"v{version}")
            v_label.setStyleSheet("color:#777; padding-left:8px;")
            top_row.addWidget(v_label)
        if state.in_tree:
            in_tree = self.InTreeBadge("[ in-tree ]")
            in_tree.setStyleSheet("color:#777; padding-left:8px;")
            top_row.addWidget(in_tree)
        elif state.source:
            src = state.source
            if src.get("type") == "github":
                src_label = QLabel(f"from github:{src.get('user_repo', '?')}")
                src_label.setStyleSheet("color:#777; padding-left:8px;")
                top_row.addWidget(src_label)
        top_row.addStretch(1)
        v.addLayout(top_row)

        if desc:
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color:#444;")
            desc_label.setWordWrap(True)
            v.addWidget(desc_label)

        bottom_row = QHBoxLayout()
        text, color = _STATUS_COPY.get(state.status, ("?", "#888"))
        badge = self.StatusBadge(text)
        badge.setStyleSheet(f"color:{color}; font-weight:600;")
        bottom_row.addWidget(badge)
        if state.error and state.status in ("failed", "incompatible"):
            err = QLabel(state.error)
            err.setStyleSheet("color:#c8341c; font-style:italic; padding-left:8px;")
            err.setWordWrap(True)
            bottom_row.addWidget(err, stretch=1)
        bottom_row.addStretch(1)
        if not state.in_tree:
            exclude_btn = QPushButton(
                "Include on this wallet" if state.status == "excluded"
                else "Exclude on this wallet"
            )
            exclude_btn.clicked.connect(
                lambda _=False, pid=state.plugin_id, was=state.status == "excluded":
                self.exclude_toggled.emit(pid, not was)
            )
            bottom_row.addWidget(exclude_btn)
            uninstall_btn = QPushButton("Uninstall")
            uninstall_btn.clicked.connect(
                lambda _=False, pid=state.plugin_id:
                self.uninstall_clicked.emit(pid)
            )
            bottom_row.addWidget(uninstall_btn)
        v.addLayout(bottom_row)
        return card

    # Toolbar / window protocol — every page implements this.

    def get_toolbar_config(self) -> dict:
        return {"title": "Plugins", "show_back": False}

    def on_show(self) -> None:
        self._refresh()

    def on_hide(self) -> None:
        pass

    def set_restart_required(self, required: bool) -> None:
        self._restart_banner.setVisible(required)
