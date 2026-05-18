# -*- encoding: utf-8 -*-
"""
locksmith.ui.plugins.install_dialog module

Step 1 of the install wizard: pick a source (GitHub user/repo or local path).
Emits ``source_chosen(SourceDescriptor)`` on Fetch. The window owns the
subsequent fetch + trust-dialog flow.
"""
from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from locksmith.plugins.installer import SourceDescriptor


_GITHUB_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class InstallSourceDialog(QDialog):
    """Two-section source picker: GitHub | Local path."""

    source_chosen = Signal(SourceDescriptor)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Install plugin")
        self.setMinimumWidth(520)

        outer = QVBoxLayout(self)
        outer.setSpacing(12)
        outer.setContentsMargins(20, 20, 20, 20)

        outer.addWidget(QLabel("Source:"))
        self.github_radio = QRadioButton("GitHub  user/repo")
        self.github_radio.setChecked(True)
        self.github_radio.toggled.connect(self._on_source_kind_changed)
        outer.addWidget(self.github_radio)

        gh_row = QHBoxLayout()
        gh_row.addSpacing(28)
        self.user_repo_input = QLineEdit()
        self.user_repo_input.setPlaceholderText("e.g. seriouscoderone/locksmith-dev-control")
        self.user_repo_input.textChanged.connect(self._revalidate)
        gh_row.addWidget(self.user_repo_input)
        outer.addLayout(gh_row)

        self.local_radio = QRadioButton("Local path")
        self.local_radio.toggled.connect(self._on_source_kind_changed)
        outer.addWidget(self.local_radio)

        loc_row = QHBoxLayout()
        loc_row.addSpacing(28)
        self.local_path_input = QLineEdit()
        self.local_path_input.setPlaceholderText("/path/to/plugin/clone")
        self.local_path_input.setEnabled(False)
        self.local_path_input.textChanged.connect(self._revalidate)
        loc_row.addWidget(self.local_path_input)
        outer.addLayout(loc_row)

        ref_form = QFormLayout()
        self.ref_input = QLineEdit()
        self.ref_input.setPlaceholderText("(defaults to default branch HEAD)")
        ref_form.addRow("Branch/ref (optional):", self.ref_input)
        outer.addLayout(ref_form)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color:#c8341c;")
        self.error_label.setWordWrap(True)
        outer.addWidget(self.error_label)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        button_row.addWidget(cancel)
        self.fetch_button = QPushButton("Fetch")
        self.fetch_button.setEnabled(False)
        self.fetch_button.clicked.connect(self._on_fetch)
        button_row.addWidget(self.fetch_button)
        outer.addLayout(button_row)

    # ----- handlers -------------------------------------------------

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
        self.accept()
