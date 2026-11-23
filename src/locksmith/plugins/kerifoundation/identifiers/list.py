# -*- encoding: utf-8 -*-
"""
locksmith.plugins.kerifoundation.identifiers.list module

Plugin-local identifier list used to choose which local AID should receive
hosted witnesses.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget
from keri import help

from locksmith.plugins.kerifoundation.core.identifiers import iter_local_identifier_choices
from locksmith.ui.toolkit.tables.paginated import PaginatedTableWidget
from locksmith.ui.toolkit.widgets import (
    FloatingLabelComboBox,
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)

logger = help.ogler.getLogger(__name__)


def _shrink_empty_state_title(table: PaginatedTableWidget, font_size: int = 20):
    target_text = f"NO {table.title.upper()}"
    for label in table.empty_state.findChildren(QLabel):
        if label.text() != target_text:
            continue
        label.setStyleSheet(
            label.styleSheet().replace("font-size: 24px;", f"font-size: {font_size}px;")
        )
        break


class IdentifierListPage(QWidget):
    add_witnesses_requested = Signal(str)
    mailbox_requested = Signal(str)

    def __init__(self, app=None, parent=None):
        super().__init__(parent)
        self._app = app
        self._db = None
        self._mailbox_enabled = None
        self._mailbox_busy = False
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._setup_ui()

    def set_db(self, db):
        self._db = db
        if db is None:
            self.set_mailbox_state()
            self._table.set_static_data([])

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._mailbox_notice = QLabel()
        self._mailbox_notice.setWordWrap(True)
        self._mailbox_notice.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._mailbox_notice)

        self._table = PaginatedTableWidget(
            columns=["Alias", "Prefix", "Seq No.", "Witnesses", "Mailbox"],
            title="KERI Foundation Identifiers",
            icon_path=":/assets/custom/identifiers.png",
            show_search=True,
            show_add_button=True,
            add_button_text="Add Identifier",
            items_per_page=10,
            row_actions=["Add Witnesses", "Retry Mailbox"],
            row_actions_callback=self._row_actions,
            row_action_icons={"Add Witnesses": ":/assets/material-icons/witness1.svg"},
            monospace_columns=["Prefix"],
        )
        _shrink_empty_state_title(self._table)
        self._table.add_clicked.connect(self._on_add_identifier_clicked)
        self._table.row_action_triggered.connect(self._on_row_action)
        layout.addWidget(self._table)

    def set_mailbox_state(self, *, enabled=None, busy=False, error=""):
        self._mailbox_enabled, self._mailbox_busy = enabled, busy
        if error:
            notice = f"Could not check mailbox availability: {error}. Try again from this page."
        elif busy:
            notice = "Setting up mailboxes…" if enabled is True else "Checking mailbox availability…"
        elif enabled is False:
            notice = "This service does not offer mailboxes. You can still add identifiers for hosted witnesses."
        else:
            notice = ""
        self._mailbox_notice.setText(notice)
        self._mailbox_notice.setVisible(bool(notice))
        self._table.header.add_button.setEnabled(not busy)
        for button in self._table.empty_state.findChildren(LocksmithButton):
            button.setEnabled(not busy)
        self.on_show()

    def _row_actions(self, row):
        actions = ["Add Witnesses"]
        if not self._mailbox_busy and self._mailbox_enabled is not False:
            actions.append("Retry Mailbox")
        return actions, {"Add Witnesses": ":/assets/material-icons/witness1.svg"}

    def on_show(self):
        self._table.set_static_data(self._build_rows())

    def _build_rows(self):
        if not self._app or not getattr(self._app, "vault", None) or self._db is None:
            return []

        rows = []
        hby = self._app.vault.hby
        prefixes = set(self._db.list_attached_identifier_prefixes())
        prefixes.update(prefix for (prefix,), _ in self._db.mailboxes.getTopItemIter())
        account = self._db.get_account()
        if account is not None and account.account_aid:
            prefixes.add(account.account_aid)
        for prefix in sorted(prefixes):
            hab = hby.habByPre(prefix)
            if hab is None:
                continue
            mailbox = self._db.mailboxes.get(keys=(prefix,))
            status = {"active": "Ready", "pending": "Setting up", "failed": "Setup failed"}
            mailbox_text = status.get(mailbox.status, mailbox.status) if mailbox else "Not set up"
            if not mailbox or mailbox.status != "active":
                if self._mailbox_enabled is False:
                    mailbox_text = "Setup paused" if mailbox else "Not offered"
                elif self._mailbox_enabled is None:
                    mailbox_text = "Setup paused" if mailbox else "Availability unknown"
            if mailbox and mailbox.error:
                mailbox_text += f": {mailbox.error}"
                if not self._mailbox_busy and self._mailbox_enabled is not False:
                    mailbox_text += " (use Retry Mailbox)"
            rows.append(
                {
                    "Alias": hab.name,
                    "Prefix": prefix,
                    "Seq No.": hab.kever.sn if hab and hab.kever else "N/A",
                    "Witnesses": len(hab.kever.wits) if hab and hab.kever else "N/A",
                    "Mailbox": mailbox_text,
                }
            )

        return rows

    def _available_identifier_choices(self):
        if not self._app or self._db is None:
            return []

        account = self._db.get_account()
        return [
            (alias, prefix)
            for alias, prefix in iter_local_identifier_choices(self._app)
            if not self._db.is_identifier_attached(prefix)
            and self._db.mailboxes.get(keys=(prefix,)) is None
            and (account is None or prefix != account.account_aid)
        ]

    def _choose_identifier_prefix(self) -> str:
        choices = self._available_identifier_choices()
        if not choices:
            logger.info("No additional local identifiers available for the KF provider")
            return ""

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 8, 0, 0)
        content_layout.setSpacing(16)

        selector = FloatingLabelComboBox("Local Identifier")
        selector.setFixedWidth(360)
        selector.addItem("Select an identifier...")
        for alias, prefix in choices:
            selector.addItem(f"{alias} - {prefix}", prefix)
        content_layout.addWidget(selector)

        button_row = QHBoxLayout()
        button_row.addStretch()

        cancel_button = LocksmithInvertedButton("Cancel")
        add_button = LocksmithButton("Add Identifier")
        button_row.addWidget(cancel_button)
        button_row.addWidget(add_button)

        dialog = LocksmithDialog(
            parent=self,
            title="Add Identifier",
            title_icon=":/assets/custom/identifiers.png",
            content=content,
            buttons=button_row,
        )
        dialog.setFixedWidth(420)
        cancel_button.clicked.connect(dialog.reject)
        add_button.clicked.connect(
            lambda: dialog.accept() if selector.currentIndex() > 0 else None
        )

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return ""

        return selector.currentData() or ""

    def _on_add_identifier_clicked(self):
        if self._db is None or self._mailbox_busy:
            return

        prefix = self._choose_identifier_prefix()
        if not prefix:
            return

        self.mailbox_requested.emit(prefix)

    def _on_row_action(self, row_data, action):
        if action == "Retry Mailbox":
            if self._mailbox_busy or self._mailbox_enabled is False:
                return
            self.mailbox_requested.emit(row_data["Prefix"])
            return
        if action != "Add Witnesses":
            return

        self.add_witnesses_requested.emit(row_data["Prefix"])
