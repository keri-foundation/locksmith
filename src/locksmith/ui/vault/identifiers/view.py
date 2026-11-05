# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.identifiers.view module

Dialog for viewing identifier details
"""
import asyncio

from PySide6.QtGui import QIcon
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QHBoxLayout
)
from keri import help

from locksmith.core import habbing
from locksmith.core.messaging import ensure_receiving, receiving_ready
from locksmith.ui.vault.shared.messaging import prepare_messaging
from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection
from locksmith.core.indirecting import receiving_endpoints
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithInvertedButton
)
from locksmith.ui.vault.identifiers.identifier_sections import IdentifierViewSectionsMixin
from locksmith.ui.vault.shared.export import export_identifier_to_cesr

logger = help.ogler.getLogger(__name__)


class ViewIdentifierDialog(IdentifierViewSectionsMixin, LocksmithDialog):
    """Dialog for viewing identifier details."""

    def __init__(self, icon_path, app, identifier_alias, parent=None):
        """
        Initialize the ViewIdentifierDialog.

        Args:
            icon_path: Path to the identifier icon
            app: Application instance
            identifier_alias: Alias of the identifier to view
            parent: Parent widget (typically VaultPage)
        """
        self.app = app
        self.vault = app.vault
        self.identifier_alias = identifier_alias

        # Get the hab (identifier)
        try:
            self.hab = self.app.vault.hby.habByName(identifier_alias)
            if not self.hab:
                raise ValueError(f"Identifier '{identifier_alias}' not found")
        except Exception as e:
            logger.error(f"Error loading identifier: {e}")
            raise

        # Get identifier details
        self.details = habbing.get_identifier_details(self.app, self.hab)

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(15)

        # AID Section
        self._build_aid_section(layout)
        self.receiving_status = QLabel()
        self.receiving_status.setWordWrap(True)
        layout.addWidget(self.receiving_status)
        self.share_button = LocksmithInvertedButton('Share introduction')
        layout.addWidget(self.share_button)
        self.copy_link_button = LocksmithInvertedButton('Copy contact link')
        self.copy_link_button.clicked.connect(self._copy_contact_link)
        layout.addWidget(self.copy_link_button)

        # Key Event Log Section
        self._build_kel_section(layout)

        # KEL Information Section (from mixin)
        self._build_kel_info_section(layout, self.details)

        # Resubmit Section (from mixin)
        self._build_resubmit_section(layout, self.details)

        self.connection_section = CollapsibleSection(title='Connection details', parent=content_widget)
        connection_layout = QVBoxLayout()
        self.connection_details = QLabel()
        self.connection_details.setWordWrap(True)
        connection_layout.addWidget(self.connection_details)
        self.retry_connection = LocksmithInvertedButton('Retry connection')
        self.retry_connection.clicked.connect(self._retry_connection)
        connection_layout.addWidget(self.retry_connection)
        self.export_available = LocksmithInvertedButton('Export available introduction')
        self.export_available.clicked.connect(lambda: export_identifier_to_cesr(
            self, self.app, self.identifier_alias, require_messaging=False))
        connection_layout.addWidget(self.export_available)
        self._build_oobi_section(connection_layout)
        self.connection_section.set_content_layout(connection_layout)
        layout.addWidget(self.connection_section)

        # Refresh Key State Section (for group multisig)
        if self.details['is_group_multisig']:
            self._build_refresh_keystate_section(layout)

        layout.addStretch()

        # Create button row
        button_row = QHBoxLayout()
        self.close_button = LocksmithInvertedButton("Close")
        button_row.addWidget(self.close_button)

        # Create title content
        title_content_widget = QWidget()
        title_content = QHBoxLayout()
        icon = QIcon(icon_path)
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        title_content.addWidget(icon_label)

        title_label = QLabel(f"  {identifier_alias}")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_content.addWidget(title_label)
        title_content_widget.setLayout(title_content)

        # Initialize parent dialog
        super().__init__(
            parent=parent,
            title_content=title_content_widget,
            show_close_button=True,
            content=content_widget,
            buttons=button_row,
            show_overlay=False
        )

        # Set initial size
        self.setFixedSize(640, 940)

        # Connect buttons
        self.close_button.clicked.connect(self.close)
        self.share_button.clicked.connect(self._share_introduction)
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self._refresh_receiving)
        self.status_timer.start(1000)
        self.finished.connect(self.status_timer.stop)
        self._connection_task = None
        self.finished.connect(self._cancel_connection)
        self._refresh_receiving()

        # Connect to vault signal bridge if available
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            logger.info("ViewIdentifierDialog: Connected to vault signal bridge")

    def _refresh_receiving(self):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.status_timer.stop()
            self.receiving_status.setText('Vault closed')
            self.share_button.setEnabled(False)
            return
        endpoints = receiving_endpoints(self.hab)
        states = [state for _, state in self.vault.db.connections.getTopItemIter(keys=(self.hab.pre,))]
        errors = [state.error for state in states if state.error]
        ready = receiving_ready(self.vault, self.hab)
        manager = getattr(self.vault, 'plugin_manager', None)
        setup = manager.messaging_status(self.vault, self.hab.pre) if manager else None
        if setup and setup[1]:
            errors.append(setup[1])
        self.receiving_status.setText('Messaging needs attention' if errors else
                                     'Messaging ready' if ready else 'Setting up messaging')
        details = ([f'Setup: {setup[0]}. {setup[1]}'] if setup else [])
        details.extend(f'Endpoint: {eid}' for eid in sorted(endpoints))
        details.extend(f'{state.error} (attempts: {state.attempts}/4)' for state in states if state.error)
        self.connection_details.setText('\n'.join(details) or 'No receiving address is configured.')

    def _cancel_connection(self, *_):
        if self._connection_task is not None:
            self._connection_task.cancel()

    def _retry_connection(self):
        if self._connection_task is not None:
            return
        async def retry():
            self.retry_connection.setEnabled(False)
            try:
                await ensure_receiving(self.vault, self.hab, retry=True)
                self.vault.mbx.retry_receiving(self.hab.pre)
                self._generate_oobi('mailbox')
                self._refresh_receiving()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.receiving_status.setText(str(exc))
            finally:
                self._connection_task = None
                self.retry_connection.setEnabled(True)
        self._connection_task = asyncio.get_running_loop().create_task(retry())

    def _copy_contact_link(self):
        if prepare_messaging(self, self.app, self.hab, self._copy_contact_link, self.show_error):
            return
        result = habbing.generate_oobi(self.app, self.hab, role='mailbox')
        if result['success']:
            QApplication.clipboard().setText(result['oobi'])
            self.show_success('Contact link copied')
        else:
            self.show_error('No mailbox link is available. Share the introduction file instead.')

    def _share_introduction(self):
        if self.app.vault is self.vault and not getattr(self.vault, 'closed', False):
            export_identifier_to_cesr(self, self.app, self.identifier_alias)
