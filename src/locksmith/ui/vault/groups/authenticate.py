# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.groups.authenticate module

Dialog for authenticating witnesses during group identifier rotation
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout
)
from keri import help

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.vault.shared.witness_auth_mixin import (
    WitnessAuthenticationMixin,
    witness_auth_dialog_height
)

logger = help.ogler.getLogger(__name__)


class GroupWitnessAuthenticationDialog(WitnessAuthenticationMixin, LocksmithDialog):
    """Dialog for authenticating witnesses during rotation."""

    def __init__(self, app, hab, witness_ids: list[str], auth_only=False, parent=None):
        """
        Initialize the GroupWitnessAuthenticationDialog.

        Args:
            app: Application instance
            hab: The hab that was rotated
            witness_ids: List of witness IDs requiring authentication
            auth_only: If True, this is a retry (not part of rotation)
            parent: Parent widget
        """
        self.app = app
        self.hab = hab
        self.witness_ids = witness_ids
        self.auth_only = auth_only
        self.passcode_fields = {}  # Maps witness_id or batch_key -> FloatingLabelLineEdit
        self.witness_info = {}  # Maps witness_id -> witness record dict
        self.batch_groups = []  # List of (batch_label, [witness_ids]) for batch auth
        self.individual_witnesses = []  # List of witness_ids for individual auth
        self._signals_connected = False

        # Look up witness information (aliases) from org contacts
        self._load_witness_info()

        # Organize witnesses into batches and individuals
        self._organize_witnesses_by_batch()

        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(20, 10, 20, 0)
        layout.setSpacing(15)
        layout.addSpacing(10)
        self._build_witness_fields(layout)

        layout.addStretch()

        # Create button row
        button_row = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton("Cancel")
        self.cancel_button.clicked.connect(self.close)

        # Change button text based on mode
        button_text = "Authenticate" if self.auth_only else "Rotate"
        self.rotate_button = LocksmithButton(button_text)

        button_row.addWidget(self.cancel_button)
        button_row.addSpacing(10)
        button_row.addWidget(self.rotate_button)

        # Create title content
        title_content_widget = QWidget()
        title_content = QHBoxLayout()
        icon = QIcon(":/assets/custom/identifiers.png")
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        title_content.addWidget(icon_label)

        title_label = QLabel("  Authenticate Witnesses")
        title_label.setStyleSheet("font-size: 16px;")
        title_content.addWidget(title_label)
        title_content_widget.setLayout(title_content)

        super().__init__(
            parent=parent,
            title_content=title_content_widget,
            show_close_button=True,
            content=content_widget,
            buttons=button_row
        )

        self.rotate_button.clicked.connect(self._on_rotate)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.setFixedSize(700, witness_auth_dialog_height(self.individual_witnesses, self.batch_groups))

        # Connect to vault signal bridge for doer events
        if hasattr(self.app, 'vault') and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            self._signals_connected = True

        self.finished.connect(self._cleanup_signal_connection)

    def _cleanup_signal_connection(self):
        self._set_auth_submit_enabled(True)
        if not self._signals_connected:
            return

        if hasattr(self.app, 'vault') and hasattr(self.app.vault, 'signals'):
            try:
                self.app.vault.signals.doer_event.disconnect(self._on_doer_event)
            except RuntimeError:
                pass
        self._signals_connected = False

    def closeEvent(self, event):
        self._cleanup_signal_connection()
        super().closeEvent(event)

    async def _check_and_spawn_keystate_update(self):
        """
        Check if the rotated identifier needs keystate update via plugin hooks.
        """
        if hasattr(self.app, 'plugin_manager') and self.app.plugin_manager:
            await self.app.plugin_manager.after_identifier_authenticated(self.app.vault, self.hab)

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """
        Handle doer events from the signal bridge.

        Args:
            doer_name: Name of the doer that emitted the event
            event_type: Type of event
            data: Event data dictionary
        """
        logger.info(f"GroupWitnessAuthenticationDialog received doer_event: {doer_name} - {event_type}")

        if doer_name == "AuthenticateWitnessesDoer":
            # Only handle events for this identifier
            if data.get('pre') == self.hab.pre:
                if event_type == "witness_authentication_success":
                    logger.info(f"Witness authentication succeeded for {data.get('alias')}")

                    # Check if keystate update is needed via plugins
                    import asyncio
                    asyncio.ensure_future(self._check_and_spawn_keystate_update())

                    # Close dialog on success
                    self.accept()

                elif event_type == "witness_authentication_failed":
                    error_msg = data.get('error', 'Authentication failed')
                    logger.error(f"Witness authentication failed: {error_msg}")
                    self._set_auth_submit_enabled(True)
                    # Show error and keep dialog open for retry
                    self.show_error(error_msg)
