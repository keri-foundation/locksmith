# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.groups.accept_rotation module

Dialog for accepting multisig group rotation proposals.
"""
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QScrollArea,
    QFrame
)
from keri import help
from keri.help import helping
from keri.peer import exchanging
from keri.core.serdering import SerderKERI

from locksmith.core import rotating
from locksmith.core.grouping import MultisigRotationJoinDoer
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.shared.display_helpers import resolve_alias, add_info_row
from locksmith.ui.vault.shared.witness_auth_mixin import (
    WitnessAuthenticationPanel,
    witness_auth_dialog_height
)

if TYPE_CHECKING:
    from locksmith.core.apping import LocksmithApplication
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class AcceptMultisigRotationDialog(LocksmithDialog):
    """Dialog for accepting multisig group rotation proposals.

    Displays the rotation proposal details including participants,
    thresholds, and witness changes. Allows selection of local
    identifier for signing, then joins the rotation.
    """

    def __init__(
        self,
        app: "LocksmithApplication",
        parent: "VaultPage",
        proposal_said: str
    ):
        """
        Initialize the AcceptMultisigRotationDialog.

        Args:
            app: Application instance
            parent: Parent widget (VaultPage)
            proposal_said: SAID of the rotation proposal exn message
        """
        self.app = app
        self.parent_widget = parent
        self.proposal_said = proposal_said
        self._auth_panel = None
        self._auth_hab = None
        self._workflow_mode = "join"
        self._signals_connected = False

        # Load proposal message data
        try:
            self._load_proposal_message()
        except Exception as e:
            logger.exception(f"Failed to load rotation proposal: {e}")
            self.proposal_error = str(e)
            self._build_error_ui()
            return

        # Build the dialog UI
        self._build_ui()

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Join Multisig Rotation",
            title_icon=":/assets/material-icons/rotate_right.svg",
            content=self.proposal_scroll_area,
            buttons=self.button_row,
            show_overlay=False
        )

        self.setFixedSize(550, 880)

        # Connect signals
        self.cancel_button.clicked.connect(self.close)
        self.accept_button.clicked.connect(self._on_primary_clicked)

        # Connect to vault signal bridge for doer events
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            self._signals_connected = True
        self.finished.connect(self._on_dialog_finished)

    def _cleanup_signal_connection(self):
        if not self._signals_connected:
            return

        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            try:
                self.app.vault.signals.doer_event.disconnect(self._on_doer_event)
            except RuntimeError:
                pass
        self._signals_connected = False

    def _on_dialog_finished(self, _result):
        self._cleanup_signal_connection()

    def closeEvent(self, event):
        self._cleanup_signal_connection()
        super().closeEvent(event)

    def _on_primary_clicked(self):
        if self._workflow_mode == "auth":
            self._submit_auth_step()
        else:
            self._on_accept()

    def _show_auth_step(self, hab, witness_ids: list[str]):
        self.clear_error()
        self.clear_success()

        if self._auth_panel is not None:
            self.content_layout.removeWidget(self._auth_panel)
            self._auth_panel.setParent(None)
            self._auth_panel.deleteLater()

        self.proposal_scroll_area.hide()
        self._auth_hab = hab
        self._auth_panel = WitnessAuthenticationPanel(
            app=self.app,
            hab=hab,
            witness_ids=witness_ids,
            parent=self
        )
        self.content_layout.addWidget(self._auth_panel)

        self._workflow_mode = "auth"
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.cancel_button.setText("Close")
        self.cancel_button.setEnabled(True)
        self.accept_button.setText("Authenticate")
        self.accept_button.setEnabled(True)
        self.setFixedSize(700, self._auth_step_height())
        self.center_on_parent()

    def _auth_step_height(self) -> int:
        if self._auth_panel is None:
            return 440

        return witness_auth_dialog_height(
            self._auth_panel.individual_witnesses,
            self._auth_panel.batch_groups
        )

    def _submit_auth_step(self):
        if self._auth_panel is None or self._auth_hab is None:
            self.close()
            return

        self.clear_error()
        valid, codes, error_message = self._auth_panel.validate_authentication_codes()
        if not valid:
            self.show_error(error_message)
            return

        self.accept_button.setEnabled(False)
        self.accept_button.setText("Authenticating...")
        self.cancel_button.setEnabled(False)
        rotating.authenticate_witnesses(self.app, self._auth_hab, codes)

    def _set_auth_button_idle(self):
        self.cancel_button.setEnabled(True)
        self.accept_button.setEnabled(True)
        self.accept_button.setText("Authenticate")

    async def _check_and_spawn_keystate_update(self):
        if hasattr(self.app, 'plugin_manager') and self.app.plugin_manager and self._auth_hab is not None:
            await self.app.plugin_manager.after_identifier_authenticated(self.app.vault, self._auth_hab)

    def _load_proposal_message(self):
        """Load rotation proposal message using exchanging.cloneMessage()."""
        logger.info(f"Loading rotation proposal: {self.proposal_said}")

        self.exn, self.pathed = exchanging.cloneMessage(self.app.vault.hby, self.proposal_said)

        if self.exn is None:
            raise ValueError(f"Proposal message not found: {self.proposal_said}")

        # Validate it's a multisig rotation proposal
        route = self.exn.ked.get('r', '')
        if '/multisig/rot' not in route:
            raise ValueError(f"Not a multisig rotation proposal, route: {route}")

        logger.debug(f"Rotation proposal loaded: {self.exn.ked}")

        # Extract proposal metadata
        self.initiator = self.exn.ked['i']
        self.timestamp = self.exn.ked.get('dt', '')

        # Extract payload
        payload = self.exn.ked.get('a', {})
        self.gid = payload.get('gid', '')
        self.smids = payload.get('smids', [])
        self.rmids = payload.get('rmids', self.smids)

        # Get rotation event from embeds
        embeds = self.exn.ked.get('e', {})
        rot_sad = embeds.get('rot')
        if rot_sad is None:
            raise ValueError("No rotation event found in proposal")

        self.rot_serder = SerderKERI(sad=rot_sad)
        self.group_pre = self.rot_serder.ked.get('i', '')
        self.next_sn = self.rot_serder.sn
        self.isith = self.rot_serder.ked.get('kt', '1')
        self.nsith = self.rot_serder.ked.get('nt', self.isith)
        self.toad = self.rot_serder.ked.get('bt', '0')
        self.witness_adds = self.rot_serder.ked.get('ba', [])
        self.witness_cuts = self.rot_serder.ked.get('br', [])

        # Check if the group already exists locally
        self.group_exists = self.group_pre in self.app.vault.hby.habs
        if self.group_exists:
            self.ghab = self.app.vault.hby.habs[self.group_pre]
            self.current_sn = self.ghab.kever.sn
        else:
            self.ghab = None
            self.current_sn = self.next_sn - 1

        # Find local identifiers that are participants
        self.local_smids = []
        for pre, hab in self.app.vault.hby.habs.items():
            if hab.pre in self.smids or hab.pre in self.rmids:
                self.local_smids.append({'alias': hab.name, 'pre': hab.pre})

        if not self.local_smids:
            raise ValueError("None of your local identifiers are participants in this rotation")

        logger.info(f"Rotation proposal for group {self.group_pre[:16]}... "
                    f"SN {self.current_sn} -> {self.next_sn} with {len(self.smids)} participants")

    def _build_ui(self):
        """Build the dialog UI."""
        # Create scroll area for content
        self.proposal_scroll_area = QScrollArea()
        self.proposal_scroll_area.setWidgetResizable(True)
        self.proposal_scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.proposal_scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)

        # Proposal Information Section
        info_section_label = QLabel("Rotation Proposal")
        info_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(info_section_label)

        # Initiator
        initiator_alias = resolve_alias(self.app,self.initiator)
        initiator_display = initiator_alias if initiator_alias else f"{self.initiator[:24]}..."
        add_info_row(content_layout, "From:", initiator_display, label_width=150)

        # Timestamp
        if self.timestamp:
            try:
                ts_dt = helping.fromIso8601(self.timestamp)
                timestamp_display = ts_dt.strftime("%b %d, %Y %I:%M %p")
            except Exception:
                timestamp_display = self.timestamp
            add_info_row(content_layout, "Received:", timestamp_display, label_width=150)

        # Group prefix
        add_info_row(content_layout, "Group ID:", f"{self.group_pre[:32]}...", label_width=150)

        # Sequence number
        add_info_row(content_layout, "Sequence:", f"{self.current_sn} -> {self.next_sn}", label_width=150)

        content_layout.addSpacing(10)

        # Rotation Details Section
        details_section_label = QLabel("Rotation Details")
        details_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(details_section_label)

        add_info_row(content_layout, "Signing Threshold:", str(self.isith), label_width=150)
        add_info_row(content_layout, "Rotation Threshold:", str(self.nsith), label_width=150)
        add_info_row(content_layout, "TOAD:", str(self.toad), label_width=150)

        if self.witness_adds:
            add_info_row(content_layout, "Witnesses Added:", str(len(self.witness_adds)), label_width=150)
        if self.witness_cuts:
            add_info_row(content_layout, "Witnesses Removed:", str(len(self.witness_cuts)), label_width=150)

        content_layout.addSpacing(10)

        # Signing Members Section
        smids_section_label = QLabel("Signing Members")
        smids_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(smids_section_label)

        for i, smid in enumerate(self.smids):
            alias = resolve_alias(self.app, smid)
            is_local = any(l['pre'] == smid for l in self.local_smids)
            suffix = " (You)" if is_local else ""
            display = f"{alias}{suffix}" if alias else f"{smid[:20]}...{suffix}"
            add_info_row(content_layout, f"Member {i+1}:", display, label_width=150)

        # Rotation Members Section (only if different from smids)
        if self.rmids != self.smids:
            content_layout.addSpacing(10)
            rmids_section_label = QLabel("Rotation Members")
            rmids_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
            content_layout.addWidget(rmids_section_label)

            for i, rmid in enumerate(self.rmids):
                alias = resolve_alias(self.app, rmid)
                is_local = any(l['pre'] == rmid for l in self.local_smids)
                suffix = " (You)" if is_local else ""
                display = f"{alias}{suffix}" if alias else f"{rmid[:20]}...{suffix}"
                add_info_row(content_layout, f"Member {i+1}:", display, label_width=150)

        content_layout.addSpacing(20)

        # Local Identifier Selection Section
        local_id_section_label = QLabel("Select Your Identifier")
        local_id_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(local_id_section_label)

        local_id_note = QLabel("Select the local identifier to sign this rotation.")
        local_id_note.setStyleSheet(f"color: {colors.TEXT_MUTED}; font-size: 13px;")
        local_id_note.setWordWrap(True)
        local_id_note.setFixedWidth(400)
        content_layout.addWidget(local_id_note)

        self.local_id_dropdown = FloatingLabelComboBox("Local Identifier")
        self.local_id_dropdown.setFixedWidth(400)

        for item in self.local_smids:
            self.local_id_dropdown.addItem(f"{item['alias']} ({item['pre'][:16]}...)", item)

        content_layout.addWidget(self.local_id_dropdown)

        content_layout.addStretch()

        self.proposal_scroll_area.setWidget(content_widget)

        # Button row
        self.button_row = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton("Close")
        self.button_row.addWidget(self.cancel_button)
        self.button_row.addSpacing(10)
        self.accept_button = LocksmithButton("Join")
        self.button_row.addWidget(self.accept_button)

    def _build_error_ui(self):
        """Build error UI when proposal loading fails."""
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)

        error_label = QLabel(f"Error loading rotation proposal:\n\n{self.proposal_error}")
        error_label.setStyleSheet(f"color: {colors.DANGER};")
        error_label.setWordWrap(True)
        content_layout.addWidget(error_label)
        content_layout.addStretch()

        # Create scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(content_widget)

        # Button row
        self.button_row = QHBoxLayout()
        close_button = LocksmithInvertedButton("Close")
        close_button.clicked.connect(self.close)
        self.button_row.addWidget(close_button)

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Error",
            content=self.scroll_area,
            buttons=self.button_row,
            show_overlay=False
        )

        self.setFixedSize(400, 250)

    def _on_accept(self):
        """Handle accept button click - join the multisig rotation."""
        logger.info("Accepting rotation proposal...")

        # Get selected local identifier
        mhab_data = self.local_id_dropdown.currentData()
        if not mhab_data:
            logger.error("No local identifier selected")
            return

        mhab_alias = mhab_data.get('alias')
        mhab = self.app.vault.hby.habByName(mhab_alias)

        if not mhab:
            logger.error(f"Could not find local identifier: {mhab_alias}")
            return

        # Disable buttons during processing
        self.accept_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.accept_button.setText("Joining...")

        # Create and launch MultisigRotationJoinDoer
        try:
            join_doer = MultisigRotationJoinDoer(
                app=self.app,
                proposal_said=self.proposal_said,
                mhab=mhab,
                signal_bridge=self.app.vault.signals
            )
            self.app.vault.extend([join_doer])
            logger.info(f"MultisigRotationJoinDoer started for proposal {self.proposal_said}")

        except Exception as e:
            logger.exception(f"Failed to start MultisigRotationJoinDoer: {e}")
            self.accept_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.accept_button.setText("Join")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """Handle doer events from the signal bridge."""
        if doer_name not in ("MultisigRotationJoinDoer", "AuthenticateWitnessesDoer"):
            return

        logger.info(f"AcceptMultisigRotationDialog received: {event_type} - {data}")

        if doer_name == "AuthenticateWitnessesDoer":
            if self._auth_hab is None or data.get('pre') != self._auth_hab.pre:
                return

            if event_type == "witness_authentication_success":
                logger.info(f"Witness authentication succeeded for {data.get('alias')}")
                import asyncio
                asyncio.ensure_future(self._check_and_spawn_keystate_update())
                self.accept()

            elif event_type == "witness_authentication_failed":
                error_msg = data.get('error', 'Authentication failed')
                logger.error(f"Witness authentication failed: {error_msg}")
                self._set_auth_button_idle()
                self.show_error(error_msg)

            return

        if event_type == "group_rotation_joined":
            logger.info(f"Successfully joined rotation: {data.get('alias')} ({data.get('pre')})")

            # Check if witnesses need authentication
            if data.get('needs_witness_auth'):
                shared_witnesses = data.get('shared_witnesses', [])
                logger.info(f"Showing authentication step for {len(shared_witnesses)} shared witnesses")

                # Get the group hab for witness auth
                ghab = self.app.vault.hby.habs.get(data.get('pre'))
                if ghab:
                    self._show_auth_step(ghab, shared_witnesses)
                else:
                    self.accept()
            else:
                self.accept()

        elif event_type == "group_rotation_join_failed":
            logger.error(f"Failed to join rotation: {data.get('error')}")
            self.accept_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.accept_button.setText("Join")
