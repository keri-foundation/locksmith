# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.issued.list module

Issued credentials list content page (displayed within VaultPage container).
"""
from typing import Dict, Any, TYPE_CHECKING

from PySide6.QtGui import QPalette, QColor
from PySide6.QtWidgets import QVBoxLayout, QSizePolicy
from keri import help
from keri.core import SerderACDC

from locksmith.ui import colors
from locksmith.core import credentialing
from locksmith.ui.vault.credentials.presentation import credential_name, identifier_name, date_label, status_label
from locksmith.ui.toolkit.tables import PaginatedTableWidget
from locksmith.ui.vault.credentials.inventory import CredentialInventoryPage
from locksmith.ui.vault.credentials.issued.delete import DeleteIssuedCredentialDialog
from locksmith.ui.vault.credentials.issued.grant import GrantCredentialDialog
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from locksmith.ui.vault.credentials.issued.revoke import RevokeCredentialDialog
from locksmith.ui.vault.credentials.issued.view import ViewIssuedCredentialDialog

if TYPE_CHECKING:
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class IssuedCredentialsListPage(CredentialInventoryPage):
    """
    Issued credentials list content page.

    This is a content-only page that displays within the VaultPage container.
    The VaultPage manages the navigation menu.
    """

    inventory_events = {
        ('IssueCredentialDoer', 'credential_issued'),
        ('IssueCredentialDoer', 'credential_issuance_failed'),
        ('RevokeCredentialDoer', 'credential_revoked'),
        ('RevokeCredentialDoer', 'credential_revocation_failed'),
        ('DeleteIssuedCredential', 'credential_deleted'),
    }

    def __init__(self, parent: "VaultPage" = None):
        """
        Initialize the IssuedCredentialsListPage.

        Args:
            parent: Parent widget (VaultPage container)
        """
        super().__init__(parent)

        # Ensure widget fills parent
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Set background using palette instead of stylesheet for better control
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(colors.BACKGROUND_CONTENT))
        self.setPalette(palette)
        self.setAutoFillBackground(True)

        # Create table widget
        self.icon_path = ":/assets/material-icons/out-badge.svg"
        self.table = PaginatedTableWidget(
            columns=["Credential", "Recipient", "Status", "Created", "Actions"],
            column_widths={"Credential": 220, "Status": 110, "Created": 165, "Actions": 50},
            title="Issued Credentials",
            icon_path=self.icon_path,
            items_per_page=10,
            show_search=True,
            show_add_button=True,
            add_button_text="Issue Credential",
            row_actions=["View", "Offer", "Grant", "View exchange history", "Revoke", "Delete"],
            row_actions_callback=lambda row: (row['_actions'], self.table.row_action_icons),
            row_action_icons={
                "View": ":/assets/material-icons/view.svg",
                "Offer": ":/assets/material-icons/share.svg",
                "Grant": ":/assets/material-icons/send.svg",
                "View exchange history": ":/assets/material-icons/swap_horiz.svg",
                "Delete": ":/assets/material-icons/delete.svg"
            }
        )

        # Connect signals
        self.table.search_changed.connect(self._on_search)
        self.table.page_changed.connect(self._on_page_changed)
        self.table.sort_changed.connect(self._on_sort_changed)
        self.table.add_clicked.connect(self._on_issue_credential)
        self.table.row_action_triggered.connect(self._on_row_action)
        self.table.row_clicked.connect(self._on_row_clicked)

        main_layout.addWidget(self.table)

        logger.info("IssuedCredentialsListPage initialized with table widget")

    def _load_rows(self, *, reset_page=False):
        """
        Load issued credentials data from the opened vault.

        This method is called after a vault is opened and hby is available.
        """
        try:
            issued_credentials_data = []
            creds = credentialing.credentials(self.app.vault, received=False)

            pending = {}
            for (request, key), record in self.app.vault.db.pending_issuances.getTopItemIter():
                acdc = SerderACDC(raw=record.raw.encode())
                pending[acdc.said] = (request, key)
                if self.app.vault.db.issued.get((acdc.said,)) is None:
                    schemer = self.app.vault.hby.db.schema.get((acdc.schema,))
                    creds.append({'sad': acdc.sad, 'schema': schemer.sed if schemer else {},
                                  'recipient': record.recipient, 'status': {'et': 'pending'}, 'created_at': ''})
            for credential in creds:
                sad = credential['sad']
                schemer = credential.get("schema") or {}
                status = credential.get("status", {})
                status_text = status_label(status)
                recipient_name = identifier_name(self.app.vault, credential['recipient'])
                actions = ["View"]
                if status.get('et') in ('issued', 'authenticated'):
                    actions += ["Offer", "Grant"]
                actions.append("View exchange history")
                # Keep access to the existing retry path for a pending registry update.
                if sad.get('rd') and status.get('et') in ('issued', 'pending'):
                    actions.append("Revoke")
                actions.append("Delete")
                cred_dict = {
                    "Credential": credential_name(schemer),
                    "Recipient": recipient_name,
                    "Issuer": sad['i'],
                    "Status": status_text,
                    "Created": date_label(credential['created_at']),
                    "SAID": sad['d'],
                    "_actions": actions,
                }
                if sad['d'] in pending:
                    cred_dict['_pending_issuance'] = pending[sad['d']]
                    cred_dict['_actions'] = ['Resume issuance']
                issued_credentials_data.append(cred_dict)

            self._watch_signers(creds)
            self.table.set_static_data(issued_credentials_data, reset_page=reset_page)
            logger.info(f"Loaded {len(issued_credentials_data)} issued credentials")
        except Exception as e:
            logger.exception(f"Error loading issued credentials data: {e}")
            self.table.set_static_data([])

    def _on_issue_credential(self):
        """Handle issue credential button click."""
        logger.info("Issue credential clicked")
        dialog = IssueCredentialDialog(app=self.app, parent=self.parent)
        dialog.open()

    def _on_row_action(self, row_data: Dict[str, Any], action: str):
        """Handle row action from skewer menu."""
        credential_schema = row_data.get('Credential', 'Unknown')
        credential_recipient = row_data.get('Recipient', 'Unknown')
        credential_issuer = row_data.get('Issuer', 'Unknown')
        credential_said = row_data.get('SAID', '')
        logger.info(f"Row action '{action}' triggered for: {credential_schema} -> {credential_recipient}")

        if row_data.get('_pending_issuance') and action in ('View', 'Resume issuance'):
            request, key = row_data['_pending_issuance']
            dialog = IssueCredentialDialog(self.app, self.parent, request_said=None if request == 'direct' else request,
                                           resume=key)
            dialog.open()
        elif action == "View exchange history":
            self.parent.show_credential_activity(credential_said, received=False)
        elif action == "Offer":
            self.parent.start_credential_exchange('Offer', credential_said=credential_said)
        elif action == "View":
            # Open view credential dialog
            try:
                dialog = ViewIssuedCredentialDialog(
                    icon_path=self.icon_path,
                    app=self.app,
                    credential_said=credential_said,
                    parent=self.parent
                )
                dialog.open()
            except Exception as e:
                logger.exception(f"Error opening view dialog: {e}")
        elif action == "Grant":
            # Open grant credential dialog
            if not credential_said:
                logger.error("Credential SAID not found in row data")
                return

            try:
                dialog = GrantCredentialDialog(
                    app=self.app,
                    parent=self.parent,
                    credential_said=credential_said,
                    credential_schema=credential_schema,
                    credential_issuer=credential_issuer
                )
                dialog.open()
            except Exception as e:
                logger.exception(f"Error opening grant dialog: {e}")
        elif action == "Revoke":
            dialog = RevokeCredentialDialog(self.app, credential_said, credential_schema, parent=self.parent)
            dialog.open()
        elif action == "Delete":
            # Open delete confirmation dialog
            dialog = DeleteIssuedCredentialDialog(
                schema_name=credential_schema,
                said=credential_said,
                icon_path=self.icon_path,
                app=self.app,
                parent=self.parent
            )
            dialog.open()
        elif action == "Send":
            logger.info(f"Export issued credential: {credential_schema}")
        elif action == "Export":
            logger.info(f"Export issued credential: {credential_schema}")
        else:
            logger.info(f"Action '{action}' not yet implemented")
