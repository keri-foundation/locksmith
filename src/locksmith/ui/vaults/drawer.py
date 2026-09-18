# -*- encoding: utf-8 -*-
"""
locksmith.ui.home.vaults module

This module contains the VaultDrawer component for managing vaults.
"""
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal, QPropertyAnimation, QEasingCurve, QRect, QSize
from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import QWidget, QFrame, QVBoxLayout, QLabel, QGraphicsOpacityEffect, QHBoxLayout, \
    QListWidgetItem, QListWidget
from keri import help

from locksmith.ui import colors
from locksmith.ui.toolkit.utils import load_scaled_pixmap, create_spacer
from locksmith.ui.toolkit.widgets.fields import LocksmithLineEdit
from locksmith.ui.vaults.create import CreateVaultDialog
from locksmith.ui.vaults.open import OpenVaultDialog

if TYPE_CHECKING:
    from locksmith.ui.window import LocksmithWindow

logger = help.ogler.getLogger(__name__)

# Item data role holding each row's index in the unfiltered baseline order.
# The baseline is whatever order ``LocksmithApplication.environments()`` returns,
# so clearing the filter can restore it without re-reading the filesystem.
_BASELINE_INDEX_ROLE = Qt.ItemDataRole.UserRole


class VaultDrawer(QWidget):
    """
    Vault drawer that slides in from the right with overlay.
    Manages its own animation and state.
    """

    # Signals
    drawer_opened = Signal()
    drawer_closed = Signal()

    def __init__(self, parent: "LocksmithWindow", toolbar_ref):
        """
        Initialize the VaultDrawer.

        Args:
            parent: Parent window (needed for positioning).
            toolbar_ref: Reference to toolbar (needed for height calculations).
        """
        super().__init__(parent)

        self.parent = parent
        self.toolbar_ref = toolbar_ref
        self.drawer_visible = False
        self.drawer_width = 330
        self.app = self.parent.app
        self._overlay_animation_connected = False  # Track connection state
        self._filter_active = False  # Track filter transitions for logging only

        # Create components
        self._create_overlay()
        self._create_drawer_widget()

    def _create_overlay(self):
        """Create a semi-transparent overlay that appears behind the drawer."""
        self.drawer_overlay = QFrame(self.parent)
        self.drawer_overlay.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
            }
        """)
        self.drawer_overlay.hide()

        # Ensure overlay stays below toolbar
        self.drawer_overlay.setWindowFlag(Qt.WindowType.SubWindow)

        # Make overlay clickable to close drawer
        self.drawer_overlay.mousePressEvent = lambda event: self.toggle()

        # Position overlay to cover everything except toolbar
        toolbar_height = self.toolbar_ref.height()
        self.drawer_overlay.setGeometry(
            0,
            toolbar_height,
            self.parent.width(),
            self.parent.height() - toolbar_height
        )

        # Create opacity effect for fade animation
        self.overlay_opacity = QGraphicsOpacityEffect(self.drawer_overlay)
        self.drawer_overlay.setGraphicsEffect(self.overlay_opacity)

        # Create fade animation
        self.overlay_animation = QPropertyAnimation(self.overlay_opacity, b"opacity")
        self.overlay_animation.setDuration(300)  # Match drawer animation duration
        self.overlay_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _create_drawer_widget(self):
        """Create the vault drawer that slides in from the right."""
        # Create drawer widget
        self.vault_drawer = QFrame(self.parent)
        self.vault_drawer.setStyleSheet(f"""
            QFrame {{
                background-color: {colors.BACKGROUND_WINDOW};
                border-top-left-radius: 16px;
                border-bottom-left-radius: 16px;
            }}
            QFrame#vault-header-divider {{
                background-color: {colors.DIVIDER};
                max-height: 3px;
            }}
        """)

        # Drawer layout
        drawer_layout = QVBoxLayout(self.vault_drawer)
        drawer_layout.setContentsMargins(0, 16, 0, 16)
        drawer_layout.setSpacing(0)

        # Title
        drawer_header_layout = QHBoxLayout()
        drawer_header_layout.addWidget(create_spacer(12))
        drawer_header_layout.setContentsMargins(10, 10, 16, 10)
        drawer_header_layout.setSpacing(10)


        favicon_label = QLabel()
        favicon_pixmap = load_scaled_pixmap(":/assets/custom/SymbolLogo.svg", 36, 36)
        favicon_label.setPixmap(favicon_pixmap)
        drawer_header_layout.addWidget(favicon_label)

        title_label = QLabel("Vaults")
        title_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {colors.TEXT_PRIMARY};")
        drawer_header_layout.addWidget(title_label)
        drawer_header_layout.addStretch()
        drawer_layout.addLayout(drawer_header_layout)

        # Add a horizontal divider
        divider = QFrame()
        divider.setObjectName("vault-header-divider")
        divider.setFrameShape(QFrame.Shape.HLine)
        drawer_layout.addWidget(divider)

        # Search filter, between the header divider and "Initialize New Vault"
        search_row = QHBoxLayout()
        search_row.setContentsMargins(12, 8, 12, 12)
        self.search_field = LocksmithLineEdit(
            placeholder_text="Search vaults",
            leading_icon=":/assets/material-icons/search.svg",
        )
        self.search_field.setClearButtonEnabled(True)
        self.search_field.textChanged.connect(self._filter_vaults)
        search_row.addWidget(self.search_field)
        drawer_layout.addLayout(search_row)

        # New vault button in its own list widget with custom styling
        new_vault_button_container = QListWidget()
        new_vault_button_container.setObjectName("new-vault-button-container")
        new_vault_button_container.setIconSize(QSize(30, 30))
        new_vault_button_container.setStyleSheet(f"""
            QListWidget {{
                border: none;
                background: transparent;
            }}
            QListWidget::item {{
                border-radius: 8px;
                padding: 10px;
                padding-left: 6px;
            }}
            QListWidget::item:hover {{
                background-color: {colors.BACKGROUND_COLLAPSIBLE_HOVER};
            }}

        """)
        new_vault_button = QListWidgetItem(QIcon(":/assets/material-icons/add.svg"), "Initialize New Vault")
        new_vault_button_font = QFont()
        new_vault_button_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1)
        new_vault_button_font.setPointSize(16)
        new_vault_button.setFont(new_vault_button_font)
        new_vault_button_container.addItem(new_vault_button)
        new_vault_button_container.setFixedHeight(54)  # icon(36) + padding(24*2) + spacing(10)
        new_vault_button_container.setCursor(Qt.CursorShape.PointingHandCursor)
        new_vault_button_container.clicked.connect(self.show_create_vault_dialog)
        drawer_layout.addWidget(new_vault_button_container)


        # Create vault list widget (store as instance variable for refreshing)
        self.vault_list = QListWidget()
        self.vault_list.setIconSize(QSize(36, 36))
        self.vault_list.setCursor(Qt.CursorShape.PointingHandCursor)
        self.vault_list.setStyleSheet(f"""
            QListWidget {{
                border: none;
                background: transparent;
            }}
            QListWidget::item {{
                padding: 12px;
                padding-left: 24px;
                border-radius: 8px;
            }}
            QListWidget::item:hover {{
                background-color: {colors.BACKGROUND_COLLAPSIBLE_HOVER};
            }}
        """)

        self.vault_list.itemClicked.connect(self._on_vault_item_clicked)

        # Filter empty state. It replaces the vault list only; the
        # "Initialize New Vault" action above stays available.
        # PlainText so unusual search input is shown literally, never as markup.
        self.empty_state_label = QLabel("")
        self.empty_state_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state_label.setTextFormat(Qt.TextFormat.PlainText)
        self.empty_state_label.setWordWrap(True)
        self.empty_state_label.setStyleSheet(
            f"color: {colors.TEXT_SECONDARY}; font-size: 14px; padding: 24px 16px;"
        )
        self.empty_state_label.hide()
        drawer_layout.addWidget(self.empty_state_label)

        # Populate vault list
        self._refresh_vault_list()

        drawer_layout.addWidget(self.vault_list)


        # Set drawer dimensions
        self.vault_drawer.setFixedWidth(self.drawer_width)

        # Position drawer off-screen to the right initially
        window_width = self.parent.width()
        window_height = self.parent.height()
        toolbar_height = self.toolbar_ref.height()

        self.vault_drawer.setGeometry(
            window_width,  # Start off-screen to the right
            toolbar_height,
            self.drawer_width,
            window_height - toolbar_height
        )

        # Create animation for sliding
        self.drawer_animation = QPropertyAnimation(self.vault_drawer, b"geometry")
        self.drawer_animation.setDuration(300)  # 300ms animation
        self.drawer_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Show the drawer widget (but positioned off-screen)
        self.vault_drawer.show()

    def toggle(self):
        """Toggle drawer open/closed with animations."""
        window_width = self.parent.width()
        window_height = self.parent.height()
        toolbar_height = self.toolbar_ref.height()

        # Disconnect previous animation handler if connected
        if self._overlay_animation_connected:
            self.overlay_animation.finished.disconnect()
            self._overlay_animation_connected = False

        if self.drawer_visible:
            # Slide out (hide)
            start_rect = QRect(
                window_width - self.drawer_width,
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )
            end_rect = QRect(
                window_width,  # Off screen to the right
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )
            self.drawer_visible = False

            # Fade out overlay
            self.overlay_animation.setStartValue(1.0)
            self.overlay_animation.setEndValue(0.0)

            # Hide overlay after animation completes
            self.overlay_animation.finished.connect(self.drawer_overlay.hide)
            self._overlay_animation_connected = True
            self.overlay_animation.start()

            # Emit signal
            self.drawer_closed.emit()
        else:
            # Slide in (show)
            start_rect = QRect(
                window_width,
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )
            end_rect = QRect(
                window_width - self.drawer_width,  # On screen
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )
            self.drawer_visible = True

            # Every open starts from a clean filter. This runs before the drawer
            # becomes visible so the user never sees the previous query applied.
            self._reset_filter()

            # Show overlay and fade in
            self.drawer_overlay.show()
            self.drawer_overlay.raise_()  # Bring overlay to front

            # Ensure toolbar stays on top
            self.toolbar_ref.raise_()

            self.vault_drawer.raise_()    # Bring drawer above overlay

            self.overlay_animation.setStartValue(0.0)
            self.overlay_animation.setEndValue(1.0)
            self.overlay_animation.start()

            # Emit signal
            self.drawer_opened.emit()

        self.drawer_animation.setStartValue(start_rect)
        self.drawer_animation.setEndValue(end_rect)
        self.drawer_animation.start()

    def handle_resize(self, window_width: int, window_height: int, toolbar_height: int):
        """
        Reposition drawer and overlay on window resize.

        Args:
            window_width: Current window width.
            window_height: Current window height.
            toolbar_height: Current toolbar height.
        """
        # Update overlay size
        self.drawer_overlay.setGeometry(
            0,
            toolbar_height,
            window_width,
            window_height - toolbar_height
        )

        if self.drawer_visible:
            # Drawer is visible, keep it on screen
            self.vault_drawer.setGeometry(
                window_width - self.drawer_width,
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )
        else:
            # Drawer is hidden, keep it off screen
            self.vault_drawer.setGeometry(
                window_width,
                toolbar_height,
                self.drawer_width,
                window_height - toolbar_height
            )

    def is_visible(self) -> bool:
        """
        Check if drawer is currently visible.

        Returns:
            True if drawer is visible, False otherwise.
        """
        return self.drawer_visible

    def hide_drawer_widgets(self):
        """
        Hide the drawer and overlay widgets completely.
        Used when navigating away from pages that use the drawer.
        """
        # Close the drawer if it's open
        if self.drawer_visible:
            self.toggle()

        # Explicitly hide the drawer widgets
        self.drawer_overlay.hide()
        self.vault_drawer.hide()

    def show_drawer_widgets(self):
        """
        Show the drawer widgets (but keep drawer closed).
        Used when navigating to pages that use the drawer.
        """
        # Navigation-level re-entry: start from a clean filter state, then
        # refresh the list to pick up any changes (e.g., deleted vaults).
        self._reset_filter()
        self._refresh_vault_list()
        
        # Don't show overlay (it's only shown when drawer is toggled open)
        # But show the drawer frame (positioned off-screen, ready to slide in)
        self.vault_drawer.show()

    def _refresh_vault_list(self):
        """
        Rebuild the vault list from the application's environment list.

        The order returned by ``self.app.environments()`` is the baseline order.
        Each row records its baseline index so an inactive filter can restore
        that exact order without re-reading the filesystem.
        """
        self.vault_list.clear()

        vault_font = QFont()
        vault_font.setPointSize(15)

        for baseline_index, vault_name in enumerate(self.app.environments()):
            vault_item = QListWidgetItem(QIcon(":/assets/custom/vault.png"), vault_name)
            vault_item.setFont(vault_font)
            vault_item.setData(_BASELINE_INDEX_ROLE, baseline_index)
            self.vault_list.addItem(vault_item)

        # Re-apply the active filter so an add or delete cannot desync the
        # visible list while the drawer stays open.
        query = self.search_field.text() if hasattr(self, "search_field") else ""
        self._filter_vaults(query)

    def _reset_filter(self):
        """
        Clear the search field and restore the unfiltered list.

        This is the drawer's real open transition. ``QLineEdit.clear()`` emits
        ``textChanged`` synchronously, so list order and the empty state are
        restored before the drawer scrolls into view.

        Note: ``show_drawer_widgets()`` is a separate navigation-level lifecycle
        method. It is not the path a toolbar close/reopen takes, so it must not
        be the only place the filter is cleared.
        """
        if not hasattr(self, "search_field"):
            return
        if self.search_field.text():
            self.search_field.clear()
        else:
            self._filter_vaults("")

    def _filter_vaults(self, query: str):
        """
        Apply ``query`` to the vault list.

        Matching is a case-insensitive substring test on the vault name. Prefix
        matches are ordered above other substring matches, and each group is
        ordered alphabetically. Rows that do not match stay in the model but are
        hidden, so the baseline order is always recoverable.

        The query is used exactly as typed: no whitespace stripping and no other
        normalisation, because the contract is substring matching.

        This operates on the already-loaded rows and never touches the
        filesystem.
        """
        if not hasattr(self, "search_field"):
            return

        needle = query.casefold()
        total = self.vault_list.count()

        ranked: list[tuple[int, str, int, QListWidgetItem]] = []
        for position in range(total):
            item = self.vault_list.item(position)
            folded = item.text().casefold()
            baseline_index = item.data(_BASELINE_INDEX_ROLE)
            if baseline_index is None:
                baseline_index = position

            if not needle or folded.startswith(needle):
                rank = 0  # prefix match, or inactive filter (everything matches)
            elif needle in folded:
                rank = 1  # substring-only match
            else:
                rank = 2  # no match
            ranked.append((rank, folded, baseline_index, item))

        matching = [entry for entry in ranked if entry[0] != 2]
        non_matching = [entry for entry in ranked if entry[0] == 2]

        if needle:
            matching.sort(key=lambda entry: (entry[0], entry[1]))
        else:
            matching.sort(key=lambda entry: entry[2])
        non_matching.sort(key=lambda entry: entry[2])

        self.vault_list.blockSignals(True)
        for position in range(self.vault_list.count() - 1, -1, -1):
            self.vault_list.takeItem(position)
        for _rank, _folded, _baseline_index, item in matching:
            self.vault_list.addItem(item)
            item.setHidden(False)
        for _rank, _folded, _baseline_index, item in non_matching:
            self.vault_list.addItem(item)
            item.setHidden(True)
        self.vault_list.blockSignals(False)

        self._set_empty_state(query, len(matching))
        self._log_filter_state(needle, len(matching), total)

    def _set_empty_state(self, query: str, match_count: int):
        """
        Show the no-match message in place of the vault list.

        The message replaces the list only. The "Initialize New Vault" action is
        a separate widget and deliberately stays visible.
        """
        if query and match_count == 0:
            self.empty_state_label.setText(f"No vaults match '{query}'")
            self.vault_list.hide()
            self.empty_state_label.show()
        else:
            self.empty_state_label.hide()
            self.vault_list.show()

    def _log_filter_state(self, needle: str, match_count: int, total: int):
        """
        Log filter state transitions, not keystrokes.

        INFO is reserved for a meaningful transition (filter enabled, filter
        cleared). The user's query text is never written to the log, and typing
        further characters while the filter is already active produces no INFO
        record, so a keystroke cannot leak the search text or flood the log.
        """
        active = bool(needle)
        if active and not self._filter_active:
            logger.info(f"Vault drawer filter enabled: matches={match_count} total={total}")
        elif not active and self._filter_active:
            logger.info(f"Vault drawer filter cleared: total={total}")
        self._filter_active = active
        logger.debug(f"Vault drawer filter applied: active={active} matches={match_count} total={total}")

    def show_create_vault_dialog(self):
        """Show the vault creation dialog."""
        dialog = CreateVaultDialog(parent=self.parent, config=self.app.config, app=self.app)

        # Connect the vault_created signal to refresh the list (persistent vaults)
        dialog.vault_created.connect(self._on_vault_created)
        # Connect the vault_opened signal for temp vaults (auto-navigate)
        dialog.vault_opened.connect(self._on_vault_opened)

        dialog.show()

    def _on_vault_item_clicked(self, item: QListWidgetItem):
        """
        Handle vault item click.

        Args:
            item: The clicked QListWidgetItem
        """
        vault_name = item.text()
        logger.info(f"Vault item clicked: {vault_name}")
        self.show_open_vault_dialog(vault_name)

    def show_open_vault_dialog(self, vault_name: str):
        """
        Show the open vault dialog.

        Args:
            vault_name: Name of the vault to open
        """
        dialog = OpenVaultDialog(
            vault_name=vault_name,
            parent=self.parent,
            config=self.app.config,
        )

        # Connect vault_opened signal to close drawer and navigate
        dialog.vault_opened.connect(self._on_vault_opened)

        dialog.show() # Using show here to avoid overlay

    def _on_vault_opened(self, vault_name: str):
        """
        Handle vault opening completion.

        Args:
            vault_name (str): Name of the opened vault
        """

        # Close the drawer
        if self.is_visible():
            self.toggle()

        self.parent.setWindowTitle(f"Locksmith | {vault_name}")

        # Navigate to vault page
        from locksmith.ui.navigation import Pages
        self.parent.nav_manager.navigate_to(Pages.VAULT, vault_name=vault_name)

    def _on_vault_created(self, vault_name: str):
        """
        Handle vault creation completion.

        Args:
            vault_name (str): Name of the newly created vault
        """
        # Refresh the vault list
        self._refresh_vault_list()

        # Automatically open the login dialog for the newly created vault
        self.show_open_vault_dialog(vault_name)