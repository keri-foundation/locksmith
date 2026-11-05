from types import SimpleNamespace
from unittest.mock import patch

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QWidget

from locksmith.ui.toolkit.widgets import LocksmithDialog
from locksmith.ui.vaults import open as open_module
from locksmith.ui.vaults.open import OpenVaultDialog


def test_child_dialog_returns_to_parent_and_unrelated_dialog_replaces_stack(qapp):
    parent = LocksmithDialog()
    child = LocksmithDialog(parent)
    grandchild = LocksmithDialog(child)
    unrelated = LocksmithDialog()
    try:
        parent.open()
        child.open()
        qapp.processEvents()
        assert parent.isVisible() and child.isVisible()
        for dialog in (parent, child):
            assert dialog.windowType() == Qt.WindowType.Dialog
            assert dialog.windowFlags() & Qt.WindowType.FramelessWindowHint
            assert dialog.windowOpacity() == 1.0

        child.reject()
        qapp.processEvents()
        assert parent.isVisible() and not child.isVisible()
        child.open()
        grandchild.open()
        qapp.processEvents()
        assert parent.isVisible() and child.isVisible() and grandchild.isVisible()
        assert grandchild.windowType() == Qt.WindowType.Dialog
        assert grandchild.windowOpacity() == 1.0

        grandchild.accept()
        qapp.processEvents()
        assert parent.isVisible() and child.isVisible() and not grandchild.isVisible()
        grandchild.open()
        unrelated.open()
        qapp.processEvents()
        assert unrelated.isVisible()
        assert not any(dialog.isVisible() for dialog in (parent, child, grandchild))
    finally:
        for dialog in (unrelated, grandchild, child, parent):
            dialog.close()


def test_open_vault_dialog_focuses_passcode_field_on_show(qapp, tmp_path):
    parent = QWidget()
    parent.app = SimpleNamespace()
    config = SimpleNamespace(base=str(tmp_path), salt=None)

    previous = LocksmithDialog(parent)
    previous.show()
    previous.accept()
    previous.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    previous_parent = QWidget()
    previous = LocksmithDialog(previous_parent)
    previous.show()
    previous_parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    with patch.object(open_module.otping, "has_otp_configured", return_value=False):
        dialog = OpenVaultDialog(vault_name="test-vault", parent=parent, config=config)

    try:
        dialog.show()
        qapp.processEvents()

        assert qapp.focusWidget() is dialog.passcode_field.line_edit
    finally:
        dialog.close()
        parent.close()
