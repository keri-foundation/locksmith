from itertools import combinations
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QPoint, QRect, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

import locksmith.resources_rc  # noqa: F401
from locksmith.ui.toolkit.tables.components import SkewersMenuButton, TableHeader
from locksmith.ui.vault.credentials.received.list import ReceivedCredentialsListPage


# The 1280px minimum application window leaves 1000px beside its 280px sidebar.
@pytest.mark.parametrize('width', [1000, 1280])
def test_received_header_keeps_title_search_and_actions_visible(qapp, width):
    window = QWidget()
    window.app = SimpleNamespace()
    layout = QVBoxLayout(window)
    layout.setContentsMargins(0, 0, 0, 0)
    page = ReceivedCredentialsListPage(window)
    layout.addWidget(page)
    window.resize(width, 520)
    window.show()
    qapp.processEvents()

    header = page.table.header
    title = next(label for label in header.findChildren(QLabel) if label.text() == 'Received Credentials')
    actions_menu = header.findChild(SkewersMenuButton)
    controls = [title, header.search_input, actions_menu, page.request_credential,
                page.request_presentation, page.inventory]
    rectangles = [QRect(widget.mapTo(header, QPoint()), widget.size()) for widget in controls]

    assert window.width() == width, 'The header must fit without expanding the page'
    assert title.height() >= title.heightForWidth(title.width())
    for button in (actions_menu, page.request_credential, page.request_presentation):
        assert button.width() >= button.minimumSizeHint().width()
    assert all(header.rect().contains(rectangle) for rectangle in rectangles)
    assert all(not first.intersects(second) for first, second in combinations(rectangles, 2))
    assert header.search_input.rect().contains(header.search_input.line_edit.geometry())


def test_received_toolbar_retains_search_actions_and_keyboard_order(qapp, monkeypatch):
    actions = []
    searches = []
    monkeypatch.setattr(ReceivedCredentialsListPage, '_on_accept_credential', lambda self: actions.append('Import'))
    window = QWidget()
    window.app = SimpleNamespace()
    window.start_credential_exchange = lambda action, **kwargs: actions.append((action, kwargs['intent']))
    layout = QVBoxLayout(window)
    page = ReceivedCredentialsListPage(window)
    layout.addWidget(page)
    page.table.set_static_data([{'Credential': 'SEDI', '_actions': []}])
    window.resize(900, 520)
    window.show()
    qapp.processEvents()
    header = page.table.header
    page.table.search_changed.connect(searches.append)
    actions_menu = header.findChild(SkewersMenuButton)

    header.search_input.line_edit.setFocus()
    QTest.keyClicks(header.search_input.line_edit, 'SEDI')
    assert searches[-1] == 'SEDI'
    QTest.keyClick(header.search_input.line_edit, Qt.Key.Key_Tab)
    assert qapp.focusWidget() is page.inventory.combo_box
    QTest.keyClick(page.inventory.combo_box, Qt.Key.Key_Tab)
    assert qapp.focusWidget() is actions_menu
    QTest.keyClick(actions_menu, Qt.Key.Key_Space)
    assert actions_menu.menu.isVisible()
    QTest.keyClick(actions_menu.menu, Qt.Key.Key_Down)
    QTest.keyClick(actions_menu.menu, Qt.Key.Key_Return)
    assert not actions_menu.menu.isVisible()
    assert actions == ['Import']
    QTest.keyClick(actions_menu, Qt.Key.Key_Tab)
    assert qapp.focusWidget() is page.request_credential
    QTest.keyClick(page.request_credential, Qt.Key.Key_Space)
    QTest.keyClick(page.request_credential, Qt.Key.Key_Tab)
    assert qapp.focusWidget() is page.request_presentation
    QTest.keyClick(page.request_presentation, Qt.Key.Key_Space)
    assert actions == ['Import', ('Apply', 'issuance'), ('Apply', 'presentation')]

    page.table.set_static_data([])
    qapp.processEvents()
    assert page.request_credential.isVisible() and page.request_presentation.isVisible()
    assert page.empty_request_credential.isVisible() and page.empty_request_presentation.isVisible()
    for button in (page.empty_request_credential, page.empty_request_presentation):
        rectangle = QRect(button.mapTo(page.table.empty_state, QPoint()), button.size())
        assert page.table.empty_state.rect().contains(rectangle)
        button.click()
    assert actions[-2:] == [('Apply', 'issuance'), ('Apply', 'presentation')]
    page.table.set_static_data([{'Credential': 'SEDI', '_actions': []}])
    assert not page.empty_request_credential.isVisible() and not page.empty_request_presentation.isVisible()
    assert page.request_credential.isVisible() and page.request_presentation.isVisible()


def test_existing_single_row_header_keeps_filter_search_and_add(qapp):
    actions = []
    searches = []
    header = TableHeader(title='Identifiers', filter_func=lambda: actions.append('Filter'))
    header.add_clicked.connect(lambda: actions.append('Add'))
    header.search_changed.connect(searches.append)
    header.resize(1000, 85)
    header.show()
    qapp.processEvents()

    header.filter_button.click()
    QTest.keyClicks(header.search_input.line_edit, 'Alice')
    header.add_button.click()
    assert actions == ['Filter', 'Add']
    assert searches[-1] == 'Alice'


def test_table_opens_selected_row_with_enter(qapp):
    from locksmith.ui.toolkit.tables import PaginatedTableWidget

    rows = [{'Alias': 'Alice'}, {'Alias': 'Bob'}]
    opened = []
    widget = PaginatedTableWidget(columns=['Alias'], show_add_button=False)
    widget.row_clicked.connect(opened.append)
    widget.set_static_data(rows)
    widget.show()
    qapp.processEvents()
    widget.table.setFocus()
    widget.table.setCurrentCell(0, 0)
    QTest.keyClick(widget.table, Qt.Key.Key_Down)
    QTest.keyClick(widget.table, Qt.Key.Key_Return)
    assert opened == [rows[1]]
    widget.close()


def test_empty_table_keeps_only_the_centered_action(qapp):
    from locksmith.ui.toolkit.tables import PaginatedTableWidget
    from locksmith.ui.toolkit.widgets import LocksmithButton

    actions = []
    table = PaginatedTableWidget(columns=['Credential'], title='Received Credentials',
                                 add_button_text='Request credential…', items_per_page=10)
    table.add_clicked.connect(lambda: actions.append('request'))
    table.set_static_data([])
    table.show()
    qapp.processEvents()
    centered = table.empty_state.findChild(LocksmithButton)
    assert centered.isVisible()
    assert table.header.add_button.isHidden()
    assert table.table.horizontalHeader().isVisible()
    centered.click()
    assert actions == ['request']

    table.set_static_data([{'Credential': 'Example'}])
    assert table.empty_state.isHidden()
    assert table.header.add_button.isVisible()
    table.header.add_button.click()
    assert actions == ['request', 'request']

    table.set_static_data([])
    assert centered.isVisible()
    assert table.header.add_button.isHidden()
