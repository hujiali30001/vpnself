"""
Furun VPN - Log Viewer Widget

嵌入式日志查看器 -- 可滚动、可过滤的实时日志面板。
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit,
    QPushButton, QCheckBox,
)
from PyQt6.QtGui import QFont


class LogViewer(QWidget):
    """可滚动、可筛选的日志查看器"""

    MAX_LINES = 5000

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._auto_scroll = True
        self._all_lines: list[tuple[str, str]] = []  # (message, level)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        ctrl_layout = QHBoxLayout()
        self.auto_scroll_cb = QCheckBox("自动滚动")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.toggled.connect(self._toggle_auto_scroll)
        ctrl_layout.addWidget(self.auto_scroll_cb)

        self.show_debug_cb = QCheckBox("显示调试信息")
        self.show_debug_cb.setChecked(False)
        self.show_debug_cb.toggled.connect(self._apply_filter)
        ctrl_layout.addWidget(self.show_debug_cb)

        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(clear_btn)
        layout.addLayout(ctrl_layout)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setMaximumBlockCount(self.MAX_LINES)
        self.text_edit.setFont(QFont("Cascadia Code", 10))
        layout.addWidget(self.text_edit)

    def _toggle_auto_scroll(self, checked: bool):
        self._auto_scroll = checked

    def _apply_filter(self):
        """Rebuild display content based on debug filter toggle."""
        show_debug = self.show_debug_cb.isChecked()
        self.text_edit.clear()
        for message, level in self._all_lines:
            if level == "DEBUG" and not show_debug:
                continue
            self.text_edit.appendPlainText(message)

    def append_log(self, message: str, level: str = "INFO"):
        self._all_lines.append((message, level))
        # Cap retained history to match the display block limit, so a
        # long-running session does not grow _all_lines without bound.
        if len(self._all_lines) > self.MAX_LINES:
            del self._all_lines[:len(self._all_lines) - self.MAX_LINES]
        if level == "DEBUG" and not self.show_debug_cb.isChecked():
            return
        self.text_edit.appendPlainText(message)
        if self._auto_scroll:
            scrollbar = self.text_edit.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def clear(self):
        self._all_lines.clear()
        self.text_edit.clear()

    def set_show_debug(self, show: bool):
        self.show_debug_cb.setChecked(show)
