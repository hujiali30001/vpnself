"""
Furun VPN - Log Viewer Widget

嵌入式日志查看器 -- 可滚动、可过滤、按级别着色的实时日志面板。
"""

import html

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit,
    QPushButton, QCheckBox, QLineEdit, QLabel, QFileDialog,
)
from PyQt6.QtGui import QFont

# Catppuccin Mocha level colours.
LEVEL_COLORS = {
    "ERROR": "#f38ba8",
    "CRITICAL": "#f38ba8",
    "WARNING": "#f9e2af",
    "DEBUG": "#6c7086",
    "INFO": "#cdd6f4",
}


class LogViewer(QWidget):
    """可滚动、可筛选、按级别着色的日志查看器"""

    MAX_LINES = 5000

    def __init__(self, parent=None):
        super().__init__(parent)
        self._auto_scroll = True
        self._all_lines: list[tuple[str, str]] = []  # (message, level)
        self._filter_text = ""
        self._prev_filter = None   # (filter_text, show_debug) — skip rebuild when unchanged
        self._truncated = False    # True once the buffer has been capped at MAX_LINES
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        ctrl_layout = QHBoxLayout()
        ctrl_layout.setSpacing(8)
        self.auto_scroll_cb = QCheckBox("自动滚动")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.toggled.connect(self._toggle_auto_scroll)
        ctrl_layout.addWidget(self.auto_scroll_cb)

        self.show_debug_cb = QCheckBox("显示调试信息")
        self.show_debug_cb.setChecked(False)
        self.show_debug_cb.toggled.connect(self._apply_filter)
        ctrl_layout.addWidget(self.show_debug_cb)

        ctrl_layout.addWidget(QLabel("筛选:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("按关键字过滤（域名 / 级别 / 消息）")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self._on_filter_changed)
        ctrl_layout.addWidget(self.filter_input, 1)

        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear)
        ctrl_layout.addWidget(clear_btn)

        export_btn = QPushButton("导出日志")
        export_btn.clicked.connect(self._export_log)
        ctrl_layout.addWidget(export_btn)
        layout.addLayout(ctrl_layout)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setMaximumBlockCount(self.MAX_LINES)
        self.text_edit.setFont(QFont("Cascadia Code", 10))
        self.text_edit.setPlaceholderText("等待日志输出…")
        layout.addWidget(self.text_edit)

    def _toggle_auto_scroll(self, checked: bool):
        self._auto_scroll = checked

    def _on_filter_changed(self, text: str):
        self._filter_text = text.strip().lower()
        self._apply_filter()

    def _visible(self, message: str, level: str) -> bool:
        if level == "DEBUG" and not self.show_debug_cb.isChecked():
            return False
        if self._filter_text and self._filter_text not in message.lower() \
                and self._filter_text not in level.lower():
            return False
        return True

    def _append_html(self, message: str, level: str):
        color = LEVEL_COLORS.get(level, "#cdd6f4")
        safe = html.escape(message)
        self.text_edit.appendHtml(f'<span style="color:{color};">{safe}</span>')

    def _apply_filter(self):
        """Rebuild display content based on the debug toggle and text filter."""
        key = (self._filter_text, self.show_debug_cb.isChecked())
        if key == self._prev_filter:
            return
        self._prev_filter = key
        self.text_edit.clear()
        for message, level in self._all_lines:
            if self._visible(message, level):
                self._append_html(message, level)
        if self._truncated:
            self.text_edit.appendHtml(
                '<span style="color:#6c7086;">'
                f'(日志已截断至最近 {self.MAX_LINES} 条)'
                '</span>'
            )
        if self._auto_scroll:
            sb = self.text_edit.verticalScrollBar()
            sb.setValue(sb.maximum())

    def append_log(self, message: str, level: str = "INFO"):
        self._all_lines.append((message, level))
        # Cap retained history to match the display block limit, so a
        # long-running session does not grow _all_lines without bound.
        if len(self._all_lines) > self.MAX_LINES:
            del self._all_lines[:len(self._all_lines) - self.MAX_LINES]
            if not self._truncated:
                self._truncated = True
                self._prev_filter = None  # force rebuild on next filter change
                self.text_edit.appendHtml(
                    f'<span style="color:#6c7086;">'
                    f'(日志已截断至最近 {self.MAX_LINES} 条)'
                    f'</span>'
                )
        if not self._visible(message, level):
            return
        self._append_html(message, level)
        if self._auto_scroll:
            scrollbar = self.text_edit.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def get_full_text(self) -> str:
        """Return the full retained history (all levels), for export."""
        return "\n".join(msg for msg, _ in self._all_lines)

    def _export_log(self):
        """Save the full log history to a user-chosen file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "furun_log.txt",
            "文本文件 (*.txt *.log);;所有文件 (*)"
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.get_full_text())
        except OSError:
            pass  # silently ignore; parent window handles its own export errors

    def clear(self):
        self._all_lines.clear()
        self._truncated = False
        self._prev_filter = None
        self.text_edit.clear()

    def set_show_debug(self, show: bool):
        self.show_debug_cb.setChecked(show)
