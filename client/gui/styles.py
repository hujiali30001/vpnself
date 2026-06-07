"""
Furun VPN - Qt Stylesheet
"""

MAIN_STYLE = """
QMainWindow {
    background-color: #1e1e2e;
    color: #cdd6f4;
}

QWidget {
    font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
    font-size: 13px;
}

QLabel {
    color: #cdd6f4;
}

QGroupBox {
    border: 1px solid #45475a;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 12px;
    color: #cdd6f4;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #89b4fa;
}

QLineEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px 10px;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
}

QLineEdit:focus {
    border-color: #89b4fa;
}

QLineEdit:disabled {
    background-color: #1e1e2e;
    color: #6c7086;
}

QPushButton {
    background-color: #45475a;
    border: 1px solid #585b70;
    border-radius: 4px;
    padding: 7px 16px;
    color: #cdd6f4;
    font-weight: bold;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #585b70;
}

QPushButton:pressed {
    background-color: #6c7086;
}

QPushButton:disabled {
    background-color: #313244;
    color: #6c7086;
}

QPushButton#connectBtn {
    background-color: #a6e3a1;
    color: #1e1e2e;
    font-size: 14px;
    padding: 10px 24px;
}

QPushButton#connectBtn:hover {
    background-color: #94e2d5;
}

QPushButton#connectBtn[connected="true"] {
    background-color: #f38ba8;
    color: #1e1e2e;
}

QPushButton#connectBtn[connected="true"]:hover {
    background-color: #eba0ac;
}

QCheckBox {
    color: #cdd6f4;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
}

QTableWidget {
    background-color: #313244;
    alternate-background-color: #363755;
    border: 1px solid #45475a;
    border-radius: 4px;
    gridline-color: #45475a;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
}

QTableWidget::item {
    padding: 4px 8px;
}

QHeaderView::section {
    background-color: #45475a;
    color: #cdd6f4;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #585b70;
    border-bottom: 1px solid #585b70;
    font-weight: bold;
}

QTextEdit, QPlainTextEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    color: #cdd6f4;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    selection-background-color: #89b4fa;
}

QScrollBar:vertical {
    background-color: #1e1e2e;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #45475a;
    border-radius: 5px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #585b70;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QComboBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px 10px;
    color: #cdd6f4;
}

QComboBox::drop-down {
    border: none;
}

QComboBox QAbstractItemView {
    background-color: #313244;
    border: 1px solid #45475a;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
}

QMenuBar {
    background-color: #181825;
    color: #cdd6f4;
    border-bottom: 1px solid #45475a;
}

QMenuBar::item:selected {
    background-color: #45475a;
}

QMenu {
    background-color: #313244;
    border: 1px solid #45475a;
    color: #cdd6f4;
}

QMenu::item:selected {
    background-color: #89b4fa;
    color: #1e1e2e;
}

QStatusBar {
    background-color: #181825;
    color: #a6adc8;
    border-top: 1px solid #45475a;
}

QToolTip {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    padding: 4px;
}

QProgressBar {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    text-align: center;
    color: #cdd6f4;
}

QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 3px;
}
"""

STATUS_LABELS = {
    "connected": "QLabel { color: #a6e3a1; font-weight: bold; }",
    "disconnected": "QLabel { color: #f38ba8; font-weight: bold; }",
    "connecting": "QLabel { color: #f9e2af; font-weight: bold; }",
}

STAT_LABEL = """
QLabel {
    background-color: #313244;
    border-radius: 4px;
    padding: 6px 12px;
    color: #cdd6f4;
    font-size: 12px;
}
"""
