"""
Furun VPN - Rule Editor Dialog

路由规则编辑器 — 管理域名规则和 IP CIDR 规则。
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QHeaderView,
    QMessageBox, QTabWidget, QWidget,
)
from PyQt6.QtCore import Qt

from client.core.rule_engine import Action, DomainRule, IpCidrRule

COLUMNS = ["匹配规则", "动作", "优先级", "说明"]


class RuleEditorDialog(QDialog):
    """路由规则编辑对话框"""

    def __init__(self, domain_rules: list[DomainRule],
                 ip_rules: list[IpCidrRule],
                 default_action: Action,
                 parent=None):
        super().__init__(parent)
        self.domain_rules = domain_rules
        self.ip_rules = ip_rules
        self.default_action = default_action
        self._modified = False

        self.setWindowTitle("路由规则编辑器")
        self.setMinimumSize(780, 520)
        self._build_ui()
        self._populate_tables()

    @property
    def modified(self) -> bool:
        return self._modified

    def _build_ui(self):
        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # 域名规则选项卡
        domain_tab = QWidget()
        domain_layout = QVBoxLayout(domain_tab)
        self.domain_table = QTableWidget(0, len(COLUMNS))
        self.domain_table.setHorizontalHeaderLabels(COLUMNS)
        self.domain_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.domain_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Interactive)
        self.domain_table.setColumnWidth(0, 220)
        self.domain_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.domain_table.setAlternatingRowColors(True)
        domain_layout.addWidget(self.domain_table)

        domain_btn_layout = QHBoxLayout()
        add_domain_btn = QPushButton("添加域名规则")
        add_domain_btn.clicked.connect(self._add_domain_rule)
        del_domain_btn = QPushButton("删除选中规则")
        del_domain_btn.clicked.connect(self._delete_domain_rule)
        domain_btn_layout.addWidget(add_domain_btn)
        domain_btn_layout.addWidget(del_domain_btn)
        domain_btn_layout.addStretch()
        domain_layout.addLayout(domain_btn_layout)

        self.tabs.addTab(domain_tab, "域名规则")

        # IP 规则选项卡
        ip_tab = QWidget()
        ip_layout = QVBoxLayout(ip_tab)
        self.ip_table = QTableWidget(0, len(COLUMNS))
        self.ip_table.setHorizontalHeaderLabels(COLUMNS)
        self.ip_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.ip_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Interactive)
        self.ip_table.setColumnWidth(0, 220)
        self.ip_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ip_table.setAlternatingRowColors(True)
        ip_layout.addWidget(self.ip_table)

        ip_btn_layout = QHBoxLayout()
        add_ip_btn = QPushButton("添加 IP 规则")
        add_ip_btn.clicked.connect(self._add_ip_rule)
        del_ip_btn = QPushButton("删除选中规则")
        del_ip_btn.clicked.connect(self._delete_ip_rule)
        ip_btn_layout.addWidget(add_ip_btn)
        ip_btn_layout.addWidget(del_ip_btn)
        ip_btn_layout.addStretch()
        ip_layout.addLayout(ip_btn_layout)

        self.tabs.addTab(ip_tab, "IP CIDR 规则")

        # 默认动作
        default_layout = QHBoxLayout()
        default_layout.addWidget(QLabel("默认动作（无规则匹配时）:"))
        self.default_combo = QComboBox()
        self.default_combo.addItems(["direct (直连)", "proxy (代理)", "block (拦截)"])
        idx = {"direct": 0, "proxy": 1, "block": 2}.get(self.default_action.value, 0)
        self.default_combo.setCurrentIndex(idx)
        default_layout.addWidget(self.default_combo)
        default_layout.addStretch()
        layout.addLayout(default_layout)

        # 底部按钮
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def _populate_tables(self):
        self._populate_domain_table()
        self._populate_ip_table()

    def _populate_domain_table(self):
        self.domain_table.setRowCount(len(self.domain_rules))
        for i, rule in enumerate(self.domain_rules):
            self._set_rule_row(self.domain_table, i, rule.pattern,
                               rule.action.value, rule.priority,
                               rule.description)

    def _populate_ip_table(self):
        self.ip_table.setRowCount(len(self.ip_rules))
        for i, rule in enumerate(self.ip_rules):
            self._set_rule_row(self.ip_table, i, rule.pattern,
                               rule.action.value, rule.priority,
                               rule.description)

    def _set_rule_row(self, table: QTableWidget, row: int,
                      pattern: str, action: str, priority: int,
                      description: str):
        items = [pattern, action, str(priority), description]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            table.setItem(row, col, item)

    def _add_domain_rule(self):
        row = self.domain_table.rowCount()
        self.domain_table.insertRow(row)
        self._set_rule_row(self.domain_table, row,
                           "*.example.com", "proxy", 0, "新规则")
        self._modified = True

    def _add_ip_rule(self):
        row = self.ip_table.rowCount()
        self.ip_table.insertRow(row)
        self._set_rule_row(self.ip_table, row,
                           "0.0.0.0/0", "direct", 0, "新 IP 规则")
        self._modified = True

    def _delete_domain_rule(self):
        rows = set()
        for item in self.domain_table.selectedItems():
            rows.add(item.row())
        for row in sorted(rows, reverse=True):
            self.domain_table.removeRow(row)
        if rows:
            self._modified = True

    def _delete_ip_rule(self):
        rows = set()
        for item in self.ip_table.selectedItems():
            rows.add(item.row())
        for row in sorted(rows, reverse=True):
            self.ip_table.removeRow(row)
        if rows:
            self._modified = True

    def _save(self):
        # 读取域名规则
        new_domain_rules = []
        for row in range(self.domain_table.rowCount()):
            pattern = self.domain_table.item(row, 0).text().strip()
            action_str = self.domain_table.item(row, 1).text().strip().lower()
            priority_str = self.domain_table.item(row, 2).text().strip()
            desc = self.domain_table.item(row, 3).text().strip()

            if not pattern:
                continue
            try:
                action = Action(action_str)
                priority = int(priority_str)
            except (ValueError, KeyError):
                QMessageBox.warning(self, "数据错误",
                                    f"域名规则第 {row + 1} 行: 动作或优先级无效。")
                return

            new_domain_rules.append(DomainRule(
                pattern=pattern, action=action, priority=priority,
                description=desc,
            ))

        # 读取 IP 规则
        new_ip_rules = []
        for row in range(self.ip_table.rowCount()):
            pattern = self.ip_table.item(row, 0).text().strip()
            action_str = self.ip_table.item(row, 1).text().strip().lower()
            priority_str = self.ip_table.item(row, 2).text().strip()
            desc = self.ip_table.item(row, 3).text().strip()

            if not pattern:
                continue
            try:
                action = Action(action_str)
                priority = int(priority_str)
            except (ValueError, KeyError):
                QMessageBox.warning(self, "数据错误",
                                    f"IP 规则第 {row + 1} 行: 动作或优先级无效。")
                return

            new_ip_rules.append(IpCidrRule(
                pattern=pattern, action=action, priority=priority,
                description=desc,
            ))

        # 更新
        self.domain_rules[:] = new_domain_rules
        self.ip_rules[:] = new_ip_rules
        default_text = self.default_combo.currentText()
        default_str = default_text.split(" ")[0]  # "direct (直连)" -> "direct"
        if default_str in ("direct", "proxy", "block"):
            self.default_action = Action(default_str)

        self._modified = True
        self.accept()
