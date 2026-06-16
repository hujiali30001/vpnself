"""
Furun VPN - Main Window

VPN 客户端主窗口 -- 连接管理、流量统计、规则/日志入口。
"""

import sys
import asyncio
import threading
import time
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QCheckBox, QMessageBox,
    QSystemTrayIcon, QMenu, QApplication, QGridLayout, QFileDialog, QSpinBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QCloseEvent, QPixmap, QPainter, QColor, QBrush

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.utils import get_logger, get_data_path
from client.core.tunnel import TunnelPool, TunnelConfig, POOL_DEFAULT_SIZE
from client.core.rule_engine import RuleEngine, Action
from client.core.router import Router
from client.core.http_proxy import HttpConnectProxy
from client.config.settings import load_config as load_client_config, save_config
from client.gui.styles import MAIN_STYLE, STATUS_LABELS, STAT_LABEL
from client.gui.rule_editor import RuleEditorDialog
from client.gui.log_viewer import LogViewer

log = get_logger("client.gui")


def _make_tray_icon(color: str) -> QIcon:
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(4, 4, 24, 24)
    painter.end()
    return QIcon(pixmap)


class MainWindow(QMainWindow):
    """Furun VPN 主窗口"""

    status_changed = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    log_message = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Furun VPN")
        self.setMinimumSize(620, 560)
        self.resize(640, 570)

        self._running = False
        self._pool: TunnelPool | None = None
        self._router: Router | None = None
        self._proxy: HttpConnectProxy | None = None
        self._rule_engine = RuleEngine()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._connect_start_time: float = 0
        self._cleaned_up = False

        self._config = load_client_config()

        self._build_ui()
        self._build_tray()
        self._connect_signals()

        rules_path = get_data_path("client", "config", "default_rules.json")
        self._rule_engine.load_rules(rules_path)

        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._refresh_stats)
        self._stats_timer.start(2000)

        # Hook into application quit signal
        QApplication.instance().aboutToQuit.connect(self._on_app_quit)

        log.info("主窗口初始化完成")

    # --- UI 构建 ---

    def _build_ui(self):
        self.setStyleSheet(MAIN_STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- 连接状态 ---
        status_group = QGroupBox("连接状态")
        status_layout = QGridLayout(status_group)
        status_layout.setSpacing(8)

        self.status_label = QLabel(" 未连接")
        self.status_label.setStyleSheet(STATUS_LABELS["disconnected"])
        status_layout.addWidget(self.status_label, 0, 0)

        self.uptime_label = QLabel("--")
        self.uptime_label.setStyleSheet(STAT_LABEL)
        status_layout.addWidget(QLabel("运行时间:"), 0, 1)
        status_layout.addWidget(self.uptime_label, 0, 2)

        self.proxy_label = QLabel("HTTP: 未启动")
        self.proxy_label.setStyleSheet(STAT_LABEL)
        status_layout.addWidget(self.proxy_label, 0, 3)

        layout.addWidget(status_group)

        # --- 服务器配置 ---
        config_group = QGroupBox("服务器配置")
        config_layout = QGridLayout(config_group)
        config_layout.setSpacing(8)

        config_layout.addWidget(QLabel("服务器地址:"), 0, 0)
        self.host_input = QLineEdit(self._config.get("server_host", ""))
        self.host_input.setPlaceholderText("日本服务器 IP 或域名")
        config_layout.addWidget(self.host_input, 0, 1, 1, 3)

        config_layout.addWidget(QLabel("端口:"), 1, 0)
        self.port_input = QLineEdit(str(self._config.get("server_port", 8443)))
        self.port_input.setMaximumWidth(80)
        config_layout.addWidget(self.port_input, 1, 1)

        config_layout.addWidget(QLabel("密钥:"), 1, 2)
        self.psk_input = QLineEdit(self._config.get("psk", ""))
        self.psk_input.setEchoMode(QLineEdit.EchoMode.Password)
        config_layout.addWidget(self.psk_input, 1, 3)

        self.verify_cert_cb = QCheckBox("验证 TLS 证书（勾选=严格验证，不勾选=接受自签名）")
        self.verify_cert_cb.setChecked(self._config.get("verify_cert", False))
        config_layout.addWidget(self.verify_cert_cb, 2, 0, 1, 2)

        config_layout.addWidget(QLabel("连接池:"), 3, 0)
        self.pool_size_spin = QSpinBox()
        self.pool_size_spin.setRange(1, 128)
        self.pool_size_spin.setValue(int(self._config.get("pool_size", POOL_DEFAULT_SIZE)))
        self.pool_size_spin.setToolTip(u"并行隧道数量，增加可提升多连接吞吐量")
        config_layout.addWidget(self.pool_size_spin, 3, 1)

        layout.addWidget(config_group)

        # --- 流量统计 ---
        stats_group = QGroupBox("流量统计")
        stats_layout = QHBoxLayout(stats_group)
        stats_layout.setSpacing(16)

        self.direct_label = QLabel("直连: 0")
        self.direct_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.direct_label)

        self.proxy_count_label = QLabel("代理: 0")
        self.proxy_count_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.proxy_count_label)

        self.blocked_label = QLabel("拦截: 0")
        self.blocked_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.blocked_label)

        self.failed_label = QLabel("失败: 0")
        self.failed_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.failed_label)

        stats_layout.addStretch()

        self.tunnel_status_label = QLabel("隧道: --")
        self.tunnel_status_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.tunnel_status_label)
        self.cb_label = QLabel("CB: --")
        self.cb_label.setStyleSheet(STAT_LABEL)
        stats_layout.addWidget(self.cb_label)

        layout.addWidget(stats_group)

        # --- 日志 ---
        self.log_viewer = LogViewer()
        layout.addWidget(self.log_viewer, 1)

        # --- 底部操作 ---
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(12)

        self.connect_btn = QPushButton(" 连接")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setMinimumWidth(120)
        self.connect_btn.clicked.connect(self._toggle_connection)
        bottom_layout.addWidget(self.connect_btn)

        self.rules_btn = QPushButton("规则管理")
        self.rules_btn.clicked.connect(self._open_rule_editor)
        bottom_layout.addWidget(self.rules_btn)

        self.save_log_btn = QPushButton("导出日志")
        self.save_log_btn.clicked.connect(self._save_logs)
        bottom_layout.addWidget(self.save_log_btn)

        self.system_proxy_cb = QCheckBox("自动设置系统代理")
        self.system_proxy_cb.setChecked(self._config.get("auto_set_system_proxy", True))
        self.system_proxy_cb.setEnabled(False)
        bottom_layout.addWidget(self.system_proxy_cb)

        self.auto_connect_cb = QCheckBox("启动时自动连接")
        self.auto_connect_cb.setChecked(self._config.get("auto_connect", False))
        bottom_layout.addWidget(self.auto_connect_cb)

        bottom_layout.addStretch()
        layout.addLayout(bottom_layout)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setToolTip("Furun VPN")
        self.tray.setIcon(_make_tray_icon("#f38ba8"))

        tray_menu = QMenu()
        show_action = QAction("显示主窗口", self)
        show_action.triggered.connect(self._show_window)
        tray_menu.addAction(show_action)

        self.tray_connect_action = QAction("连接", self)
        self.tray_connect_action.triggered.connect(self._toggle_connection)
        tray_menu.addAction(self.tray_connect_action)

        tray_menu.addSeparator()

        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self._do_quit)
        tray_menu.addAction(quit_action)

        self.tray.setContextMenu(tray_menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _connect_signals(self):
        self.status_changed.connect(self._on_status_changed)
        self.stats_updated.connect(self._on_stats_updated)
        self.log_message.connect(self._on_log_message)

    # --- 异步循环 ---

    def _start_async_loop(self):
        if self._loop_thread and self._loop_thread.is_alive():
            return
        self._loop = asyncio.new_event_loop()

        def run_loop():
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_forever()
            except Exception as e:
                log.error("异步事件循环异常退出: %s", e, exc_info=True)
            finally:
                # Cancel all pending tasks
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                self._loop.close()

        self._loop_thread = threading.Thread(target=run_loop, daemon=True)
        self._loop_thread.start()
        log.debug("异步事件循环已启动")

    def _stop_async_loop(self):
        loop = self._loop
        if loop and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        thread = self._loop_thread
        if thread and thread.is_alive():
            thread.join(timeout=3.0)
        self._loop = None
        self._loop_thread = None
        log.debug("异步事件循环已停止")

    def _run_async(self, coro):
        if self._loop is None or self._loop.is_closed():
            return None
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # --- 连接操作 ---

    async def _connect_async(self):
        try:
            self.status_changed.emit("connecting")
            log.info("正在连接 %s:%d ...",
                     self._config["server_host"], int(self._config["server_port"]))

            tunnel_config = TunnelConfig(
                host=self._config["server_host"],
                port=int(self._config["server_port"]),
                psk=self._config["psk"],
                tls_cert_file=self._config.get("tls_cert_file") or None,
                verify_cert=self._config.get("verify_cert", False),
                connect_timeout=float(self._config.get("connect_timeout", 10)),
                optimistic_connect=bool(self._config.get("optimistic_connect", False)),
            )

            pool_size = int(self._config.get("pool_size", POOL_DEFAULT_SIZE))
            log.info("隧道池: %d 条连接, 乐观流水线=%s, 验证证书=%s",
                     pool_size, self._config.get("optimistic_connect", False),
                     self._config.get("verify_cert", False))
            self._pool = TunnelPool(tunnel_config, pool_size)
            # Auto-reconnect when tunnel drops
            self._pool.on_disconnect(lambda: self._run_async(self._auto_reconnect()))
            connected = await self._pool.connect()

            if not connected:
                self.status_changed.emit("disconnected")
                log.error("连接失败 -- 请检查服务器地址、端口和密钥")
                return

            log.info("加密隧道已建立")

            self._router = Router(self._pool, self._rule_engine)

            proxy_host = self._config.get("socks5_host", "127.0.0.1")
            proxy_port = int(self._config.get("socks5_port", 1080))
            self._proxy = HttpConnectProxy(self._router, proxy_host, proxy_port)

            await self._proxy.start()
            log.info("HTTP CONNECT proxy started: %s:%d", proxy_host, proxy_port)

            if self._config.get("auto_set_system_proxy", True):
                self._set_system_proxy(True)

            self._running = True
            self._connect_start_time = time.time()
            self.status_changed.emit("connected")
            log.info("Furun VPN 已连接，正在运行")

        except Exception as e:
            log.error("连接异常: %s", e, exc_info=True)
            self.status_changed.emit("disconnected")

    async def _auto_reconnect(self):
        if not self._running:
            return
        for attempt in range(1, 6):
            delay = min(attempt * 3, 15)
            log.info("auto-reconnect in %ds (attempt %d/5)...", delay, attempt)
            self.status_changed.emit("reconnecting")
            await asyncio.sleep(delay)
            if not self._running:
                return
            if self._pool:
                try:
                    ok = await self._pool.connect()
                    if ok:
                        log.info("auto-reconnect OK")
                        self.status_changed.emit("connected")
                        return
                except Exception as e:
                    log.warning("auto-reconnect failed: %s", e)
        log.error("auto-reconnect exhausted, please reconnect manually")
        self.status_changed.emit("disconnected")

    async def _disconnect_async(self):
        try:
            log.info("正在断开连接...")
            self._running = False  # must be set before disconnect to prevent auto-reconnect

            if self._config.get("auto_set_system_proxy", True):
                self._set_system_proxy(False)

            if self._proxy:
                await self._proxy.stop()
                self._proxy = None

            if self._pool:
                await self._pool.disconnect()
                self._pool = None

            self._router = None

        except Exception as e:
            log.error("断开异常: %s", e, exc_info=True)
        finally:
            self.status_changed.emit("disconnected")

    def _toggle_connection(self):
        if self._running:
            self.connect_btn.setEnabled(False)
            self.connect_btn.setText("断开中...")
            self._run_async(self._disconnect_async())
        else:
            if not self.host_input.text().strip():
                QMessageBox.warning(self, "配置错误", "请输入服务器地址。")
                return

            self._config["server_host"] = self.host_input.text().strip()
            self._config["server_port"] = int(self.port_input.text().strip())
            self._config["psk"] = self.psk_input.text()
            self._config["verify_cert"] = self.verify_cert_cb.isChecked()
            self._config["auto_set_system_proxy"] = self.system_proxy_cb.isChecked()
            self._config["auto_connect"] = self.auto_connect_cb.isChecked()
            self._config["pool_size"] = self.pool_size_spin.value()
            save_config(self._config)

            self._start_async_loop()

            self.connect_btn.setEnabled(False)
            self.connect_btn.setText("连接中...")
            self._run_async(self._connect_async())

    def _refresh_stats(self):
        if self._router:
            stats = self._router.stats
            self.stats_updated.emit(stats)

        if self._pool:
            ts = self._pool.stats
            active = ts.get("active_streams", 0)
            con = ts.get("connected_count", 0)
            tot = ts.get("total_count", 0)
            self.tunnel_status_label.setText(
                f"隧道: {'正常' if ts['connected'] else '断开'} "
                f"({con}/{tot} 个隧道, {active} 个流)"
            )
            if self._connect_start_time and ts['connected']:
                elapsed = int(time.time() - self._connect_start_time)
                h, m = divmod(elapsed, 3600)
                m, s = divmod(m, 60)
                self.uptime_label.setText(f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self.tunnel_status_label.setText("隧道: --")
            self.uptime_label.setText("--")

    # --- 系统代理 ---

    def _set_system_proxy(self, enable: bool):
        """Enable or disable the Windows system proxy."""
        http_port = self._config.get("socks5_port", 1080)
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_SET_VALUE
            )
            if enable:
                try:
                    winreg.DeleteValue(key, "ProxyServer")
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                                  "http=127.0.0.1:%d;https=127.0.0.1:%d" % (http_port, http_port))
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                try:
                    winreg.DeleteValue(key, "ProxyServer")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            self._notify_proxy_change()
            label = "HTTP: 127.0.0.1:%d" % http_port if enable else "HTTP: 未启动"
            self.proxy_label.setText(label)
            log.info("系统代理已%s", "设置" if enable else "关闭")
        except PermissionError:
            log.warning("系统代理: 权限不足（请以管理员运行以自动配置）")
            if enable:
                self.proxy_label.setText("HTTP: 127.0.0.1:%d (手动)" % http_port)
        except Exception as e:
            log.warning("%s系统代理失败: %s", "设置" if enable else "关闭", e)

    def _notify_proxy_change(self):
        """Notify Windows and running apps of proxy configuration change."""
        try:
            import ctypes
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception:
            pass

    # --- 规则编辑器 ---

    def _open_rule_editor(self):
        dialog = RuleEditorDialog(
            domain_rules=self._rule_engine.get_domain_rules(),
            ip_rules=self._rule_engine.get_ip_rules(),
            default_action=self._rule_engine.default_action,
            parent=self,
        )
        if dialog.exec() == RuleEditorDialog.DialogCode.Accepted and dialog.modified:
            self._rule_engine.clear_rules()
            for rule in dialog.domain_rules:
                self._rule_engine.add_domain_rule(rule)
            for rule in dialog.ip_rules:
                self._rule_engine.add_ip_rule(rule)
            self._rule_engine.default_action = dialog.default_action

            rules_path = get_data_path("client", "config", "default_rules.json")
            self._rule_engine.save_rules(rules_path)
            log.info("路由规则已更新并保存至 %s", rules_path.name)

    # --- 导出日志 ---

    def _save_logs(self):
        default_name = "furun_logs.txt"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", default_name, "文本文件 (*.txt *.log);;所有文件 (*)"
        )
        if not file_path:
            return
        try:
            text = self.log_viewer.text_edit.toPlainText()
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text)
            log.info("日志已导出到 %s (%d 字节)", file_path, len(text))
        except OSError as e:
            log.error("导出日志失败: %s", e)
            QMessageBox.critical(self, "错误", f"导出日志失败:\n{e}")

    # --- 信号处理 ---

    def _on_status_changed(self, status: str):
        if status == "connected":
            self.status_label.setText(" 已连接")
            self.status_label.setStyleSheet(STATUS_LABELS["connected"])
            self._style_connect_button(True)
            self.host_input.setEnabled(False)
            self.port_input.setEnabled(False)
            self.psk_input.setEnabled(False)
            self.pool_size_spin.setEnabled(False)
            self.system_proxy_cb.setEnabled(True)
            self.tray_connect_action.setText("断开连接")
            port = self._config.get("socks5_port", 1080)
            self.proxy_label.setText("HTTP: 127.0.0.1:%d" % port)
            self.tray.setIcon(_make_tray_icon("#a6e3a1"))

        elif status == "disconnected":
            self.status_label.setText(" 未连接")
            self.status_label.setStyleSheet(STATUS_LABELS["disconnected"])
            self._style_connect_button(False)
            self.host_input.setEnabled(True)
            self.port_input.setEnabled(True)
            self.psk_input.setEnabled(True)
            self.pool_size_spin.setEnabled(True)
            if not self._running:
                self.system_proxy_cb.setEnabled(False)
            self.tray_connect_action.setText("连接")
            self.proxy_label.setText("HTTP: 未启动")
            self._running = False
            self._connect_start_time = 0
            self.tray.setIcon(_make_tray_icon("#f38ba8"))

        elif status == "connecting":
            self.status_label.setText(" 连接中...")
            self.status_label.setStyleSheet(STATUS_LABELS["connecting"])
            self.connect_btn.setText("连接中...")
            self.connect_btn.setEnabled(False)

    def _style_connect_button(self, connected: bool):
        """Update connect button text, enabled state, and style."""
        self.connect_btn.setText(" 断开连接" if connected else " 连接")
        self.connect_btn.setEnabled(True)
        self.connect_btn.setProperty("connected", connected)
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)

    def _on_stats_updated(self, stats: dict):
        self.direct_label.setText(f"直连: {stats.get('direct_connections', 0)}")
        self.proxy_count_label.setText(f"代理: {stats.get('proxy_connections', 0)}")
        self.blocked_label.setText(f"拦截: {stats.get('blocked_connections', 0)}")
        self.failed_label.setText(f"失败: {stats.get('failed_connections', 0)}")

    def _on_log_message(self, message: str, level: str = "INFO"):
        self.log_viewer.append_log(message, level)

    # --- 窗口事件 ---

    def _show_window(self):
        """显示并激活主窗口。"""
        self.show()
        self.raise_()
        self.activateWindow()

    def _tray_activated(self, reason):
        """托盘图标双击 -> 显示窗口。"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_window()

    def closeEvent(self, event: QCloseEvent):
        """点击 X 按钮 -> 最小化到系统托盘。"""
        if self.tray.isVisible():
            self.hide()
            event.ignore()

    def _do_quit(self):
        """从托盘菜单选择退出时调用。"""
        log.info("用户请求退出...")
        self._cleanup()
        QApplication.instance().quit()

    def _on_app_quit(self):
        """Qt 即将退出时的回调（防止重复清理）。"""
        if not self._cleaned_up:
            self._cleanup()

    def _cleanup(self):
        """执行清理：断开连接、停止事件循环、隐藏托盘。幂等。"""
        if self._cleaned_up:
            return
        self._cleaned_up = True

        log.info("正在清理资源...")
        self._stats_timer.stop()

        if self._running:
            fut = self._run_async(self._disconnect_async())
            if fut:
                try:
                    fut.result(timeout=3.0)
                except Exception:
                    pass

        self._stop_async_loop()

        try:
            self.tray.hide()
        except Exception:
            pass

        log.info("清理完成")

    def cleanup(self):
        """外部调用入口（main.py 中使用）。"""
        self._cleanup()
