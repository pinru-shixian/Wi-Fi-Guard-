# -*- coding: utf-8 -*-
"""
Wi-Fi Guard v7.0 —— PySide6 (Qt) 版
Fluent Design 暗色界面 + Windows 11 液态玻璃 (DWM Acrylic)
功能：校园网 (^) 期间持续查杀代理进程 + 自动关闭系统代理，
      离开校园网稳定后自动恢复（防抖），托盘常驻、开机自启动、退出确认。
PS：作者建议先编译成exe，然后图形化改就好
"""
import os
import re
import sys
import json
import time
import ctypes
import subprocess
import threading
from ctypes import wintypes

from PySide6.QtCore import Qt, QTimer, Signal, QObject, QPointF, QRectF, QThread
from PySide6.QtGui import QColor, QPainter, QIcon, QPixmap, QFont, QAction, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QStackedWidget, QLineEdit, QPlainTextEdit, QComboBox, QCheckBox,
    QScrollArea, QSystemTrayIcon, QMenu, QDialog, QAbstractButton, QSizePolicy,
)

APP_NAME = "Wi-Fi Guard"
APP_VER  = "7.0"

# ---------------- 配置 ----------------
def default_config():
    return {
        "SsidPattern":         "^CAMPUS", #写网络名前缀，如^SHIXIAN
        "ProcessNames": ["v2ray", "v2rayN", "xray", "clash", "clash-verge",
                         "clash-verge-service", "verge-mihomo", "clash-meta",
                         "mihomo", "sing-box", "sing_box"],
        "PollMs":              500,#波动时长
        "ReleaseDelaySeconds": 3,#释放时间
        "V2rayNPath":          "",
        "AutoStart":           False,
        "ProxyAutoOff":        True,
        "CloseAction":         0,     # 0=每次询问 1=最小化到托盘 2=直接退出
        "FontSize":            10,    # 界面字体大小（pt，8~16）
    }

def cfg_path():
    base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "WiFiGuard")
    return os.path.join(base, "config.json")

def load_config():
    c = default_config()
    try:
        with open(cfg_path(), "r", encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            for k in c.keys():
                if k in saved and saved[k] is not None:
                    c[k] = saved[k]
            if not c["ProcessNames"]:
                c["ProcessNames"] = default_config()["ProcessNames"]
            if c["PollMs"] < 200:
                c["PollMs"] = 500
            if c["ReleaseDelaySeconds"] < 0:
                c["ReleaseDelaySeconds"] = 0
            try:
                c["FontSize"] = min(16, max(8, int(c.get("FontSize", 10))))
            except Exception:
                c["FontSize"] = 10
    except Exception:
        pass
    return c

def save_config(c):
    try:
        os.makedirs(os.path.dirname(cfg_path()), exist_ok=True)
        with open(cfg_path(), "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def log_file():
    return os.path.join(os.environ.get("TEMP", "/tmp"), "v2ray_wifi_guard.log")

# ---------------- 引擎（后台线程，逻辑与 v6 完全一致） ----------------
class Engine(QObject):
    logLine = Signal(str)          # 日志行（线程安全，队列投递到 UI 线程）

    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.cfg_lock = threading.Lock()
        self.paused = False
        self.running = True
        self.log_lock = threading.Lock()
        self.log_queue = []
        self.current_ssid = "检测中..."
        self.state = "init"          # init / blocking / released / paused
        self.switch_count = 0
        self.kill_count = 0
        self._last_ssid = "__INIT__"
        self._stable_ssid = None
        self._stable_count = 0
        self._last_campus = 0.0
        self._launched_client = False
        self._proxy_was_enabled = False

    def get_cfg(self):
        with self.cfg_lock:
            return dict(self.cfg)

    def update_cfg(self, c):
        with self.cfg_lock:
            self.cfg = c

    def log(self, s):
        line = time.strftime("%H:%M:%S") + "  " + s
        with self.log_lock:
            self.log_queue.append(line)
        try:
            with open(log_file(), "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "  " + s + "\n")
        except Exception:
            pass
        self.logLine.emit(line)

    def fetch_logs(self):
        with self.log_lock:
            out = self.log_queue[:]
            self.log_queue = []
        return out

    # ---- SSID ----
    @staticmethod
    def get_ssid_once():
        try:
            r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                               capture_output=True, creationflags=0x08000000)
            text = r.stdout.decode("gbk", errors="ignore")
            for line in text.splitlines():
                m = re.match(r"^\s*SSID\s*:\s*(\S.*)$", line)
                if m:
                    v = m.group(1).strip()
                    if v:
                        return v
        except Exception:
            pass
        return None

    # ---- 进程枚举 / 终止 (ctypes 原生) ----
    @staticmethod
    def _enum_processes():
        psapi = ctypes.WinDLL("Psapi.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")
        arr = (ctypes.c_ulong * 4096)()
        cb = ctypes.c_ulong(ctypes.sizeof(arr))
        ret = ctypes.c_ulong()
        if not psapi.EnumProcesses(arr, cb, ctypes.byref(ret)):
            return []
        n = ret.value // ctypes.sizeof(ctypes.c_ulong)
        procs = []
        for i in range(min(n, 4096)):
            pid = arr[i]
            if not pid:
                continue
            h = kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                continue
            try:
                size = wintypes.DWORD(1024)
                buf = ctypes.create_unicode_buffer(1024)
                if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    procs.append((pid, buf.value))
            finally:
                kernel32.CloseHandle(h)
        return procs

    @staticmethod
    def kill_processes(names):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        name_set = set(n.lower() for n in names)
        killed, desc = 0, []
        for pid, path in Engine._enum_processes():
            base = os.path.basename(path or "").lower()
            stem = base[:-4] if base.endswith(".exe") else base
            if stem in name_set:
                h = kernel32.OpenProcess(0x0001, False, pid)   # PROCESS_TERMINATE
                if h:
                    try:
                        if kernel32.TerminateProcess(h, 1):
                            killed += 1
                            desc.append("%s (PID %d)" % (base, pid))
                    finally:
                        kernel32.CloseHandle(h)
        return killed, desc

    # ---- 系统代理 ----
    @staticmethod
    def _refresh_proxy():
        try:
            wininet = ctypes.WinDLL("wininet.dll")
            wininet.InternetSetOptionW(None, 39, None, 0)
            wininet.InternetSetOptionW(None, 37, None, 0)
        except Exception:
            pass

    @staticmethod
    def _set_proxy(enable):
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            winreg.CloseKey(key)
            Engine._refresh_proxy()
            return True
        except Exception:
            return False

    @staticmethod
    def _proxy_enabled():
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ)
            v, _ = winreg.QueryValueEx(key, "ProxyEnable")
            winreg.CloseKey(key)
            return int(v) == 1
        except Exception:
            return False

    def disable_proxy(self):
        if self._proxy_enabled():
            if self._set_proxy(False):
                self._proxy_was_enabled = True
                self.log("已自动关闭系统代理（Windows 设置 - 网络和 Internet - 代理）")

    def restore_proxy(self):
        if self._proxy_was_enabled:
            if self._set_proxy(True):
                self._proxy_was_enabled = False
                self.log("已自动恢复系统代理")

    # ---- 自启动 ----
    @staticmethod
    def set_autostart(on):
        import winreg
        try:
            if getattr(sys, "frozen", False):        # PyInstaller 打包：exe 自身即可
                cmd = '"%s" --hidden' % sys.executable
            else:
                pythonw = sys.executable.replace("python.exe", "pythonw.exe")
                cmd = '"%s" "%s" --hidden' % (pythonw, os.path.abspath(__file__))
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if on:
                winreg.SetValueEx(key, "WiFiGuard", 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, "WiFiGuard")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
        except Exception:
            pass

    @staticmethod
    def is_autostart():
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            winreg.QueryValueEx(key, "WiFiGuard")
            winreg.CloseKey(key)
            return True
        except Exception:
            return False

    # ---- 主循环 ----
    def run(self):
        c0 = self.get_cfg()
        self.log("===== %s %s 已启动 =====" % (APP_NAME, APP_VER))
        self.log("拦截规则: %s | 进程: %s" % (c0["SsidPattern"], ", ".join(c0["ProcessNames"])))
        self.log("检测周期 %dms，校园网首次命中即刻终止；系统代理自动化: %s"
                 % (c0["PollMs"], "已启用" if c0["ProxyAutoOff"] else "未启用"))
        while self.running:
            try:
                if not self.paused:
                    self.tick()
            except Exception:
                pass
            time.sleep(max(0.2, self.get_cfg()["PollMs"]) / 1000.0)

    def tick(self):
        cfg = self.get_cfg()
        ssid = self.get_ssid_once()
        try:
            re_obj = re.compile(cfg["SsidPattern"])
        except Exception:
            re_obj = None
        campus = ssid is not None and re_obj is not None and re_obj.search(ssid)

        if campus:
            if self.state != "blocking":
                self.log("检测到校园网: %s —— 进入拦截模式" % ssid)
            self.state = "blocking"
            self.current_ssid = ssid
            self._last_campus = time.time()
            self._launched_client = False
            if self._last_ssid != ssid:
                self._last_ssid = ssid
            if cfg["ProxyAutoOff"]:
                self.disable_proxy()
            killed, desc = self.kill_processes(cfg["ProcessNames"])
            if killed:
                self.log("已终止进程: " + "; ".join(desc))
                self.kill_count += killed
        else:
            if ssid == self._stable_ssid:
                self._stable_count += 1
            else:
                self._stable_ssid = ssid
                self._stable_count = 1
            if self._stable_count >= 2 and (ssid or "") != self._last_ssid:
                if self._last_ssid != "__INIT__":
                    old = self._last_ssid or "未连接"
                    new = ssid if ssid else "未连接无线"
                    self.log("检测到网络切换: %s -> %s ，立即检查" % (old, new))
                    self.switch_count += 1
                self._last_ssid = ssid or ""

            since = time.time() - self._last_campus
            if self.state == "blocking" and since < cfg["ReleaseDelaySeconds"]:
                pass   # 防抖
            elif self.state == "blocking":
                self.state = "released"
                self.log("已稳定离开校园网（当前: %s）—— 停止拦截" % (ssid or "未连接无线"))
                if cfg["ProxyAutoOff"]:
                    self.restore_proxy()
                p = cfg["V2rayNPath"]
                if p and os.path.isfile(p) and not self._launched_client:
                    try:
                        subprocess.Popen([p], creationflags=0x08000000)
                        self._launched_client = True
                        self.log("已自动启动客户端: " + p)
                    except Exception:
                        pass
            elif self.state == "init":
                self.state = "released"
            self.current_ssid = ssid if ssid else "未连接无线网络"

# ---------------- 液态玻璃（DWM Acrylic，Qt 原生合成，无魔色 hack） ----------------
def enable_glass(win):
    """Win11 22H2+: 系统级 Acrylic 背景。Qt 的 WA_TranslucentBackground 是真正的
    RGBA 窗口合成，点击命中/缩放/重绘均正常；失败返回 False 走纯色回退。"""
    try:
        if sys.getwindowsversion().build < 22621:
            return False
        win.setAttribute(Qt.WA_TranslucentBackground)
        hwnd = int(win.winId())          # 触发原生句柄创建（属性已生效）
        dwm = ctypes.windll.dwmapi
        one = ctypes.c_int(1)
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(one), 4)   # 深色标题栏
        dwm.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(one), 4)
        rnd = ctypes.c_int(2)
        dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(rnd), 4)   # 窗口圆角
        acrylic = ctypes.c_int(3)        # DWMSBT_TRANSIENTWINDOW = Acrylic
        if dwm.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(acrylic), 4) != 0:
            return False
        return True
    except Exception:
        return False

# ---------------- Fluent 配色 ----------------
BG        = "#202020"
CARD      = "#2b2b2b"
EDGE      = "#333333"
FIELD     = "#333333"
FIELD_EDGE= "#4a4a4a"
TXT       = "#ffffff"
TXT_DIM   = "#a6a6a6"
TXT_FAINT = "#707070"
ACCENT    = "#60cdff"
ACCENT_BASE = "#0078d4"
NAV_SEL   = "#3d3d3d"
NAV_HOVER = "#2d2d2d"
DANGER    = "#c42b1c"
OK_GREEN  = "#0f7b0f"

# ---------------- 自绘 Fluent 开关 ----------------
class ToggleSwitch(QAbstractButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(52, 24)
        self.setCursor(Qt.PointingHandCursor)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.height() / 2.0
        track = QColor("#4cc2ff") if self.isChecked() else QColor("#5a5a5a")
        p.setPen(Qt.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(QRectF(0, 0, self.width(), self.height()), r, r)
        cx = self.width() - r - 1 if self.isChecked() else r + 1
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QPointF(cx, r), 8.5, 8.5)

# ---------------- 圆角卡片 ----------------
class Card(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")

# ---------------- 主窗口 ----------------
class MainWindow(QMainWindow):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.real_exit = False
        self.font_size = int(engine.get_cfg().get("FontSize", 10))
        self._dwm_reapplied = False
        self.setWindowTitle("%s — 校园网代理拦截" % APP_NAME)
        self.resize(980, 640)
        self.setMinimumSize(860, 560)

        self.glass = enable_glass(self)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- 左侧导航 ----
        nav = QFrame()
        nav.setObjectName("nav")
        nav.setFixedWidth(212)
        nv = QVBoxLayout(nav)
        nv.setContentsMargins(0, 18, 0, 14)
        nv.setSpacing(2)

        logo = QLabel("Wi-Fi Guard")
        logo.setObjectName("logo")
        sub = QLabel("校园网代理拦截监控")
        sub.setObjectName("logoSub")
        nv.addWidget(logo)
        nv.addWidget(sub)
        nv.addSpacing(14)

        pages = ["主页", "设置", "运行日志", "使用说明"]
        self.nav_btns = []
        for i, name in enumerate(pages):
            b = QPushButton("    " + name)
            b.setObjectName("navbtn")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedHeight(40)
            b.clicked.connect(lambda checked=False, idx=i: self.show_page(idx))
            nv.addWidget(b)
            self.nav_btns.append(b)
        nv.addStretch(1)

        ver = QLabel("v%s · Fluent + Acrylic" % APP_VER)
        ver.setObjectName("verLabel")
        nv.addWidget(ver)

        root.addWidget(nav)

        # ---- 右侧内容 ----
        self.stack = QStackedWidget()
        self.stack.setObjectName("content")
        root.addWidget(self.stack, 1)

        self.stack.addWidget(self.build_home())
        self.stack.addWidget(self.build_settings())
        self.stack.addWidget(self.build_logs())
        self.stack.addWidget(self.build_help())
        self.show_page(0)

        self.apply_qss()
        self.build_tray()

        # UI 刷新定时器（只读引擎属性，轻量）
        t = QTimer(self)
        t.timeout.connect(self.refresh_ui)
        t.start(300)

    def show_page(self, i):
        self.stack.setCurrentIndex(i)
        for k, b in enumerate(self.nav_btns):
            b.setChecked(k == i)

    # ---------- QSS ----------
    QSS_TEMPLATE = """
#rootArea, QMainWindow { background: @ROOT@; }
#nav { background: @NAV@; border-right: 1px solid @EDGE@; }
#logo { color: @ACCENT@; font: 700 @LOGO@px "Microsoft YaHei UI"; padding-left: 22px; }
#logoSub { color: @TXTDIM@; font: @LOGOSUB@px "Microsoft YaHei UI"; padding-left: 24px; padding-top: 2px; }
#verLabel { color: @TXTFAINT@; font: @VER@px "Microsoft YaHei UI"; padding-left: 24px; }
#navbtn {
    color: @TXTDIM@; background: transparent; border: none;
    font: @NAVPT@pt "Microsoft YaHei UI"; text-align: left; padding-left: 18px;
    border-radius: 6px; margin: 1px 10px;
}
#navbtn:hover { background: @NAVHOVER@; }
#navbtn:checked {
    background: @NAVSEL@; color: @TXT@; font-weight: 600;
    border-left: 3px solid @ACCENT@;
}
#content { background: transparent; }
#card { background: @CARD@; border: 1px solid @EDGE@; border-radius: 10px; }
#pageTitle { color: @TXT@; font: 600 @TITLE@px "Microsoft YaHei UI"; }
#labelTitle { color: @TXT@; font: @BODYPT@pt "Microsoft YaHei UI"; }
#labelDesc  { color: @TXTDIM@; font: @DESCPT@pt "Microsoft YaHei UI"; }
#ssidLabel  { color: @TXT@; font: 700 @SSID@px "Microsoft YaHei UI"; }
#statValue  { color: @ACCENT@; font: 700 @STAT@px "Microsoft YaHei UI"; }
#statValueRed { color: #ff99a4; font: 700 @STAT@px "Microsoft YaHei UI"; }
#chip {
    color: white; font: 600 @BODYPT@pt "Microsoft YaHei UI";
    border-radius: 13px; padding: 5px 14px;
}
#tipLabel { color: @TXTDIM@; font: @DESCPT@pt "Microsoft YaHei UI"; }
QLineEdit, QComboBox {
    background: @FIELD@; color: @TXT@; border: 1px solid @FIELD_EDGE@;
    border-radius: 6px; padding: 5px 10px; font: @BODYPT@pt "Microsoft YaHei UI";
    selection-background-color: @ACCENT@;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid @ACCENT@; }
QComboBox QAbstractItemView {
    background: #2b2b2b; color: @TXT@; border: 1px solid @EDGE@;
    selection-background-color: @NAVSEL@;
}
QPlainTextEdit {
    background: #1a1a1a; color: #cfd8e3; border: 1px solid @EDGE@;
    border-radius: 8px; font: @LOGPT@pt "Consolas"; padding: 8px;
}
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #4a4a4a; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #5a5a5a; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QCheckBox { color: @TXTDIM@; font: @BODYPT@pt "Microsoft YaHei UI"; }
QDialog { background: #2b2b2b; color: @TXT@; font: @BODYPT@pt "Microsoft YaHei UI"; }
"""

    def apply_qss(self):
        fs = float(self.font_size)
        if self.glass:
            root_bg = "transparent"
            nav_bg  = "rgba(24,24,24,190)"
            card_bg = "rgba(43,43,43,215)"
        else:
            root_bg = BG
            nav_bg  = "#1b1b1b"
            card_bg = CARD
        tokens = {
            "@ROOT@": root_bg,
            "@NAV@": nav_bg,
            "@EDGE@": EDGE,
            "@ACCENT@": ACCENT,
            "@TXTDIM@": TXT_DIM,
            "@TXTFAINT@": TXT_FAINT,
            "@TXT@": TXT,
            "@NAVHOVER@": NAV_HOVER,
            "@NAVSEL@": NAV_SEL,
            "@CARD@": card_bg,
            "@FIELD@": FIELD,
            "@FIELD_EDGE@": FIELD_EDGE,
            "@LOGO@": str(round(fs * 1.9)),          # Logo 大标题
            "@LOGOSUB@": str(round(fs * 0.9)),       # Logo 副标题
            "@VER@": str(round(fs * 0.8)),           # 版本号
            "@NAVPT@": str(round(fs)),               # 导航项
            "@TITLE@": str(round(fs * 1.7)),         # 页面标题
            "@BODYPT@": str(round(fs)),              # 正文
            "@DESCPT@": str(max(7, round(fs - 1))), # 说明小字
            "@SSID@": str(round(fs * 3.0)),          # SSID 大字
            "@STAT@": str(round(fs * 2.2)),          # 统计数字
            "@LOGPT@": str(max(8, round(fs - 1))),   # 日志
        }
        qss = self.QSS_TEMPLATE
        for k, v in tokens.items():
            qss = qss.replace(k, v)
        self.setStyleSheet(qss)

    # ---------- 主页 ----------
    def build_home(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(26, 22, 26, 18)
        v.setSpacing(14)

        title = QLabel("主页")
        title.setObjectName("pageTitle")
        v.addWidget(title)

        # 状态卡
        card = Card()
        cv = QVBoxLayout(card)
        cv.setContentsMargins(22, 16, 22, 18)
        cv.setSpacing(6)
        l1 = QLabel("当前 Wi-Fi 网络")
        l1.setObjectName("labelDesc")
        self.lbl_ssid = QLabel("检测中...")
        self.lbl_ssid.setObjectName("ssidLabel")
        self.chip = QLabel("初始化")
        self.chip.setObjectName("chip")
        self.chip.setFixedWidth(200)
        self.chip.setAlignment(Qt.AlignCenter)
        cv.addWidget(l1)
        cv.addWidget(self.lbl_ssid)
        cv.addWidget(self.chip)
        v.addWidget(card)

        # 统计卡
        row = QHBoxLayout()
        row.setSpacing(14)
        c1 = Card()
        c1v = QVBoxLayout(c1)
        c1v.setContentsMargins(20, 14, 20, 14)
        t1 = QLabel("网络切换次数")
        t1.setObjectName("labelDesc")
        self.lbl_switch = QLabel("0")
        self.lbl_switch.setObjectName("statValue")
        c1v.addWidget(t1)
        c1v.addWidget(self.lbl_switch)
        c2 = Card()
        c2v = QVBoxLayout(c2)
        c2v.setContentsMargins(20, 14, 20, 14)
        t2 = QLabel("累计终止进程")
        t2.setObjectName("labelDesc")
        self.lbl_kill = QLabel("0")
        self.lbl_kill.setObjectName("statValueRed")
        c2v.addWidget(t2)
        c2v.addWidget(self.lbl_kill)
        row.addWidget(c1, 1)
        row.addWidget(c2, 1)
        v.addLayout(row)

        # 按钮
        btns = QHBoxLayout()
        btns.setSpacing(12)
        self.btn_kill = self._btn("立即查杀", DANGER, self.kill_now)
        self.btn_pause = self._btn("暂停监控", "#333333", self.toggle_pause)
        self.btn_open = self._btn("打开日志", "#333333", self.open_log)
        btns.addWidget(self.btn_kill)
        btns.addWidget(self.btn_pause)
        btns.addWidget(self.btn_open)
        btns.addStretch(1)
        v.addLayout(btns)

        tip = QLabel("提示：点窗口关闭按钮可选择缩至系统托盘；设置保存后立即生效")
        tip.setObjectName("tipLabel")
        v.addWidget(tip)
        v.addStretch(1)
        return page

    def _btn(self, text, bg, slot):
        b = QPushButton(text)
        b.setCursor(Qt.PointingHandCursor)
        b.setFixedHeight(34)
        b.setStyleSheet("""
            QPushButton {
                background: %s; color: white; border: none; border-radius: 6px;
                font: 600 %dpt "Microsoft YaHei UI"; padding: 0 18px;
            }
            QPushButton:hover { background: %s; }
            QPushButton:pressed { background: %s; }
        """ % (bg, self.font_size, self._lighten(bg), bg))
        b.clicked.connect(slot)
        return b

    @staticmethod
    def _lighten(hexc):
        try:
            c = QColor(hexc)
            c.setRed(min(255, c.red() + 26))
            c.setGreen(min(255, c.green() + 26))
            c.setBlue(min(255, c.blue() + 26))
            return c.name()
        except Exception:
            return hexc

    # ---------- 设置页 ----------
    def build_settings(self):
        outer = QWidget()
        ov = QVBoxLayout(outer)
        ov.setContentsMargins(26, 22, 26, 18)
        ov.setSpacing(14)
        title = QLabel("设置")
        title.setObjectName("pageTitle")
        ov.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        sv = QVBoxLayout(inner)
        sv.setContentsMargins(0, 0, 6, 6)
        sv.setSpacing(10)

        def row(title_t, desc_t, widget):
            card = Card()
            h = QHBoxLayout(card)
            h.setContentsMargins(20, 12, 20, 12)
            h.setSpacing(16)
            left = QVBoxLayout()
            lt = QLabel(title_t)
            lt.setObjectName("labelTitle")
            ld = QLabel(desc_t)
            ld.setObjectName("labelDesc")
            ld.setWordWrap(True)
            left.addWidget(lt)
            left.addWidget(ld)
            h.addLayout(left, 1)
            h.addWidget(widget, 0, Qt.AlignVCenter)
            sv.addWidget(card)
            return widget

        def entry(width):
            e = QLineEdit()
            e.setFixedWidth(width)
            return e

        self.ent_pattern = entry(220)
        row("网络名匹配规则","正则表达式，例如 ^CAMPUS 会自动匹配 CAMPUS-NETWORK-01 等关联网络",self.ent_pattern)

        self.ent_proc = entry(340)
        row("拦截进程名", "英文逗号分隔，可自行增删；默认覆盖 V2ray / Clash / Sing-box 全家桶", self.ent_proc)

        self.ent_poll = entry(120)
        row("拦截轮询间隔", "毫秒（最小 200）；越小响应越快，500ms 内几乎无感知", self.ent_poll)

        self.ent_delay = entry(120)
        row("离开校园网防抖延迟", "秒；离开后保持拦截的时长，防止网络波动误放行", self.ent_delay)

        self.ent_v2 = entry(300)
        row("离开校园网后自动启动的客户端", "可选；填入 v2rayN 等客户端的完整路径，离开校园网后自动拉起", self.ent_v2)

        self.tg_auto = ToggleSwitch()
        row("开机自启动", "写入当前用户注册表 Run 项，开机后自动缩至托盘运行", self.tg_auto)

        self.tg_proxy = ToggleSwitch()
        row("校园网内自动关闭系统代理", "进入校园网时关闭 Windows 系统代理，稳定离开后自动恢复", self.tg_proxy)

        self.cmb_font = QComboBox()
        self.cmb_font.setFixedWidth(180)
        self.cmb_font.addItems(["9（小）", "10（标准）", "11（大）", "12（更大）", "13（特大）", "14（最大）"])
        self.cmb_font.setCurrentIndex(max(0, min(5, self.font_size - 9)))
        row("界面字体大小", "适配高分屏：整体界面文字按此缩放，保存后立即生效并记住选择", self.cmb_font)

        self.cmb_close = QComboBox()
        self.cmb_close.setFixedWidth(220)
        self.cmb_close.addItems(["每次询问（弹窗选择）", "最小化到托盘（不询问）", "直接退出程序（不询问）"])
        row("关闭主窗口时", "点标题栏 × 后的行为；与退出确认弹窗中的「记住我的选择」联动", self.cmb_close)

        # 回填配置
        cfg = self.engine.get_cfg()
        self.ent_pattern.setText(cfg["SsidPattern"])
        self.ent_proc.setText(", ".join(cfg["ProcessNames"]))
        self.ent_poll.setText(str(cfg["PollMs"]))
        self.ent_delay.setText(str(cfg["ReleaseDelaySeconds"]))
        self.ent_v2.setText(cfg["V2rayNPath"])
        self.tg_auto.setChecked(bool(cfg["AutoStart"]))
        self.tg_proxy.setChecked(bool(cfg["ProxyAutoOff"]))
        self.cmb_close.setCurrentIndex(int(cfg.get("CloseAction", 0)))
        self.tg_auto.setChecked(Engine.is_autostart())

        btn = self._btn("保存设置（立即生效）", ACCENT_BASE, self.save_settings)
        hb = QHBoxLayout()
        hb.addWidget(btn)
        hb.addStretch(1)
        sv.addLayout(hb)
        sv.addStretch(1)

        scroll.setWidget(inner)
        ov.addWidget(scroll, 1)
        return outer

    def save_settings(self):
        try:
            poll = max(200, int(self.ent_poll.text().strip() or "500"))
        except ValueError:
            poll = 500
        try:
            delay = max(0, int(self.ent_delay.text().strip() or "3"))
        except ValueError:
            delay = 3
        proc = [p.strip() for p in self.ent_proc.text().split(",") if p.strip()]
        if not proc:
            proc = default_config()["ProcessNames"]
        cfg = {
            "SsidPattern": self.ent_pattern.text().strip() or "^",
            "ProcessNames": proc,
            "PollMs": poll,
            "ReleaseDelaySeconds": delay,
            "V2rayNPath": self.ent_v2.text().strip(),
            "AutoStart": bool(self.tg_auto.isChecked()),
            "ProxyAutoOff": bool(self.tg_proxy.isChecked()),
            "CloseAction": self.cmb_close.currentIndex(),
            "FontSize": 9 + self.cmb_font.currentIndex(),
        }
        save_config(cfg)
        self.engine.update_cfg(cfg)
        Engine.set_autostart(cfg["AutoStart"])
        # 字体立即生效
        self.font_size = int(cfg["FontSize"])
        app = QApplication.instance()
        f = app.font()
        f.setPointSize(self.font_size)
        app.setFont(f)
        self._chip_text = None   # 强制胶囊重算宽度与字体
        self.apply_qss()
        self.engine.log("设置已更新并生效（周期 %dms，防抖 %ds，字体 %dpt）" % (poll, delay, self.font_size))

    # ---------- 日志页 ----------
    def build_logs(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(26, 22, 26, 18)
        v.setSpacing(14)
        title = QLabel("运行日志")
        title.setObjectName("pageTitle")
        v.addWidget(title)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        v.addWidget(self.txt_log, 1)

        hb = QHBoxLayout()
        hb.addWidget(self._btn("打开日志文件", "#333333", self.open_log))
        hb.addWidget(self._btn("清空显示", "#333333", lambda: self.txt_log.clear()))
        hb.addStretch(1)
        v.addLayout(hb)
        return page

    # ---------- 说明页 ----------
    def build_help(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(26, 22, 26, 18)
        v.setSpacing(14)
        title = QLabel("使用说明")
        title.setObjectName("pageTitle")
        v.addWidget(title)

        card = Card()
        cv = QVBoxLayout(card)
        cv.setContentsMargins(24, 18, 24, 18)
        cv.setSpacing(10)
        body = QLabel(
            "快速上手\n"
            "1. 在「设置」页确认网络名匹配规则（默认 ^）与拦截进程列表\n"
            "2. 按需开启「开机自启动」与「校园网内自动关闭系统代理」，点保存\n"
            "3. 关闭窗口时可选择缩至托盘并记住选择，程序在后台持续守护\n\n"
            "工作原理\n"
            "· 后台线程按设定周期读取当前 Wi-Fi SSID，命中规则即刻终止代理进程并关闭系统代理\n"
            "· 拦截期间持续查杀——手动重开也会被再次终止\n"
            "· 稳定离开校园网（防抖延迟后）自动恢复代理，可选自动启动客户端\n\n"
            "小技巧\n"
            "· 响应更快：把轮询间隔调到 200~300ms\n"
            "· 网络波动大：把防抖延迟调到 5 秒以上\n"
            "· 日志文件位置：%TEMP%\\v2ray_wifi_guard.log"
        )
        body.setObjectName("labelTitle")
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignTop)
        cv.addWidget(body)
        v.addWidget(card, 1)
        return page

    # ---------- 托盘 ----------
    def build_tray(self):
        self.tray = QSystemTrayIcon(self.make_icon(), self)
        self.tray.setToolTip("%s（校园网代理拦截）" % APP_NAME)
        menu = QMenu()
        act_show = QAction("显示主界面", self)
        act_pause = QAction("暂停/恢复监控", self)
        act_kill = QAction("立即查杀", self)
        act_exit = QAction("退出", self)
        act_show.triggered.connect(self.show_main)
        act_pause.triggered.connect(self.toggle_pause)
        act_kill.triggered.connect(self.kill_now)
        act_exit.triggered.connect(self.exit_app)
        menu.addAction(act_show)
        menu.addAction(act_pause)
        menu.addAction(act_kill)
        menu.addSeparator()
        menu.addAction(act_exit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()

    @staticmethod
    def make_icon():
        pm = QPixmap(64, 64)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#0078d4"))
        path = QPainterPath()
        path.moveTo(32, 4)
        path.lineTo(58, 14)
        path.lineTo(54, 44)
        path.quadTo(46, 58, 32, 60)
        path.quadTo(18, 58, 10, 44)
        path.lineTo(6, 14)
        path.closeSubpath()
        p.drawPath(path)
        p.setPen(QPen(QColor("#ffffff"), 5))
        p.drawLine(22, 32, 30, 40)
        p.drawLine(30, 40, 44, 24)
        p.end()
        return QIcon(pm)

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_main()

    def show_main(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def showEvent(self, e):
        """窗口显示后重申 DWM 属性（部分环境下首帧前设置的深色标题栏/玻璃会被覆盖）"""
        super().showEvent(e)
        if self.glass and not self._dwm_reapplied:
            self._dwm_reapplied = True
            try:
                hwnd = int(self.winId())
                dwm = ctypes.windll.dwmapi
                one = ctypes.c_int(1)
                dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(one), 4)
                dwm.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(one), 4)
                rnd = ctypes.c_int(2)
                dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(rnd), 4)
                ac = ctypes.c_int(3)
                dwm.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(ac), 4)
            except Exception:
                pass

    # ---------- 操作 ----------
    def kill_now(self):
        cfg = self.engine.get_cfg()
        killed, desc = Engine.kill_processes(cfg["ProcessNames"])
        if killed:
            self.engine.log("手动查杀: 已终止 " + "; ".join(desc))
            self.engine.kill_count += killed
        else:
            self.engine.log("手动查杀: 未发现目标进程")

    def toggle_pause(self):
        self.engine.paused = not self.engine.paused
        st = "已暂停" if self.engine.paused else "已恢复"
        self.engine.log("监控%s" % st)

    def open_log(self):
        os.startfile(log_file())

    def refresh_ui(self):
        for line in self.engine.fetch_logs():
            self.txt_log.appendPlainText(line)
            sb = self.txt_log.verticalScrollBar()
            sb.setValue(sb.maximum())
        self.lbl_ssid.setText(self.engine.current_ssid)
        self.lbl_switch.setText(str(self.engine.switch_count))
        self.lbl_kill.setText(str(self.engine.kill_count))
        st = self.engine.state
        if self.engine.paused:
            self.set_chip("已暂停", "#5a5a5a")
        elif st == "blocking":
            self.set_chip("拦截中 · 持续查杀代理进程 + 系统代理已关闭", DANGER)
        elif st == "released":
            self.set_chip("放行 · 非校园网", OK_GREEN)
        else:
            self.set_chip("初始化", "#5a5a5a")
        self.btn_pause.setText("恢复监控" if self.engine.paused else "暂停监控")

    def set_chip(self, text, color):
        if getattr(self, "_chip_text", None) != text:
            self._chip_text = text
            self.chip.setText(text)
            fm = self.chip.fontMetrics()
            self.chip.setFixedWidth(min(680, fm.horizontalAdvance(text) + 40))
        self.chip.setStyleSheet(
            "#chip { background: %s; color: white; border-radius: 13px; "
            "padding: 5px 14px; font: 600 %dpt 'Microsoft YaHei UI'; }" % (color, self.font_size))

    # ---------- 关闭 / 退出 ----------
    def _do_exit(self):
        """统一的真实退出：停引擎、隐藏托盘、退出 Qt 事件循环（否则进程会残留后台）"""
        self.real_exit = True
        self.engine.running = False
        try:
            self.tray.hide()
        except Exception:
            pass
        self.close()
        QApplication.instance().quit()

    def closeEvent(self, e):
        if self.real_exit:
            self.engine.running = False
            try:
                self.tray.hide()
            except Exception:
                pass
            e.accept()
            return
        action = int(self.engine.get_cfg().get("CloseAction", 0))
        if action == 1:
            self.to_tray()
            e.ignore()
            return
        if action == 2:
            self._do_exit()
            e.accept()
            return
        choice, remember = self.ask_close()
        if choice == 0:      # 取消
            e.ignore()
            return
        if remember:
            cfg = self.engine.get_cfg()
            cfg["CloseAction"] = choice
            save_config(cfg)
            self.engine.update_cfg(cfg)
        if choice == 1:
            self.to_tray()
            e.ignore()
        else:
            self._do_exit()
            e.accept()

    def to_tray(self):
        self.hide()
        self.tray.showMessage(APP_NAME, "已缩至系统托盘，继续守护校园网拦截", QSystemTrayIcon.Information, 2000)

    def ask_close(self):
        """返回 (choice, remember)：0=取消 1=托盘 2=退出"""
        dlg = QDialog(self)
        dlg.setWindowTitle("关闭 Wi-Fi Guard")
        dlg.setFixedWidth(420)
        dlg.setStyleSheet("QDialog { background: #2b2b2b; }")
        v = QVBoxLayout(dlg)
        v.setContentsMargins(24, 20, 24, 18)
        v.setSpacing(12)
        msg = QLabel("你关闭了主窗口。希望关闭后程序如何运行？")
        msg.setStyleSheet("color: #ffffff; font: 600 %dpt 'Microsoft YaHei UI';" % (self.font_size + 1))
        v.addWidget(msg)
        chk = QCheckBox("记住我的选择（下次不再询问）")
        chk.setStyleSheet("color: #a6a6a6; font: %dpt 'Microsoft YaHei UI';" % self.font_size)
        v.addWidget(chk)
        hb = QHBoxLayout()
        hb.addStretch(1)
        b_cancel = self._btn("取消", "#333333", dlg.reject)
        b_tray = self._btn("最小化到托盘", "#333333", lambda: dlg.done(1))
        b_exit = self._btn("退出程序", DANGER, lambda: dlg.done(2))
        hb.addWidget(b_cancel)
        hb.addWidget(b_tray)
        hb.addWidget(b_exit)
        v.addLayout(hb)
        result = dlg.exec()
        return result, chk.isChecked()

    def exit_app(self):
        self._do_exit()

# ---------------- 入口 ----------------
def main():
    kernel32 = ctypes.WinDLL("kernel32.dll")
    kernel32.CreateMutexW(None, False, "Local\\WiFiGuardSingleInstance")
    if kernel32.GetLastError() == 183:
        from PySide6.QtWidgets import QMessageBox
        app = QApplication([])
        QMessageBox.information(None, "提示", "%s 已在运行中（请查看系统托盘）。" % APP_NAME)
        return

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyle("Fusion")

    engine = Engine()
    # 高分屏字体：Microsoft YaHei UI 渲染中文最细腻，全局按配置大小设定
    app.setFont(QFont("Microsoft YaHei UI", int(engine.cfg.get("FontSize", 10))))

    win = MainWindow(engine)

    thread = threading.Thread(target=engine.run, daemon=True)
    thread.start()

    # 命令行隐藏启动（开机自启动场景）：传 --hidden 不显示主窗口
    if "--hidden" not in sys.argv:
        win.show()

    # 自测模式：--smoke 运行 5 秒自动退出（用于验证打包后的 exe）
    if "--smoke" in sys.argv:
        QTimer.singleShot(5000, app.quit)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
