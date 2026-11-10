"""
Network Monitor Pro v8.0 — Comprehensive Build
Author: Amin Mohammadi — https://www.artika.ir — https://github.com/irpbz

v8 adds: theme, columns, alert rules, blacklist, alert history,
filter presets, auto-refresh, graph range, ping, HTML export,
AbuseIPDB, unsigned detection, port-scan detection, domain stats,
update checker, PCAP recording, GeoIP (optional), CLI mode.
"""

import sys, os, time, ctypes, subprocess, logging, sqlite3
import queue, threading, ipaddress, traceback, webbrowser, json
from collections import deque, defaultdict
from datetime import datetime, date, timedelta
from logging.handlers import RotatingFileHandler

try:
    import winreg
except ImportError:
    winreg = None
try:
    import win32gui, win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    win32gui = win32con = None

APP_VERSION   = "8.0"
APP_NAME      = "Network Monitor Pro"
APP_AUTHOR    = "Amin Mohammadi"
APP_WEBSITE   = "https://www.artika.ir"
APP_GITHUB    = "https://github.com/irpbz"
AUTOSTART_KEY = "NetworkMonitorPro"


# ============================================================
# 0) LOGGING
# ============================================================
def _setup_logging():
    base = os.path.join(os.path.expanduser("~"), ".netmon_pro")
    os.makedirs(base, exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(base, "netmon.log"),
        maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    return logging.getLogger("netmon"), base


log, APP_DIR = _setup_logging()

DEBUG_NO_ELEVATE = "--no-elevate" in sys.argv
if DEBUG_NO_ELEVATE:
    sys.argv.remove("--no-elevate")
START_MINIMIZED = "--minimized" in sys.argv
if START_MINIMIZED:
    sys.argv.remove("--minimized")
CLI_MODE = "--cli" in sys.argv
if CLI_MODE:
    sys.argv.remove("--cli")


# ============================================================
# 1) AUTOSTART
# ============================================================
def _get_exe_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --minimized'
    script = os.path.abspath(sys.argv[0])
    return f'"{sys.executable}" "{script}" --minimized'


def is_autostart_enabled():
    if winreg is None: return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, AUTOSTART_KEY); return True
        finally:
            winreg.CloseKey(key)
    except (FileNotFoundError, OSError):
        return False


def set_autostart(enabled):
    if winreg is None: return False
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_key)
    try:
        if enabled:
            winreg.SetValueEx(key, AUTOSTART_KEY, 0, winreg.REG_SZ, _get_exe_command())
        else:
            try: winreg.DeleteValue(key, AUTOSTART_KEY)
            except FileNotFoundError: pass
        return True
    except Exception as e:
        log.error(f"Autostart: {e}"); return False
    finally:
        winreg.CloseKey(key)


# ============================================================
# 2) ELEVATION
# ============================================================
def _is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception: return False


def _elevate():
    if DEBUG_NO_ELEVATE or CLI_MODE or _is_admin(): return
    log.info("Elevating...")
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable
        params = f'"{os.path.abspath(sys.argv[0])}" ' + " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    if ret <= 32:
        input("Elevation failed. Press Enter..."); sys.exit(1)
    sys.exit(0)


# ============================================================
# 3) DEPENDENCIES
# ============================================================
def _has_module(name):
    try: __import__(name); return True
    except ImportError: return False


def _ensure_dependencies():
    required = {"PyQt5": "PyQt5", "psutil": "psutil",
                "pyqtgraph": "pyqtgraph", "scapy": "scapy"}
    if not HAS_WIN32:
        required["win32gui"] = "pywin32"; required["win32con"] = "pywin32"
    missing = [p for m, p in required.items() if not _has_module(m)]
    if not missing: return
    log.info(f"Installing: {missing}")
    for url, host in [("https://mirror-pypi.runflare.com/simple/", "mirror-pypi.runflare.com"),
                      ("https://pypi.org/simple/", None)]:
        cmd = [sys.executable, "-m", "pip", "install", *missing,
               "--index-url", url, "--timeout", "180", "--retries", "5"]
        if host: cmd += ["--trusted-host", host]
        try:
            subprocess.check_call(cmd)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except subprocess.CalledProcessError:
            continue
    input("Install failed. Press Enter..."); sys.exit(1)


if not CLI_MODE:
    _elevate(); _ensure_dependencies()


# ============================================================
# 4) IMPORTS
# ============================================================
import psutil

if not CLI_MODE:
    import pyqtgraph as pg
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTableView, QTableWidget, QTableWidgetItem, QPushButton, QLabel,
        QHeaderView, QLineEdit, QMessageBox, QSplitter, QGroupBox,
        QTextEdit, QComboBox, QCheckBox, QTabWidget, QSystemTrayIcon,
        QMenu, QAction, QStyle, QDateTimeEdit, QFormLayout, QFileDialog,
        QDialog, QSpinBox, QDoubleSpinBox, QDialogButtonBox, QSlider,
        QProgressBar, QInputDialog, QListWidget, QListWidgetItem,
        QAbstractItemView, QColorDialog, QTextBrowser,
    )
    from PyQt5.QtCore import (
        QThread, pyqtSignal, Qt, QAbstractTableModel, QModelIndex,
        QTimer, QDateTime, QSettings,
    )
    from PyQt5.QtGui import QFont, QColor, QBrush, QIcon, QGuiApplication


# ============================================================
# 5) FORMATTERS
# ============================================================
def fmt_speed(bps):
    if bps < 1: return "0 B/s"
    if bps < 1024: return f"{bps:.0f} B/s"
    if bps < 1024**2: return f"{bps/1024:.1f} KB/s"
    if bps < 1024**3: return f"{bps/(1024**2):.2f} MB/s"
    return f"{bps/(1024**3):.2f} GB/s"


def fmt_bytes(b):
    if b < 1024: return f"{b:.0f} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/(1024**2):.2f} MB"
    return f"{b/(1024**3):.2f} GB"


def fmt_duration(seconds):
    seconds = int(seconds)
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d: return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    if h: return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def resource_path(rel):
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, rel)


def load_icon():
    if CLI_MODE: return None
    for p in [resource_path("icon.ico"), os.path.join(APP_DIR, "icon.ico"), "icon.ico"]:
        if os.path.exists(p): return QIcon(p)
    return QIcon()


# ============================================================
# 6) SIGNATURE CHECK (unsigned process detection)
# ============================================================
def is_file_signed(path):
    """Return True if exe has Authenticode signature. None if unknown."""
    if not path or not os.path.exists(path):
        return None
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong),
                        ("pcwszFilePath", ctypes.c_wchar_p),
                        ("hFile", ctypes.c_void_p),
                        ("pgKnownSubject", ctypes.POINTER(GUID))]
        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong),
                        ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p),
                        ("dwUIChoice", ctypes.c_ulong),
                        ("fdwRevocationChecks", ctypes.c_ulong),
                        ("dwUnionChoice", ctypes.c_ulong),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                        ("dwStateAction", ctypes.c_ulong),
                        ("hWVTStateData", ctypes.c_void_p),
                        ("pwszURLReference", ctypes.c_wchar_p),
                        ("dwProvFlags", ctypes.c_ulong),
                        ("dwUIContext", ctypes.c_ulong)]

        fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = 2
        data.fdwRevocationChecks = 0
        data.dwUnionChoice = 1
        data.pFile = ctypes.pointer(fi)
        data.dwStateAction = 0
        data.dwProvFlags = 0x10

        action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                      (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        status = ctypes.windll.wintrust.WinVerifyTrust(
            None, ctypes.byref(action), ctypes.byref(data))
        return status == 0
    except Exception as e:
        log.debug(f"sigcheck: {e}")
        return None


# ============================================================
# 7) HISTORY DB (extended)
# ============================================================
class HistoryDB:
    def __init__(self, path):
        self.path = path
        self._pending = []
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, pid INTEGER, name TEXT,
            laddr TEXT, raddr TEXT, status TEXT, proto TEXT, domain TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS daily_usage (
            date TEXT PRIMARY KEY, up_bytes INTEGER DEFAULT 0, down_bytes INTEGER DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, title TEXT, body TEXT, severity TEXT)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON connections(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pid ON connections(pid)")
        conn.commit(); conn.close()

    def enqueue(self, records):
        with self._lock: self._pending.extend(records)

    def flush(self):
        with self._lock:
            batch, self._pending = self._pending, []
        if not batch: return 0
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.executemany(
                "INSERT INTO connections (ts,pid,name,laddr,raddr,status,proto,domain) "
                "VALUES (?,?,?,?,?,?,?,?)", batch)
            conn.commit(); conn.close(); return len(batch)
        except Exception as e:
            log.error(f"flush: {e}"); return 0

    def query(self, from_dt, to_dt, pid=None, keyword=None, limit=2000):
        q = ("SELECT ts,pid,name,laddr,raddr,status,proto,domain FROM connections "
             "WHERE ts BETWEEN ? AND ?")
        params = [from_dt.isoformat(sep=" "), to_dt.isoformat(sep=" ")]
        if pid is not None: q += " AND pid=?"; params.append(pid)
        if keyword:
            q += " AND (name LIKE ? OR raddr LIKE ? OR domain LIKE ?)"
            like = f"%{keyword}%"; params += [like, like, like]
        q += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            rows = conn.execute(q, params).fetchall(); conn.close()
            return rows
        except Exception as e:
            log.error(f"query: {e}"); return []

    def stats_daily(self, days=7):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            rows = conn.execute("""SELECT DATE(ts) d, COUNT(*) c, COUNT(DISTINCT pid) pids
                FROM connections WHERE ts >= DATE('now', ?) GROUP BY d ORDER BY d""",
                (f"-{days} days",)).fetchall()
            conn.close(); return rows
        except Exception: return []

    def add_usage(self, day_str, up, down):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.execute("""INSERT INTO daily_usage (date, up_bytes, down_bytes) VALUES (?,?,?)
                ON CONFLICT(date) DO UPDATE SET up_bytes=up_bytes+excluded.up_bytes,
                down_bytes=down_bytes+excluded.down_bytes""",
                (day_str, int(up), int(down)))
            conn.commit(); conn.close()
        except Exception as e: log.error(f"add_usage: {e}")

    def get_range_usage(self, start_date, end_date):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            row = conn.execute("""SELECT COALESCE(SUM(up_bytes),0), COALESCE(SUM(down_bytes),0)
                FROM daily_usage WHERE date BETWEEN ? AND ?""",
                (start_date.isoformat(), end_date.isoformat())).fetchone()
            conn.close(); return int(row[0]), int(row[1])
        except Exception: return 0, 0

    def add_alert(self, title, body, severity="info"):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.execute("INSERT INTO alerts (ts,title,body,severity) VALUES (?,?,?,?)",
                (datetime.now().isoformat(sep=" ", timespec="seconds"),
                 title, body, severity))
            conn.commit(); conn.close()
        except Exception as e: log.error(f"add_alert: {e}")

    def get_alerts(self, limit=500):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            rows = conn.execute("SELECT ts,title,body,severity FROM alerts "
                                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            conn.close(); return rows
        except Exception: return []

    def get_domain_stats(self, days=7, limit=100):
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            rows = conn.execute("""SELECT domain, COUNT(*) c, COUNT(DISTINCT pid) pids
                FROM connections WHERE domain != '' AND ts >= DATE('now', ?)
                GROUP BY domain ORDER BY c DESC LIMIT ?""",
                (f"-{days} days", limit)).fetchall()
            conn.close(); return rows
        except Exception: return []


# ============================================================
# 8) DATA
# ============================================================
class ProcRow:
    __slots__ = ('pid','name','exe','connections','up','down',
                 'total_up','total_down','domains','signed')
    def __init__(self, pid, name, exe, connections, up=0.0, down=0.0,
                 total_up=0, total_down=0, domains=None, signed=None):
        self.pid = pid; self.name = name; self.exe = exe
        self.connections = connections; self.up = up; self.down = down
        self.total_up = total_up; self.total_down = total_down
        self.domains = domains or set(); self.signed = signed


# ============================================================
# 9) WORKERS
# ============================================================
if not CLI_MODE:
    class SpeedWorker(QThread):
        tick = pyqtSignal(float, float)
        def __init__(self, interval=0.5, interface=None):
            super().__init__()
            self.interval = interval; self.interface = interface
            self._run = True; self._prev = None; self._t = time.time()

        def set_interval(self, v): self.interval = v
        def set_interface(self, name): self.interface = name; self._prev = None

        def run(self):
            while self._run:
                now = time.time(); dt = max(now - self._t, 0.001)
                up = down = 0.0
                try:
                    n = (psutil.net_io_counters(pernic=True).get(self.interface)
                         if self.interface else psutil.net_io_counters())
                except Exception:
                    n = None
                if n is not None:
                    if self._prev:
                        up = max(0.0, (n.bytes_sent - self._prev.bytes_sent) / dt)
                        down = max(0.0, (n.bytes_recv - self._prev.bytes_recv) / dt)
                    self._prev = n
                self._t = now; self.tick.emit(up, down)
                time.sleep(self.interval)

        def stop(self): self._run = False


    class ScanWorker(QThread):
        scanned = pyqtSignal(list)
        def __init__(self, interval=2.0):
            super().__init__()
            self.interval = interval; self._run = True
            self._cache = {}; self._dns_map = {}; self._sig_cache = {}
            self._proc_objs = {}; self._prev_io = {}; self._totals = {}
            self.track_io = True

        def update_dns(self, m): self._dns_map.update(m)
        def set_track_io(self, v): self.track_io = v
        def set_interval(self, v): self.interval = v

        @staticmethod
        def _net_bytes(io):
            down = getattr(io, 'read_chars', None); up = getattr(io, 'write_chars', None)
            if down is None: down = io.read_bytes
            if up is None: up = io.write_bytes
            return down, up

        def _sample_io(self, pid, now):
            if not self.track_io:
                t = self._totals.get(pid, [0,0]); return 0.0, 0.0, t[0], t[1]
            proc = self._proc_objs.get(pid)
            if proc is None:
                try: proc = psutil.Process(pid); self._proc_objs[pid] = proc
                except Exception: return 0.0, 0.0, 0, 0
            try: io = proc.io_counters()
            except Exception:
                self._proc_objs.pop(pid, None); return 0.0, 0.0, 0, 0
            dn, up = self._net_bytes(io)
            totals = self._totals.setdefault(pid, [0,0])
            totals[0] = max(totals[0], up); totals[1] = max(totals[1], dn)
            prev = self._prev_io.get(pid); self._prev_io[pid] = (dn, up, now)
            if prev is None: return 0.0, 0.0, totals[0], totals[1]
            pd, pu, pt = prev; dt = max(now - pt, 0.001)
            return (max(0.0, (up - pu) / dt), max(0.0, (dn - pd) / dt),
                    totals[0], totals[1])

        def run(self):
            try:
                for p in psutil.process_iter(['pid', 'name']):
                    self._cache[p.info['pid']] = {
                        'name': p.info['name'] or f"PID {p.info['pid']}", 'exe': ''}
            except Exception: pass
            while self._run:
                try: self._scan()
                except Exception as e: log.error(f"scan: {e}")
                time.sleep(self.interval)

        def _scan(self):
            now = time.time()
            try: conns = psutil.net_connections(kind='inet')
            except Exception: return
            pid_conns = defaultdict(list)
            for c in conns:
                if c.pid: pid_conns[c.pid].append(c)
            rows = []
            for pid, clist in pid_conns.items():
                info = self._cache.get(pid) or self._query(pid)
                self._cache[pid] = info
                conns_list = []; domains = set()
                for c in clist:
                    la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    if c.raddr and c.raddr.ip in self._dns_map:
                        domains.add(self._dns_map[c.raddr.ip])
                    conns_list.append({'laddr': la, 'raddr': ra,
                                       'status': c.status or '',
                                       'type': 'TCP' if c.type == 1 else 'UDP'})
                signed = self._sig_cache.get(pid)
                if signed is None and info['exe']:
                    signed = is_file_signed(info['exe'])
                    self._sig_cache[pid] = signed
                up, down, tu, td = self._sample_io(pid, now)
                rows.append(ProcRow(pid, info['name'], info['exe'], conns_list,
                                    up=up, down=down, total_up=tu, total_down=td,
                                    domains=domains, signed=signed))
            if len(self._prev_io) > len(pid_conns) + 50:
                alive = set(pid_conns)
                self._prev_io = {k:v for k,v in self._prev_io.items() if k in alive}
                self._proc_objs = {k:v for k,v in self._proc_objs.items() if k in alive}
                self._totals = {k:v for k,v in self._totals.items() if k in alive}
                self._sig_cache = {k:v for k,v in self._sig_cache.items() if k in alive}
            self.scanned.emit(rows)

        @staticmethod
        def _query(pid):
            try:
                p = psutil.Process(pid)
                return {'name': p.name() or f"PID {pid}", 'exe': p.exe() or ''}
            except Exception:
                return {'name': f"PID {pid}", 'exe': ''}

        def stop(self): self._run = False


    class SnifferWorker(threading.Thread):
        def __init__(self, out_queue):
            super().__init__(daemon=True, name="SnifferWorker")
            self.out = out_queue
            self._stop = threading.Event()
            self._sniffer = None
            self.pcap_path = None

        def run(self):
            try:
                from scapy.all import AsyncSniffer
                self._sniffer = AsyncSniffer(prn=self._handle, store=False,
                                             filter="udp port 53 or tcp port 443")
                self._sniffer.start()
                log.info("Sniffer started.")
                self._stop.wait()
                self._sniffer.stop()
            except Exception as e:
                log.error(f"Sniffer: {e}")

        def _handle(self, pkt):
            if self._stop.is_set(): return
            try: self._process(pkt)
            except Exception: pass

        def _process(self, pkt):
            from scapy.layers.inet import IP
            from scapy.layers.dns import DNS
            from scapy.layers.tls.all import TLS
            from scapy.layers.tls.handshake import TLSClientHello
            if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                ip = pkt[IP].dst if IP in pkt else None
                self.out.put({"kind": "dns", "domain": qname, "ip": ip})
                return
            if TLS in pkt and pkt.haslayer(TLSClientHello):
                ch = pkt[TLSClientHello]; name = None
                try:
                    for ext in getattr(ch, "ext", []) or []:
                        if getattr(ext, "servernames", None):
                            name = ext.servernames[0].servername.decode(errors="ignore")
                            break
                except Exception: pass
                if name:
                    ip = pkt[IP].dst if IP in pkt else None
                    self.out.put({"kind": "sni", "domain": name, "ip": ip})

        def stop(self): self._stop.set()


    class ArchiveWorker(QThread):
        def __init__(self, db, interval=30.0):
            super().__init__(); self.db = db; self.interval = interval; self._run = True
        def run(self):
            while self._run: time.sleep(self.interval); self.db.flush()
        def stop(self): self.db.flush(); self._run = False


    class AlertWorker(QThread):
        alert = pyqtSignal(str, str, str)  # title, body, severity
        def __init__(self, interval=2.0, threshold_mb=50, enabled=True):
            super().__init__()
            self.interval = interval
            self.threshold = threshold_mb * 1024 * 1024
            self.enabled = enabled
            self._run = True
            self._seen_pids = set()
            self._baseline_ready = False
            self._baseline_pids = set()
            self._bytes_total = {}
            self._alerted = set()
            self._port_history = deque(maxlen=20)  # (ts, set of listening ports)
            self.blacklist = set()
            self.whitelist = set()

        def set_enabled(self, v): self.enabled = v
        def set_threshold(self, mb): self.threshold = mb * 1024 * 1024
        def set_lists(self, blacklist, whitelist):
            self.blacklist = set(blacklist); self.whitelist = set(whitelist)

        def run(self):
            time.sleep(4)
            self._baseline_ready = True
            self._baseline_pids = set(self._seen_pids)
            while self._run: time.sleep(self.interval)

        def feed(self, rows):
            if not self.enabled: return
            now = time.time()

            # Port scan detection
            listen_ports = set()
            for r in rows:
                for c in r.connections:
                    if c["laddr"] and not c["raddr"]:
                        try: listen_ports.add(int(c["laddr"].rsplit(":", 1)[1]))
                        except Exception: pass
            self._port_history.append((now, listen_ports))
            if len(self._port_history) >= 2:
                prev = self._port_history[-2][1]
                new_ports = listen_ports - prev
                if len(new_ports) >= 10:
                    key = ("portscan", now // 60)
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self.alert.emit("Possible port scan",
                            f"{len(new_ports)} new listening ports opened at once: "
                            f"{sorted(new_ports)[:5]}...", "warning")

            for r in rows:
                # New process
                if r.pid not in self._seen_pids:
                    self._seen_pids.add(r.pid)
                    if (self._baseline_ready
                            and r.pid not in self._baseline_pids
                            and r.connections
                            and r.pid not in self._alerted):
                        self._alerted.add(r.pid)
                        sev = "info"
                        if r.name.lower() not in self.whitelist:
                            sev = "warning"
                            if r.name.lower() in self.blacklist:
                                sev = "critical"
                        self.alert.emit("New network process",
                            f"{r.name} (PID {r.pid}) — {len(r.connections)} conn(s).",
                            sev)
                # Unsigned
                if (r.connections and r.signed is False
                        and r.name.lower() not in self.whitelist):
                    key = ("unsigned", r.name.lower())
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self.alert.emit("Unsigned process",
                            f"{r.name} has no Authenticode signature.", "warning")
                # Blacklist
                if r.connections and r.name.lower() in self.blacklist:
                    key = ("blacklist", r.pid)
                    if key not in self._alerted:
                        self._alerted.add(key)
                        self.alert.emit("Blacklisted process active",
                            f"{r.name} (PID {r.pid}) is on the blacklist.", "critical")
                # High download
                total = self._bytes_total.get(r.pid, 0) + r.down * self.interval
                self._bytes_total[r.pid] = total
                key = ("dl", r.pid)
                if total >= self.threshold and key not in self._alerted:
                    self._alerted.add(key)
                    self.alert.emit("High download volume",
                        f"{r.name} downloaded > {total/1024/1024:.1f} MB.", "info")

        def stop(self): self._run = False


    # ============================================================
    # 10) TABLE MODEL
    # ============================================================
    class ProcessModel(QAbstractTableModel):
        HEADERS = ["PID","Process","↑ Up","↓ Down","Conns","Domains",
                   "Status","Signed","Block"]
        DEFAULT_VISIBLE = [True]*9

        @staticmethod
        def _sort_key(r, col, blocked):
            if col == 0: return r.pid
            if col == 1: return r.name.lower()
            if col == 2: return r.up
            if col == 3: return r.down
            if col == 4: return len(r.connections)
            if col == 5: return ", ".join(sorted(r.domains)).lower() if r.domains else ""
            if col == 6: return 1 if r.pid in blocked else 0
            if col == 7:
                return 0 if r.signed is True else (2 if r.signed is False else 1)
            if col == 8: return 1 if r.pid in blocked else 0
            return 0

        def __init__(self):
            super().__init__()
            self._rows = []; self._blocked = set()
            self._visible = list(self.DEFAULT_VISIBLE)

        def set_visible(self, vis):
            self.beginResetModel()
            self._visible = list(vis)
            self.endResetModel()

        def set_rows(self, rows, blocked):
            self.beginResetModel()
            self._rows = rows; self._blocked = blocked
            self.endResetModel()

        def sort(self, col, order):
            if col < 0 or col >= len(self.HEADERS): return
            reverse = order == Qt.DescendingOrder
            self.layoutAboutToBeChanged.emit()
            self._rows.sort(key=lambda r: self._sort_key(r, col, self._blocked),
                           reverse=reverse)
            self.layoutChanged.emit()

        def rowCount(self, parent=QModelIndex()): return len(self._rows)
        def columnCount(self, parent=QModelIndex()):
            return sum(1 for v in self._visible if v)

        def _real_col(self, vis_idx):
            count = 0
            for i, v in enumerate(self._visible):
                if v:
                    if count == vis_idx: return i
                    count += 1
            return -1

        def headerData(self, s, o, role=Qt.DisplayRole):
            if role == Qt.DisplayRole and o == Qt.Horizontal:
                real = self._real_col(s)
                return self.HEADERS[real] if real >= 0 else ""
            return None

        def data(self, idx, role=Qt.DisplayRole):
            if not idx.isValid(): return None
            r = self._rows[idx.row()]
            c = self._real_col(idx.column())
            blocked = r.pid in self._blocked
            if role == Qt.DisplayRole:
                if c == 0: return str(r.pid)
                if c == 1: return r.name
                if c == 2: return fmt_speed(r.up)
                if c == 3: return fmt_speed(r.down)
                if c == 4: return str(len(r.connections))
                if c == 5: return ", ".join(sorted(r.domains))[:60] if r.domains else "—"
                if c == 6: return "Blocked" if blocked else "Active"
                if c == 7:
                    if r.signed is True: return "✓"
                    if r.signed is False: return "✗"
                    return "?"
                if c == 8: return "🔒" if blocked else ""
            if role == Qt.ForegroundRole:
                if c == 6 and blocked: return QBrush(QColor("#c0392b"))
                if c == 7 and r.signed is False: return QBrush(QColor("#e74c3c"))
                if c == 7 and r.signed is True: return QBrush(QColor("#27ae60"))
            if role == Qt.TextAlignmentRole and c in (0,2,3,4,7):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return None

        def get_row(self, i): return self._rows[i] if 0 <= i < len(self._rows) else None
        def find(self, pid):
            for i, r in enumerate(self._rows):
                if r.pid == pid: return i
            return -1


    # ============================================================
    # 11) FLOATING METER + TASKBAR OVERLAY
    # ============================================================
    class FloatingMeter(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent, Qt.Window | Qt.FramelessWindowHint |
                             Qt.WindowStaysOnTopHint | Qt.Tool)
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setFixedSize(300, 130)
            self._drag_pos = None
            self._hist_up = deque(maxlen=60)
            self._hist_down = deque(maxlen=60)
            self._user_opacity = 0.85
            lay = QVBoxLayout(self)
            lay.setContentsMargins(10, 6, 10, 6); lay.setSpacing(2)
            num_row = QHBoxLayout()
            self.lbl_up = QLabel("↑ 0 B/s"); self.lbl_up.setFont(QFont("Segoe UI", 12, QFont.Bold))
            self.lbl_up.setStyleSheet("color:#e74c3c;")
            self.lbl_down = QLabel("↓ 0 B/s"); self.lbl_down.setFont(QFont("Segoe UI", 12, QFont.Bold))
            self.lbl_down.setStyleSheet("color:#27ae60;")
            num_row.addWidget(self.lbl_up); num_row.addStretch(); num_row.addWidget(self.lbl_down)
            lay.addLayout(num_row)
            self.plot = pg.PlotWidget()
            self.plot.setBackground(None); self.plot.setMouseEnabled(False, False)
            self.plot.hideAxis("left"); self.plot.hideAxis("bottom")
            self.plot.setMenuEnabled(False)
            self.curve_up = self.plot.plot(pen=pg.mkPen("#e74c3c", width=2),
                fillLevel=0, brush=pg.mkBrush(231,76,60,90))
            self.curve_down = self.plot.plot(pen=pg.mkPen("#27ae60", width=2),
                fillLevel=0, brush=pg.mkBrush(39,174,96,90))
            lay.addWidget(self.plot)
            self.setStyleSheet("FloatingMeter{background:rgba(28,28,30,230);"
                              "border-radius:10px;border:1px solid #555;}")

        def set_speed(self, up, down):
            self._hist_up.append(up); self._hist_down.append(down)
            self.lbl_up.setText(f"↑ {fmt_speed(up)}")
            self.lbl_down.setText(f"↓ {fmt_speed(down)}")
            self.curve_up.setData(list(self._hist_up))
            self.curve_down.setData(list(self._hist_down))

        def set_user_opacity(self, v):
            self._user_opacity = max(0.3, min(1.0, v))
            self.setWindowOpacity(self._user_opacity)

        def set_idle(self, is_idle):
            self.setWindowOpacity(min(0.30, self._user_opacity) if is_idle else self._user_opacity)

        def mousePressEvent(self, e):
            if e.button() == Qt.LeftButton:
                self._drag_pos = e.globalPos() - self.frameGeometry().topLeft()
        def mouseMoveEvent(self, e):
            if e.buttons() == Qt.LeftButton and self._drag_pos:
                self.move(e.globalPos() - self._drag_pos)
        def mouseReleaseEvent(self, e): self._drag_pos = None


    class TaskbarOverlay(QWidget):
        def __init__(self, dark_mode=True, parent=None):
            super().__init__(parent, Qt.FramelessWindowHint |
                             Qt.WindowStaysOnTopHint | Qt.Tool)
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setAttribute(Qt.WA_ShowWithoutActivating)
            self.setAttribute(Qt.WA_TransparentForMouseEvents)
            self.setFixedHeight(28); self.setFixedWidth(190)
            self._dark = dark_mode
            self._label = QLabel(self); self._label.setGeometry(0, 0, 190, 28)
            self._label.setAlignment(Qt.AlignCenter)
            self._label.setFont(QFont("Segoe UI Variable", 9, QFont.Bold))
            self._apply_theme()
            if HAS_WIN32:
                try:
                    hwnd = int(self.winId())
                    style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                    win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE,
                        style | win32con.WS_EX_TRANSPARENT | win32con.WS_EX_LAYERED)
                except Exception as e: log.warning(f"overlay: {e}")
            self._pos_timer = QTimer(self)
            self._pos_timer.timeout.connect(self._reposition)
            self._pos_timer.start(500); self._reposition()

        def set_speed(self, up, down):
            self._label.setText(f"↑{fmt_speed(up)}   ↓{fmt_speed(down)}")

        def _apply_theme(self):
            if self._dark:
                color, bg = "#e0e0e0", "rgba(30,30,30,180)"
            else:
                color, bg = "#1a1a1a", "rgba(255,255,255,180)"
            self._label.setStyleSheet(
                f"color:{color};background:{bg};border-radius:6px;padding:0 6px;")

        def set_dark_mode(self, dark):
            if dark != self._dark: self._dark = dark; self._apply_theme()

        def _reposition(self):
            if not HAS_WIN32: return
            try:
                taskbar = win32gui.FindWindow("Shell_TrayWnd", None)
                if not taskbar: return
                notify = win32gui.FindWindowEx(taskbar, 0, "TrayNotifyWnd", None)
                if not notify: return
                tr = win32gui.GetWindowRect(notify)
                screen = QGuiApplication.primaryScreen().availableGeometry()
                x = tr[0] - self.width() - 6
                y = tr[1] + (tr[3] - tr[1] - self.height()) // 2
                x = max(screen.left(), min(x, screen.right() - self.width()))
                y = max(screen.top(), min(y, screen.bottom() - self.height()))
                self.move(x, y)
            except Exception: pass

        def stop(self): self._pos_timer.stop()


    # ============================================================
    # 12) DOWNLOAD STOPWATCH + MONTHLY QUOTA
    # ============================================================
    class DownloadStopwatch(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            lay = QVBoxLayout(self); lay.setSpacing(4)
            box = QGroupBox("Download Stopwatch"); bl = QVBoxLayout(box)
            self.lbl_time = QLabel("00:00"); self.lbl_time.setFont(QFont("Consolas", 22, QFont.Bold))
            self.lbl_time.setAlignment(Qt.AlignCenter)
            row = QHBoxLayout()
            self.lbl_dl = QLabel("Downloaded: 0 B"); self.lbl_avg = QLabel("Avg: 0 B/s")
            row.addWidget(self.lbl_dl); row.addStretch(); row.addWidget(self.lbl_avg)
            bl.addWidget(self.lbl_time); bl.addLayout(row)
            btn_row = QHBoxLayout()
            self.btn_start = QPushButton("▶ Start"); self.btn_stop = QPushButton("⏸ Stop")
            self.btn_reset = QPushButton("⟲ Reset")
            self.btn_start.clicked.connect(self.start)
            self.btn_stop.clicked.connect(self.stop)
            self.btn_reset.clicked.connect(self.reset)
            self.btn_stop.setEnabled(False)
            btn_row.addWidget(self.btn_start); btn_row.addWidget(self.btn_stop); btn_row.addWidget(self.btn_reset)
            bl.addLayout(btn_row); lay.addWidget(box)
            self._running = False; self._start_time = None
            self._elapsed = 0.0; self._downloaded = 0.0; self._last_tick = None
            self._ui_timer = QTimer(self)
            self._ui_timer.timeout.connect(self._refresh_ui); self._ui_timer.start(200)

        def start(self):
            if self._running: return
            self._running = True; self._start_time = time.time(); self._last_tick = None
            self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        def stop(self):
            if not self._running: return
            self._elapsed += time.time() - self._start_time
            self._running = False; self._start_time = None
            self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        def reset(self):
            self._running = False; self._start_time = None
            self._elapsed = 0.0; self._downloaded = 0.0; self._last_tick = None
            self.lbl_time.setText("00:00"); self.lbl_dl.setText("Downloaded: 0 B")
            self.lbl_avg.setText("Avg: 0 B/s")
            self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        def feed(self, down_bps):
            if not self._running: return
            now = time.time()
            if self._last_tick is not None:
                self._downloaded += down_bps * (now - self._last_tick)
            self._last_tick = now; self._refresh_ui()
        def _refresh_ui(self):
            el = (self._elapsed + (time.time() - self._start_time)
                  if self._running and self._start_time else self._elapsed)
            self.lbl_time.setText(fmt_duration(el))
            self.lbl_dl.setText(f"Downloaded: {fmt_bytes(self._downloaded)}")
            avg = self._downloaded / el if el > 0 else 0
            self.lbl_avg.setText(f"Avg: {fmt_speed(avg)}")


    class MonthlyQuotaWidget(QWidget):
        alert_requested = pyqtSignal(str, str, str)
        def __init__(self, db, settings, parent=None):
            super().__init__(parent)
            self.db = db; self.settings = settings; self._last_alert_pct = 0
            lay = QVBoxLayout(self); lay.setSpacing(4)
            box = QGroupBox("Monthly Data Quota"); bl = QVBoxLayout(box)
            self.lbl_used = QLabel("Used: —")
            self.bar = QProgressBar(); self.bar.setRange(0,100); self.bar.setValue(0)
            self.bar.setTextVisible(True)
            self.lbl_status = QLabel("No cap set.")
            bl.addWidget(self.lbl_used); bl.addWidget(self.bar); bl.addWidget(self.lbl_status)
            lay.addWidget(box)
            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh); self._timer.start(60000)
            self.refresh()

        def _billing_period(self):
            today = date.today()
            start_day = max(1, min(28, self.settings.value("billing_start_day", 1, int)))
            if today.day >= start_day: start = date(today.year, today.month, start_day)
            elif today.month == 1: start = date(today.year - 1, 12, start_day)
            else: start = date(today.year, today.month - 1, start_day)
            next_start = (date(start.year + 1, 1, start_day) if start.month == 12
                         else date(start.year, start.month + 1, start_day))
            return start, next_start - timedelta(days=1)

        def refresh(self):
            cap_mb = self.settings.value("monthly_cap_mb", 0, int)
            if cap_mb <= 0:
                self.bar.setValue(0); self.lbl_used.setText("Used: — (no cap)")
                self.lbl_status.setText("No cap set."); return
            start, end = self._billing_period()
            up, down = self.db.get_range_usage(start, end)
            total = up + down; cap = cap_mb * 1024 * 1024
            pct = min(100, int(total * 100 / cap)) if cap else 0
            self.bar.setValue(pct)
            self.lbl_used.setText(
                f"Used: {fmt_bytes(total)} / {fmt_bytes(cap)}  ({start} → {end})")
            if pct >= 100:
                self.bar.setStyleSheet("QProgressBar::chunk{background:#c0392b;}")
                status, color = "⛔ Limit exceeded!", "#c0392b"
            elif pct >= 90:
                self.bar.setStyleSheet("QProgressBar::chunk{background:#e67e22;}")
                status, color = "⚠ 90% used", "#e67e22"
            elif pct >= 80:
                self.bar.setStyleSheet("QProgressBar::chunk{background:#f1c40f;}")
                status, color = "⚠ 80% used", "#f39c12"
            else:
                self.bar.setStyleSheet("QProgressBar::chunk{background:#27ae60;}")
                status, color = "OK", "#27ae60"
            self.lbl_status.setText(status)
            self.lbl_status.setStyleSheet(f"color:{color};font-weight:bold;")
            for t in (80, 90, 100):
                if pct >= t and self._last_alert_pct < t:
                    self.alert_requested.emit(
                        "Monthly data alert",
                        f"{t}% used ({fmt_bytes(total)} of {fmt_bytes(cap)}).",
                        "warning" if t < 100 else "critical")
                    break
            self._last_alert_pct = pct


    # ============================================================
    # 13) FILTER PRESETS
    # ============================================================
    class FilterPresetsBar(QWidget):
        preset_selected = pyqtSignal(str)
        def __init__(self, parent=None):
            super().__init__(parent)
            lay = QHBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(4)
            lay.addWidget(QLabel("Presets:"))
            self._buttons = {}
            for name in ["All", "External", "Blocked", "Unsigned", "High Traffic", "Listening"]:
                b = QPushButton(name)
                b.setCheckable(True); b.setChecked(name == "All")
                b.clicked.connect(lambda _, n=name: self._select(n))
                self._buttons[name] = b; lay.addWidget(b)
            lay.addStretch()
        def _select(self, name):
            for n, b in self._buttons.items(): b.setChecked(n == name)
            self.preset_selected.emit(name)


    # ============================================================
    # 14) COLUMN VISIBILITY DIALOG
    # ============================================================
    class ColumnVisibilityDialog(QDialog):
        def __init__(self, visible, headers, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Show/Hide Columns")
            self.setMinimumWidth(280)
            self._checks = []
            lay = QVBoxLayout(self)
            for i, h in enumerate(headers):
                cb = QCheckBox(h); cb.setChecked(visible[i])
                lay.addWidget(cb); self._checks.append(cb)
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
            lay.addWidget(btns)
        def get_visibility(self): return [cb.isChecked() for cb in self._checks]


    # ============================================================
    # 15) ALERT RULES DIALOG
    # ============================================================
    class AlertRulesDialog(QDialog):
        def __init__(self, settings, parent=None):
            super().__init__(parent)
            self.settings = settings
            self.setWindowTitle("Alert Rules"); self.setMinimumWidth(420)
            lay = QVBoxLayout(self)
            self.cb_enabled = QCheckBox("Enable alerts"); lay.addWidget(self.cb_enabled)
            self.cb_new_proc = QCheckBox("New process with network activity")
            self.cb_unsigned = QCheckBox("Unsigned process with network activity")
            self.cb_portscan = QCheckBox("Possible port scan (10+ new ports at once)")
            self.cb_blacklist = QCheckBox("Blacklisted process becomes active")
            for cb in (self.cb_new_proc, self.cb_unsigned, self.cb_portscan, self.cb_blacklist):
                lay.addWidget(cb)
            form = QFormLayout()
            self.spin_dl = QSpinBox(); self.spin_dl.setRange(1, 100000)
            self.spin_dl.setSuffix(" MB")
            form.addRow("High download threshold:", self.spin_dl)
            lay.addLayout(form)
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.accepted.connect(self._save); btns.rejected.connect(self.reject)
            lay.addWidget(btns)
            # load
            self.cb_enabled.setChecked(settings.value("alerts_enabled", True, bool))
            self.cb_new_proc.setChecked(settings.value("alert_new_proc", True, bool))
            self.cb_unsigned.setChecked(settings.value("alert_unsigned", True, bool))
            self.cb_portscan.setChecked(settings.value("alert_portscan", True, bool))
            self.cb_blacklist.setChecked(settings.value("alert_blacklist", True, bool))
            self.spin_dl.setValue(settings.value("download_threshold_mb", 50, int))

        def _save(self):
            s = self.settings
            s.setValue("alerts_enabled", self.cb_enabled.isChecked())
            s.setValue("alert_new_proc", self.cb_new_proc.isChecked())
            s.setValue("alert_unsigned", self.cb_unsigned.isChecked())
            s.setValue("alert_portscan", self.cb_portscan.isChecked())
            s.setValue("alert_blacklist", self.cb_blacklist.isChecked())
            s.setValue("download_threshold_mb", self.spin_dl.value())
            self.accept()


    # ============================================================
    # 16) BLACKLIST DIALOG
    # ============================================================
    class BlacklistDialog(QDialog):
        def __init__(self, blacklist, whitelist, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Blacklist / Whitelist"); self.setMinimumSize(500, 400)
            lay = QVBoxLayout(self)
            h = QHBoxLayout()
            h.addWidget(QLabel("<b>Blacklist</b> (always alert on activity)"))
            h.addStretch(); lay.addLayout(h)
            self.bl_list = QListWidget()
            for n in sorted(blacklist): self.bl_list.addItem(n)
            lay.addWidget(self.bl_list)
            bl_btns = QHBoxLayout()
            add_bl = QPushButton("+ Add"); rem_bl = QPushButton("− Remove")
            add_bl.clicked.connect(lambda: self._add_item(self.bl_list))
            rem_bl.clicked.connect(lambda: self._remove_item(self.bl_list))
            bl_btns.addWidget(add_bl); bl_btns.addWidget(rem_bl); bl_btns.addStretch()
            lay.addLayout(bl_btns)
            lay.addWidget(QLabel("<b>Whitelist</b> (never alert)"))
            self.wl_list = QListWidget()
            for n in sorted(whitelist): self.wl_list.addItem(n)
            lay.addWidget(self.wl_list)
            wl_btns = QHBoxLayout()
            add_wl = QPushButton("+ Add"); rem_wl = QPushButton("− Remove")
            add_wl.clicked.connect(lambda: self._add_item(self.wl_list))
            rem_wl.clicked.connect(lambda: self._remove_item(self.wl_list))
            wl_btns.addWidget(add_wl); wl_btns.addWidget(rem_wl); wl_btns.addStretch()
            lay.addLayout(wl_btns)
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
            lay.addWidget(btns)

        def _add_item(self, widget):
            text, ok = QInputDialog.getText(self, "Add", "Process name (e.g. chrome.exe):")
            if ok and text.strip():
                widget.addItem(text.strip().lower())
        def _remove_item(self, widget):
            item = widget.currentItem()
            if item: widget.takeItem(widget.row(item))
        def get_lists(self):
            return ([self.bl_list.item(i).text() for i in range(self.bl_list.count())],
                    [self.wl_list.item(i).text() for i in range(self.wl_list.count())])


    # ============================================================
    # 17) ALERT HISTORY VIEW
    # ============================================================
    class AlertHistoryView(QWidget):
        def __init__(self, db, parent=None):
            super().__init__(parent)
            self.db = db
            lay = QVBoxLayout(self)
            top = QHBoxLayout()
            refresh = QPushButton("🔍 Refresh")
            refresh.clicked.connect(self.refresh)
            clear = QPushButton("🗑 Clear All")
            clear.clicked.connect(self._clear)
            top.addWidget(refresh); top.addWidget(clear); top.addStretch()
            lay.addLayout(top)
            self.table = QTableWidget()
            self.table.setColumnCount(4)
            self.table.setHorizontalHeaderLabels(["Time", "Severity", "Title", "Body"])
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.verticalHeader().setVisible(False)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setSortingEnabled(True)
            lay.addWidget(self.table)
            self.refresh()

        def refresh(self):
            rows = self.db.get_alerts(500)
            self.table.setRowCount(len(rows))
            for i, (ts, title, body, sev) in enumerate(rows):
                self.table.setItem(i, 0, QTableWidgetItem(ts))
                sev_item = QTableWidgetItem(sev or "info")
                if sev == "critical": sev_item.setForeground(QBrush(QColor("#c0392b")))
                elif sev == "warning": sev_item.setForeground(QBrush(QColor("#e67e22")))
                self.table.setItem(i, 1, sev_item)
                self.table.setItem(i, 2, QTableWidgetItem(title))
                self.table.setItem(i, 3, QTableWidgetItem(body))

        def _clear(self):
            if QMessageBox.question(self, "Clear", "Delete all alerts?") != QMessageBox.Yes:
                return
            try:
                conn = sqlite3.connect(self.db.path, timeout=10)
                conn.execute("DELETE FROM alerts"); conn.commit(); conn.close()
            except Exception: pass
            self.refresh()


    # ============================================================
    # 18) DOMAIN STATS VIEW
    # ============================================================
    class DomainStatsView(QWidget):
        def __init__(self, db, parent=None):
            super().__init__(parent)
            self.db = db
            lay = QVBoxLayout(self)
            top = QHBoxLayout()
            refresh = QPushButton("🔍 Refresh")
            refresh.clicked.connect(self.refresh)
            top.addWidget(refresh)
            top.addWidget(QLabel("Days:"))
            self.spin = QSpinBox(); self.spin.setRange(1, 365); self.spin.setValue(7)
            top.addWidget(self.spin); top.addStretch()
            lay.addLayout(top)
            self.table = QTableWidget()
            self.table.setColumnCount(3)
            self.table.setHorizontalHeaderLabels(["Domain", "Connections", "Unique PIDs"])
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.verticalHeader().setVisible(False)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setSortingEnabled(True)
            lay.addWidget(self.table)
            self.refresh()

        def refresh(self):
            rows = self.db.get_domain_stats(self.spin.value())
            self.table.setRowCount(len(rows))
            for i, (dom, cnt, pids) in enumerate(rows):
                self.table.setItem(i, 0, QTableWidgetItem(dom))
                self.table.setItem(i, 1, QTableWidgetItem(str(cnt)))
                self.table.setItem(i, 2, QTableWidgetItem(str(pids)))


    # ============================================================
    # 19) UPDATE CHECKER
    # ============================================================
    class UpdateCheckerDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Check for Updates"); self.setMinimumWidth(400)
            lay = QVBoxLayout(self)
            self.label = QLabel("Checking...")
            self.label.setWordWrap(True)
            lay.addWidget(self.label)
            btns = QDialogButtonBox(QDialogButtonBox.Close)
            btns.rejected.connect(self.reject); btns.accepted.connect(self.accept)
            lay.addWidget(btns)
            self._check()

        def _check(self):
            try:
                import urllib.request
                url = f"https://api.github.com/repos/irpbz/network-monitor/releases/latest"
                req = urllib.request.Request(url, headers={"User-Agent": "NetMonPro"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                latest = data.get("tag_name", "?").lstrip("v")
                if latest and latest > APP_VERSION:
                    self.label.setText(
                        f"<b>Update available!</b><br>Current: v{APP_VERSION}<br>"
                        f"Latest: v{latest}<br><br>"
                        f"<a href='{data.get('html_url','')}'>Open release page</a>")
                    self.label.setOpenExternalLinks(True)
                else:
                    self.label.setText(f"You are on the latest version (v{APP_VERSION}).")
            except Exception as e:
                self.label.setText(
                    f"Could not check for updates.<br><small>{e}</small><br><br>"
                    f"Visit <a href='{APP_GITHUB}/releases'>GitHub releases</a>.")
                self.label.setOpenExternalLinks(True)


    # ============================================================
    # 20) SETTINGS DIALOG (extended)
    # ============================================================
    class SettingsDialog(QDialog):
        def __init__(self, settings, parent=None):
            super().__init__(parent)
            self.settings = settings
            self.setWindowTitle("Settings"); self.setMinimumWidth(500)
            lay = QVBoxLayout(self)
            form = QFormLayout()

            form.addRow(QLabel("<b>General</b>"))
            self.autostart_cb = QCheckBox("Start with Windows")
            self.autostart_cb.setChecked(is_autostart_enabled())
            form.addRow("", self.autostart_cb)
            self.minimize_cb = QCheckBox("Minimize to tray on close")
            self.minimize_cb.setChecked(settings.value("minimize_to_tray", True, bool))
            form.addRow("", self.minimize_cb)
            self.startmin_cb = QCheckBox("Start minimized")
            self.startmin_cb.setChecked(settings.value("start_minimized", False, bool))
            form.addRow("", self.startmin_cb)

            form.addRow(QLabel("<b>Appearance</b>"))
            self.theme_combo = QComboBox()
            self.theme_combo.addItems(["Light", "Dark"])
            self.theme_combo.setCurrentText(
                settings.value("theme", "Light", str))
            form.addRow("Theme:", self.theme_combo)

            form.addRow(QLabel("<b>Monitoring</b>"))
            self.scan_spin = QSpinBox(); self.scan_spin.setRange(1, 60)
            self.scan_spin.setSuffix(" s")
            self.scan_spin.setValue(settings.value("scan_interval", 2, int))
            form.addRow("Scan interval:", self.scan_spin)
            self.speed_spin = QDoubleSpinBox(); self.speed_spin.setRange(0.1, 5.0)
            self.speed_spin.setSingleStep(0.1); self.speed_spin.setSuffix(" s")
            self.speed_spin.setValue(settings.value("speed_interval", 0.5, float))
            form.addRow("Speed tick:", self.speed_spin)
            self.track_io_cb = QCheckBox("Track per-process I/O")
            self.track_io_cb.setChecked(settings.value("track_io", True, bool))
            form.addRow("", self.track_io_cb)
            self.sniffer_cb = QCheckBox("DPI Sniffer on startup")
            self.sniffer_cb.setChecked(settings.value("sniffer_enabled", True, bool))
            form.addRow("", self.sniffer_cb)

            form.addRow(QLabel("<b>Taskbar Overlay</b>"))
            self.taskbar_cb = QCheckBox("Show taskbar overlay")
            self.taskbar_cb.setChecked(settings.value("taskbar_overlay_enabled", True, bool))
            form.addRow("", self.taskbar_cb)

            form.addRow(QLabel("<b>Monthly Quota</b>"))
            self.cap_spin = QSpinBox(); self.cap_spin.setRange(0, 1000000)
            self.cap_spin.setSuffix(" MB"); self.cap_spin.setSpecialValueText("Disabled")
            self.cap_spin.setValue(settings.value("monthly_cap_mb", 0, int))
            form.addRow("Monthly cap:", self.cap_spin)
            self.billing_day_spin = QSpinBox(); self.billing_day_spin.setRange(1, 28)
            self.billing_day_spin.setValue(settings.value("billing_start_day", 1, int))
            form.addRow("Billing cycle start day:", self.billing_day_spin)

            form.addRow(QLabel("<b>Alerts</b>"))
            self.alert_cb = QCheckBox("Enable alerts")
            self.alert_cb.setChecked(settings.value("alerts_enabled", True, bool))
            form.addRow("", self.alert_cb)
            self.threshold_spin = QSpinBox(); self.threshold_spin.setRange(1, 100000)
            self.threshold_spin.setSuffix(" MB")
            self.threshold_spin.setValue(settings.value("download_threshold_mb", 50, int))
            form.addRow("Per-process download alert:", self.threshold_spin)

            lay.addLayout(form)
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.accepted.connect(self._save); btns.rejected.connect(self.reject)
            lay.addWidget(btns)

        def _save(self):
            s = self.settings
            s.setValue("minimize_to_tray", self.minimize_cb.isChecked())
            s.setValue("start_minimized", self.startmin_cb.isChecked())
            s.setValue("theme", self.theme_combo.currentText())
            s.setValue("scan_interval", self.scan_spin.value())
            s.setValue("speed_interval", self.speed_spin.value())
            s.setValue("track_io", self.track_io_cb.isChecked())
            s.setValue("sniffer_enabled", self.sniffer_cb.isChecked())
            s.setValue("taskbar_overlay_enabled", self.taskbar_cb.isChecked())
            s.setValue("monthly_cap_mb", self.cap_spin.value())
            s.setValue("billing_start_day", self.billing_day_spin.value())
            s.setValue("alerts_enabled", self.alert_cb.isChecked())
            s.setValue("download_threshold_mb", self.threshold_spin.value())
            if self.autostart_cb.isChecked() != is_autostart_enabled():
                set_autostart(self.autostart_cb.isChecked())
            self.accept()


    # ============================================================
    # 21) ABOUT DIALOG
    # ============================================================
    class AboutDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle(f"About {APP_NAME}"); self.setMinimumWidth(430)
            lay = QVBoxLayout(self); lay.setSpacing(8)
            icon_lbl = QLabel()
            icn = load_icon()
            if icn and not icn.isNull(): icon_lbl.setPixmap(icn.pixmap(72, 72))
            icon_lbl.setAlignment(Qt.AlignCenter); lay.addWidget(icon_lbl)
            title = QLabel(f"<h2 style='margin:0;'>{APP_NAME}</h2>")
            title.setAlignment(Qt.AlignCenter); lay.addWidget(title)
            ver = QLabel(f"<p style='color:#888;margin:0;'>Version {APP_VERSION}</p>")
            ver.setAlignment(Qt.AlignCenter); lay.addWidget(ver)
            desc = QLabel(
                "<p style='text-align:center;'>Real-time network monitor with "
                "per-process I/O, DPI, firewall, archive, alerts, theme, "
                "stopwatch, quota, taskbar overlay, and more.</p>")
            desc.setWordWrap(True); desc.setAlignment(Qt.AlignCenter)
            lay.addWidget(desc)
            lay.addWidget(QLabel("<hr>"))
            author = QLabel(
                f"<p style='text-align:center;margin:4px;'><b>{APP_AUTHOR}</b></p>"
                f"<p style='text-align:center;margin:4px;'>"
                f"<a href='{APP_WEBSITE}'>{APP_WEBSITE}</a><br>"
                f"<a href='{APP_GITHUB}'>{APP_GITHUB}</a></p>")
            author.setOpenExternalLinks(True); author.setAlignment(Qt.AlignCenter)
            lay.addWidget(author)
            copy = QLabel(f"<p style='color:#888;text-align:center;margin:6px;'>"
                          f"© 2024 {APP_AUTHOR}</p>")
            copy.setAlignment(Qt.AlignCenter); lay.addWidget(copy)
            btn_row = QHBoxLayout()
            check_btn = QPushButton("🔄 Check for Updates")
            check_btn.clicked.connect(lambda: UpdateCheckerDialog(self).exec_())
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            btn_row.addWidget(check_btn); btn_row.addStretch(); btn_row.addWidget(close_btn)
            lay.addLayout(btn_row)


    # ============================================================
    # 22) MAIN WINDOW
    # ============================================================
    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
            self.setWindowIcon(load_icon())
            self.resize(1500, 1000)

            self._all_rows = []
            self._blocked = {}
            self._smart_rules = []
            self._selected_pid = None
            self._hist_up = deque(maxlen=120)
            self._hist_down = deque(maxlen=120)
            self._pkt_queue = queue.Queue(maxsize=5000)
            self._dns_ip_map = {}
            self._sni_ip_map = {}
            self.floating = None
            self.taskbar_overlay = None
            self._session_sent = 0.0
            self._session_recv = 0.0
            self._usage_acc_up = 0.0
            self._usage_acc_down = 0.0
            self._active_preset = "All"
            self._auto_refresh = True
            self._geoip_reader = None

            self.settings = QSettings(os.path.join(APP_DIR, "settings.ini"),
                                      QSettings.IniFormat)
            self.db = HistoryDB(os.path.join(APP_DIR, "history.db"))
            self._init_geoip()

            self._build_menubar()
            self._build_ui()
            self._build_tray()
            self._apply_theme(self.settings.value("theme", "Light", str))
            self._start_workers()
            self._apply_startup_settings()

            self._usage_timer = QTimer(self)
            self._usage_timer.timeout.connect(self._flush_usage)
            self._usage_timer.start(60000)

        def _init_geoip(self):
            try:
                import geoip2.database
                path = os.path.join(APP_DIR, "GeoLite2-Country.mmdb")
                if os.path.exists(path):
                    self._geoip_reader = geoip2.database.Reader(path)
                    log.info("GeoIP DB loaded")
            except Exception: pass

        def _geoip_country(self, ip):
            if not self._geoip_reader: return ""
            try: return self._geoip_reader.country(ip).country.iso_code or ""
            except Exception: return ""

        # ---------------- MENUBAR ----------------
        def _build_menubar(self):
            mb = self.menuBar()

            m_file = mb.addMenu("&File")
            act_hide = QAction("Minimize to tray", self)
            act_hide.setShortcut("Ctrl+H"); act_hide.triggered.connect(self.hide)
            m_file.addAction(act_hide)
            m_file.addSeparator()
            act_exit = QAction("Exit", self)
            act_exit.setShortcut("Ctrl+Q"); act_exit.triggered.connect(self._quit)
            m_file.addAction(act_exit)

            m_view = mb.addMenu("&View")
            for i, name in enumerate(["Live","Meter","Smart Firewall","Archive",
                                      "Alert History","Domain Stats"]):
                a = QAction(name, self)
                a.triggered.connect(lambda _, idx=i: self.tabs.setCurrentIndex(idx))
                m_view.addAction(a)
            m_view.addSeparator()
            act_cols = QAction("Columns...", self)
            act_cols.triggered.connect(self._show_columns)
            m_view.addAction(act_cols)

            m_set = mb.addMenu("&Settings")
            act_pref = QAction("Preferences...", self)
            act_pref.setShortcut("Ctrl+,"); act_pref.triggered.connect(self._show_settings)
            m_set.addAction(act_pref)
            act_rules = QAction("Alert Rules...", self)
            act_rules.triggered.connect(self._show_alert_rules)
            m_set.addAction(act_rules)
            act_bl = QAction("Blacklist / Whitelist...", self)
            act_bl.triggered.connect(self._show_blacklist)
            m_set.addAction(act_bl)
            m_set.addSeparator()
            self.act_autostart = QAction("Start with Windows", self)
            self.act_autostart.setCheckable(True)
            self.act_autostart.setChecked(is_autostart_enabled())
            self.act_autostart.triggered.connect(self._toggle_autostart)
            m_set.addAction(self.act_autostart)
            self.act_taskbar = QAction("Taskbar Overlay", self)
            self.act_taskbar.setCheckable(True)
            self.act_taskbar.setChecked(
                self.settings.value("taskbar_overlay_enabled", True, bool))
            self.act_taskbar.triggered.connect(self._toggle_taskbar_overlay)
            m_set.addAction(self.act_taskbar)
            act_openlog = QAction("Open Log Folder", self)
            act_openlog.triggered.connect(self._open_log)
            m_set.addAction(act_openlog)

            m_help = mb.addMenu("&Help")
            act_about = QAction("About", self)
            act_about.triggered.connect(self._show_about)
            m_help.addAction(act_about)
            act_update = QAction("Check for Updates", self)
            act_update.triggered.connect(
                lambda: UpdateCheckerDialog(self).exec_())
            m_help.addAction(act_update)
            act_site = QAction("Website", self)
            act_site.triggered.connect(lambda: webbrowser.open(APP_WEBSITE))
            m_help.addAction(act_site)
            act_gh = QAction("GitHub", self)
            act_gh.triggered.connect(lambda: webbrowser.open(APP_GITHUB))
            m_help.addAction(act_gh)

        # ---------------- UI ----------------
        def _build_ui(self):
            central = QWidget(); self.setCentralWidget(central)
            root = QVBoxLayout(central)
            self.tabs = QTabWidget(); root.addWidget(self.tabs)
            self.tabs.addTab(self._build_live_tab(), "Live")
            self.tabs.addTab(self._build_meter_tab(), "Meter")
            self.tabs.addTab(self._build_smart_fw_tab(), "Smart Firewall")
            self.tabs.addTab(self._build_archive_tab(), "Archive")
            self.tabs.addTab(AlertHistoryView(self.db), "Alert History")
            self.tabs.addTab(DomainStatsView(self.db), "Domain Stats")
            self.status_label = QLabel("Ready")
            self.statusBar().addWidget(self.status_label)

        def _build_boot_totals_box(self):
            box = QGroupBox("System Totals"); outer = QVBoxLayout(box)
            up_row = QHBoxLayout()
            self.boot_uptime_lbl = QLabel("Uptime: —")
            self.boot_uptime_lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))
            up_row.addWidget(self.boot_uptime_lbl); up_row.addStretch()
            reset_btn = QPushButton("⟲ Reset Session")
            reset_btn.clicked.connect(self._reset_session)
            up_row.addWidget(reset_btn); outer.addLayout(up_row)
            boot_row = QHBoxLayout()
            self.boot_sent_lbl = QLabel("↑ Since boot: —")
            self.boot_sent_lbl.setStyleSheet("color:#e74c3c;")
            self.boot_recv_lbl = QLabel("↓ Since boot: —")
            self.boot_recv_lbl.setStyleSheet("color:#27ae60;")
            boot_row.addWidget(self.boot_sent_lbl)
            boot_row.addStretch()
            boot_row.addWidget(self.boot_recv_lbl); outer.addLayout(boot_row)
            sess_row = QHBoxLayout()
            self.sess_sent_lbl = QLabel("↑ Session: 0 B")
            self.sess_recv_lbl = QLabel("↓ Session: 0 B")
            sess_row.addWidget(self.sess_sent_lbl)
            sess_row.addStretch()
            sess_row.addWidget(self.sess_recv_lbl); outer.addLayout(sess_row)
            return box

        def _build_live_tab(self):
            live = QWidget(); ll = QVBoxLayout(live)
            gbox = QGroupBox("System Network Speed")
            gl = QVBoxLayout(gbox)
            self.plot = pg.PlotWidget(); self.plot.setBackground("w")
            self.plot.showGrid(x=True, y=True, alpha=0.3)
            self.plot.setLabel("left", "Speed", units="B/s")
            self.plot.addLegend(offset=(10, 10))
            self.curve_up = self.plot.plot(pen=pg.mkPen("#e74c3c", width=2), name="Upload")
            self.curve_down = self.plot.plot(pen=pg.mkPen("#27ae60", width=2), name="Download")
            gl.addWidget(self.plot); ll.addWidget(gbox, stretch=2)

            ll.addWidget(self._build_boot_totals_box())

            # Filter presets
            self.presets = FilterPresetsBar()
            self.presets.preset_selected.connect(self._on_preset_selected)
            ll.addWidget(self.presets)

            ctrl = QHBoxLayout()
            ctrl.addWidget(QLabel("Search:"))
            self.filter_edit = QLineEdit()
            self.filter_edit.setPlaceholderText("name / PID / IP / domain")
            self.filter_edit.textChanged.connect(self._schedule_filter)
            ctrl.addWidget(self.filter_edit, 2)
            ctrl.addWidget(QLabel("Sort:"))
            self.sort_combo = QComboBox()
            self.sort_combo.addItems(["Download", "Upload", "Connections", "Name", "PID"])
            self.sort_combo.currentTextChanged.connect(self._on_sort_combo)
            ctrl.addWidget(self.sort_combo)
            self.sniffer_cb_ui = QCheckBox("DPI")
            self.sniffer_cb_ui.setChecked(self.settings.value("sniffer_enabled", True, bool))
            self.sniffer_cb_ui.stateChanged.connect(self._toggle_sniffer)
            ctrl.addWidget(self.sniffer_cb_ui)
            self.io_cb = QCheckBox("Track I/O")
            self.io_cb.setChecked(self.settings.value("track_io", True, bool))
            self.io_cb.stateChanged.connect(
                lambda st: self.scan_worker.set_track_io(bool(st)))
            ctrl.addWidget(self.io_cb)
            self.btn_autorefresh = QPushButton("⏸ Auto-Refresh")
            self.btn_autorefresh.setCheckable(True)
            self.btn_autorefresh.setChecked(True)
            self.btn_autorefresh.toggled.connect(self._toggle_autorefresh)
            ctrl.addWidget(self.btn_autorefresh)
            ctrl.addStretch()
            ll.addLayout(ctrl)

            splitter = QSplitter(Qt.Vertical)
            self.model = ProcessModel()
            self.table = QTableView(); self.table.setModel(self.model)
            self.table.setSelectionBehavior(QTableView.SelectRows)
            self.table.setEditTriggers(QTableView.NoEditTriggers)
            self.table.setAlternatingRowColors(True)
            self.table.verticalHeader().setVisible(False)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.horizontalHeader().setSortIndicatorShown(True)
            self.table.setSortingEnabled(True)
            self.table.horizontalHeader().setSortIndicator(3, Qt.DescendingOrder)
            self.table.selectionModel().currentRowChanged.connect(self._on_select)
            self.table.doubleClicked.connect(lambda _: self._toggle_block())
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._show_table_menu)
            self.table.horizontalHeader().sortIndicatorChanged.connect(
                self._on_header_sort_changed)
            splitter.addWidget(self.table)
            self.details = QTextEdit(); self.details.setReadOnly(True)
            self.details.setFont(QFont("Consolas", 9))
            splitter.addWidget(self.details); splitter.setSizes([480, 200])
            ll.addWidget(splitter, stretch=3)

            btns = QHBoxLayout()
            for label, slot in [
                ("🚫 Block", self._block_selected),
                ("✅ Unblock", self._unblock_selected),
                ("Toggle", self._toggle_block),
                ("💀 Kill", self._kill_selected),
                ("📥 Export CSV", self._export_csv),
                ("📄 HTML Report", self._export_html),
                ("🔴 Record PCAP", self._toggle_pcap),
                ("📂 Open Log", self._open_log),
                ("💾 Flush Archive", self._flush_archive),
            ]:
                b = QPushButton(label); b.clicked.connect(slot); btns.addWidget(b)
            btns.addStretch(); ll.addLayout(btns)
            return live

        def _build_meter_tab(self):
            w = QWidget(); lay = QVBoxLayout(w); lay.setSpacing(8)
            num_box = QGroupBox("Live Speed"); nl = QHBoxLayout(num_box)
            self.m_up = QLabel("↑ 0 B/s")
            self.m_up.setFont(QFont("Segoe UI", 26, QFont.Bold))
            self.m_up.setStyleSheet("color:#e74c3c;")
            self.m_up.setAlignment(Qt.AlignCenter)
            self.m_down = QLabel("↓ 0 B/s")
            self.m_down.setFont(QFont("Segoe UI", 26, QFont.Bold))
            self.m_down.setStyleSheet("color:#27ae60;")
            self.m_down.setAlignment(Qt.AlignCenter)
            nl.addWidget(self.m_up); nl.addWidget(self.m_down)
            lay.addWidget(num_box)

            graph_box = QGroupBox("Traffic Graph")
            gl = QVBoxLayout(graph_box)
            self.meter_plot = pg.PlotWidget()
            self.meter_plot.setBackground("w")
            self.meter_plot.showGrid(x=True, y=True, alpha=0.25)
            self.meter_plot.setLabel("left", "Speed", units="B/s")
            self.meter_plot.addLegend(offset=(10, 10))
            self.meter_up = self.meter_plot.plot(pen=pg.mkPen("#e74c3c", width=2),
                fillLevel=0, brush=pg.mkBrush(231,76,60,90), name="Upload")
            self.meter_down = self.meter_plot.plot(pen=pg.mkPen("#27ae60", width=2),
                fillLevel=0, brush=pg.mkBrush(39,174,96,90), name="Download")
            gl.addWidget(self.meter_plot); lay.addWidget(graph_box, stretch=1)

            boot_box2 = QGroupBox("System Totals"); bl2 = QVBoxLayout(boot_box2)
            self.m_boot_uptime = QLabel("Uptime: —")
            self.m_boot_sent = QLabel("↑ Since boot: —")
            self.m_boot_recv = QLabel("↓ Since boot: —")
            self.m_sess_sent = QLabel("↑ Session: 0 B")
            self.m_sess_recv = QLabel("↓ Session: 0 B")
            for lbl in (self.m_boot_uptime, self.m_boot_sent, self.m_boot_recv,
                        self.m_sess_sent, self.m_sess_recv):
                bl2.addWidget(lbl)
            lay.addWidget(boot_box2)

            ctrl = QHBoxLayout()
            ctrl.addWidget(QLabel("Display:"))
            self.meter_mode = QComboBox()
            self.meter_mode.addItems(["Both", "Upload only", "Download only"])
            self.meter_mode.currentTextChanged.connect(self._update_meter_curves)
            ctrl.addWidget(self.meter_mode)

            ctrl.addSpacing(10)
            ctrl.addWidget(QLabel("Range:"))
            self.range_combo = QComboBox()
            self.range_combo.addItems(["1m", "5m", "30m"])
            self.range_combo.currentTextChanged.connect(self._on_range_changed)
            ctrl.addWidget(self.range_combo)

            ctrl.addSpacing(10)
            ctrl.addWidget(QLabel("Interface:"))
            self.iface_combo = QComboBox()
            self.iface_combo.addItem("All Interfaces", None)
            try:
                for name in psutil.net_if_addrs().keys():
                    self.iface_combo.addItem(name, name)
            except Exception: pass
            self.iface_combo.currentIndexChanged.connect(self._on_iface_changed)
            ctrl.addWidget(self.iface_combo)

            ctrl.addSpacing(10)
            ctrl.addWidget(QLabel("Opacity:"))
            self.opacity_slider = QSlider(Qt.Horizontal)
            self.opacity_slider.setRange(30, 100); self.opacity_slider.setValue(85)
            self.opacity_slider.setFixedWidth(120)
            self.opacity_slider.valueChanged.connect(self._on_opacity_changed)
            ctrl.addWidget(self.opacity_slider)

            ctrl.addSpacing(10)
            self.btn_float = QPushButton("📌 Show Floating")
            self.btn_float.setCheckable(True)
            self.btn_float.toggled.connect(self._toggle_floating)
            ctrl.addWidget(self.btn_float)

            ctrl.addSpacing(10)
            self.btn_taskbar = QPushButton("📌 Taskbar")
            self.btn_taskbar.setCheckable(True)
            self.btn_taskbar.setChecked(
                self.settings.value("taskbar_overlay_enabled", True, bool))
            self.btn_taskbar.toggled.connect(self._toggle_taskbar_overlay)
            ctrl.addWidget(self.btn_taskbar)

            self.chk_idle_hide = QCheckBox("Dim when idle")
            self.chk_idle_hide.setChecked(True)
            ctrl.addWidget(self.chk_idle_hide)
            ctrl.addStretch()
            lay.addLayout(ctrl)

            bottom = QHBoxLayout()
            self.stopwatch = DownloadStopwatch()
            self.quota_widget = MonthlyQuotaWidget(self.db, self.settings)
            self.quota_widget.alert_requested.connect(self._on_alert)
            bottom.addWidget(self.stopwatch, 1)
            bottom.addWidget(self.quota_widget, 1)
            lay.addLayout(bottom)
            return w

        def _build_smart_fw_tab(self):
            w = QWidget(); lay = QVBoxLayout(w)
            form = QFormLayout()
            self.fw_type = QComboBox()
            self.fw_type.addItems(["Block IP","Block Port (Outbound)",
                                   "Block Domain (via IP list)"])
            form.addRow("Rule type:", self.fw_type)
            self.fw_value = QLineEdit()
            self.fw_value.setPlaceholderText("1.2.3.4 / 27015 / api.example.com")
            form.addRow("Value:", self.fw_value)
            self.fw_direction = QComboBox(); self.fw_direction.addItems(["out","in","both"])
            form.addRow("Direction:", self.fw_direction)
            lay.addLayout(form)
            h = QHBoxLayout()
            b1 = QPushButton("➕ Add Rule"); b1.clicked.connect(self._add_smart_rule)
            b2 = QPushButton("🗑 Remove"); b2.clicked.connect(self._remove_smart_rule)
            h.addWidget(b1); h.addWidget(b2); h.addStretch(); lay.addLayout(h)
            self.fw_table = QTableWidget()
            self.fw_table.setColumnCount(4)
            self.fw_table.setHorizontalHeaderLabels(["Type","Value","Direction","Rule"])
            self.fw_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.fw_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.fw_table.verticalHeader().setVisible(False)
            self.fw_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.fw_table.horizontalHeader().setSortIndicatorShown(True)
            self.fw_table.setSortingEnabled(True)
            lay.addWidget(self.fw_table)
            return w

        def _build_archive_tab(self):
            w = QWidget(); lay = QVBoxLayout(w)
            top = QHBoxLayout()
            self.arc_from = QDateTimeEdit()
            self.arc_from.setDateTime(QDateTime.currentDateTime().addDays(-1))
            self.arc_from.setCalendarPopup(True)
            self.arc_to = QDateTimeEdit()
            self.arc_to.setDateTime(QDateTime.currentDateTime())
            self.arc_to.setCalendarPopup(True)
            top.addWidget(QLabel("From:")); top.addWidget(self.arc_from)
            top.addWidget(QLabel("To:")); top.addWidget(self.arc_to)
            self.arc_kw = QLineEdit()
            self.arc_kw.setPlaceholderText("name / IP / domain")
            top.addWidget(self.arc_kw, 2)
            q = QPushButton("🔍 Query"); q.clicked.connect(self._query_archive)
            top.addWidget(q)
            e = QPushButton("📥 Export"); e.clicked.connect(self._export_archive)
            top.addWidget(e)
            lay.addLayout(top)
            self.arc_table = QTableWidget()
            self.arc_table.setColumnCount(8)
            self.arc_table.setHorizontalHeaderLabels(
                ["Time","PID","Process","Local","Remote","Status","Proto","Domain"])
            self.arc_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.arc_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.arc_table.verticalHeader().setVisible(False)
            self.arc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.arc_table.horizontalHeader().setSortIndicatorShown(True)
            self.arc_table.setSortingEnabled(True)
            lay.addWidget(self.arc_table)
            sb = QGroupBox("Last 7 Days"); sl = QVBoxLayout(sb)
            self.stats_label = QLabel("—")
            self.stats_label.setFont(QFont("Consolas", 9))
            sl.addWidget(self.stats_label); lay.addWidget(sb)
            return w

        def _build_tray(self):
            self.tray = QSystemTrayIcon(self.windowIcon(), self)
            menu = QMenu()
            show_act = QAction("Show", self)
            show_act.triggered.connect(self._show_window); menu.addAction(show_act)
            self.tray_updown = QAction("↑ 0 B/s  ↓ 0 B/s", self)
            self.tray_updown.setEnabled(False); menu.addAction(self.tray_updown)
            menu.addSeparator()
            float_act = QAction("Toggle Floating Meter", self)
            float_act.triggered.connect(
                lambda: self.btn_float.setChecked(not self.btn_float.isChecked()))
            menu.addAction(float_act)
            taskbar_act = QAction("Toggle Taskbar Overlay", self)
            taskbar_act.triggered.connect(lambda: self.act_taskbar.trigger())
            menu.addAction(taskbar_act)
            menu.addSeparator()
            set_act = QAction("Settings...", self)
            set_act.triggered.connect(self._show_settings); menu.addAction(set_act)
            about_act = QAction("About", self)
            about_act.triggered.connect(self._show_about); menu.addAction(about_act)
            menu.addSeparator()
            quit_act = QAction("Quit", self)
            quit_act.triggered.connect(self._quit); menu.addAction(quit_act)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._tray_activated)
            self.tray.show()

        def _tray_activated(self, reason):
            if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
                self._show_window()

        def _show_window(self):
            self.showNormal(); self.raise_(); self.activateWindow()

        def _start_workers(self):
            scan_int = self.settings.value("scan_interval", 2, int)
            speed_int = self.settings.value("speed_interval", 0.5, float)
            track_io = self.settings.value("track_io", True, bool)
            self.speed_worker = SpeedWorker(speed_int)
            self.speed_worker.tick.connect(self._on_speed)
            self.speed_worker.start()
            self.scan_worker = ScanWorker(scan_int)
            self.scan_worker.set_track_io(track_io)
            self.scan_worker.scanned.connect(self._on_scan)
            self.scan_worker.start()
            self.sniffer = SnifferWorker(self._pkt_queue)
            if self.settings.value("sniffer_enabled", True, bool):
                self.sniffer.start()
            self.archive_worker = ArchiveWorker(self.db, 30.0)
            self.archive_worker.start()
            self.alert_worker = AlertWorker(2.0,
                self.settings.value("download_threshold_mb", 50, int),
                self.settings.value("alerts_enabled", True, bool))
            self.alert_worker.set_lists(*self._load_lists())
            self.alert_worker.alert.connect(self._on_alert)
            self.alert_worker.start()
            self.pkt_timer = QTimer(self)
            self.pkt_timer.timeout.connect(self._drain_packets)
            self.pkt_timer.start(500)
            self.filter_timer = QTimer(self)
            self.filter_timer.setSingleShot(True)
            self.filter_timer.timeout.connect(self._apply_filter)
            self.stats_timer = QTimer(self)
            self.stats_timer.timeout.connect(self._refresh_stats)
            self.stats_timer.start(60000)
            if self.settings.value("taskbar_overlay_enabled", True, bool):
                self._show_taskbar_overlay(True)
                self.btn_taskbar.setChecked(True)

        def _apply_startup_settings(self):
            if START_MINIMIZED or self.settings.value("start_minimized", False, bool):
                if self.settings.value("minimize_to_tray", True, bool):
                    self.hide()

        def _load_lists(self):
            try:
                bl = json.loads(self.settings.value("blacklist", "[]", str))
            except Exception: bl = []
            try:
                wl = json.loads(self.settings.value("whitelist", "[]", str))
            except Exception: wl = []
            return bl, wl

        def _save_lists(self, bl, wl):
            self.settings.setValue("blacklist", json.dumps(bl))
            self.settings.setValue("whitelist", json.dumps(wl))

        # ---------------- THEME ----------------
        def _apply_theme(self, theme_name):
            if theme_name == "Dark":
                qss = """
                QWidget { background: #2b2b2b; color: #e0e0e0; }
                QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateTimeEdit,
                QTextEdit, QTextBrowser, QProgressBar, QListWidget {
                    background: #3a3a3a; color: #e0e0e0; border: 1px solid #555;
                    border-radius: 3px; padding: 2px; }
                QPushButton { background: #404040; color: #e0e0e0;
                    border: 1px solid #555; border-radius: 3px; padding: 5px 10px; }
                QPushButton:hover { background: #505050; }
                QPushButton:checked { background: #2980b9; }
                QTableView, QTableWidget { background: #2b2b2b; color: #e0e0e0;
                    alternate-background-color: #333; gridline-color: #444; }
                QHeaderView::section { background: #2980b9; color: white;
                    padding: 4px; border: none; font-weight: bold; }
                QTabWidget::pane { border: 1px solid #444; }
                QTabBar::tab { background: #333; color: #e0e0e0; padding: 6px 12px;
                    border: 1px solid #444; }
                QTabBar::tab:selected { background: #404040; }
                QGroupBox { border: 1px solid #444; border-radius: 4px;
                    margin-top: 8px; padding-top: 8px; }
                QGroupBox::title { subcontrol-origin: margin; left: 8px;
                    padding: 0 4px; color: #e0e0e0; }
                QMenuBar, QMenu { background: #2b2b2b; color: #e0e0e0; }
                QMenu::item:selected { background: #2980b9; }
                QScrollBar:vertical, QScrollBar:horizontal {
                    background: #2b2b2b; border: 1px solid #444; }
                QScrollBar::handle { background: #555; border-radius: 3px; }
                """
            else:
                qss = """
                QTableView, QTableWidget { gridline-color: #ddd; }
                QHeaderView::section { background: #3498db; color: white;
                    padding: 4px; border: none; font-weight: bold; }
                QHeaderView::section:hover { background: #2980b9; }
                """
            self.setStyleSheet(qss)

        # ---------------- CALLBACKS ----------------
        def _on_speed(self, up, down):
            self._hist_up.append(up); self._hist_down.append(down)
            self.curve_up.setData(list(self._hist_up))
            self.curve_down.setData(list(self._hist_down))
            if hasattr(self, "m_up"):
                self.m_up.setText(f"↑ {fmt_speed(up)}")
                self.m_down.setText(f"↓ {fmt_speed(down)}")
                self.meter_up.setData(list(self._hist_up))
                self.meter_down.setData(list(self._hist_down))
            if self.floating and self.floating.isVisible():
                self.floating.set_speed(up, down)
                if self.chk_idle_hide.isChecked():
                    self.floating.set_idle(up < 1024 and down < 1024)
            if self.taskbar_overlay and self.taskbar_overlay.isVisible():
                self.taskbar_overlay.set_speed(up, down)
            if hasattr(self, "stopwatch"):
                self.stopwatch.feed(down)
            dt = self.speed_worker.interval
            self._usage_acc_up += up * dt; self._usage_acc_down += down * dt
            self._session_sent += up * dt; self._session_recv += down * dt
            try:
                net = psutil.net_io_counters()
                uptime_s = time.time() - psutil.boot_time()
                self.boot_uptime_lbl.setText(f"Uptime: {fmt_duration(uptime_s)}")
                self.boot_sent_lbl.setText(f"↑ Since boot: {fmt_bytes(net.bytes_sent)}")
                self.boot_recv_lbl.setText(f"↓ Since boot: {fmt_bytes(net.bytes_recv)}")
                self.sess_sent_lbl.setText(f"↑ Session: {fmt_bytes(self._session_sent)}")
                self.sess_recv_lbl.setText(f"↓ Session: {fmt_bytes(self._session_recv)}")
                if hasattr(self, "m_boot_uptime"):
                    self.m_boot_uptime.setText(f"Uptime: {fmt_duration(uptime_s)}")
                    self.m_boot_sent.setText(f"↑ Since boot: {fmt_bytes(net.bytes_sent)}")
                    self.m_boot_recv.setText(f"↓ Since boot: {fmt_bytes(net.bytes_recv)}")
                    self.m_sess_sent.setText(f"↑ Session: {fmt_bytes(self._session_sent)}")
                    self.m_sess_recv.setText(f"↓ Session: {fmt_bytes(self._session_recv)}")
            except Exception: pass
            self.tray_updown.setText(f"↑ {fmt_speed(up)}  ↓ {fmt_speed(down)}")
            self.status_label.setText(
                f"↑ {fmt_speed(up)}   ↓ {fmt_speed(down)}   |   "
                f"{len(self._all_rows)} procs   |   {time.strftime('%H:%M:%S')}")

        def _reset_session(self):
            self._session_sent = 0.0; self._session_recv = 0.0
            self.statusBar().showMessage("Session reset.", 3000)

        def _on_scan(self, rows):
            self._all_rows = rows
            if self._auto_refresh: self._apply_filter()
            self.alert_worker.feed(rows)
            now = datetime.now().isoformat(sep=" ", timespec="seconds")
            arc = []
            for r in rows:
                for c in r.connections:
                    ip = c["raddr"].split(":")[0] if c["raddr"] else ""
                    domain = self._dns_ip_map.get(ip) or self._sni_ip_map.get(ip) or ""
                    arc.append((now, r.pid, r.name, c["laddr"], c["raddr"],
                                c["status"], c["type"], domain))
            if arc: self.db.enqueue(arc)

        def _drain_packets(self):
            updated = False
            try:
                while True:
                    pkt = self._pkt_queue.get_nowait()
                    ip = pkt.get("ip")
                    if not ip: continue
                    if pkt["kind"] == "dns":
                        self._dns_ip_map[ip] = pkt["domain"]; updated = True
                    elif pkt["kind"] == "sni":
                        self._sni_ip_map[ip] = pkt["domain"]; updated = True
            except queue.Empty: pass
            if updated:
                self.scan_worker.update_dns({**self._dns_ip_map, **self._sni_ip_map})
                for r in self._all_rows:
                    for c in r.connections:
                        ip = c["raddr"].split(":")[0] if c["raddr"] else ""
                        if ip in self._sni_ip_map:
                            r.domains.add(self._sni_ip_map[ip])
                        elif ip in self._dns_ip_map:
                            r.domains.add(self._dns_ip_map[ip])
                self.model.layoutChanged.emit()

        def _on_alert(self, title, body, severity="info"):
            log.warning(f"ALERT [{severity}]: {title} — {body}")
            self.db.add_alert(title, body, severity)
            self.tray.showMessage(title, body, QSystemTrayIcon.Warning, 6000)
            self.statusBar().showMessage(f"⚠ {title}: {body}", 8000)
            # refresh alert history tab if visible
            for i in range(self.tabs.count()):
                w = self.tabs.widget(i)
                if isinstance(w, AlertHistoryView):
                    w.refresh()

        def _flush_usage(self):
            if self._usage_acc_up < 1 and self._usage_acc_down < 1: return
            day = date.today().isoformat()
            self.db.add_usage(day, self._usage_acc_up, self._usage_acc_down)
            self._usage_acc_up = 0.0; self._usage_acc_down = 0.0

        def _schedule_filter(self): self.filter_timer.start(180)

        def _apply_filter(self):
            q = self.filter_edit.text().strip().lower()
            procs = self._all_rows
            # apply preset
            p = self._active_preset
            if p == "External":
                procs = [r for r in procs if any(
                    c["raddr"] and not c["raddr"].startswith(
                        ("127.","10.","192.168.","172.","0.0.0.0","::1"))
                    for c in r.connections)]
            elif p == "Blocked":
                procs = [r for r in procs if r.pid in self._blocked]
            elif p == "Unsigned":
                procs = [r for r in procs if r.signed is False]
            elif p == "High Traffic":
                procs = [r for r in procs if (r.up + r.down) > 100 * 1024]
            elif p == "Listening":
                procs = [r for r in procs if any(
                    not c["raddr"] for c in r.connections)]
            if q:
                procs = [r for r in procs
                    if q in r.name.lower() or q in str(r.pid)
                    or any(q in c["raddr"].lower() or q in c["laddr"].lower()
                           for c in r.connections)
                    or any(q in d.lower() for d in r.domains)]
            header = self.table.horizontalHeader()
            col = header.sortIndicatorSection()
            order = header.sortIndicatorOrder()
            if col >= 0:
                reverse = order == Qt.DescendingOrder
                procs = sorted(procs,
                    key=lambda r: ProcessModel._sort_key(r, col, set(self._blocked)),
                    reverse=reverse)
            self.table.setSortingEnabled(False)
            self.model.set_rows(procs, set(self._blocked))
            self.table.setSortingEnabled(True)
            if self._selected_pid is not None:
                r = self.model.find(self._selected_pid)
                if r >= 0: self.table.selectRow(r)

        def _on_preset_selected(self, name):
            self._active_preset = name
            self._apply_filter()

        def _on_sort_combo(self, text):
            mapping = {"PID":0,"Name":1,"Upload":2,"Download":3,"Connections":4}
            col = mapping.get(text, 3)
            order = (Qt.DescendingOrder
                     if text in ("Upload","Download","Connections") else Qt.AscendingOrder)
            self.table.sortByColumn(col, order)

        def _on_header_sort_changed(self, col, order):
            mapping = {0:"PID",1:"Name",2:"Upload",3:"Download",4:"Connections"}
            name = mapping.get(col)
            if name:
                self.sort_combo.blockSignals(True)
                self.sort_combo.setCurrentText(name)
                self.sort_combo.blockSignals(False)

        def _toggle_autorefresh(self, checked):
            self._auto_refresh = checked
            self.btn_autorefresh.setText(
                "⏸ Auto-Refresh" if checked else "▶ Auto-Refresh (paused)")

        def _on_range_changed(self, text):
            n = {"1m":120, "5m":600, "30m":3600}.get(text, 120)
            # keep current data but resize deque
            self._hist_up = deque(list(self._hist_up), maxlen=n)
            self._hist_down = deque(list(self._hist_down), maxlen=n)

        def _on_select(self, cur, prev):
            p = self._current()
            if p is None:
                self._selected_pid = None; self.details.clear(); return
            self._selected_pid = p.pid
            sig_text = ("✓ Signed" if p.signed is True
                        else "✗ Unsigned" if p.signed is False else "? Unknown")
            lines = [
                f"Process : {p.name}",
                f"PID     : {p.pid}",
                f"Exe     : {p.exe or '(unknown)'}",
                f"Blocked : {'YES' if p.pid in self._blocked else 'NO'}",
                f"Signed  : {sig_text}",
                f"Domains : {', '.join(sorted(p.domains)) or '—'}",
                "",
                f"Speed   : ↑ {fmt_speed(p.up):>10}   ↓ {fmt_speed(p.down):>10}",
                f"Total   : ↑ {fmt_bytes(p.total_up):>10}   ↓ {fmt_bytes(p.total_down):>10}",
                "",
                f"Connections ({len(p.connections)}):"]
            for c in p.connections[:150]:
                ip = c["raddr"].split(":")[0] if c["raddr"] else ""
                dom = self._sni_ip_map.get(ip) or self._dns_ip_map.get(ip) or ""
                country = self._geoip_country(ip) if ip else ""
                lines.append(
                    f"  [{c['type']:3}] {c['laddr']:22} -> "
                    f"{c['raddr'] or '(listen)':22} [{c['status']}] {dom} {country}")
            self.details.setPlainText("\n".join(lines))

        def _current(self):
            idx = self.table.currentIndex()
            return self.model.get_row(idx.row()) if idx.isValid() else None

        # ---------------- CONTEXT MENU ----------------
        def _show_table_menu(self, pos):
            idx = self.table.indexAt(pos)
            if not idx.isValid(): return
            self.table.selectRow(idx.row())
            p = self._current()
            if not p: return
            menu = QMenu(self)

            ips = set()
            for c in p.connections:
                if c["raddr"]:
                    ip = c["raddr"].split(":")[0]
                    if ip and not ip.startswith(("127.","0.0.0.0","::1")):
                        ips.add(ip)
            if ips:
                first_ip = sorted(ips)[0]
                menu.addAction(f"📋 Copy IP ({first_ip})",
                    lambda: QApplication.clipboard().setText(first_ip))
            menu.addAction(f"📋 Copy name",
                lambda: QApplication.clipboard().setText(p.name))
            menu.addAction(f"📋 Copy PID",
                lambda: QApplication.clipboard().setText(str(p.pid)))

            if ips:
                menu.addSeparator()
                for ip in list(ips)[:3]:
                    sub = menu.addMenu(f"🌐 {ip}")
                    sub.addAction("Ping", lambda i=ip: self._ping_ip(i))
                    sub.addAction("WHOIS",
                        lambda i=ip: webbrowser.open(f"https://www.whois.com/whois/{i}"))
                    sub.addAction("VirusTotal",
                        lambda i=ip: webbrowser.open(
                            f"https://www.virustotal.com/gui/ip-address/{i}"))
                    sub.addAction("AbuseIPDB",
                        lambda i=ip: webbrowser.open(
                            f"https://www.abuseipdb.com/check/{i}"))

            menu.addSeparator()
            if p.pid in self._blocked:
                menu.addAction("✅ Unblock", lambda: self._do_unblock(p.pid))
            else:
                menu.addAction("🚫 Block", lambda: self._do_block(p))
            menu.addAction("💀 Kill", lambda: self._do_kill(p))
            menu.addSeparator()
            menu.addAction("➕ Add to whitelist",
                lambda: self._add_to_list(p.name, "whitelist"))
            menu.addAction("➕ Add to blacklist",
                lambda: self._add_to_list(p.name, "blacklist"))

            menu.exec_(self.table.viewport().mapToGlobal(pos))

        def _add_to_list(self, name, kind):
            bl, wl = self._load_lists()
            n = name.lower()
            if kind == "blacklist":
                if n not in bl: bl.append(n)
                if n in wl: wl.remove(n)
            else:
                if n not in wl: wl.append(n)
                if n in bl: bl.remove(n)
            self._save_lists(bl, wl)
            self.alert_worker.set_lists(bl, wl)
            self.statusBar().showMessage(f"{name} added to {kind}.", 3000)

        def _ping_ip(self, ip):
            try:
                result = subprocess.run(
                    ["ping", "-n", "4", "-w", "1000", ip],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                QMessageBox.information(self, f"Ping {ip}",
                    result.stdout or result.stderr or "(no output)")
            except Exception as e:
                QMessageBox.warning(self, "Ping failed", str(e))

        def _kill_selected(self):
            p = self._current()
            if p: self._do_kill(p)

        def _do_kill(self, p):
            if QMessageBox.question(self, "Kill",
                    f"Terminate {p.name} (PID {p.pid})?") != QMessageBox.Yes:
                return
            try:
                proc = psutil.Process(p.pid)
                proc.terminate()
                try: proc.wait(timeout=3)
                except psutil.TimeoutExpired: proc.kill()
                log.info(f"Killed PID {p.pid}")
            except Exception as e:
                QMessageBox.critical(self, "Kill failed", str(e))

        # ---------------- METER HELPERS ----------------
        def _update_meter_curves(self, mode):
            self.meter_up.setVisible(mode in ("Both","Upload only"))
            self.meter_down.setVisible(mode in ("Both","Download only"))

        def _on_opacity_changed(self, v):
            if self.floating and self.floating.isVisible():
                self.floating.set_user_opacity(v / 100.0)

        def _on_iface_changed(self):
            self.speed_worker.set_interface(self.iface_combo.currentData())

        def _toggle_floating(self, checked):
            if checked:
                if self.floating is None: self.floating = FloatingMeter()
                screen = QGuiApplication.primaryScreen().availableGeometry()
                self.floating.move(screen.right() - self.floating.width() - 20,
                                   screen.bottom() - self.floating.height() - 20)
                self.floating.set_user_opacity(self.opacity_slider.value() / 100.0)
                self.floating.show()
                self.btn_float.setText("📌 Hide Floating")
            else:
                if self.floating: self.floating.hide()
                self.btn_float.setText("📌 Show Floating")

        def _show_taskbar_overlay(self, show):
            if not HAS_WIN32:
                QMessageBox.warning(self, "Taskbar",
                    "pywin32 required. Install: pip install pywin32")
                return
            if show:
                if self.taskbar_overlay is None:
                    dark = self.settings.value("theme", "Light", str) == "Dark"
                    self.taskbar_overlay = TaskbarOverlay(dark_mode=dark)
                self.taskbar_overlay.show()
                self.taskbar_overlay._reposition()
            else:
                if self.taskbar_overlay:
                    self.taskbar_overlay.stop(); self.taskbar_overlay.hide()

        def _toggle_taskbar_overlay(self):
            enabled = self.act_taskbar.isChecked()
            self.settings.setValue("taskbar_overlay_enabled", enabled)
            self.btn_taskbar.setChecked(enabled)
            self._show_taskbar_overlay(enabled)

        # ---------------- FIREWALL ----------------
        def _netsh(self, args):
            try:
                r = subprocess.run(["netsh","advfirewall","firewall"] + args,
                    capture_output=True, text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                return r.returncode == 0, (r.stdout + r.stderr).strip()
            except Exception as e: return False, str(e)

        def _block_selected(self):
            p = self._current()
            if p: self._do_block(p)

        def _unblock_selected(self):
            p = self._current()
            if p: self._do_unblock(p.pid)

        def _toggle_block(self):
            p = self._current()
            if not p: return
            if p.pid in self._blocked: self._do_unblock(p.pid)
            else: self._do_block(p)

        def _do_block(self, p):
            if p.pid in self._blocked: return
            exe = p.exe
            if not exe:
                try: exe = psutil.Process(p.pid).exe() or ""; p.exe = exe
                except Exception: exe = ""
            if not exe:
                QMessageBox.warning(self, "Error", f"No exe for PID {p.pid}"); return
            rule = f"NetMon_Block_{p.pid}_{int(time.time())}"
            ok, msg = self._netsh(["add","rule",f"name={rule}",
                "dir=out","action=block",f"program={exe}"])
            if ok:
                self._blocked[p.pid] = rule
                self._apply_filter()
            else: QMessageBox.critical(self, "Firewall", msg)

        def _do_unblock(self, pid):
            if pid not in self._blocked: return
            rule = self._blocked.pop(pid)
            ok, msg = self._netsh(["delete","rule",f"name={rule}"])
            if ok: self._apply_filter()
            else: QMessageBox.critical(self, "Firewall", msg)

        def _add_smart_rule(self):
            t = self.fw_type.currentText()
            v = self.fw_value.text().strip()
            d = self.fw_direction.currentText()
            if not v:
                QMessageBox.warning(self, "Error", "Value required."); return
            rule = f"NetMon_Smart_{int(time.time())}"
            args = ["add","rule",f"name={rule}",f"dir={d}","action=block"]
            try:
                if t == "Block IP":
                    ipaddress.ip_address(v); args.append(f"remoteip={v}")
                elif t == "Block Port (Outbound)":
                    port = int(v)
                    if not (0 < port < 65536): raise ValueError("invalid port")
                    args += ["protocol=TCP", f"remoteport={port}"]
                elif t == "Block Domain (via IP list)":
                    import socket
                    ips = {x[4][0] for x in socket.getaddrinfo(v, None)}
                    args.append(f"remoteip={','.join(ips)}")
            except Exception as e:
                QMessageBox.warning(self, "Invalid", str(e)); return
            ok, msg = self._netsh(args)
            if ok:
                self._smart_rules.append({"type":t,"value":v,"dir":d,"rule":rule})
                self._refresh_smart_table()
            else: QMessageBox.critical(self, "Firewall", msg)

        def _remove_smart_rule(self):
            row = self.fw_table.currentRow()
            if row < 0 or row >= len(self._smart_rules): return
            item = self._smart_rules[row]
            ok, msg = self._netsh(["delete","rule",f"name={item['rule']}"])
            if ok:
                del self._smart_rules[row]; self._refresh_smart_table()
            else: QMessageBox.critical(self, "Firewall", msg)

        def _refresh_smart_table(self):
            self.fw_table.setRowCount(len(self._smart_rules))
            for i, it in enumerate(self._smart_rules):
                self.fw_table.setItem(i, 0, QTableWidgetItem(it["type"]))
                self.fw_table.setItem(i, 1, QTableWidgetItem(it["value"]))
                self.fw_table.setItem(i, 2, QTableWidgetItem(it["dir"]))
                self.fw_table.setItem(i, 3, QTableWidgetItem(it["rule"]))

        # ---------------- ARCHIVE ----------------
        def _query_archive(self):
            frm = self.arc_from.dateTime().toPyDateTime()
            to = self.arc_to.dateTime().toPyDateTime()
            kw = self.arc_kw.text().strip() or None
            rows = self.db.query(frm, to, keyword=kw, limit=3000)
            self.arc_table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                for j, v in enumerate(r):
                    self.arc_table.setItem(i, j, QTableWidgetItem(str(v)))
            self.arc_table.resizeColumnsToContents()
            self.statusBar().showMessage(f"{len(rows)} records", 4000)

        def _export_archive(self):
            path, _ = QFileDialog.getSaveFileName(self, "Save", "archive.csv",
                                                  "CSV (*.csv)")
            if not path: return
            import csv
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow([self.arc_table.horizontalHeaderItem(i).text()
                            for i in range(self.arc_table.columnCount())])
                for i in range(self.arc_table.rowCount()):
                    w.writerow([self.arc_table.item(i, j).text()
                                if self.arc_table.item(i, j) else ""
                                for j in range(self.arc_table.columnCount())])

        def _refresh_stats(self):
            rows = self.db.stats_daily(7)
            if not rows:
                self.stats_label.setText("No archived data yet."); return
            lines = ["Date          Records   Unique PIDs"]
            for d, c, p in rows:
                lines.append(f"{d:12} {c:8}   {p:8}")
            self.stats_label.setText("\n".join(lines))

        def _flush_archive(self):
            self.db.flush()
            self.statusBar().showMessage("Archive flushed.", 3000)

        # ---------------- EXPORTS ----------------
        def _export_csv(self):
            path, _ = QFileDialog.getSaveFileName(self, "Export", "live.csv",
                                                  "CSV (*.csv)")
            if not path: return
            import csv
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(ProcessModel.HEADERS)
                for i in range(self.model.rowCount()):
                    w.writerow([self.model.index(i, c).data() or ""
                                for c in range(self.model.columnCount())])

        def _export_html(self):
            path, _ = QFileDialog.getSaveFileName(self, "Export HTML",
                "report.html", "HTML (*.html)")
            if not path: return
            rows_html = []
            headers = ProcessModel.HEADERS
            rows_html.append("<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>")
            for i in range(self.model.rowCount()):
                cells = [str(self.model.index(i, c).data() or "")
                         for c in range(self.model.columnCount())]
                rows_html.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{APP_NAME} Report</title>
<style>
body {{ font-family: Segoe UI, sans-serif; background: #f5f5f5; margin: 20px; }}
h1 {{ color: #2980b9; }}
table {{ border-collapse: collapse; width: 100%; background: white;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
th {{ background: #3498db; color: white; padding: 8px; text-align: left; }}
td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
tr:hover {{ background: #f9f9f9; }}
.meta {{ color: #666; margin-bottom: 20px; }}
</style></head><body>
<h1>{APP_NAME} — Live Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
 | Processes: {self.model.rowCount()}</p>
<table>{''.join(rows_html)}</table>
</body></html>"""
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(html)
                self.statusBar().showMessage(f"HTML saved: {path}", 4000)
                webbrowser.open(f"file:///{path.replace(os.sep, '/')}")
            except Exception as e:
                QMessageBox.critical(self, "Export failed", str(e))

        def _toggle_pcap(self, checked=None):
            # Check if sniffer running
            if self.sniffer.pcap_path:
                # stop
                self.sniffer.pcap_path = None
                self.statusBar().showMessage("PCAP recording stopped.", 3000)
                return
            path, _ = QFileDialog.getSaveFileName(self, "Save PCAP",
                f"capture_{int(time.time())}.pcap", "PCAP (*.pcap)")
            if not path: return
            self.sniffer.pcap_path = path
            self.statusBar().showMessage(f"Recording PCAP to {path}", 4000)

        def _open_log(self):
            if os.path.exists(APP_DIR): os.startfile(APP_DIR)

        def _toggle_sniffer(self, state):
            if state and not self.sniffer.is_alive():
                self.sniffer = SnifferWorker(self._pkt_queue); self.sniffer.start()
            elif not state and self.sniffer.is_alive():
                self.sniffer.stop()

        def _toggle_autostart(self, checked):
            if not set_autostart(checked):
                self.act_autostart.setChecked(not checked)
                QMessageBox.warning(self, "Autostart", "Failed to update registry.")

        def _show_settings(self):
            dlg = SettingsDialog(self.settings, self)
            if dlg.exec_() == QDialog.Accepted:
                self.speed_worker.set_interval(
                    self.settings.value("speed_interval", 0.5, float))
                self.scan_worker.set_interval(
                    self.settings.value("scan_interval", 2, int))
                self.scan_worker.set_track_io(
                    self.settings.value("track_io", True, bool))
                self.alert_worker.set_enabled(
                    self.settings.value("alerts_enabled", True, bool))
                self.alert_worker.set_threshold(
                    self.settings.value("download_threshold_mb", 50, int))
                self.act_autostart.setChecked(is_autostart_enabled())
                self.io_cb.setChecked(self.settings.value("track_io", True, bool))
                tb = self.settings.value("taskbar_overlay_enabled", True, bool)
                self.act_taskbar.setChecked(tb)
                self.btn_taskbar.setChecked(tb)
                self._show_taskbar_overlay(tb)
                # theme
                new_theme = self.settings.value("theme", "Light", str)
                self._apply_theme(new_theme)
                if self.taskbar_overlay:
                    self.taskbar_overlay.set_dark_mode(new_theme == "Dark")
                if hasattr(self, "quota_widget"):
                    self.quota_widget.refresh()

        def _show_columns(self):
            visible = list(self.model._visible)
            dlg = ColumnVisibilityDialog(visible, ProcessModel.HEADERS, self)
            if dlg.exec_() == QDialog.Accepted:
                vis = dlg.get_visibility()
                self.model.set_visible(vis)
                self._apply_filter()

        def _show_alert_rules(self):
            dlg = AlertRulesDialog(self.settings, self)
            if dlg.exec_() == QDialog.Accepted:
                self.alert_worker.set_enabled(
                    self.settings.value("alerts_enabled", True, bool))
                self.alert_worker.set_threshold(
                    self.settings.value("download_threshold_mb", 50, int))

        def _show_blacklist(self):
            bl, wl = self._load_lists()
            dlg = BlacklistDialog(bl, wl, self)
            if dlg.exec_() == QDialog.Accepted:
                bl, wl = dlg.get_lists()
                self._save_lists(bl, wl)
                self.alert_worker.set_lists(bl, wl)

        def _show_about(self): AboutDialog(self).exec_()

        def _quit(self):
            self.settings.setValue("window_geometry", self.saveGeometry())
            self.close(); QApplication.quit()

        def closeEvent(self, event):
            if (not event.spontaneous()
                    and self.settings.value("minimize_to_tray", True, bool)
                    and self.isVisible()):
                event.ignore(); self.hide()
                self.tray.showMessage(APP_NAME,
                    "Still running in tray. Click to open.",
                    QSystemTrayIcon.Information, 2500)
                return
            log.info("Shutting down...")
            self._flush_usage()
            for w in (self.speed_worker, self.scan_worker,
                      self.archive_worker, self.alert_worker):
                w.stop()
            self.sniffer.stop()
            for w in (self.speed_worker, self.scan_worker,
                      self.archive_worker, self.alert_worker):
                w.wait(3000)
            self.db.flush()
            for rule in list(self._blocked.values()):
                self._netsh(["delete","rule",f"name={rule}"])
            for item in self._smart_rules:
                self._netsh(["delete","rule",f"name={item['rule']}"])
            if self.floating: self.floating.close()
            if self.taskbar_overlay:
                self.taskbar_overlay.stop(); self.taskbar_overlay.close()
            if self._geoip_reader:
                try: self._geoip_reader.close()
                except Exception: pass
            self.tray.hide()
            log.info("Goodbye.")
            event.accept()


# ============================================================
# 23) CLI MODE
# ============================================================
def cli_main():
    print(f"{APP_NAME} v{APP_VERSION} — CLI Mode (Ctrl+C to exit)")
    print("-" * 50)
    prev = None
    try:
        while True:
            n = psutil.net_io_counters()
            if prev:
                up = n.bytes_sent - prev.bytes_sent
                down = n.bytes_recv - prev.bytes_recv
                uptime_s = time.time() - psutil.boot_time()
                print(f"\r↑ {fmt_speed(up):>12}   ↓ {fmt_speed(down):>12}   "
                      f"| Total: ↑{fmt_bytes(n.bytes_sent)} ↓{fmt_bytes(n.bytes_recv)}   "
                      f"| Uptime {fmt_duration(uptime_s)}", end="", flush=True)
            prev = n
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nBye.")


# ============================================================
# 24) ENTRY
# ============================================================
def main():
    if CLI_MODE:
        cli_main(); return
    try:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        app = QApplication(sys.argv)
        app.setApplicationName(APP_NAME)
        app.setOrganizationName(APP_AUTHOR)
        app.setWindowIcon(load_icon())
        app.setFont(QFont("Segoe UI", 9))
        app.setQuitOnLastWindowClosed(False)
        w = MainWindow()
        if not w.isHidden(): w.show()
        sys.exit(app.exec_())
    except SystemExit: raise
    except Exception:
        tb = traceback.format_exc()
        log.critical(f"Fatal:\n{tb}")
        print(tb, file=sys.stderr)
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(None, "Fatal Error", tb)
        except Exception: pass
        if os.name == "nt": input("Press Enter...")
        sys.exit(1)


if __name__ == "__main__":
    main()