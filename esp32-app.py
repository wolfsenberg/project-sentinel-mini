"""
SENTINEL MINI — Data Room RFID Door Lock Monitor
=================================================
PyQt6 desktop application that monitors two ESP32 serial ports
(TAP IN / TAP OUT) for RFID card events, logs activity in real-time,
and manages registered cards via a MySQL database.

Requirements:
    pip install pyserial pymysql PyQt6
"""

import os
import sys
import time
import queue
import ctypes
import hashlib
import shutil
import subprocess
import socket
import serial
import serial.tools.list_ports
import pymysql
import threading
from datetime import datetime
import paho.mqtt.client as paho_mqtt

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QMessageBox,
    QInputDialog, QAbstractItemView, QFrame, QDialog, QDialogButtonBox,
    QProgressBar, QComboBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QTextCursor, QTextCharFormat, QIcon

# ── Paths ────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
ICON_PATH = os.path.join(BASE_DIR, "logo-ng-sentinel3.ico")

# ── Database Config ──────────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     3307,
    "user":     "root",
    "password": "Spiderman@19",
    "database": "sentinel_db",
}

# ── Color Palette ────────────────────────────────────────────────────
BG       = "#E8EAF6"
BG2      = "#D0D4E5"
BG3      = "#A6ABC2"
ACCENT   = "#1A9C54"
ACCENT2  = "#797E96"
SUCCESS  = "#1A9C54"
DANGER   = "#E53935"
WARNING  = "#FB8C00"
TEXT     = "#282A36"
TEXT_DIM = "#797E96"

TAG_COLORS = {
    "[OK]":     SUCCESS,
    "[DENY]":   DANGER,
    "[BLOCK]":  WARNING,
    "[WARN]":   WARNING,
    "[DOOR]":   ACCENT,
    "[SYSTEM]": ACCENT2,
    "[STATUS]": TEXT_DIM,
    "[TAP]":    "#797E96",
    "[SYNC]":   "#1A9C54",
    "[RECV]":   "#797E96",
}

# ── Inline Style Definitions ────────────────────────────────────────
BTN_CONNECT_STYLE = (
    f"background-color: {ACCENT}; color: {BG}; border-radius: 4px; "
    f"padding: 6px 16px; font-weight: bold; letter-spacing: 1px;"
)
BTN_STOP_STYLE = (
    f"background-color: {DANGER}; color: {TEXT}; border-radius: 4px; "
    f"padding: 6px 16px; font-weight: bold; letter-spacing: 1px;"
)
DOT_STYLE = (
    "border-radius: 6px; min-width: 12px; min-height: 12px; "
    "max-width: 12px; max-height: 12px;"
)

# ── Administrator PIN (SHA-256 hash of 'cornersteel123') ──────────────
SUPERADMIN_PIN_HASH = "b63ae1e3da0e2b5c62acd69773bb231aac6659b8a214ea466e5e275ce33f79a7"

# ── Mosquitto Config Content ─────────────────────────────────────────
MOSQUITTO_CONF = """# Sentinel MQTT Broker Configuration
listener 1883 0.0.0.0
allow_anonymous true
"""


# =====================================================================
#  MOSQUITTO AUTO-SETUP
# =====================================================================
def _setup_mosquitto():
    """Ensure Mosquitto is running with the correct config.
    Called once at app startup before the GUI is created."""
    conf_dir = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Sentinel")
    os.makedirs(conf_dir, exist_ok=True)
    conf_path = os.path.join(conf_dir, "sentinel.conf")

    # Always write / overwrite the config so it stays current
    with open(conf_path, "w") as f:
        f.write(MOSQUITTO_CONF)

    # Try to find mosquitto.exe
    mosquitto_exe = _find_mosquitto()
    if not mosquitto_exe:
        return  # not installed — serial still works

    # Always kill existing Mosquitto (it may be running with the wrong
    # config — e.g. default localhost-only, anonymous=false).  Then
    # restart with our sentinel.conf which binds 0.0.0.0 + allows anon.
    try:
        subprocess.run(
            ["taskkill", "/f", "/im", "mosquitto.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        time.sleep(1)  # let it fully exit
    except Exception:
        pass

    # Start Mosquitto with our config
    try:
        subprocess.Popen(
            [mosquitto_exe, "-c", conf_path, "-d"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        time.sleep(1)  # let it bind the port
    except Exception:
        pass

    # Attempt to add firewall rule (needs admin — UAC popup once)
    _ensure_firewall_rule()


def _is_port_open(port):
    """Return True if something is already listening on localhost:<port>."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False


def _find_mosquitto():
    """Locate mosquitto.exe on this PC."""
    # Check PATH first
    found = shutil.which("mosquitto")
    if found:
        return found
    # Common install locations
    for p in [
        r"C:\Program Files\mosquitto\mosquitto.exe",
        r"C:\Program Files (x86)\mosquitto\mosquitto.exe",
        r"C:\mosquitto\mosquitto.exe",
    ]:
        if os.path.isfile(p):
            return p
    return None


def _ensure_firewall_rule():
    """Add a Windows Firewall rule for port 1883 if it doesn't exist.
    This triggers a UAC prompt the first time only."""
    try:
        # Check if rule already exists (no admin needed for query)
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=Mosquitto MQTT"],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if "Mosquitto MQTT" in result.stdout:
            return  # rule exists
    except Exception:
        pass

    # Elevate to add the rule (UAC prompt)
    try:
        cmd = (
            'netsh advfirewall firewall add rule '
            'name="Mosquitto MQTT" dir=in action=allow protocol=tcp localport=1883'
        )
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", f"/c {cmd}", None, 0
        )
    except Exception:
        pass


# =====================================================================
#  DATABASE LAYER
# =====================================================================
class Database:
    """Thread-safe MySQL wrapper for card registration and access logs."""

    def __init__(self):
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self):
        return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)

    def _init_db(self):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS cards (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        uid VARCHAR(50) UNIQUE NOT NULL,
                        name VARCHAR(100) DEFAULT 'Unknown',
                        registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS access_log (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        uid VARCHAR(50),
                        source VARCHAR(20),
                        action VARCHAR(50),
                        result VARCHAR(50),
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            conn.commit()

    def register_card(self, uid, name="Unknown"):
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO cards (uid, name) VALUES (%s, %s) "
                            "ON DUPLICATE KEY UPDATE is_active=TRUE, name=%s",
                            (uid, name, name),
                        )
                    conn.commit()
                return True, "Card registered."
            except Exception as e:
                return False, str(e)

    def remove_card(self, uid):
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE cards SET is_active=FALSE WHERE uid=%s", (uid,))
                    conn.commit()
                return True, "Card deactivated."
            except Exception as e:
                return False, str(e)

    def get_all_cards(self):
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM cards ORDER BY registered_at DESC")
                        return cur.fetchall()
            except Exception:
                return []

    def log_event(self, uid, source, action, result):
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO access_log (uid, source, action, result) "
                            "VALUES (%s,%s,%s,%s)",
                            (uid, source, action, result),
                        )
                    conn.commit()
            except Exception:
                pass

    def get_recent_logs(self, limit=100):
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT %s",
                            (limit,),
                        )
                        return cur.fetchall()
            except Exception:
                return []

    def get_active_uids(self):
        """Return a list of UIDs for all active cards."""
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT uid FROM cards WHERE is_active=TRUE")
                        return [row["uid"] for row in cur.fetchall()]
            except Exception:
                return []

    def get_name_by_uid(self, uid):
        """Return the cardholder name for a UID, or None if not found."""
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT name FROM cards WHERE uid=%s AND is_active=TRUE",
                            (uid,),
                        )
                        row = cur.fetchone()
                        return row["name"] if row else None
            except Exception:
                return None

    def get_last_action(self, uid):
        """Return the last SUCCESSFUL action (TAPIN or TAPOUT) for a UID, or None."""
        with self.lock:
            try:
                with self._connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT action FROM access_log "
                            "WHERE uid=%s AND result='SUCCESS' "
                            "ORDER BY timestamp DESC LIMIT 1",
                            (uid,)
                        )
                        row = cur.fetchone()
                        return row["action"] if row else None
            except Exception:
                return None


# =====================================================================
#  SERIAL MONITOR
# =====================================================================
class SentinelMonitor:
    """Reads two serial ports (TAP IN / TAP OUT) on background threads."""

    RESULT_TAG_MAP = {
        "SUCCESS":     "[OK]",
        "ANTIPASSBACK": "[BLOCK]",
        "DENIED":      "[DENY]",
    }

    def __init__(self, port_tapin, port_tapout, baudrate=115200,
                 log_queue=None, db=None):
        self.log_queue   = log_queue or queue.Queue()
        self.uid_queue   = queue.Queue()  # for auto-detect UID during registration
        self.db          = db
        self.running     = False
        self.tapin       = None
        self.tapout      = None
        self.port_tapin  = port_tapin
        self.port_tapout = port_tapout
        self.baudrate    = baudrate
        self.log_lock    = threading.Lock()
        self.log_file    = f"sentinel_log_{datetime.now():%Y%m%d_%H%M%S}.txt"
        self.mqtt_client = None
        self._mqtt_connected = False
        self._start_mqtt_reconnect_thread()

    # ── Connection ───────────────────────────────────────────────────
    def connect(self):
        errors = []
        for label, port, attr in [
            ("TAP IN",  self.port_tapin,  "tapin"),
            ("TAP OUT", self.port_tapout, "tapout"),
        ]:
            try:
                setattr(self, attr, serial.Serial(port, self.baudrate, timeout=1))
            except Exception as e:
                errors.append(f"{label} ({port}): {e}")

        # Push the full registered-card list from DB to each ESP32
        if not errors:
            self._push_cards_to_esp32()

        return errors

    def _push_cards_to_esp32(self):
        """Send the current active card UIDs to both ESP32s via serial."""
        if not self.db:
            return
        uids = self.db.get_active_uids()
        payload = "CARDS:" + ",".join(uids) + "\n"
        for ser in (self.tapin, self.tapout):
            try:
                if ser and ser.is_open:
                    ser.write(payload.encode("utf-8"))
            except Exception:
                pass
        self.log("APP", f"Pushed {len(uids)} registered cards to ESP32s", "[SYSTEM]")

    def send_card_command(self, command, uid):
        """Send CARD_ADD:<uid> or CARD_REMOVE:<uid> to both ESP32s."""
        payload = f"{command}:{uid}\n"
        for ser in (self.tapin, self.tapout):
            try:
                if ser and ser.is_open:
                    ser.write(payload.encode("utf-8"))
            except Exception:
                pass

    def start(self):
        self.running = True
        for ser, label in [(self.tapin, "TAP IN"), (self.tapout, "TAP OUT")]:
            threading.Thread(target=self._read_port, args=(ser, label),
                             daemon=True).start()

    def stop(self):
        self.running = False
        for s in (self.tapin, self.tapout):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        # Stop MQTT listener
        if self.mqtt_client:
            try:
                self.mqtt_client.disconnect()
                self.mqtt_client.loop_stop()
            except Exception:
                pass

    # ── MQTT Auto-Reconnect ────────────────────────────────────────────
    def _start_mqtt_reconnect_thread(self):
        """Launch a daemon thread that keeps MQTT connected."""
        threading.Thread(target=self._mqtt_reconnect_loop, daemon=True).start()

    def _mqtt_reconnect_loop(self):
        """Retry MQTT connection every 5 s until connected, then monitor."""
        fail_count = 0
        while self.running or not self._mqtt_connected:
            try:
                # Already connected — just keep watching
                if self.mqtt_client and self.mqtt_client.is_connected():
                    self._mqtt_connected = True
                    fail_count = 0
                    time.sleep(5)
                    continue

                # Mark disconnected while attempting
                self._mqtt_connected = False

                # Stop any previous loop_start thread
                if self.mqtt_client:
                    try:
                        self.mqtt_client.loop_stop()
                        self.mqtt_client.disconnect()
                    except Exception:
                        pass

                # (Re)create the client
                if hasattr(paho_mqtt, 'CallbackAPIVersion'):
                    self.mqtt_client = paho_mqtt.Client(
                        client_id="SENTINEL_APP",
                        callback_api_version=paho_mqtt.CallbackAPIVersion.VERSION2,
                    )
                else:
                    self.mqtt_client = paho_mqtt.Client(client_id="SENTINEL_APP")

                self.mqtt_client.on_message = self._on_mqtt_message
                self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
                self.mqtt_client.connect("127.0.0.1", 1883, keepalive=60)
                self.mqtt_client.subscribe("sentinel/unreg_uid")
                self.mqtt_client.loop_start()
                self._mqtt_connected = True
                self.log("MQTT", "Connected to broker", "[SYSTEM]")
                fail_count = 0
            except Exception:
                self._mqtt_connected = False
                fail_count += 1
                # Log sparingly: first failure, then every ~60 s (12 × 5 s)
                if fail_count == 1 or fail_count % 12 == 0:
                    self.log("MQTT", "Connection failed — retrying…", "[WARN]")
            time.sleep(5)

    def _on_mqtt_disconnect(self, client, userdata, *args):
        """Mark MQTT as disconnected so the reconnect loop picks it up."""
        self._mqtt_connected = False
        self.log("MQTT", "Disconnected from broker", "[WARN]")

    def _on_mqtt_message(self, client, userdata, msg):
        """Push unregistered UID into uid_queue for the registration dialog."""
        try:
            uid = msg.payload.decode("utf-8", errors="ignore").strip().upper()
            if uid:
                self.uid_queue.put(uid)
                self.log("MQTT", f"Unregistered UID detected: {uid}", "[TAP]")
        except Exception:
            pass

    # ── Internal ─────────────────────────────────────────────────────
    def log(self, source, message, tag=None):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.log_queue.put({"time": ts, "source": source,
                            "message": message, "tag": tag})
        with self.log_lock:
            with open(self.log_file, "a") as f:
                f.write(f"[{ts}] [{source}] {message}\n")

    def parse_message(self, source, line):
        line = line.strip()
        if not line:
            return
        if line == "---":
            self.log_queue.put({"separator": True})
            return

        prefix, _, body = line.partition(":")
        if not body:
            self.log(source, line)
            return

        def handle_system():
            self.log(source, body, "[SYSTEM]")
            # If an ESP32 reboots (which door-in does after locking),
            # it loses its RAM-based array of registered cards.
            # We must resync the card list so it knows who is registered.
            if body == "READY":
                self._push_cards_to_esp32()

        handler = {
            "SYSTEM": handle_system,
            "STATUS": lambda: self.log(source, body, "[STATUS]"),
            "DOOR":   lambda: self.log(source, body, "[DOOR]"),
            "LOG":    lambda: self._parse_log(source, body),
            "TAP":    lambda: self._parse_tap(source, body),
            "SYNC":   lambda: self._parse_sync(source, body),
            "RECV":   lambda: self._parse_recv(source, body),
        }.get(prefix)

        if handler:
            handler()
        else:
            self.log(source, line)

    def _parse_log(self, source, body):
        parts = body.split(",")
        if len(parts) >= 4:
            uid, action, reg_status, result = parts[:4]
            tag = self.RESULT_TAG_MAP.get(result, "[WARN]")
            # Look up cardholder name from DB
            name = None
            if self.db:
                name = self.db.get_name_by_uid(uid)
            if name and name != "Unknown":
                who = f"{name} ({uid})"
            elif reg_status == "REG":
                who = f"UID: {uid}"
            else:
                who = f"UNREGISTERED ({uid})"
            self.log(source, f"{action} | {who} | {result}", tag)
            if self.db:
                self.db.log_event(uid, source, action, result)
        else:
            self.log(source, f"Malformed LOG: {body}", "[WARN]")

    def _parse_tap(self, source, body):
        # Master server-side anti-passback and routing logic
        parts = body.split(",")
        if len(parts) >= 1:
            uid = parts[0].strip()
            self.uid_queue.put(uid)  # push to auto-detect queue
            
            if not self.db:
                self.log(source, f"UID: {uid} | No DB connection", "[WARN]")
                return
                
            active_uids = self.db.get_active_uids()
            current_action = "TAPIN" if source == "TAP IN" else "TAPOUT"
            
            if uid not in active_uids:
                # Unregistered card
                self.log(source, f"UID: {uid} | UNREG", "[TAP]")
                self.log(source, f"{current_action} | UNREGISTERED ({uid}) | DENIED", "[DENY]")
                self.db.log_event(uid, source, current_action, "DENIED")
                return
                
            # Card is registered
            last_action_str = self.db.get_last_action(uid)
            
            # Anti-passback logic
            # TAPIN is allowed if last action was TAPOUT or None
            # TAPOUT is allowed if last action was TAPIN
            is_allowed = False
            if current_action == "TAPIN":
                is_allowed = (last_action_str != "TAPIN")
            else: # TAPOUT
                is_allowed = (last_action_str == "TAPIN")
                
            name = self.db.get_name_by_uid(uid) or "Unknown"
            who = f"{name} ({uid})"
            
            self.log(source, f"UID: {uid} | REG", "[TAP]")
            
            if is_allowed:
                self.log(source, f"{current_action} | {who} | SUCCESS", "[OK]")
                self.db.log_event(uid, source, current_action, "SUCCESS")
                # Send UNLOCK command to door-in relay immediately
                if self.tapin and self.tapin.is_open:
                    try:
                        self.tapin.write(b"UNLOCK:\n")
                    except Exception:
                        pass
            else:
                self.log(source, f"{current_action} | {who} | ANTIPASSBACK", "[BLOCK]")
                self.db.log_event(uid, source, current_action, "ANTIPASSBACK")
                
        else:
            self.log(source, f"Malformed TAP: {body}", "[WARN]")

    def _parse_sync(self, source, body):
        parts = body.split(",")
        if len(parts) >= 2:
            self.log(source, f"{parts[1]} | UID: {parts[0]}", "[SYNC]")

    def _parse_recv(self, source, body):
        parts = body.split(",")
        if len(parts) >= 3:
            self.log(source, f"{parts[1]} | UID: {parts[0]} | {parts[2]}", "[RECV]")

    def _read_port(self, ser, label):
        while self.running:
            try:
                if ser and ser.is_open and ser.in_waiting > 0:
                    line = ser.readline().decode("utf-8", errors="ignore")
                    self.parse_message(label, line)
            except serial.SerialException:
                self.log(label, "Serial disconnected. Retrying in 3s...", "[WARN]")
                time.sleep(3)
                try:
                    ser.close()
                    ser.open()
                except Exception:
                    pass
            except Exception as e:
                self.log(label, f"ERROR: {e}", "[WARN]")
            time.sleep(0.01)


# =====================================================================
#  MAIN GUI
# =====================================================================
class SentinelApp(QMainWindow):
    """PyQt6 main window for the Sentinel Mini Data Room monitor."""

    UID_LENGTH = 8  # RFID card UIDs must be exactly 8 hex characters

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SENTINEL MINI — Data Room RFID Monitor")
        self.setWindowIcon(QIcon(ICON_PATH))
        self.resize(1100, 720)
        self.setMinimumSize(900, 600)

        self.log_queue = queue.Queue()
        self.db = None
        self.monitor = None
        self.is_superadmin = False  # administrator session state

        self._try_db()
        self._apply_styles()
        self._build_ui()

        # Timers
        self._timer(self._poll_queue, 50)
        self._timer(self._tick_clock, 1000)
        self._tick_clock()

    # ── Helpers ──────────────────────────────────────────────────────
    def _timer(self, slot, ms):
        t = QTimer(self)
        t.timeout.connect(slot)
        t.start(ms)
        return t

    def _try_db(self):
        try:
            self.db = Database()
        except Exception:
            self.db = None

    def _make_log_entry(self, msg, tag=None):
        return {"time": datetime.now().strftime("%H:%M:%S"),
                "source": "APP", "message": msg, "tag": tag}

    # ── Stylesheet ───────────────────────────────────────────────────
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {BG}; color: {TEXT};
                font-family: "Google Sans Code", "Consolas", monospace;
                font-size: 10pt;
            }}
            QLineEdit {{
                background-color: {BG3}; color: {TEXT};
                border: none; border-radius: 6px; padding: 8px 12px;
                font-family: "Google Sans Code", "Consolas", monospace;
            }}
            QPushButton {{
                background-color: {BG3}; color: {TEXT_DIM};
                border: none; border-radius: 6px; padding: 8px 16px;
                font-weight: bold; letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background-color: {ACCENT2}; color: {BG};
            }}
            QTextEdit {{
                background-color: {BG}; color: {TEXT};
                border: 1px solid {BG2}; border-radius: 8px;
                font-family: "Google Sans Code", "Consolas", monospace;
                padding: 8px;
            }}
            QTableWidget {{
                background-color: {BG}; color: {TEXT};
                alternate-background-color: {BG2};
                gridline-color: {BG2};
                border: 1px solid {BG2}; border-radius: 8px; outline: 0;
            }}
            QHeaderView::section {{
                background-color: {BG3}; color: {TEXT};
                padding: 8px; font-weight: bold; border: none;
                border-right: 1px solid {BG2};
                border-bottom: 1px solid {BG2};
            }}
            QTableWidget::item {{ padding: 4px; }}
            QTableWidget::item:selected {{
                background-color: {ACCENT2}; color: {TEXT};
            }}
            QScrollBar:vertical {{
                background-color: {BG2}; width: 10px;
                border: none; border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {BG3}; min-height: 20px; border-radius: 5px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """)

    # ── UI Construction ──────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_titlebar())
        layout.addWidget(self._build_main(), 1)
        layout.addWidget(self._build_statusbar())

    def _build_titlebar(self):
        bar = QFrame()
        bar.setStyleSheet(f"background-color: {BG2};")
        bar.setFixedHeight(56)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)

        title = QLabel("SENTINEL MINI")
        title.setStyleSheet(f"color: {TEXT}; font-size: 16pt; font-weight: bold; background: transparent;")
        lay.addWidget(title)

        sub = QLabel("  DATA ROOM RFID MONITOR")
        sub.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10pt; background: transparent;")
        lay.addWidget(sub)

        lay.addStretch()

        lbl_in = QLabel("TAP IN:")
        lbl_in.setStyleSheet(f"color: {TEXT_DIM}; background: transparent;")
        lay.addWidget(lbl_in)
        self.combo_tapin = QComboBox()
        self.combo_tapin.setFixedWidth(110)
        self.combo_tapin.setStyleSheet(
            f"background-color: {BG3}; color: {TEXT}; border-radius: 4px; padding: 4px 8px;"
        )
        lay.addWidget(self.combo_tapin)

        lay.addSpacing(12)

        lbl_out = QLabel("TAP OUT:")
        lbl_out.setStyleSheet(f"color: {TEXT_DIM}; background: transparent;")
        lay.addWidget(lbl_out)
        self.combo_tapout = QComboBox()
        self.combo_tapout.setFixedWidth(110)
        self.combo_tapout.setStyleSheet(
            f"background-color: {BG3}; color: {TEXT}; border-radius: 4px; padding: 4px 8px;"
        )
        lay.addWidget(self.combo_tapout)

        lay.addSpacing(8)

        btn_refresh_ports = QPushButton("↻")
        btn_refresh_ports.setToolTip("Refresh COM ports")
        btn_refresh_ports.setFixedWidth(32)
        btn_refresh_ports.clicked.connect(self._refresh_ports)
        lay.addWidget(btn_refresh_ports)

        lay.addSpacing(12)

        self.btn_connect = QPushButton("CONNECT")
        self.btn_connect.setStyleSheet(BTN_CONNECT_STYLE)
        self.btn_connect.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_connect.clicked.connect(self._toggle_connect)
        lay.addWidget(self.btn_connect)

        lay.addSpacing(8)

        btn_restart = QPushButton("⟳ RESTART")
        btn_restart.setStyleSheet(
            f"background-color: {WARNING}; color: {TEXT}; border-radius: 4px; "
            f"padding: 6px 12px; font-weight: bold; letter-spacing: 0.5px;"
        )
        btn_restart.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_restart.setToolTip("Restart the application")
        btn_restart.clicked.connect(self._restart_app)
        lay.addWidget(btn_restart)

        # Populate dropdowns on startup
        self._refresh_ports()

        return bar

    def _build_main(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BG2}; }}")

        # ── Left pane: Live Log ──────────────────────────────────────
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(8, 8, 4, 8)

        left_splitter = QSplitter(Qt.Orientation.Vertical)
        left_splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BG2}; }}")

        # -- Top: LIVE LOG (tap in/out access events only) --
        log_widget = QWidget()
        log_lay = QVBoxLayout(log_widget)
        log_lay.setContentsMargins(0, 0, 0, 0)
        log_lay.setSpacing(0)

        hdr = QFrame()
        hdr.setStyleSheet(f"background-color: {BG2};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(8, 4, 8, 4)

        lbl = QLabel("LIVE LOG")
        lbl.setStyleSheet(f"color: {ACCENT}; font-weight: bold;")
        hl.addWidget(lbl)
        hl.addStretch()

        btn_dl = QPushButton("DOWNLOAD LOG")
        btn_dl.clicked.connect(self._export_log)
        hl.addWidget(btn_dl)
        log_lay.addWidget(hdr)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        log_lay.addWidget(self.log_text, 1)

        left_splitter.addWidget(log_widget)

        # -- Bottom: DEVICE STATUS (system/status/warnings) --
        status_widget = QWidget()
        status_lay = QVBoxLayout(status_widget)
        status_lay.setContentsMargins(0, 0, 0, 0)
        status_lay.setSpacing(0)

        hdr_status = QFrame()
        hdr_status.setStyleSheet(f"background-color: {BG2};")
        hl_status = QHBoxLayout(hdr_status)
        hl_status.setContentsMargins(8, 4, 8, 4)

        lbl_status = QLabel("DEVICE STATUS")
        lbl_status.setStyleSheet(f"color: {WARNING}; font-weight: bold;")
        hl_status.addWidget(lbl_status)
        hl_status.addStretch()
        status_lay.addWidget(hdr_status)

        self.device_status_text = QTextEdit()
        self.device_status_text.setReadOnly(True)
        self.device_status_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        status_lay.addWidget(self.device_status_text, 1)

        left_splitter.addWidget(status_widget)
        left_splitter.setSizes([400, 200])

        ll.addWidget(left_splitter, 1)

        # ── Right pane: Cards ────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 8, 8, 8)

        hdr2 = QFrame()
        hdr2.setStyleSheet(f"background-color: {BG2};")
        h2l = QHBoxLayout(hdr2)
        h2l.setContentsMargins(8, 4, 8, 4)

        self.lbl_cards_title = QLabel("REGISTERED USERS")
        self.lbl_cards_title.setStyleSheet(f"color: {ACCENT}; font-weight: bold;")
        h2l.addWidget(self.lbl_cards_title)
        h2l.addStretch()

        # Administrator login button (in header)
        self.btn_login = QPushButton("ADD USER")
        self.btn_login.setStyleSheet(f"background-color: {ACCENT2}; color: {BG};")
        self.btn_login.clicked.connect(self._toggle_superadmin)
        h2l.addWidget(self.btn_login)

        # ADD / REMOVE — only visible when logged in as administrator
        self.btn_add = QPushButton("ADD")
        self.btn_add.setStyleSheet(f"background-color: {SUCCESS}; color: {BG};")
        self.btn_add.clicked.connect(self._add_card)
        self.btn_add.setVisible(False)
        h2l.addWidget(self.btn_add)

        self.btn_remove = QPushButton("REMOVE")
        self.btn_remove.setStyleSheet(f"background-color: {DANGER}; color: {BG};")
        self.btn_remove.clicked.connect(self._remove_card)
        self.btn_remove.setVisible(False)
        h2l.addWidget(self.btn_remove)

        btn_refresh = QPushButton("REFRESH")
        btn_refresh.clicked.connect(self._refresh_cards)
        h2l.addWidget(btn_refresh)
        rl.addWidget(hdr2)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["UID", "Name", "Status", "Registered"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setMinimumSectionSize(80)
        self.table.setColumnWidth(0, 90)   # UID: snug fit for 8 hex chars
        self.table.setColumnWidth(1, 180)  # Name: wider for full names
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setColumnHidden(0, True)  # UID hidden by default (non-superadmin)
        rl.addWidget(self.table, 1)

        # Stats strip
        stats = QFrame()
        stats.setStyleSheet(f"background-color: {BG2};")
        sl = QHBoxLayout(stats)
        sl.setContentsMargins(16, 8, 16, 8)

        sl.addStretch()  # left spacer

        # TOTAL stat
        self.lbl_total_val = self._make_stat_widget(sl, "TOTAL")

        sl.addSpacing(40)  # gap between TOTAL and ACTIVE

        # ACTIVE stat
        self.lbl_active_val = self._make_stat_widget(sl, "ACTIVE")

        sl.addStretch()  # right spacer

        # EXIT button in lower-right (hidden by default)
        self.btn_logout = QPushButton("EXIT")
        self.btn_logout.setStyleSheet(f"background-color: {WARNING}; color: {TEXT};")
        self.btn_logout.clicked.connect(self._toggle_superadmin)
        self.btn_logout.setVisible(False)
        sl.addWidget(self.btn_logout)

        rl.addWidget(stats)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([600, 500])

        self._refresh_cards()
        return splitter

    def _make_stat_widget(self, parent_layout, label_text):
        """Create a stat value + description pair and return the value label."""
        col = QVBoxLayout()
        val = QLabel("0")
        val.setStyleSheet(f"color: {ACCENT}; font-size: 18pt; font-weight: bold;")
        val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(val)
        desc = QLabel(label_text)
        desc.setStyleSheet(f"color: {TEXT_DIM}; font-size: 8pt;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(desc)
        parent_layout.addLayout(col)
        return val

    def _build_statusbar(self):
        bar = QFrame()
        bar.setStyleSheet(f"background-color: {BG2};")
        bar.setFixedHeight(32)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)

        self.status_dot = QLabel(" ")
        self.status_dot.setStyleSheet(f"background-color: {DANGER}; {DOT_STYLE}")
        lay.addWidget(self.status_dot)

        self.status_lbl = QLabel("DISCONNECTED")
        self.status_lbl.setStyleSheet(f"color: {TEXT_DIM};")
        lay.addWidget(self.status_lbl)

        lay.addStretch()

        self.db_lbl = QLabel("DB: CONNECTED" if self.db else "DB: DISCONNECTED")
        self.db_lbl.setStyleSheet(f"color: {SUCCESS if self.db else DANGER};")
        lay.addWidget(self.db_lbl)

        lay.addSpacing(16)

        self.mqtt_lbl = QLabel("MQTT: WAITING")
        self.mqtt_lbl.setStyleSheet(f"color: {WARNING};")
        lay.addWidget(self.mqtt_lbl)

        lay.addSpacing(16)

        self.time_lbl = QLabel("")
        self.time_lbl.setStyleSheet(f"color: {TEXT_DIM};")
        lay.addWidget(self.time_lbl)

        return bar

    # ── Clock ────────────────────────────────────────────────────────
    def _tick_clock(self):
        self.time_lbl.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

    # ── Port Management ──────────────────────────────────────────
    def _refresh_ports(self):
        """Re-scan available COM ports and populate both dropdowns."""
        ports = [p.device for p in serial.tools.list_ports.comports()]
        prev_in = self.combo_tapin.currentText()
        prev_out = self.combo_tapout.currentText()

        self.combo_tapin.clear()
        self.combo_tapout.clear()
        self.combo_tapin.addItems(ports)
        self.combo_tapout.addItems(ports)

        # Restore previous selection if still available
        if prev_in in ports:
            self.combo_tapin.setCurrentText(prev_in)
        if prev_out in ports:
            self.combo_tapout.setCurrentText(prev_out)

        # Try auto-detect (silent, best-effort) to pre-select correct ports
        self._try_auto_detect(ports)

    def _try_auto_detect(self, ports):
        """Silently try to identify TAP IN / TAP OUT via ID? command."""
        for port in ports:
            try:
                ser = serial.Serial(port, 115200, timeout=2)
                time.sleep(0.1)
                ser.reset_input_buffer()
                ser.write(b"ID?\n")
                time.sleep(0.5)
                response = ""
                while ser.in_waiting > 0:
                    response += ser.readline().decode("utf-8", errors="ignore")
                ser.close()

                if "ID:TAPIN" in response:
                    self.combo_tapin.setCurrentText(port)
                elif "ID:TAPOUT" in response:
                    self.combo_tapout.setCurrentText(port)
            except Exception:
                continue

    # ── Serial Connection ────────────────────────────────────────────
    def _toggle_connect(self):
        if self.monitor and self.monitor.running:
            self.monitor.stop()
            self.monitor = None
            self.btn_connect.setText("CONNECT")
            self.btn_connect.setStyleSheet(BTN_CONNECT_STYLE)
            self.status_dot.setStyleSheet(f"background-color: {DANGER}; {DOT_STYLE}")
            self.status_lbl.setText("DISCONNECTED")
            self.combo_tapin.setEnabled(True)
            self.combo_tapout.setEnabled(True)
            self._append_log(self._make_log_entry("Monitor stopped.", "[WARN]"))
        else:
            tp_in = self.combo_tapin.currentText()
            tp_out = self.combo_tapout.currentText()

            if not tp_in or not tp_out:
                QMessageBox.warning(
                    self, "No Ports Selected",
                    "Please select COM ports for both TAP IN and TAP OUT."
                )
                return
            if tp_in == tp_out:
                QMessageBox.warning(
                    self, "Same Port",
                    "TAP IN and TAP OUT must be different COM ports."
                )
                return

            self.monitor = SentinelMonitor(
                tp_in, tp_out, log_queue=self.log_queue, db=self.db
            )
            errors = self.monitor.connect()
            if errors:
                QMessageBox.critical(self, "Connection Error", "\n".join(errors))
                self.monitor = None
                return
            self.monitor.start()
            self.combo_tapin.setEnabled(False)
            self.combo_tapout.setEnabled(False)
            self.btn_connect.setText("STOP")
            self.btn_connect.setStyleSheet(BTN_STOP_STYLE)
            self.status_dot.setStyleSheet(f"background-color: {SUCCESS}; {DOT_STYLE}")
            self.status_lbl.setText(f"MONITORING  {tp_in}  |  {tp_out}")
            self._append_log(self._make_log_entry(
                f"Connected — TAP IN: {tp_in} | TAP OUT: {tp_out}", "[OK]"
            ))

    # ── Restart App ──────────────────────────────────────────────────
    def _restart_app(self):
        """Close everything and relaunch the application."""
        if self.monitor and self.monitor.running:
            self.monitor.stop()
            self.monitor = None
        subprocess.Popen(
            [sys.executable] + sys.argv,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        QApplication.instance().quit()

    # ── Log Panel ────────────────────────────────────────────────────
    def _poll_queue(self):
        try:
            while True:
                self._append_log(self.log_queue.get_nowait())
        except queue.Empty:
            pass

        # Update MQTT status indicator
        if self.monitor and hasattr(self.monitor, '_mqtt_connected'):
            if self.monitor._mqtt_connected:
                self.mqtt_lbl.setText("MQTT: CONNECTED")
                self.mqtt_lbl.setStyleSheet(f"color: {SUCCESS};")
            else:
                self.mqtt_lbl.setText("MQTT: DISCONNECTED")
                self.mqtt_lbl.setStyleSheet(f"color: {DANGER};")
        elif not self.monitor:
            self.mqtt_lbl.setText("MQTT: WAITING")
            self.mqtt_lbl.setStyleSheet(f"color: {WARNING};")

    # Tags that go to LIVE LOG (access events)
    LIVE_LOG_TAGS = {"[OK]", "[DENY]", "[BLOCK]", "[TAP]", "[SYNC]", "[RECV]"}

    def _append_log(self, entry):
        if entry.get("separator"):
            self.log_text.append("")
            return

        tag = entry.get("tag", "")

        # Route to the correct panel
        if tag in self.LIVE_LOG_TAGS:
            target = self.log_text
        else:
            target = self.device_status_text

        cursor = target.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()

        # Timestamp
        fmt.setForeground(QColor(TEXT_DIM))
        cursor.insertText(f"[{entry['time']}] ", fmt)

        # Source
        fmt.setForeground(QColor(ACCENT2))
        cursor.insertText(f"[{entry['source']}] ", fmt)

        # Tag
        if tag:
            fmt.setForeground(QColor(TAG_COLORS.get(tag, TEXT)))
            cursor.insertText(f"{tag} ", fmt)

        # Message
        fmt.setForeground(QColor(TEXT))
        cursor.insertText(entry["message"] + "\n", fmt)

        target.setTextCursor(cursor)
        target.ensureCursorVisible()

    def _clear_log(self):
        self.log_text.clear()
        self.device_status_text.clear()

    def _export_log(self):
        fname = f"export_{datetime.now():%Y%m%d_%H%M%S}.txt"
        with open(fname, "w") as f:
            f.write("=== LIVE LOG ===\n")
            f.write(self.log_text.toPlainText())
            f.write("\n\n=== DEVICE STATUS ===\n")
            f.write(self.device_status_text.toPlainText())
        QMessageBox.information(self, "Exported", f"Log saved to {fname}")

    # ── Card Management ──────────────────────────────────────────────
    def _refresh_cards(self):
        self.table.setRowCount(0)
        if not self.db:
            return
        cards = self.db.get_all_cards()
        active = 0
        for i, c in enumerate(cards):
            self.table.insertRow(i)
            is_active = c["is_active"]
            color = QColor(TEXT) if is_active else QColor(TEXT_DIM)
            ts = c["registered_at"].strftime("%Y-%m-%d %H:%M") if c["registered_at"] else ""

            for col, val, fg in [
                (0, c["uid"],                color),
                (1, c["name"],               color),
                (2, "ON" if is_active else "OFF",
                    QColor(SUCCESS if is_active else DANGER)),
                (3, ts,                      color),
            ]:
                item = QTableWidgetItem(val)
                item.setForeground(fg)
                self.table.setItem(i, col, item)

            if is_active:
                active += 1

        self.lbl_total_val.setText(str(len(cards)))
        self.lbl_active_val.setText(str(active))

    def _toggle_superadmin(self):
        """Login or logout as administrator."""
        if self.is_superadmin:
            # Logout
            self.is_superadmin = False
            self.btn_add.setVisible(False)
            self.btn_remove.setVisible(False)
            self.btn_login.setVisible(True)
            self.btn_logout.setVisible(False)
            self.table.setColumnHidden(0, True)   # hide UID
            self.lbl_cards_title.setText("REGISTERED USERS")
            self._append_log(self._make_log_entry(
                "Administrator logged out.", "[SYSTEM]"
            ))
        else:
            # Login
            pin, ok = QInputDialog.getText(
                self, "Administrator Login",
                "Enter administrator password:",
                QLineEdit.EchoMode.Password,
            )
            if not ok or not pin:
                return
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            if pin_hash != SUPERADMIN_PIN_HASH:
                QMessageBox.critical(self, "Access Denied", "Incorrect password.")
                return
            self.is_superadmin = True
            self.btn_add.setVisible(True)
            self.btn_remove.setVisible(True)
            self.btn_login.setVisible(False)
            self.btn_logout.setVisible(True)
            self.table.setColumnHidden(0, False)  # show UID
            self.lbl_cards_title.setText("REGISTERED CARDS")
            self._append_log(self._make_log_entry(
                "Administrator logged in.", "[SYSTEM]"
            ))

    def _add_card(self):
        if not self.db:
            QMessageBox.critical(self, "No DB", "Database not connected.")
            return
        if not self.monitor or not self.monitor.running:
            QMessageBox.warning(
                self, "Not Connected",
                "Please connect to the RFID scanners first before registering a card."
            )
            return

        # Superadmin gate (already handled by button visibility, but just in case)
        if not self.is_superadmin:
            return

        # Flush any old UIDs sitting in the queue
        while not self.monitor.uid_queue.empty():
            try:
                self.monitor.uid_queue.get_nowait()
            except queue.Empty:
                break

        # Show "waiting for tap" dialog
        dlg = QDialog(self)
        dlg.setWindowTitle("Register Card")
        dlg.setFixedSize(400, 180)
        dlg_layout = QVBoxLayout(dlg)

        lbl = QLabel("Tap the unregistered card on the RFID scanner...")
        lbl.setStyleSheet(f"color: {TEXT}; font-size: 12pt; font-weight: bold;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dlg_layout.addWidget(lbl)

        uid_lbl = QLabel("Waiting...")
        uid_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 16pt; font-weight: bold;")
        uid_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dlg_layout.addWidget(uid_lbl)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        btn_box.rejected.connect(dlg.reject)
        dlg_layout.addWidget(btn_box)

        detected_uid = [None]  # mutable container for closure

        def poll_uid():
            try:
                uid = self.monitor.uid_queue.get_nowait()
                if uid and len(uid) == self.UID_LENGTH:
                    detected_uid[0] = uid.upper()
                    uid_lbl.setText(f"Detected: {detected_uid[0]}")
                    uid_lbl.setStyleSheet(f"color: {SUCCESS}; font-size: 16pt; font-weight: bold;")
                    poll_timer.stop()
                    # Auto-accept after short delay so user sees the UID
                    QTimer.singleShot(800, dlg.accept)
            except queue.Empty:
                pass

        poll_timer = QTimer(dlg)
        poll_timer.timeout.connect(poll_uid)
        poll_timer.start(100)

        result = dlg.exec()
        poll_timer.stop()

        if result != QDialog.DialogCode.Accepted or not detected_uid[0]:
            return

        uid = detected_uid[0]

        # Ask for name
        name, ok2 = QInputDialog.getText(
            self, "Register Card",
            f"UID: {uid}\n\nEnter cardholder name (optional):"
        )
        if not ok2:
            return
        name = name.strip() or "Unknown"

        success, msg = self.db.register_card(uid, name)
        if success:
            self._append_log(self._make_log_entry(
                f"Registered card UID: {uid} — {name}", "[OK]"
            ))
            # Push the full updated cards list to both ESP32s so they recognise this card reliably
            # A full sync is safer than just CARD_ADD in case an ESP32 was busy and dropped it.
            if self.monitor and self.monitor.running:
                self.monitor._push_cards_to_esp32()
            self._refresh_cards()
        else:
            QMessageBox.critical(self, "Error", msg)

    def _remove_card(self):
        if not self.db:
            QMessageBox.critical(self, "No DB", "Database not connected.")
            return
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Card", "Please select a card to remove.")
            return

        # Superadmin gate (already handled by button visibility, but just in case)
        if not self.is_superadmin:
            return

        uid = self.table.item(row, 0).text()
        ans = QMessageBox.question(
            self, "Confirm", f"Deactivate card {uid}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            success, msg = self.db.remove_card(uid)
            if success:
                self._append_log(self._make_log_entry(
                    f"Deactivated card UID: {uid}", "[WARN]"
                ))
                # Push CARD_REMOVE to both ESP32s
                if self.monitor and self.monitor.running:
                    self.monitor.send_card_command("CARD_REMOVE", uid)
                self._refresh_cards()
            else:
                QMessageBox.critical(self, "Error", msg)


# =====================================================================
#  ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    # Windows taskbar icon: register unique AppUserModelID
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "sentinel.mini.dataroom.1.0"
        )
    except Exception:
        pass

    # Auto-setup Mosquitto (config + start + firewall)
    _setup_mosquitto()

    # High DPI support (attributes may not exist in PyQt6 6.5+)
    for attr in ("AA_EnableHighDpiScaling", "AA_UseHighDpiPixmaps"):
        if hasattr(Qt.ApplicationAttribute, attr):
            QApplication.setAttribute(getattr(Qt.ApplicationAttribute, attr), True)

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(ICON_PATH))

    window = SentinelApp()
    window.setWindowIcon(QIcon(ICON_PATH))
    window.show()
    sys.exit(app.exec())
