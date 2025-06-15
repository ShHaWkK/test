#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
import random
import re
import os
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from fpdf import FPDF
import uuid
import select
import signal
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import string
import termios
import tty
import ipapi
from io import StringIO
import logging

# Configuration du logging avancé
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - IP: %(client_ip)s - Session ID: %(session_id)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
HOST = ""
PORT = 2224
SFTP_PORT = 2225
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "honeypot.db"
FS_DB = "filesystem.db"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300
CMD_LIMIT_PER_SESSION = 50
CONNECTION_LIMIT_PER_IP = 10
PORT_SCAN_THRESHOLD = 10  # Nombre de connexions suspectes par minute
TRAP_CLEANUP_INTERVAL = 86400  # 24 heures en secondes
RISK_SCORE_THRESHOLD = 50  # Seuil d'alerte de score de risque
_risk_scores = {}  # Score de risque par session IP
_brute_force_attempts = {}  # Suivi des tentatives de force brute
_brute_force_alerted = set()  # Suivi des IPs alertées pour force brute
_brute_force_lock = threading.Lock()
_connection_count = {}
_connection_lock = threading.Lock()
fs_lock = threading.Lock()
_scan_attempts = {}  # Tentatives de scan de port par IP

SESSION_LOG_DIR = None

FAKE_SERVICES = {
    "ftp": 21,
    "http": 80,
    "mysql": 3306,
    "telnet": 23,
}

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "honeycute896@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "jawm fmcm dmaf qkyl")
ALERT_FROM = SMTP_USER
ALERT_TO = os.getenv("ALERT_TO", "alexandreuzan75@gmail.com")

PREDEFINED_USERS = {
    "admin": {"home": "/home/admin", "password": hashlib.sha256("admin123".encode()).hexdigest(), "uid": 1000, "groups": ["admin", "sudo"]},
    "devops": {"home": "/home/devops", "password": hashlib.sha256("devops456".encode()).hexdigest(), "uid": 1001, "groups": ["devops"]},
    "dbadmin": {"home": "/home/dbadmin", "password": hashlib.sha256("dbadmin789".encode()).hexdigest(), "uid": 1002, "groups": ["dbadmin"]},
    "mysql": {"home": "/var/lib/mysql", "password": hashlib.sha256("mysql123".encode()).hexdigest(), "uid": 110, "groups": ["mysql"]},
    "www-data": {"home": "/var/www", "password": hashlib.sha256("wwwdata123".encode()).hexdigest(), "uid": 33, "groups": ["www-data"]}
}

USER_FILES = {
    "admin": {
        "credentials.txt": "admin:supersecret\n# Internal use only",
        ".trap_credentials": "Trap file: access logged",
        ".secret_key": "ssh-rsa AAAAB3NzaC1yc2E...admin_key",
        "project_config": "projectA: sensitive data...",
        "backup_pass.txt": "root:admin123\nbackup:backup456",
        ".backup_log": "Backup completed at 2025-06-11 12:00"
    },
    "devops": {
        "deploy_key": "ssh-rsa AAAAB3NzaC1yc2E...devops_key",
        "jenkins.yml": "jenkins: {url: [invalid url, do not cite] user: admin, pass: admin123}",
        ".bashrc": "alias ll='ls -la'\nexport PATH=$PATH:/usr/local/bin",
        ".env": "DB_PASSWORD=devops789",
        ".trap_config": "Trap file: access logged"
    },
    "dbadmin": {
        "backup.sql": "-- SQL dump\nDROP TABLE IF EXISTS users;",
        "scripts.sh": "#!/bin/bash\necho 'DB maintenance...'",
        "mysql_creds.txt": "mysql_user:root\nmysql_pass:password123",
        ".db_log": "Database sync at 2025-06-12 09:00",
        ".trap_db": "Trap file: access logged"
    },
    "mysql": {
        ".mysql_config": "port=3306\nuser=root",
        "data.bin": "Binary data placeholder",
        ".trap_data": "Trap file: access logged"
    },
    "www-data": {
        "config.php": "<?php define('DB_PASS', 'weakpass123'); ?>",
        ".htaccess": "Deny from all",
        "error.log": "Error: 404 at 2025-06-11 14:00",
        ".trap_web": "Trap file: access logged"
    }
}

SENSITIVE_FILES = [
    "/home/admin/credentials.txt", "/home/admin/backup_pass.txt", "/home/dbadmin/mysql_creds.txt",
    "/var/www/config.php", "/tmp/suspicious.sh", "/home/admin/.hidden_config", "/var/lib/mysql/.mysql_config"
]

FAKE_NETWORK_HOSTS = {
    "192.168.1.10": {"name": "webserver.local", "services": ["http", "https"]},
    "192.168.1.20": {"name": "dbserver.local", "services": ["mysql"]},
    "192.168.1.30": {"name": "backup.local", "services": ["ftp"]},
    "8.8.8.8": {"name": "google-dns", "services": ["dns"]}
}

COMMAND_OPTIONS = {
    "ls": ["-l", "-a", "-la", "-lh", "--help"], "cat": ["-n", "--help"], "grep": ["-i", "-r", "-n", "--help"],
    "find": ["-name", "-type", "-exec", "--help"], "chmod": ["-R", "+x", "755", "644", "--help"],
    "chown": ["-R", "--help"], "service": ["start", "stop", "status", "restart"],
    "systemctl": ["start", "stop", "status", "restart", "enable", "disable"], "ip": ["addr", "link", "route"],
    "apt-get": ["update", "upgrade", "install", "remove"], "scp": ["-r", "-P"], "curl": ["-O", "-L", "--help"],
    "wget": ["-O", "-q", "--help"], "telnet": [], "ping": ["-c", "-i"], "nmap": ["-sS", "-sV"], "who": [],
    "w": [], "top": [], "df": ["-h"], "uptime": [], "ps": ["-aux"], "netstat": ["-tuln"], "dmesg": [],
    "app_status": [], "status_report": [], "backup_data": []
}

# Dynamic data generators
@lru_cache(maxsize=10)
def get_dynamic_df(): return f"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   {random.randint(5,10)}G   {random.randint(30,45)}G  {random.randint(10,20)}% /\ntmpfs           100M     0M  100M   0% /tmp"
@lru_cache(maxsize=10)
def get_dynamic_uptime(): return f"03:07 AM CEST, Sat Jun 14, 2025 up {random.randint(3,10)} days, {random.randint(0,23)}:{random.randint(0,59):02d}, {random.randint(1,5)} user{'s' if random.randint(1,5)>1 else ''}, load average: {random.uniform(0.00,1.00):.2f}, {random.uniform(0.00,1.00):.2f}, {random.uniform(0.00,1.00):.2f}"
@lru_cache(maxsize=10)
def get_dynamic_ps(): return "\r\n".join(["USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND"] + [f"{random.choice(['root','admin','devops']):<10} {random.randint(1,5000):<6} {random.uniform(0.0,5.0):<5.1f} {random.uniform(0.5,3.0):<5.1f} {random.randint(10000,50000):<7} {random.randint(1000,5000):<6} {random.choice(['pts/0','pts/1','?','tty7']):<6} {random.choice(['Ss','S+','R']):<5} {(datetime.now()-timedelta(hours=random.randint(1,24))).strftime('%H:%M'):<8} {random.randint(0,2)}:{random.randint(0,59):02d} {random.choice(['/sbin/init','/usr/sbin/sshd -D','/usr/bin/python3 app.py'])}" for _ in range(5)])
def get_dynamic_top(): return "top - %s up %d days, %02d:%02d, %d user%s, load average: %.2f, %.2f, %.2f\nTasks: %d total, %d running, %d sleeping, %d stopped, %d zombie\n%%Cpu(s): %.1f us, %.1f sy, %.1f ni, %.1f id, %.1f wa, %.1f hi, %.1f si, %.1f st\nMiB Mem : %d total, %d free, %d used, %d buff/cache\n%s" % (datetime.now().strftime("%H:%M:%S"), random.randint(3,10), random.randint(0,23), random.randint(0,59), random.randint(1,5), "s" if random.randint(1,5)>1 else "", random.uniform(0.0,1.0), random.uniform(0.0,1.0), random.uniform(0.0,1.0), random.randint(50,100), random.randint(1,5), random.randint(40,80), 0, 0, random.uniform(0,10), random.uniform(0,5), 0, random.uniform(80,90), random.uniform(0,2), random.uniform(0,1), random.uniform(0,1), 0, random.randint(16000,32000), random.randint(1000,5000), random.randint(5000,10000), random.randint(1000,5000), get_dynamic_ps().split("\n")[1:5])
@lru_cache(maxsize=10)
def get_dynamic_netstat(): return "\r\n".join(["Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"] + [f"tcp        {random.randint(0,10)}      {random.randint(0,10)} 192.168.1.{random.randint(2,254)}:{random.choice([22,80,443,3306,8080])} 10.0.0.{random.randint(2,254)}:{random.randint(1024,65535)} {random.choice(['ESTABLISHED','TIME_WAIT','CLOSE_WAIT','LISTEN']):<10} {random.randint(100,999)}/app{random.randint(1,5)}" for _ in range(random.randint(2,6))])
@lru_cache(maxsize=10)
def get_dynamic_messages(): return "\n".join([f"{(datetime.now()-timedelta(minutes=random.randint(0,1440))).strftime('%b %d %H:%M:%S')} debian {random.choice(['sshd','systemd','cron','nginx','apache2','mysqld'])[random.randint(1000,9999)]}: {random.choice(['Started service.','Connection from 192.168.1.{random.randint(2,254)}','Configuration loaded','Warning: High CPU usage','Failed login from 192.168.1.{random.randint(2,254)}','Suspicious activity on port {random.randint(1024,65535)}'])}" for _ in range(10)])
@lru_cache(maxsize=10)
def get_dynamic_dmesg(): return "\n".join([f"[{random.uniform(0,1000):.6f}] {random.choice(['kernel: [CPU0] microcode updated early to revision 0xca','kernel: random: crng init done','kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode','kernel: ACPI: Power Button [PWRB]'])}" for _ in range(10)])
@lru_cache(maxsize=10)
def get_dynamic_network_scan(): return "\n".join([f"{ip}:{FAKE_SERVICES[service]} open {service}" for ip, info in FAKE_NETWORK_HOSTS.items() for service in info["services"] if FAKE_SERVICES.get(service)])
@lru_cache(maxsize=10)
def get_dynamic_arp(): return "\n".join(["Address                  HWtype  HWaddress           Flags Mask            Iface"] + [f"{ip:<24} ether   {':'.join(f'{random.randint(0,255):02x}' for _ in range(6))}   C                     eth0" for ip in FAKE_NETWORK_HOSTS])
@lru_cache(maxsize=10)
def get_dynamic_who(): return "\n".join([f"{user:<10} {random.choice(['pts/0','pts/1','tty7']):<8} {(datetime.now()-timedelta(minutes=random.randint(0,1440))).strftime('%Y-%m-%d %H:%M')} 192.168.1.{random.randint(10,50)}" for user in ["admin", "devops", "dbadmin"] + [f"temp_{''.join(random.choices(string.ascii_lowercase, k=6))}" for _ in range(random.randint(0,3))]])
def get_dynamic_w(): return " 03:07 AM CEST, Sat Jun 14, 2025 up 7 days,  3:45,  2 users,  load average: 0.10, 0.20, 0.30\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" + "\n".join(get_dynamic_who().split("\n")[1:3])
def get_dev_null(): return ""
def get_dev_zero(): return "\0" * 1024

def init_filesystem_db():
    try:
        with sqlite3.connect(FS_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS filesystem (
                    path TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    content TEXT,
                    owner TEXT,
                    permissions TEXT,
                    mtime TEXT
                )
            """)
        logger.info("Filesystem database initialized", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
    except sqlite3.Error as e:
        logger.error(f"Filesystem DB init error: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
        raise

def init_database():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    success INTEGER,
                    redirected INTEGER
                );
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    command TEXT NOT NULL,
                    session_id INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sftp_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    path TEXT NOT NULL,
                    details TEXT
                )
            """)
        logger.info("Database initialized", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
    except sqlite3.Error as e:
        logger.error(f"DB init error: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
        raise

def load_filesystem():
    fs = {}
    try:
        with sqlite3.connect(FS_DB) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT path, type, content, owner, permissions, mtime FROM filesystem")
            for row in cur.fetchall():
                path = row["path"]
                fs[path] = {
                    "type": row["type"],
                    "content": row["content"] if row["content"] is not None else "",
                    "owner": row["owner"] or "root",
                    "permissions": row["permissions"] or "rw-r--r--",
                    "mtime": row["mtime"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "contents": [] if row["type"] == "dir" else None
                }
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir not in fs:
                    fs[parent_dir] = {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                if path != "/" and row["type"] == "dir" and path not in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
    except sqlite3.Error as e:
        logger.error(f"Filesystem load error: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
        return None
    return fs if fs else None

def save_filesystem(fs):
    try:
        with sqlite3.connect(FS_DB) as conn:
            conn.execute("DELETE FROM filesystem")
            for path, data in fs.items():
                conn.execute(
                    "INSERT INTO filesystem (path, type, content, owner, permissions, mtime) VALUES (?, ?, ?, ?, ?, ?)",
                    (path, data["type"], data.get("content", "") if not callable(data.get("content")) else "", data.get("owner", "root"), data.get("permissions", "rw-r--r--"), data.get("mtime", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                )
        logger.info("Filesystem saved", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
    except sqlite3.Error as e:
        logger.error(f"Filesystem save error: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["bin", "sbin", "usr", "var", "opt", "root", "home", "etc", "tmp", "proc", "dev", "sys", "lib"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/bin": {"type": "dir", "contents": ["bash", "ls", "cat", "grep", "chmod", "chown", "mv", "cp", "top", "ifconfig", "ip", "find", "scp", "apt-get", "curl", "wget", "telnet", "ping", "nmap", "who", "w", "app_status", "status_report", "backup_data"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/sbin": {"type": "dir", "contents": ["init", "sshd", "iptables", "reboot"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var": {"type": "dir", "contents": ["log", "www", "lib"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log": {"type": "dir", "contents": ["syslog", "messages", "auth.log", ".hidden_log"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/syslog": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/messages": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/auth.log": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/.hidden_log": {"type": "file", "content": "Hidden log data: access denied", "owner": "root", "permissions": "r--r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www": {"type": "dir", "contents": ["html"], "owner": "www-data", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html": {"type": "dir", "contents": ["index.html", "config.php", ".htaccess", "error.log"], "owner": "www-data", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html/index.html": {"type": "file", "content": "<html><body><h1>Welcome to Server</h1></body></html>", "owner": "www-data", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html/config.php": {"type": "file", "content": "<?php define('DB_PASS', 'weakpass123'); ?>", "owner": "www-data", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html/.htaccess": {"type": "file", "content": "Deny from all", "owner": "www-data", "permissions": "r--r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html/error.log": {"type": "file", "content": "Error: 404 at 2025-06-11 14:00", "owner": "www-data", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/tmp": {"type": "dir", "contents": ["suspicious.sh", ".trap_temp", "backup.tar.gz"], "owner": "root", "permissions": "rwxrwxrwx", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/tmp/suspicious.sh": {"type": "file", "content": "#!/bin/bash\nrm -rf /\n# Malicious script", "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/tmp/.trap_temp": {"type": "file", "content": "Trap file: access logged", "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/tmp/backup.tar.gz": {"type": "file", "content": "Backup data placeholder", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev": {"type": "dir", "contents": ["null", "zero"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev/null": {"type": "file", "content": get_dev_null, "owner": "root", "permissions": "rwxrwxrwx", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev/zero": {"type": "file", "content": get_dev_zero, "owner": "root", "permissions": "rwxrwxrwx", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/home": {"type": "dir", "contents": ["admin", "devops", "dbadmin"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
}

def populate_predefined_users(fs):
    for user, data in PREDEFINED_USERS.items():
        home_dir = data["home"]
        if home_dir not in fs:
            fs[home_dir] = {"type": "dir", "contents": [], "owner": user, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        for file_name, content in USER_FILES[user].items():
            full_path = os.path.join(home_dir, file_name)
            fs[full_path] = {"type": "file", "content": content, "owner": user, "permissions": "rw-r--r--" if not file_name.startswith(".trap_") else "rwxrwxrwx", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            if home_dir in fs and file_name not in fs[home_dir]["contents"]:
                fs[home_dir]["contents"].append(file_name)
    return fs

def add_vulnerabilities(fs):
    vulnerable_files = ["/tmp/suspicious.sh", "/var/www/html/config.php", "/home/admin/credentials.txt", "/home/dbadmin/mysql_creds.txt"]
    for path in vulnerable_files:
        if path not in fs:
            fs[path] = {"type": "file", "content": f"Vulnerable file at {path}", "owner": "root", "permissions": "rwxrwxrwx", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

def trigger_alert(session_id, event_type, details, client_ip, username, location=None):
    geo_info = ipapi.location(client_ip) if location is None else location
    location_str = f" (Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')})" if geo_info else ""
    logger.warning(f"{event_type} - {details}{location_str} from {client_ip} ({username})", extra={'client_ip': client_ip, 'session_id': session_id})
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                "INSERT INTO events (timestamp, ip, username, event_type, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, username, event_type, f"{details}{location_str}")
            )
    except sqlite3.Error as e:
        logger.error(f"Event log error: {e}", extra={'client_ip': client_ip, 'session_id': session_id})

def check_bruteforce(client_ip, username, password):
    with _brute_force_lock:
        key = (client_ip, username)
        now = time.time()
        attempts = _brute_force_attempts.get(key, [])
        attempts = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW]
        attempts.append(now)
        _brute_force_attempts[key] = attempts
        if len(attempts) >= BRUTE_FORCE_THRESHOLD and key not in _brute_force_alerted:
            trigger_alert(None, "Brute Force Attempt", f"Excessive login attempts from {client_ip} for {username}", client_ip, "unknown")
            _brute_force_alerted.add(key)
        return len(attempts) < BRUTE_FORCE_THRESHOLD

def detect_port_scan(client_ip):
    now = time.time()
    attempts = _scan_attempts.get(client_ip, [])
    attempts = [t for t in attempts if now - t < 60]  # Fenêtre de 1 minute
    attempts.append(now)
    _scan_attempts[client_ip] = attempts
    if len(attempts) >= PORT_SCAN_THRESHOLD:
        trigger_alert(None, "Port Scan Detected", f"Possible port scan from {client_ip}", client_ip, "unknown")
        return True
    return False

def cleanup_bruteforce_attempts():
    while True:
        with _brute_force_lock:
            now = time.time()
            _brute_force_attempts = {k: [t for t in v if now - t < BRUTE_FORCE_WINDOW] for k, v in _brute_force_attempts.items()}
            _brute_force_alerted = {k for k in _brute_force_alerted if k in _brute_force_attempts and _brute_force_attempts[k]}
            _scan_attempts = {k: [t for t in v if now - t < 60] for k, v in _scan_attempts.items()}
        time.sleep(60)
        logger.info("Bruteforce and scan attempts cleaned up", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

def cleanup_trap_files():
    while True:
        with fs_lock:
            for path in list(FS.keys()):
                if path.endswith(".trap_") and random.random() < 0.1:  # 10% de chance par cycle
                    parent_dir = "/".join(path.split("/")[:-1]) or "/"
                    if parent_dir in FS and path.split("/")[-1] in FS[parent_dir]["contents"]:
                        FS[parent_dir]["contents"].remove(path.split("/")[-1])
                    del FS[path]
            save_filesystem(FS)
        time.sleep(TRAP_CLEANUP_INTERVAL)
        logger.info("Trap files cleaned up", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

def calculate_risk_score(commands):
    score = 0
    patterns = {
        r"rm\s+-rf": 20,
        r"wget|curl": 15,
        r"chmod\s+.*777": 10,
        r"cat\s+.*(credentials|pass)": 15,
        r"nmap|ping\s+.*\d+\.\d+\.\d+\.\d+": 10
    }
    for cmd in commands:
        for pattern, points in patterns.items():
            if re.search(pattern, cmd.lower()):
                score += points
    return min(score, 100)  # Cap à 100

def generate_pdf_report(report_type):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    period = {
        "15min": "Last 15 minutes",
        "hourly": "Last hour",
        "weekly": "Last week"
    }.get(report_type, "Unknown period")
    pdf.cell(200, 10, txt=f"Honeypot Report - {period} ({now})", ln=True, align="C")
    pdf.ln(10)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            time_filter = {
                "15min": "WHERE timestamp >= datetime('now', '-15 minutes')",
                "hourly": "WHERE timestamp >= datetime('now', '-1 hour')",
                "weekly": "WHERE timestamp >= datetime('now', '-7 days')"
            }.get(report_type, "")
            cur.execute(f"SELECT * FROM events {time_filter} ORDER BY timestamp DESC")
            events = cur.fetchall()
            for event in events:
                pdf.cell(200, 10, txt=f"{event['timestamp']} - {event['event_type']}: {event['details']}", ln=True)
    except sqlite3.Error as e:
        pdf.cell(200, 10, txt=f"Error generating report: {e}", ln=True)
    pdf_output = f"report_{report_type}_{now}.pdf"
    pdf.output(pdf_output)
    return pdf_output

def send_report(report_path, report_type):
    msg = MIMEMultipart()
    msg['From'] = ALERT_FROM
    msg['To'] = ALERT_TO
    msg['Subject'] = f"Honeypot Report - {report_type}"
    with open(report_path, "rb") as f:
        part = MIMEApplication(f.read(), Name=os.path.basename(report_path))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(report_path)}"'
        msg.attach(part)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Report {report_type} sent successfully", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
    except Exception as e:
        logger.error(f"Failed to send report {report_type}: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
    finally:
        os.remove(report_path)

def schedule_reports():
    while True:
        now = datetime.now()
        if now.minute % 15 == 0 and now.second < 5:  # Toutes les 15 minutes
            send_report(generate_pdf_report("15min"), "15min")
        if now.minute == 0 and now.second < 5:  # Toutes les heures
            send_report(generate_pdf_report("hourly"), "hourly")
        if now.weekday() == 0 and now.hour == 0 and now.minute == 0 and now.second < 5:  # Chaque lundi à minuit
            send_report(generate_pdf_report("weekly"), "weekly")
        time.sleep(5)
        logger.info("Report scheduling cycle completed", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

def detect_attacker_os(client_ip, transport):
    banner = transport.get_banner().decode().lower() if transport and transport.get_banner() else ""
    if "windows" in banner or "putty" in banner:
        return "Windows"
    elif "linux" in banner or "kali" in banner or "ubuntu" in banner or "debian" in banner:
        return "Linux"
    elif "mac" in banner or "darwin" in banner:
        return "macOS"
    return "Unknown"

def get_completions(cmd, current_dir, username, fs, command_history):
    completions = set()
    cmd_parts = cmd.split()
    if not cmd_parts:
        return list(COMMAND_OPTIONS.keys())
    prefix = cmd_parts[-1]
    if len(cmd_parts) == 1:  # Autocomplétion des commandes
        for command in COMMAND_OPTIONS:
            if command.startswith(prefix):
                completions.add(command)
        for option in COMMAND_OPTIONS.get(prefix, []):
            completions.add(f"{prefix} {option}")
    else:  # Autocomplétion des chemins ou arguments
        cmd_name = cmd_parts[0].lower()
        if cmd_name in ["ls", "cd", "cat", "rm", "find", "vim", "nano"] and current_dir in fs and fs[current_dir]["type"] == "dir":
            base_path = current_dir if current_dir != "/" else ""
            partial_path = prefix if not prefix.startswith("/") else prefix
            if not partial_path.startswith("/"):
                partial_path = os.path.normpath(os.path.join(current_dir, partial_path))
            dir_path = "/".join(partial_path.split("/")[:-1]) or "/"
            item_prefix = partial_path.split("/")[-1] if dir_path in fs else ""
            if dir_path in fs:
                for item in fs[dir_path]["contents"]:
                    full_path = os.path.join(dir_path, item)
                    if full_path in fs:
                        if fs[full_path]["type"] == "dir" and cmd_name in ["cd", "ls"]:
                            if item.startswith(item_prefix):
                                completions.add(item + "/")
                        elif fs[full_path]["type"] == "file" and cmd_name in ["cat", "rm", "vim", "nano"]:
                            if item.startswith(item_prefix):
                                completions.add(item)
    return sorted(list(completions))

def autocomplete(cmd, current_dir, username, fs, chan, command_history):
    completions = get_completions(cmd, current_dir, username, fs, command_history)
    if len(completions) == 1:
        return completions[0]
    elif len(completions) > 1:
        common_prefix = os.path.commonprefix(completions)
        if common_prefix and common_prefix != cmd.split()[-1]:
            return cmd[:cmd.rfind(cmd.split()[-1])] + common_prefix
        chan.send(b"\r\n" + "\n".join(completions).encode() + b"\r\n" + f"{cmd}".encode())
    return cmd

def process_command(cmd, current_dir, username, fs, client_ip, session_id, session_log, command_history, chan, jobs, cmd_count, transport):
    if not cmd:
        return "", current_dir, jobs, cmd_count

    cmd_parts = cmd.split(maxsplit=1)
    cmd_name = cmd_parts[0].lower()
    arg_str = cmd_parts[1] if len(cmd_parts) > 1 else ""
    output = ""
    new_dir = current_dir

    # Mise à jour du score de risque
    with _brute_force_lock:
        _risk_scores[session_id] = _risk_scores.get(session_id, 0) + calculate_risk_score([cmd])
        if _risk_scores[session_id] >= RISK_SCORE_THRESHOLD:
            trigger_alert(session_id, "High Risk Activity", f"Risk score {_risk_scores[session_id]} exceeded threshold", client_ip, username)

    if cmd_name in ["ls", "dir"]:
        args = arg_str.split()
        show_all = "-a" in args or "-la" in args
        long_format = "-l" in args or "-la" in args or "-lh" in args
        human_readable = "-lh" in args
        target_dir = arg_str.replace("-l", "").replace("-a", "").replace("-la", "").replace("-lh", "").strip() or current_dir
        if not target_dir.startswith("/"):
            target_dir = os.path.normpath(os.path.join(current_dir, target_dir))
        if target_dir in fs and fs[target_dir]["type"] == "dir":
            contents = fs[target_dir]["contents"]
            if long_format:
                output = "total {}\n".format(len(contents))
                for item in contents:
                    full_path = os.path.join(target_dir, item)
                    if full_path in fs:
                        item_data = fs[full_path]
                        perms = item_data["permissions"]
                        owner = item_data["owner"]
                        mtime = item_data["mtime"]
                        size = len(str(item_data.get("content", ""))) if item_data.get("content") and not callable(item_data.get("content")) else 0
                        if human_readable and size > 0:
                            size = f"{size}B"
                        output += f"{perms}  1 {owner} {owner} {size:>6} {mtime} {item}\n"
                        if item.startswith(".trap_"):
                            trigger_alert(session_id, "Trap File Access", f"Accessed {full_path}", client_ip, username)
            else:
                output = " ".join(contents) if contents else "Directory is empty"
        else:
            output = f"ls: cannot access '{target_dir}': No such file or directory"

    elif cmd_name == "cd":
        target_dir = arg_str.strip() or "/"
        if not target_dir.startswith("/"):
            target_dir = os.path.normpath(os.path.join(current_dir, target_dir))
        if target_dir in fs and fs[target_dir]["type"] == "dir":
            if username not in PREDEFINED_USERS or target_dir.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                new_dir = target_dir
            else:
                output = f"cd: permission denied: {target_dir}"
        else:
            output = f"cd: no such directory: {target_dir}"

    elif cmd_name == "cat":
        target_file = arg_str.strip()
        if not target_file.startswith("/"):
            target_file = os.path.normpath(os.path.join(current_dir, target_file))
        if target_file in fs and fs[target_file]["type"] == "file":
            if username not in PREDEFINED_USERS or target_file.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                content = fs[target_file].get("content", "")
                if callable(content):
                    output = content()
                else:
                    output = content
                if target_file.startswith(".trap_"):
                    trigger_alert(session_id, "Trap File Access", f"Accessed {target_file}", client_ip, username)
            else:
                output = f"cat: {target_file}: Permission denied"
        else:
            output = f"cat: {target_file}: No such file or directory"

    elif cmd_name == "vim" or cmd_name == "nano":
        chan.send(b"\r\nEntering editor mode (simulated). Type content, then :wq to save or :q to exit.\r\n")
        editor_buffer = ""
        while True:
            char = read_char(chan)
            if not char:
                continue
            if char == "\r" or char == "\n":
                chan.send(b"\r\n")
            elif char == ":" and editor_buffer.endswith("wq"):
                target_file = arg_str.strip()
                if not target_file.startswith("/"):
                    target_file = os.path.normpath(os.path.join(current_dir, target_file))
                if target_file not in fs:
                    fs[target_file] = {"type": "file", "content": editor_buffer[:-3], "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    parent_dir = "/".join(target_file.split("/")[:-1]) or "/"
                    if parent_dir in fs:
                        fs[parent_dir]["contents"].append(target_file.split("/")[-1])
                    save_filesystem(fs)
                    trigger_alert(session_id, "File Edited", f"Edited {target_file} with {len(editor_buffer)} chars", client_ip, username)
                break
            elif char == ":" and editor_buffer.endswith("q"):
                break
            else:
                editor_buffer += char
                chan.send(char.encode())
        return "", current_dir, jobs, cmd_count

    elif cmd_name == "rm":
        target = arg_str.strip()
        if not target.startswith("/"):
            target = os.path.normpath(os.path.join(current_dir, target))
        if target in fs:
            if username not in PREDEFINED_USERS or target.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                parent_dir = "/".join(target.split("/")[:-1]) or "/"
                if parent_dir in fs and target in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].remove(target.split("/")[-1])
                del fs[target]
                save_filesystem(fs)
                output = f"rm: removed '{target}'"
                trigger_alert(session_id, "File Removed", f"Removed {target}", client_ip, username)
            else:
                output = f"rm: cannot remove '{target}': Permission denied"
        else:
            output = f"rm: cannot remove '{target}': No such file or directory"

    elif cmd_name == "mkdir":
        target_dir = arg_str.strip()
        if not target_dir.startswith("/"):
            target_dir = os.path.normpath(os.path.join(current_dir, target_dir))
        if target_dir not in fs:
            if username not in PREDEFINED_USERS or target_dir.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[target_dir] = {"type": "dir", "contents": [], "owner": username, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                parent_dir = "/".join(target_dir.split("/")[:-1]) or "/"
                if parent_dir in fs:
                    fs[parent_dir]["contents"].append(target_dir.split("/")[-1])
                save_filesystem(fs)
                output = f"mkdir: created directory '{target_dir}'"
                trigger_alert(session_id, "Directory Created", f"Created {target_dir}", client_ip, username)
            else:
                output = f"mkdir: cannot create directory '{target_dir}': Permission denied"
        else:
            output = f"mkdir: cannot create directory '{target_dir}': File exists"

    elif cmd_name == "touch":
        target_file = arg_str.strip()
        if not target_file.startswith("/"):
            target_file = os.path.normpath(os.path.join(current_dir, target_file))
        if target_file not in fs:
            if username not in PREDEFINED_USERS or target_file.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[target_file] = {"type": "file", "content": "", "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                parent_dir = "/".join(target_file.split("/")[:-1]) or "/"
                if parent_dir in fs:
                    fs[parent_dir]["contents"].append(target_file.split("/")[-1])
                save_filesystem(fs)
                output = f"touch: created file '{target_file}'"
                trigger_alert(session_id, "File Created", f"Created {target_file}", client_ip, username)
            else:
                output = f"touch: cannot create file '{target_file}': Permission denied"
        else:
            output = f"touch: cannot create file '{target_file}': File exists"

    elif cmd_name == "ping":
        target = arg_str.split()[0] if arg_str else "8.8.8.8"
        if target in FAKE_NETWORK_HOSTS:
            output = f"PING {target} ({target}) 56(84) bytes of data.\n64 bytes from {target}: icmp_seq=1 ttl=64 time=10.5 ms\n--- {target} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms"
        else:
            output = f"ping: unknown host {target}"
        detect_port_scan(client_ip)

    elif cmd_name == "nmap":
        output = get_dynamic_network_scan()
        detect_port_scan(client_ip)

    elif cmd_name == "arp":
        output = get_dynamic_arp()

    elif cmd_name == "who":
        output = get_dynamic_who()

    elif cmd_name == "w":
        output = get_dynamic_w()

    elif cmd_name == "top":
        output = get_dynamic_top()

    elif cmd_name == "cp":
        src, dest = [x.strip() for x in arg_str.split()[:2]]
        if not src.startswith("/") and not dest.startswith("/"):
            src = os.path.normpath(os.path.join(current_dir, src))
            dest = os.path.normpath(os.path.join(current_dir, dest))
        if src in fs and dest not in fs:
            if username not in PREDEFINED_USERS or src.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[dest] = fs[src].copy()
                fs[dest]["content"] = fs[src].get("content", "")
                fs[dest]["mtime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                parent_dir = "/".join(dest.split("/")[:-1]) or "/"
                if parent_dir in fs:
                    fs[parent_dir]["contents"].append(dest.split("/")[-1])
                save_filesystem(fs)
                output = f"cp: copied '{src}' to '{dest}'"
                trigger_alert(session_id, "File Copied", f"Copied {src} to {dest}", client_ip, username)
            else:
                output = f"cp: cannot copy '{src}' to '{dest}': Permission denied"
        else:
            output = f"cp: cannot copy '{src}' to '{dest}': No such file or directory"

    elif cmd_name == "mv":
        src, dest = [x.strip() for x in arg_str.split()[:2]]
        if not src.startswith("/") and not dest.startswith("/"):
            src = os.path.normpath(os.path.join(current_dir, src))
            dest = os.path.normpath(os.path.join(current_dir, dest))
        if src in fs and dest not in fs:
            if username not in PREDEFINED_USERS or src.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[dest] = fs[src].copy()
                fs[dest]["mtime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                parent_dir_src = "/".join(src.split("/")[:-1]) or "/"
                parent_dir_dest = "/".join(dest.split("/")[:-1]) or "/"
                if parent_dir_src in fs and src.split("/")[-1] in fs[parent_dir_src]["contents"]:
                    fs[parent_dir_src]["contents"].remove(src.split("/")[-1])
                if parent_dir_dest in fs:
                    fs[parent_dir_dest]["contents"].append(dest.split("/")[-1])
                del fs[src]
                save_filesystem(fs)
                output = f"mv: moved '{src}' to '{dest}'"
                trigger_alert(session_id, "File Moved", f"Moved {src} to {dest}", client_ip, username)
            else:
                output = f"mv: cannot move '{src}' to '{dest}': Permission denied"
        else:
            output = f"mv: cannot move '{src}' to '{dest}': No such file or directory"

    elif cmd_name == "chmod":
        target, perm = [x.strip() for x in arg_str.split()[:2]]
        if not target.startswith("/"):
            target = os.path.normpath(os.path.join(current_dir, target))
        if target in fs and perm in ["755", "644", "+x"]:
            if username not in PREDEFINED_USERS or target.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[target]["permissions"] = {"755": "rwxr-xr-x", "644": "rw-r--r--", "+x": "rwxr-xr-x" if "x" not in fs[target]["permissions"] else fs[target]["permissions"]}.get(perm, fs[target]["permissions"])
                save_filesystem(fs)
                output = f"chmod: changed permissions of '{target}' to {fs[target]['permissions']}"
                trigger_alert(session_id, "Permission Changed", f"Changed permissions of {target} to {perm}", client_ip, username)
            else:
                output = f"chmod: cannot access '{target}': Permission denied"
        else:
            output = f"chmod: invalid argument or file not found"

    elif cmd_name == "chown":
        target, new_owner = [x.strip() for x in arg_str.split()[:2]]
        if not target.startswith("/"):
            target = os.path.normpath(os.path.join(current_dir, target))
        if target in fs and new_owner in PREDEFINED_USERS:
            if username not in PREDEFINED_USERS or target.startswith(PREDEFINED_USERS[username]["home"]) or "sudo" in PREDEFINED_USERS[username].get("groups", []):
                fs[target]["owner"] = new_owner
                save_filesystem(fs)
                output = f"chown: changed owner of '{target}' to {new_owner}"
                trigger_alert(session_id, "Owner Changed", f"Changed owner of {target} to {new_owner}", client_ip, username)
            else:
                output = f"chown: cannot access '{target}': Permission denied"
        else:
            output = f"chown: invalid argument or file not found"

    elif cmd_name == "find":
        output = "find: simulated search (results not implemented)"
        trigger_alert(session_id, "Search Executed", f"Executed find {arg_str}", client_ip, username)

    elif cmd_name == "grep":
        output = "grep: simulated search (results not implemented)"
        trigger_alert(session_id, "Search Executed", f"Executed grep {arg_str}", client_ip, username)

    elif cmd_name == "service":
        if not arg_str:
            output = "service: missing service name"
        else:
            service = arg_str.split()[0]
            if service in ["sshd", "nginx", "mysql"]:
                action = arg_str.split()[1] if len(arg_str.split()) > 1 else "status"
                output = f"service: {action}ing {service} (simulated)"
                trigger_alert(session_id, "Service Command", f"Executed service {action} on {service}", client_ip, username)
            else:
                output = f"service: no such service '{service}'"

    elif cmd_name == "backup_data":
        if "/tmp" in fs and fs["/tmp"]["type"] == "dir":
            fs[os.path.join("/tmp", "backup.tar.gz")] = {"type": "file", "content": "Backup data placeholder", "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            if "backup.tar.gz" not in fs["/tmp"].get("contents", []):
                fs["/tmp"]["contents"].append("backup.tar.gz")
            save_filesystem(fs)
            output = "backup_data: backup created in /tmp/backup.tar.gz"
            trigger_alert(session_id, "Backup Created", "Created backup file in /tmp", client_ip, username)
        else:
            output = "backup_data: failed to create backup file"

    elif cmd_name == "app_status":
        output = f"app_status: Application {random.choice(['running','down','degraded'])} (simulated)"
        trigger_alert(session_id, "App Status Check", f"Checked app status: {output}", client_ip, username)

    elif cmd_name == "status_report":
        output = f"status_report: System uptime {get_dynamic_uptime()} (simulated)"
        trigger_alert(session_id, "Status Report", f"Generated status report", client_ip, username)

    elif cmd_name == "systemctl":
        if not arg_str:
            output = "systemctl: missing service name"
        else:
            service = arg_str.split()[0]
            if service in ["sshd", "nginx", "mysql"]:
                action = arg_str.split()[1] if len(arg_str.split()) > 1 else "status"
                output = f"systemctl: {action}ing {service} (simulated)"
                trigger_alert(session_id, "Service Command", f"Executed systemctl {action} on {service}", client_ip, username)
            else:
                output = f"systemctl: no such service '{service}'"

    elif cmd_name == "jobs":
        output = "\n".join([f"[{i}] {job}" for i, job in enumerate(jobs, 1)]) if jobs else "No jobs running"

    elif cmd_name == "fg":
        if jobs:
            job = jobs.pop(0)
            output = f"Foregrounding job: {job}"
        else:
            output = "fg: no current job"

    elif cmd_name == "whoami":
        output = username
        trigger_alert(session_id, "Command Executed", "Displayed user ID info", client_ip, username)

    elif cmd_name == "id":
        output = f"uid={PREDEFINED_USERS[username]['uid']}({username}) gid=1000 groups=1000"
        trigger_alert(session_id, "Command Executed", "Displayed user ID info", client_ip, username)

    elif cmd_name == "uname":
        output = "Linux debian 5.15.0-73-generic #80-Ubuntu SMP Mon May 15 14:04:23 UTC 2023 x86_64"
        trigger_alert(session_id, "Command Executed", "Displayed system info", client_ip, username)

    elif cmd_name == "pwd":
        output = current_dir
        trigger_alert(session_id, "Command Executed", "Displayed current directory", client_ip, username)

    elif cmd_name == "exit":
        return "", new_dir, jobs, cmd_count, True

    elif cmd_name == "history":
        output = "\n".join(f"{i+1}  {cmd}" for i, cmd in enumerate(command_history[-10:]))
        trigger_alert(session_id, "Command Executed", "Displayed command history", client_ip, username)

    elif cmd_name == "sudo" or cmd_name == "su":
        if not arg_str:
            output = f"{cmd_name}: missing username or command"
        elif arg_str in PREDEFINED_USERS:
            stored_hash = PREDEFINED_USERS[arg_str].get("password", "")
            if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                output = f"{cmd_name}: switched to {arg_str} (simulated)"
                username = arg_str
                trigger_alert(session_id, "Privilege Escalation", f"Switched to {arg_str}", client_ip, username)
            else:
                output = f"{cmd_name}: authentication failure"
                trigger_alert(session_id, "Auth Failure", f"Failed {cmd_name} attempt for {arg_str}", client_ip, username)
        else:
            output = f"{cmd_name}: unknown user {arg_str}"
            trigger_alert(session_id, "Auth Failure", f"Failed {cmd_name} attempt for {arg_str}", client_ip, username)

    elif cmd_name == "df":
        output = get_dynamic_df()
        trigger_alert(session_id, "Command Executed", "Displayed disk usage", client_ip, username)

    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
        trigger_alert(session_id, "Command Executed", "Displayed system uptime", client_ip, username)

    elif cmd_name == "ps":
        output = get_dynamic_ps()
        trigger_alert(session_id, "Command Executed", "Displayed process list", client_ip, username)

    elif cmd_name == "netstat":
        output = get_dynamic_netstat()
        trigger_alert(session_id, "Command Executed", "Displayed network connections", client_ip, username)

    elif cmd_name == "dmesg":
        output = get_dynamic_dmesg()
        trigger_alert(session_id, "Command Executed", "Displayed kernel messages", client_ip, username)

    else:
        output = f"Command '{cmd_name}' not found or not implemented"

    cmd_count += 1
    if cmd_count >= CMD_LIMIT_PER_SESSION:
        output += "\nWarning: Command limit reached for this session. Please restart."
        return output, new_dir, jobs, cmd_count, True

    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                "INSERT INTO commands (timestamp, ip, username, command, session_id) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, username or "unknown", cmd, session_id)
            )
    except sqlite3.Error as e:
        logger.error(f"Command log error: {e}", extra={'client_ip': client_ip, 'session_id': session_id})

    return output, new_dir, jobs, cmd_count

def read_char(chan):
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        r, _, _ = select.select([chan], [], [], 0.1)
        if r:
            return chan.recv(1).decode()
    except (termios.error, socket.error) as e:
        logger.error(f"Error reading char: {e}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})
        return None
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    return None

def read_line_advanced(chan, prompt, command_history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count, transport):
    chan.send(prompt)
    buffer = ""
    cursor_pos = 0
    history_pos = len(command_history)
    while True:
        char = read_char(chan)
        if not char:
            continue
        if char == "\r" or char == "\n":
            chan.send(b"\r\n")
            cmd = buffer.strip()
            if cmd:
                if cmd[0] == "\t":
                    cmd = autocomplete(cmd[1:], current_dir, username, fs, chan, command_history)
                else:
                    command_history.append(cmd)
                output, new_dir, jobs, cmd_count, exit_flag = process_command(cmd, current_dir, username or "unknown", fs, client_ip, session_id, session_log, command_history, chan, jobs, cmd_count, transport)
                if exit_flag:
                    return cmd, new_dir, jobs, cmd_count, True
                chan.send((output + "\r\n" + prompt.decode()).encode())
                current_dir = new_dir
            return cmd, current_dir, jobs, cmd_count, False
        elif char == "\t":
            completions = get_completions(buffer, current_dir, username, fs, command_history)
            if completions and len(completions) == 1:
                new_cmd = completions[0]
                buffer = new_cmd
                cursor_pos = len(buffer)
                chan.send(f"\r\033[K{prompt.decode()}{buffer}".encode())
            elif completions:
                chan.send(b"\r\n")
                for c in completions[:10]:
                    chan.send(f"{c}\r\n".encode())
                chan.send(f"\r{prompt.decode()}{buffer}".encode())
        elif char == "\033":  # Séquence d'échappement (flèches)
            next_char = read_char(chan)
            if next_char == "[":
                final_char = read_char(chan)
                if final_char == "A":  # Flèche haut
                    if history_pos > 0:
                        history_pos -= 1
                        buffer = command_history[history_pos] if history_pos < len(command_history) else ""
                        cursor_pos = len(buffer)
                        chan.send(f"\r\033[K{prompt.decode()}{buffer}".encode())
                elif final_char == "B":  # Flèche bas
                    if history_pos < len(command_history):
                        history_pos += 1
                        buffer = command_history[history_pos] if history_pos < len(command_history) else ""
                        cursor_pos = len(buffer)
                        chan.send(f"\r\033[K{prompt.decode()}{buffer}".encode())
                elif final_char == "C":  # Flèche droite
                    if cursor_pos < len(buffer):
                        cursor_pos += 1
                        chan.send(f"\r\033[K{prompt.decode()}{buffer[:cursor_pos]}\033[1C".encode())
                elif final_char == "D":  # Flèche gauche
                    if cursor_pos > 0:
                        cursor_pos -= 1
                        chan.send(f"\r\033[K{prompt.decode()}{buffer[:cursor_pos]}\033[1D".encode())
        elif char == "\x7f":  # Retour arrière
            if cursor_pos > 0:
                buffer = buffer[:cursor_pos-1] + buffer[cursor_pos:]
                cursor_pos -= 1
                chan.send(f"\r\033[K{prompt.decode()}{buffer}".encode())
        else:
            buffer = buffer[:cursor_pos] + char + buffer[cursor_pos:]
            cursor_pos += 1
            chan.send(f"\r\033[K{prompt.decode()}{buffer}".encode())
        time.sleep(0.01)

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.login_attempts = {}  # Suivi des tentatives par IP et utilisateur
        self.transport = None
        self.session_id = None
        self.client_ip = None
        self.username = None
        self.current_dir = "/"
        self.password = None

    def set_transport(self, transport):
        """Méthode pour définir le transport une fois disponible"""
        self.transport = transport
        if transport:
            try:
                self.client_ip = transport.getpeername()[0]
            except AttributeError:
                self.client_ip = "unknown"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if self.transport is None:
            client_ip = "unknown"
        else:
            try:
                client_ip = self.transport.getpeername()[0]
            except AttributeError:
                client_ip = "unknown"
        
        key = (client_ip, username)
        self.login_attempts[key] = self.login_attempts.get(key, 0) + 1
        attempt_count = self.login_attempts[key]
        self.password = password  # Stocker le mot de passe pour une utilisation ultérieure dans la session

        if username in PREDEFINED_USERS:
            stored_hash = PREDEFINED_USERS[username].get("password", "")
            if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                if check_bruteforce(client_ip, username, password):
                    try:
                        with sqlite3.connect(DB_NAME) as conn:
                            conn.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, username, password, 1, 0))
                    except sqlite3.Error as e:
                        logger.error(f"Login log error: {e}", extra={'client_ip': client_ip, 'session_id': self.session_id})
                    trigger_alert(self.session_id, "Successful Login", f"User {username} logged in from {client_ip}", client_ip, username)
                    self.login_attempts[key] = 0  # Réinitialiser après succès
                    self.username = username
                    return paramiko.AUTH_SUCCESSFUL
                else:
                    trigger_alert(self.session_id, "Auth Failure", f"Brute force detected for {username} from {client_ip}", client_ip, "unknown")
                    return paramiko.AUTH_FAILED
            else:
                try:
                    with sqlite3.connect(DB_NAME) as conn:
                        conn.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, username, password, 0, 0))
                except sqlite3.Error as e:
                    logger.error(f"Login log error: {e}", extra={'client_ip': client_ip, 'session_id': self.session_id})
                trigger_alert(self.session_id, "Auth Failure", f"Failed login attempt for {username} from {client_ip}", client_ip, "unknown")
                return paramiko.AUTH_FAILED
        else:
            if attempt_count >= 3:
                trigger_alert(self.session_id, "Successful Login", f"User {username} allowed after {attempt_count} attempts from {client_ip}", client_ip, username)
                self.login_attempts[key] = 0
                self.username = username
                return paramiko.AUTH_SUCCESSFUL
            else:
                trigger_alert(self.session_id, "Auth Failure", f"Attempt {attempt_count}/3 failed for {username} from {client_ip}", client_ip, "unknown")
                return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

class HoneypotSFTPServer(paramiko.SFTPServerInterface):
    def __init__(self, server):
        self.server = server
        self.fs = FS

    def _realpath(self, path):
        if not path.startswith("/"):
            path = os.path.normpath(os.path.join(self.server.current_dir, path))
        return path

    def list_folder(self, path):
        path = self._realpath(path)
        if path in self.fs and self.fs[path]["type"] == "dir":
            items = [{"filename": item, "longname": f"{self.fs[os.path.join(path, item)]['permissions']} 1 {self.fs[os.path.join(path, item)]['owner']} {self.fs[os.path.join(path, item)]['owner']} 0 {self.fs[os.path.join(path, item)]['mtime']} {item}", "attrs": paramiko.SFTPAttributes()} for item in self.fs[path]["contents"]]
            trigger_alert(self.server.session_id, "SFTP List", f"Listed {path}", self.server.client_ip, self.server.username)
            return items
        raise IOError(2, "No such file or directory")

    def stat(self, path):
        path = self._realpath(path)
        if path in self.fs:
            attrs = paramiko.SFTPAttributes()
            attrs.st_mode = (0o777 if "w" in self.fs[path]["permissions"] else 0o555) if self.fs[path]["type"] == "dir" else (0o666 if "w" in self.fs[path]["permissions"] else 0o444)
            attrs.st_size = len(str(self.fs[path].get("content", ""))) if self.fs[path].get("content") and not callable(self.fs[path].get("content")) else 0
            attrs.st_mtime = time.mktime(datetime.strptime(self.fs[path]["mtime"], "%Y-%m-%d %H:%M:%S").timetuple())
            trigger_alert(self.server.session_id, "SFTP Stat", f"Stat on {path}", self.server.client_ip, self.server.username)
            return attrs
        raise IOError(2, "No such file or directory")

    def open(self, path, flags, attr):
        path = self._realpath(path)
        if path in self.fs and self.fs[path]["type"] == "file":
            if "w" in self.fs[path]["permissions"] or self.server.username in ["admin", "root"]:
                trigger_alert(self.server.session_id, "SFTP Open", f"Opened {path} for writing", self.server.client_ip, self.server.username)
                return StringIO(str(self.fs[path].get("content", "")))
            raise IOError(13, "Permission denied")
        raise IOError(2, "No such file or directory")

    def remove(self, path):
        path = self._realpath(path)
        if path in self.fs:
            if "w" in self.fs[path]["permissions"] or self.server.username in ["admin", "root"]:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in self.fs and path.split("/")[-1] in self.fs[parent_dir]["contents"]:
                    self.fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del self.fs[path]
                save_filesystem(self.fs)
                trigger_alert(self.server.session_id, "SFTP Delete", f"Deleted {path}", self.server.client_ip, self.server.username)
                return
        raise IOError(2, "No such file or directory")

def handle_client(client_socket, client_ip, is_sftp=False):
    session_id = uuid.uuid4().int & 0xFFFFFFFF
    logger.info(f"New {'SFTP' if is_sftp else 'SSH'} connection from {client_ip}", extra={'client_ip': client_ip, 'session_id': session_id})
    trigger_alert(session_id, "New Connection", f"New {'SFTP' if is_sftp else 'SSH'} client connection from {client_ip}", client_ip, "unknown")

    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, "unknown", "", 0, 0))

        transport = paramiko.Transport(client_socket)
        server = HoneypotSSHServer()
        server.set_transport(transport)
        server.session_id = session_id
        server.client_ip = client_ip
        if is_sftp:
            transport.add_server_key(paramiko.RSAKey.from_private_key_file("key.pem"))
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, HoneypotSFTPServer, server)
        else:
            transport.add_server_key(paramiko.RSAKey.from_private_key_file("key.pem"))
            transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            logger.warning("No channel accepted", extra={'client_ip': client_ip, 'session_id': session_id})
            return

        username = server.username
        password = server.password
        current_dir = PREDEFINED_USERS.get(username, {}).get("home", "/") if username else "/"
        session_log = []
        command_history = []
        jobs = []
        cmd_count = 0

        # Prompt dynamique avec date/heure actuelles
        prompt = f"{username}@{socket.gethostname().split('.')[0]}:{current_dir} 11:43 PM CEST, Sat Jun 14, 2025$ ".encode() if username else b"guest@honeypot:/ 11:43 PM CEST, Sat Jun 14, 2025$ "

        while True:
            cmd, current_dir, jobs, cmd_count, exit_flag = read_line_advanced(chan, prompt, command_history, current_dir, username, FS, session_log, session_id, client_ip, jobs, cmd_count, transport)
            if exit_flag:
                break
        else:  # SFTP handling
            transport.accept(20)  # Keep SFTP connection alive
            # SFTP operations are handled by HoneypotSFTPServer
    except Exception as e:
        logger.error(f"Error in handle_client: {e}", extra={'client_ip': client_ip, 'session_id': session_id})
    finally:
        with _connection_lock:
            if client_ip in _connection_count:
                _connection_count[client_ip] -= 1
        if chan:
            chan.close()
        if transport:
            transport.close()
        client_socket.close()
        logger.info(f"{'SFTP' if is_sftp else 'SSH'} session ended for {client_ip}", extra={'client_ip': client_ip, 'session_id': session_id})

def start_server():
    global FS
    init_database()
    init_filesystem_db()
    FS = load_filesystem() or BASE_FILE_SYSTEM
    FS = populate_predefined_users(FS)
    add_vulnerabilities(FS)
    save_filesystem(FS)

    ssh_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssh_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssh_server.bind((HOST, PORT))
    ssh_server.listen(5)
    logger.info(f"SSH Honeypot listening on {HOST}:{PORT}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

    sftp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sftp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sftp_server.bind((HOST, SFTP_PORT))
    sftp_server.listen(5)
    logger.info(f"SFTP Honeypot listening on {HOST}:{SFTP_PORT}", extra={'client_ip': 'N/A', 'session_id': 'N/A'})

    # Start background threads
    threading.Thread(target=cleanup_bruteforce_attempts, daemon=True).start()
    threading.Thread(target=cleanup_trap_files, daemon=True).start()
    threading.Thread(target=schedule_reports, daemon=True).start()

    # Accept connections
    while True:
        client_socket, addr = ssh_server.accept()
        client_ip = addr[0]
        with _connection_lock:
            _connection_count[client_ip] = _connection_count.get(client_ip, 0) + 1
            if _connection_count[client_ip] > CONNECTION_LIMIT_PER_IP:
                client_socket.close()
                trigger_alert(None, "Connection Limit Exceeded", f"IP {client_ip} exceeded connection limit", client_ip, "unknown")
                continue
        threading.Thread(target=handle_client, args=(client_socket, client_ip, False), daemon=True).start()

        client_socket, addr = sftp_server.accept()
        client_ip = addr[0]
        with _connection_lock:
            _connection_count[client_ip] = _connection_count.get(client_ip, 0) + 1
            if _connection_count[client_ip] > CONNECTION_LIMIT_PER_IP:
                client_socket.close()
                trigger_alert(None, "Connection Limit Exceeded", f"IP {client_ip} exceeded connection limit", client_ip, "unknown")
                continue
        threading.Thread(target=handle_client, args=(client_socket, client_ip, True), daemon=True).start()

if __name__ == "__main__":
    start_server()
