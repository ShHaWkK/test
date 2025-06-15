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
import ipapi
from io import StringIO

# Désactivation des logs dans les fichiers (géré en mémoire via alertes)
# Configuration
HOST = ""  # Écoute sur toutes les interfaces
PORT = 2224  # Port personnalisé
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = ":memory:"  # Base en mémoire
FS_DB = ":memory:"    # Base en mémoire pour le système de fichiers
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes
CMD_LIMIT_PER_SESSION = 50
CONNECTION_LIMIT_PER_IP = 10
_brute_force_attempts = {}  # {ip: [(timestamp, username, password)]}
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()
_connection_count = {}  # {ip: count}
_connection_lock = threading.Lock()

SESSION_LOG_DIR = None  # Désactivé car pas de logs fichiers

FAKE_SERVICES = {
    "ftp": 21,
    "http": 80,
    "mysql": 3306,
    "telnet": 23,
}

# Identifiants SMTP via variables d'environnement
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "honeycute896@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "jawm fmcm dmaf qkyl")
ALERT_FROM = SMTP_USER
ALERT_TO = os.getenv("ALERT_TO", "alexandreuzan75@gmail.com")
PREDEFINED_USERS = {
    "admin": {
        "home": "/home/admin",
        "password": hashlib.sha256("admin123".encode()).hexdigest(),
        "files": {
            "credentials.txt": "admin:supersecret\n# Internal use only",
            "sshkey": "ssh-rsa AAAAB3NzaC1yc2E...admin_key",
            "project_config": "projectA: sensitive data...",
            "backup_pass.txt": "root:admin123\nbackup:backup456"
        },
        "uid": 1000,
        "groups": ["admin", "sudo"]
    },
    "devops": {
        "home": "/home/devops",
        "password": hashlib.sha256("devops456".encode()).hexdigest(),
        "files": {
            "deploy_key": "ssh-rsa AAAAB3NzaC1yc2E...devops_key",
            "jenkins.yml": "jenkins: {url: http://localhost:8080, user: admin, pass: admin123}",
            ".bashrc": "alias ll='ls -la'\nexport PATH=$PATH:/usr/local/bin"
        },
        "uid": 1001,
        "groups": ["devops"]
    },
    "dbadmin": {
        "home": "/home/dbadmin",
        "password": hashlib.sha256("dbadmin789".encode()).hexdigest(),
        "files": {
            "backup.sql": "-- SQL dump\nDROP TABLE IF EXISTS users;",
            "scripts.sh": "#!/bin/bash\necho 'DB maintenance...'",
            "mysql_creds.txt": "mysql_user:root\nmysql_pass:password123"
        },
        "uid": 1002,
        "groups": ["dbadmin"]
    },
    "mysql": {
        "home": "/var/lib/mysql",
        "password": hashlib.sha256("mysql123".encode()).hexdigest(),
        "files": {},
        "uid": 110,
        "groups": ["mysql"]
    },
    "www-data": {
        "home": "/var/www",
        "password": hashlib.sha256("wwwdata123".encode()).hexdigest(),
        "files": {
            "config.php": "<?php define('DB_PASS', 'weakpass123'); ?>"
        },
        "uid": 33,
        "groups": ["www-data"]
    }
}

KEYSTROKES_LOG = None  # Désactivé
FILE_TRANSFER_LOG = None  # Désactivé
SENSITIVE_FILES = [
    "/home/admin/credentials.txt",
    "/home/admin/backup_pass.txt",
    "/home/dbadmin/mysql_creds.txt",
    "/var/www/config.php",
    "/tmp/suspicious.sh"
]

FAKE_NETWORK_HOSTS = {
    "192.168.1.10": {"name": "webserver.local", "services": ["http", "https"]},
    "192.168.1.20": {"name": "dbserver.local", "services": ["mysql"]},
    "192.168.1.30": {"name": "backup.local", "services": ["ftp"]}
}

COMMAND_OPTIONS = {
    "ls": ["-l", "-a", "-la", "-lh", "--help"],
    "cat": ["-n", "--help"],
    "grep": ["-i", "-r", "-n", "--help"],
    "find": ["-name", "-type", "-exec", "--help"],
    "chmod": ["-R", "+x", "755", "644", "--help"],
    "chown": ["-R", "--help"],
    "service": ["start", "stop", "status", "restart"],
    "systemctl": ["start", "stop", "status", "restart", "enable", "disable"],
    "ip": ["addr", "link", "route"],
    "apt-get": ["update", "upgrade", "install", "remove"],
    "scp": ["-r", "-P"],
    "curl": ["-O", "-L", "--help"],
    "wget": ["-O", "-q", "--help"],
    "telnet": [],
    "ping": ["-c", "-i"],
    "nmap": ["-sS", "-sV"]
}

# Colored prompt helper
def color_prompt(username, client_ip, current_dir):
    return (
        f"\033[1;32m{username}@{client_ip}\033[0m:"
        f"\033[1;34m{current_dir}\033[0m$ "
    )

# Données dynamiques
@lru_cache(maxsize=10)
def get_dynamic_df():
    sizes = {"sda1": "50G", "tmpfs": "100M"}
    used = {"sda1": f"{random.randint(5, 10)}G", "tmpfs": "0M"}
    avail = {"sda1": f"{random.randint(30, 45)}G", "tmpfs": "100M"}
    usep = {"sda1": f"{random.randint(10, 20)}%", "tmpfs": "0%"}
    return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        {sizes['sda1']}   {used['sda1']}   {avail['sda1']}  {usep['sda1']} /
tmpfs           {sizes['tmpfs']}     {used['tmpfs']}  {avail['tmpfs']}   {usep['tmpfs']} /tmp"""

@lru_cache(maxsize=10)
def get_dynamic_uptime():
    now = datetime.now().strftime("%H:%M:%S")
    days = random.randint(3, 10)
    hours = random.randint(0, 23)
    minutes = random.randint(0, 59)
    users = random.randint(1, 5)
    la1, la2, la3 = [f"{random.uniform(0.00, 1.00):.2f}" for _ in range(3)]
    return f"{now} up {days} days, {hours}:{minutes:02d}, {users} user{'s' if users > 1 else ''}, load average: {la1}, {la2}, {la3}"

@lru_cache(maxsize=10)
def get_dynamic_ps():
    processes = [
        ("root", "1", "/sbin/init"),
        ("root", "135", "/usr/sbin/sshd -D"),
        ("mysql", "220", "/usr/sbin/mysqld"),
        ("www-data", "300", "/usr/sbin/nginx -g 'daemon off;'"),
        ("admin", str(random.randint(1000, 5000)), "/bin/bash"),
        ("devops", str(random.randint(1000, 5000)), "/usr/bin/python3 app.py"),
        ("dbadmin", str(random.randint(1000, 5000)), "/bin/sh scripts.sh")
    ]
    if random.random() < 0.3:
        processes.append(("root", str(random.randint(6000, 7000)), "/usr/bin/find / -name '*.log'"))
    lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND"]
    for user, pid, cmd in processes:
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        vsz = random.randint(10000, 50000)
        rss = random.randint(1000, 5000)
        tty = random.choice(["pts/0", "pts/1", "?", "tty7"])
        stat = random.choice(["Ss", "S+", "R"])
        start = (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime("%H:%M")
        time_str = f"{random.randint(0, 2)}:{random.randint(0, 59):02d}"
        lines.append(f"{user:<10} {pid:<6} {cpu:<5} {mem:<5} {vsz:<7} {rss:<6} {tty:<6} {stat:<5} {start:<8} {time_str:<6} {cmd}")
    return "\r\n".join(lines)

def get_dynamic_top():
    header = "top - %s up %d days, %02d:%02d, %d user%s, load average: %.2f, %.2f, %.2f\n" % (
        datetime.now().strftime("%H:%M:%S"), random.randint(3, 10), random.randint(0, 23),
        random.randint(0, 59), random.randint(1, 5), "s" if random.randint(1, 5) > 1 else "",
        random.uniform(0.0, 1.0), random.uniform(0.0, 1.0), random.uniform(0.0, 1.0)
    )
    tasks = "Tasks: %d total, %d running, %d sleeping, %d stopped, %d zombie\n" % (
        random.randint(50, 100), random.randint(1, 5), random.randint(40, 80), 0, 0
    )
    cpu = "%%Cpu(s): %.1f us, %.1f sy, %.1f ni, %.1f id, %.1f wa, %.1f hi, %.1f si, %.1f st\n" % (
        random.uniform(0, 10), random.uniform(0, 5), 0, random.uniform(80, 90),
        random.uniform(0, 2), random.uniform(0, 1), random.uniform(0, 1), 0
    )
    mem = "MiB Mem : %d total, %d free, %d used, %d buff/cache\n" % (
        random.randint(16000, 32000), random.randint(1000, 5000), random.randint(5000, 10000),
        random.randint(1000, 5000)
    )
    processes = get_dynamic_ps().split("\n")[1:]
    return header + tasks + cpu + mem + "\n" + "\n".join(processes[:5])

@lru_cache(maxsize=10)
def get_dynamic_netstat():
    lines = ["Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"]
    for _ in range(random.randint(2, 6)):
        local_ip = f"192.168.1.{random.randint(2, 254)}"
        local_port = random.choice([22, 80, 443, 3306, 8080])
        foreign_ip = f"10.0.0.{random.randint(2, 254)}"
        foreign_port = random.randint(1024, 65535)
        state = random.choice(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "LISTEN"])
        pid_prog = f"{random.randint(100, 999)}/app{random.randint(1, 5)}"
        lines.append(f"tcp        {random.randint(0, 10)}      {random.randint(0, 10)} {local_ip}:{local_port}  {foreign_ip}:{foreign_port}  {state:<10} {pid_prog}")
    return "\r\n".join(lines)

@lru_cache(maxsize=10)
def get_dynamic_messages():
    lines = []
    for _ in range(10):
        timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).strftime("%b %d %H:%M:%S")
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        service = random.choice(["sshd", "systemd", "cron", "nginx", "apache2", "mysqld"])
        message = random.choice([
            f"{service}[{random.randint(1000, 9999)}]: Started {service} service.",
            f"{service}: Connection from {src_ip}",
            f"{service}: Configuration loaded successfully.",
            f"{service}: Warning: High CPU usage detected.",
            f"{service}: Failed login attempt from {src_ip}",
            f"{service}: Suspicious activity on port {random.randint(1024, 65535)}"
        ])
        lines.append(f"{timestamp} debian {message}")
    return "\n".join(lines)

@lru_cache(maxsize=10)
def get_dynamic_dmesg():
    lines = []
    for _ in range(10):
        timestamp = f"[{random.uniform(0, 1000):.6f}]"
        message = random.choice([
            "kernel: [CPU0] microcode updated early to revision 0xca",
            "kernel: random: crng init done",
            "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
            "kernel: ACPI: Power Button [PWRB]"
        ])
        lines.append(f"{timestamp} {message}")
    return "\n".join(lines)

@lru_cache(maxsize=10)
def get_dynamic_network_scan():
    lines = []
    for ip, info in FAKE_NETWORK_HOSTS.items():
        for service in info["services"]:
            port = FAKE_SERVICES.get(service, 0)
            if port:
                lines.append(f"{ip}:{port} open {service}")
    return "\n".join(lines)

@lru_cache(maxsize=10)
def get_dynamic_arp():
    lines = ["Address                  HWtype  HWaddress           Flags Mask            Iface"]
    for ip in FAKE_NETWORK_HOSTS:
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        lines.append(f"{ip:<24} ether   {mac}   C                     eth0")
    return "\n".join(lines)

@lru_cache(maxsize=10)
def get_dynamic_who():
    lines = []
    users = ["admin", "devops", "dbadmin"] + [f"temp_{''.join(random.choices(string.ascii_lowercase, k=6))}" for _ in range(random.randint(0, 3))]
    for user in users:
        timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M")
        tty = random.choice(["pts/0", "pts/1", "tty7"])
        host = f"192.168.1.{random.randint(10, 50)}"
        lines.append(f"{user:<10} {tty:<8} {timestamp} {host}")
    return "\n".join(lines)

def get_dev_null(): return ""
def get_dev_zero(): return "\0" * 1024

# Gestion du système de fichiers
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
            print("[*] Filesystem database initialized successfully")
    except sqlite3.Error as e:
        print(f"[!] Filesystem DB init error: {e}")
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
        print(f"[!] Filesystem load error: {e}")
    return fs

def save_filesystem(fs):
    try:
        with sqlite3.connect(FS_DB) as conn:
            conn.execute("DELETE FROM filesystem")  # Efface et réinsère pour simplicité
            for path, data in fs.items():
                conn.execute(
                    "INSERT INTO filesystem (path, type, content, owner, permissions, mtime) VALUES (?, ?, ?, ?, ?, ?)",
                    (path, data["type"], data.get("content", "") if not callable(data.get("content")) else "", data.get("owner", "root"), data.get("permissions", "rw-r--r--"), data.get("mtime", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                )
    except sqlite3.Error as e:
        print(f"[!] Filesystem save error: {e}")

BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["bin", "sbin", "usr", "var", "opt", "root", "home", "etc", "tmp", "proc", "dev", "sys", "lib"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/bin": {"type": "dir", "contents": ["bash", "ls", "cat", "grep", "chmod", "chown", "mv", "cp", "top", "ifconfig", "ip", "find", "scp", "apt-get", "curl", "wget", "telnet", "ping", "nmap", "who", "w"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/sbin": {"type": "dir", "contents": ["init", "sshd", "iptables", "reboot"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var": {"type": "dir", "contents": ["log", "www"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log": {"type": "dir", "contents": ["syslog", "messages", "auth.log"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/syslog": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/messages": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/log/auth.log": {"type": "file", "content": get_dynamic_messages, "owner": "root", "permissions": "rw-r-----", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www": {"type": "dir", "contents": ["html"], "owner": "www-data", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html": {"type": "dir", "contents": ["index.html", "config.php"], "owner": "www-data", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/var/www/html/index.html": {"type": "file", "content": "<html><body><h1>Welcome to Server</h1></body></html>", "owner": "www-data", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/tmp": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxrwxrwt", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/etc": {"type": "dir", "contents": ["passwd", "shadow", "group"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/etc/passwd": {"type": "file", "content": "\n".join(f"{user}:x:{info['uid']}:1000::{info['home']}:/bin/bash" for user, info in PREDEFINED_USERS.items() if info.get("home", "").startswith("/home")), "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/etc/shadow": {"type": "file", "content": "\n".join(f"{user}:$6$...:18264:0:99999:7:::" for user in PREDEFINED_USERS if user not in ["mysql", "www-data"]), "owner": "root", "permissions": "rw-r-----", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/etc/group": {"type": "file", "content": "\n".join(f"{group}:x:{1000+i}:" for i, group in enumerate(set(group for user in PREDEFINED_USERS.values() for group in user.get("groups", [])))), "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/proc": {"type": "dir", "contents": ["cpuinfo", "meminfo"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/proc/cpuinfo": {"type": "file", "content": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/proc/meminfo": {"type": "file", "content": f"MemTotal:       {random.randint(16000, 32000)} kB\nMemFree:        {random.randint(1000, 5000)} kB", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev": {"type": "dir", "contents": ["null", "zero"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev/null": {"type": "file", "content": get_dev_null, "owner": "root", "permissions": "rw-rw-rw-", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/dev/zero": {"type": "file", "content": get_dev_zero, "owner": "root", "permissions": "rw-rw-rw-", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
}

def populate_predefined_users(fs):
    if "/home" not in fs:
        fs["/home"] = {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    for user, info in PREDEFINED_USERS.items():
        home_dir = info["home"]
        fs[home_dir] = {"type": "dir", "contents": list(info["files"].keys()), "owner": user, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if user not in fs["/home"]["contents"] and home_dir.startswith("/home/"):
            fs["/home"]["contents"].append(user)
        for filename, content in info["files"].items():
            fs[f"{home_dir}/{filename}"] = {"type": "file", "content": content, "owner": user, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    return fs

def add_vulnerabilities(fs):
    fs["/tmp/suspicious.sh"] = {"type": "file", "content": "#!/bin/bash\necho 'Running script...'\ncurl http://example.com", "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    fs["/tmp"]["contents"].append("suspicious.sh")
    fs["/home/admin/backup_pass.txt"] = {"type": "file", "content": "root:admin123\nbackup_user:backup456", "owner": "admin", "permissions": "rw-rw-r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    fs["/home/admin"]["contents"].append("backup_pass.txt")

init_filesystem_db()
FS = load_filesystem()
if not FS:
    FS = populate_predefined_users(BASE_FILE_SYSTEM.copy())
    add_vulnerabilities(FS)
    save_filesystem(FS)

# Autocomplétion
def get_completions(current_input, current_dir, username, fs, history):
    base_cmds = list(COMMAND_OPTIONS.keys()) + ["whoami", "id", "uname", "pwd", "exit", "history", "sudo", "su", "curl", "wget", "telnet", "ping", "nmap", "arp", "scp", "sftp", "who", "w", "touch", "rm", "mkdir", "rmdir", "cp", "mv", "vim", "nano", "backup_data", "systemctl", "fg", "app_status", "status_report", "jobs"]
    if not current_input.strip():
        return sorted(base_cmds)
    parts = current_input.strip().split()
    cmd = parts[0] if parts else ""
    partial = parts[-1] if parts else ""
    prev_parts = parts[:-1] if len(parts) > 1 else []
    completions = []
    if len(parts) == 1 and not current_input.endswith(" "):
        completions = [c for c in base_cmds if c.startswith(partial)]
        return sorted(completions)
    if cmd in COMMAND_OPTIONS and (partial.startswith("-") or prev_parts and prev_parts[-1].startswith("-")):
        completions = [opt for opt in COMMAND_OPTIONS[cmd] if opt.startswith(partial)]
        return sorted(completions)
    if cmd in ["cd", "ls", "cat", "rm", "scp", "find", "grep", "touch", "mkdir", "rmdir", "cp", "mv"]:
        path = partial if partial.startswith("/") else f"{current_dir}/{partial}" if current_dir != "/" else f"/{partial}"
        path = os.path.normpath(path)
        parent_dir = os.path.dirname(path) or "/"
        base_name = os.path.basename(path) or ""
        if parent_dir in fs and fs[parent_dir]["type"] == "dir" and "contents" in fs[parent_dir]:
            for item in fs[parent_dir]["contents"]:
                full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                if full_path in fs and item.startswith(base_name):
                    if cmd == "cd" and fs[full_path]["type"] == "dir":
                        completions.append(item)
                    elif cmd in ["ls", "cat", "rm", "scp", "find", "grep", "touch", "mkdir", "rmdir", "cp", "mv"]:
                        completions.append(item)
        return sorted([f"{partial.rsplit('/', 1)[0]}/{c}" if partial.rsplit('/', 1)[0] else c for c in completions])
    if cmd in ["ping", "telnet", "nmap", "scp", "curl", "wget"]:
        for ip, info in FAKE_NETWORK_HOSTS.items():
            if info["name"].startswith(partial) or ip.startswith(partial):
                completions.append(info["name"])
                completions.append(ip)
    completions.extend([h for h in history[-10:] if h.startswith(partial)])
    return sorted(completions)

def autocomplete(current_input, current_dir, username, fs, chan, history):
    completions = get_completions(current_input, current_dir, username, fs, history)
    if len(completions) == 1:
        parts = current_input.split()
        if len(parts) <= 1:
            return completions[0]
        parts[-1] = completions[0]
        return " ".join(parts)
    elif completions:
        chan.send(b"\r\n" + "\r\n".join(c.encode() for c in completions[:10]) + b"\r\n")
        return current_input
    return current_input

# Gestion des fichiers
def modify_file(fs, path, content, username, session_id, client_ip):
    allowed_paths = [f"{PREDEFINED_USERS[username]['home']}/{f}" for f in PREDEFINED_USERS.get(username, {}).get("files", {}).keys()]
    if path.startswith("/tmp/") or path in allowed_paths:
        fs[path] = {"type": "file", "content": content, "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        trigger_alert(session_id, "File Modified", f"Modified file: {path}", client_ip, username)
        save_filesystem(fs)
        return True
    return False

# Alertes (remplace les logs)
def trigger_alert(session_id, event_type, details, client_ip, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    geo_info = "Unknown"
    try:
        geo_data = ipapi.location(client_ip)
        geo_info = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
    except Exception:
        pass
    details = f"{details} (Geo: {geo_info})"
    print(f"[ALERT] {timestamp} - {client_ip} ({username}) : {event_type} - {details}")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            msg = MIMEText(f"Time: {timestamp}\nIP: {client_ip}\nUser: {username}\nEvent: {event_type}\nDetails: {details}")
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = f"Security Alert - {event_type}"
            smtp.send_message(msg)
    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {str(e)}")
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                "INSERT INTO events (timestamp, ip, username, event_type, details) VALUES (?, ?, ?, ?, ?)",
                (timestamp, client_ip, username, event_type, details)
            )
    except sqlite3.Error as e:
        print(f"[!] DB error: {e}")

def log_activity(session_id, client_ip, username, key):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[ACTIVITY] {timestamp},{session_id},{client_ip},{username},{key}")

def log_session_activity(session_id, client_ip, username, command_line, output):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[SESSION] {timestamp}|{client_ip}|{username}|{command_line}|{output}")

# Détection de bruteforce
def check_bruteforce(client_ip, username, password):
    timestamp = time.time()
    with _brute_force_lock:
        if client_ip not in _brute_force_attempts:
            _brute_force_attempts[client_ip] = []
        _brute_force_attempts[client_ip].append((timestamp, username, password))
        _brute_force_attempts[client_ip] = [attempt for attempt in _brute_force_attempts[client_ip] if timestamp - attempt[0] < BRUTE_FORCE_WINDOW]
        if len(_brute_force_attempts[client_ip]) > BRUTE_FORCE_THRESHOLD:
            if client_ip not in _brute_force_alerted:
                trigger_alert(-1, "Bruteforce Detected", f"Multiple login attempts from {client_ip}", client_ip, "unknown")
                _brute_force_alerted.add(client_ip)
            return False
    return True

def cleanup_bruteforce_attempts():
    while True:
        with _brute_force_lock:
            current_time = time.time()
            for ip in list(_brute_force_attempts.keys()):
                _brute_force_attempts[ip] = [attempt for attempt in _brute_force_attempts[ip] if current_time - attempt[0] < BRUTE_FORCE_WINDOW]
                if not _brute_force_attempts[ip]:
                    del _brute_force_attempts[ip]
                    _brute_force_alerted.discard(ip)
        time.sleep(3600)

# Détection des scans de ports
def detect_port_scan(ip, port):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE ip = ? AND event_type LIKE '%Connection' AND timestamp > ?",
                (ip, (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))
            )
            count = cur.fetchone()[0]
            if count >= 3:
                trigger_alert(-1, "Port Scan Detected", f"Potential scan from {ip} on port {port}", ip, "unknown")
    except sqlite3.Error as e:
        print(f"[!] Port scan detection error: {e}")

# Gestion de l'historique
def load_history(username):
    return []  # Pas de fichier, donc vide par défaut

def save_history(username, history):
    pass  # Pas de sauvegarde dans un fichier

# Initialisation de la base de données
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
                )
            """)
            print("[*] Database initialized successfully")
    except sqlite3.Error as e:
        print(f"[!] DB init error: {e}")
        raise

# Rapports
def generate_report(period):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"System Activity Report - {period}", 0, 1, "C")
    pdf.set_font("Arial", size=12)
    start_time = (datetime.now() - timedelta(minutes=15 if period == "15min" else 60 if period == "hourly" else 10080)).strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Period: {start_time} to {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,))
            login_count = cur.fetchone()[0]
            pdf.cell(0, 10, f"Total Login Attempts: {login_count}", 0, 1)
            cur.execute(
                "SELECT ip, COUNT(*) as count FROM login_attempts WHERE timestamp > ? GROUP BY ip ORDER BY count DESC LIMIT 5",
                (start_time,)
            )
            for ip, count in cur.fetchall():
                pdf.cell(0, 10, f"IP: {ip} - {count} attempts", 0, 1)
            cur.execute(
                "SELECT command, COUNT(*) as count FROM commands WHERE timestamp > ? GROUP BY command ORDER BY count DESC LIMIT 5",
                (start_time,)
            )
            for cmd, count in cur.fetchall():
                pdf.cell(0, 10, f"Command: {cmd} - {count} executions", 0, 1)
            cur.execute(
                "SELECT timestamp, ip, username, event_type, details FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 10",
                (start_time,)
            )
            for timestamp, ip, username, event_type, details in cur.fetchall():
                pdf.cell(0, 10, f"{timestamp} - {ip} ({username}): {event_type} - {details}", 0, 1)
    except sqlite3.Error as e:
        print(f"[!] Report error: {e}")
    report_filename = f"{period}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    return report_filename

def send_weekly_report():
    while True:
        now = datetime.now()
        if now.weekday() == 0 and now.hour == 8:
            report_filename = generate_report("weekly")
            subject = f"Weekly System Report - {datetime.now().strftime('%Y-%m-%d')}"
            body = "Attached is the weekly system activity report."
            msg = MIMEMultipart()
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            with open(report_filename, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(report_filename))
                part["Content-Disposition"] = f'attachment; filename="{os.path.basename(report_filename)}"'
                msg.attach(part)
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASS)
                    smtp.send_message(msg)
                print(f"Weekly report sent: {report_filename}")
            except Exception as e:
                print(f"Weekly report email error: {e}")
            finally:
                if os.path.exists(report_filename):
                    os.remove(report_filename)
        time.sleep(3600)

def send_periodic_report():
    while True:
        time.sleep(900)
        report_filename = generate_report("15min")
        body = f"15-Minute Activity Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        trigger_alert(-1, "15min Activity Report", body, "system", "system")
        if os.path.exists(report_filename):
            os.remove(report_filename)

# Nettoyage des fichiers pièges
def cleanup_trap_files(fs):
    while True:
        current_time = time.time()
        for path in list(fs.keys()):
            if ".trap_" in path and fs[path].get("expires", current_time) < current_time:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs and path.split("/")[-1] in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
        time.sleep(3600)

# Traitement des commandes
def process_command(cmd, current_dir, username, fs, client_ip, session_id, session_log, command_history, chan, jobs=None, cmd_count=0):
    if not cmd.strip():
        return "", current_dir, jobs or [], cmd_count
    new_dir = current_dir
    output = ""
    cmd_parts = cmd.strip().split()
    cmd_name = cmd_parts[0].lower()
    arg_str = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
    jobs = jobs or []
    session_log.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {username}@{client_ip}: {cmd}")
    log_session_activity(session_id, client_ip, username, cmd, output)
    command_seq = " ".join(command_history[-5:] + [cmd])
    malicious_patterns = {"rm -rf /": 10, "rm -rf": 8, "wget": 3, "curl": 3, "format": 7, "reboot": 4, "nc -l": 8, "exploit_db": 8, "metasploit": 8, "reverse_shell": 8, "whoami.*sudo": 6}
    risk_score = sum(malicious_patterns.get(pattern, 0) for pattern in malicious_patterns if pattern in command_seq.lower())
    if risk_score > 5:
        trigger_alert(session_id, "High Risk Command", f"Command sequence '{command_seq}' scored {risk_score} risk points", client_ip, username)
    if cmd_name in ["ls", "dir"]:
        path = arg_str if arg_str else current_dir
        path = os.path.normpath(path if path.startswith("/") else f"{current_dir}/{path}")
        if path in fs and fs[path]["type"] == "dir" and "contents" in fs[path]:
            if "-l" in cmd_parts:
                lines = []
                for item in fs[path]["contents"]:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    if full_path in fs:
                        item_type = "d" if fs[full_path]["type"] == "dir" else "-"
                        perms = fs[full_path].get("permissions", "rw-r--r--")
                        size = len(fs[full_path].get("content", "") if fs[full_path]["type"] == "file" and not callable(fs[full_path]["content"]) else "") if fs[full_path]["type"] == "file" else 0
                        mod_time = fs[full_path].get("mtime", datetime.now().strftime("%b %d %H:%M"))
                        lines.append(f"{item_type}{perms}  1 {fs[full_path].get('owner', username)} {username} {size:>8} {mod_time} {item}")
                output = "\n".join(lines)
            else:
                if random.random() < 0.3:
                    trap_file = f".trap_{random.randint(1, 1000)}.txt"
                    if trap_file not in fs[path]["contents"]:
                        fs[path]["contents"].append(trap_file)
                        fs[f"{path}/{trap_file}"] = {"type": "file", "content": f"Data {random.randint(1, 1000)}", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "expires": time.time() + 3600}
                        trigger_alert(session_id, "Trap Triggered", f"User {username} triggered trap {trap_file} in {path}", client_ip, username)
                output = " ".join(f for f in fs[path]["contents"] if not f.startswith(".trap_") or fs.get(f"{path}/{f}", {}).get("expires", 0) > time.time())
        else:
            output = f"ls: cannot access '{arg_str}': No such file or directory"
    elif cmd_name == "cd":
        path = arg_str if arg_str else f"/home/{username}"
        if path.startswith("~"):
            path = path.replace("~", f"/home/{username}", 1)
        path = os.path.normpath(path if path.startswith("/") else f"{current_dir}/{path}")
        if path in fs and fs[path]["type"] == "dir":
            new_dir = path
        else:
            output = f"cd: {arg_str}: No such file or directory"
    elif cmd_name == "cat":
        if not arg_str:
            output = "cat: missing operand"
        else:
            path = arg_str
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
            path = os.path.normpath(path)
            if path in SENSITIVE_FILES:
                trigger_alert(session_id, "Sensitive File Access", f"Accessed file: {path}", client_ip, username)
            if path == "/etc/shadow" and username != "root":
                output = "cat: /etc/shadow: Permission denied"
                trigger_alert(session_id, "Permission Denied", f"Attempted to access /etc/shadow", client_ip, username)
            elif path in fs and fs[path]["type"] == "file":
                content = fs[path]["content"]() if callable(fs[path]["content"]) else fs[path]["content"]
                output = content
                trigger_alert(session_id, "File Access", f"Read file: {path}", client_ip, username)
            else:
                output = f"cat: {arg_str}: No such file or directory"
    elif cmd_name == "rm":
        if not arg_str:
            output = "rm: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "file":
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if "-r" in cmd_parts and fs[path]["type"] == "dir":
                    trigger_alert(session_id, "Recursive Delete Attempt", f"Attempted rm -r on {path}", client_ip, username)
                if parent_dir in fs and "contents" in fs[parent_dir] and path.split("/")[-1] in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "File Deleted", f"Removed file: {path}", client_ip, username)
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
    elif cmd_name == "mkdir":
        if not arg_str:
            output = "mkdir: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
            path = os.path.normpath(path)
            if path not in fs:
                fs[path] = {"type": "dir", "contents": [], "owner": username, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs and "contents" in fs[parent_dir]:
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "Directory Created", f"Created directory {path}", client_ip, username)
            else:
                output = f"mkdir: cannot create directory '{arg_str}': File exists"
    elif cmd_name == "rmdir":
        if not arg_str:
            output = "rmdir: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "dir" and not fs[path]["contents"]:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs and "contents" in fs[parent_dir] and path.split("/")[-1] in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "Directory Removed", f"Removed directory: {path}", client_ip, username)
            else:
                output = f"rmdir: failed to remove '{arg_str}': Directory not empty or does not exist"
    elif cmd_name in ["cp", "mv"]:
        if len(cmd_parts) >= 3:
            src = os.path.normpath(cmd_parts[1] if cmd_parts[1].startswith("/") else f"{current_dir}/{cmd_parts[1]}")
            dst = os.path.normpath(cmd_parts[2] if cmd_parts[2].startswith("/") else f"{current_dir}/{cmd_parts[2]}")
            if src in fs and fs[src]["type"] == "file":
                fs[dst] = fs[src].copy()
                fs[dst]["owner"] = username
                fs[dst]["mtime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                parent_dir = "/".join(dst.split("/")[:-1]) or "/"
                if parent_dir in fs and "contents" in fs[parent_dir] and dst.split("/")[-1] not in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].append(dst.split("/")[-1])
                if cmd_name == "mv":
                    parent_src_dir = "/".join(src.split("/")[:-1]) or "/"
                    if parent_src_dir in fs and "contents" in fs[parent_src_dir] and src.split("/")[-1] in fs[parent_src_dir]["contents"]:
                        fs[parent_src_dir]["contents"].remove(src.split("/")[-1])
                    del fs[src]
                save_filesystem(fs)
                output = f"{cmd_name}: {'copied' if cmd_name == 'cp' else 'moved'} '{src}' to '{dst}'"
                trigger_alert(session_id, f"File {cmd_name.upper()}", f"{'Copied' if cmd_name == 'cp' else 'Moved'} file: {src} to {dst}", client_ip, username)
            else:
                output = f"{cmd_name}: cannot stat '{cmd_parts[1]}': No such file or directory"
        else:
            output = f"{cmd_name}: missing file operand"
    elif cmd_name == "chmod":
        if len(cmd_parts) >= 3 and cmd_parts[1] in ["+x", "-w", "755", "644"]:
            path = os.path.normpath(cmd_parts[2] if cmd_parts[2].startswith("/") else f"{current_dir}/{cmd_parts[2]}")
            if path in fs:
                fs[path]["permissions"] = cmd_parts[1] if cmd_parts[1] in ["+x", "-w"] else ("rwxr-xr-x" if cmd_parts[1] == "755" else "rw-r--r--")
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "Permission Change", f"Changed permissions of {path} to {cmd_parts[1]}", client_ip, username)
            else:
                output = f"chmod: cannot access '{cmd_parts[2]}': No such file or directory"
        else:
            output = "chmod: invalid syntax or missing operand"
    elif cmd_name == "chown":
        if len(cmd_parts) >= 3 and cmd_parts[1] in PREDEFINED_USERS:
            path = os.path.normpath(cmd_parts[2] if cmd_parts[2].startswith("/") else f"{current_dir}/{cmd_parts[2]}")
            if path in fs:
                fs[path]["owner"] = cmd_parts[1]
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "Owner Change", f"Changed owner of {path} to {cmd_parts[1]}", client_ip, username)
            else:
                output = f"chown: cannot access '{cmd_parts[2]}': No such file or directory"
        else:
            output = "chown: invalid user or missing operand"
    elif cmd_name == "kill":
        if arg_str:
            output = f"kill: process {arg_str} terminated (simulated)"
            trigger_alert(session_id, "Process Kill", f"Attempted to kill process {arg_str}", client_ip, username)
        else:
            output = "kill: usage: kill -9 <pid>"
    elif cmd_name == "ping":
        if not arg_str:
            output = "ping: missing host operand"
        else:
            host = arg_str.split()[0]
            if host in [h["name"] for h in FAKE_NETWORK_HOSTS.values()] or host in FAKE_NETWORK_HOSTS:
                output = f"PING {host} (192.168.1.x) 56(84) bytes of data.\n"
                for _ in range(4):
                    output += f"64 bytes from {host}: icmp_seq={_ + 1} ttl=64 time={random.uniform(0.1, 2.0):.2f} ms\n"
                output += f"\n--- {host} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss"
            else:
                output = f"ping: {host}: Name or service not known"
            trigger_alert(session_id, "Network Command", f"Pinged host: {host}", client_ip, username)
    elif cmd_name == "nmap":
        if not arg_str:
            output = "nmap: missing target"
        else:
            output = get_dynamic_network_scan()
            trigger_alert(session_id, "Network Scan", f"Executed nmap with args: {arg_str}", client_ip, username)
    elif cmd_name == "arp":
        output = get_dynamic_arp()
        trigger_alert(session_id, "Command Executed", "Displayed ARP table", client_ip, username)
    elif cmd_name == "curl" or cmd_name == "wget":
        if not arg_str:
            output = f"{cmd_name}: missing URL"
        else:
            output = f"{cmd_name}: downloaded data from {arg_str} (simulated)"
            trigger_alert(session_id, "Network Download Attempt", f"Attempted {cmd_name}: {arg_str}", client_ip, username)
    elif cmd_name == "telnet":
        if not arg_str:
            output = "telnet: missing host"
        else:
            host = arg_str.split()[0]
            output = f"Trying {host}...\nConnection refused"
            trigger_alert(session_id, "Telnet Attempt", f"Attempted telnet to {host}", client_ip, username)
    elif cmd_name == "scp":
        if not arg_str:
            output = "scp: missing arguments"
        else:
            output = "scp: connection refused (simulated)"
            trigger_alert(session_id, "File Transfer Attempt", f"Attempted scp: {arg_str}", client_ip, username)
    elif cmd_name == "find":
        if not arg_str:
            output = "find: missing argument"
        else:
            path = arg_str.split()[-1] if arg_str else current_dir
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "dir" and "contents" in fs[path]:
                results = []
                def recursive_find(p):
                    for item in fs[p]["contents"]:
                        full_path = f"{p}/{item}" if p != "/" else f"/{item}"
                        if full_path in fs:
                            if "-name" in arg_str and item in arg_str:
                                results.append(full_path)
                            if fs[full_path]["type"] == "dir" and "contents" in fs[full_path]:
                                recursive_find(full_path)
                recursive_find(path)
                output = "\n".join(results)
                trigger_alert(session_id, "Command Executed", f"Executed find in {path}", client_ip, username)
            else:
                output = f"find: '{path}': No such file or directory"
    elif cmd_name == "grep":
        if not arg_str:
            output = "grep: missing pattern"
        else:
            parts = arg_str.split()
            pattern = parts[0].strip("'\"")
            files = parts[1:] if len(parts) > 1 else []
            results = []
            for file in files:
                path = file if file.startswith("/") else f"{current_dir}/{file}"
                path = os.path.normpath(path)
                if path in fs and fs[path]["type"] == "file":
                    content = fs[path]["content"]() if callable(fs[path]["content"]) else fs[path]["content"]
                    for line in content.split("\n"):
                        if pattern in line:
                            results.append(f"{file}: {line}")
            output = "\n".join(results) if results else f"grep: no matches for '{pattern}'"
            trigger_alert(session_id, "Command Executed", f"Executed grep with pattern '{pattern}'", client_ip, username)
    elif cmd_name == "touch":
        if not arg_str:
            output = "touch: missing file operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
            path = os.path.normpath(path)
            if path.startswith("/tmp/"):
                fs[path] = {"type": "file", "content": "", "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                if "/tmp" in fs and "contents" in fs["/tmp"] and os.path.basename(path) not in fs["/tmp"]["contents"]:
                    fs["/tmp"]["contents"].append(os.path.basename(path))
                save_filesystem(fs)
                output = ""
                trigger_alert(session_id, "File Created", f"Created file: {path}", client_ip, username)
            else:
                output = f"touch: cannot touch '{arg_str}': Permission denied"
    elif cmd_name == "apt-get":
        if not arg_str:
            output = "apt-get: missing command"
        else:
            if "install" in arg_str:
                output = f"apt-get: installing package(s) {arg_str.split('install')[-1].strip()} (simulated)"
            elif "update" in arg_str:
                output = "apt-get: updating package lists (simulated)"
            elif "upgrade" in arg_str:
                output = "apt-get: upgrading packages (simulated)"
            else:
                output = f"apt-get: unknown command '{arg_str}'"
            trigger_alert(session_id, "Package Manager Command", f"Executed apt-get: {cmd}", client_ip, username)
    elif cmd_name == "who":
        output = get_dynamic_who()
        trigger_alert(session_id, "Command Executed", "Displayed user list", client_ip, username)
    elif cmd_name == "w":
        output = get_dynamic_w()
        trigger_alert(session_id, "Command Executed", "Displayed user activity", client_ip, username)
    elif cmd_name == "top":
        output = get_dynamic_top()
        trigger_alert(session_id, "Command Executed", "Displayed top processes", client_ip, username)
    elif cmd_name == "vim":
        chan.send(b"Entering vim mode... Press :q to exit\r\n")
        while True:
            vim_input, jobs, _ = read_line_advanced(chan, ":", history=command_history, current_dir=current_dir, username=username, fs=fs, session_log=session_log, session_id=session_id, client_ip=client_ip, jobs=jobs, cmd_count=cmd_count)
            if vim_input.strip() == ":q":
                break
            trigger_alert(session_id, "Vim Input", f"Input: {vim_input}", client_ip, username)
        chan.send(b"\r\n")
        return "", new_dir, jobs, cmd_count
    elif cmd_name == "nano":
        chan.send(b"Entering nano mode... Press Ctrl+D to exit\r\n")
        while True:
            nano_input, jobs, _ = read_line_advanced(chan, "", history=command_history, current_dir=current_dir, username=username, fs=fs, session_log=session_log, session_id=session_id, client_ip=client_ip, jobs=jobs, cmd_count=cmd_count)
            if nano_input == "\x04":
                break
            trigger_alert(session_id, "Nano Input", f"Input: {nano_input}", client_ip, username)
        chan.send(b"\r\n")
        return "", new_dir, jobs, cmd_count
    elif cmd_name == "backup_data":
        output = "Backing up data to /tmp/backup.tar.gz (simulated)..."
        fs["/tmp/backup.tar.gz"] = {"type": "file", "content": "Simulated backup data", "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if "/tmp" in fs and "contents" in fs["/tmp"] and "backup.tar.gz" not in fs["/tmp"]["contents"]:
            fs["/tmp"]["contents"].append("backup.tar.gz")
        save_filesystem(fs)
        trigger_alert(session_id, "Backup Triggered", "Triggered backup", client_ip, username)
    elif cmd_name == "systemctl":
        if "stop" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service stopped (simulated)"
            trigger_alert(session_id, "Service Stop", "Stopped nginx service", client_ip, username)
        elif "start" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service started (simulated)"
        else:
            output = f"systemctl: unknown command or service '{arg_str}'"
        trigger_alert(session_id, "Service Command", f"Executed systemctl: {cmd}", client_ip, username)
    elif cmd_name == "fg":
        if arg_str and arg_str.isdigit() and int(arg_str) - 1 in range(len(jobs)):
            job = jobs[int(arg_str) - 1]
            output = f"Resuming job [{arg_str}]: {job['cmd']}\n"
            output += job.get("output", "")
            jobs.pop(int(arg_str) - 1)
        else:
            output = "fg: no such job"
    elif cmd_name == "jobs":
        if jobs:
            output = "\n".join(f"[{job['id']}]: {job['cmd']} {job['state']}" for job in jobs)
        else:
            output = "No jobs running"
    elif cmd_name == "app_status":
        output = "Checking application status...\n\tWebServer: Running\n\tDatabase: Running\n\tBackup: Active"
        trigger_alert(session_id, "App Status Check", "Checked application status", client_ip, username)
    elif cmd_name == "status_report":
        output = f"System Status for {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}:\nCurrent Directory: {current_dir}\nActive Jobs: {len(jobs)}\nSystem Uptime: {get_dynamic_uptime()}\nDisk Usage:\n{get_dynamic_df()}"
        trigger_alert(session_id, "Status Report", "Generated system status report", client_ip, username)
    elif cmd_name == "whoami":
        output = f"{username}"
        trigger_alert(session_id, "Command Executed", "Displayed current user", client_ip, username)
    elif cmd_name == "id":
        user_info = PREDEFINED_USERS.get(username, {"uid": "1000", "groups": [username]})
        output = f"uid={user_info['uid']}({username}) gid=1000({username}) groups={','.join(user_info['groups'])}"
        trigger_alert(session_id, "Command Executed", "Displayed user ID info", client_ip, username)
    elif cmd_name == "uname":
        output = f"Linux server 5.15.0-73-generic #80-Ubuntu SMP Mon May 15 10:15:39 UTC 2023 x86_64 GNU/Linux"
        trigger_alert(session_id, "Command Executed", "Displayed system info", client_ip, username)
    elif cmd_name == "pwd":
        output = f"{current_dir}"
        trigger_alert(session_id, "Command Executed", "Displayed current directory", client_ip, username)
    elif cmd_name == "history":
        output = "\n".join(f"{i+1}  {cmd}" for i, cmd in enumerate(command_history))
        trigger_alert(session_id, "Command History", "Displayed command history", client_ip, username)
    elif cmd_name == "sudo":
        output = f"sudo: {arg_str}: command not found"
        trigger_alert(session_id, "Sudo Attempt", f"Attempted sudo command: {arg_str}", client_ip, username)
    elif cmd_name == "su":
        output = "su: Authentication failure"
        trigger_alert(session_id, "SU Attempt", "Attempted su command", client_ip, username)
    elif cmd_name == "exit":
        output = "logout"
        chan.send(b"logout\r\n")
        chan.close()
        trigger_alert(session_id, "Session Ended", "User logged out", client_ip, username)
        return output, new_dir, jobs, cmd_count, True
    elif cmd_name == "ps":
        output = get_dynamic_ps()
        trigger_alert(session_id, "Command Executed", "Displayed process list", client_ip, username)
    elif cmd_name == "netstat":
        output = get_dynamic_netstat()
        trigger_alert(session_id, "Command Executed", "Displayed network connections", client_ip, username)
    elif cmd_name == "dmesg":
        output = get_dynamic_dmesg()
        trigger_alert(session_id, "Command Executed", "Displayed kernel messages", client_ip, username)
    elif cmd_name == "df":
        output = get_dynamic_df()
        trigger_alert(session_id, "Command Executed", "Displayed disk usage", client_ip, username)
    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
        trigger_alert(session_id, "Command Executed", "Displayed system uptime", client_ip, username)
    else:
        output = f"{cmd_name}: command not found"
        trigger_alert(session_id, "Unknown Command", f"Attempted unknown command: {cmd}", client_ip, username)
    cmd_count += 1
    if cmd_count >= CMD_LIMIT_PER_SESSION:
        output += "\nSession command limit reached. Terminating session."
        chan.send(b"Session command limit reached. Terminating session.\r\n")
        chan.close()
        trigger_alert(session_id, "Session Limit Reached", "Session terminated due to command limit", client_ip, username)
        return output, new_dir, jobs, cmd_count, True
    return output, new_dir, jobs, cmd_count, False

# Lecture de ligne avancée
def read_line_advanced(chan, prompt, history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count):
    chan.send(prompt.encode())
    current_input = ""
    history_index = len(history)
    cursor_pos = 0
    while True:
        if not chan.recv_ready():
            time.sleep(0.1)
            continue
        data = chan.recv(1024)
        if not data:
            return "", jobs, cmd_count
        for char in data.decode('utf-8', errors='ignore'):
            if char == '\r' or char == '\n':
                chan.send(b"\r\n")
                if current_input.strip():
                    history.append(current_input)
                return current_input, jobs, cmd_count
            elif char == '\t':
                current_input = autocomplete(current_input, current_dir, username, fs, chan, history)
                chan.send(b"\r" + b" " * 100 + b"\r" + prompt.encode() + current_input.encode())
                cursor_pos = len(current_input)
            elif char == '\x7f' or char == '\b':
                if cursor_pos > 0:
                    current_input = current_input[:cursor_pos-1] + current_input[cursor_pos:]
                    cursor_pos -= 1
                    chan.send(b"\b \b" + current_input[cursor_pos:].encode() + b" " + b"\b" * (len(current_input[cursor_pos:]) + 1))
            elif char == '\x03':  # Ctrl+C
                chan.send(b"^C\r\n")
                current_input = ""
                cursor_pos = 0
                chan.send(prompt.encode())
            elif ord(char) == 27:  # Escape sequence (arrows)
                if chan.recv_ready():
                    next_chars = chan.recv(2).decode('utf-8', errors='ignore')
                    if next_chars == "[A" and history_index > 0:  # Up arrow
                        history_index -= 1
                        current_input = history[history_index] if history_index < len(history) else ""
                        cursor_pos = len(current_input)
                        chan.send(b"\r" + b" " * 100 + b"\r" + prompt.encode() + current_input.encode())
                    elif next_chars == "[B" and history_index < len(history) - 1:  # Down arrow
                        history_index += 1
                        current_input = history[history_index] if history_index < len(history) else ""
                        cursor_pos = len(current_input)
                        chan.send(b"\r" + b" " * 100 + b"\r" + prompt.encode() + current_input.encode())
                    elif next_chars == "[D" and cursor_pos > 0:  # Left arrow
                        cursor_pos -= 1
                        chan.send(b"\b")
                    elif next_chars == "[C" and cursor_pos < len(current_input):  # Right arrow
                        cursor_pos += 1
                        chan.send(b"\033[C")
            elif char in string.printable:
                current_input = current_input[:cursor_pos] + char + current_input[cursor_pos:]
                cursor_pos += 1
                chan.send((char + current_input[cursor_pos:]).encode() + b"\b" * len(current_input[cursor_pos:]))
            log_activity(session_id, client_ip, username, char)

# Gestion des connexions
def handle_connection(client, addr, server_key):
    client_ip = addr[0]
    session_id = uuid.uuid4().int
    with _connection_lock:
        _connection_count[client_ip] = _connection_count.get(client_ip, 0) + 1
        if _connection_count[client_ip] > CONNECTION_LIMIT_PER_IP:
            print(f"[!] Connection limit exceeded for {client_ip}")
            client.close()
            return

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(server_key)
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer, HoneypotSFTPServer)
        server = HoneypotSSHServer(client_ip, session_id)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            print(f"[!] No channel for {client_ip}")
            transport.close()
            return

        username = server.username
        if not username:
            transport.close()
            return

        trigger_alert(session_id, "Connection Established", f"New session started", client_ip, username)
        chan.send(f"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.15.0-73-generic x86_64)\r\n\r\n".encode())
        current_dir = PREDEFINED_USERS.get(username, {"home": f"/home/{username}"}).get("home", "/home")
        session_log = []
        history =        history = load_history(username)
        jobs = []
        cmd_count = 0

        while True:
            prompt_str = color_prompt(username, client_ip, current_dir)
            input_line, jobs, cmd_count = read_line_advanced(
                chan,
                prompt_str,
                history,
                current_dir,
                username,
                FS,
                session_log,
                session_id,
                client_ip,
                jobs,
                cmd_count,
            )
            if not input_line:  # Vérifie si la connexion est interrompue
                break
            output, current_dir, jobs, cmd_count, terminate = process_command(input_line, current_dir, username, FS, client_ip, session_id, session_log, history, chan, jobs, cmd_count)
            if terminate:
                break
            if output:
                chan.send((output + "\r\n").encode())

        save_history(username, history)
        with _connection_lock:
            _connection_count[client_ip] -= 1
        trigger_alert(session_id, "Session Terminated", "Session ended", client_ip, username)
        transport.close()
    except Exception as e:
        print(f"[!] Error in handle_connection: {e}")
        trigger_alert(session_id, "Connection Error", str(e), client_ip, username)
    finally:
        try:
            client.close()
        except:
            pass  # Évite l'erreur "Bad file descriptor" si déjà fermé

# Serveur SSH personnalisé
class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        self.client_ip = client_ip
        self.session_id = session_id
        self.username = None
        self.password = None
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        if not check_bruteforce(self.client_ip, username, password):
            return paramiko.AUTH_FAILED
        try:
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute(
                    "INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.client_ip, username, password, 0, 0)
                )
        except sqlite3.Error as e:
            print(f"[!] Login DB error: {e}")
        if username in PREDEFINED_USERS and hashlib.sha256(password.encode()).hexdigest() == PREDEFINED_USERS[username]["password"]:
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    conn.execute(
                        "UPDATE login_attempts SET success = 1 WHERE ip = ? AND username = ? AND timestamp = (SELECT MAX(timestamp) FROM login_attempts WHERE ip = ? AND username = ?)",
                        (self.client_ip, username, self.client_ip, username)
                    )
            except sqlite3.Error as e:
                print(f"[!] Login update error: {e}")
            trigger_alert(self.session_id, "Successful Login", f"User {username} logged in", self.client_ip, username)
            return paramiko.AUTH_SUCCESSFUL
        trigger_alert(self.session_id, "Failed Login", f"Failed login attempt for {username}", self.client_ip, username)
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        return False

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(self, username, gss_server):
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        detect_port_scan(self.client_ip, destination[1])
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# Serveur SFTP personnalisé
class HoneypotSFTPServer(paramiko.SFTPServerInterface):
    def __init__(self, server):
        self.server = server
        self.fs = FS

    def list_folder(self, path):
        path = os.path.normpath(path if path.startswith("/") else f"/{path}")
        if path not in self.fs or self.fs[path]["type"] != "dir" or "contents" not in self.fs[path]:
            return paramiko.SFTP_NO_SUCH_FILE
        return [(f, {}, {}) for f in self.fs[path]["contents"]]

    def stat(self, path):
        path = os.path.normpath(path if path.startswith("/") else f"/{path}")
        if path not in self.fs:
            return paramiko.SFTP_NO_SUCH_FILE
        attrs = paramiko.SFTPAttributes()
        attrs.st_size = len(self.fs[path].get("content", "")) if self.fs[path]["type"] == "file" and not callable(self.fs[path].get("content")) else 0
        attrs.st_uid = PREDEFINED_USERS.get(self.server.username, {"uid": 1000})["uid"]
        attrs.st_gid = 1000
        attrs.st_mode = (0o100755 if self.fs[path]["type"] == "dir" else 0o100644) | (0o0400 if "r" in self.fs[path].get("permissions", "rw-r--r--") else 0) | (0o0200 if "w" in self.fs[path].get("permissions", "") else 0) | (0o0100 if "x" in self.fs[path].get("permissions", "") else 0)
        attrs.st_atime = attrs.st_mtime = time.mktime(datetime.strptime(self.fs[path].get("mtime", datetime.now().strftime("%Y-%m-%d %H:%M:%S")), "%Y-%m-%d %H:%M:%S").timetuple())
        return attrs

    def open(self, path, flags, attr):
        path = os.path.normpath(path if path.startswith("/") else f"/{path}")
        if path not in self.fs or self.fs[path]["type"] != "file":
            return paramiko.SFTP_NO_SUCH_FILE
        trigger_alert(self.server.session_id, "SFTP Access", f"Accessed file via SFTP: {path}", self.server.client_ip, self.server.username)
        return StringIO(self.fs[path]["content"]() if callable(self.fs[path]["content"]) else self.fs[path]["content"])

    def remove(self, path):
        path = os.path.normpath(path if path.startswith("/") else f"/{path}")
        if path in self.fs and self.fs[path]["type"] == "file":
            parent_dir = "/".join(path.split("/")[:-1]) or "/"
            if parent_dir in self.fs and "contents" in self.fs[parent_dir] and path.split("/")[-1] in self.fs[parent_dir]["contents"]:
                self.fs[parent_dir]["contents"].remove(path.split("/")[-1])
            del self.fs[path]
            save_filesystem(self.fs)
            trigger_alert(self.server.session_id, "SFTP Delete", f"Deleted file via SFTP: {path}", self.server.client_ip, self.server.username)
            return paramiko.SFTP_OK
        return paramiko.SFTP_NO_SUCH_FILE

# Lancement du serveur
def signal_handler(signum, frame):
    print("[!] Shutting down server...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    init_database()
    server_key = paramiko.RSAKey.generate(2048)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)
    print(f"[*] SSH Honeypot listening on {HOST}:{PORT}")

    threading.Thread(target=cleanup_bruteforce_attempts, daemon=True).start()
    threading.Thread(target=send_weekly_report, daemon=True).start()
    threading.Thread(target=send_periodic_report, daemon=True).start()
    threading.Thread(target=cleanup_trap_files, args=(FS,), daemon=True).start()

    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_connection, args=(client, addr, server_key), daemon=True).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Server error: {e}")
    server.close()
