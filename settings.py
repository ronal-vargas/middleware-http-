import os
import re
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# --- Redis Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

# --- Security Thresholds ---
STRIKE_THRESHOLD = int(os.getenv("STRIKE_THRESHOLD", "3"))                # Number of strikes before ban
STRIKE_TTL_SEC    = int(os.getenv("STRIKE_TTL_SEC", "86400"))             # Strike expiry (24h)
BAN_DURATION      = int(os.getenv("BAN_DURATION", "604800"))              # Ban duration (7 days)
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))             # Rate-limit window (seconds)
RATE_LIMIT_MAX    = int(os.getenv("RATE_LIMIT_MAX", "30"))                # Max requests per window
MAX_PAYLOAD_SIZE  = int(os.getenv("MAX_PAYLOAD_SIZE", str(10 * 1024 * 1024)))  # 10 MB
SESSION_TTL_SEC   = int(os.getenv("SESSION_TTL_SEC", "3600"))             # JWT/session TTL (1h)

# --- JWT Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM  = os.getenv("ALGORITHM", "HS256")

# --- Allowed IPs & Docs Auth ---
#ALLOWED_IPS      = os.getenv("ALLOWED_IPS", "127.0.0.1,::1").split(",")
DOCS_AUTH_HEADER = os.getenv("DOCS_AUTH_HEADER", "Bearer your-secret-token-here")

STRIKE_PREFIX = os.getenv("STRIKE_PREFIX", "security:strike:")

# Rutas que nunca deben banearse aunque devuelvan 404
WHITELIST_404 = {
    "/",
  # tus apis aqui ejemplo /login
}

# --- Forbidden Path Patterns ---
FORBIDDEN_PATTERNS = [
    r"^/(wp-admin|wp-login|wp-content|administrator|admin|login|xmlrpc\.php)",
    r"^/(phpmyadmin|adminer|mysql|myadmin|pma)",
    r"^/(console|shell|eval|exec|system|passthru|cmd)",
    r"\.(git|env|htaccess|htpasswd|ini|log|bak|backup|swp|old|orig|~|zip|tar|gz|rar)",
    r"^/(api/v\d+/|v\d+/api/).*?(exec|system|shell|cmd|passthru)",
]
 
COMPILED_FORBIDDEN_PATTERNS = [re.compile(p, re.IGNORECASE) for p in FORBIDDEN_PATTERNS]

# --- Suspicious User-Agent Patterns ---
SUSPICIOUS_UA_PATTERNS = [
    r"(sqlmap|nikto|nmap|masscan|hydra|dirb|gobuster|wpscan)",
    r"(zgrab|censys|shodan|dirbuster|burpsuite|acunetix|nessus)",
    r"(metasploit|shellshock|slowloris|slowhttptest|siege)",
    r"(curl|wget|python-requests|go-http-client|httpclient)",
    r"\.(\d+\.){2}\d+$",  # IPs as UA
    r"^$|^-$|^null$|^undefined$",  # Empty or invalid UA
    r"(encrypt|ransom|crypt|decrypt|locker|payment)",
]
COMPILED_SUSPICIOUS_UA = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_UA_PATTERNS]

# --- Attack Patterns by Category ---
ATTACK_PATTERNS = {
    "sql_injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^<>]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Combined the broken line
        r"(\%27|\'|\"|--|\%23|#).*?(\%3D|=)",
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)",
    ],
    "xss": [
        r"<[^<>]*?(script|form|style|svg|marquee)[^>]*>", # Combined the broken line
        r"(alert\(|confirm\(|prompt\(|eval\(|javascript:)",
    ],
    "path_traversal": [
        r"(\.{2}/|\.{2}\\)",
        r"(/etc/|/var/|/usr/|/bin/|/proc/|/sys/|c:\\windows\\|c:\\program)",
    ],
    "file_inclusion": [
        r"(file://|php://|phar://|data://)",
        r"(/etc/passwd|/etc/shadow|/proc/self/environ)",
    ],
    "command_injection": [
        r"(;|&&|\|\||`|\$\(|\$\{|%0A|%0D)",
        r"(system\(|exec\(|passthru\(|shell_exec\()",
    ],
    "ransomware_specific": [
        r"(ransomware|ransom|encrypt|decrypt|bitcoin|monero|payment|unlock|locker)",
        r"(\.locked$|\.encrypted$|\.crypt$|\.cry$|\.crypto$)",
    ],
}
COMPILED_ATTACK_PATTERNS = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns]
    for name, patterns in ATTACK_PATTERNS.items()
}

# --- 404 Suspicious Patterns ---
SUSPICIOUS_404_PATTERNS = [
    r"(/admin|/administrator|/wp-admin|/login|/user|/account)",
    r"(/shell|/sh|/bash|/cmd|/cgi-bin)",
    r"(\.conf$|\.config$|\.ini$|\.env($|\.)|\.git|\.svn)",
    r"(\.php$|\.asp$|\.jsp$|\.cgi$)",
    r"(\.sql$|\.db$|\.sqlite3$)",
    r"(/solr|/struts|/drupal|/phpmyadmin|/jenkins)",
    r"(\.exe$|\.zip$|\.rar$|\.7z$)",
]
COMPILED_SUSPICIOUS_404 = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_404_PATTERNS]
