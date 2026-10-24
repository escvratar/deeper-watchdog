#!/usr/bin/env python3
"""
Deeper Connect Tunnel Watchdog & Auto-Switcher
Monitors connection quality on tunnels (US, GB, NL, etc.) and automatically switches nodes
or rebuilds tunnels when latency degrades or packet loss occurs.
Supports email notifications via SMTP.
Zero external dependencies.
"""

import os
import sys
import time
import json
import re
import base64
import hmac
import logging
import smtplib
import argparse
import threading
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def load_dotenv():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, ".env"),
        os.path.join(os.getcwd(), ".env")
    ]
    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass

load_dotenv()

# Configuration: built-in defaults <- .env / environment <- data/settings.json (web UI)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR")
if not DATA_DIR:
    if os.path.isdir("/data"):
        DATA_DIR = "/data"
    else:
        DATA_DIR = os.path.join(SCRIPT_DIR, "data")

os.makedirs(DATA_DIR, exist_ok=True)
COOKIE_FILE = os.path.join(DATA_DIR, "deeper_session.cookie")
STATE_FILE = os.path.join(DATA_DIR, "deeper_fails.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
AUTO_STATE_FILE = os.path.join(DATA_DIR, "auto_state.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
BACKUP_DIR = os.path.join(DATA_DIR, "rules-backups")

# Web UI settings are env-only, so the UI can't lock itself out
WEB_ENABLED = os.environ.get("WEB_ENABLED", "true").lower() in ("true", "1", "yes")
WEB_PORT = int(os.environ.get("WEB_PORT", "8787"))
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")

# Settings editable from the web UI: key -> (type, default, min, max)
SETTINGS_SCHEMA = {
    "DEEPER_HOST": ("str", "34.34.34.34", None, None),
    "DEEPER_USER": ("str", "admin", None, None),
    "DEEPER_PASS": ("secret", "", None, None),  # Only from .env or the web UI, never in the code
    "MAX_LATENCY_MS": ("int", "2500", 100, 60000),
    "FAIL_THRESHOLD": ("int", "3", 1, 20),
    "SKIP_ALL_SLOW": ("bool", "true", None, None),
    "CHECK_INTERVAL": ("int", "180", 30, 86400),
    "LATENCY_TIMEOUT": ("float", "3.5", 0.5, 60),
    "MONITOR_TUNNELS": ("str", "", None, None),
    # One "CODE=url1,url2" per line; .env CANARIES_XX values are the default
    "CANARIES": ("text", "", None, None),
    # Test sites, comma-separated: each one tests the tunnel its domain goes through right now
    "TEST_SITES": ("str", "", None, None),
    "RECOVERY_ACTION": ("choice", "refresh", None, None),
    "REBUILD_WAIT": ("int", "16", 0, 300),
    # "smart" recovery: node switches before rebuilding, checks per switch, pause between checks
    "SWITCH_ATTEMPTS": ("int", "3", 1, 10),
    "VERIFY_CHECKS": ("int", "3", 1, 10),
    "VERIFY_PAUSE": ("int", "5", 0, 120),
    # Tunnel comparison for Smart Route domains (web UI button) and auto-moving of ticked domains
    # Domains and "app:<name>" App Relocator apps that auto mode may move
    "AUTO_ROUTE_DOMAINS": ("str", "", None, None),
    # One "service_key=CODE" per line: the tunnel a service always goes back to while it has nodes
    "PREFERRED_TUNNELS": ("text", "", None, None),
    # App Relocator apps shown in the web UI (Deeper app keys)
    "APPS": ("str", "instagram,telegram", None, None),
    # Extra/overriding service groups, one "Name=domain1,domain2" per line
    "SERVICE_GROUPS": ("text", "", None, None),
    "AUTO_MIN_GAIN_PCT": ("int", "30", 0, 90),
    "AUTO_MIN_GAIN_MS": ("int", "200", 0, 10000),
    "COMPARE_SAMPLES": ("int", "3", 1, 10),
    "ROUTE_SETTLE": ("int", "3", 0, 60),
    # Daily comparison of auto-mode services at this hour (-1 = off)
    "AUTO_COMPARE_HOUR": ("int", "4", -1, 23),
    # An auto-mode service much slower than another tunnel gets compared right away, at most this often (min, 0 = off)
    "AUTO_GAIN_RECHECK": ("int", "60", 0, 1440),
    # Test sites per tunnel: too few of the user's go through a tunnel, temporary ones top it up
    "SITES_PER_TUNNEL": ("int", "3", 1, 6),
    # Event log: entries older than this many days are removed (0 = only the length limit); shown on the overview
    "EVENTS_DAYS": ("int", "3", 0, 365),
    "SHOW_EVENTS": ("bool", "true", None, None),
    # Undo an auto move if the service stops working in its new tunnel
    "AUTO_ROLLBACK": ("bool", "true", None, None),
    # A tunnel left without nodes: its services move to a tunnel that has them, and come back later
    "FAILOVER_EMPTY": ("bool", "true", None, None),
    "FAILOVER_WAIT": ("int", "30", 5, 600),
    "EMPTY_REBUILD_AFTER": ("int", "60", 0, 3600),
    "EMPTY_REBUILD_EVERY": ("int", "300", 60, 86400),
    # No nodes in any tunnel: all of them are rebuilt and checked again this often (0 = off)
    "ALL_EMPTY_REBUILD_EVERY": ("int", "180", 0, 86400),
    "FAILOVER_RETURN": ("bool", "true", None, None),
    # Services that leave right after a rebuild that ended without nodes ("app:<name>" / "group:<name>")
    "FAILOVER_PRIORITY": ("str", "", None, None),
    "SMTP_ENABLED": ("bool", "false", None, None),
    "SMTP_HOST": ("str", "", None, None),
    "SMTP_PORT": ("int", "465", 1, 65535),
    "SMTP_USE_SSL": ("bool", "true", None, None),
    "SMTP_USER": ("str", "", None, None),
    "SMTP_PASS": ("secret", "", None, None),
    "SMTP_FROM": ("str", "", None, None),
    "SMTP_TO": ("str", "", None, None),
    # What to email about: categories from EMAIL_CATEGORIES
    "EMAIL_EVENTS": ("str", "recovery,no_nodes,all_empty,auto,rollback,errors", None, None),
}
RECOVERY_ACTIONS = ("refresh", "switch", "smart")

# Runtime state shown in the web UI
STATUS = {"last_run": None, "next_run": None, "error": None, "tunnels": {}, "last_email": None}
CHECK_NOW = threading.Event()
# Latest per-site results of tunnel checks: "<tunnel> <url>" -> {url, tunnel, latency, status, ok, time}
SITE_RESULTS = {}
# Cached Smart Route data for the web UI
ROUTES = {"whitelist": [], "routed": {}, "site_routes": {}, "tunnels": [], "apps": [], "all_tunnels": []}
# Latest ping of App Relocator apps (measured via their website): app -> {tunnel, latency, status, ok}
APP_RESULTS = {}
# State of the tunnel comparison job
COMPARE = {"running": False, "progress": "", "stage": "", "started": None, "finished": None, "error": None, "results": []}
# Held by a check iteration or a comparison, so they never measure while routes are being moved
ROUTE_LOCK = threading.Lock()
ACTIONS = {}  # code -> {"text", "since"}: what the watchdog is doing with a tunnel right now, for the web UI
NODE_WATCH_EVERY = 10  # Seconds between node count checks
EMPTY_SINCE = {}  # code -> when the tunnel was first seen without nodes
EMPTY_REBUILT = {}  # code -> when it was last rebuilt for having no nodes
ALL_EMPTY_SINCE = 0  # When every monitored tunnel was first seen without nodes (0: some have nodes)
ALL_EMPTY_REBUILT = 0  # When all tunnels were last rebuilt for that
NODES_SINCE = {}  # code -> since when the tunnel has nodes
NODES_STABLE = 20  # Seconds a tunnel must keep its nodes before services go back to it
ENFORCED_AT = 0  # When the node watcher last checked services against their preferred tunnels
READY_SEEN = set()  # Tunnels that had stable nodes at the previous watcher tick
# Held while services are moved between tunnels by failover, returns and preferred tunnels. Separate from
# ROUTE_LOCK, so a long recovery of one tunnel doesn't hold up moving services out of another, empty one.
# Order: ROUTE_LOCK before MOVE_LOCK, never the other way round
MOVE_LOCK = threading.RLock()
WATCHER_ON = False  # The node watcher runs: it handles empty tunnels, the check doesn't wait for them
EVAC_TRIED = {}  # code -> when the watcher last tried to move services out of the empty tunnel
EVAC_NOTIFIED = {}  # code -> services that couldn't be moved and were already reported in this outage
LAST_FAIL_AT = {}  # code -> when a failed check was last counted


def set_action(code, text=None):
    if text:
        ACTIONS[code] = {"text": text, "since": int(time.time())}
    else:
        ACTIONS.pop(code, None)


def publish_tunnel(code, status):
    """Shows one tunnel's fresh status right away instead of at the end of the whole check."""
    STATUS["tunnels"] = {**STATUS["tunnels"], code: status}
COMPARE_START_LOCK = threading.Lock()
# Sites measured in parallel during a comparison (each one moves only its own route)
COMPARE_MEASURE_WORKERS = 32  # Services measured at once in one tunnel during a comparison
COMPARE_GROUP_DOMAINS = 10  # Domains of one service measured when comparing; the ping is their average


def load_saved_settings():
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def parse_setting(key, value):
    """Converts a raw value to the setting's type. Raises ValueError if invalid."""
    kind, _, lo, hi = SETTINGS_SCHEMA[key]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")
    if kind in ("int", "float"):
        try:
            num = int(value) if kind == "int" else float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key}: ожидается число")
        if (lo is not None and num < lo) or (hi is not None and num > hi):
            raise ValueError(f"{key}: значение должно быть от {lo} до {hi}")
        return num
    value = str(value).strip()
    if kind == "choice":
        value = value.lower()
        if value not in RECOVERY_ACTIONS:
            raise ValueError(f"{key}: допустимо {', '.join(RECOVERY_ACTIONS)}")
    return value


def current_settings():
    """Effective settings: values saved from the web UI override .env / environment."""
    saved = load_saved_settings()
    env_canaries = "\n".join(
        f"{k[len('CANARIES_'):]}={v}" for k, v in sorted(os.environ.items())
        if k.startswith("CANARIES_") and v.strip()
    )
    result = {}
    for key, (_, default, _, _) in SETTINGS_SCHEMA.items():
        env_default = env_canaries if key == "CANARIES" else os.environ.get(key, default)
        try:
            result[key] = parse_setting(key, saved.get(key, env_default))
        except ValueError:
            result[key] = parse_setting(key, default)
    return result


def apply_settings():
    """Loads effective settings into module globals."""
    global MONITOR_TUNNELS, CANARIES, SMTP_FROM
    settings = current_settings()
    globals().update(settings)
    MONITOR_TUNNELS = [t.strip().upper() for t in settings["MONITOR_TUNNELS"].split(",") if t.strip()]
    CANARIES = {}
    for line in settings["CANARIES"].replace(";", "\n").splitlines():
        if "=" in line:
            code, urls = line.split("=", 1)
            urls = [u.strip() for u in urls.split(",") if u.strip()]
            if code.strip() and urls:
                CANARIES[code.strip().upper()] = urls
    SMTP_FROM = settings["SMTP_FROM"] or settings["SMTP_USER"]
    return settings


SETTINGS_LOCK = threading.RLock()


def save_settings(values):
    """Validates and stores settings from the web UI. Returns a list of errors."""
    with SETTINGS_LOCK:  # Read-modify-write: two saves at once must not lose each other's values
        return _save_settings(values)


def _save_settings(values):
    saved = load_saved_settings()
    errors = []
    for key, value in values.items():
        if key not in SETTINGS_SCHEMA:
            continue
        if SETTINGS_SCHEMA[key][0] == "secret" and value in ("", None):
            continue  # Empty password field means "keep current"
        try:
            saved[key] = parse_setting(key, value)
        except ValueError as e:
            errors.append(str(e))
    if errors:
        return errors

    tmp = SETTINGS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(saved, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_FILE)
    apply_settings()
    return []


apply_settings()

# Country Names in Russian
COUNTRY_NAMES = {
    "US": "США",
    "GB": "Великобритания",
    "NL": "Нидерланды",
    "DE": "Германия",
    "FR": "Франция",
    "CA": "Канада",
    "JP": "Япония",
    "SG": "Сингапур",
    "CN": "Китай",
    "RU": "Россия",
    "PL": "Польша",
    "TR": "Турция",
    "RS": "Сербия", "IT": "Италия", "ES": "Испания", "PT": "Португалия", "IE": "Ирландия", "BE": "Бельгия",
    "LU": "Люксембург", "CH": "Швейцария", "AT": "Австрия", "CZ": "Чехия", "SK": "Словакия", "HU": "Венгрия",
    "RO": "Румыния", "BG": "Болгария", "GR": "Греция", "CY": "Кипр", "HR": "Хорватия", "SI": "Словения",
    "BA": "Босния и Герцеговина", "ME": "Черногория", "MK": "Северная Македония", "AL": "Албания",
    "MD": "Молдова", "UA": "Украина", "BY": "Беларусь", "LT": "Литва", "LV": "Латвия", "EE": "Эстония",
    "FI": "Финляндия", "SE": "Швеция", "NO": "Норвегия", "DK": "Дания", "IS": "Исландия",
    "GE": "Грузия", "AM": "Армения", "AZ": "Азербайджан", "KZ": "Казахстан", "UZ": "Узбекистан",
    "KG": "Киргизия", "IL": "Израиль", "AE": "ОАЭ", "SA": "Саудовская Аравия", "QA": "Катар", "EG": "Египет",
    "IN": "Индия", "PK": "Пакистан", "HK": "Гонконг", "TW": "Тайвань", "KR": "Южная Корея", "TH": "Таиланд",
    "VN": "Вьетнам", "MY": "Малайзия", "ID": "Индонезия", "PH": "Филиппины", "AU": "Австралия",
    "NZ": "Новая Зеландия", "BR": "Бразилия", "AR": "Аргентина", "CL": "Чили", "CO": "Колумбия",
    "MX": "Мексика", "PE": "Перу", "ZA": "ЮАР", "NG": "Нигерия", "KE": "Кения", "MA": "Марокко",
}

# AtomOS RSA Public Key
DEEPER_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZ9YwQ1CVM4zNHVNPxoD
Sz6uFGEcyHUOFkoA2hnijjJccCNRGnYlQmnCmaKPtCPiJ26ibXcL9BpfputJpE7Q
cJcJx8CN0Pr/MceYQraFS3UG+zNdI6tGzLDGrBoB+5WFSbK6aOdHFJfcoBfdULHb
g2eGp2IJwSPal3lFNwE/oTL3K1z7EiwbDq0LrY7FcwMGmG3EFaGtMxRy/cq3r0xR
M1V7WIu1I6gw463luLs6NFCdrY/fiXoSrXRf6sOTZClXeRhKjA6c0wLIxizgw6ll
4EeffYVBQSKlEjJJR2y7cxxbp1XkC19evxe0DYbnsemogDcSkmDCj75hsgwuzoTM
FwIDAQAB
-----END PUBLIC KEY-----"""

# Default / Fallback Canaries (Instagram, Telegram, YouTube, Gemini)
FALLBACK_CANARIES = {
    "US": [
        "https://www.instagram.com",
        "https://www.youtube.com"
    ],
    "NL": [
        "https://gemini.google.com",
        "https://www.youtube.com"
    ],
    "GB": [
        "https://api.telegram.org",
        "https://www.instagram.com"
    ]
}

def default_canaries(tunnel_code, routed_domains=None):
    """Default test sites for a tunnel when no override is set."""
    # 1. Domains the user routed through this tunnel in Smart Route: they really go through it
    if routed_domains and tunnel_code in routed_domains:
        return routed_domains[tunnel_code][:2]

    # 2. Configured test targets (Instagram, Telegram, YouTube, Gemini)
    if tunnel_code in FALLBACK_CANARIES:
        return FALLBACK_CANARIES[tunnel_code]

    # 3. Global fallback
    return ["https://www.youtube.com", "https://api.telegram.org"]


CDN_HOSTS = ("azureedge.net", "cloudfront.net", "akamaized.net", "akamaihd.net", "fastly.net", "googlevideo.com",
             "gstatic.com", "ggpht.com", "ytimg.com", "fbcdn.net", "cdninstagram.com", "googleusercontent.com")


def own_domain_sites(client, code, routed_domains, site_routes, apps=None, limit=2, tries=12, skip=()):
    """Temporary test sites for a tunnel with too few of the user's test sites going through it: websites
    of apps relocated there, then its Smart Route domains, only those that really go through it and skipping
    CDN domains without a site of their own (and hosts in skip). Empty if there are none."""
    sites = [a.get("website") for a in (apps or {}).values() if a.get("tunnel") == code and a.get("website")]
    sites += (routed_domains or {}).get(code, [])
    hosts = [urllib.parse.urlparse(u).hostname or "" for u in sites]
    hosts = list(dict.fromkeys(h[4:] if h.startswith("www.") else h for h in hosts))  # www.x and x are one site
    hosts = [h for h in hosts if h and h not in skip
             and not h.endswith(CDN_HOSTS) and not any("cdn" in x for x in h.split(".")[:-1])]
    picked = []
    for h in hosts[:tries]:
        if h not in site_routes:
            try:
                site_routes[h] = client.get_domain_route(h)
            except Exception:
                site_routes[h] = None
        if site_routes[h] == code:
            picked.append(f"https://{h}")
            if len(picked) >= limit:
                break
    return picked


def test_sites():
    return [u.strip() for u in TEST_SITES.split(",") if u.strip()]


def migrate_test_sites():
    """Test sites used to be set per tunnel. Now each site tests the tunnel its domain goes through,
    so the older per-tunnel lists become one list."""
    if "TEST_SITES" in load_saved_settings() or not CANARIES:
        return
    urls = list(dict.fromkeys(u for urls in CANARIES.values() for u in urls))
    if not save_settings({"TEST_SITES": ",".join(urls), "CANARIES": ""}):
        logger.info(f"Тестовые сайты теперь проверяют туннель, через который идут: {', '.join(urls)}")


def get_tunnel_canaries(tunnel_code, routed_domains=None):
    """Returns the list of endpoints to test for a given tunnel."""
    # Custom override from settings (.env CANARIES_XX or web UI)
    if tunnel_code.upper() in CANARIES:
        return CANARIES[tunnel_code.upper()]
    return default_canaries(tunnel_code, routed_domains)


def preferred_tunnels():
    result = {}
    for line in PREFERRED_TUNNELS.splitlines():
        if "=" in line:
            key, code = line.rsplit("=", 1)
            if key.strip() and code.strip():
                result[key.strip()] = code.strip().upper()
    return result


def preferred_setting(prefs):
    return "\n".join(f"{k}={v}" for k, v in sorted(prefs.items()))


def auto_route_domains():
    return {d.strip() for d in AUTO_ROUTE_DOMAINS.split(",") if d.strip()}


def configured_apps():
    return [a.strip() for a in APPS.split(",") if a.strip()]


# Known services whose Smart Route domains must always share one tunnel.
# A domain belongs to a group if it equals a listed domain or is its subdomain. Main domains go first:
# they are the ones measured when comparing tunnels.
BUILTIN_GROUPS = {
    "Google AI (Gemini)": ["gemini.google.com", "aistudio.google.com", "ai.google", "gemini.google", "ai.google.dev",
                           "bard.google.com", "generativelanguage.googleapis.com", "notebooklm.google", "labs.google",
                           "jules.google", "deepmind.google", "deepmind.com", "google.dev", "antigravity.google",
                           "accounts.google.com", "cloud.google.com", "console.cloud.google.com",
                           "firebase.google.com"],
    "Claude (Anthropic)": ["claude.ai", "claude.com", "anthropic.com"],
    "ChatGPT (OpenAI)": ["chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com"],
    "Microsoft": ["microsoft.com", "live.com", "microsoftonline.com", "msftauth.net", "msocdn.com", "onestore.ms",
                  "windowsupdate.com", "xboxlive.com", "azureedge.net", "msftncsi.com"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com"],
    "Instagram": ["instagram.com", "ig.me", "cdninstagram.com"],
    "Rutor": ["rutor.info", "rutor.org", "new-rutor.org"],
    "NNM-Club": ["nnmclub.to", "nnmstatic.win"],
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com",
                "youtubei.googleapis.com", "yt.be", "ggpht.com"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"],
    "X (Twitter)": ["x.com", "twitter.com", "twimg.com", "t.co"],
    "Facebook": ["facebook.com", "fbcdn.net", "fb.com", "messenger.com", "fbsbx.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
    "Spotify": ["spotify.com", "scdn.co", "spotifycdn.com", "spotify.design"],
    "Grok (xAI)": ["grok.com", "x.ai"],
    "Perplexity": ["perplexity.ai", "pplx.ai"],
    "GitHub Copilot": ["github.com", "githubcopilot.com", "githubusercontent.com", "githubassets.com"],
    "Kodik": ["kodik.info", "kodik.biz", "kodik.cc", "kodikapi.com", "kodik-storage.com", "aniqit.com"],
    "Twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "ext-twitch.tv"],
    "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
              "steamserver.net", "steamusercontent.com"],
    "Reddit": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "SoundCloud": ["soundcloud.com", "sndcdn.com"],
    "Patreon": ["patreon.com", "patreonusercontent.com"],
    "Notion": ["notion.so", "notion.site", "notion.com"],
    "Canva": ["canva.com"],
    "DeepL": ["deepl.com"],
    "Midjourney": ["midjourney.com"],
    "Cursor": ["cursor.com", "cursor.sh"],
    "Suno": ["suno.com", "suno.ai"],
    "ElevenLabs": ["elevenlabs.io"],
    "Hugging Face": ["huggingface.co", "hf.co"],
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value):
    """"https://Example.com/path" -> "example.com"; None if it isn't a domain."""
    if not isinstance(value, str):
        return None
    d = value.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].strip(".")
    return d if DOMAIN_RE.match(d) else None


def known_groups():
    """Built-in groups extended with the user's ones (SERVICE_GROUPS adds domains, it doesn't replace).
    A domain the user put into another service leaves its built-in group."""
    user = parse_service_groups(SERVICE_GROUPS)
    assigned = {d: name for name, domains in user.items() for d in domains}
    groups = {name: [d for d in domains if assigned.get(d, name) == name] for name, domains in BUILTIN_GROUPS.items()}
    for name, domains in user.items():
        groups[name] = list(dict.fromkeys(groups.get(name, []) + domains))
    return groups


def add_to_service_group(name, domains, current_rules):
    """Remembers domains as part of a service in SERVICE_GROUPS (and takes them out of other user groups).
    Returns a list of errors."""
    user = parse_service_groups(SERVICE_GROUPS)
    for other in user:
        user[other] = [d for d in user[other] if d not in domains]
    # A service guessed from site names exists only in the rules: keep its current domains with it
    existing = [] if name in known_groups() else \
        [d["domain"] for g in service_groups(current_rules) if g["name"] == name for d in g["domains"]]
    builtin = BUILTIN_GROUPS.get(name, [])
    user[name] = [d for d in dict.fromkeys(user.get(name, []) + existing + domains) if d not in builtin]
    text = "\n".join(f"{n}={','.join(ds)}" for n, ds in user.items() if ds)
    return save_settings({"SERVICE_GROUPS": text})


def service_catalog(rules):
    """Services that can be added in one click: [{"name", "domains", "present": {domain: tunnel}}]."""
    present = {r["domain"]: r["tunnel"] for r in rules}
    return [{"name": name, "domains": domains, "present": {d: present[d] for d in domains if d in present}}
            for name, domains in sorted(known_groups().items(), key=lambda x: x[0].lower())]


def parse_service_groups(text):
    groups = {}
    for line in text.replace(";", "\n").splitlines():
        if "=" in line:
            name, domains = line.split("=", 1)
            domains = [d.strip().lower() for d in domains.split(",") if d.strip()]
            if name.strip() and domains:
                groups[name.strip()] = domains
    return groups


def base_name(domain):
    """Service name guessed from a domain: "kinozal.tv" -> "Kinozal", "longchamp.co.th" -> "Longchamp"."""
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return parts[-3].capitalize()
    return (parts[-2] if len(parts) >= 2 else parts[0]).capitalize()


def service_groups(rules):
    """Groups Smart Route rules ([{"domain", "tunnel"}]) into services.
    Returns [{"key", "name", "domains": [{"domain", "tunnel"}], "tunnels": {code: count}, "main", "split"}]."""
    known = known_groups()
    order = {}
    for name, patterns in known.items():
        for i, p in enumerate(patterns):
            order.setdefault(p, (name, i))

    grouped = {}
    for r in rules:
        d = r["domain"]
        match = next(((order[p], p) for p in sorted(order, key=len, reverse=True) if d == p or d.endswith("." + p)), None)
        name, rank = match[0] if match else (base_name(d), 1000)
        grouped.setdefault(name, []).append((rank, d, r["tunnel"]))

    result = []
    for name, members in sorted(grouped.items(), key=lambda x: x[0].lower()):
        members.sort()
        counts = {}
        for _, _, t in members:
            counts[t] = counts.get(t, 0) + 1
        main = max(counts, key=lambda t: (counts[t], -[m[2] for m in members].index(t)))
        result.append({"key": "group:" + name, "name": name, "domains": [{"domain": d, "tunnel": t} for _, d, t in members],
                       "tunnels": counts, "main": main, "split": len(counts) > 1})
    return result

logger = logging.getLogger("DeeperWatchdog")
migrate_test_sites()

HISTORY_HOURS = 24        # Ping history kept per tunnel
MAX_EVENTS = 2000         # Event log length limit, on top of EVENTS_DAYS
MAX_BACKUPS = 30          # Rule backups kept
PROBATION_CHECKS = 3      # Good checks in a row after an auto move before it is trusted
ROLLBACK_FAILS = 2        # Bad checks in a row that undo an auto move
BLOCK_HOURS = 24          # How long auto mode avoids a tunnel it had to roll back from
STATE_LOCK = threading.Lock()


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


# Event log shown in the web UI: [{time, kind, text}], newest last
EVENTS = load_json(EVENTS_FILE, [])
# Auto mode state: moves on probation, tunnels to avoid after a rollback, last scheduled comparison
AUTO_STATE = load_json(AUTO_STATE_FILE, {})
AUTO_STATE.setdefault("probation", {})
AUTO_STATE.setdefault("blocked", {})
AUTO_STATE.setdefault("evacuated", {})  # key -> {"from", "to", "since"}: services moved out of an empty tunnel
# Ping history: tunnel -> [[unix_time, ms or None], ...]
HISTORY = load_json(HISTORY_FILE, {})
# Latest ping of every service: "group:<name>" -> {name, tunnel, url, latency, status, ok}
SERVICE_RESULTS = {}
SERVICES_EVERY = 15 * 60  # Seconds between service status measurements
SERVICES_MEASURED = {"at": 0}


# Email categories the user picks in the settings
EMAIL_CATEGORIES = ("recovery", "check", "all_slow", "no_nodes", "nodes_back", "all_empty", "auto", "rollback",
                    "errors", "changes")


def log_event(kind, text, mail=None):
    """Adds an entry to the event log. kind: ok, warn, bad, info. mail: email category to also send it by."""
    with STATE_LOCK:
        EVENTS.append({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "text": text})
        prune_events()
    if mail:
        notify(mail, f"[Deeper Connect] {text if len(text) <= 90 else text[:88] + '…'}", text + "\n")


def notify(category, subject, body):
    """Emails in the background if this category is chosen in the settings."""
    if SMTP_ENABLED and category in {c.strip() for c in EMAIL_EVENTS.split(",")}:
        threading.Thread(target=send_email_notification, args=(subject, body), daemon=True).start()


def prune_events(clear=False):
    """Drops entries older than EVENTS_DAYS (all of them with clear) and saves the log. Under STATE_LOCK."""
    if clear:
        EVENTS.clear()
    elif EVENTS_DAYS:
        oldest = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - EVENTS_DAYS * 86400))
        EVENTS[:] = [e for e in EVENTS if e.get("time", "") >= oldest]
    del EVENTS[:-MAX_EVENTS]
    STATUS["events_at"] = time.time()  # The web UI reloads the log when this changes
    try:
        save_json(EVENTS_FILE, EVENTS)
    except Exception as e:
        logger.debug(f"Could not save events: {e}")


def save_auto_state():
    with STATE_LOCK:
        try:
            save_json(AUTO_STATE_FILE, AUTO_STATE)
        except Exception as e:
            logger.debug(f"Could not save auto state: {e}")


def blocked_tunnel(key):
    """Tunnel auto mode must not pick for a service right now (after a rollback), or None."""
    b = AUTO_STATE["blocked"].get(key)
    return b["tunnel"] if b and b.get("until", 0) > time.time() else None


def take_snapshot(client):
    """Current Smart Route rules and tunnels of the configured apps."""
    rules = sorted(({"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")}
                    for i in client.get_whitelist_domains()), key=lambda r: r["domain"])
    apps = client.get_apps()
    return {"rules": rules, "apps": {a: (apps.get(a) or {}).get("tunnel") for a in configured_apps() if a in apps}}


def backup_rules(client, reason):
    """Saves the rules to data/rules-backups before a change (skipped if nothing changed since the last one)."""
    try:
        snapshot = take_snapshot(client)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        files = sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith(".json"))
        if files:
            last = load_json(os.path.join(BACKUP_DIR, files[-1]), {})
            if last.get("rules") == snapshot["rules"] and last.get("apps") == snapshot["apps"]:
                return files[-1][:-5]
        bid = time.strftime("%Y%m%d-%H%M%S")
        n = 1
        while os.path.exists(os.path.join(BACKUP_DIR, bid + ".json")):
            n += 1
            bid = time.strftime("%Y%m%d-%H%M%S") + f"_{n}"  # "_" sorts after ".json", so order stays by time
        save_json(os.path.join(BACKUP_DIR, bid + ".json"),
                  dict(snapshot, time=time.strftime("%Y-%m-%d %H:%M:%S"), reason=reason))
        for old in (files + [bid + ".json"])[:-MAX_BACKUPS]:
            os.remove(os.path.join(BACKUP_DIR, old))
        return bid
    except Exception as e:
        logger.warning(f"Не удалось сохранить резервную копию правил: {e}")
        return None


def list_backups():
    try:
        files = sorted((f for f in os.listdir(BACKUP_DIR) if f.endswith(".json")), reverse=True)
    except FileNotFoundError:
        return []
    result = []
    for f in files:
        data = load_json(os.path.join(BACKUP_DIR, f), {})
        result.append({"id": f[:-5], "time": data.get("time"), "reason": data.get("reason"),
                       "rules": len(data.get("rules") or []), "apps": data.get("apps") or {}})
    return result


def apply_snapshot(client, snapshot, exact):
    """Brings Deeper to the snapshot's rules. exact=True also deletes rules missing from it.
    Returns (changed, failed) lists of domains/apps."""
    target = {}
    for r in snapshot.get("rules") or []:
        d = normalize_domain(r.get("domain")) if isinstance(r, dict) else None
        if d and isinstance(r.get("tunnel"), str):
            target[d] = r["tunnel"]
    current = {i.get("domainName"): i.get("tunnelCode") for i in client.get_whitelist_domains()}
    changed, failed = [], []
    extra = [d for d in current if d not in target] if exact else []
    if extra:
        (changed if client.delete_domains(extra) else failed).extend(extra)
    for d, t in target.items():
        if current.get(d) == t:
            continue
        ok = client.move_domain(d, current[d], t) if d in current else client.add_domain(d, t)
        (changed if ok else failed).append(d)
    apps = client.get_apps()
    for a, t in (snapshot.get("apps") or {}).items():
        if a in configured_apps() and isinstance(t, str) and (apps.get(a) or {}).get("tunnel") != t:
            (changed if client.set_app_tunnel(a, t) else failed).append("app:" + a)
    return changed, failed


def record_history(tunnel_status):
    """Appends this check's ping of every tunnel to the 24-hour history."""
    now = int(time.time())
    cutoff = now - HISTORY_HOURS * 3600
    with STATE_LOCK:
        for code, st in tunnel_status.items():
            if st.get("unchecked"):
                continue
            ms = round(st["latency"]) if st["latency"] else None  # 0 means no site answered
            points = [p for p in HISTORY.get(code, []) if p[0] >= cutoff]
            points.append([now, ms, bool(st["healthy"])])
            HISTORY[code] = points
        for code in [c for c in HISTORY if c not in tunnel_status and (not HISTORY[c] or HISTORY[c][-1][0] < cutoff)]:
            del HISTORY[code]
        try:
            save_json(HISTORY_FILE, HISTORY)
        except Exception as e:
            logger.debug(f"Could not save history: {e}")


def send_email_notification(subject, body, verbose=False):
    """Sends an email notification via SMTP."""
    if not SMTP_ENABLED and not verbose:
        logger.debug("Email notification skipped: SMTP_ENABLED is false.")
        return False
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    recipients = [r.strip() for r in SMTP_TO.split(",") if r.strip()]
    if not SMTP_HOST:
        logger.error("Email notification error: SMTP_HOST is empty! Check .env")
        STATUS["last_email"] = {"time": now_str, "ok": False, "error": "не указан SMTP-сервер"}
        return False
    if not recipients:
        logger.error("Email notification error: SMTP_TO is empty! Check .env")
        STATUS["last_email"] = {"time": now_str, "ok": False, "error": "не указан адрес получателя"}
        return False

    logger.info(f"Connecting to SMTP {SMTP_HOST}:{SMTP_PORT} (SSL: {SMTP_USE_SSL}, user: {SMTP_USER})...")
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = SMTP_FROM
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if SMTP_USE_SSL or SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
            server.ehlo()
            server.starttls()
            server.ehlo()

        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)

        server.sendmail(SMTP_FROM, recipients, msg.as_string())
        server.quit()
        logger.info(f"Email notification successfully sent to {SMTP_TO}!")
        STATUS["last_email"] = {"time": now_str, "ok": True, "error": None}
        return True
    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")
        STATUS["last_email"] = {"time": now_str, "ok": False, "error": str(e)}
        return False


class DeeperClient:
    def __init__(self, host=DEEPER_HOST, username=DEEPER_USER, password=DEEPER_PASS, cookie_path=COOKIE_FILE):
        self.base_url = f"http://{host}"
        self.username = username
        self.password = password
        self.cookie_path = cookie_path
        self.cookie_jar = http.cookiejar.LWPCookieJar(self.cookie_path)
        if os.path.exists(self.cookie_path):
            try:
                self.cookie_jar.load(ignore_discard=True, ignore_expires=True)
            except Exception as e:
                logger.debug(f"Could not load cookies: {e}")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        # One API call at a time: the client is shared by comparison threads
        self._lock = threading.Lock()
        self._auth_checked_at = 0

    def _encrypt_password(self):
        """Encrypt password using RSA-OAEP SHA-1. Uses cryptography if present, else openssl CLI."""
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import serialization, hashes
            pub = serialization.load_pem_public_key(DEEPER_PUB_KEY.encode("utf-8"))
            encrypted = pub.encrypt(
                self.password.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode("utf-8")
        except ImportError:
            import tempfile
            with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
                tf.write(DEEPER_PUB_KEY)
                tf_path = tf.name
            try:
                p = subprocess.Popen(
                    ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", tf_path,
                     "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha1", "-pkeyopt", "rsa_mgf1_md:sha1"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                out, err = p.communicate(self.password.encode("utf-8"))
                if p.returncode != 0:
                    raise RuntimeError(f"OpenSSL encryption failed: {err.decode()}")
                return base64.b64encode(out).decode("utf-8")
            finally:
                if os.path.exists(tf_path):
                    try:
                        os.remove(tf_path)
                    except OSError:
                        pass

    def _request(self, endpoint, method="GET", payload=None):
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": "10.254.0.1"  # Anti-lockout safeguard
        }
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._lock, self.opener.open(req, timeout=12) as resp:
                text = resp.read().decode("utf-8")
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return text
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            raise RuntimeError(f"HTTP {e.code}: {body}")

    def ensure_authenticated(self):
        """Validate existing session or login if needed."""
        # Re-validate at most once a minute instead of before every API call
        if time.time() - self._auth_checked_at < 60:
            return True
        try:
            res = self._request("/api/admin/validateToken", method="POST")
            if isinstance(res, dict) and res.get("success"):
                self._auth_checked_at = time.time()
                return True
        except Exception:
            pass

        logger.info("Session invalid or expired. Authenticating with Deeper Connect...")
        enc_pass = self._encrypt_password()
        payload = {"username": self.username, "password": enc_pass}
        res = self._request("/api/admin/login", method="POST", payload=payload)
        if isinstance(res, dict) and res.get("success"):
            logger.info("Authentication successful!")
            self._auth_checked_at = time.time()
            try:
                cookie_dir = os.path.dirname(self.cookie_path)
                if cookie_dir and not os.path.exists(cookie_dir):
                    os.makedirs(cookie_dir, exist_ok=True)
                self.cookie_jar.save(ignore_discard=True, ignore_expires=True)
            except Exception as e:
                logger.debug(f"Could not save cookies: {e}")
            return True
        else:
            raise RuntimeError(f"Login failed: {res}")

    def _api(self, endpoint, method="GET", payload=None):
        """Authenticated API call; logs in again once if the session turned out to be invalid."""
        self.ensure_authenticated()
        try:
            return self._request(endpoint, method, payload)
        except RuntimeError as e:
            if not str(e).startswith(("HTTP 401", "HTTP 403")):
                raise
            self._auth_checked_at = 0
            self.ensure_authenticated()
            return self._request(endpoint, method, payload)

    def list_tunnels(self):
        return self._api("/api/smartRoute/listTunnels")

    def get_routed_domains(self):
        """Fetches smart-routed domains from Deeper Connect to use as live canaries."""
        try:
            items = self.get_whitelist_domains()
        except Exception as e:
            logger.debug(f"Could not auto-discover domains: {e}")
            return {}
        grouped = {}
        for item in items:
            tc = item.get("tunnelCode")
            dname = item.get("domainName")
            if tc and dname:
                grouped.setdefault(tc, []).append(f"https://{dname}")
        # Cache for the web UI
        ROUTES["whitelist"] = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in items]
        ROUTES["routed"] = grouped
        return grouped

    def get_whitelist_domains(self):
        """Returns all Smart Route domain rules as a list of {domainName, tunnelCode, ...}."""
        items, page = [], 1
        while True:
            data = self._api(f"/api/smartRoute/getRoutingWhitelist/domain?pageNo={page}&pageSize=100")
            batch = (data.get("list") or []) if isinstance(data, dict) else []
            items += batch
            if len(batch) < 100 or len(items) >= data.get("total", 0):
                return items
            page += 1

    def get_domain_route(self, domain):
        """Returns the tunnel code a domain is actually routed through (None if unknown)."""
        query = urllib.parse.urlencode({"routingAddress": domain})
        res = self._api(f"/api/smartRoute/getRoutingRecord/domain?{query}")
        return res.get("tunnelCode") if isinstance(res, dict) else None

    def move_domain(self, domain, from_tunnel, to_tunnel):
        """Moves a Smart Route domain rule to another tunnel. Returns True on success."""
        logger.info(f"Перенос маршрута {domain}: {from_tunnel} -> {to_tunnel}")
        payload = {"domainName": domain, "fromTunnelCode": from_tunnel, "toTunnelCode": to_tunnel}
        res = self._api("/api/smartRoute/editWhiteEntry/domain", method="POST", payload=payload)
        return isinstance(res, dict) and bool(res.get("success"))

    def add_domain(self, domain, tunnel):
        """Adds a Smart Route domain rule. Returns True on success."""
        logger.info(f"Добавление маршрута {domain} -> {tunnel}")
        res = self._api("/api/smartRoute/addToWhitelist/domain", method="POST",
                        payload={"domainName": domain, "tunnelCode": tunnel})
        return isinstance(res, dict) and bool(res.get("success"))

    def delete_domains(self, domains):
        """Deletes Smart Route domain rules. Returns True on success."""
        logger.info(f"Удаление маршрутов: {', '.join(domains)}")
        res = self._api("/api/smartRoute/deleteFromWhitelist/domain", method="POST", payload=list(domains))
        return isinstance(res, dict) and bool(res.get("success"))

    def get_apps(self):
        """App Relocator apps: {appName: {"tunnel", "website", "recommendedTunnels", ...}}."""
        data = self._api("/api/appRelocator/appsData")
        return (data.get("apps") or {}) if isinstance(data, dict) else {}

    def set_app_tunnel(self, app, tunnel):
        """Routes an App Relocator app through a tunnel ("ZZ" = direct). Returns True on success."""
        logger.info(f"Перемещение приложения {app} -> {tunnel}")
        if tunnel == "ZZ":
            res = self._api("/api/appRelocator/delApp", method="POST", payload={"appName": app})
        else:
            res = self._api("/api/appRelocator/addApp", method="POST", payload={"appName": app, "tunnelCode": tunnel})
        return isinstance(res, dict) and bool(res.get("success"))

    def move_item(self, key, from_tunnel, to_tunnel):
        """Moves a comparison item: a Smart Route domain, or an "app:<name>" App Relocator app."""
        if key.startswith("app:"):
            return self.set_app_tunnel(key[4:], to_tunnel)
        return self.move_domain(key, from_tunnel, to_tunnel)

    def refresh_apps_cache(self, tunnels=None):
        """Caches configured apps and available tunnels for the web UI."""
        apps = self.get_apps()
        ROUTES["apps"] = [{"app": a, "tunnel": apps[a].get("tunnel"), "website": apps[a].get("website"),
                           "recommended": apps[a].get("recommendedTunnels") or []}
                          for a in configured_apps() if a in apps]
        tunnels = tunnels if tunnels is not None else self.list_tunnels()
        ROUTES["all_tunnels"] = [{"code": t.get("tunnelCode"), "nodes": t.get("activeNum", 0), "ip": t.get("activeIp")}
                                 for t in tunnels]
        return apps

    def switch_node(self, tunnel_code, current_ip):
        """Switches to another active peer node in this tunnel's pool."""
        country = COUNTRY_NAMES.get(tunnel_code, tunnel_code)
        logger.info(f"Switching node for tunnel [{tunnel_code} - {country}] (Current IP: {current_ip})...")
        payload = {"tunnelCode": tunnel_code, "currentIp": current_ip}
        return self._api("/api/smartRoute/switchNode", method="POST", payload=payload)

    def refresh_tunnel(self, tunnel_code):
        """Re-discovers and rebuilds tunnel node candidates."""
        country = COUNTRY_NAMES.get(tunnel_code, tunnel_code)
        logger.info(f"Rebuilding tunnel candidates for [{tunnel_code} - {country}]...")
        payload = {"tunnelCode": tunnel_code}
        return self._api("/api/smartRoute/refreshTunnel", method="POST", payload=payload)


_SHARED = {"params": None, "client": None}
_SHARED_LOCK = threading.Lock()


def shared_client():
    """One Deeper session for the web UI, the node watcher and comparisons instead of a login check per
    request. A new one when the address, login or password changes in the settings."""
    with _SHARED_LOCK:
        params = (DEEPER_HOST, DEEPER_USER, DEEPER_PASS)
        if _SHARED["params"] != params:
            _SHARED.update(params=params, client=DeeperClient(host=DEEPER_HOST, username=DEEPER_USER, password=DEEPER_PASS))
        return _SHARED["client"]


def test_url_latency(url, timeout=3.5):
    """Measures HTTP response time in ms. Returns (latency_ms, status_or_error)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            lat = (time.time() - t0) * 1000.0
            return lat, resp.status
    except urllib.error.HTTPError as e:
        lat = (time.time() - t0) * 1000.0
        return lat, e.code
    except Exception as e:
        return None, str(e)


def check_tunnel_health(tunnel_code, canaries=None, max_latency_ms=None):
    """Tests canaries for the given tunnel code. Returns (is_healthy, avg_lat, details)."""
    if max_latency_ms is None:
        max_latency_ms = MAX_LATENCY_MS
    endpoints = canaries or FALLBACK_CANARIES.get(tunnel_code, [])
    if not endpoints:
        return True, 0, "No canaries configured"

    def measure_once():
        # All sites at once, so a check takes as long as the slowest site instead of their sum
        with ThreadPoolExecutor(max_workers=len(endpoints)) as pool:
            return list(pool.map(lambda ep: test_url_latency(ep, timeout=LATENCY_TIMEOUT), endpoints))

    def summary(measured):
        lats = [lat for lat, _ in measured if lat is not None]
        return lats and sum(lats) / len(lats) <= max_latency_ms

    measured = measure_once()
    retried = False
    if not summary(measured):
        # One slow answer is often just noise: measure again and keep each site's better result
        retried = True
        again = measure_once()
        measured = [min((m for m in pair if m[0] is not None), key=lambda m: m[0], default=pair[1])
                    for pair in zip(measured, again)]

    results = []
    latencies = []
    for ep, (lat, status) in zip(endpoints, measured):
        SITE_RESULTS[f"{tunnel_code} {ep}"] = {"url": ep, "tunnel": tunnel_code, "latency": lat, "status": status,
                            "ok": lat is not None, "time": time.strftime("%H:%M:%S")}
        if lat is not None:
            latencies.append(lat)
            results.append(f"{ep}: {lat:.0f}ms (HTTP {status})")
        else:
            results.append(f"{ep}: FAIL ({status})")

    note = " (после повторного замера)" if retried else ""
    if not latencies:
        return False, 0, "All canaries failed" + note + ": " + "; ".join(results)

    avg_lat = sum(latencies) / len(latencies)
    if avg_lat > max_latency_ms:
        return False, avg_lat, f"High latency ({avg_lat:.0f}ms > {max_latency_ms}ms){note}: " + "; ".join(results)

    return True, avg_lat, f"OK ({avg_lat:.0f}ms): " + "; ".join(results)


def tunnel_services(client, code):
    """Services and apps routed through a tunnel: [(key, move_to)]. A service with any domain there counts."""
    rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
    items = [(g["key"], group_mover(client, g)[0]) for g in service_groups(rules)
             if any(d["tunnel"] == code for d in g["domains"])]
    apps = client.get_apps()
    items += [("app:" + a, lambda t, a=a: client.set_app_tunnel(a, t))
              for a in configured_apps() if (apps.get(a) or {}).get("tunnel") == code]
    return items


def failover_target(key, empty_code, tunnels):
    """The best tunnel with nodes for a service leaving an empty one: working, faster, more nodes."""
    blocked = blocked_tunnel(key)
    usable = [t for t in tunnels if t.get("activeNum", 0) > 0 and t.get("tunnelCode") not in (empty_code, blocked)]

    def rank(t):
        st = STATUS["tunnels"].get(t["tunnelCode"]) or {}
        known = st.get("latency") and not st.get("unchecked")
        return (not st.get("healthy", True), st["latency"] if known else 10 ** 6, -t.get("activeNum", 0))
    return min(usable, key=rank)["tunnelCode"] if usable else None


def wait_for_nodes(client, code, seconds):
    """Waits up to `seconds` for the tunnel to get nodes. Returns True if it has them."""
    end = time.time() + seconds
    while True:
        t = get_tunnel(client, code)
        if t is None or t.get("activeNum", 0) > 0:
            return True
        if time.time() >= end:
            return False
        time.sleep(5)


def evacuate(client, code, only=None, reason=""):
    """Moves services (all, or only the given keys) out of a tunnel without nodes. Returns the moved keys."""
    prev = ACTIONS.get(code)
    set_action(code, "Перенос сервисов в туннели с нодами…")
    try:
        with MOVE_LOCK:
            return _evacuate(client, code, only, reason)
    finally:
        set_action(code, prev and prev["text"])


def _evacuate(client, code, only, reason):
    tunnels = client.list_tunnels()
    moved, failed = [], []
    for key, move_to in tunnel_services(client, code):
        if only is not None and key not in only:
            continue
        target = failover_target(key, code, tunnels)
        if target is None:
            failed.append(key.split(":", 1)[1])
            continue
        if move_to(target):
            with STATE_LOCK:
                first = AUTO_STATE["evacuated"].get(key, {}).get("from", code)  # Moved twice: return to the first one
                AUTO_STATE["evacuated"][key] = {"from": first, "to": target, "since": time.strftime("%Y-%m-%d %H:%M:%S")}
                AUTO_STATE["probation"].pop(key, None)  # Not auto mode's doing: nothing to roll back
            moved.append(f"{key.split(':', 1)[1]} → {target}")
        else:
            failed.append(key.split(":", 1)[1])
    # Services that can't go anywhere are reported once per outage, not on every retry
    if failed and not moved and set(failed) <= EVAC_NOTIFIED.get(code, set()):
        return moved
    EVAC_NOTIFIED[code] = EVAC_NOTIFIED.get(code, set()) | set(failed)
    if moved or failed:
        save_auto_state()
        text = f"{code}: нет нод{reason}. " + (f"Переехали: {', '.join(moved)}" if moved else "") \
            + (f"{'. ' if moved else ''}Не удалось перенести: {', '.join(failed)}" if failed else "")
        logger.warning(text)
        log_event("bad" if failed else "warn", text)
        notify("no_nodes", f"[Deeper Connect] В туннеле {COUNTRY_NAMES.get(code, code)} нет нод", text + "\n")
        client.get_routed_domains()
        client.refresh_apps_cache()
    return moved


def failover_empty_tunnels(client, tunnels):
    """Tunnels with 0 nodes that still carry services: wait FAILOVER_WAIT seconds, then move everything out.
    Only for a single run: in daemon mode the node watcher does it without holding up the check."""
    if not FAILOVER_EMPTY or WATCHER_ON:
        return
    for t in tunnels:
        code = t.get("tunnelCode")
        if t.get("activeNum", 0) > 0 or not code or not tunnel_services(client, code):
            continue
        logger.warning(f"В туннеле {code} 0 нод, жду до {FAILOVER_WAIT} с...")
        set_action(code, f"Нет нод, жду до {FAILOVER_WAIT} с…")
        try:
            if not wait_for_nodes(client, code, FAILOVER_WAIT):
                evacuate(client, code, reason=f" дольше {FAILOVER_WAIT} с")
        finally:
            set_action(code)


def return_evacuated(client):
    """Brings services back to their tunnel once it has nodes again and its check passes."""
    if not FAILOVER_RETURN or not AUTO_STATE["evacuated"]:
        return
    with MOVE_LOCK:
        _return_evacuated(client)


def _return_evacuated(client):
    nodes = {t.get("tunnelCode"): t.get("activeNum", 0) for t in client.list_tunnels()}
    prefs = preferred_tunnels()
    # A tunnel removed from Deeper never gets nodes again: its services stay where they are now
    gone = [(k, e) for k, e in AUTO_STATE["evacuated"].items() if nodes and e["from"] not in nodes and k not in prefs]
    for key, e in gone:
        AUTO_STATE["evacuated"].pop(key, None)
        log_event("info", f"{key.split(':', 1)[1]}: туннеля {e['from']} больше нет в Deeper, остаётся в {e['to']}")
    if gone:
        save_auto_state()
    due = [(k, e) for k, e in AUTO_STATE["evacuated"].items() if k not in prefs  # Those go back in enforce_preferred
           and nodes.get(e["from"], 0) > 0 and (STATUS["tunnels"].get(e["from"]) or {}).get("healthy", True)]
    if not due:
        return
    rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
    groups = {g["key"]: g for g in service_groups(rules)}
    apps = client.get_apps() if any(k.startswith("app:") for k, _ in due) else {}
    for key, e in due:
        name = key.split(":", 1)[1]
        group = groups.get(key)
        now_in = (apps.get(name) or {}).get("tunnel") if key.startswith("app:") else group and group["main"]
        if now_in != e["to"]:
            AUTO_STATE["evacuated"].pop(key, None)  # Moved by hand or by auto mode meanwhile: leave it be
            continue
        if key.startswith("app:"):
            ok = client.set_app_tunnel(name, e["from"])
        else:
            ok = group_mover(client, group)[0](e["from"])
        if ok:
            AUTO_STATE["evacuated"].pop(key, None)
            logger.info(f"{name} вернулся в {e['from']}: там снова есть ноды")
            log_event("ok", f"{name}: вернулся из {e['to']} в {e['from']}, там снова есть ноды", mail="nodes_back")
    save_auto_state()
    client.get_routed_domains()


PIN_RETRY = 300  # Seconds before retrying a move back to the preferred tunnel that Deeper refused
PIN_FAILED = {}  # key -> time of the last refused move back


def enforce_preferred(client, ready, only=None):
    """Services with a preferred tunnel go back to it as soon as it has nodes (`ready`: tunnel codes with
    nodes), whoever moved them away: a failover, a comparison that couldn't restore, Deeper's own app."""
    prefs = {k: c for k, c in preferred_tunnels().items() if c in ready and (only is None or k in only)}
    if not prefs or COMPARE["running"]:
        return
    with MOVE_LOCK:
        _enforce_preferred(client, prefs)


def _enforce_preferred(client, prefs):
    rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
    groups = {g["key"]: g for g in service_groups(rules)}
    apps = client.get_apps() if any(k.startswith("app:") for k in prefs) else {}
    changed = False
    for key, code in prefs.items():
        name = key.split(":", 1)[-1]
        if key.startswith("app:"):
            cur = (apps.get(name) or {}).get("tunnel")
            if cur is None or cur == code:
                continue
            move = lambda: client.set_app_tunnel(name, code)
        else:
            g = groups.get(key)
            if g is None or (not g["split"] and g["main"] == code):
                continue
            cur = " / ".join(sorted(g["tunnels"]))
            move = lambda g=g: group_mover(client, g)[0](code)
        if time.time() - PIN_FAILED.get(key, 0) < PIN_RETRY:
            continue
        evac = AUTO_STATE["evacuated"].get(key)
        if move():
            PIN_FAILED.pop(key, None)
            with STATE_LOCK:
                AUTO_STATE["evacuated"].pop(key, None)
            changed = True
            logger.info(f"{name}: {cur} -> предпочтительный туннель {code}")
            log_event("ok", f"{name}: вернулся из {cur} в {code}, там снова есть ноды" if evac and evac.get("from") == code
                      else f"{name}: перенесён из {cur} в предпочтительный туннель {code}", mail="nodes_back")
        else:
            PIN_FAILED[key] = time.time()
            log_event("bad", f"{name}: не удалось вернуть в предпочтительный туннель {code}, повтор через {PIN_RETRY // 60} мин", mail="rollback")
    if changed:
        save_auto_state()
        client.get_routed_domains()
        client.refresh_apps_cache()


def priority_keys():
    return {k.strip() for k in FAILOVER_PRIORITY.split(",") if k.strip()}


def get_tunnel(client, code):
    """Returns the current tunnel record for code, or None."""
    try:
        return next((t for t in client.list_tunnels() if t.get("tunnelCode") == code), None)
    except Exception:
        return None


def refresh_and_wait(client, code, country, active_ip, active_num):
    """Rebuilds the tunnel pool and waits for a new IP. Returns (success, new_ip, new_pool)."""
    set_action(code, "Перестроение туннеля…")
    try:
        return _refresh_and_wait(client, code, country, active_ip, active_num)
    finally:
        set_action(code)


def _refresh_and_wait(client, code, country, active_ip, active_num):
    new_ip, new_pool = "не изменился", active_num
    # В веб-интерфейсе Deeper Connect туннель при этом сбрасывается до 0 и строится заново
    res = client.refresh_tunnel(code)
    logger.info(f"Результат refresh_tunnel: {res}")
    if not (isinstance(res, dict) and res.get("success")):
        return False, new_ip, new_pool

    started = time.time()
    logger.info(f"Ожидание перестроения туннеля [{country}] в Deeper Connect...")
    match = None
    set_action(code, "Перестроение туннеля: жду новые ноды…")
    for _ in range(REBUILD_WAIT // 2):
        time.sleep(2)
        match = get_tunnel(client, code)
        if match:
            live_pool(code, match)
        if match and match.get("activeIp") and match.get("activeNum", 0) > 0 and match.get("activeIp") != active_ip:
            new_ip, new_pool = match.get("activeIp"), match.get("activeNum")
            logger.info(f"Туннель [{country}] перестроен: новый IP {new_ip} (пул: {new_pool})")
            break
    if match is not None and match.get("activeNum", 0) == 0:
        new_pool = 0
    # Still no nodes after the rebuild: priority services don't wait for the next check
    if new_pool == 0 and priority_keys():
        set_action(code, f"После перестроения нет нод, жду до {FAILOVER_WAIT} с…")
        if not wait_for_nodes(client, code, max(0, FAILOVER_WAIT - (time.time() - started))):
            evacuate(client, code, only=priority_keys(), reason=f" через {FAILOVER_WAIT} с после перестроения")
        else:
            match = get_tunnel(client, code) or {}
            new_ip, new_pool = match.get("activeIp") or new_ip, match.get("activeNum", new_pool)
    return True, new_ip, new_pool


def verify_tunnel(code, canaries, max_latency_ms):
    """Runs VERIFY_CHECKS checks in a row. Healthy if most of them pass. Returns (ok, summary)."""
    passed = 0
    for i in range(VERIFY_CHECKS):
        if i:
            time.sleep(VERIFY_PAUSE)
        ok, _, details = check_tunnel_health(code, canaries=canaries, max_latency_ms=max_latency_ms)
        passed += ok
        logger.info(f"    Проверка {i + 1}/{VERIFY_CHECKS}: {'OK' if ok else 'СБОЙ'} -> {details}")
    return passed * 2 > VERIFY_CHECKS, f"успешных проверок {passed} из {VERIFY_CHECKS}"


def fmt_ms(ms):
    return f"{ms:.0f} мс" if ms is not None else "нет ответа"


def measure_site(url, samples):
    """Measures a site several times in a row. Returns (median_ms or None if any attempt failed, last_status)."""
    lats, status = [], None
    for _ in range(samples):
        lat, status = test_url_latency(url, timeout=LATENCY_TIMEOUT)
        if lat is None:
            return None, status
        lats.append(lat)
    return sorted(lats)[len(lats) // 2], status


def pick_better_tunnel(pings, original):
    """Returns a tunnel noticeably faster than the original one, or None."""
    base = pings.get(original, {})
    base_ms, base_status = base.get("ms"), base.get("status")

    def usable(p):
        # An HTTP error that the original tunnel didn't have usually means a geo-block
        geo_blocked = isinstance(p["status"], int) and p["status"] >= 400 and isinstance(base_status, int) and base_status < 400
        return p["ms"] is not None and not geo_blocked

    candidates = [t for t, p in pings.items() if t != original and usable(p)]
    if not candidates:
        return None
    best = min(candidates, key=lambda t: pings[t]["ms"])
    best_ms = pings[best]["ms"]
    if base_ms is None:
        return best
    if best_ms <= base_ms * (1 - AUTO_MIN_GAIN_PCT / 100) and base_ms - best_ms >= AUTO_MIN_GAIN_MS:
        return best
    return None


def measure_urls(urls, samples):
    """Measures several URLs of one service at once.
    Returns (average of the answering ones or None, a status, how many answered)."""
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        results = list(pool.map(lambda u: measure_site(u, samples), urls))
    answered = [ms for ms, _ in results if ms is not None]
    status = next((st for ms, st in results if ms is not None), results[0][1] if results else None)
    return (sum(answered) / len(answered) if answered else None), status, len(answered)


def fastest_tunnel(pings):
    """The tunnel where most of the service answers, and among those the lowest average ping."""
    usable = [t for t, p in pings.items() if p["ms"] is not None]
    return min(usable, key=lambda t: (-pings[t].get("answered", 1), pings[t]["ms"])) if usable else None


def finish_item(key, base, split, pings, error, auto, urls, move_to, restore, moved):
    """After a comparison: restores the service with restore(), or, if it is ticked for auto mode,
    leaves it united in the best tunnel with move_to(tunnel). Returns the result for the web UI."""
    # A split service has no current tunnel to stick to: it goes where the average ping is lowest.
    # A tunnel auto mode had to roll back from is skipped for a day
    blocked = blocked_tunnel(key)
    candidates = {t: p for t, p in pings.items() if t != blocked or t == base}
    if error:
        recommended = None
    elif split:
        recommended = fastest_tunnel(candidates)
    else:
        recommended = pick_better_tunnel(candidates, base)
    final = "split" if split else base
    try:
        if key in auto and not error:
            # Auto mode always leaves the service united: in the faster tunnel, or in its current one
            target = recommended or base
            if move_to(target):
                final = target
            elif not restore():
                error = "не удалось вернуть маршрут"
        elif moved:
            if not restore():
                error = error or "не удалось вернуть маршрут"
    except Exception as e:
        error = error or str(e)
    if error:
        logger.error(f"{key}: {error}")

    if final not in ("split", base) or (split and final != "split"):
        logger.info(f"Авторежим: {key} собран в туннеле {final}")
        name = key.split(':', 1)[1]
        base_ms = (pings.get(base) or {}).get("ms")
        log_event("ok", f"{name}: " + (f"собран в {final}" if split else f"перенесён {base} → {final}")
                  + f", {fmt_ms(pings[final]['ms'])}" + (f" вместо {fmt_ms(base_ms)}" if base_ms and not split else ""))
        if final != base:
            start_probation(key, base, final, urls)
        notify(
            "auto", f"[Deeper Connect] {key.split(':', 1)[1]} перенесён в туннель {COUNTRY_NAMES.get(final, final)}",
            f"Авторежим перенёс {key.split(':', 1)[1]}: {'разные туннели' if split else base} -> {final}\n\n"
            + "".join(f"{t}: {fmt_ms(p['ms'])} ({p['status']})\n" for t, p in pings.items())
        )
    return {"domain": key, "original": base, "split": split, "final": final, "pings": pings,
            "recommended": recommended, "auto": key in auto, "error": error}


def group_mover(client, group):
    """move_to/restore callbacks that move every domain of a service group."""
    originals = {d["domain"]: d["tunnel"] for d in group["domains"]}
    current = dict(originals)

    def move_all(target_of):
        ok = True
        for d in current:
            to = target_of(d)
            if current[d] != to:
                if client.move_domain(d, current[d], to):
                    current[d] = to
                else:
                    ok = False
        return ok

    return (lambda t: move_all(lambda d: t)), (lambda: move_all(lambda d: originals[d]))


def compare_routes(client, keys):
    """Compares the given services ("group:<name>") and apps ("app:<name>"), all of them if the list is empty,
    several at a time."""
    rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
    groups = {g["key"]: g for g in service_groups(rules)}
    apps = client.get_apps()
    tunnels = [t.get("tunnelCode") for t in client.list_tunnels() if t.get("activeNum", 0) > 0]
    if MONITOR_TUNNELS:
        tunnels = [t for t in tunnels if t in MONITOR_TUNNELS]

    auto = auto_route_domains() | auto_group_keys(groups.values())

    jobs = {}
    for key, g in groups.items():
        move_to, restore = group_mover(client, g)
        urls = [f"https://{d['domain']}" for d in g["domains"][:COMPARE_GROUP_DOMAINS]]
        jobs[key] = (g["main"], g["split"], urls, move_to, restore)
    for a in configured_apps():
        info = apps.get(a) or {}
        if info.get("website"):
            orig = info.get("tunnel")
            jobs["app:" + a] = (orig, False, [info["website"]],
                                lambda t, a=a: client.set_app_tunnel(a, t), lambda a=a, orig=orig: client.set_app_tunnel(a, orig))

    # Plain domains (older clients) select their service group
    wanted = []
    for k in keys or jobs:
        if k not in jobs:
            k = next((g["key"] for g in groups.values() if any(d["domain"] == k for d in g["domains"])), k)
        if k in jobs and k not in wanted:
            wanted.append(k)
    # Tunnel by tunnel instead of service by service: every service is moved into a tunnel, the routes settle
    # once, and all of them are measured together. Far fewer waits than moving and measuring each one alone
    pings, errors, moved = {k: {} for k in wanted}, {}, set()
    phases = len(tunnels) + 1

    def measure(key, tunnel):
        urls = jobs[key][2]
        try:
            ms, status, answered = measure_urls(urls, COMPARE_SAMPLES)
        except Exception as e:
            ms, status, answered = None, str(e), 0
        logger.info(f"Сравнение {key} через {tunnel}: {fmt_ms(ms)} в среднем, ответили {answered} из {len(urls)} ({status})")
        pings[key][tunnel] = {"ms": ms, "status": status, "answered": answered, "total": len(urls)}

    def measure_all(keys, tunnel_of):
        # All at once: a few small requests per service, so they don't get in each other's way
        if keys:
            with ThreadPoolExecutor(max_workers=min(COMPARE_MEASURE_WORKERS, len(keys))) as pool:
                list(pool.map(lambda k: measure(k, tunnel_of(k)), keys))

    if wanted:
        # Each tunnel in turn. Services already in it are measured in place, together with the moved ones;
        # services in a tunnel that isn't compared (e.g. an app going directly) are measured in the first round
        for n, t in enumerate(tunnels, 1):
            COMPARE.update(progress=f"{n} из {phases}", stage=f"{t}: перенос")
            stay = [k for k in wanted if not jobs[k][1] and k not in moved
                    and (jobs[k][0] == t or (n == 1 and jobs[k][0] not in tunnels))]
            todo = [k for k in wanted if k not in errors and k not in stay]
            ready = []
            for i, k in enumerate(todo, 1):
                COMPARE["stage"] = f"{t}: перенос {i} из {len(todo)}"
                moved.add(k)
                try:
                    if jobs[k][3](t):
                        ready.append(k)
                    else:
                        pings[k][t] = {"ms": None, "status": "не удалось переключить"}
                except Exception as e:
                    errors[k] = str(e)
                    logger.error(f"Ошибка сравнения {k}: {e}")
            if ready:
                COMPARE["stage"] = f"{t}: ждём применения маршрутов"
                time.sleep(ROUTE_SETTLE)
            COMPARE["stage"] = f"{t}: замер {len(ready) + len(stay)}"
            measure_all(ready + stay, lambda k: t if k in ready else jobs[k][0])

        # Back where they were, or into the best tunnel for auto mode
        COMPARE.update(progress=f"{phases} из {phases}", stage="Возврат маршрутов")
        for k in wanted:
            base, split, urls, move_to, restore = jobs[k]
            COMPARE["results"].append(finish_item(k, base, split, pings[k], errors.get(k), auto, urls,
                                                  move_to, restore, k in moved))
    client.get_routed_domains()  # Refresh cached rules for the web UI
    client.refresh_apps_cache()


def measure_services():
    """Pings the main domain of every service once, for its status on the overview.
    Not on every check: it doesn't affect tunnel health and would only make checks longer."""
    if time.time() - SERVICES_MEASURED["at"] < SERVICES_EVERY:
        return
    SERVICES_MEASURED["at"] = time.time()
    groups = service_groups(ROUTES["whitelist"])
    if not groups:
        SERVICE_RESULTS.clear()
        return
    urls = [f"https://{g['domains'][0]['domain']}" for g in groups]
    with ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
        measured = list(pool.map(lambda u: test_url_latency(u, timeout=LATENCY_TIMEOUT), urls))
    SERVICE_RESULTS.clear()
    for g, u, (lat, status) in zip(groups, urls, measured):
        SERVICE_RESULTS[g["key"]] = {"name": g["name"], "tunnel": "split" if g["split"] else g["main"], "url": u,
                                     "latency": lat, "status": status, "ok": lat is not None}


def start_probation(key, previous, new, urls):
    """Remembers an auto move so it can be undone if the service stops working in the new tunnel."""
    with STATE_LOCK:
        AUTO_STATE["probation"][key] = {"from": previous, "to": new, "urls": urls[:3], "good": 0, "bad": 0,
                                        "since": time.strftime("%Y-%m-%d %H:%M:%S")}
    save_auto_state()


def end_probation(key):
    """A manual move: the user decides, auto mode stops watching and avoiding tunnels for this service."""
    with STATE_LOCK:
        changed = [AUTO_STATE["probation"].pop(key, None), AUTO_STATE["blocked"].pop(key, None),
                   AUTO_STATE["evacuated"].pop(key, None)] != [None, None, None]
    if changed:
        save_auto_state()


def check_probation(client):
    """Checks services auto mode moved recently; moves one back after ROLLBACK_FAILS bad checks in a row."""
    probation = AUTO_STATE["probation"]
    if not probation:
        return
    nodes = {t.get("tunnelCode"): t.get("activeNum", 0) for t in client.list_tunnels()}
    for key, p in list(probation.items()):
        ms, status, answered = measure_urls(p["urls"], 1)
        bad = ms is None or ms > MAX_LATENCY_MS
        p["bad"], p["good"] = (p["bad"] + 1, 0) if bad else (0, p["good"] + 1)
        name = key.split(":", 1)[1]
        if bad and p["bad"] >= ROLLBACK_FAILS and AUTO_ROLLBACK and not nodes.get(p["from"]):
            p["bad"] = 0  # Nowhere to go back to: the previous tunnel has no nodes now
            logger.info(f"Автоперенос {name}: в {p['from']} нет нод, откат отложен")
        elif bad and p["bad"] >= ROLLBACK_FAILS and AUTO_ROLLBACK:
            logger.warning(f"Автоперенос {name} в {p['to']} не прижился ({fmt_ms(ms)}, {status}), возвращаю в {p['from']}")
            if key.startswith("app:"):
                ok = client.set_app_tunnel(name, p["from"])
            else:
                rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
                group = next((g for g in service_groups(rules) if g["key"] == key), None)
                ok = group is not None and group_mover(client, group)[0](p["from"])
            with STATE_LOCK:
                probation.pop(key, None)
                AUTO_STATE["blocked"][key] = {"tunnel": p["to"], "until": time.time() + BLOCK_HOURS * 3600}
            if ok:
                log_event("bad", f"{name}: в {p['to']} не работает ({fmt_ms(ms) if ms else 'нет ответа'}), возвращён в {p['from']}. "
                                 f"Сутки авторежим не будет переносить его в {p['to']}")
                notify(
                    "rollback", f"[Deeper Connect] {name} возвращён в туннель {COUNTRY_NAMES.get(p['from'], p['from'])}",
                    f"Авторежим переносил {name}: {p['from']} -> {p['to']}, но в {p['to']} он не работает "
                    f"({fmt_ms(ms) if ms else 'нет ответа'}, {status}).\nВозвращён в {p['from']}.\n")
            else:
                log_event("bad", f"{name}: не удалось вернуть из {p['to']} в {p['from']}", mail="rollback")
            client.get_routed_domains()
        elif p["good"] >= PROBATION_CHECKS:
            with STATE_LOCK:
                probation.pop(key, None)
            logger.info(f"Автоперенос {name} в {p['to']} подтверждён")
    save_auto_state()


def scheduled_compare():
    """Once a day, at AUTO_COMPARE_HOUR, compares the auto-mode services. A comparison missed because the
    server was off (or busy) at that hour runs at the first check after it is back."""
    if AUTO_COMPARE_HOUR < 0 or COMPARE["running"]:
        return
    now = time.localtime()
    # The last moment a comparison was due: today at the hour, or yesterday if that hour hasn't come yet
    due = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, AUTO_COMPARE_HOUR, 0, 0, 0, 0, -1))
    if now.tm_hour < AUTO_COMPARE_HOUR:
        due -= 86400
    if scheduled_last() >= due:
        return
    groups = service_groups(ROUTES["whitelist"])
    auto = auto_route_domains()
    keys = sorted(auto_group_keys(groups) | {k for k in auto if k.startswith("app:") and k[4:] in configured_apps()})
    if keys and not start_compare(keys):
        return
    late = time.time() - due > 3 * 3600
    AUTO_STATE["last_scheduled"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_auto_state()
    if keys:
        text = f"{'Пропущенное ночью' if late else 'Плановое'} сравнение сервисов с «Авто»: {len(keys)}"
        logger.info(text)
        log_event("info", text)


def scheduled_last():
    """When the last daily comparison ran (older files keep only its date: counted as that day at the hour)."""
    last = AUTO_STATE.get("last_scheduled") or ""
    for fmt, hour in (("%Y-%m-%d %H:%M:%S", None), ("%Y-%m-%d", AUTO_COMPARE_HOUR)):
        try:
            ts = time.mktime(time.strptime(last, fmt))
            return ts + (hour or 0) * 3600
        except ValueError:
            pass
    return 0


GAIN_TRIED = {}  # auto-mode service -> when a comparison was last started because another tunnel looked faster


def gain_compare():
    """After a check: an auto-mode service whose ping is worse than another working tunnel's by the auto-move
    thresholds (or that doesn't answer) is compared right away instead of waiting for the daily comparison.
    The comparison measures the service itself in every tunnel and moves it only if that is really faster."""
    if not AUTO_GAIN_RECHECK or COMPARE["running"] or STATUS.get("all_slow"):
        return
    tunnels = {c: s["latency"] for c, s in STATUS["tunnels"].items()
               if s.get("healthy") and not s.get("unchecked") and s.get("pool") and s.get("latency")}
    if len(tunnels) < 2:
        return
    groups = service_groups(ROUTES["whitelist"])
    current = {k: (r["tunnel"], r["latency"]) for k, r in SERVICE_RESULTS.items()}
    current.update({"app:" + a: (r["tunnel"], r["latency"]) for a, r in APP_RESULTS.items()})
    keys = auto_group_keys(groups) | {k for k in auto_route_domains() if k.startswith("app:") and k[4:] in configured_apps()}
    now, todo, why = time.time(), [], []
    for k in sorted(keys):
        if k not in current or k in AUTO_STATE.get("probation", {}) or now - GAIN_TRIED.get(k, 0) < AUTO_GAIN_RECHECK * 60:
            continue
        tunnel, lat = current[k]
        others = {c: l for c, l in tunnels.items() if c != tunnel}
        if not others or tunnel == "split":
            continue
        best = min(others, key=others.get)
        if lat is None or (lat - others[best] >= AUTO_MIN_GAIN_MS and (lat - others[best]) * 100 >= AUTO_MIN_GAIN_PCT * lat):
            todo.append(k)
            why.append(f"{k.split(':', 1)[1]} ({tunnel} {fmt_ms(lat) if lat else 'нет ответа'}, {best} {fmt_ms(others[best])})")
    if todo and start_compare(todo):
        for k in todo:
            GAIN_TRIED[k] = now
        logger.info(f"Авторежим: другой туннель быстрее, сравниваю: {', '.join(why)}")
        log_event("info", f"Авто: похоже, в другом туннеле быстрее, сравниваю: {', '.join(why)}")


def auto_group_keys(groups):
    """Services in auto mode: "group:<name>", or (older settings) any domain of the group."""
    auto = auto_route_domains()
    return {g["key"] for g in groups if g["key"] in auto or any(d["domain"] in auto for d in g["domains"])}


def unite_auto_groups():
    """Starts a comparison for auto-mode services whose domains ended up in different countries:
    it measures them and puts every domain where the average ping is lowest."""
    split = sorted(g["key"] for g in service_groups(ROUTES["whitelist"])
                   if g["split"] and g["key"] in auto_group_keys([g]))
    if split and start_compare(split):
        logger.info(f"Авторежим: домены в разных странах, собираю: {', '.join(k[6:] for k in split)}")


def start_compare(domains):
    """Runs compare_routes in a background thread. Returns False if one is already running."""
    with COMPARE_START_LOCK:
        if COMPARE["running"]:
            return False
        COMPARE.update(running=True, progress="подготовка", stage="Подготовка", started=time.strftime("%Y-%m-%d %H:%M:%S"),
                       finished=None, error=None, results=[])

    def job():
        try:
            with ROUTE_LOCK:
                client = shared_client()
                backup_rules(client, "перед сравнением туннелей")
                compare_routes(client, domains)
        except Exception as e:
            logger.error(f"Ошибка сравнения туннелей: {e}")
            COMPARE["error"] = str(e)
        finally:
            COMPARE.update(running=False, progress="", stage="", finished=time.strftime("%Y-%m-%d %H:%M:%S"))

    threading.Thread(target=job, daemon=True).start()
    return True


def recover_tunnel(client, code, country, active_ip, active_num, canaries, max_latency_ms):
    """Runs the configured recovery action. Returns (success, new_ip, new_pool, action_taken, steps)."""
    new_pool = active_num
    new_ip = "не изменился"
    success = False
    steps = []
    if RECOVERY_ACTION == "smart":
        # Switch node up to SWITCH_ATTEMPTS times, verifying each one; rebuild if none helps.
        # Never more switches than other nodes in the pool, so we don't come back to the bad one.
        current_ip = active_ip
        attempts = min(SWITCH_ATTEMPTS, max(0, active_num - 1))
        for n in range(1, attempts + 1):
            set_action(code, f"Смена ноды {n} из {attempts}…")
            res = client.switch_node(code, current_ip)
            logger.info(f"Смена ноды {n}/{attempts}: {res}")
            if not (isinstance(res, dict) and res.get("success")):
                steps.append(f"Смена ноды {n}: ошибка ({res})")
                break
            time.sleep(VERIFY_PAUSE)
            match = get_tunnel(client, code) or {}
            current_ip = match.get("activeIp") or res.get("activeIp") or current_ip
            if match:
                live_pool(code, match)
            set_action(code, f"Проверка новой ноды {current_ip} ({n} из {attempts})…")
            ok, summary = verify_tunnel(code, canaries, max_latency_ms)
            steps.append(f"Смена ноды {n}: IP {current_ip}, {summary}")
            if ok:
                success, new_ip = True, current_ip
                new_pool = match.get("activeNum", active_num)
                action_taken = f"Смена ноды в пуле (помогла попытка {n} из {attempts})"
                break
        if not success:
            reason = "в пуле одна нода" if attempts == 0 else f"смена ноды не помогла (попыток: {len(steps)})"
            logger.warning(f"Туннель [{code} - {country}]: {reason}, перестроение туннеля...")
            success, new_ip, new_pool = refresh_and_wait(client, code, country, current_ip, active_num)
            success = success and bool(new_pool)  # Rebuilt into an empty pool: didn't help
            action_taken = f"Перестроение туннеля (rebuild tunnel), так как {reason}"
            steps.append(f"Перестроение туннеля: {'успешно' if success else 'ошибка'}, новый IP {new_ip}")
    elif RECOVERY_ACTION == "switch" and active_num > 1:
        set_action(code, "Смена ноды…")
        res = client.switch_node(code, active_ip)
        logger.info(f"Результат switch_node: {res}")
        action_taken = "Переключение на следующий узел в пуле (switch node)"
        if isinstance(res, dict) and res.get("success"):
            success = True
            new_ip = res.get("activeIp", "новый IP")
    else:
        # По умолчанию: полное перестроение пула (refresh/rebuild tunnel)
        # При этом в веб-интерфейсе Deeper Connect туннель сбрасывается до 0 и строится заново
        success, new_ip, new_pool = refresh_and_wait(client, code, country, active_ip, active_num)
        success = success and bool(new_pool)
        action_taken = "Полный перезапуск и перестроение туннеля (rebuild tunnel)"
    return success, new_ip, new_pool, action_taken, steps


def run_watchdog_iteration(client, max_latency_ms=None, state_file=STATE_FILE):
    """Executes a single monitoring cycle and repairs degraded tunnels."""
    if max_latency_ms is None:
        max_latency_ms = MAX_LATENCY_MS
    fails = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                fails = json.load(f)
        except Exception:
            pass

    STATUS["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        tunnels = client.list_tunnels()
    except Exception as e:
        logger.error(f"Failed to fetch tunnels from Deeper Connect: {e}")
        if not STATUS["error"]:  # Once per outage, not on every check
            log_event("bad", f"Deeper Connect недоступен: {e}", mail="errors")
        STATUS["error"] = f"Не удалось получить список туннелей: {e}"
        return
    if STATUS["error"]:
        log_event("ok", "Связь с Deeper Connect восстановлена", mail="errors")
    STATUS["error"] = None

    try:
        failover_empty_tunnels(client, tunnels)
    except Exception as e:
        logger.error(f"Ошибка переноса из пустого туннеля: {e}")
    routed_domains = client.get_routed_domains()  # After failover: rules may have moved

    # A tunnel added in Deeper joins monitoring by itself, also when the monitored list is set explicitly
    codes = [t.get("tunnelCode") for t in tunnels if t.get("tunnelCode")]
    seen = AUTO_STATE.get("seen_tunnels")
    new = [c for c in codes if seen is not None and c not in seen]
    if seen is None or new:
        AUTO_STATE["seen_tunnels"] = sorted(set(seen or []) | set(codes))
        save_auto_state()
    for c in new:
        if MONITOR_TUNNELS and c not in MONITOR_TUNNELS:
            save_settings({"MONITOR_TUNNELS": ",".join(MONITOR_TUNNELS + [c])})
        logger.info(f"Новый туннель {c} ({COUNTRY_NAMES.get(c, c)}) добавлен в проверку")
        log_event("info", f"Новый туннель {c} ({COUNTRY_NAMES.get(c, c)}) добавлен в проверку", mail="changes")

    # Filter tunnels if MONITOR_TUNNELS is specified
    active_tunnels = []
    for t in tunnels:
        code = t.get("tunnelCode")
        if not MONITOR_TUNNELS or code in MONITOR_TUNNELS:
            active_tunnels.append(t)

    logger.info(f"Checking {len(active_tunnels)} monitored tunnel(s) ({', '.join(t.get('tunnelCode') for t in active_tunnels)})...")

    ROUTES["tunnels"] = [t.get("tunnelCode") for t in active_tunnels]
    SITE_RESULTS.clear()
    # Each test site tests the tunnel its domain goes through right now (Smart Route or App Relocator)
    site_routes = {}
    for url in test_sites():
        host = urllib.parse.urlparse(url).hostname
        if host and host not in site_routes:
            try:
                site_routes[host] = client.get_domain_route(host)
            except Exception:
                site_routes[host] = None
    try:
        apps_now = client.get_apps()
    except Exception:
        apps_now = {}
    auto_sites = {}
    tunnel_status = {}
    fails_before = dict(fails)
    checked = []  # Measured tunnels: (code, country, ip, nodes, test sites, details), recovered after all are measured
    for t in active_tunnels:
        code = t.get("tunnelCode")
        country = COUNTRY_NAMES.get(code, code)
        active_ip = t.get("activeIp")
        active_num = t.get("activeNum", 0)

        # No nodes: nothing to measure, and a rebuild can't bring nodes back (failover moves the services)
        if active_num == 0:
            logger.warning(f"  [NO NODES] [{code} - {country}] нет активных нод")
            fails[code] = 0
            tunnel_status[code] = {"country": country, "ip": active_ip, "pool": 0, "healthy": False,
                                   "latency": 0, "details": "Нет активных нод", "fails": 0}
            publish_tunnel(code, tunnel_status[code])
            continue

        # Test sites going through this tunnel; without any, older per-tunnel settings or its own domains
        own = [u for u in test_sites() if site_routes.get(urllib.parse.urlparse(u).hostname) == code]
        canaries = list(own or CANARIES.get(code) or [])
        # One site says little: temporary ones top the tunnel up to SITES_PER_TUNNEL
        if len(canaries) < SITES_PER_TUNNEL:
            used = {(urllib.parse.urlparse(u).hostname or "").removeprefix("www.") for u in canaries}
            extra = own_domain_sites(client, code, routed_domains, site_routes, apps_now,
                                     limit=SITES_PER_TUNNEL - len(canaries), skip=used)
            if extra:
                auto_sites[code] = extra
                canaries += extra

        # Which tunnel each test site really goes through, so the UI can warn about mismatches
        for ep in canaries:
            host = urllib.parse.urlparse(ep).hostname
            if host and host not in site_routes:
                try:
                    site_routes[host] = client.get_domain_route(host)
                except Exception:
                    site_routes[host] = None
            if host and site_routes[host] and site_routes[host] != code:
                logger.warning(f"  Тестовый сайт {host} идёт через {site_routes[host]}, а не через {code}")
        ROUTES["site_routes"] = site_routes

        # Default test sites that all go through other tunnels say nothing about this one (e.g. a new tunnel
        # without any service in it): it isn't failed or rebuilt for their sake
        if not canaries:
            logger.info(f"  [SKIP] [{code} - {country}] через туннель не идёт ни один тестовый сайт, проверка пропущена")
            fails[code] = 0
            tunnel_status[code] = {"country": country, "ip": active_ip, "pool": active_num, "healthy": True,
                                   "unchecked": True, "latency": 0, "details": "", "fails": 0}
            publish_tunnel(code, tunnel_status[code])
            continue

        set_action(code, "Проверка…")
        try:
            healthy, lat, details = check_tunnel_health(code, canaries=canaries, max_latency_ms=max_latency_ms)
        finally:
            set_action(code)
        was = (STATUS["tunnels"].get(code) or {}).get("healthy")
        if was is True and not healthy:
            log_event("warn", f"{code}: проверка не прошла ({fmt_ms(lat) if lat else 'нет ответа'})", mail="check")
        elif was is False and healthy:
            log_event("ok", f"{code}: снова в норме, {fmt_ms(lat)}", mail="check")
        if healthy:
            logger.info(f"  [PASS] [{code} - {country}] (IP: {active_ip}, Pool: {active_num}) -> {details}")
            fails[code] = 0
        else:
            # Extra checks (a manual one, nodes coming back) don't bring a recovery closer: fails count
            # at most once per check interval, so FAIL_THRESHOLD means minutes, not seconds
            if time.time() - LAST_FAIL_AT.get(code, 0) >= CHECK_INTERVAL * 0.75:
                fails[code] = fails.get(code, 0) + 1
                LAST_FAIL_AT[code] = time.time()
            logger.warning(f"  [FAIL #{fails.get(code, 0)}] [{code} - {country}] (IP: {active_ip}) -> {details}")

        tunnel_status[code] = {
            "country": country, "ip": active_ip, "pool": active_num,
            "healthy": healthy, "latency": lat, "details": details, "fails": fails.get(code, 0),
            "sites": [{k: r[k] for k in ("url", "latency", "status")} for r in
                      (SITE_RESULTS.get(f"{code} {ep}") for ep in canaries) if r],
        }
        publish_tunnel(code, tunnel_status[code])
        checked.append((code, country, active_ip, active_num, canaries, details))

    # Every measured tunnel failing at once points at the local network or Deeper itself, not at the nodes:
    # rebuilding all tunnels then only cuts every service off
    measured = [c for c, *_ in checked]
    all_slow = SKIP_ALL_SLOW and len(measured) >= 2 and not any(tunnel_status[c]["healthy"] for c in measured)
    if all_slow:
        if not STATUS.get("all_slow"):
            log_event("warn", "Медленные все туннели сразу: похоже на проблему сети или Deeper, восстановление не запускается", mail="all_slow")
        logger.warning("Все туннели не прошли проверку одновременно: восстановление пропущено")
        for c in measured:
            fails[c] = fails_before.get(c, 0)  # Not the nodes' fault: doesn't count towards a recovery
            LAST_FAIL_AT.pop(c, None)
            tunnel_status[c]["fails"] = fails[c]
            tunnel_status[c]["details"] += " → все туннели медленные одновременно, восстановление не запускалось"
            publish_tunnel(c, tunnel_status[c])
    STATUS["all_slow"] = all_slow

    for code, country, active_ip, active_num, canaries, details in ([] if all_slow else checked):
        healthy = tunnel_status[code]["healthy"]
        # Trigger recovery on FAIL_THRESHOLD consecutive failed runs
        if not healthy and fails.get(code, 0) >= FAIL_THRESHOLD:
            logger.warning(f"Туннель [{code} - {country}] деградировал (сбоев подряд: {fails[code]}). Запуск восстановления...")
            set_action(code, "Восстановление…")
            try:
                success, new_ip, new_pool, action_taken, steps = recover_tunnel(
                    client, code, country, active_ip, active_num, canaries, max_latency_ms)
            except Exception as e:
                logger.error(f"Ошибка восстановления туннеля [{code} - {country}]: {e}")
                success, new_ip, new_pool, action_taken, steps = False, "не изменился", active_num, f"Ошибка восстановления: {e}", []
            finally:
                set_action(code)
            if new_ip != "не изменился":
                tunnel_status[code]["ip"] = new_ip
            tunnel_status[code]["pool"] = new_pool

            tunnel_status[code]["details"] += f" → {action_taken}: {'успешно' if success else 'ошибка'}"
            publish_tunnel(code, tunnel_status[code])
            log_event("ok" if success else "bad",
                      f"{code}: {action_taken.split(' (')[0].lower()}, {'успешно' if success else 'не помогло'}. IP {active_ip} → {new_ip}")
            steps_text = "".join(f"  - {s}\n" for s in steps)

            # Send email notification
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            subject = f"[Deeper Connect] Туннель \"{country}\" перезапущен / перестроен"
            body = (
                f"Уведомление Deeper Connect Watchdog\n\n"
                f"Туннель: {country} ({code})\n"
                f"Действие: {action_taken}\n"
                f"Статус: {'Успешно' if success else 'Ошибка'}\n"
                f"Старый IP: {active_ip}\n"
                f"Новый IP: {new_ip}\n"
                f"Размер пула нод: {new_pool}\n"
                f"Причина: сбоев проверки подряд — {fails[code]} ({details})\n"
                + (f"Ход восстановления:\n{steps_text}" if steps else "")
                + f"Время события: {now_str}\n"
            )
            notify("recovery", subject, body)

            fails[code] = 0

    STATUS["tunnels"] = tunnel_status
    ROUTES["auto_sites"] = auto_sites
    record_history(tunnel_status)

    # App Relocator apps: current tunnel and ping via their website
    try:
        client.refresh_apps_cache(tunnels)
        apps = [a for a in ROUTES["apps"] if a["website"]]
        if apps:
            with ThreadPoolExecutor(max_workers=len(apps)) as pool:
                measured = list(pool.map(lambda a: test_url_latency(a["website"], timeout=LATENCY_TIMEOUT), apps))
            APP_RESULTS.clear()
            for a, (lat, status) in zip(apps, measured):
                APP_RESULTS[a["app"]] = {"tunnel": a["tunnel"], "latency": lat, "status": status, "ok": lat is not None}
    except Exception as e:
        logger.warning(f"Не удалось получить приложения App Relocator: {e}")

    # Rollbacks and returns first, so the service statuses show where services really are
    try:
        check_probation(client)
        return_evacuated(client)
        enforce_preferred(client, {t.get("tunnelCode") for t in client.list_tunnels() if t.get("activeNum", 0) > 0})
    except Exception as e:
        logger.error(f"Ошибка проверки автопереносов: {e}")
    measure_services()

    try:
        state_dir = os.path.dirname(state_file)
        if state_dir and not os.path.exists(state_dir):
            os.makedirs(state_dir, exist_ok=True)
        with open(state_file, "w") as f:
            json.dump(fails, f)
    except Exception as e:
        logger.debug(f"Could not save state file: {e}")


LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0a84ff"/><stop offset="1" stop-color="#5e5ce6"/></linearGradient></defs><path d="M32 5.5 52.5 13v16.5c0 13.2-8.6 23.3-20.5 28.8C20.1 52.8 11.5 42.7 11.5 29.5V13Z" fill="url(#g)" stroke="url(#g)" stroke-width="5" stroke-linejoin="round"/><path d="M17.5 33h6.5l4-9 6 18 4.5-13 3 4h5" fill="none" stroke="#fff" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
LOGO_PNG = base64.b64decode(
    "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")
LOGO_WIDE_PNG = base64.b64decode(
    "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")
ICON_192_PNG = base64.b64decode(
    "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")
APPLE_ICON_PNG = base64.b64decode(
    "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")

WEB_PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f5f5f7" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#000000" media="(prefers-color-scheme: dark)">
<title>Deeper Watchdog</title>
<link rel="icon" href="logo.svg" type="image/svg+xml">
<link rel="icon" href="logo.png" type="image/png" sizes="512x512">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="manifest" href="manifest.webmanifest" crossorigin="use-credentials">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Deeper">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<style>
:root{
 color-scheme:light dark;
 --bg:#f2f2f7;--card:#fff;--card2:#fff;--raise:#fff;
 --label:#000;--text:#1d1d1f;--muted:rgba(60,60,67,.6);--muted2:rgba(60,60,67,.3);
 --sep:rgba(60,60,67,.18);--fill:rgba(120,120,128,.12);--fill2:rgba(120,120,128,.16);--fill3:rgba(118,118,128,.24);
 --accent:#007aff;--accent-soft:rgba(0,122,255,.12);--accent-text:#0066d6;
 --green:#248a3d;--green-dot:#34c759;--green-soft:rgba(52,199,89,.15);
 --red:#d70015;--red-dot:#ff3b30;--red-soft:rgba(255,59,48,.12);
 --orange:#c93400;--orange-dot:#ff9500;--orange-soft:rgba(255,149,0,.15);
 --indigo:#5856d6;--purple:#af52de;--teal:#30b0c7;--pink:#ff2d55;--gray:#8e8e93;
 --shadow:0 0 0 .5px rgba(0,0,0,.04),0 2px 6px rgba(0,0,0,.04),0 12px 32px -8px rgba(0,0,0,.08);
 --shadow-lift:0 0 0 .5px rgba(0,0,0,.05),0 4px 12px rgba(0,0,0,.06),0 24px 48px -12px rgba(0,0,0,.14);
 --glass:rgba(249,249,251,.72);--glass-strong:rgba(250,250,252,.86);--glass-line:rgba(0,0,0,.08);
 --menu:rgba(246,246,248,.82);--menu-shadow:0 0 0 .5px rgba(0,0,0,.12),0 10px 40px rgba(0,0,0,.18),0 2px 8px rgba(0,0,0,.08);
 --radius:22px;--radius-sm:14px;
 --spring:cubic-bezier(.32,.72,0,1);
 --bg-art:radial-gradient(70% 55% at 0% 0%,rgba(0,122,255,.12),transparent 70%),
  radial-gradient(60% 50% at 100% 0%,rgba(175,82,222,.10),transparent 70%),
  radial-gradient(60% 50% at 100% 100%,rgba(255,149,0,.07),transparent 70%);
}
@media (prefers-color-scheme:dark){:root{
 --bg:#000;--card:#1c1c1e;--card2:#2c2c2e;--raise:#2c2c2e;
 --label:#fff;--text:#f5f5f7;--muted:rgba(235,235,245,.6);--muted2:rgba(235,235,245,.3);
 --sep:rgba(84,84,88,.6);--fill:rgba(118,118,128,.24);--fill2:rgba(118,118,128,.3);--fill3:rgba(118,118,128,.36);
 --accent:#0a84ff;--accent-soft:rgba(10,132,255,.2);--accent-text:#409cff;
 --green:#30d158;--green-dot:#30d158;--green-soft:rgba(48,209,88,.18);
 --red:#ff453a;--red-dot:#ff453a;--red-soft:rgba(255,69,58,.18);
 --orange:#ff9f0a;--orange-dot:#ff9f0a;--orange-soft:rgba(255,159,10,.18);
 --indigo:#5e5ce6;--purple:#bf5af2;--teal:#40c8e0;--pink:#ff375f;--gray:#8e8e93;
 --shadow:0 0 0 .5px rgba(255,255,255,.06);--shadow-lift:0 0 0 .5px rgba(255,255,255,.1),0 20px 40px -12px rgba(0,0,0,.6);
 --glass:rgba(22,22,24,.72);--glass-strong:rgba(28,28,30,.88);--glass-line:rgba(255,255,255,.1);
 --menu:rgba(40,40,42,.8);--menu-shadow:0 0 0 .5px rgba(255,255,255,.12),0 16px 48px rgba(0,0,0,.55);
 --bg-art:radial-gradient(70% 55% at 0% 0%,rgba(10,132,255,.18),transparent 70%),
  radial-gradient(60% 50% at 100% 0%,rgba(94,92,230,.16),transparent 70%),
  radial-gradient(60% 50% at 100% 100%,rgba(191,90,242,.08),transparent 70%);
}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%;scroll-padding-top:80px}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:var(--bg-art)}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.42 -apple-system,BlinkMacSystemFont,"SF Pro Text","Inter","Segoe UI Variable","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;letter-spacing:-.01em;font-feature-settings:"ss01","cv11"}
button,input,select,textarea{font:inherit;color:inherit;letter-spacing:inherit}
button{-webkit-user-select:none;user-select:none}
[hidden]{display:none!important}
svg.i{width:1em;height:1em;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-.125em}
:focus{outline:none}
:focus-visible{outline:3px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:2px;border-radius:10px}
.muted{color:var(--muted)}.small{font-size:13px}
.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--orange)}

/* Navigation bar */
.top{position:sticky;top:0;z-index:30;background:var(--glass);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-bottom:.5px solid var(--glass-line);padding-top:env(safe-area-inset-top)}
.top-in{max-width:1180px;margin:0 auto;padding:10px 20px;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px}
.brand{font-weight:650;font-size:17px;display:flex;align-items:center;gap:9px;letter-spacing:-.02em}
.logo{width:30px;height:30px;display:grid;place-items:center;filter:drop-shadow(0 2px 6px rgba(10,132,255,.35))}.logo svg{width:100%;height:100%}
.pill{justify-self:end;display:inline-flex;align-items:center;gap:7px;padding:6px 12px 6px 10px;border-radius:999px;background:var(--fill);font-size:13px;font-weight:550;white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis;transition:background .3s}
.pill.bad{background:var(--red-soft);color:var(--red)}.pill.warn{background:var(--orange-soft);color:var(--orange)}.pill.ok{background:var(--green-soft);color:var(--green)}
.pill span:last-child{overflow:hidden;text-overflow:ellipsis}
.dot{width:8px;height:8px;border-radius:50%;background:var(--gray);flex:none}
.dot.ok{background:var(--green-dot)}.dot.bad{background:var(--red-dot)}.dot.warn{background:var(--orange-dot)}.dot.info{background:var(--accent)}
.pill .dot.warn,.pill .dot.bad{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{50%{box-shadow:0 0 0 5px transparent;opacity:.55}}

/* Segmented control with a sliding thumb */
.seg{position:relative;display:inline-flex;background:var(--fill);border-radius:10px;padding:2px;gap:0;max-width:100%;isolation:isolate}
.seg::before{content:"";position:absolute;z-index:-1;top:2px;bottom:2px;left:var(--tx,2px);width:var(--tw,0);border-radius:8px;background:var(--raise);box-shadow:0 3px 8px rgba(0,0,0,.12),0 3px 1px rgba(0,0,0,.04),0 0 0 .5px rgba(0,0,0,.04);transition:left .32s var(--spring),width .32s var(--spring);opacity:var(--to,0)}
.seg button{position:relative;border:0;background:transparent;padding:6px 18px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;white-space:nowrap;flex:1;transition:color .2s}
.seg:not(.thumbed) button[aria-pressed="true"]{background:var(--raise);box-shadow:0 3px 8px rgba(0,0,0,.12),0 0 0 .5px rgba(0,0,0,.04)}
.seg button[aria-pressed="true"]{font-weight:600}
.seg.noanim::before{transition:none!important}
.seg.accent::before{background:var(--accent);box-shadow:0 2px 8px rgba(0,122,255,.35)}
.seg.accent:not(.thumbed) button[aria-pressed="true"]{background:var(--accent);box-shadow:0 2px 8px rgba(0,122,255,.35)}
.seg.accent button[aria-pressed="true"]{color:#fff}
.seg button:disabled{cursor:default}.seg button:disabled:not([aria-pressed="true"]){opacity:.4}
.seg button+button::after{content:"";position:absolute;left:0;top:25%;bottom:25%;border-left:1px solid var(--muted2);transition:opacity .2s}
.seg button[aria-pressed="true"]::after,.seg button[aria-pressed="true"]+button::after{opacity:0}
.navtabs{justify-self:center}
.navtabs .seg{min-width:260px}
.navtabs .seg button{display:inline-flex;align-items:center;justify-content:center;gap:6px}

/* Tab bar (phones) */
.tabbar{display:none}
@media (max-width:700px){
 .navtabs{display:none}
 .top-in{grid-template-columns:1fr auto;padding:8px 16px}
 .tabbar{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:30;background:var(--glass-strong);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-top:.5px solid var(--glass-line);padding:6px 0 calc(6px + env(safe-area-inset-bottom))}
 .tabbar button{flex:1;border:0;background:none;display:flex;flex-direction:column;align-items:center;gap:2px;font-size:10.5px;font-weight:550;color:var(--gray);cursor:pointer;padding:2px 0}
 .tabbar button svg.i{width:26px;height:26px;stroke-width:1.8}
 .tabbar button[aria-pressed="true"]{color:var(--accent)}
}

main{max-width:1180px;margin:0 auto;padding:8px 20px calc(120px + env(safe-area-inset-bottom))}
h1{font-size:34px;font-weight:700;letter-spacing:-.03em;margin:22px 2px 2px;line-height:1.15}
.lead{color:var(--muted);margin:0 2px 20px;font-size:15px}
.card{background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow)}
@media (max-width:700px){main{padding:4px 16px calc(150px + env(safe-area-inset-bottom))}h1{font-size:30px;margin-top:14px}}

/* Buttons */
.btn{border:0;border-radius:999px;padding:9px 18px;font-size:15px;font-weight:590;cursor:pointer;background:var(--accent-soft);color:var(--accent-text);display:inline-flex;align-items:center;gap:7px;justify-content:center;min-height:38px;transition:transform .18s var(--spring),filter .2s,background .2s,opacity .2s;white-space:nowrap}
.btn svg.i{font-size:16px;stroke-width:2.2}
.btn.primary{background:var(--accent);color:#fff;box-shadow:0 1px 2px rgba(0,0,0,.08),0 6px 16px -6px color-mix(in srgb,var(--accent) 70%,transparent)}
.btn.plain{background:transparent;padding:9px 12px}
.btn.danger{background:var(--red-soft);color:var(--red)}
.btn.gray{background:var(--fill);color:var(--text)}
.btn.sm{padding:5px 13px;font-size:13px;min-height:30px;font-weight:590}
.btn.icon{width:32px;min-height:32px;height:32px;padding:0;border-radius:50%;background:var(--fill);color:var(--text)}
.btn.icon svg.i{font-size:17px}
.btn:disabled{opacity:.38;cursor:default}
@media (hover:hover){.btn:not(:disabled):hover{filter:brightness(1.06)}.btn.gray:not(:disabled):hover,.btn.icon:not(:disabled):hover{background:var(--fill3)}}
.btn:not(:disabled):active{transform:scale(.96);filter:brightness(.94)}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
a.btn{text-decoration:none}

/* Overview: hero */
.hero{display:flex;align-items:center;gap:18px;padding:20px 22px;margin-bottom:18px;flex-wrap:wrap}
.hero-ic{width:56px;height:56px;border-radius:16px;display:grid;place-items:center;color:#fff;flex:none;background:linear-gradient(160deg,#5ac8fa,#007aff);box-shadow:0 8px 20px -8px rgba(0,122,255,.6)}
.hero-ic svg.i{font-size:30px;stroke-width:2.2}
.hero-ic.ok{background:linear-gradient(160deg,#5fe08a,#28b04e);box-shadow:0 8px 20px -8px rgba(52,199,89,.7)}
.hero-ic.bad{background:linear-gradient(160deg,#ff7a6e,#ff3b30);box-shadow:0 8px 20px -8px rgba(255,59,48,.7)}
.hero-ic.warn{background:linear-gradient(160deg,#ffc04d,#ff9500);box-shadow:0 8px 20px -8px rgba(255,149,0,.7)}
.hero-t{flex:1 1 220px;min-width:0}
.hero-t b{display:block;font-size:20px;font-weight:700;letter-spacing:-.02em;line-height:1.2}
.hero-t span{display:block;color:var(--muted);font-size:14px;margin-top:3px}
.hero .actions{flex:0 1 auto}
@media (max-width:700px){.hero{padding:18px}.hero .actions{width:100%}.hero .actions .btn{flex:1}}

/* Overview: tunnel cards */
.sect{display:flex;align-items:baseline;justify-content:space-between;font-size:22px;font-weight:700;letter-spacing:-.025em;margin:30px 2px 12px}
.tunnels{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:6px}
.tcard{padding:18px 20px 18px;position:relative;transition:transform .35s var(--spring),box-shadow .35s var(--spring);display:flex;flex-direction:column}
@media (hover:hover){.tcard:hover{box-shadow:var(--shadow-lift);transform:translateY(-2px)}}
.thead{display:flex;align-items:center;gap:12px}
.thead>div:nth-child(2){flex:1;min-width:0}
.code{width:44px;height:44px;border-radius:50%;background:var(--fill);display:grid;place-items:center;font-weight:650;font-size:13px;flex:none;letter-spacing:0;position:relative}
.code .fw{width:100%;height:100%;border-radius:50%;overflow:hidden;display:grid;place-items:center;box-shadow:inset 0 0 0 .5px rgba(0,0,0,.1)}
.code .flag{font-size:30px;line-height:1;transform:scale(1.5)}
.code .cc{position:absolute;right:-6px;bottom:-3px;font-size:9.5px;font-weight:750;background:var(--card);color:var(--text);border-radius:6px;padding:1px 4px;box-shadow:0 0 0 .5px var(--sep),0 1px 3px rgba(0,0,0,.12)}
.tname{font-weight:650;font-size:17px;line-height:1.2;letter-spacing:-.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tstate{font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:5px;margin-top:4px;padding:2px 8px 2px 7px;border-radius:999px;background:var(--fill);color:var(--muted)}
.tstate.ok{background:var(--green-soft);color:var(--green)}.tstate.bad{background:var(--red-soft);color:var(--red)}.tstate.warn{background:var(--orange-soft);color:var(--orange)}
.tstate .dot{width:6px;height:6px}
.ping{font-size:40px;font-weight:700;letter-spacing:-.04em;margin:16px 0 2px;font-variant-numeric:tabular-nums;line-height:1.05;font-feature-settings:"tnum"}
.ping small{font-size:17px;font-weight:600;color:var(--muted);margin-left:4px;letter-spacing:-.01em}
.ping.ok{color:var(--text)}.ping.warn{color:var(--orange)}.ping.bad{color:var(--red)}
.meta{font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;gap:4px 14px;align-items:center}
.meta span{display:inline-flex;align-items:center;gap:5px}
.meta .warn{color:var(--orange)}
.details{font-size:12.5px;color:var(--muted);margin-top:12px;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;word-break:break-word}
.sitelist{list-style:none;margin:14px 0 0;padding:10px 0 0;border-top:.5px solid var(--sep)}
.sitelist li{display:flex;align-items:center;gap:8px;font-size:13px;padding:3px 0}
.sitelist .h{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sitelist .v{font-variant-numeric:tabular-nums;color:var(--muted);font-weight:500}
.tact{display:flex;align-items:center;gap:10px;margin-top:14px;padding:10px 12px;border-radius:12px;background:var(--accent-soft);color:var(--accent-text);font-size:13px;font-weight:600}
.tact .sec{margin-left:auto;color:var(--muted);font-variant-numeric:tabular-nums;font-weight:500}
.spin{width:16px;height:16px;flex:none;border-radius:50%;border:2.2px solid currentColor;border-right-color:transparent;animation:spin .75s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.tcard .actions{margin-top:auto;padding-top:14px}
.tcard .seg{width:100%;margin-top:16px}.tcard .seg button{padding:7px 4px}
.tmore{margin-left:auto;align-self:flex-start}
.avatar{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-weight:700;font-size:19px;color:#fff;flex:none;box-shadow:inset 0 0 0 .5px rgba(0,0,0,.08)}
.spark{position:relative;margin-top:14px}
.spark svg{display:block;width:100%;height:58px;overflow:visible;touch-action:pan-y}
.spark .cap{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-top:6px;font-variant-numeric:tabular-nums}
.spark .tip{position:absolute;top:-8px;transform:translate(-50%,-100%);background:var(--menu);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:var(--menu-shadow);color:var(--text);font-size:12px;font-weight:550;padding:4px 9px;border-radius:8px;white-space:nowrap;pointer-events:none;font-variant-numeric:tabular-nums}
.alert{display:flex;gap:12px;align-items:center;padding:14px 18px;margin-bottom:16px;color:var(--red);font-weight:550;background:var(--red-soft);box-shadow:none}
.empty{padding:34px 20px;text-align:center;color:var(--muted);display:flex;flex-direction:column;align-items:center;gap:8px}
.empty svg.i{font-size:30px;color:var(--muted2);stroke-width:1.6}

/* Services on the overview */
.svcgrid{padding:12px;display:flex;flex-wrap:wrap;gap:8px}
.svc{display:inline-flex;align-items:center;gap:7px;border:0;background:var(--fill);border-radius:12px;padding:8px 12px;font-size:13px;font-weight:550;cursor:pointer;color:var(--text);transition:background .2s,transform .18s var(--spring)}
@media (hover:hover){.svc:hover{background:var(--fill3)}}
.svc:active{transform:scale(.96)}
.svc .t{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.02em}.svc .v{color:var(--muted);font-variant-numeric:tabular-nums;font-weight:500}
.svc .t.bad{color:var(--red)}

/* Inset grouped lists */
.list{overflow:hidden}
.li{display:grid;grid-template-columns:auto 1fr auto;gap:4px 12px;align-items:center;padding:12px 16px;position:relative;min-height:48px}
.li+.li::before{content:"";position:absolute;top:0;left:52px;right:0;border-top:.5px solid var(--sep)}
.list.plainsep .li+.li::before{left:16px}
.li.noselect{grid-template-columns:1fr auto}
.li.noselect+.li::before,.li.noselect::before{left:16px}
.li-main{min-width:0}
.li-title{font-weight:590;word-break:break-word;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.li-right{display:flex;flex-direction:column;align-items:flex-end;gap:4px;font-size:12px;color:var(--muted)}
.li-right.inline{flex-direction:row;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.li-right .tseg{color:var(--text)}.li-right .tseg button{padding:4px 10px;font-size:12px}
@media (max-width:700px){.li:has(.tseg){grid-template-columns:auto 1fr}.li:has(.tseg) .li-right{grid-column:2;justify-content:flex-start}}
.chip{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:7px;background:var(--fill);color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.chip.best{background:var(--green-soft);color:var(--green)}
.chip.bad{background:var(--red-soft);color:var(--red)}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.rec{font-size:13px;margin-top:8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.events .li{grid-template-columns:auto 1fr auto;align-items:start;padding:11px 16px}
.events .li::before{left:56px!important}
.events .tm{font-size:12px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums;padding-top:2px}
.events .tx{font-size:14px;line-height:1.38;padding-top:2px}
.evi{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;color:#fff;background:var(--gray)}
.evi svg.i{font-size:15px;stroke-width:2.6}
.evi.ok{background:var(--green-dot)}.evi.bad{background:var(--red-dot)}.evi.warn{background:var(--orange-dot)}.evi.info{background:var(--accent)}
.more{display:flex;margin:10px auto 0}

/* Settings: sidebar + grouped forms */
.settings-wrap{display:grid;grid-template-columns:240px 1fr;gap:28px;align-items:start}
.sidenav{position:sticky;top:76px;display:flex;flex-direction:column;gap:2px;padding:8px}
.sidenav button{display:flex;align-items:center;gap:10px;border:0;background:none;border-radius:10px;padding:7px 10px;font-size:14px;font-weight:500;cursor:pointer;text-align:left;color:var(--text)}
@media (hover:hover){.sidenav button:hover{background:var(--fill)}}
.sidenav button[aria-current="true"]{background:var(--accent);color:#fff}
.sidenav button[aria-current="true"] .tile{box-shadow:0 0 0 1.5px rgba(255,255,255,.6)}
@media (max-width:900px){.settings-wrap{grid-template-columns:1fr}.sidenav{display:none}}
.tile{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;color:#fff;flex:none;background:var(--gray)}
.tile svg.i{font-size:16px;stroke-width:2.2}
.ghead{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;letter-spacing:-.02em;color:var(--text);margin:30px 4px 10px;scroll-margin-top:84px}
.ghead .tile{width:30px;height:30px;border-radius:8px}
.ghead:first-child{margin-top:6px}
.gfoot{font-size:13px;color:var(--muted);margin:8px 18px 0;line-height:1.45}
.group{overflow:hidden}
.row{display:flex;align-items:center;gap:12px 18px;padding:12px 18px;min-height:52px;position:relative}
.row+.row::before{content:"";position:absolute;top:0;left:18px;right:0;border-top:.5px solid var(--sep)}
.row-text{flex:1;min-width:0}
.row-text label{display:block;font-size:15px;font-weight:500}
.help{font-size:13px;color:var(--muted);margin-top:2px;line-height:1.4}
.row-ctl{flex:none;display:flex;align-items:center;gap:8px}
.field{border:0;outline:0;background:var(--fill);border-radius:10px;padding:9px 12px;width:100%;min-height:38px;transition:box-shadow .2s,background .2s}
.field::placeholder{color:var(--muted)}
.field:focus{background:var(--card);box-shadow:0 0 0 4px var(--accent-soft),0 0 0 1px var(--accent) inset}
.row-ctl .field[type=number]{width:110px;text-align:right;font-variant-numeric:tabular-nums;font-weight:500}
.row.wide .row-ctl{width:min(340px,48%)}
@media (max-width:640px){.row.wide{flex-wrap:wrap}.row.wide .row-ctl{width:100%}}
.row.block{display:block}
.row.block .seg{width:100%;margin-top:12px}
.row.block .seg button{padding:7px 6px}
textarea.field{min-height:120px;font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:13px;resize:vertical;margin-top:10px}
input[type=search].field{padding-left:34px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238e8e93' stroke-width='2.4' stroke-linecap='round'%3E%3Ccircle cx='10.5' cy='10.5' r='6.5'/%3E%3Cpath d='m15.5 15.5 5 5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:11px 50%;background-size:16px}
input[type=search]::-webkit-search-cancel-button{-webkit-appearance:none}

/* Switch and check */
.switch{appearance:none;-webkit-appearance:none;width:51px;height:31px;border-radius:999px;background:var(--fill3);position:relative;cursor:pointer;transition:background .25s;flex:none;margin:0}
.switch::after{content:"";position:absolute;top:2px;left:2px;width:27px;height:27px;border-radius:50%;background:#fff;box-shadow:0 3px 8px rgba(0,0,0,.15),0 3px 1px rgba(0,0,0,.06);transition:transform .32s var(--spring),width .2s}
.switch:active::after{width:33px}
.switch:checked{background:var(--green-dot)}
.switch:checked::after{transform:translateX(20px)}
.switch:checked:active::after{transform:translateX(14px)}
.check{appearance:none;-webkit-appearance:none;width:22px;height:22px;border-radius:50%;border:1.5px solid var(--muted2);cursor:pointer;flex:none;margin:0;display:grid;place-items:center;transition:background .2s,border-color .2s,transform .18s var(--spring)}
.check:active{transform:scale(.9)}
.check:checked,.check:indeterminate{background:var(--accent);border-color:var(--accent)}
.check:checked::after{content:"";width:11px;height:6px;border:solid #fff;border-width:0 0 2.2px 2.2px;transform:translate(0,-1px) rotate(-45deg)}
.check:indeterminate::after{content:"";width:10px;height:2.2px;border-radius:2px;background:#fff}

/* Pop-up buttons and menus (replace native selects) */
.nsel{position:absolute!important;opacity:0!important;pointer-events:none!important;width:1px!important;height:1px!important;overflow:hidden}
.popup{display:inline-flex;align-items:center;justify-content:space-between;gap:8px;border:0;cursor:pointer;background:var(--fill);border-radius:10px;padding:8px 10px 8px 12px;min-height:38px;font-weight:500;text-align:left;transition:background .2s,transform .18s var(--spring)}
.popup .pv{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.popup svg.i{font-size:13px;color:var(--muted);stroke-width:2.4}
@media (hover:hover){.popup:not(:disabled):hover{background:var(--fill3)}}
.popup:active{transform:scale(.98)}
.popup[aria-expanded="true"]{background:var(--fill3)}
.popup:disabled{opacity:.4;cursor:default}
.popup.mini{min-height:28px;padding:4px 8px 4px 11px;border-radius:999px;font-size:13px;font-weight:600;background:var(--accent-soft);color:var(--accent-text);max-width:190px}
.popup.mini svg.i{color:currentColor}
.popup.mini.on{background:var(--accent);color:#fff}
.popup.mini.pin{background:var(--indigo);color:#fff}
.menu{position:fixed;z-index:80;inset:auto;margin:0;border:0;color:var(--text);min-width:200px;max-width:min(340px,calc(100vw - 24px));max-height:min(60vh,460px);overflow:auto;padding:6px;border-radius:14px;background:var(--menu);backdrop-filter:saturate(180%) blur(30px);-webkit-backdrop-filter:saturate(180%) blur(30px);box-shadow:var(--menu-shadow);transform-origin:var(--ox,50%) var(--oy,0);animation:menuin .26s var(--spring);overscroll-behavior:contain}
.menu.out{animation:menuout .16s ease forwards}
@keyframes menuin{from{opacity:0;transform:scale(.86)}}
@keyframes menuout{to{opacity:0;transform:scale(.94)}}
.menu .mh{font-size:12px;font-weight:600;color:var(--muted);padding:8px 10px 4px}
.menu .msep{height:.5px;background:var(--sep);margin:5px 8px}
.menu .mi{display:grid;grid-template-columns:18px 1fr auto;align-items:center;gap:8px;width:100%;border:0;background:none;text-align:left;padding:8px 10px;border-radius:8px;font-size:14px;cursor:pointer;color:var(--text)}
.menu .mi .mc{color:var(--accent);font-size:15px;stroke-width:2.6}
.menu .mi small{display:block;color:var(--muted);font-size:12px;margin-top:1px}
.menu .mi .mic{color:var(--muted);font-size:16px}
.menu .mi.dz{color:var(--red)}.menu .mi.dz .mic{color:var(--red)}
.menu .mi:disabled{opacity:.4;cursor:default}
.menu .mi:not(:disabled):hover,.menu .mi.hl{background:var(--accent);color:#fff}
.menu .mi:not(:disabled):hover small,.menu .mi.hl small,.menu .mi:not(:disabled):hover .mc,.menu .mi.hl .mc,.menu .mi:not(:disabled):hover .mic,.menu .mi.hl .mic{color:inherit}
@media (pointer:coarse){.menu .mi{padding:11px 12px;font-size:16px}.menu{border-radius:16px}}

/* Alerts */
dialog.alertd{border:0;padding:0;background:var(--glass-strong);backdrop-filter:saturate(180%) blur(30px);-webkit-backdrop-filter:saturate(180%) blur(30px);color:var(--text);width:min(320px,calc(100vw - 48px));border-radius:16px;box-shadow:var(--menu-shadow);overflow:hidden;text-align:center}
dialog.alertd[open]{animation:alertin .3s var(--spring)}
@keyframes alertin{from{opacity:0;transform:scale(1.12)}}
dialog.alertd::backdrop{background:rgba(0,0,0,.28)}
.alertd .ab{padding:20px 18px 16px}
.alertd h3{margin:0 0 4px;font-size:17px;font-weight:650;letter-spacing:-.02em}
.alertd p{margin:0;font-size:13px;line-height:1.4;color:var(--text);white-space:pre-line}
.alertd .field{margin-top:14px;background:var(--card)}
.alertd .abtns{display:flex;border-top:.5px solid var(--sep)}
.alertd .abtns button{flex:1;border:0;background:none;padding:12px 8px;font-size:17px;color:var(--accent);cursor:pointer;min-height:46px}
.alertd .abtns button+button{border-left:.5px solid var(--sep)}
.alertd .abtns button.def{font-weight:650}
.alertd .abtns button.dz{color:var(--red)}
@media (hover:hover){.alertd .abtns button:hover{background:var(--fill)}}

/* Toast banner */
.toast{position:fixed;left:50%;top:calc(12px + env(safe-area-inset-top));transform:translate(-50%,-140%);z-index:90;display:flex;align-items:center;gap:10px;background:var(--glass-strong);backdrop-filter:saturate(180%) blur(30px);-webkit-backdrop-filter:saturate(180%) blur(30px);color:var(--text);padding:10px 18px 10px 12px;border-radius:999px;font-size:14px;font-weight:550;max-width:calc(100vw - 32px);box-shadow:var(--menu-shadow);transition:transform .5s var(--spring),opacity .3s;opacity:0;pointer-events:none}
.toast.show{transform:translate(-50%,0);opacity:1}
.toast .ti{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;color:#fff;background:var(--green-dot);flex:none}
.toast.bad .ti{background:var(--red-dot)}
.toast .ti svg.i{font-size:14px;stroke-width:3}

/* Save bar */
.savebar{position:fixed;left:50%;bottom:calc(16px + env(safe-area-inset-bottom));transform:translateX(-50%);z-index:25;background:var(--glass-strong);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-radius:999px;box-shadow:var(--menu-shadow);padding:6px;width:max-content;max-width:calc(100vw - 24px)}
.savebar .actions{gap:6px;flex-wrap:nowrap}
.savebar .primary{min-width:130px}
@media (max-width:700px){.savebar{bottom:calc(68px + env(safe-area-inset-bottom));width:calc(100vw - 24px);border-radius:20px}.savebar .actions{flex-wrap:wrap}.savebar .primary{flex:1 1 100%}.savebar .btn:not(.primary){flex:1}}

/* Sheet */
dialog.sheet{border:0;padding:0;background:var(--bg);color:var(--text);width:min(940px,calc(100vw - 48px));max-width:none;max-height:calc(100vh - 48px);border-radius:28px;box-shadow:0 40px 100px rgba(0,0,0,.4),0 0 0 .5px var(--glass-line);overflow:hidden;display:none;flex-direction:column}
dialog.sheet[open]{display:flex;animation:sheetin .45s var(--spring)}
@keyframes sheetin{from{opacity:0;transform:translateY(24px) scale(.97)}}
dialog.sheet::backdrop{background:rgba(0,0,0,.32);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
@media (max-width:700px){
 dialog.sheet{width:100vw;max-height:94vh;margin:auto 0 0;border-radius:22px 22px 0 0}
 dialog.sheet[open]{animation:up .45s var(--spring)}
 @keyframes up{from{transform:translateY(100%)}}
}
.sheet-h{display:flex;align-items:center;gap:10px;padding:14px 16px 12px 22px;background:var(--glass);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-bottom:.5px solid var(--glass-line)}
.sheet-h h2{font-size:17px;font-weight:650;margin:0;flex:1;letter-spacing:-.02em}
.sheet-b{overflow:auto;padding:4px 18px calc(28px + env(safe-area-inset-bottom));-webkit-overflow-scrolling:touch;overscroll-behavior:contain}
.sheet-b .ghead{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin:26px 16px 8px}
.grab{display:none}
@media (max-width:700px){.grab{display:block;width:36px;height:5px;border-radius:3px;background:var(--fill3);margin:7px auto 0}}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}
.toolbar .field{flex:1;min-width:160px}
.selall{display:flex;align-items:center;gap:9px;font-size:14px;font-weight:500;cursor:pointer;white-space:nowrap}
.progress{height:6px;border-radius:3px;background:var(--fill);overflow:hidden;margin:6px 0 10px}
.progress i{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,#5ac8fa,var(--accent));width:0;transition:width .5s var(--spring)}
.addrow{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.addrow .field,.addrow .popup:not(.mini){flex:1 1 180px;min-width:0}.addrow .popup.tun{flex:0 0 auto;min-width:130px}
.svc-doms{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
details.doms{margin-top:8px;font-size:13px}
details.doms summary{cursor:pointer;color:var(--accent-text);font-weight:550;list-style:none;display:inline-flex;align-items:center;gap:4px}
details.doms summary::-webkit-details-marker{display:none}
details.doms summary::after{content:"";width:6px;height:6px;border:solid currentColor;border-width:0 1.8px 1.8px 0;transform:rotate(-45deg);transition:transform .25s var(--spring);margin-left:2px}
details.doms[open] summary::after{transform:rotate(45deg) translate(-2px,-1px)}
details.doms ul{list-style:none;margin:8px 0 0;padding:4px 12px;background:var(--fill);border-radius:12px}
details.doms li{display:flex;justify-content:space-between;gap:8px;padding:6px 0;flex-wrap:wrap;align-items:center;row-gap:4px}
details.doms li+li{border-top:.5px solid var(--sep)}
details.doms li>span:first-child{flex:1 1 160px;min-width:0;overflow-wrap:anywhere;word-break:normal;font-weight:500}
details.doms li>span:last-child{display:inline-flex;align-items:center;gap:6px;margin-left:auto}
.xdel{border:0;background:var(--fill);color:var(--muted);cursor:pointer;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;padding:0;flex:none}
.xdel svg.i{font-size:11px;stroke-width:3}
@media (hover:hover){.xdel:hover{color:#fff;background:var(--red-dot)}}
.tsite{padding-top:10px;padding-bottom:10px}.tsite .li-main{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tpings{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.tp{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:550;background:var(--fill);border-radius:7px;padding:3px 8px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tp b{font-weight:700;color:var(--muted)}
.warnline{font-size:13px;margin-top:5px;color:var(--orange);display:flex;gap:6px;align-items:center;font-weight:500}

/* Test sites editor and backups */
.sites{padding:4px 18px 16px}
.cn-row{display:flex;align-items:center;gap:8px 12px;flex-wrap:wrap;padding:11px 0;border-bottom:.5px solid var(--sep)}
.cn-u{flex:1 1 160px;min-width:0;display:flex;align-items:center;gap:10px;flex-wrap:wrap;overflow-wrap:anywhere;font-weight:500}
.cn-r{display:flex;align-items:center;gap:10px;margin-left:auto}
.tchips{display:flex;gap:6px;flex-wrap:wrap}
.tch{border:0;border-radius:999px;padding:5px 11px;font-size:12.5px;font-weight:600;cursor:pointer;background:var(--fill);color:var(--muted);transition:background .2s,color .2s,transform .18s var(--spring)}
.tch:active{transform:scale(.95)}
.tch[aria-pressed="true"]{background:var(--accent);color:#fff}
.tag{font-size:12.5px;color:var(--muted)}
.tag.bad{color:var(--red)}
.x{border:0;background:var(--fill);color:var(--muted);width:24px;height:24px;border-radius:50%;cursor:pointer;flex:none;display:grid;place-items:center;padding:0}
.x svg.i{font-size:11px;stroke-width:3}
@media (hover:hover){.x:hover{background:var(--red-dot);color:#fff}}
.add{display:flex;gap:8px}.add .field{flex:1;min-width:0}
.mailcats{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:2px 16px;margin-top:8px}
.mc-row{display:flex;align-items:flex-start;gap:10px;padding:7px 0;cursor:pointer}
.mc-row .check{margin-top:1px}.mc-row b{display:block;font-weight:500;font-size:14px}.mc-row small{display:block;color:var(--muted);font-size:12px;margin-top:1px}
.autosites{margin-top:14px;padding:12px 14px;border-radius:12px;background:var(--fill);font-size:13px;color:var(--muted)}
.autosites b{color:var(--text);font-weight:600}
.autosites div+div{margin-top:4px}
.bk{display:flex;align-items:center;gap:12px;padding:10px 0;border-top:.5px solid var(--sep)}
.bk:first-child{border-top:0}.bk .bk-t{flex:1;min-width:0;font-size:14px;font-weight:500}.bk .bk-t small{display:block;color:var(--muted);font-size:12px;font-weight:400}
.note{font-size:13px;color:var(--muted);margin:6px 4px 0}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}.spin{animation-duration:1.5s!important}}
</style></head>
<body>
<header class="top"><div class="top-in">
 <div class="brand"><span class="logo" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0a84ff"/><stop offset="1" stop-color="#5e5ce6"/></linearGradient></defs><path d="M32 5.5 52.5 13v16.5c0 13.2-8.6 23.3-20.5 28.8C20.1 52.8 11.5 42.7 11.5 29.5V13Z" fill="url(#lg)" stroke="url(#lg)" stroke-width="5" stroke-linejoin="round"/><path d="M17.5 33h6.5l4-9 6 18 4.5-13 3 4h5" fill="none" stroke="#fff" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Deeper Watchdog</div>
 <nav class="navtabs" aria-label="Разделы"><div class="seg" id="navseg">
  <button type="button" data-tab="overview" aria-pressed="true"><i data-ic="gauge"></i>Обзор</button>
  <button type="button" data-tab="settings" aria-pressed="false"><i data-ic="sliders"></i>Настройки</button>
 </div></nav>
 <span class="pill" id="statePill"><span class="dot"></span><span>Загрузка…</span></span>
</div></header>

<main>
<section id="tab-overview">
 <h1>Обзор</h1>
 <p class="lead">Туннели Deeper Connect, приложения и сервисы</p>
 <div id="alert" class="card alert" hidden></div>
 <div class="card hero">
  <div class="hero-ic" id="heroIc"><i data-ic="shield"></i></div>
  <div class="hero-t"><b id="heroTitle">Загрузка…</b><span id="runInfo"></span><span class="small muted" id="emailInfo"></span></div>
  <div class="actions">
   <button class="btn primary" id="checkNow" type="button"><i data-ic="refresh"></i><span>Проверить сейчас</span></button>
   <button class="btn gray" id="openRoutes" type="button"><i data-ic="chart"></i><span>Пинг и рекомендации</span></button>
  </div>
 </div>
 <div class="sect">Туннели</div>
 <div class="tunnels" id="tunnels"></div>
 <div id="appsBlock" hidden><div class="sect">Приложения</div><div class="tunnels" id="apps"></div></div>
 <div id="svcBlock" hidden><div class="sect">Сервисы</div><div class="card svcgrid" id="svcList"></div></div>
 <div id="eventsBlock"><div class="sect">Журнал</div>
 <div class="card list events" id="events"></div>
 <button class="btn sm plain more" id="eventsMore" type="button" hidden>Показать все</button></div>
</section>

<section id="tab-settings" hidden>
 <h1>Настройки</h1>
 <p class="lead">Изменения применяются сразу после сохранения, перезапускать контейнер не нужно.</p>
 <div class="settings-wrap"><nav class="card sidenav" id="sidenav" aria-label="Разделы настроек"></nav><div id="form"></div></div>
</section>
</main>

<div class="savebar" id="savebar" hidden><div class="actions">
 <button class="btn primary" id="save" type="button"><i data-ic="check"></i>Сохранить</button>
 <button class="btn danger" id="reset" type="button">Сброс настроек</button>
</div></div>
<nav class="tabbar" aria-label="Разделы">
 <button type="button" data-tab="overview" aria-pressed="true"><i data-ic="gauge"></i><span>Обзор</span></button>
 <button type="button" data-tab="settings" aria-pressed="false"><i data-ic="sliders"></i><span>Настройки</span></button>
</nav>
<div class="toast" id="toast" role="status" aria-live="polite"></div>

<dialog class="sheet" id="routes" aria-labelledby="routesTitle">
 <div class="grab" aria-hidden="true"></div>
 <div class="sheet-h"><h2 id="routesTitle">Пинг и рекомендации</h2><button class="btn sm primary" id="closeRoutes" type="button">Готово</button></div>
 <div class="sheet-b">
  <div class="ghead">Тестовые сайты · последняя проверка</div>
  <div class="card list" id="rtTests"></div>
  <div class="ghead">Сайты и приложения</div>
  <div class="card" style="padding:14px 16px">
   <div class="small muted">Сравнение меряет все сервисы там, где они сейчас, затем по очереди переносит их все в каждый туннель и меряет разом, а в конце возвращает обратно. Во время сравнения сайты могут подтормаживать.
   Пинг сервиса считается как средний по его доменам. Справа у каждого сервиса выбирается режим. «Авто»: сервис держится в одной стране и сам переезжает туда, где пинг меньше. Туннель (📌): предпочтительный, сервис всегда в нём; если там пропали ноды, сервис временно переезжает в работающий туннель и обязательно возвращается, когда ноды появятся. «Вручную»: ничего не переносится само, туннель выбирается кнопками рядом с сервисом.</div>
   <div class="toolbar">
    <label class="selall"><input type="checkbox" class="check" id="selAll">Выбрать все</label>
    <input class="field" id="rtFilter" type="search" placeholder="Поиск" aria-label="Поиск сайта">
    <button class="btn primary" id="compareBtn" type="button">Сравнить все</button>
   </div>
   <div class="progress" id="progress" hidden><i></i></div>
   <div class="small" id="rtProgress"></div>
  </div>
  <div class="ghead" id="rtAppsHead">Приложения</div>
  <div class="card list" id="rtApps"></div>
  <div class="ghead">Сервисы из правил Smart Route</div>
  <div class="note" style="margin:-2px 20px 8px">Домены одного сервиса всегда переносятся и сравниваются вместе, в одной стране.</div>
  <div class="card list" id="rtRules"></div>
  <div class="ghead">Добавить сервис</div>
  <div class="card" style="padding:14px 16px">
   <div class="small muted">Все домены сервиса добавляются в Smart Route одной кнопкой. Домены, которые уже есть в другой стране, переносятся в выбранную.</div>
   <div class="addrow">
    <select class="field" id="svcPick" aria-label="Сервис"></select>
    <select class="field tun" id="svcTun" aria-label="Страна"></select>
    <button class="btn primary" id="svcAdd" type="button">Добавить все домены</button>
   </div>
   <div class="svc-doms" id="svcDoms"></div>
  </div>
  <div class="ghead">Добавить домены</div>
  <div class="card" style="padding:14px 16px">
   <div class="small muted">Можно несколько через запятую или пробел. Поддомены Deeper подхватывает сам. Если выбрать сервис, домены станут его частью и всегда будут в одной стране с ним.</div>
   <div class="addrow">
    <input class="field" id="domInput" placeholder="example.com, example.net" aria-label="Домены" autocapitalize="off" spellcheck="false">
   </div>
   <div class="addrow">
    <select class="field" id="domGroup" aria-label="Сервис"></select>
    <select class="field tun" id="domTun" aria-label="Страна"></select>
    <button class="btn primary" id="domAdd" type="button">Добавить</button>
   </div>
  </div>
 </div>
</dialog>

<script>
const GROUP_ICONS={"Проверка":["gauge","#007aff"],"Тестовые сайты":["globe","#30b0c7"],"Приложения":["grid","#5856d6"],
 "Восстановление при сбое":["refresh","#ff9500"],"Туннель без нод":["bolt","#ff3b30"],"Сравнение туннелей для сайтов":["chart","#34c759"],
 "Резервные копии и перенос":["archive","#8e8e93"],"Почта":["mail","#1e8cff"],"Журнал":["clock","#ff2d55"],"Deeper Connect":["shield","#af52de"]};
const tile=title=>{const [ic,c]=GROUP_ICONS[title]||["sliders","#8e8e93"];const t=el("span",{class:"tile",style:"background:"+c});t.append(icon(ic));return t};
const GROUPS=[
 {title:"Проверка",fields:[
  ["MAX_LATENCY_MS","number","Допустимый пинг, мс","Выше этого значения проверка считается неудачной"],
  ["FAIL_THRESHOLD","number","Сбоев подряд до восстановления","Сколько неудачных проверок подряд нужно для восстановления"],
  ["CHECK_INTERVAL","number","Интервал проверки, сек","Как часто проверять туннели, от 30 сек"],
  ["LATENCY_TIMEOUT","number","Таймаут запроса, сек","Сколько ждать ответа тестового сайта"],
  ["MONITOR_TUNNELS","text","Туннели","Коды через запятую, например US,GB,NL. Пусто: все активные"]]},
 {title:"Тестовые сайты",foot:"Каждый сайт сам проверяет тот туннель, через который сейчас идёт его домен: перенесли сервис в другую страну — сайт начнёт проверять её. Пинг туннеля считается как среднее время ответа его сайтов. Если через туннель идёт меньше сайтов из списка, чем «Сайтов на туннель», он добирает сайты своих приложений и домены из Smart Route.",fields:[
  ["TEST_SITES","canaries"],
  ["SITES_PER_TUNNEL","number","Сайтов на туннель","Если через туннель идёт меньше сайтов из списка, добавляются временные: сайты его приложений и домены Smart Route. Больше сайтов — точнее пинг"]]},
 {title:"Приложения",foot:"Приложения из «Перемещения приложений» Deeper, которые показываются на обзоре и участвуют в сравнении. Например: instagram, telegram, facebook, chatGpt, youtube.",fields:[
  ["APPS","text","Приложения","Коды через запятую"]]},
 {title:"Восстановление при сбое",fields:[
  ["RECOVERY_ACTION","segmented","Действие при сбое","",[["refresh","Перестроить"],["switch","Сменить ноду"],["smart","Smart"]]],
  ["SWITCH_ATTEMPTS","number","Смен ноды до перестроения","Сколько раз менять ноду, прежде чем перестроить туннель"],
  ["VERIFY_CHECKS","number","Проверок после смены ноды","Нода хорошая, если успешно больше половины проверок"],
  ["VERIFY_PAUSE","number","Пауза между проверками, сек","И пауза после смены ноды перед первой проверкой"],
  ["REBUILD_WAIT","number","Ожидание перестроения, сек","Сколько ждать новый IP после перестроения"],
  ["SKIP_ALL_SLOW","switch","Не восстанавливать, если медленные все туннели","Если проверку не прошли все туннели сразу, виновата скорее сеть или сам Deeper: смена нод и перестроение только оборвут связь"]]},
 {title:"Туннель без нод",foot:"Число нод проверяется каждые 10 секунд. Сервисы переезжают в работающий туннель с наименьшим пингом.",fields:[
  ["FAILOVER_EMPTY","switch","Уводить сервисы из туннеля без нод","Если в туннеле 0 нод дольше времени ожидания, все его сервисы и приложения переезжают туда, где ноды есть"],
  ["FAILOVER_WAIT","number","Ожидание нод, сек","Сколько ждать появления нод, прежде чем переносить"],
  ["EMPTY_REBUILD_AFTER","number","Перестроить без нод через, сек","Если в туннеле 0 нод дольше этого, он перестраивается. 0: выключено"],
  ["EMPTY_REBUILD_EVERY","number","Повторять перестроение, сек","Если нод так и нет, следующая попытка не раньше чем через столько"],
  ["ALL_EMPTY_REBUILD_EVERY","number","Нет нод нигде: перестраивать все, сек","Если нод нет ни в одном туннеле, все туннели перестраиваются с этой периодичностью, затем запускается проверка. 0: выключено"],
  ["FAILOVER_RETURN","switch","Возвращать обратно","Когда в туннеле снова появятся ноды и проверка пройдёт"],
  ["FAILOVER_PRIORITY","services","Приоритетные сервисы","Если после перестроения туннеля нод нет дольше времени ожидания, эти сервисы переезжают сразу, не дожидаясь следующей проверки"]]},
 {title:"Сравнение туннелей для сайтов",fields:[
  ["AUTO_MIN_GAIN_PCT","number","Быстрее хотя бы на, %","Авторежим переносит сайт, только если выигрыш не меньше этого…"],
  ["AUTO_MIN_GAIN_MS","number","…и хотя бы на, мс","…и одновременно не меньше этого"],
  ["AUTO_GAIN_RECHECK","number","Сравнить сразу, не чаще раза в, мин","Если сервис с «Авто» после проверки заметно медленнее, чем другой туннель (по порогам выше), он сравнивается сразу, а не ночью. Не чаще этого. 0: выключено"],
  ["COMPARE_SAMPLES","number","Замеров на туннель","По каждому домену берётся медиана, по сервису — среднее"],
  ["ROUTE_SETTLE","number","Пауза после переключения, сек","Время, чтобы Deeper применил новый маршрут"],
  ["AUTO_COMPARE_HOUR","number","Плановое сравнение, час","Каждый день в этот час (0–23) сервисы с «Авто» сравниваются заново. Если сервер в это время был выключен, сравнение пройдёт сразу после включения. −1: выключено"],
  ["AUTO_ROLLBACK","switch","Откат неудачных переносов","Если после автопереноса сервис не отвечает 2 проверки подряд, он возвращается обратно, и эта страна сутки для него не используется"]]},
 {title:"Резервные копии и перенос",foot:"Копия правил Deeper сохраняется сама перед каждым изменением: переносом, добавлением и удалением доменов, сравнением. Хранятся последние 30. Файл содержит правила, приложения и настройки без паролей; при загрузке файла домены только добавляются и переносятся, лишние не удаляются.",fields:[
  ["BACKUPS","backups"]]},
 {title:"Журнал",fields:[
  ["SHOW_EVENTS","switch","Показывать журнал","Журнал событий внизу обзора"],
  ["EVENTS_DAYS","number","Хранить, дней","Записи старше удаляются сами. 0: хранить, пока не наберётся 2000 записей"],
  ["CLEAR_EVENTS","clearlog","Очистить журнал","Удалить все записи сейчас"]]},
 {title:"Почта",fields:[
  ["SMTP_ENABLED","switch","Письма-отчёты","О событиях, отмеченных ниже"],
  ["EMAIL_EVENTS","mailcats","О чём писать"],
  ["SMTP_TO","email","Кому","Можно несколько адресов через запятую"],
  ["SMTP_HOST","text","SMTP-сервер","Например, smtp.yandex.ru"],
  ["SMTP_PORT","number","Порт","465 для SSL, 587 для STARTTLS"],
  ["SMTP_USE_SSL","switch","SSL","Для порта 465"],
  ["SMTP_USER","text","Логин"],
  ["SMTP_PASS","password","Пароль приложения"],
  ["SMTP_FROM","text","От кого","Пусто: как логин"]]},
 {title:"Deeper Connect",fields:[
  ["DEEPER_HOST","text","IP-адрес устройства"],
  ["DEEPER_USER","text","Логин"],
  ["DEEPER_PASS","password","Пароль"]]}];
// Fields hidden unless the given setting has one of the values
const SHOW_IF={
 FAILOVER_RETURN:["FAILOVER_EMPTY",[true]],
 SWITCH_ATTEMPTS:["RECOVERY_ACTION",["smart"]],VERIFY_CHECKS:["RECOVERY_ACTION",["smart"]],VERIFY_PAUSE:["RECOVERY_ACTION",["smart"]],
 SMTP_TO:["SMTP_ENABLED",[true]],SMTP_HOST:["SMTP_ENABLED",[true]],SMTP_PORT:["SMTP_ENABLED",[true]],SMTP_USE_SSL:["SMTP_ENABLED",[true]],
 SMTP_USER:["SMTP_ENABLED",[true]],SMTP_PASS:["SMTP_ENABLED",[true]],SMTP_FROM:["SMTP_ENABLED",[true]],EMAIL_EVENTS:["SMTP_ENABLED",[true]]};
// Email categories: [key, title, what it covers]
const MAIL_CATS=[
 ["recovery","Восстановление туннеля","Смена ноды или перестроение после сбоев проверки"],
 ["check","Проверка не прошла","Туннель медленный или не отвечает, и когда он снова в норме"],
 ["all_slow","Медленные все туннели","Похоже на проблему сети или Deeper, восстановление не запускается"],
 ["no_nodes","Нет нод в туннеле","Перенос сервисов из туннеля без нод и его перестроение"],
 ["nodes_back","Ноды появились","Туннель снова с нодами, сервисы вернулись"],
 ["all_empty","Нет нод ни в одном туннеле","И результат перестроения всех туннелей"],
 ["auto","Автоперенос","Сервис с «Авто» переехал туда, где быстрее"],
 ["rollback","Откат автопереноса","На новом месте сервис не заработал и возвращён, ошибки возврата"],
 ["errors","Deeper Connect недоступен","Не удаётся связаться с устройством, и когда связь восстановлена"],
 ["changes","Изменения","Настройки, ручные переносы, смена ноды и перестроение вручную, новые туннели"]];
const MODE_HELP={
 refresh:"Весь пул нод сбрасывается и собирается заново. Надёжно, но на время перестроения связь прерывается.",
 switch:"Переключение на другую ноду из текущего пула. Быстро, но новая нода тоже может оказаться плохой. Если в пуле одна нода, туннель перестраивается.",
 smart:"Нода меняется, после каждой смены сразу идут проверки. Если ни одна смена не помогла, туннель перестраивается."};

const $=id=>document.getElementById(id);
// SF Symbols-like line icons
const ICONS={
 gauge:'<path d="M12 14.5 16 10"/><path d="M3.6 17.5a9 9 0 1 1 16.8 0"/><circle cx="12" cy="14.5" r="1.3" fill="currentColor"/>',
 sliders:'<path d="M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="17" r="2"/>',
 globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>',
 grid:'<rect x="4" y="4" width="7" height="7" rx="2"/><rect x="13" y="4" width="7" height="7" rx="2"/><rect x="4" y="13" width="7" height="7" rx="2"/><rect x="13" y="13" width="7" height="7" rx="2"/>',
 refresh:'<path d="M19.5 10.5A7.7 7.7 0 0 0 5.6 7.4L4 9"/><path d="M4 4.5V9h4.5"/><path d="M4.5 13.5a7.7 7.7 0 0 0 13.9 3.1L20 15"/><path d="M20 19.5V15h-4.5"/>',
 bolt:'<path d="M13.5 3 5 13.5h6.5L10.5 21 19 10.5h-6.5z"/>',
 chart:'<path d="M5 20v-8M12 20V5M19 20v-5"/>',
 archive:'<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v9a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9M10 13h4"/>',
 mail:'<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m4 7.5 8 5.5 8-5.5"/>',
 shield:'<path d="M12 3 5 6v5.5c0 4.4 3 8 7 9.5 4-1.5 7-5.1 7-9.5V6z"/>',
 shieldok:'<path d="M12 3 5 6v5.5c0 4.4 3 8 7 9.5 4-1.5 7-5.1 7-9.5V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
 check:'<path d="M5 12.5 10 17.5 19 7"/>',
 x:'<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
 excl:'<path d="M12 6.5v7M12 17.5h.01"/>',
 info:'<path d="M12 10.5v7M12 6.5h.01"/>',
 more:'<circle cx="5.5" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="18.5" cy="12" r="1.4" fill="currentColor" stroke="none"/>',
 updown:'<path d="m8 9.5 4-4 4 4M8 14.5l4 4 4-4"/>',
 pin:'<path d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11z"/><circle cx="12" cy="10" r="2.3"/>',
 sparkle:'<path d="M12 3.5 13.9 9 19.5 11l-5.6 2L12 18.5 10.1 13 4.5 11l5.6-2z"/><path d="M19 3.5v3M17.5 5h3"/>',
 hand:'<path d="M7 12.5V7.8a1.4 1.4 0 0 1 2.8 0V11M9.8 10.5V5.4a1.4 1.4 0 0 1 2.8 0v5M12.6 10.5V6.4a1.4 1.4 0 0 1 2.8 0V12M15.4 11V9a1.4 1.4 0 0 1 2.8 0v5a7 7 0 0 1-7 7h-.4A6.6 6.6 0 0 1 5 16.2l-.9-2.1a1.4 1.4 0 0 1 2.5-1.2l.4.6"/>',
 swap:'<path d="M5 8h13l-3.5-3.5M19 16H6l3.5 3.5"/>',
 trash:'<path d="M4.5 7h15M10 11v6M14 11v6M6.5 7l.8 11.2A2 2 0 0 0 9.3 20h5.4a2 2 0 0 0 2-1.8L17.5 7M9 7V4.5h6V7"/>',
 server:'<rect x="4" y="4" width="16" height="7" rx="2.2"/><rect x="4" y="13" width="16" height="7" rx="2.2"/><path d="M8 7.5h.01M8 16.5h.01"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 folder:'<path d="M3.5 7.5A2 2 0 0 1 5.5 5.5H10l2 2h6.5a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
 download:'<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14"/>',
 upload:'<path d="M12 15V4M7.5 8.5 12 4l4.5 4.5M5 19.5h14"/>',
 tri:'<path d="M10.3 4.6 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>',
 clock:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
 nodes:'<circle cx="6" cy="12" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="18" cy="18" r="2.2"/><path d="m8 11 8-4M8 13l8 4"/>'};
function icon(name,cls){const t=document.createElement("template");
 t.innerHTML=`<svg class="i${cls?" "+cls:""}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]||""}</svg>`;return t.content.firstChild}
function hydrateIcons(root=document){for(const i of root.querySelectorAll("i[data-ic]"))i.replaceWith(icon(i.dataset.ic))}
// Country flag from a two-letter code
const flag=c=>/^[A-Z]{2}$/.test(c||"")&&c!=="ZZ"&&c!=="LL"?String.fromCodePoint(...[...c].map(ch=>0x1F1A5+ch.charCodeAt(0))):"";
function setBtn(b,ic,text){b.textContent="";b.append(ic==="spin"?el("span",{class:"spin"}):icon(ic),el("span",{text}))}

// Settings side navigation: highlight the section being read; a clicked section stays highlighted
// even when the page cannot scroll far enough to bring it to the top
let navPick=null,navPickAt=0,navBound=false;
function navMark(id){for(const b of $("sidenav").children)b.setAttribute("aria-current",String(b.dataset.g===id))}
function navUpdate(){const hs=[...document.querySelectorAll("#form .ghead")].filter(h=>h.offsetParent);if(!hs.length)return;
 const picked=navPick&&document.getElementById(navPick);
 if(picked&&Date.now()-navPickAt<1500)return navMark(navPick);
 let cur=hs[0];for(const h of hs)if(h.getBoundingClientRect().top<=140)cur=h;
 if(innerHeight+scrollY>=document.documentElement.scrollHeight-4){
  const r=picked&&picked.getBoundingClientRect();cur=r&&r.top>=0&&r.top<innerHeight?picked:hs[hs.length-1]}
 navMark(cur.id)}
// Menus: Apple-style pop-up menu anchored to a control
let openMenu=null;
function closeMenu(){if(!openMenu)return;const m=openMenu;openMenu=null;m.anchor&&m.anchor.setAttribute("aria-expanded","false");
 m.el.classList.add("out");setTimeout(()=>m.el.remove(),160);document.removeEventListener("pointerdown",m.outside,true);document.removeEventListener("keydown",m.keys,true);
 window.removeEventListener("resize",closeMenu);window.removeEventListener("scroll",m.scroll,true)}
// items: {text, sub, icon, checked, danger, disabled, onSelect} | {sep:true} | {header:"…"}
function showMenu(anchor,items,{align="start",minWidth=0}={}){
 closeMenu();const m=el("div",{class:"menu",role:"menu"});const buttons=[];
 for(const it of items){
  if(it.sep){m.append(el("div",{class:"msep"}));continue}
  if(it.header){m.append(el("div",{class:"mh",text:it.header}));continue}
  const b=el("button",{type:"button",class:"mi"+(it.danger?" dz":""),role:it.checked!=null?"menuitemradio":"menuitem","aria-checked":it.checked!=null?String(!!it.checked):null});
  b.disabled=!!it.disabled;
  b.append(it.checked?icon("check","mc"):it.icon?icon(it.icon,"mic"):el("span"),
   el("span",{},it.text,it.sub?el("small",{text:it.sub}):null),it.right?el("span",{class:"muted small",text:it.right}):el("span"));
  b.onclick=()=>{closeMenu();it.onSelect&&it.onSelect()};m.append(b);buttons.push(b)}
 // Inside a modal dialog the menu must live in it (the rest of the page is inert) and in the top layer above it
 (anchor.closest("dialog[open]")||document.body).append(m);
 if(m.showPopover){m.setAttribute("popover","manual");m.showPopover()}
 const r=anchor.getBoundingClientRect(),mw=Math.max(m.offsetWidth,minWidth,align==="stretch"?r.width:0);m.style.minWidth=mw+"px";
 const W=innerWidth,H=innerHeight,mh=m.offsetHeight;
 let left=align==="end"?r.right-mw:r.left;left=Math.max(12,Math.min(left,W-mw-12));
 let top=r.bottom+6,above=false;if(top+mh>H-12&&r.top-mh-6>12){top=r.top-mh-6;above=true}else top=Math.min(top,H-mh-12);
 m.style.left=left+"px";m.style.top=Math.max(12,top)+"px";
 m.style.setProperty("--ox",(r.left+r.width/2-left)+"px");m.style.setProperty("--oy",above?"100%":"0");
 anchor.setAttribute("aria-expanded","true");
 let hl=buttons.findIndex(b=>b.getAttribute("aria-checked")==="true");
 const mark=i=>{buttons.forEach((b,k)=>b.classList.toggle("hl",k===i));hl=i;buttons[i]&&buttons[i].focus({preventScroll:false})};
 const keys=e=>{if(e.key==="Escape"){e.preventDefault();closeMenu();anchor.focus();return}
  if(e.key==="ArrowDown"||e.key==="ArrowUp"){e.preventDefault();const en=buttons.map((b,i)=>b.disabled?-1:i).filter(i=>i>=0);if(!en.length)return;
   const pos=en.indexOf(hl);mark(e.key==="ArrowDown"?en[(pos+1)%en.length]:en[(pos-1+en.length)%en.length])}
  if(e.key==="Tab")closeMenu()};
 const outside=e=>{if(!m.contains(e.target)&&!anchor.contains(e.target))closeMenu()};
 const scroll=e=>{if(!m.contains(e.target))closeMenu()};
 openMenu={el:m,anchor,outside,keys,scroll};
 setTimeout(()=>{document.addEventListener("pointerdown",outside,true);document.addEventListener("keydown",keys,true);
  window.addEventListener("resize",closeMenu);window.addEventListener("scroll",scroll,true)});
 if(hl>=0)buttons[hl].scrollIntoView({block:"nearest"});
 return m}
// Native <select> stays as the data model; a pop-up button shows and edits it
const valueDesc=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,"value");
function enhanceSelect(sel){
 if(sel.dataset.enh)return;sel.dataset.enh="1";
 const mini=sel.classList.contains("mini");
 const btn=el("button",{type:"button",class:"popup"+(mini?" mini":"")+(sel.classList.contains("tun")?" tun":""),"aria-haspopup":"menu","aria-expanded":"false","aria-label":sel.getAttribute("aria-label")||"",title:sel.title||null});
 const pv=el("span",{class:"pv"});btn.append(pv,icon(mini?"updown":"updown"));
 const sync=()=>{const o=sel.options[sel.selectedIndex];pv.textContent=o?(o.dataset.short||o.textContent):"—";btn.disabled=sel.disabled||!sel.options.length;
  btn.classList.toggle("on",sel.dataset.tone==="on");btn.classList.toggle("pin",sel.dataset.tone==="pin")};
 Object.defineProperty(sel,"value",{configurable:true,get(){return valueDesc.get.call(this)},set(v){valueDesc.set.call(this,v);sync()}});
 btn.onclick=()=>{if(openMenu&&openMenu.anchor===btn){closeMenu();return}
  const items=[];
  for(const node of sel.children){
   const opts=node.tagName==="OPTGROUP"?[...node.children]:[node];
   if(node.tagName==="OPTGROUP"){if(items.length)items.push({sep:true});items.push({header:node.label})}
   for(const o of opts)items.push({text:o.dataset.menu||o.textContent,sub:o.dataset.sub,icon:o.dataset.ic,disabled:o.disabled,checked:o.selected,
    onSelect:()=>{if(sel.value===o.value)return;sel.value=o.value;sel.dispatchEvent(new Event("change"))}})}
  showMenu(btn,items,{align:mini?"end":"stretch"})};
 new MutationObserver(sync).observe(sel,{childList:true,subtree:true,attributes:true,attributeFilter:["disabled","data-tone"]});
 sel.classList.add("nsel");sel.tabIndex=-1;sel.setAttribute("aria-hidden","true");sel.after(btn);sync()}
new MutationObserver(ms=>{for(const m of ms)for(const n of m.addedNodes)if(n.nodeType===1){
 if(n.tagName==="SELECT")enhanceSelect(n);else for(const s of n.querySelectorAll("select"))enhanceSelect(s);
 if(n.querySelector&&n.querySelector("i[data-ic]"))hydrateIcons(n)}}).observe(document.documentElement,{childList:true,subtree:true});

// Alerts instead of confirm()/prompt()
function ask(title,text,{ok="OK",cancel="Отменить",danger=false,input=null}={}){
 return new Promise(resolve=>{
  const d=el("dialog",{class:"alertd",role:"alertdialog"});const field=input?el("input",{class:"field",placeholder:input.placeholder||"",value:input.value||"",autocapitalize:"off",spellcheck:"false"}):null;
  const no=el("button",{type:"button",text:cancel}),yes=el("button",{type:"button",class:danger?"dz def":"def",text:ok});
  d.append(el("div",{class:"ab"},el("h3",{text:title}),text?el("p",{text}):null,field),el("div",{class:"abtns"},no,yes));
  document.body.append(d);d.showModal();(field||yes).focus();
  const done=v=>{d.close();d.remove();resolve(v)};
  no.onclick=()=>done(input?null:false);yes.onclick=()=>done(input?field.value.trim():true);
  if(field)field.onkeydown=e=>{if(e.key==="Enter"){e.preventDefault();yes.click()}};
  d.addEventListener("cancel",e=>{e.preventDefault();done(input?null:false)})})}
// Segmented controls: a thumb that slides to the selected segment
const segRO=window.ResizeObserver?new ResizeObserver(es=>es.forEach(e=>thumb(e.target))):null;
function thumb(seg){if(!seg)return;if(segRO&&!seg._ro){seg._ro=1;segRO.observe(seg)}const b=seg.querySelector('button[aria-pressed="true"]');
 if(!b||!b.offsetWidth){seg.classList.remove("thumbed");seg.style.setProperty("--to",0);return}
 // A new or just shown control gets its thumb in place; only a change of selection slides
 const first=!seg.classList.contains("thumbed");if(first)seg.classList.add("noanim");
 seg.classList.add("thumbed");seg.style.setProperty("--tx",b.offsetLeft+"px");seg.style.setProperty("--tw",b.offsetWidth+"px");seg.style.setProperty("--to",1);
 if(first){seg.offsetWidth;requestAnimationFrame(()=>requestAnimationFrame(()=>seg.classList.remove("noanim")))}}
const thumbAll=()=>document.querySelectorAll(".seg").forEach(thumb);
addEventListener("resize",()=>requestAnimationFrame(thumbAll));
function el(tag,attrs={},...kids){const e=document.createElement(tag);
 for(const k in attrs){if(k==="text")e.textContent=attrs[k];else if(k==="class")e.className=attrs[k];else if(attrs[k]!==false&&attrs[k]!=null)e.setAttribute(k,attrs[k])}
 for(const k of kids)if(k!=null)e.append(k);return e}
let toastTimer;
function toast(text,bad){const t=$("toast");t.textContent="";t.append(el("span",{class:"ti"},icon(bad?"excl":"check")),el("span",{text}));
 t.className="toast show"+(bad?" bad":"");clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.className="toast"+(bad?" bad":""),bad?6000:3500)}
async function api(path,body){
 const r=await fetch(path,body===undefined?{cache:"no-store"}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error((d.errors||[d.error||r.statusText]).join("; "));return d}
const ms=v=>v!=null?Math.round(v)+" мс":"нет ответа";
const hostOf=u=>{try{return new URL(u).hostname}catch(e){return u}};
let countryNames={};const tname=c=>countryNames[c]||c;
const APP_NAMES={instagram:"Instagram",telegram:"Telegram",facebook:"Facebook",messenger:"Messenger",chatGpt:"ChatGPT",youtube:"YouTube",twitter:"X (Twitter)",whatsapp:"WhatsApp",tiktok:"TikTok",netflix:"Netflix",spotify:"Spotify",discord:"Discord",gemini:"Gemini",claude:"Claude"};
const APP_COLORS={instagram:"linear-gradient(135deg,#feda75,#d62976 55%,#4f5bd5)",telegram:"#2aabee",facebook:"#1877f2",youtube:"#ff0000",chatGpt:"#10a37f"};
const appName=a=>APP_NAMES[a]||a.charAt(0).toUpperCase()+a.slice(1);
const itemName=k=>k.startsWith("app:")?appName(k.slice(4)):k.startsWith("group:")?k.slice(6):k;
const tunnelLabel=c=>c==="ZZ"?"напрямую":c==="LL"?"авто":c;

// Tabs
function setTab(name){
 for(const b of document.querySelectorAll("[data-tab]"))b.setAttribute("aria-pressed",b.dataset.tab===name);
 $("tab-overview").hidden=name!=="overview";$("tab-settings").hidden=name!=="settings";$("savebar").hidden=name!=="settings";
 try{localStorage.setItem("tab",name)}catch(e){}
 requestAnimationFrame(thumbAll);scrollTo({top:0})
 if(name==="settings")loadBackups()}
for(const b of document.querySelectorAll("[data-tab]"))b.onclick=()=>setTab(b.dataset.tab);

// Settings form
const values={};
function segmented(key,opts){const s=el("div",{class:"seg",role:"radiogroup","aria-label":"Действие при сбое"});
 for(const [v,t] of opts){const b=el("button",{type:"button","data-value":v,"aria-pressed":"false",text:t});b.onclick=()=>{$(key).value=v;syncSeg(key);updateVisibility()};s.append(b)}return s}
function syncSeg(key){const v=$(key).value;for(const b of document.querySelectorAll(`[data-seg="${key}"] button`))b.setAttribute("aria-pressed",b.dataset.value===v);
 requestAnimationFrame(()=>thumb(document.querySelector(`[data-seg="${key}"]`)))}
GROUPS.forEach((g,gi)=>{
 const head=el("div",{class:"ghead",id:"g"+gi},tile(g.title),el("span",{text:g.title}));$("form").append(head);
 const nb=el("button",{type:"button","data-g":"g"+gi},tile(g.title),el("span",{text:g.title}));
 nb.onclick=()=>{navPick=head.id;navPickAt=Date.now();navMark(head.id);head.scrollIntoView({behavior:"smooth",block:"start"})};$("sidenav").append(nb);
 const card=el("div",{class:"card group"});
 for(const [key,type,label,help,opts] of g.fields){
  if(type==="services"){const input=el("input",{type:"hidden",id:key});input.dataset.key=key;
   const row=el("div",{class:"row block","data-field":key},el("div",{class:"row-text"},el("label",{text:label}),el("div",{class:"help",text:help})),
    el("div",{class:"tchips",id:"prioBox",style:"margin-top:10px"}),input);card.append(row);continue}
  if(type==="backups"){card.append(el("div",{class:"row block"},el("div",{class:"actions"},
    el("a",{class:"btn gray",href:"api/export",download:""},icon("download"),"Скачать файл"),
    (()=>{const f=el("input",{type:"file",accept:".json,application/json",hidden:""});f.onchange=()=>importFile(f);
     const b=el("button",{type:"button",class:"btn gray"},icon("upload"),"Загрузить файл");b.onclick=()=>f.click();return el("span",{},b,f)})()),
    el("div",{id:"backupList",style:"margin-top:10px"})));continue}
  if(type==="mailcats"){const input=el("input",{type:"hidden",id:key});input.dataset.key=key;
   const list=el("div",{class:"mailcats",id:"mailcats"});
   for(const [k,title,sub] of MAIL_CATS){const c=el("input",{type:"checkbox",class:"check","data-cat":k,"aria-label":title});
    c.onchange=()=>{input.value=[...list.querySelectorAll("[data-cat]")].filter(x=>x.checked).map(x=>x.dataset.cat).join(",")};
    list.append(el("label",{class:"mc-row"},c,el("span",{},el("b",{text:title}),el("small",{text:sub}))))}
   card.append(el("div",{class:"row block","data-field":key},el("div",{class:"row-text"},el("label",{text:label})),list,input));continue}
  if(type==="clearlog"){const b=el("button",{type:"button",class:"btn danger"},icon("trash"),"Очистить");
   b.onclick=async()=>{if(!await ask("Очистить журнал?","Все записи журнала будут удалены.",{ok:"Очистить",danger:true}))return;
    try{await api("/api/events/clear",{});toast("Журнал очищен");loadEvents()}catch(e){toast(e.message,true)}};
   card.append(el("div",{class:"row"},el("div",{class:"row-text"},el("label",{text:label}),el("div",{class:"help",text:help})),el("div",{class:"row-ctl"},b)));continue}
  if(type==="canaries"){const input=el("textarea",{id:key,hidden:""});input.dataset.key=key;card.append(input,el("div",{class:"sites",id:"canaryEditor"}));continue}
  const row=el("div",{class:"row","data-field":key}),text=el("div",{class:"row-text"}),ctl=el("div",{class:"row-ctl"});let input;
  text.append(el("label",{for:key,text:label}));if(help)text.append(el("div",{class:"help",text:help}));
  if(type==="switch"){input=el("input",{type:"checkbox",class:"switch",id:key,role:"switch"});input.onchange=updateVisibility}
  else if(type==="textarea"){row.className="row block";input=el("textarea",{id:key,class:"field",spellcheck:"false",placeholder:"Название=домен1,домен2"});
   input.dataset.key=key;row.append(text,input);card.append(row);continue}
  else if(type==="segmented"){row.className="row block";input=el("input",{type:"hidden",id:key});const s=segmented(key,opts);s.dataset.seg=key;
   text.append(el("div",{class:"help",id:"modeHelp"}));row.append(text,s,input);input.dataset.key=key;card.append(row);continue}
  else{input=el("input",{type,id:key,class:"field",autocomplete:type==="password"?"new-password":"off",spellcheck:"false"});
   if(type==="number"){input.step="any";input.inputMode="decimal"}else row.classList.add("wide")}
  input.dataset.key=key;ctl.append(input);row.append(text,ctl);card.append(row)}
 if(g.title==="Почта")card.append(el("div",{class:"row"},el("div",{class:"row-text"},el("label",{text:"Проверка почты"}),
  el("div",{class:"help",text:"Письмо уходит с сохранёнными настройками: сначала нажмите «Сохранить»"})),
  el("div",{class:"row-ctl"},el("button",{class:"btn gray",id:"testEmail",type:"button"},icon("mail"),"Тестовое письмо"))));
 $("form").append(card);if(g.foot)$("form").append(el("div",{class:"gfoot",text:g.foot}))});
// The sidebar follows the group in view
navUpdate();if(!navBound){navBound=true;addEventListener("scroll",navUpdate,{passive:true})}
const inputs=[...document.querySelectorAll("[data-key]")];
function val(key){const i=$(key);return i.type==="checkbox"?i.checked:i.value}
function updateVisibility(){
 for(const k in SHOW_IF){const [dep,vals]=SHOW_IF[k];document.querySelector(`[data-field="${k}"]`).hidden=!vals.includes(val(dep))}
 $("modeHelp").textContent=MODE_HELP[val("RECOVERY_ACTION")]||""}
async function loadSettings(){
 const s=await api("/api/settings");
 for(const i of inputs){const k=i.dataset.key;
  if(i.type==="checkbox")i.checked=!!s[k];
  else if(i.type==="password"){i.value="";i.placeholder=s[k+"_SET"]?"Задан":"Не задан"}
  else i.value=s[k]??""}
 canaryDefaults=s.DEFAULT_CANARIES||{};countryNames=s.COUNTRY_NAMES||{};testSites=(s.TEST_SITES||"").split(",").map(u=>u.trim()).filter(Boolean);renderPriority();
 const cats=new Set($("EMAIL_EVENTS").value.split(",").map(x=>x.trim()));
 for(const c of document.querySelectorAll("#mailcats [data-cat]"))c.checked=cats.has(c.dataset.cat);
 syncSeg("RECOVERY_ACTION");renderCanaries();updateVisibility()}

// Test sites. Stored in CANARIES as "CODE=url1,url2" lines; tunnels without one use defaults
let testSites=[],canaryDefaults={},statusTunnels=[];
function normUrl(v){v=v.trim();if(!v||/[,\s=]/.test(v))return null;if(!/^https?:\/\//i.test(v))v="https://"+v;
 try{return new URL(v).hostname.includes(".")?v:null}catch(e){return null}}
// Priority services: toggles for every service and app; the value is "app:x,group:Y"
function renderPriority(){const box=$("prioBox");if(!box)return;box.textContent="";
 const on=new Set($("FAILOVER_PRIORITY").value.split(",").map(x=>x.trim()).filter(Boolean));
 const keys=routesData?[...routesData.apps.map(a=>"app:"+a.app),...routesData.groups.map(g=>g.key)]:[];
 for(const k of [...new Set([...keys,...on])]){const b=el("button",{type:"button",class:"tch","aria-pressed":String(on.has(k)),text:itemName(k)+(k.startsWith("app:")?" · приложение":"")});
  b.onclick=()=>{on.has(k)?on.delete(k):on.add(k);$("FAILOVER_PRIORITY").value=[...on].join(",");renderPriority()};box.append(b)}
 if(!box.children.length)box.append(el("span",{class:"tag",text:"Список появится после первой проверки"}))}
// Test sites: each one tests the tunnel its domain goes through right now, so there is nothing to pick
function renderCanaries(focus){
 const box=$("canaryEditor");if(!box)return;box.textContent="";
 const routes=(routesData&&routesData.site_routes)||{},used=new Set();
 for(const u of testSites){const h=hostOf(u),real=routes[h],tunnel=real&&real!=="ZZ"&&real!=="LL";if(tunnel)used.add(real);
  const x=el("button",{type:"button",class:"x",title:"Убрать сайт","aria-label":"Убрать "+h},icon("x"));
  x.onclick=()=>{testSites=testSites.filter(v=>v!==u);renderCanaries()};
  box.append(el("div",{class:"cn-row"},el("div",{class:"cn-u"},el("span",{class:"tile",style:"background:"+(tunnel?"#30b0c7":"#8e8e93")},icon("globe")),el("span",{text:h})),
   el("div",{class:"cn-r"},el("span",{class:"tch",style:"cursor:default","aria-pressed":String(!!tunnel),
    title:tunnel?`Сейчас идёт через ${tname(real)} и проверяет его`:"",
    text:tunnel?`проверяет ${real}`:real?"идёт напрямую, туннели не проверяет":"страна определится при проверке"}),x)))}
 if(!testSites.length)box.append(el("div",{class:"tag",style:"padding:8px 0",text:"Список пуст: каждому туннелю сайты подбираются автоматически"}));
 const inp=el("input",{type:"url",class:"field",placeholder:"Добавить сайт, например example.com","aria-label":"Новый тестовый сайт",inputmode:"url",autocapitalize:"off"});
 const btn=el("button",{type:"button",class:"btn"},icon("plus"),"Добавить");
 const doAdd=()=>{const u=normUrl(inp.value);if(!u){toast("Неверный адрес сайта",true);return}
  if(!testSites.some(v=>hostOf(v)===hostOf(u)))testSites.push(u);renderCanaries(true)};
 btn.onclick=doAdd;inp.onkeydown=e=>{if(e.key==="Enter"){e.preventDefault();doAdd()}};
 box.append(el("div",{class:"add",style:"margin-top:10px"},inp,btn));
 const monitored=$("MONITOR_TUNNELS").value.split(",").map(t=>t.trim().toUpperCase()).filter(Boolean);
 // Tunnels topped up with temporary sites, and tunnels without any site of the list
 const rest=(monitored.length?monitored:statusTunnels).filter(c=>(canaryDefaults[c]||[]).length||!used.has(c));
 if(rest.length)box.append(el("div",{class:"autosites"},el("div",{text:`Добавлены автоматически, чтобы у туннеля было до ${$("SITES_PER_TUNNEL").value||3} сайтов:`}),
  ...rest.map(c=>el("div",{},el("b",{text:`${flag(c)} ${c}`}),"  "+((canaryDefaults[c]||[]).length?canaryDefaults[c].map(hostOf).join(", "):used.has(c)?"":!(c in canaryDefaults)?"определится при проверке":"через него ничего не идёт, не проверяется")))));
 if(focus)box.querySelector("input").focus()}
$("MONITOR_TUNNELS").oninput=()=>renderCanaries();

$("save").onclick=async()=>{$("TEST_SITES").value=testSites.join(",");const body={};for(const i of inputs)body[i.dataset.key]=val(i.dataset.key);
 try{await api("/api/settings",body);toast("Сохранено");loadSettings();loadStatus()}catch(e){toast(e.message,true)}};
$("testEmail").onclick=async()=>{toast("Отправка с сохранёнными настройками…");
 try{const d=await api("/api/test-email",{});toast(d.ok?"Тестовое письмо отправлено":"Ошибка: "+d.error,!d.ok)}catch(e){toast(e.message,true)}loadStatus()};
$("reset").onclick=async()=>{if(!await ask("Сбросить настройки?","Все изменения, сделанные в веб-интерфейсе, удалятся, и вернутся исходные значения из файла .env. Сервисы, «Авто» и предпочтительные туннели сохранятся.",{ok:"Сбросить",danger:true}))return;
 try{await api("/api/reset",{});toast("Настройки сброшены");loadSettings()}catch(e){toast(e.message,true)}};

// Overview
let lastStatus=null;
async function loadStatus(){
 let st;try{st=await api("/api/status")}catch(e){setPill("bad","Нет связи с сервером");return}
 lastStatus=st;const codes=Object.keys(st.tunnels||{});$("eventsBlock").hidden=st.show_events===false;
 if(codes.join()!==statusTunnels.join()){statusTunnels=codes;if(!$("MONITOR_TUNNELS").value.trim())renderCanaries()}
 $("runInfo").textContent=st.last_run?`Последняя проверка ${st.last_run.slice(11)} · следующая ${st.next_run?st.next_run.slice(11):"—"}`:"Проверок ещё не было";
 $("alert").hidden=!st.error;$("alert").textContent=st.error||"";
 if(st.last_run!==lastRunSeen){const first=lastRunSeen===null;lastRunSeen=st.last_run;
  await loadHistory();loadEvents();if(!first)loadRoutes()}
 else if(st.events_at!==eventsSeen)loadEvents();
 eventsSeen=st.events_at;
 renderTunnels();
 const em=st.last_email;$("emailInfo").textContent=em?`Последнее письмо ${em.time.slice(11)}: ${em.ok?"отправлено":"ошибка, "+em.error}`:"";
 $("emailInfo").className="small "+(em&&!em.ok?"bad":"muted");
 updatePill()}
// Ping history sparkline: one series, so no legend; failed checks are red ticks on the baseline
let historyData=null,eventsData=[],showAllEvents=false,lastRunSeen=null,eventsSeen=null;
function spark(code){
 const pts=historyData&&historyData.tunnels[code];if(!pts||pts.length<2)return null;
 const W=300,H=56,now=Date.now()/1000,t0=now-historyData.hours*3600,max=historyData.max_latency;
 const vals=pts.filter(p=>p[1]!=null).map(p=>p[1]);if(!vals.length)return null;
 const top=Math.max(...vals)*1.15||1,x=t=>(t-t0)/(now-t0)*W,y=v=>H-2-Math.min(v,top)/top*(H-6);
 let d="",pen=false;for(const [t,v] of pts){if(v==null){pen=false;continue}d+=(pen?"L":"M")+x(t).toFixed(1)+" "+y(v).toFixed(1);pen=true}
 const NS="http://www.w3.org/2000/svg",mk=(tag,a)=>{const e=document.createElementNS(NS,tag);for(const k in a)e.setAttribute(k,a[k]);return e};
 const svg=mk("svg",{viewBox:`0 0 ${W} ${H}`,preserveAspectRatio:"none",role:"img","aria-label":`Пинг ${code} за ${historyData.hours} ч`});
 if(max<top)svg.append(mk("line",{x1:0,x2:W,y1:y(max),y2:y(max),stroke:"var(--muted)","stroke-width":1,"stroke-dasharray":"3 3",opacity:.6,"vector-effect":"non-scaling-stroke"}));
 svg.append(mk("path",{d,fill:"none",stroke:"var(--accent)","stroke-width":2,"stroke-linejoin":"round","stroke-linecap":"round","vector-effect":"non-scaling-stroke"}));
 for(const [t,v,ok] of pts)if(!ok)svg.append(mk("line",{x1:x(t),x2:x(t),y1:H-8,y2:H,stroke:"var(--red-dot)","stroke-width":2,"vector-effect":"non-scaling-stroke"}));
 const cross=mk("line",{y1:0,y2:H,stroke:"var(--muted)","stroke-width":1,"vector-effect":"non-scaling-stroke",visibility:"hidden"});svg.append(cross);
 const wrap=el("div",{class:"spark"}),tip=el("div",{class:"tip",hidden:""});
 svg.addEventListener("pointermove",e=>{const r=svg.getBoundingClientRect(),t=t0+(e.clientX-r.left)/r.width*(now-t0);
  const p=pts.reduce((a,b)=>Math.abs(b[0]-t)<Math.abs(a[0]-t)?b:a);const px=x(p[0]);
  cross.setAttribute("x1",px);cross.setAttribute("x2",px);cross.setAttribute("visibility","visible");
  tip.hidden=false;tip.style.left=Math.min(Math.max(px/W*r.width,40),r.width-40)+"px";
  tip.textContent=new Date(p[0]*1000).toTimeString().slice(0,5)+" · "+(p[1]!=null?p[1]+" мс":"нет ответа")+(p[2]?"":" · сбой")});
 svg.addEventListener("pointerleave",()=>{cross.setAttribute("visibility","hidden");tip.hidden=true});
 const fails=pts.filter(p=>!p[2]).length;
 wrap.append(svg,tip,el("div",{class:"cap"},el("span",{text:`${historyData.hours} ч · мин ${Math.min(...vals)} · макс ${Math.max(...vals)} мс`}),el("span",{class:fails?"bad":"",text:fails?`сбоев ${fails}`:"без сбоев"})));
 return wrap}
async function loadHistory(){try{historyData=await api("/api/history")}catch(e){}}
async function loadEvents(){try{eventsData=(await api("/api/events")).events}catch(e){return}renderEvents()}
function renderEvents(){const box=$("events");box.textContent="";const today=new Date().toISOString().slice(0,10);
 const list=showAllEvents?eventsData.slice(0,150):eventsData.slice(0,8);
 if(!list.length)box.append(el("div",{class:"empty"},icon("clock"),"Событий пока нет"));
 const EVI={ok:"check",bad:"x",warn:"excl",info:"info"};
 for(const e of list)box.append(el("div",{class:"li"},el("span",{class:"evi "+e.kind},icon(EVI[e.kind]||"info")),
  el("div",{class:"tx",text:e.text}),el("div",{class:"tm",text:e.time.slice(0,10)===today?e.time.slice(11,16):e.time.slice(8,10)+"."+e.time.slice(5,7)+" "+e.time.slice(11,16)})));
 $("eventsMore").hidden=eventsData.length<=8;$("eventsMore").textContent=showAllEvents?"Свернуть":`Показать все (${Math.min(eventsData.length,150)})`}
$("eventsMore").onclick=()=>{showAllEvents=!showAllEvents;renderEvents()};
function renderServices(){const d=routesData;if(!d)return;
 const list=Object.entries(d.services||{}).sort((a,b)=>(a[1].ok-b[1].ok)||a[1].name.localeCompare(b[1].name));
 $("svcBlock").hidden=!list.length;const box=$("svcList");box.textContent="";
 for(const [key,x] of list){const prob=d.probation[key];
  const b=el("button",{type:"button",class:"svc",title:`${hostOf(x.url)}: ${x.latency!=null?Math.round(x.latency)+" мс":"нет ответа ("+x.status+")"}`+(prob?` · проверяется после переноса ${prob.from} → ${prob.to}`:"")},
   el("span",{class:"dot "+pingKind(x.latency)}),x.name,
   el("span",{class:"t"+(x.tunnel==="split"?" bad":""),text:x.tunnel==="split"?"⚠ разные страны":x.tunnel+(prob?" · проверка":"")}),
   el("span",{class:"v",text:x.latency!=null?Math.round(x.latency):"—"}));
  b.onclick=async()=>{$("rtFilter").value=x.name;openDoms.add(key);await loadRoutes();openSheet()};box.append(b)}}
async function loadBackups(){const box=$("backupList");if(!box)return;let list;
 try{list=(await api("/api/backups")).backups}catch(e){box.textContent=e.message;return}
 box.textContent="";if(!list.length){box.append(el("div",{class:"small muted",text:"Копий пока нет: первая появится перед первым изменением правил"}));return}
 for(const b of list){const r=el("button",{type:"button",class:"btn sm",text:"Восстановить"});
  r.onclick=async()=>{if(!await ask(`Восстановить копию от ${b.time}?`,`Доменов в копии: ${b.rules}. Домены, которых в копии нет, будут удалены. Текущие правила сначала сохранятся в новую копию.`,{ok:"Восстановить",danger:true}))return;
   r.disabled=true;try{const x=await api("/api/restore",{id:b.id});toast(`Восстановлено, изменено: ${x.changed.length}`)}catch(e){toast(e.message,true)}loadBackups();loadRoutes();loadEvents()};
  box.append(el("div",{class:"bk"},el("div",{class:"bk-t"},b.time,el("small",{text:`${b.reason||""} · доменов ${b.rules}`})),r))}}
async function importFile(input){const f=input.files[0];input.value="";if(!f)return;let data;
 try{data=JSON.parse(await f.text())}catch(e){toast("Файл не читается как JSON",true);return}
 if(data.app!=="deeper-watchdog"){toast("Это не файл Deeper Watchdog",true);return}
 if(!await ask(`Загрузить ${f.name}?`,`Доменов: ${(data.rules||[]).length}, файл от ${data.exported||"?"}. Настройки (кроме паролей и адреса Deeper) заменятся, домены добавятся или перенесутся в страны из файла.`,{ok:"Загрузить"}))return;
 try{const x=await api("/api/import",{data});toast(`Загружено, изменено правил: ${x.changed.length}`);await loadSettings()}catch(e){toast(e.message,true)}
 loadBackups();loadRoutes();loadEvents()}
// Green: answered, yellow: slower than the threshold, red: no answer
function pingKind(latency){const max=(routesData&&routesData.max_latency)||Infinity;return latency==null?"bad":latency>max?"warn":"ok"}
function siteList(tunnel,x){
 const sites=x&&x.sites&&x.sites.length?x.sites:routesData?Object.values(routesData.sites).filter(s=>s.tunnel===tunnel):[];
 if(!sites.length)return null;
 return el("ul",{class:"sitelist"},...sites.map(s=>el("li",{},el("span",{class:"dot "+pingKind(s.latency)}),
  el("span",{class:"h",text:hostOf(s.url)}),el("span",{class:"v",text:s.latency!=null?Math.round(s.latency)+" мс":"нет ответа"}))))}
// Check details are for the log; the card says the same in plain words when there is no site list
function plainDetails(x){const d=x.details||"";if(!d)return "";
 if(/^All canaries failed/.test(d))return "Тестовые сайты не ответили";
 if(/^High latency/.test(d))return `Пинг ${Math.round(x.latency)} мс — выше допустимого`;
 if(/^OK/.test(d))return "Тестовые сайты отвечают";
 return d.replace(/ \(HTTP \d+\)/g,"")}
function renderTunnels(){
 const st=lastStatus;if(!st)return;const codes=Object.keys(st.tunnels||{});
 const box=$("tunnels");box.textContent="";
 for(const c of codes){const x=st.tunnels[c];const action=(x.details||"").split(" → ")[1];
  const act=actionRow(c);
  if(x.unchecked){box.append(el("div",{class:"card tcard"},
   el("div",{class:"thead"},codeBadge(c),
    el("div",{},el("div",{class:"tname",text:x.country}),el("div",{class:"tstate"},el("span",{class:"dot"}),"Не проверяется")),tunnelButtons(c,x)),
   el("div",{class:"ping"},"—"),
   tmeta(x),
   act||el("div",{class:"details",text:"Через этот туннель сейчас не идёт ни один сайт, поэтому пинг не измерить. Перенесите в него сервис в «Пинг и рекомендации» или добавьте тестовый сайт."})));continue}
  const noNodes=x.pool===0;
  box.append(el("div",{class:"card tcard"},
   el("div",{class:"thead"},codeBadge(c),
    el("div",{},el("div",{class:"tname",text:x.country}),
     el("div",{class:"tstate "+(x.healthy?"ok":noNodes?"warn":"bad")},el("span",{class:"dot "+(x.healthy?"ok":noNodes?"warn":"bad")}),x.healthy?"Работает":noNodes?"Нет нод":"Сбой")),
    tunnelButtons(c,x)),
   el("div",{class:"ping "+(x.latency?pingKind(x.latency):"")},x.latency?String(Math.round(x.latency)):"—",el("small",{text:x.latency?"мс":""})),
   tmeta(x,st.fail_threshold),
   act,spark(c),
   noNodes?el("div",{class:"details",text:"Нет активных нод: сервисы переносятся в другие туннели, туннель перестраивается."}):siteList(c,x)||el("div",{class:"details",text:plainDetails(x)}),
   action?el("div",{class:"details",text:"→ "+action}):null))}
 if(!codes.length&&!st.error)box.append(el("div",{class:"card empty"},el("span",{class:"spin"}),"Ждём первую проверку…"))}
function codeBadge(c){const f=flag(c);return f?el("span",{class:"code",title:tname(c)},el("span",{class:"fw"},el("span",{class:"flag",text:f})),el("span",{class:"cc",text:c})):el("span",{class:"code",text:c})}
function tmeta(x,threshold){return el("div",{class:"meta"},el("span",{},icon("server"),x.ip||"—"),el("span",{},icon("nodes"),`${x.pool??"—"} ${plural(x.pool||0,"нода","ноды","нод")}`),
 threshold!=null?el("span",{class:x.fails?"warn":""},icon("tri"),`сбоев ${x.fails} из ${threshold}`):null)}
// What the watchdog is doing with the tunnel right now (rebuild, node switch, waiting for nodes)
function actionRow(c){const a=lastStatus&&(lastStatus.actions||{})[c];if(!a)return null;
 const sec=Math.max(0,lastStatus.now-a.since);
 return el("div",{class:"tact",role:"status"},el("span",{class:"spin","aria-hidden":"true"}),el("span",{text:a.text}),el("span",{class:"sec",text:sec+" с"}))}
// Actions of a tunnel live in its "⋯" menu, like on Apple platforms
function tunnelButtons(c,x){const busy=!!(lastStatus&&(lastStatus.actions||{})[c]);
 const b=el("button",{type:"button",class:"btn icon tmore","aria-label":"Действия с туннелем "+c,"aria-haspopup":"menu",title:busy?"Туннель сейчас занят":"Действия"},icon("more"));
 b.disabled=busy;
 b.onclick=()=>showMenu(b,[{header:`${flag(c)} ${tname(c)} · ${x.ip||"—"}`},
  {text:"Сменить ноду",icon:"swap",sub:(x.pool||0)<2?"В пуле одна нода":"Другая нода из пула",disabled:(x.pool||0)<2,onSelect:()=>switchNode(c,b)},
  {text:"Перестроить туннель",icon:"refresh",sub:"Пул нод соберётся заново",danger:true,onSelect:()=>refreshTunnel(c,b)},
  {sep:true},{text:"Пинг и рекомендации",icon:"chart",onSelect:async()=>{await loadRoutes();openSheet()}}],{align:"end"});
 return b}
function setPill(kind,text){const p=$("statePill");p.textContent="";p.className="pill "+kind;p.append(el("span",{class:"dot "+kind}),el("span",{text}));
 const h=$("heroIc");h.className="hero-ic "+kind;h.textContent="";
 h.append(kind==="warn"&&lastStatus&&Object.keys(lastStatus.actions||{}).length?el("span",{class:"spin",style:"width:26px;height:26px;border-width:3px"}):icon(kind==="ok"?"shieldok":kind==="bad"?"excl":kind==="warn"?"refresh":"shield"));
 $("heroTitle").textContent=text}
function updatePill(){const st=lastStatus;if(!st)return;
 if(routesData&&routesData.compare.running)return setPill("warn","Идёт сравнение");
 const acts=Object.entries(st.actions||{}).filter(([,a])=>!a.text.startsWith("Проверка…"));
 if(acts.length)return setPill("warn",acts.map(([c,a])=>c+": "+a.text.replace(/…$/,"")).join(" · "));
 if(st.error)return setPill("bad","Нет связи с Deeper");
 const bad=Object.entries(st.tunnels||{}).filter(([,x])=>!x.healthy).map(([c])=>c);
 if(bad.length)return setPill("bad","Сбой: "+bad.join(", "));
 const n=Object.keys(st.tunnels||{}).length;setPill(n?"ok":"",n?"Все туннели в норме":"Ожидание первой проверки")}

function renderApps(){
 const d=routesData,box=$("apps");if(!d)return;$("appsBlock").hidden=!d.apps.length;box.textContent="";
 const usable=d.all_tunnels.filter(t=>t.nodes>0);
 for(const a of d.apps){const r=d.app_results[a.app],key="app:"+a.app;
  const seg=el("div",{class:"seg accent",role:"radiogroup","aria-label":"Страна для "+appName(a.app)});
  for(const t of usable){const b=el("button",{type:"button","aria-pressed":String(t.code===a.tunnel),title:tname(t.code),text:t.code});
   b.onclick=async()=>{if(t.code===a.tunnel)return;for(const x of seg.children){x.disabled=true;x.setAttribute("aria-pressed",String(x===b))}thumb(seg);
    try{await api("/api/move",{domain:key,to:t.code});toast(`${appName(a.app)} теперь через ${tname(t.code)}`)}catch(e){toast(e.message,true)}loadRoutes()};
   seg.append(b)}
  const cur=usable.find(t=>t.code===a.tunnel);
  box.append(el("div",{class:"card tcard"},
   el("div",{class:"thead"},el("span",{class:"avatar",style:"background:"+(APP_COLORS[a.app]||"#8e8e93"),text:appName(a.app).charAt(0)}),
    el("div",{},el("div",{class:"tname",text:appName(a.app)}),
     el("div",{class:"small muted",style:"margin-top:3px",text:(cur?`${flag(a.tunnel)} через ${tname(a.tunnel)}`:"через "+tunnelLabel(a.tunnel))+(cur?` · ${cur.ip||"—"}`:"")}))),
   el("div",{class:"ping "+(r?pingKind(r.latency):"")},r&&r.latency?String(Math.round(r.latency)):"—",el("small",{text:r&&r.latency?"мс":r?"нет ответа":""})),
   el("div",{class:"meta"},el("span",{},icon("sparkle"),"Deeper рекомендует: "+(a.recommended.join(", ")||"—"))),
   seg))}
 requestAnimationFrame(thumbAll)}
async function refreshTunnel(tunnel,btn){
 if(!await ask(`Перестроить ${flag(tunnel)} ${tunnel}?`,`Пул нод соберётся заново, на это время связь через ${tname(tunnel)} прервётся.`,{ok:"Перестроить",danger:true}))return;
 btn.disabled=true;
 try{const r=await api("/api/refresh-tunnel",{tunnel});toast(`Туннель ${tunnel} перестроен: ${r.old_ip} → ${r.new_ip}, нод в пуле ${r.pool}`)}catch(e){toast(e.message,true)}
 btn.disabled=false;loadRoutes();setTimeout(loadStatus,4000)}
async function switchNode(tunnel,btn){
 if(!await ask(`Сменить ноду ${flag(tunnel)} ${tunnel}?`,`Это затронет все сайты и приложения, которые идут через ${tname(tunnel)}.`,{ok:"Сменить"}))return;
 btn.disabled=true;
 try{const r=await api("/api/switch-node",{tunnel});toast(`Нода ${tunnel}: ${r.old_ip} → ${r.new_ip}`)}catch(e){toast(e.message,true)}
 btn.disabled=false;loadRoutes();loadStatus()}

$("checkNow").onclick=async()=>{const btn=$("checkNow"),before=lastStatus&&lastStatus.last_run;btn.disabled=true;setBtn(btn,"spin","Проверяем…");
 try{await api("/api/check-now",{});
  for(let i=0;i<60;i++){await new Promise(r=>setTimeout(r,2000));await loadStatus();if(lastStatus&&lastStatus.last_run!==before)break}
  if(lastStatus&&lastStatus.last_run!==before){await loadRoutes();openSheet()}else toast("Проверка ещё идёт, результат появится позже")}
 catch(e){toast(e.message,true)}
 btn.disabled=false;setBtn(btn,"refresh","Проверить сейчас")};

// Ping & recommendations sheet
let routesData=null,routesTimer=null,wasRunning=false;const selected=new Set(),openDoms=new Set();
async function loadRoutes(){
 try{routesData=await api("/api/routes")}catch(e){return}
 countryNames=routesData.country_names||countryNames;
 const running=routesData.compare.running;
 if(wasRunning&&!running)toast(routesData.compare.error?"Ошибка сравнения: "+routesData.compare.error:"Сравнение завершено",!!routesData.compare.error);
 wasRunning=running;
 renderCanaries();renderPriority();renderApps();renderTunnels();renderServices();updatePill();if($("routes").open)renderRoutes();
 clearTimeout(routesTimer);if(running)routesTimer=setTimeout(loadRoutes,2000)}
function openSheet(){if(!$("routes").open){$("routes").showModal();document.activeElement&&document.activeElement.blur()}renderRoutes()}
function renderRoutes(){
 if(!routesData)return;
 const d=routesData,c=d.compare,results={};for(const r of c.results)results[r.domain]=r;
 // Test sites
 const tb=$("rtTests");tb.textContent="";
 // One row per site: the ping through every tunnel that tested it, side by side
 const byHost={};for(const x of Object.values(d.sites))(byHost[hostOf(x.url)]=byHost[hostOf(x.url)]||[]).push(x);
 const hosts=Object.keys(byHost).sort();
 if(!hosts.length)tb.append(el("div",{class:"empty",text:"Проверок ещё не было"}));
 for(const h of hosts){const real=d.site_routes[h],list=byHost[h].sort((a,b)=>a.tunnel.localeCompare(b.tunnel));
  const foreign=real&&list.some(x=>x.tunnel!==real);
  tb.append(el("div",{class:"li noselect tsite"},
   el("div",{class:"li-main"},el("span",{class:"li-title",text:h}),
    el("span",{class:"chip"+(foreign?" bad":""),title:foreign?`Сайт идёт через ${real}, поэтому в других туннелях он на самом деле проверяет ${real}`:"",text:real?"через "+real:"маршрут неизвестен"})),
   el("div",{class:"tpings"},...list.map(x=>el("span",{class:"tp",title:`${x.tunnel}: ${ms(x.latency)}${x.status!=null?" ("+x.status+")":""}`},
    el("span",{class:"dot "+pingKind(x.latency)}),el("b",{text:x.tunnel}),x.latency!=null?String(Math.round(x.latency)):"—")))))}
 // Compare controls
 const allKeys=allItemKeys();
 $("compareBtn").disabled=c.running||!allKeys.length;
 $("compareBtn").textContent=c.running?"Сравнение…":selected.size?`Сравнить выбранные (${selected.size})`:`Сравнить все (${allKeys.length})`;
 const [done,all]=(c.progress||"").split(" из ").map(Number);
 $("progress").hidden=!c.running;$("progress").firstChild.style.width=(all?Math.round(done/all*100):3)+"%";
 $("rtProgress").textContent=c.running?`Шаг ${c.progress||"…"}: ${c.stage||""}`:c.error?"Ошибка: "+c.error:c.finished?`Сравнение завершено ${c.finished.slice(11)}`:"";
 $("rtProgress").className="small "+(c.error?"bad":"muted");
 $("selAll").checked=allKeys.length>0&&selected.size===allKeys.length;
 $("selAll").indeterminate=selected.size>0&&selected.size<allKeys.length;
 // Apps and rules
 const auto=new Set(d.auto),q=$("rtFilter").value.trim().toLowerCase();
 const appItems=d.apps.map(a=>({key:"app:"+a.app,tunnel:a.tunnel})).filter(x=>!q||itemName(x.key).toLowerCase().includes(q));
 $("rtAppsHead").hidden=$("rtApps").hidden=!appItems.length;
 renderItems($("rtApps"),appItems,results,auto,d);
 const rules=d.groups.map(g=>({key:g.key,tunnel:g.main,group:g}))
  .filter(x=>!q||x.group.name.toLowerCase().includes(q)||x.group.domains.some(m=>m.domain.includes(q))).sort((a,b)=>
  (b.group.split-a.group.split)||(!!results[b.key]-!!results[a.key])||(selected.has(b.key)-selected.has(a.key))||(auto.has(b.key)-auto.has(a.key))||
  (b.group.domains.length>1)-(a.group.domains.length>1)||a.group.name.localeCompare(b.group.name));
 renderItems($("rtRules"),rules,results,auto,d);
 renderCatalog();
 if(!rules.length)$("rtRules").append(el("div",{class:"empty",text:d.whitelist.length?"Ничего не найдено":"Правила появятся после первой проверки"}))}
function moveButtons(key,label,exclude){
 const wrap=el("div",{class:"rec"},el("span",{class:"muted",text:label}));
 for(const t of routesData.all_tunnels.filter(t=>t.nodes>0&&t.code!==exclude)){
  const b=el("button",{type:"button",class:"btn sm",text:t.code,title:tname(t.code)});b.onclick=()=>moveDomain(key,t.code,b);wrap.append(b)}
 return wrap}
function renderItems(box,items,results,auto,d){box.textContent="";
 for(const {key,tunnel,group} of items){const res=results[key],name=group?group.name:itemName(key);
  const sel=el("input",{type:"checkbox",class:"check","aria-label":"Выбрать "+name});sel.checked=selected.has(key);
  sel.onchange=()=>{sel.checked?selected.add(key):selected.delete(key);renderRoutes()};
  const pin=(d.preferred||{})[key]||"",mode=auto.has(key)?"auto":pin,ev=(d.evacuated||{})[key];
  const sw=el("select",{class:"mini","aria-label":"Режим для "+name,title:"«Авто», предпочтительный туннель или вручную"});
  sw.append(el("option",{value:"","data-ic":"hand","data-sub":"Туннель выбираете вы, кнопками рядом",text:"Вручную"}),
   el("option",{value:"auto","data-ic":"sparkle","data-sub":"Сам переезжает туда, где пинг меньше",text:"Авто"}));
  const pg=el("optgroup",{label:"Предпочтительный туннель"});
  const tl=[...d.all_tunnels];if(pin&&!tl.some(t=>t.code===pin))tl.push({code:pin,nodes:0});
  for(const t of tl)pg.append(el("option",{value:t.code,"data-ic":"pin","data-short":`${flag(t.code)} ${t.code}`,"data-menu":`${flag(t.code)} ${t.code} · ${tname(t.code)}`,
   "data-sub":t.nodes?`${t.nodes} ${plural(t.nodes,"нода","ноды","нод")}`:"сейчас нет нод",text:t.code}));
  sw.append(pg);sw.dataset.tone=mode==="auto"?"on":pin?"pin":"";
  sw.value=mode;sw.onchange=()=>saveMode(key,sw.value,sw,mode);
  const tchip=group&&group.split
   ?el("span",{class:"chip bad",text:"⚠ "+Object.entries(group.tunnels).map(([t,n])=>`${t} ${n}`).join(" · ")})
   :el("span",{class:"chip",text:tunnelLabel(tunnel)});
  const main=el("div",{class:"li-main"},el("div",{class:"li-title"},name,tchip));
  if(pin&&ev&&ev.from===pin)main.append(el("div",{class:"warnline"},icon("clock"),`Временно в ${ev.to}: в ${pin} нет нод. Вернётся, как только они появятся`));
  else if(pin&&tunnel&&tunnel!==pin&&!(group&&group.split))main.append(el("div",{class:"warnline"},icon("pin"),`Вернётся в ${pin}, когда там будут ноды`));
  if(group){const n=group.domains.length,del=el("button",{type:"button",class:"btn sm danger"},icon("trash"),n>1?"Удалить все домены":"Удалить домен");
   del.onclick=()=>deleteDomains([key],`${name}: удалить ${n} ${plural(n,"домен","домена","доменов")} из Smart Route?`,del);
   const det=el("details",{class:"doms"},el("summary",{text:`${n} ${plural(n,"домен","домена","доменов")}`}),
   el("ul",{},...group.domains.map(m=>{const x=el("button",{type:"button",class:"xdel",title:"Удалить","aria-label":"Удалить "+m.domain},icon("x"));
    x.onclick=()=>deleteDomains([m.domain],`Удалить ${m.domain} из Smart Route?`,x);
    return el("li",{},el("span",{text:m.domain}),el("span",{},regroupSelect(m,group),el("span",{class:"chip"+(group.split&&m.tunnel!==group.main?" bad":""),text:m.tunnel}),x))})),
   addToGroupRow(group),el("div",{class:"rec"},del));det.open=openDoms.has(key);det.ontoggle=()=>det.open?openDoms.add(key):openDoms.delete(key);main.append(det)}
  if(res){
   const best=Object.entries(res.pings).filter(([,p])=>p.ms!=null).sort((a,b)=>a[1].ms-b[1].ms)[0];
   main.append(el("div",{class:"chips"},...Object.keys(res.pings).map(t=>{const p=res.pings[t];
    return el("span",{class:"chip"+(best&&best[0]===t?" best":"")+(p.ms==null?" bad":""),title:(p.total>1?`среднее по ${p.answered} из ${p.total} доменов, `:"")+String(p.status),text:`${t} ${p.ms!=null?Math.round(p.ms):"—"}`})})));
   const rec=el("div",{class:"rec"});
   if(res.error)rec.append(el("span",{class:"bad",text:"Ошибка: "+res.error}));
   else if(res.final!=="split"&&(res.split||(res.recommended&&res.final===res.recommended&&res.final!==res.original)))rec.append(el("span",{class:"ok",text:(res.split?`Собран в ${res.final}`:`Перенесён ${tunnelLabel(res.original)} → ${res.final}`)}));
   else if(res.recommended&&tunnel!==res.recommended){const base=(res.pings[res.original]||{}).ms;
    rec.append(el("span",{text:`Лучше ${res.recommended}`+(base!=null?`, быстрее на ${Math.round(base-res.pings[res.recommended].ms)} мс`:", в текущем не отвечает")}));
    const b=el("button",{type:"button",class:"btn sm",text:"Перенести"});b.onclick=()=>moveDomain(key,res.recommended,b);rec.append(b)}
   else if(group&&group.split){rec.append(el("span",{class:"muted",text:`Быстрее всего ${res.original}`}));
    const b=el("button",{type:"button",class:"btn sm",text:`Собрать в ${res.original}`});b.onclick=()=>moveDomain(key,res.original,b);rec.append(b)}
   else rec.append(el("span",{class:"muted",text:"Текущий туннель подходит"}));
   main.append(rec)}
  else if(group&&group.split)main.append(moveButtons(key,"Домены в разных странах. Собрать в:",null));
  const right=el("div",{class:"li-right"},sw);
  if(!mode&&!(group&&group.split)){right.classList.add("inline");right.prepend(tunnelSeg(key,tunnel,d))}
  box.append(el("div",{class:"li"},sel,main,right))}}
// Manual mode: the service's tunnel is picked right in the row
function tunnelSeg(key,tunnel,d){const s=el("div",{class:"seg tseg accent",role:"radiogroup","aria-label":"Туннель для "+itemName(key)});
 const tl=d.all_tunnels.filter(t=>t.nodes>0||t.code===tunnel);
 if(tunnel&&!tl.some(t=>t.code===tunnel))tl.push({code:tunnel,nodes:0});
 for(const t of tl){const on=t.code===tunnel;
  const b=el("button",{type:"button","aria-pressed":String(on),title:`${tname(t.code)}${t.nodes?"":" · нет нод"}`},`${flag(t.code)} ${t.code}`);
  b.disabled=!on&&!t.nodes;b.onclick=()=>{if(on)return;s.querySelectorAll("button").forEach(x=>x.setAttribute("aria-pressed",String(x===b)));thumb(s);moveDomain(key,t.code,b)};
  s.append(b)}
 requestAnimationFrame(()=>thumb(s));return s}
async function saveMode(key,mode,sw,was){const n=itemName(key);sw.disabled=true;
 try{const r=await api("/api/pin",{key,mode});
  toast(r.note||(mode==="auto"?`Авто включено для ${n}`:mode?`${n}: предпочтительный туннель ${mode}`:`${n}: вручную`),!!r.note);
  if(mode==="auto")wasRunning=true}
 catch(e){sw.value=was;toast(e.message,true)}sw.disabled=false;loadRoutes()}
async function moveDomain(domain,to,btn){btn.disabled=true;
 try{await api("/api/move",{domain,to});toast(`${itemName(domain)} перенесён в ${to}`)}catch(e){toast(e.message,true);btn.disabled=false}loadRoutes()}
$("compareBtn").onclick=async()=>{
 try{await api("/api/compare",{domains:[...selected]});wasRunning=true;toast("Сравнение запущено")}catch(e){toast(e.message,true)}loadRoutes()};
const plural=(n,a,b,c)=>{const m=n%10,h=n%100;return m===1&&h!==11?a:m>=2&&m<=4&&(h<12||h>14)?b:c};
function fillTunnels(sel){const v=sel.value;sel.textContent="";
 for(const t of routesData.all_tunnels.filter(t=>t.nodes>0))sel.append(el("option",{value:t.code,"data-short":`${flag(t.code)} ${t.code}`,"data-sub":`${t.nodes} ${plural(t.nodes,"нода","ноды","нод")}`,text:`${flag(t.code)} ${t.code} · ${tname(t.code)}`}));
 if(v&&[...sel.options].some(o=>o.value===v))sel.value=v;else if(sel.options.length)sel.selectedIndex=0}
function renderCatalog(){const d=routesData,pick=$("svcPick"),v=pick.value;pick.textContent="";
 for(const s of d.catalog){const n=Object.keys(s.present).length;
  pick.append(el("option",{value:s.name,"data-sub":n?`добавлено ${n} из ${s.domains.length}`:`${s.domains.length} ${plural(s.domains.length,"домен","домена","доменов")}`,text:s.name}))}
 if(v)pick.value=v;fillTunnels($("svcTun"));fillTunnels($("domTun"));fillGroups();
 const s=d.catalog.find(x=>x.name===pick.value),box=$("svcDoms");box.textContent="";if(!s)return;
 const to=$("svcTun").value;
 for(const dm of s.domains){const t=s.present[dm];
  box.append(el("span",{class:"chip"+(t===to?" best":""),title:t?"Уже в "+t:"Будет добавлен",text:t?`${dm} · ${t}`:dm}))}
 const left=s.domains.filter(dm=>s.present[dm]!==to).length;
 $("svcAdd").disabled=!left;$("svcAdd").textContent=left?`Добавить все домены (${left})`:"Все домены уже здесь"}
$("svcPick").onchange=$("svcTun").onchange=()=>renderCatalog();
$("svcAdd").onclick=async()=>{const b=$("svcAdd"),service=$("svcPick").value,to=$("svcTun").value;b.disabled=true;
 try{const r=await api("/api/add-domains",{service,to});toast(r.done.length?`${service}: ${r.done.length} ${plural(r.done.length,"домен","домена","доменов")} теперь через ${to}`:"Ничего менять не нужно")}
 catch(e){toast(e.message,true)}loadRoutes()};
// Moves an already added domain into another service (it also goes to that service's country)
function regroupSelect(m,group){
 const sel=el("select",{class:"mini","aria-label":"Перенести "+m.domain+" в другой сервис",title:"Перенести в другой сервис"});
 sel.append(el("option",{value:"",text:"В сервис…"}));
 const names=[...new Set([...routesData.groups.map(g=>g.name),...routesData.catalog.map(c=>c.name)])].filter(n=>n!==group.name).sort((a,b)=>a.localeCompare(b));
 for(const n of names)sel.append(el("option",{value:n,text:n}));
 sel.append(el("option",{value:"=new","data-ic":"plus",text:"Новый сервис…"}));
 sel.onchange=async()=>{let name=sel.value;if(!name)return;
  if(name==="=new"){name=(await ask("Новый сервис",`Как назвать сервис для ${m.domain}?`,{ok:"Создать",input:{placeholder:"Название"}}))||"";if(!name){sel.value="";return}}
  const target=routesData.groups.find(g=>g.name===name),to=target?target.main:m.tunnel;sel.disabled=true;
  try{await api("/api/add-domains",{domains:[m.domain],to,group:name});toast(`${m.domain} теперь в сервисе ${name}`+(to!==m.tunnel?`, через ${to}`:""))}
  catch(e){toast(e.message,true)}loadRoutes()};
 return sel}
const splitDomains=v=>v.split(/[\s,;]+/).filter(Boolean);
function addToGroupRow(group){
 const inp=el("input",{class:"field",placeholder:"Добавить домены в "+group.name,"aria-label":"Домены для "+group.name,autocapitalize:"off",spellcheck:"false"});
 const b=el("button",{type:"button",class:"btn sm",text:"Добавить"});
 b.onclick=async()=>{const domains=splitDomains(inp.value);if(!domains.length){toast("Введите домен",true);return}b.disabled=true;
  try{const r=await api("/api/add-domains",{domains,to:group.main,group:group.name});
   toast(`${group.name}: ${r.done.length?"добавлено "+r.done.join(", ")+" через "+group.main:"домены уже в сервисе"}`)}
  catch(e){toast(e.message,true);b.disabled=false}loadRoutes()};
 inp.onkeydown=e=>{if(e.key==="Enter")b.click()};
 return el("div",{class:"addrow"},inp,b)}
function fillGroups(){const sel=$("domGroup"),v=sel.value;sel.textContent="";
 sel.append(el("option",{value:"","data-ic":"folder","data-short":"Отдельный сервис","data-sub":"Название берётся из домена",text:"Отдельный сервис"}));
 const names=[...new Set([...routesData.groups.map(g=>g.name),...routesData.catalog.map(c=>c.name)])].sort((a,b)=>a.localeCompare(b));
 for(const n of names)sel.append(el("option",{value:n,"data-short":"В сервис "+n,text:n}));
 sel.value=names.includes(v)?v:""}
$("domGroup").onchange=()=>{const g=routesData.groups.find(x=>x.name===$("domGroup").value);if(g)$("domTun").value=g.main};
$("domAdd").onclick=async()=>{const b=$("domAdd"),domains=splitDomains($("domInput").value),to=$("domTun").value,group=$("domGroup").value;
 if(!domains.length){toast("Введите домен",true);return}b.disabled=true;
 try{const r=await api("/api/add-domains",group?{domains,to,group}:{domains,to});$("domInput").value="";toast(r.done.length?`Добавлено через ${to}: ${r.done.join(", ")}`:"Эти домены уже есть в "+to)}
 catch(e){toast(e.message,true)}b.disabled=false;loadRoutes()};
$("domInput").onkeydown=e=>{if(e.key==="Enter")$("domAdd").click()};
async function deleteDomains(domains,question,btn){if(!await ask(question,"Правила удалятся из Smart Route Deeper. Перед этим сохранится резервная копия.",{ok:"Удалить",danger:true}))return;btn.disabled=true;
 try{const r=await api("/api/delete-domains",{domains});toast(`Удалено: ${r.done.length} ${plural(r.done.length,"домен","домена","доменов")}`)}
 catch(e){toast(e.message,true);btn.disabled=false}loadRoutes()}
function allItemKeys(){return [...routesData.apps.map(a=>"app:"+a.app),...routesData.groups.map(g=>g.key)]}
$("selAll").onchange=()=>{if($("selAll").checked)for(const k of allItemKeys())selected.add(k);else selected.clear();renderRoutes()};
$("openRoutes").onclick=async()=>{await loadRoutes();openSheet()};
$("closeRoutes").onclick=()=>$("routes").close();
$("routes").addEventListener("click",e=>{if(e.target===$("routes"))$("routes").close()});
$("rtFilter").oninput=()=>renderRoutes();

hydrateIcons();document.querySelectorAll("select").forEach(enhanceSelect);
let tab="overview";try{tab=localStorage.getItem("tab")||tab}catch(e){}setTab(tab==="settings"?"settings":"overview");
loadSettings().catch(e=>toast("Не удалось загрузить настройки: "+e.message,true));
loadRoutes();
// Every 5 s, every 2 s while something is being done with a tunnel, rarely in a background tab
(function statusLoop(){loadStatus().finally(()=>setTimeout(statusLoop,
 document.hidden?30000:Object.keys((lastStatus&&lastStatus.actions)||{}).length?2000:5000))})();
document.addEventListener("visibilitychange",()=>{if(!document.hidden)loadStatus()});
</script></body></html>
"""


class SettingsHandler(BaseHTTPRequestHandler):
    """Web UI for viewing status and editing settings."""

    def log_message(self, fmt, *args):
        logger.debug("web: " + fmt % args)

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _check_auth(self):
        if not WEB_PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                password = base64.b64decode(header[6:]).decode("utf-8").split(":", 1)[-1]
                if hmac.compare_digest(password, WEB_PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Deeper Watchdog"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if not self._check_auth():
            return
        self.path = urllib.parse.urlparse(self.path).path
        if self.path == "/":
            self._send(200, WEB_PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path in ("/logo.svg", "/favicon.svg"):
            self._send(200, LOGO_SVG.encode("utf-8"), "image/svg+xml")
        elif self.path in ("/logo.png", "/favicon.ico"):
            self._send(200, LOGO_PNG, "image/png")
        elif self.path == "/logo-wide.png":
            self._send(200, LOGO_WIDE_PNG, "image/png")
        elif self.path == "/icon-192.png":
            self._send(200, ICON_192_PNG, "image/png")
        elif self.path == "/apple-touch-icon.png":
            self._send(200, APPLE_ICON_PNG, "image/png")
        elif self.path == "/manifest.webmanifest":
            self._send(200, json.dumps(WEB_MANIFEST, ensure_ascii=False).encode("utf-8"), "application/manifest+json")
        elif self.path == "/api/events":
            with STATE_LOCK:
                if EVENTS and EVENTS_DAYS and EVENTS[0].get("time", "") < time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(time.time() - EVENTS_DAYS * 86400)):
                    prune_events()
                events = list(reversed(EVENTS))
            self._send(200, {"events": events})
        elif self.path == "/api/history":
            self._send(200, {"hours": HISTORY_HOURS, "max_latency": MAX_LATENCY_MS,
                             "tunnels": {c: list(p) for c, p in HISTORY.items()}})
        elif self.path == "/api/backups":
            self._send(200, {"backups": list_backups()})
        elif self.path == "/api/export":
            try:
                snapshot = take_snapshot(shared_client())
            except Exception as e:
                return self._send(502, {"error": f"Не удалось получить правила из Deeper: {e}"})
            settings = current_settings()
            data = dict(snapshot, app="deeper-watchdog", version=1, exported=time.strftime("%Y-%m-%d %H:%M:%S"),
                        settings={k: v for k, v in settings.items() if k in EXPORT_SETTINGS})
            name = f"deeper-watchdog-{time.strftime('%Y%m%d-%H%M')}.json"
            self._send(200, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"), "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})
        elif self.path == "/api/settings":
            settings = current_settings()
            for key, (kind, *_) in SETTINGS_SCHEMA.items():
                if kind == "secret":
                    settings[key + "_SET"] = bool(settings[key])
                    settings[key] = ""
            settings["DEFAULT_CANARIES"] = ROUTES.get("auto_sites", {})
            settings["COUNTRY_NAMES"] = COUNTRY_NAMES
            self._send(200, settings)
        elif self.path == "/api/routes":
            self._send(200, {
                "whitelist": ROUTES["whitelist"], "tunnels": ROUTES["tunnels"], "site_routes": ROUTES["site_routes"],
                # Copies: the check and comparison threads may be changing these right now
                "sites": dict(SITE_RESULTS), "compare": dict(COMPARE, results=list(COMPARE["results"])),
                "auto": sorted(auto_route_domains()),
                "country_names": COUNTRY_NAMES,
                "apps": ROUTES["apps"], "app_results": dict(APP_RESULTS), "all_tunnels": ROUTES["all_tunnels"],
                "max_latency": MAX_LATENCY_MS,
                "groups": service_groups(ROUTES["whitelist"]),
                "catalog": service_catalog(ROUTES["whitelist"]),
                "services": dict(SERVICE_RESULTS),
                "probation": {k: {"from": p["from"], "to": p["to"]} for k, p in AUTO_STATE["probation"].items()},
                "blocked": {k: b["tunnel"] for k, b in AUTO_STATE["blocked"].items() if b.get("until", 0) > time.time()},
                "evacuated": dict(AUTO_STATE["evacuated"]),
                "preferred": preferred_tunnels(),
            })
        elif self.path == "/api/status":
            self._send(200, dict(STATUS, fail_threshold=FAIL_THRESHOLD, actions=ACTIONS, now=int(time.time()),
                                 show_events=SHOW_EVENTS))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._check_auth():
            return
        # Requiring JSON forces a CORS preflight, so other sites can't post here
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._send(415, {"error": "expected application/json"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            return self._send(400, {"error": "bad JSON"})
        self.path = urllib.parse.urlparse(self.path).path

        if self.path == "/api/settings":
            if not isinstance(body, dict):
                return self._send(400, {"error": "expected object"})
            before = current_settings()
            errors = save_settings(body)
            if errors:
                return self._send(400, {"errors": errors})
            after = current_settings()
            changed = [k for k in body if k in after and before.get(k) != after[k]]
            logger.info("Настройки обновлены через веб-интерфейс")
            if "TEST_SITES" in body:
                CHECK_NOW.set()  # New test sites: find out which tunnels they test right away
            changed = [k for k in changed if k != "AUTO_ROUTE_DOMAINS"]
            if changed:
                log_event("info", "Изменены настройки: " + ", ".join(changed), mail="changes")
            if "AUTO_ROUTE_DOMAINS" in body:
                unite_auto_groups()
            self._send(200, {"ok": True})
        elif self.path == "/api/test-email":
            ok = send_email_notification(
                "[Deeper Connect] Тестовое уведомление",
                "Тестовое письмо от Deeper Connect Watchdog!\n\nЕсли вы видите это сообщение, настройки почты работают корректно.",
                verbose=True
            )
            self._send(200, {"ok": ok, "error": None if ok else (STATUS["last_email"] or {}).get("error")})
        elif self.path == "/api/compare":
            domains = body.get("domains") if isinstance(body, dict) else None
            # An empty list means all Smart Route rules
            if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
                return self._send(400, {"error": "Неверный список сайтов"})
            if not start_compare(domains):
                return self._send(409, {"error": "Сравнение уже идёт"})
            self._send(200, {"ok": True})
        elif self.path == "/api/move":
            domain, to = (body.get("domain"), body.get("to")) if isinstance(body, dict) else (None, None)
            usable = {t["code"] for t in ROUTES["all_tunnels"] if t["nodes"] > 0} | set(ROUTES["tunnels"])
            is_app = isinstance(domain, str) and domain.startswith("app:")
            if not isinstance(domain, str) or to not in usable or (is_app and domain[4:] not in configured_apps()):
                return self._send(400, {"error": "Неизвестный сайт, приложение или туннель"})
            if not ROUTE_LOCK.acquire(timeout=2):
                return self._send(409, {"error": "Идёт проверка или сравнение, попробуйте через минуту"})
            ok, error = False, None
            try:
                client = shared_client()
                backup_rules(client, f"перед переносом {domain.split(':', 1)[-1]} в {to}")
                # Current tunnel from Deeper itself: the cached one may be stale
                if domain.startswith("group:"):
                    # The whole service goes to one tunnel
                    rules = [{"domain": i.get("domainName"), "tunnel": i.get("tunnelCode")} for i in client.get_whitelist_domains()]
                    group = next((g for g in service_groups(rules) if g["key"] == domain), None)
                    if group is None:
                        error = f"{domain[6:]} не найден в правилах Deeper"
                    else:
                        ok = group_mover(client, group)[0](to)
                        if not ok:
                            error = f"Deeper перенёс не все домены {domain[6:]}"
                else:
                    if is_app:
                        current = (client.get_apps().get(domain[4:]) or {}).get("tunnel")
                    else:
                        current = next((i.get("tunnelCode") for i in client.get_whitelist_domains() if i.get("domainName") == domain), None)
                    if current is None:
                        error = f"{domain} не найден в Deeper"
                    else:
                        ok = current == to or client.move_item(domain, current, to)
                client.get_routed_domains()
                client.refresh_apps_cache()
            except Exception as e:
                error = str(e)
                logger.error(f"Ошибка переноса {domain}: {e}")
            finally:
                ROUTE_LOCK.release()
            if not ok:
                return self._send(502, {"error": error or f"Deeper не перенёс {domain}"})
            for r in COMPARE["results"]:
                if r["domain"] == domain:
                    r["final"] = to
            end_probation(domain)
            prefs = preferred_tunnels()
            if domain in prefs and prefs[domain] != to:
                prefs[domain] = to  # Otherwise the watchdog would move it straight back
                save_settings({"PREFERRED_TUNNELS": preferred_setting(prefs)})
            log_event("info", f"{domain.split(':', 1)[-1]}: перенесён в {to} вручную"
                      + (", теперь это его предпочтительный туннель" if domain in prefs else ""), mail="changes")
            self._send(200, {"ok": True})
        elif self.path == "/api/pin":
            # mode: "" (nothing), "auto" (auto mode) or a tunnel code (preferred tunnel). One excludes the other:
            # auto mode moves a service to the fastest tunnel, a preferred tunnel keeps it in one place
            key, mode = (body.get("key"), body.get("mode")) if isinstance(body, dict) else (None, None)
            codes = {t["code"] for t in ROUTES["all_tunnels"]} | set(ROUTES["tunnels"])
            if not isinstance(key, str) or not key or "=" in key or "\n" in key or "," in key \
                    or not isinstance(mode, str) or (mode not in ("", "auto") and mode not in codes):
                return self._send(400, {"error": "Неверный сервис или туннель"})
            auto, prefs = auto_route_domains(), preferred_tunnels()
            was = "auto" if key in auto else prefs.get(key, "")
            auto.discard(key)
            prefs.pop(key, None)
            if mode == "auto":
                auto.add(key)
            elif mode:
                prefs[key] = mode
            errors = save_settings({"AUTO_ROUTE_DOMAINS": ",".join(sorted(auto)), "PREFERRED_TUNNELS": preferred_setting(prefs)})
            if errors:
                return self._send(400, {"errors": errors})
            end_probation(key)
            name = key.split(":", 1)[-1]
            note = None
            if mode == "auto":
                log_event("info", f"{name}: включено «Авто»" + (f", предпочтительный туннель {was} снят" if was not in ("", "auto") else ""))
                unite_auto_groups()
            elif mode:
                log_event("info", f"{name}: предпочтительный туннель {mode}" + (", «Авто» выключено" if was == "auto" else ""))
                nodes = {t["code"]: t["nodes"] for t in ROUTES["all_tunnels"]}
                if not nodes.get(mode):
                    note = f"В {mode} сейчас нет нод: {name} переедет туда, когда они появятся"
                elif ROUTE_LOCK.acquire(timeout=2):
                    try:
                        client = shared_client()
                        PIN_FAILED.pop(key, None)
                        enforce_preferred(client, {mode}, only={key})
                    except Exception as e:
                        note = f"Не удалось перенести сейчас: {e}"
                    finally:
                        ROUTE_LOCK.release()
                else:
                    note = f"Идёт проверка или сравнение: {name} переедет в {mode} в течение минуты"
            elif was:
                log_event("info", f"{name}: " + ("«Авто» выключено" if was == "auto" else f"предпочтительный туннель {was} снят"))
            self._send(200, {"ok": True, "note": note})
        elif self.path in ("/api/add-domains", "/api/delete-domains"):
            body = body if isinstance(body, dict) else {}
            adding = self.path == "/api/add-domains"
            raw, to, service = body.get("domains") or [], body.get("to"), body.get("service")
            group = body.get("group") if adding else None
            if group is not None and (not isinstance(group, str) or not group.strip() or len(group) > 60
                                      or any(c in group for c in "=;,\n\r")):
                return self._send(400, {"error": "Неверное название сервиса"})
            if service is not None:
                raw = known_groups().get(service) if isinstance(service, str) else None
                if raw is None:
                    return self._send(400, {"error": "Неизвестный сервис"})
            if not isinstance(raw, list):
                return self._send(400, {"error": "Неверный список доменов"})
            group_keys = [d for d in raw if isinstance(d, str) and d.startswith("group:") and not adding]
            domains = [normalize_domain(d) for d in raw if d not in group_keys]
            if None in domains or not (domains or group_keys):
                return self._send(400, {"error": "Неверный домен"})
            usable = {t["code"] for t in ROUTES["all_tunnels"] if t["nodes"] > 0} | set(ROUTES["tunnels"])
            if adding and to not in usable:
                return self._send(400, {"error": "Неизвестный туннель"})
            if not ROUTE_LOCK.acquire(timeout=2):
                return self._send(409, {"error": "Идёт проверка или сравнение, попробуйте через минуту"})
            done, failed, error = [], [], None
            try:
                client = shared_client()
                backup_rules(client, "перед добавлением доменов" if adding else "перед удалением доменов")
                current = {i.get("domainName"): i.get("tunnelCode") for i in client.get_whitelist_domains()}
                if group:
                    errors = add_to_service_group(group.strip(), list(dict.fromkeys(domains)),
                                                  [{"domain": d, "tunnel": t} for d, t in current.items()])
                    if errors:
                        raise RuntimeError("; ".join(errors))
                if adding:
                    # One service = one country: rules already present elsewhere are moved
                    for d in dict.fromkeys(domains):
                        if current.get(d) == to:
                            continue
                        ok = client.move_domain(d, current[d], to) if d in current else client.add_domain(d, to)
                        (done if ok else failed).append(d)
                else:
                    rules = [{"domain": d, "tunnel": t} for d, t in current.items()]
                    for g in service_groups(rules):
                        if g["key"] in group_keys:
                            domains += [m["domain"] for m in g["domains"]]
                    targets = [d for d in dict.fromkeys(domains) if d in current]
                    if targets:
                        (done if client.delete_domains(targets) else failed).extend(targets)
                client.get_routed_domains()
            except Exception as e:
                error = str(e)
                logger.error(f"Ошибка изменения правил: {e}")
            finally:
                ROUTE_LOCK.release()
            if done:
                what = f"добавлены в {to}" + (f" (сервис {group.strip()})" if group else "") if adding else "удалены"
                log_event("info", f"Домены {what}: {', '.join(done[:8])}" + (f" и ещё {len(done) - 8}" if len(done) > 8 else ""))
            if error or failed:
                return self._send(502, {"error": error or f"Deeper не принял: {', '.join(failed)}", "done": done})
            self._send(200, {"ok": True, "done": done})
        elif self.path == "/api/switch-node":
            tunnel = body.get("tunnel") if isinstance(body, dict) else None
            if tunnel not in {t["code"] for t in ROUTES["all_tunnels"]}:
                return self._send(400, {"error": "Неизвестный туннель"})
            if not ROUTE_LOCK.acquire(timeout=2):
                return self._send(409, {"error": "Идёт проверка или сравнение, попробуйте через минуту"})
            try:
                client = shared_client()
                before = get_tunnel(client, tunnel) or {}
                if before.get("activeNum", 0) < 2:
                    return self._send(409, {"error": f"В туннеле {tunnel} нет другой ноды для переключения"})
                set_action(tunnel, "Смена ноды…")
                res = client.switch_node(tunnel, before.get("activeIp") or "")
                if not (isinstance(res, dict) and res.get("success")):
                    return self._send(502, {"error": f"Deeper не сменил ноду: {res}"})
                time.sleep(2)
                after = get_tunnel(client, tunnel) or {}
                if after:
                    live_pool(tunnel, after)
                client.refresh_apps_cache()
            except Exception as e:
                logger.error(f"Ошибка смены ноды {tunnel}: {e}")
                return self._send(502, {"error": str(e)})
            finally:
                set_action(tunnel)
                ROUTE_LOCK.release()
            new_ip = after.get("activeIp") or res.get("activeIp")
            logger.info(f"Нода туннеля {tunnel} сменена вручную: {before.get('activeIp')} -> {new_ip}")
            log_event("info", f"{tunnel}: нода сменена вручную, IP {before.get('activeIp')} → {new_ip}", mail="changes")
            self._send(200, {"ok": True, "old_ip": before.get("activeIp"), "new_ip": new_ip})
        elif self.path == "/api/refresh-tunnel":
            tunnel = body.get("tunnel") if isinstance(body, dict) else None
            if tunnel not in {t["code"] for t in ROUTES["all_tunnels"]}:
                return self._send(400, {"error": "Неизвестный туннель"})
            if not ROUTE_LOCK.acquire(timeout=2):
                return self._send(409, {"error": "Идёт проверка или сравнение, попробуйте через минуту"})
            try:
                client = shared_client()
                before = get_tunnel(client, tunnel) or {}
                ok, new_ip, new_pool = refresh_and_wait(client, tunnel, COUNTRY_NAMES.get(tunnel, tunnel),
                                                        before.get("activeIp"), before.get("activeNum", 0))
                client.refresh_apps_cache()
            except Exception as e:
                logger.error(f"Ошибка перестроения туннеля {tunnel}: {e}")
                return self._send(502, {"error": str(e)})
            finally:
                ROUTE_LOCK.release()
            if not ok:
                return self._send(502, {"error": f"Deeper не перестроил туннель {tunnel}"})
            logger.info(f"Туннель {tunnel} перестроен вручную: {before.get('activeIp')} -> {new_ip} (пул: {new_pool})")
            log_event("info", f"{tunnel}: туннель перестроен вручную, IP {before.get('activeIp')} → {new_ip}", mail="changes")
            CHECK_NOW.set()  # Re-check right away so the overview shows the new state
            self._send(200, {"ok": True, "old_ip": before.get("activeIp"), "new_ip": new_ip, "pool": new_pool})
        elif self.path in ("/api/restore", "/api/import"):
            body = body if isinstance(body, dict) else {}
            restoring = self.path == "/api/restore"
            if restoring:
                bid = body.get("id")
                if not isinstance(bid, str) or not re.fullmatch(r"[0-9_-]+", bid):
                    return self._send(400, {"error": "Неверная копия"})
                snapshot = load_json(os.path.join(BACKUP_DIR, bid + ".json"), {})
                if not snapshot.get("rules"):
                    return self._send(404, {"error": "Копия не найдена"})
            else:
                snapshot = body.get("data")
                if not isinstance(snapshot, dict) or snapshot.get("app") != "deeper-watchdog":
                    return self._send(400, {"error": "Это не файл Deeper Watchdog"})
                if isinstance(snapshot.get("settings"), dict):
                    imported = {k: v for k, v in snapshot["settings"].items() if k in EXPORT_SETTINGS - {"DEEPER_HOST", "DEEPER_USER"}}
                    errors = save_settings(imported)
                    if errors:
                        return self._send(400, {"errors": errors})
            if not ROUTE_LOCK.acquire(timeout=2):
                return self._send(409, {"error": "Идёт проверка или сравнение, попробуйте через минуту"})
            changed, failed, error = [], [], None
            try:
                client = shared_client()
                backup_rules(client, "перед восстановлением копии" if restoring else "перед загрузкой файла")
                # Restore brings back exactly the saved rules; a file from elsewhere only adds and moves
                changed, failed = apply_snapshot(client, snapshot, exact=restoring)
                client.get_routed_domains()
                client.refresh_apps_cache()
            except Exception as e:
                error = str(e)
                logger.error(f"Ошибка восстановления правил: {e}")
            finally:
                ROUTE_LOCK.release()
            what = f"Восстановлена копия от {snapshot.get('time')}" if restoring else "Загружен файл настроек и правил"
            log_event("bad" if error or failed else "info",
                      f"{what}: изменено {len(changed)}" + (f", не удалось {len(failed)}" if failed else "") + (f", ошибка: {error}" if error else ""))
            if error or failed:
                return self._send(502, {"error": error or f"Deeper не принял: {', '.join(failed[:10])}", "changed": changed})
            self._send(200, {"ok": True, "changed": changed})
        elif self.path == "/api/check-now":
            CHECK_NOW.set()
            self._send(200, {"ok": True})
        elif self.path == "/api/events/clear":
            with STATE_LOCK:
                prune_events(clear=True)
            logger.info("Журнал очищен через веб-интерфейс")
            self._send(200, {"ok": True})
        elif self.path == "/api/reset":
            # Service groups and auto-mode ticks are set from the routes window, not .env: they survive a reset
            with SETTINGS_LOCK:
                kept = {k: v for k, v in load_saved_settings().items()
                        if k in ("SERVICE_GROUPS", "AUTO_ROUTE_DOMAINS", "PREFERRED_TUNNELS")}
                try:
                    os.remove(SETTINGS_FILE)
                except FileNotFoundError:
                    pass
                if kept:
                    save_settings(kept)
                apply_settings()
            logger.info("Настройки веб-интерфейса сброшены к значениям из .env")
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})


# Settings carried in an exported file (no passwords)
EXPORT_SETTINGS = {k for k, (kind, *_) in SETTINGS_SCHEMA.items() if kind != "secret"}

WEB_MANIFEST = {
    "name": "Deeper Watchdog", "short_name": "Deeper", "lang": "ru", "start_url": "./", "scope": "./",
    "display": "standalone", "background_color": "#f5f5f7", "theme_color": "#f5f5f7",
    "icons": [{"src": "icon-192.png", "sizes": "192x192", "type": "image/png"},
              {"src": "logo.png", "sizes": "512x512", "type": "image/png"}],
}


def live_pool(code, t):
    """Puts a tunnel's current IP and node count into the overview without waiting for the next check."""
    st = STATUS["tunnels"].get(code)
    if st and (st.get("pool") != t.get("activeNum", 0) or st.get("ip") != t.get("activeIp")):
        publish_tunnel(code, dict(st, pool=t.get("activeNum", 0), ip=t.get("activeIp")))


def watch_nodes_once(client, tunnels):
    """Live node counts for the web UI. A monitored tunnel without nodes moves its services out after
    FAILOVER_WAIT seconds and is rebuilt after EMPTY_REBUILD_AFTER seconds (again every EMPTY_REBUILD_EVERY)."""
    now = time.time()
    prefs = preferred_tunnels()
    ROUTES["all_tunnels"] = [{"code": t.get("tunnelCode"), "nodes": t.get("activeNum", 0), "ip": t.get("activeIp")}
                             for t in tunnels]
    for t in tunnels:
        code = t.get("tunnelCode")
        if code and t.get("activeNum", 0) > 0:
            NODES_SINCE.setdefault(code, now)
        else:
            NODES_SINCE.pop(code, None)
    # Back to the preferred tunnel once it has had nodes for NODES_STABLE seconds, so a flapping tunnel
    # doesn't bounce services back and forth
    ready = {c for c, since in NODES_SINCE.items() if now - since >= NODES_STABLE}
    global ENFORCED_AT, READY_SEEN
    READY_SEEN &= ready
    fresh = ready - READY_SEEN  # A preferred tunnel that just got its nodes back: return right away
    if not prefs:
        READY_SEEN = ready
    elif ready and (fresh or now - ENFORCED_AT >= 30) and MOVE_LOCK.acquire(blocking=False):
        try:
            ENFORCED_AT, READY_SEEN = now, ready  # Busy lock: stays fresh and is retried next tick
            enforce_preferred(client, ready)
        except Exception as e:
            logger.error(f"Ошибка возврата в предпочтительный туннель: {e}")
        finally:
            MOVE_LOCK.release()
    all_empty = rebuild_all_if_empty(client, tunnels, now)
    for t in tunnels:
        code = t.get("tunnelCode")
        if not code:
            continue
        live_pool(code, t)
        if MONITOR_TUNNELS and code not in MONITOR_TUNNELS:
            continue
        if t.get("activeNum", 0) > 0:
            EVAC_NOTIFIED.pop(code, None)
            if EMPTY_SINCE.pop(code, None) is not None:
                log_event("ok", f"{code}: ноды появились, нод {t.get('activeNum')}", mail="nodes_back")
                CHECK_NOW.set()
            continue
        if code not in EMPTY_SINCE:
            EMPTY_SINCE[code] = now
            log_event("bad", f"{code}: нет активных нод")  # Mailed with what was done about it
        empty_for = now - EMPTY_SINCE[code]
        if code in ACTIONS:
            continue  # Already being handled: a check, a rebuild or a failover
        # Services preferring this tunnel leave it even with failover off: they come back by themselves
        pinned = {k for k, c in prefs.items() if c == code}
        # Not during a comparison: it is moving services itself. Retried every 30 s, not every tick
        if (FAILOVER_EMPTY or pinned) and empty_for >= FAILOVER_WAIT and not COMPARE["running"] \
                and now - EVAC_TRIED.get(code, 0) >= 30 and MOVE_LOCK.acquire(blocking=False):
            try:
                EVAC_TRIED[code] = now
                if tunnel_services(client, code):
                    evacuate(client, code, only=None if FAILOVER_EMPTY else pinned, reason=f" дольше {int(empty_for)} с")
            except Exception as e:
                logger.error(f"Ошибка переноса из пустого туннеля {code}: {e}")
            finally:
                MOVE_LOCK.release()
        # A rebuild moves no routes, so it doesn't wait for a check or recovery of another tunnel to finish
        if EMPTY_REBUILD_AFTER and empty_for >= EMPTY_REBUILD_AFTER and code not in ACTIONS and not all_empty \
                and now - EMPTY_REBUILT.get(code, 0) >= EMPTY_REBUILD_EVERY:
            try:
                EMPTY_REBUILT[code] = now
                logger.warning(f"В туннеле {code} нет нод {int(empty_for)} с, перестраиваю...")
                log_event("warn", f"{code}: нет нод {int(empty_for)} с, перестраиваю туннель")
                ok, new_ip, new_pool = refresh_and_wait(client, code, COUNTRY_NAMES.get(code, code), t.get("activeIp"), 0)
                if not ok:
                    log_event("bad", f"{code}: Deeper не перестроил туннель", mail="no_nodes")
                elif new_pool:
                    log_event("ok", f"{code}: туннель перестроен, нод {new_pool}, IP {new_ip}", mail="nodes_back")
                else:
                    log_event("bad", f"{code}: после перестроения нод нет, повтор через {EMPTY_REBUILD_EVERY // 60} мин", mail="no_nodes")
            except Exception as e:
                logger.error(f"Ошибка перестроения пустого туннеля {code}: {e}")


def span(sec):
    return f"{sec // 60} мин" if sec >= 60 and sec % 60 == 0 else f"{sec} с"


def rebuild_all_if_empty(client, tunnels, now):
    """No nodes in any monitored tunnel: every ALL_EMPTY_REBUILD_EVERY seconds all of them are rebuilt at once
    and checked again. Returns True while all tunnels are empty and this is on (single rebuilds then wait)."""
    global ALL_EMPTY_SINCE, ALL_EMPTY_REBUILT
    watched = [t for t in tunnels if t.get("tunnelCode") and (not MONITOR_TUNNELS or t.get("tunnelCode") in MONITOR_TUNNELS)]
    if not watched or any(t.get("activeNum", 0) > 0 for t in watched):
        ALL_EMPTY_SINCE = 0  # Each tunnel reports its own nodes coming back
        return False
    if not ALL_EMPTY_SINCE:
        ALL_EMPTY_SINCE = now
        log_event("bad", "Нет нод ни в одном туннеле"
                  + (f": через {span(ALL_EMPTY_REBUILD_EVERY)} перестрою все туннели" if ALL_EMPTY_REBUILD_EVERY else ""),
                  mail="all_empty")
    if not ALL_EMPTY_REBUILD_EVERY:
        return False
    if now - max(ALL_EMPTY_SINCE, ALL_EMPTY_REBUILT) < ALL_EMPTY_REBUILD_EVERY or COMPARE["running"]:
        return True
    todo = [t for t in watched if t.get("tunnelCode") not in ACTIONS]
    if not todo:
        return True
    ALL_EMPTY_REBUILT = now
    codes = [t.get("tunnelCode") for t in todo]
    logger.warning(f"Нет нод ни в одном туннеле {int(now - ALL_EMPTY_SINCE)} с, перестраиваю все: {', '.join(codes)}")
    log_event("warn", f"Нет нод ни в одном туннеле {int(now - ALL_EMPTY_SINCE)} с, перестраиваю все туннели: {', '.join(codes)}")
    results = {}

    def rebuild(t):
        code = t.get("tunnelCode")
        EMPTY_REBUILT[code] = now
        try:
            results[code] = refresh_and_wait(client, code, COUNTRY_NAMES.get(code, code), t.get("activeIp"), 0)
        except Exception as e:
            logger.error(f"Ошибка перестроения туннеля {code}: {e}")
            results[code] = (False, None, 0)

    threads = [threading.Thread(target=rebuild, args=(t,), daemon=True) for t in todo]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    got = [f"{c} {r[2]}" for c, r in results.items() if r[0] and r[2]]
    failed = [c for c, r in results.items() if not r[0]]
    log_event("ok" if got else "bad",
              (f"Все туннели перестроены, ноды: {', '.join(got)}" if got
               else f"Все туннели перестроены, нод по-прежнему нет. Повтор через {span(ALL_EMPTY_REBUILD_EVERY)}")
              + (f". Deeper не перестроил: {', '.join(failed)}" if failed else ""), mail="all_empty")
    CHECK_NOW.set()  # Check everything again right away
    return True


def watch_nodes():
    global WATCHER_ON
    WATCHER_ON = True
    while True:
        time.sleep(NODE_WATCH_EVERY)
        try:
            client = shared_client()
            watch_nodes_once(client, client.list_tunnels())
        except Exception as e:
            logger.debug(f"Проверка нод: {e}")


def start_web_server():
    try:
        server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), SettingsHandler)
    except OSError as e:
        logger.error(f"Не удалось запустить веб-интерфейс на порту {WEB_PORT}: {e}")
        return
    threading.Thread(target=server.serve_forever, daemon=True).start()
    note = "" if WEB_PASSWORD else " (без пароля, задайте WEB_PASSWORD в .env)"
    logger.info(f"Веб-интерфейс настроек: http://<IP-сервера>:{WEB_PORT}/{note}")


def main():
    # CLI values default to None so settings from the web UI apply unless a flag is given explicitly
    parser = argparse.ArgumentParser(description="Deeper Connect Tunnel Watchdog")
    parser.add_argument("--host", help="Deeper Connect IP")
    parser.add_argument("--password", help="Admin password")
    parser.add_argument("--max-latency", type=int, help="Max latency threshold in ms")
    parser.add_argument("--test-only", action="store_true", help="Diagnose all tunnels once and print status without changes")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background daemon loop")
    parser.add_argument("--interval", type=int, help="Check interval in seconds for daemon mode")
    parser.add_argument("--switch", help="Manually force node switch for given tunnel (e.g. --switch NL)")
    parser.add_argument("--refresh", help="Manually force tunnel refresh for given tunnel (e.g. --refresh NL)")
    parser.add_argument("--test-email", action="store_true", help="Send a test email notification to verify SMTP settings")
    parser.add_argument("--log-file", help="Path to write log output")
    args = parser.parse_args()

    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True
    )

    if args.test_email:
        print("Отправка тестового письма с текущими настройками SMTP...")
        success = send_email_notification(
            "[Deeper Connect] Тестовое уведомление",
            "Тестовое письмо от Deeper Connect Watchdog!\n\nЕсли вы видите это сообщение, настройки почты работают корректно.",
            verbose=True
        )
        if success:
            print("Тестовое письмо успешно отправлено!")
        else:
            print("Ошибка отправки! Проверьте параметры SMTP в веб-интерфейсе или в файле .env.")
        return

    def client_params():
        return (args.host or DEEPER_HOST, DEEPER_USER, args.password or DEEPER_PASS)

    host, user, password = client_params()
    client = DeeperClient(host=host, username=user, password=password)

    if args.switch:
        tunnels = client.list_tunnels()
        curr_ip = next((t["activeIp"] for t in tunnels if t.get("tunnelCode") == args.switch), None)
        res = client.switch_node(args.switch, curr_ip or "")
        country = COUNTRY_NAMES.get(args.switch, args.switch)
        print(f"Результат switchNode для [{country}]: {res}")
        return

    if args.refresh:
        res = client.refresh_tunnel(args.refresh)
        country = COUNTRY_NAMES.get(args.refresh, args.refresh)
        print(f"Результат refreshTunnel для [{country}]: {res}")
        return

    if args.test_only:
        tunnels = client.list_tunnels()
        routed_domains = client.get_routed_domains()
        print(f"\n--- Диагностика туннелей Deeper Connect ({len(tunnels)} найдено) ---")
        for t in tunnels:
            code = t.get("tunnelCode")
            country = COUNTRY_NAMES.get(code, code)
            ip = t.get("activeIp")
            pool = t.get("activeNum")
            canaries = get_tunnel_canaries(code, routed_domains)
            healthy, lat, details = check_tunnel_health(code, canaries=canaries, max_latency_ms=args.max_latency)
            status_str = "OK (ЗДОРОВ)" if healthy else "DEGRADED (СБОЙ/ВЫСОКИЙ ПИНГ)"
            print(f"[{code} - {country}] Статус: {status_str} | IP: {ip} | Пул нод: {pool}")
            print(f"     Проверка: {details}\n")
        return

    if not DEEPER_PASS and not args.password:
        logger.error("Пароль Deeper Connect не задан: укажите DEEPER_PASS в .env или в настройках веб-интерфейса")

    if args.daemon:
        if WEB_ENABLED:
            start_web_server()
        threading.Thread(target=watch_nodes, daemon=True).start()
        logger.info(f"Запуск Deeper Watchdog в режиме демона (интервал: {args.interval or CHECK_INTERVAL}с, "
                    f"порог задержки: {args.max_latency or MAX_LATENCY_MS}мс, сбоев до восстановления: {FAIL_THRESHOLD})...")
        last_params = client_params()
        last_run = None
        while True:
            # Interval is re-read every tick so changes from the web UI apply without a restart
            interval = args.interval or CHECK_INTERVAL
            next_run = last_run + interval if last_run else time.time()
            if CHECK_NOW.is_set() or time.time() >= next_run:
                CHECK_NOW.clear()
                if client_params() != last_params:
                    last_params = client_params()
                    host, user, password = last_params
                    logger.info(f"Параметры подключения к Deeper Connect изменены ({host}), переподключение...")
                    client = DeeperClient(host=host, username=user, password=password)
                try:
                    with ROUTE_LOCK:
                        run_watchdog_iteration(client, max_latency_ms=args.max_latency)
                    unite_auto_groups()
                    scheduled_compare()
                    gain_compare()
                except Exception as e:
                    logger.error(f"Ошибка итерации: {e}")
                last_run = time.time()
                next_run = last_run + interval
            STATUS["next_run"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run))
            CHECK_NOW.wait(min(5, max(0.1, next_run - time.time())))
    else:
        run_watchdog_iteration(client, max_latency_ms=args.max_latency)


if __name__ == "__main__":
    main()
