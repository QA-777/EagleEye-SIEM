# ======================================================================================
# EagleEye SIEM: The Main Engine
# ======================================================================================

import time, os, re, sqlite3, logging, yaml
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

load_dotenv()

from detectors.windows.brute_force import detect_bruteforce
from detectors.windows.log_cleared import detect_log_clear
from detectors.windows.new_service import detect_new_service
from detectors.windows.powershell import detect_suspicious_powershell
from detectors.linux.linux_auth import detect_linux_auth_fail
from detectors.linux.linux_new_user import detect_linux_new_user
from detectors.linux.linux_priv_group import detect_linux_priv_group
from detectors.linux.linux_brute_force import detect_linux_brute_force

from ai_engine.groq_enrichment import enrich_alert_with_ai

warnings.simplefilter("ignore", InsecureRequestWarning)
init(autoreset=True)

# ======================================================================================
# Load config.yaml
# ======================================================================================
_ROOT     = os.path.dirname(os.path.abspath(__file__))
_cfg_path = os.path.join(_ROOT, "config.yaml")

with open(_cfg_path, "r") as f:
    CFG = yaml.safe_load(f)

# Pull each section out with a safe fallback in case a key is missing
_es_cfg  = CFG.get("elasticsearch", {})
_eng_cfg = CFG.get("engine", {})

ES_HOST              = _es_cfg.get("host",              "http://127.0.0.1:9200")
ES_USER              = _es_cfg.get("user",              "elastic")
ALERTS_INDEX         = _es_cfg.get("alerts_index",      "siem_alerts")
POLL_INTERVAL        = _eng_cfg.get("poll_interval",    5)    # seconds between cycles
LOOKBACK_MINUTES     = _eng_cfg.get("lookback_minutes", 10)   # how far back to search
DEDUP_RETENTION_DAYS = _eng_cfg.get("dedup_retention_days", 3)

# Credentials still come from .env — never from config.yaml
ES_PASSWORD   = os.getenv("ELASTIC_PASSWORD")
DEDUP_DB_PATH = os.path.join(_ROOT, "dedup.db")

# ======================================================================================
# Logging — file only, print() owns the terminal
# ======================================================================================
LOG_PATH = os.path.join(_ROOT, "eagleeye.log")
log = logging.getLogger("eagleeye")
log.setLevel(logging.DEBUG)
_fmt  = logging.Formatter("%(asctime)s | %(levelname)-5s | %(message)s", "%Y-%m-%d %H:%M:%S")
_file = RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
_file.setLevel(logging.DEBUG)
_file.setFormatter(_fmt)
log.addHandler(_file)

# ======================================================================================
# Elasticsearch client
# ======================================================================================
if not ES_PASSWORD:
    print(Fore.RED + "[-] CRITICAL: ELASTIC_PASSWORD not found in .env!" + Style.RESET_ALL)
    log.error("ELASTIC_PASSWORD not found in .env!")

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD), request_timeout=30)

# ======================================================================================
# Persistent Dedup
# ======================================================================================

def init_dedup_db():
    conn = sqlite3.connect(DEDUP_DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS seen_alerts (alert_id TEXT PRIMARY KEY, seen_at TEXT NOT NULL)")
    conn.commit(); conn.close()

def is_already_seen(alert_id):
    conn = sqlite3.connect(DEDUP_DB_PATH)
    found = conn.execute("SELECT 1 FROM seen_alerts WHERE alert_id=?", (alert_id,)).fetchone()
    conn.close(); return found is not None

def mark_as_seen(alert_id):
    conn = sqlite3.connect(DEDUP_DB_PATH)
    conn.execute("INSERT OR IGNORE INTO seen_alerts (alert_id, seen_at) VALUES (?,?)",
                 (alert_id, datetime.now(timezone.utc).isoformat()))
    conn.commit(); conn.close()

def cleanup_old_dedup_records(days=3):
    conn = sqlite3.connect(DEDUP_DB_PATH)
    deleted = conn.execute("DELETE FROM seen_alerts WHERE seen_at < datetime('now',?)",
                           (f'-{days} days',)).rowcount
    conn.commit(); conn.close()
    if deleted:
        print(Fore.CYAN + f"[*] Dedup DB: cleaned {deleted} old records." + Style.RESET_ALL)
        log.info(f"Dedup DB: cleaned {deleted} old records.")

# ======================================================================================
# Helper Functions
# ======================================================================================

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
def clean_terminal_colors(text):
    return ANSI_ESCAPE.sub("", str(text)) if text else ""

def get_severity_from_message(msg):
    m = clean_terminal_colors(msg).upper()
    return "HIGH" if ("[CRITICAL]" in m or "[HIGH]" in m) else ("MEDIUM" if "[MEDIUM]" in m else "LOW")

def send_desktop_notification(msg):
    try:
        clean   = clean_terminal_colors(msg).replace("'","").replace('"',"")
        urgency = "critical" if get_severity_from_message(clean) == "HIGH" else "normal"
        os.system(f"notify-send -u {urgency} '🚨 EagleEye SIEM' '{clean}'")
    except Exception: pass

def save_to_elasticsearch(alert):
    clean_msg = clean_terminal_colors(alert.get("message",""))
    doc = {
        "@timestamp":      datetime.now(timezone.utc).isoformat(),
        "message":         clean_msg,
        "severity":        alert.get("severity", get_severity_from_message(clean_msg)),
        "source_event_id": alert.get("id"),
        "ai_error":        alert.get("ai_error"),
        "status":          "Open",
        "analyst_note":    ""
    }
    try:
        es.index(index=ALERTS_INDEX, document=doc)
    except Exception as e:
        print(Fore.RED + f"[!] DB Save Failed: {e}" + Style.RESET_ALL)
        log.error(f"DB Save Failed: {e}")

def enrich_alert_safely(alert):
    original = alert.get("message","")
    alert["severity"] = get_severity_from_message(original)
    alert["ai_error"]  = None
    try:
        playbook = enrich_alert_with_ai(original)
        if playbook and str(playbook).strip():
            alert["message"]  = f"{original}\n\n{playbook}"
            alert["severity"] = get_severity_from_message(alert["message"])
    except Exception as e:
        alert["ai_error"] = str(e)
        alert["message"]  = original
        print(Fore.YELLOW + f"[!] AI failed for {alert.get('id','?')}: {e}" + Style.RESET_ALL)
        log.warning(f"AI failed for {alert.get('id','?')}: {e}")
    return alert

def pretty_print_and_save(alerts_objects):
    new_alerts = [a for a in alerts_objects if not is_already_seen(a["id"])]
    if not new_alerts: return

    print(Fore.CYAN + f"\n==== DETECTED {len(new_alerts)} NEW ALERTS ====" + Style.RESET_ALL)
    log.info(f"Detected {len(new_alerts)} new alerts.")

    for alert in new_alerts:
        msg      = alert.get("message","")
        severity = alert.get("severity", get_severity_from_message(msg))
        color    = Fore.RED if severity=="HIGH" else (Fore.YELLOW if severity=="MEDIUM" else Fore.GREEN)
        clean    = clean_terminal_colors(msg)

        print(color + clean + Style.RESET_ALL)
        log.info(f"[{severity}] {clean}")

        mark_as_seen(alert["id"])
        save_to_elasticsearch(alert)
        send_desktop_notification(msg)

    print(Fore.CYAN + "    [+] Alerts processed." + Style.RESET_ALL)
    log.info("Alerts processed.")

# ======================================================================================

def main():
    print(Fore.CYAN + "[*] EagleEye SIEM Engine Started." + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Config loaded from: {_cfg_path}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Logging to: {LOG_PATH}" + Style.RESET_ALL)
    log.info("EagleEye SIEM Engine Started.")

    init_dedup_db()
    cleanup_old_dedup_records(days=DEDUP_RETENTION_DAYS)

    if not es.ping():
        print(Fore.RED + "[-] Elasticsearch unreachable! Check Docker and ELASTIC_PASSWORD in .env." + Style.RESET_ALL)
        log.error("Elasticsearch unreachable at startup.")
        return

    ENGINE_START_TIME = datetime.now(timezone.utc)

    while True:
        try:
            lookback         = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
            look_back_window = max(ENGINE_START_TIME, lookback).isoformat()

            alerts  = []
            alerts += detect_bruteforce(es, look_back_window)
            alerts += detect_log_clear(es, look_back_window)
            alerts += detect_new_service(es, look_back_window)
            alerts += detect_suspicious_powershell(es, look_back_window)
            
            alerts += detect_linux_auth_fail(es, look_back_window)
            alerts += detect_linux_brute_force(es, look_back_window)
            alerts += detect_linux_new_user(es, look_back_window)
            alerts += detect_linux_priv_group(es, look_back_window)

            if alerts:
                fresh = [a for a in alerts if not is_already_seen(a["id"])]
                if fresh:
                    print(Fore.MAGENTA + f"[*] Sending {len(fresh)} fresh alerts to Groq AI..." + Style.RESET_ALL)
                    log.info(f"Sending {len(fresh)} fresh alerts to Groq AI.")
                    for i, alert in enumerate(alerts):
                        if not is_already_seen(alert["id"]):
                            alerts[i] = enrich_alert_safely(alert)

            pretty_print_and_save(alerts)
            time.sleep(POLL_INTERVAL)  # from config.yaml

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] EagleEye SIEM Engine stopped." + Style.RESET_ALL)
            log.info("Engine stopped by user.")
            break
        except Exception as e:
            print(Fore.RED + f"\n[!] Unexpected error: {e}" + Style.RESET_ALL)
            log.error(f"Unexpected error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

