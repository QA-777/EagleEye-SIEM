# EagleEye SIEM — Linux SSH Brute Force
# Detects: 5+ "Failed password" from same IP within 5 minutes → HIGH
# Reports targeted usernames so analyst knows targeted vs spray attack.
# Mirrors: Windows brute_force.py (Event ID 4625 grouped by IP + time window)

import os, yaml
from datetime import datetime, timezone, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(_ROOT, "config.yaml")) as f:
    _CFG = yaml.safe_load(f)

_LBF         = _CFG.get("linux_brute_force", {})
THRESHOLD    = _LBF.get("threshold", 5)
WINDOW_MINS  = _LBF.get("window_minutes", 5)
FILEBEAT_IDX = _CFG.get("elasticsearch", {}).get("filebeat_index", "filebeat-*")

with open(os.path.join(_ROOT, "whitelist.txt")) as f:
    WHITELIST_IPS = {l.strip() for l in f if l.strip() and not l.startswith("#")}


def detect_linux_brute_force(es, start_time):
    alerts = []
    now             = datetime.now(timezone.utc)
    engine_start    = datetime.fromisoformat(start_time) if isinstance(start_time, str) else start_time
    effective_start = max(engine_start, now - timedelta(minutes=WINDOW_MINS)).isoformat()

    query = {
        "query": {"bool": {
            "must":   [{"match_phrase": {"message": "Failed password"}}],
            "filter": [{"range": {"@timestamp": {"gt": effective_start}}}]
        }},
        "size": 500
    }

    try:
        # counts       → how many failures per attacker IP
        # last_seen    → latest failure timestamp per attacker IP
        # users        → which usernames were targeted per attacker IP
        # hostname_map → victim machine name per attacker IP
        counts, last_seen, users, hostname_map = {}, {}, {}, {}

        hits = es.search(index=FILEBEAT_IDX, body=query)['hits']['hits']

        for hit in hits:
            src      = hit['_source']
            msg      = src.get('message', '')
            ts       = src.get('@timestamp', '')
            # host.hostname = VICTIM machine — direct field access, Filebeat extracted this
            hostname = src.get('host', {}).get('hostname', 'unknown')

            # ATTACKER IP is only inside the message string
            # message format: "Failed password for [invalid user] X from ::1 port 49572 ssh2"
            # attacker IP is always the word right after " from "
            if " from " not in msg:
                continue
            ip = msg.split(" from ")[1].split()[0]

            if not ip or ip in WHITELIST_IPS:
                continue

            counts[ip]       = counts.get(ip, 0) + 1
            hostname_map[ip] = hostname

            if ip not in last_seen or ts > last_seen[ip]:
                last_seen[ip] = ts

            # targeted username is also only in the message string
            # format 1: "Failed password for root from ..."          → username = "root"
            # format 2: "Failed password for invalid user X from ..." → username = X
            if " for " in msg and " from " in msg:
                after_for = msg.split(" for ")[1].split(" from ")[0].strip()
                user      = after_for.replace("invalid user ", "").strip()
                if user:
                    users.setdefault(ip, set()).add(user)

        for ip, count in counts.items():
            if count >= THRESHOLD:
                ul    = sorted(users.get(ip, set()))
                ustr  = ", ".join(ul[:3]) + (f" (+{len(ul)-3} more)" if len(ul) > 3 else "")
                upart = f" | targeted users: {ustr}" if ustr else ""
                # bucket = current 5-minute slot e.g. "2026-04-24T06:10"
                # any attack from same IP within the same 5-minute window
                # gets the same ID → dedup catches it → only ONE alert fires
                bucket = now.strftime("%Y-%m-%dT%H:%M")[:-1] + "0"
                alerts.append({
                    "id": f"linux_brute_{ip}_{bucket}",
                    "message": (f"[HIGH] Linux SSH Brute Force: {count} attempts "
                                f"from actor={ip}{upart} → "
                                f"victim={hostname_map.get(ip, 'unknown')} "
                                f"in {WINDOW_MINS} minutes | "
                                f"time={last_seen[ip]}")
                })

    except Exception as e:
        print(f"Error in Linux Brute Force rule: {e}")
    return alerts
