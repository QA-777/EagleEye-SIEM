# ======================================================================================
# EagleEye SIEM — Windows Detection Rule: Brute Force
# ======================================================================================

import os
# ==============================================================================
# Load config and whitelist at import time (once per engine run, not per cycle)
# Both files are expected to sit in the project root alongside engine.py.
# os.path logic here means this works regardless of where you run the script from.
# ==============================================================================
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
THRESHOLD = 3

# Load whitelist.txt — one IP per line, lines starting with # are ignored
_wl_path = os.path.join(_ROOT, "whitelist.txt")
with open(_wl_path, "r") as f:
    WHITELIST_IPS = {
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    }


def detect_bruteforce(es, start_time):
    alerts = []

    query = {
        "query": {
            "bool": {
                "must":   [{"match": {"normalized_event_id": "4625"}}],
                "filter": [{"range": {"@timestamp": {"gt":start_time }}}]
            }
        },
        "size": 100
    }

    try:
        response = es.search(index="winlogbeat-*", body=query)
        failed_attempts = {}
        last_seen_time = {}
        hits = response['hits']['hits']

        for hit in hits:
            ip = hit['_source'].get('winlog', {}).get('event_data', {}).get('IpAddress', 'Unknown_IP')
            timestamp  = hit['_source'].get('@timestamp')

            if ip in ("-", "Unknown_IP") or ip in WHITELIST_IPS:
                continue

            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            if ip not in last_seen_time or timestamp > last_seen_time[ip]:
                last_seen_time[ip] = timestamp

        for ip, count in failed_attempts.items():
            if count >= THRESHOLD:
                alerts.append({
                    "id":      f"brute_{ip}_{last_seen_time[ip]}",
                    "message": f"[HIGH] Possible Brute Force Attack from IP {ip} ({count} failed logins)"
                })

    except Exception as e:
        print(f"Error in Brute Force rule: {e}")

    return alerts
