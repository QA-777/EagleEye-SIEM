# EagleEye SIEM — Privilege Group Modification
# Detects: user added to sudo/root/adm/shadow via usermod or gpasswd
# Mirrors: Windows Event ID 4728

import os, yaml
from detectors.linux.linux_utils import lookup_sudo_actor

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(_ROOT, "config.yaml")) as f:
    _CFG = yaml.safe_load(f)
FILEBEAT_IDX = _CFG.get("elasticsearch", {}).get("filebeat_index", "filebeat-*")

PRIVILEGED_GROUPS = ["sudo", "root", "adm", "shadow"]


def detect_linux_priv_group(es, start_time):
    alerts = []
    for group in PRIVILEGED_GROUPS:
        query = {"query": {"bool": {
                    "must":   [{"match_phrase": {"message": f"to group '{group}'"}}],
                    "filter": [{"range":        {"@timestamp": {"gt": start_time}}}]}},
                 "size": 10}
        try:
            for hit in es.search(index=FILEBEAT_IDX, body=query)['hits']['hits']:
                src = hit['_source']
                msg = src.get('message', '')
                ts  = src.get('@timestamp', '')

                # direct field access — Filebeat already extracted these
                hostname = src.get('host', {}).get('hostname', 'unknown')
                host_ip  = src.get('host', {}).get('ip', ['unknown'])[0]

                # message format: "add 'tteesstt' to group 'sudo'"
                # added username is always between the FIRST pair of single quotes in the message
                # group is already known from the loop variable — no need to parse it
                user = msg.split("'")[1] if "'" in msg else "unknown"

                # find who ran usermod/gpasswd by searching sudo logs near this timestamp
                actor = (lookup_sudo_actor(es, ts, "usermod", FILEBEAT_IDX)
                         or lookup_sudo_actor(es, ts, "gpasswd", FILEBEAT_IDX)
                         or "actor=root (no sudo log)")

                alerts.append({"id": hit['_id'],
                                "message": (f"[HIGH] User Added to Privileged Group: "
                                            f"{actor} | user='{user}' → group='{group}' | "
                                            f"hostname={hostname} | host_ip={host_ip} | time={ts}")})
        except Exception as e:
            print(f"Error in Linux Priv Group rule (group={group}): {e}")
    return alerts
