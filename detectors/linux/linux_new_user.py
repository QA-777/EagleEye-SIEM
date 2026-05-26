# EagleEye SIEM — New Linux User Created
# Detects: useradd ("new user: name=") and adduser ("new user '")
# WHY BOTH: adduser is the default tool on Kali/Debian. Watching only useradd
#           lets an attacker evade by using adduser instead.
# Mirrors: Windows Event ID 4720

import os, yaml, re
from detectors.linux.linux_utils import lookup_sudo_actor

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(_ROOT, "config.yaml")) as f:
    _CFG = yaml.safe_load(f)
FILEBEAT_IDX = _CFG.get("elasticsearch", {}).get("filebeat_index", "filebeat-*")


def detect_linux_new_user(es, start_time):
    alerts = []
    query = {
        "query": {"bool": {
            "should": [{"match_phrase": {"message": "new user: name="}},
                       {"match_phrase": {"message": "new user '"}}],
            "minimum_should_match": 1,
            "filter": [{"range": {"@timestamp": {"gt": start_time}}}]
        }},
        "size": 10
    }
    try:
        for hit in es.search(index=FILEBEAT_IDX, body=query)['hits']['hits']:
            src = hit['_source']
            msg = src.get('message', '')
            ts  = src.get('@timestamp', '')

            # direct field access — Filebeat already extracted these
            hostname = src.get('host', {}).get('hostname', 'unknown')
            host_ip  = src.get('host', {}).get('ip', ['unknown'])[0]
            os_name  = src.get('host', {}).get('os', {}).get('name', 'unknown')

            tool = "useradd" if "new user: name=" in msg else "adduser"

            if tool == "useradd":
                # message format: "new user: name=tteesstt, UID=1007, GID=1008, home=/home/tteesstt, shell=/bin/sh, from=/dev/pts/2"
                # all fields are key=value pairs separated by ", "
                # we split by ", " then split each pair by "=" to build a dictionary
                raw    = msg.split("new user: ")[-1]
                fields = {k.strip(): v.strip() for k, v in
                          (f.split("=", 1) for f in raw.split(", ") if "=" in f)}
                user  = fields.get("name",  "unknown")
                uid   = fields.get("UID",   "")
                gid   = fields.get("GID",   "")
                home  = fields.get("home",  "")
                shell = fields.get("shell", "")

            else:
                # adduser format: "new user 'tteesstt' (uid=1001) in group 'tteesstt'"
                # username is between the first pair of single quotes
                # uid is inside (uid=...)
                user  = msg.split("'")[1]                                    if "'" in msg       else "unknown"
                uid   = re.search(r'\(uid=(\d+)\)', msg).group(1)            if re.search(r'\(uid=(\d+)\)', msg) else ""
                gid   = ""
                home  = ""
                shell = ""

            # find who ran the useradd/adduser command by searching sudo logs near this timestamp
            actor     = lookup_sudo_actor(es, ts, tool, FILEBEAT_IDX)
            actor_str = actor if actor else "actor=root (no sudo log)"

            # UID=0 means the new user is a root clone — most dangerous persistence technique
            uid_note  = f" | UID={uid}" + (" (root clone!)" if uid == "0" else "") if uid else ""
            gid_note  = f" | GID={gid}"     if gid   else ""
            home_note = f" | home={home}"   if home   else ""
            sh_note   = f" | shell={shell}" if shell  else ""

            alerts.append({"id": hit['_id'],
                            "message": (f"[HIGH] New Linux User Created (Possible Backdoor): "
                                        f"{actor_str} | username='{user}'"
                                        f"{uid_note}{gid_note}{home_note}{sh_note} | "
                                        f"hostname={hostname} | host_ip={host_ip} | "
                                        f"os={os_name} | time={ts}")})
    except Exception as e:
        print(f"Error in Linux New User rule: {e}")
    return alerts
