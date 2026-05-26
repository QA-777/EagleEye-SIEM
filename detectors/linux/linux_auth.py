# EagleEye SIEM — Linux Auth Failure
# Detects: su failure (FAILED SU) + sudo wrong password (authentication failure + sudo:)
# Mirrors: Windows Event ID 4625

import os, yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(_ROOT, "config.yaml")) as f:
    _CFG = yaml.safe_load(f)
FILEBEAT_IDX = _CFG.get("elasticsearch", {}).get("filebeat_index", "filebeat-*")


def detect_linux_auth_fail(es, start_time):
    alerts = []
    query = {
        "query": {"bool": {
            # at least one condition must match
            "should": [
                {"match_phrase": {"message": "FAILED SU"}},
                {"bool": {"must": [{"match_phrase": {"message": "authentication failure"}},
                                   {"match_phrase": {"message": "sudo:"}}]}}
            ],
            "minimum_should_match": 1,
            "filter": [{"range": {"@timestamp": {"gt": start_time}}}]
        }},
        "size": 20
    }
    try:
        for hit in es.search(index=FILEBEAT_IDX, body=query)['hits']['hits']:
            src = hit['_source']
            msg = src.get('message', '')
            ts  = src.get('@timestamp', '')

            # direct field access — Filebeat already extracted these
            hostname = src.get('host', {}).get('hostname', 'unknown')
            host_ip  = src.get('host', {}).get('ip', ['unknown'])[0]

            # detect which command failed
            kind = "sudo" if "sudo:" in msg else "su"

            if kind == "su":
                # message format: "FAILED SU (to kali) tteesstt2 on pts/3"
                #                              ↑           ↑
                #                           TARGET        ACTOR
                # target = word inside "(to ...)"
                # actor  = word between ") " and " on"
                # terminal = word after "on"
                target   = msg.split("(to ")[-1].split(")")[0].strip() if "(to " in msg   else "unknown"
                actor    = msg.split(") ")[-1].split(" on")[0].strip() if ") " in msg     else "unknown"
                terminal = msg.split(" on ")[-1].strip()               if " on " in msg   else "unknown"

                alerts.append({"id": hit['_id'],
                                "message": (f"[HIGH] Linux Authentication Failure (su): "
                                            f"actor={actor} | target={target} | "
                                            f"terminal={terminal} | "
                                            f"hostname={hostname} | host_ip={host_ip} | time={ts}")})
            else:
                # message format: "authentication failure; logname=kali uid=1000 euid=0 tty=/dev/pts/0 ruser=kali rhost=  user=kali"
                # actor (ruser) = who tried to run sudo
                # target (user) = which user they tried to become (usually root)
                # tty = the terminal they used
                actor    = msg.split("ruser=")[-1].split()[0].strip(";,") if "ruser=" in msg else "unknown"
                target   = msg.split(" user=")[-1].split()[0].strip(";,") if " user=" in msg else "unknown"
                terminal = msg.split("tty=")[-1].split()[0].strip(";,")   if "tty="   in msg else "unknown"

                alerts.append({"id": hit['_id'],
                                "message": (f"[HIGH] Linux Authentication Failure (sudo): "
                                            f"actor={actor} | target={target} | "
                                            f"terminal={terminal} | "
                                            f"hostname={hostname} | host_ip={host_ip} | time={ts}")})
    except Exception as e:
        print(f"Error in Linux Auth rule: {e}")
    return alerts
