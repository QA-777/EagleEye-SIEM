# EagleEye SIEM — Linux Shared Utilities
# lookup_sudo_actor: finds WHO ran a privileged command by searching sudo logs
# near the event timestamp — used by linux_new_user.py and linux_priv_group.py

import re
from datetime import datetime, timedelta

# es              → Elasticsearch client instance
# timestamp       → the time the suspicious event occurred
# command_hint    → the command to search for in sudo logs (e.g. "useradd", "usermod")
# filebeat_idx    → the Elasticsearch index where Filebeat logs are stored
# window_seconds  → search 30 seconds before and after the event timestamp
def lookup_sudo_actor(es, timestamp, command_hint, filebeat_idx, window_seconds=30):
    try:
        # convert timestamp from ISO string to a datetime object
        # replace "Z" with "+00:00" because Python needs explicit UTC offset
        ts      = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        # subtract 30 seconds → start of search window
        t_start = (ts - timedelta(seconds=window_seconds)).isoformat()
        # add 30 seconds → end of search window
        t_end   = (ts + timedelta(seconds=window_seconds)).isoformat()

        # sudo log format: "sudo:     kali : TTY=pts/3 ; PWD=... ; COMMAND=/usr/sbin/usermod -aG sudo op"
        # we search for "COMMAND=" + command_hint in the same line
        # this is more reliable than searching for "sudo:" + command_hint
        # because "COMMAND=" always appears on the sudo actor line specifically
        q = {"query": {"bool": {"must": [{"match_phrase": {"message": "COMMAND="}},
                                          {"match_phrase": {"message": command_hint}}],
                                 "filter": [{"range": {"@timestamp": {"gte": t_start, "lte": t_end}}}]}},
             "size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}
        r = es.search(index=filebeat_idx, body=q)

        # r['hits']['hits'] is the list of matching log entries
        if r['hits']['hits']:
            # _source is the actual log data inside the matched entry
            msg = r['hits']['hits'][0]['_source'].get('message', '')
            # sudo log format: "sudo:     kali : TTY=pts/1 ; PWD=... ; COMMAND=..."
            # actor username is the word between "sudo:" and the next ":"
            m    = re.search(r'sudo:\s+(\S+)\s+:', msg)
            user = m.group(1) if m else ""
            return f"actor={user}" if user else ""
    except Exception:
        pass
    return ""
