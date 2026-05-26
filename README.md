# 🦅 EagleEye SIEM

A real-time Security Information and Event Management (SIEM) system built for detecting threats on both **Linux** and **Windows** machines, enriched with **Groq AI** for automated incident response playbooks.

---

## 📌 What It Does

EagleEye monitors system logs continuously and fires alerts when suspicious activity is detected. Each alert is automatically analyzed by an AI that generates a 3-step incident response playbook for the analyst.

---

## 🔍 Detection Rules

### Linux (via Filebeat → Elasticsearch)
| Rule | Mirrors | What it detects |
|---|---|---|
| `linux_auth.py` | Windows Event ID 4625 | Failed su and sudo authentication attempts |
| `linux_brute_force.py` | Windows Event ID 4625 | SSH brute force — 5+ failures from same IP in 5 minutes |
| `linux_new_user.py` | Windows Event ID 4720 | New user account created via useradd or adduser |
| `linux_priv_group.py` | Windows Event ID 4728 | User added to privileged group (sudo, root, adm, shadow) |

### Windows (via Winlogbeat → Elasticsearch)
| Rule | Event ID | What it detects |
|---|---|---|
| `brute_force.py` | 4625 | Failed login attempts grouped by IP |
| `log_cleared.py` | 1102, 104 | Windows event log cleared |
| `new_service.py` | 7045 | New service installed |
| `powershell.py` | 4688 | Suspicious PowerShell commands |

---

## 🏗️ Architecture
