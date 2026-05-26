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
Log Sources (Linux auth.log / Windows Event Logs)
->
Filebeat / Winlogbeat
->
Logstash (normalization)
->
E.lasticsearch (storage)
->
EagleEye Engine (detection rules)
->
Groq AI (alert enrichment → 3-step playbook)
->
Dashboard (live alerts + statistics)
---

## ⚙️ Tech Stack

- **Python 3** — detection engine and rules
- **Elasticsearch 8.11** — log storage and querying
- **Logstash 8.11** — log normalization
- **Filebeat / Winlogbeat** — log shipping
- **Groq API** — AI alert enrichment (llama-3.1-8b-instant)
- **FastAPI** — dashboard backend
- **Docker** — Elasticsearch and Logstash containers

---

## 🚀 How to Run

### 1. Start Elasticsearch and Logstash
```bash
docker-compose up -d
```

### 2. Create a `.env` file in the project root
ELASTIC_PASSWORD=your_password_here
GROQ_API_KEY=your_groq_key_here
### 3. Install dependencies
```bash
pip install elasticsearch groq python-dotenv colorama pyyaml fastapi uvicorn
```

### 4. Run the detection engine
```bash
python3 engine.py
```

### 5. Run the dashboard (separate terminal)
```bash
uvicorn dashboard:app --reload --port 8000
```

Then open **http://localhost:8000** in your browser.

---

## 📁 Project Structure

```
EagleEye-SIEM/
├── engine.py
├── config.yaml
├── whitelist.txt
├── docker-compose.yml
├── detectors/
│   ├── linux/
│   │   ├── linux_auth.py
│   │   ├── linux_brute_force.py
│   │   ├── linux_new_user.py
│   │   ├── linux_priv_group.py
│   │   └── linux_utils.py
│   └── windows/
│       ├── brute_force.py
│       ├── log_cleared.py
│       ├── new_service.py
│       └── powershell.py
├── ai_engine/
│   └── groq_enrichment.py
├── Dashboard/
│   ├── dashboard.py
│   └── templates/
│       └── dashboard.html
└── logstash/
    └── logstash.conf
```

## 🔒 Security Notes

- `.env` is excluded from this repository — never commit API keys
- Elasticsearch has authentication enabled (`xpack.security.enabled=true`)
- Whitelist trusted IPs in `whitelist.txt` to reduce false positives

---

## 👨‍💻 Author

Built as a Bachelor's graduation project.
