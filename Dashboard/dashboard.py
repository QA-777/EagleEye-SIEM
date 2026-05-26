# EagleEye SIEM — Dashboard
# Run: uvicorn dashboard.dashboard:app --reload --port 8000

import os
import logging
import yaml

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from elasticsearch import Elasticsearch, NotFoundError
from dotenv import load_dotenv
from pydantic import BaseModel

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Paths & Config ───────────────────────────────────────────────────────────
load_dotenv()

ROOT_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(ROOT_DIR, "config.yaml")) as f:
    config = yaml.safe_load(f)

es_config = config.get("elasticsearch", {})
ai_config = config.get("ai", {})  # reserved for future AI features

ALERTS_INDEX     = es_config.get("alerts_index",    "siem_alerts")
WINLOGBEAT_INDEX = es_config.get("winlogbeat_index", "winlogbeat-*")
FILEBEAT_INDEX   = es_config.get("filebeat_index",   "filebeat-*")

# ─── Elasticsearch Client ─────────────────────────────────────────────────────
es_host     = es_config.get("host", "http://127.0.0.1:9200")
es_user     = es_config.get("user", "elastic")
es_password = os.getenv("ELASTIC_PASSWORD")

# بدلاً من الاتصال بكلمة مرور None بصمت، نوقف التطبيق فوراً
if not es_password:
    raise RuntimeError(
        "ELASTIC_PASSWORD environment variable is not set. "
        "Add it to your .env file."
    )

es = Elasticsearch(
    es_host,
    basic_auth=(es_user, es_password),
    request_timeout=30,
)

# ─── FastAPI & Templates ──────────────────────────────────────────────────────
app       = FastAPI(title="EagleEye SIEM")
templates = Jinja2Templates(directory=os.path.join(DASHBOARD_DIR, "templates"))

# ─── Validation sets ──────────────────────────────────────────────────────────
VALID_SEVERITIES = {"all", "HIGH", "MEDIUM", "LOW", "CRITICAL"}
VALID_STATUSES   = {"all", "Open", "Closed"}

# ─── Helper: build ES query ───────────────────────────────────────────────────
def build_query(
    filters: list,
    sort:    list | None = None,
    size:    int         = 100,
) -> dict:
    """بناء استعلام Elasticsearch من قائمة فلاتر."""
    if sort is None:
        # القيمة الافتراضية داخل الدالة — تجنّب مشكلة mutable default argument
        sort = [{"@timestamp": {"order": "desc"}}]

    query = {"bool": {"must": filters}} if filters else {"match_all": {}}
    return {"query": query, "sort": sort, "size": size}


# ─── Helper: format a raw ES hit ─────────────────────────────────────────────
def format_alert(hit: dict) -> dict:
    """تحويل سجل Elasticsearch الخام إلى قاموس نظيف."""
    source = hit["_source"]
    return {
        "id":              hit["_id"],
        "timestamp":       source.get("@timestamp",    ""),
        "message":         source.get("message",       ""),
        "severity":        source.get("severity",      "LOW"),
        "status":          source.get("status",        "Open"),
        "analyst_note":    source.get("analyst_note",  ""),
        "source_event_id": source.get("source_event_id", ""),
        "ai_error":        source.get("ai_error"),
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/alerts")
async def get_alerts(
    severity: str = Query(default="all", description="Filter by severity"),
    status:   str = Query(default="all", description="Filter by status"),
    search:   str = Query(default="",    max_length=200),
    size:     int = Query(default=100,   ge=1, le=1000),
):
    # تحقق من صحة المدخلات قبل إرسالها لـ Elasticsearch
    if severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Choose from: {VALID_SEVERITIES}")
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose from: {VALID_STATUSES}")

    filters = []

    if severity != "all":
        filters.append({"match": {"severity": severity.upper()}})

    if status != "all":
        filters.append({"match": {"status": status}})

    if search:
        filters.append({
            "query_string": {
                "query":  f"*{search}*",
                "fields": ["message"],
            }
        })

    try:
        response = es.search(index=ALERTS_INDEX, body=build_query(filters, size=size))
        alerts   = [format_alert(hit) for hit in response["hits"]["hits"]]
        return {
            "total":  response["hits"]["total"]["value"],
            "alerts": alerts,
        }
    except Exception as e:
        logger.error(f"Failed to fetch alerts: {e}")
        raise HTTPException(status_code=503, detail="Could not reach Elasticsearch")


# ─── Alert update models ──────────────────────────────────────────────────────
class UpdateValue(BaseModel):
    value: str


@app.post("/api/alerts/{alert_id}/status")
async def set_alert_status(alert_id: str, body: UpdateValue):
    if body.value not in {"Open", "Closed"}:
        raise HTTPException(status_code=400, detail="Status must be 'Open' or 'Closed'")
    try:
        es.update(index=ALERTS_INDEX, id=alert_id, body={"doc": {"status": body.value}})
        return {"ok": True}
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        logger.error(f"Failed to update status for alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update alert status")


@app.post("/api/alerts/{alert_id}/note")
async def set_analyst_note(alert_id: str, body: UpdateValue):
    try:
        es.update(index=ALERTS_INDEX, id=alert_id, body={"doc": {"analyst_note": body.value}})
        return {"ok": True}
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        logger.error(f"Failed to save note for alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to save note")


@app.get("/api/rawlog/{event_id:path}")
async def get_raw_log(event_id: str):
    """البحث عن سجل خام بمعرّفه في فهارس Windows وLinux."""
    for index in [WINLOGBEAT_INDEX, FILEBEAT_INDEX]:
        try:
            response = es.search(
                index=index,
                body={"query": {"ids": {"values": [event_id]}}, "size": 1},
            )
            hits = response["hits"]["hits"]
            if hits:
                hit = hits[0]
                return {"raw": hit["_source"], "index": hit["_index"]}
        except Exception as e:
            # سجّل الخطأ لكن استمر للفهرس التالي
            logger.warning(f"Error searching index {index} for event {event_id}: {e}")

    return {"raw": None}


@app.get("/api/stats")
async def get_stats():
    """جمع إحصائيات عامة وخط زمني لآخر 24 ساعة."""

    def count(query=None) -> int:
        body = {"query": query} if query else None
        return es.count(index=ALERTS_INDEX, body=body)["count"]

    try:
        total    = count()
        open_c   = count({"match": {"status":   "Open"}})
        high_c   = count({"match": {"severity": "HIGH"}})
        medium_c = count({"match": {"severity": "MEDIUM"}})
        low_c    = count({"match": {"severity": "LOW"}})

        timeline_resp = es.search(
            index=ALERTS_INDEX,
            body={
                "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "size":  0,
                "aggs": {
                    "by_hour": {
                        "date_histogram": {
                            "field":             "@timestamp",
                            "calendar_interval": "hour",
                            "min_doc_count":     0,
                            "extended_bounds":   {"min": "now-24h", "max": "now"},
                        }
                    }
                },
            },
        )

        buckets  = timeline_resp["aggregations"]["by_hour"]["buckets"]
        timeline = [
            {"t": bucket["key_as_string"][:16], "c": bucket["doc_count"]}
            for bucket in buckets
        ]

        return {
            "total":    total,
            "open":     open_c,
            "closed":   total - open_c,
            "high":     high_c,
            "medium":   medium_c,
            "low":      low_c,
            "timeline": timeline,
        }

    except Exception as e:
        logger.error(f"Failed to load stats: {e}")
        raise HTTPException(status_code=503, detail="Could not load statistics")


@app.get("/api/logs")
async def get_logs(
    source: str = Query(default="both"),
    size:   int = Query(default=100, ge=1, le=1000),
):
    if source not in {"both", "windows", "linux"}:
        raise HTTPException(status_code=400, detail="source must be 'both', 'windows', or 'linux'")

    # اختيار الفهارس بناءً على المصدر المطلوب
    indexes = []
    if source != "linux":
        indexes.append(WINLOGBEAT_INDEX)
    if source != "windows":
        indexes.append(FILEBEAT_INDEX)

    all_logs = []

    for index in indexes:
        try:
            response = es.search(index=index, body=build_query(filters=[], size=size))
            for hit in response["hits"]["hits"]:
                source_data = hit["_source"]
                is_windows  = "winlogbeat" in hit["_index"]
                all_logs.append({
                    "id":          hit["_id"],
                    "index":       hit["_index"],
                    "timestamp":   source_data.get("@timestamp", ""),
                    "message":     source_data.get("message",    "")[:300],
                    "source_type": "Windows" if is_windows else "Linux",
                    "raw":         source_data,
                })
        except Exception as e:
            logger.warning(f"Failed to fetch logs from {index}: {e}")

    # ترتيب النتائج المدمجة زمنياً
    all_logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"logs": all_logs[:size]}
