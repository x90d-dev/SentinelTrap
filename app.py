import asyncio
import csv
import datetime
import io
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from attack_simulator import (
     run_continuous_simulation,
    send_simulated_http_attack,
    send_simulated_ssh_attack,
)
from honeypot_engine import HoneypotDatabase, HoneypotEngine

logger = logging.getLogger("sentineltrap.app")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel.db"))
SSH_PORT = int(os.environ.get("SENTINEL_SSH_PORT", "2222"))
HTTP_PORT = int(os.environ.get("SENTINEL_HTTP_PORT", "8080"))
AUTO_SIMULATE = os.environ.get("SENTINEL_AUTO_SIMULATE", "1") == "1"

SERVER_START_TIME = time.time()


class TelemetryConnectionManager:
    """Manages active WebSocket clients for sub-second telemetry streaming."""

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        if not self.active_connections:
            return
        payload_text = json.dumps(message)
        stale: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload_text)
            except Exception:
                stale.append(connection)
        for s in stale:
            self.disconnect(s)


db = HoneypotDatabase(db_path=DB_PATH)
ws_manager = TelemetryConnectionManager()


async def on_honeypot_event(event: Dict[str, Any]) -> None:
    """Callback invoked whenever the honeypot engine captures an intrusion event."""
    metrics = db.get_metrics()
    await ws_manager.broadcast(
        {
            "type": "telemetry_event",
            "event": event,
            "metrics": metrics,
            "uptime_seconds": int(time.time() - SERVER_START_TIME),
        }
    )


engine = HoneypotEngine(
    db=db,
    ssh_port=SSH_PORT,
    http_port=HTTP_PORT,
    on_event_callback=on_honeypot_event,
)


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Start the SSH/HTTP honeypot listeners and optional embedded simulator if DB is empty."""
    await engine.start()
    sim_task: Optional[asyncio.Task] = None

    # If the database has no events and embedded auto-seed is enabled, ensure immediate readiness
    existing_metrics = db.get_metrics()
    if AUTO_SIMULATE and existing_metrics["total_events"] == 0:
        async def _seed_initial_if_idle() -> None:
            await asyncio.sleep(1.5)
            # Check if external attack_simulator.py already populated events
            if db.get_metrics()["total_events"] == 0:
                logger.info("No external traffic detected yet; seeding initial baseline telemetry...")
                for idx in range(10):
                    if idx % 2 == 0:
                        await send_simulated_http_attack("127.0.0.1", HTTP_PORT)
                    else:
                        await send_simulated_ssh_attack("127.0.0.1", SSH_PORT)
                    await asyncio.sleep(0.08)

        sim_task = asyncio.create_task(_seed_initial_if_idle())

    yield

    if sim_task and not sim_task.done():
        sim_task.cancel()
    await engine.stop()


app = FastAPI(
    title="SentinelTrap: Threat Intelligence Honeypot & Global Attack Surface Observer",
    version="2.4.0-enterprise",
    description="Asynchronous Low-Interaction Honeypot, Real-Time GeoIP Telemetry & STIX 2.1 IoC Platform",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request) -> HTMLResponse:
    """Render the single-page enterprise security command interface."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/v1/telemetry")
async def get_telemetry(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
) -> JSONResponse:
    """Fetch recent forensic events, aggregate metrics, and system status."""
    events = db.get_recent_events(limit=limit, severity=severity, protocol=protocol, search=search)
    metrics = db.get_metrics()
    return JSONResponse(
        {
            "status": "live" if engine.running else "idle",
            "uptime_seconds": int(time.time() - SERVER_START_TIME),
            "listeners": {
                "ssh_port": SSH_PORT,
                "http_port": HTTP_PORT,
            },
            "metrics": metrics,
            "events": events,
        }
    )


@app.post("/api/v1/simulate-burst")
async def trigger_simulation_burst(count: int = Query(5, ge=1, le=25)) -> JSONResponse:
    """Manually trigger an immediate burst of simulated multi-vector attacks."""
    sent = 0
    for i in range(count):
        ok = (
            await send_simulated_http_attack("127.0.0.1", HTTP_PORT)
            if i % 2 == 0
            else await send_simulated_ssh_attack("127.0.0.1", SSH_PORT)
        )
        if ok:
            sent += 1
        await asyncio.sleep(0.04)
    return JSONResponse({"status": "ok", "dispatched": sent, "metrics": db.get_metrics()})


@app.delete("/api/v1/database")
async def clear_database() -> JSONResponse:
    """Purge all stored telemetry events from SQLite and notify connected WebSocket clients."""
    deleted_count = db.clear_all()
    metrics = db.get_metrics()
    await ws_manager.broadcast(
        {
            "type": "database_cleared",
            "deleted_rows": deleted_count,
            "metrics": metrics,
            "uptime_seconds": int(time.time() - SERVER_START_TIME),
        }
    )
    return JSONResponse(
        {
            "status": "cleared",
            "deleted_rows": deleted_count,
            "metrics": metrics,
        }
    )


@app.get("/api/v1/export/json")
async def export_json(limit: int = Query(1000, ge=1, le=10000)) -> Response:
    """Export captured threat intelligence events as a structured JSON bundle."""
    events = db.get_recent_events(limit=limit)
    metrics = db.get_metrics()
    export_payload = {
        "schema_version": "2.4.0",
        "platform": "SentinelTrap Enterprise Threat Intelligence Honeypot",
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "summary_metrics": metrics,
        "total_exported_events": len(events),
        "ioc_records": events,
    }
    content = json.dumps(export_payload, indent=2)
    filename = f"sentineltrap_ioc_export_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/v1/export/csv")
async def export_stix_csv(limit: int = Query(1000, ge=1, le=10000)) -> Response:
    """
    Export captured indicators of compromise (IoCs) in a STIX 2.1 compliant
    tabular CSV representation suitable for SIEM/TIP ingestion.
    """
    events = db.get_recent_events(limit=limit)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "stix_id",
            "stix_type",
            "spec_version",
            "created",
            "valid_from",
            "indicator_types",
            "pattern_type",
            "pattern",
            "confidence",
            "severity",
            "source_ip",
            "reverse_ptr",
            "country",
            "iso_code",
            "city",
            "latitude",
            "longitude",
            "asn",
            "targeted_protocol",
            "dst_port",
            "attack_method",
            "credentials",
            "payload",
            "shannon_entropy",
            "user_agent",
        ]
    )

    confidence_map = {"Critical": 95, "Medium": 75, "Low": 50}

    for ev in events:
        namespace_uuid = uuid.uuid5(
            uuid.NAMESPACE_DNS,
            f"sentineltrap.{ev['id']}.{ev['source_ip']}.{ev['timestamp']}",
        )
        stix_id = f"indicator--{namespace_uuid}"
        pattern = (
            f"[ipv4-addr:value = '{ev['source_ip']}' AND "
            f"network-traffic:dst_port = {ev['dst_port']}]"
        )
        writer.writerow(
            [
                stix_id,
                "indicator",
                "2.1",
                ev["timestamp"],
                ev["timestamp"],
                "malicious-activity,compromised",
                "stix",
                pattern,
                confidence_map.get(ev["severity"], 60),
                ev["severity"],
                ev["source_ip"],
                ev["reverse_ptr"],
                ev["country"],
                ev["iso_code"],
                ev["city"],
                ev["latitude"],
                ev["longitude"],
                ev["asn"],
                ev["targeted_protocol"],
                ev["dst_port"],
                ev["attack_method"],
                ev["credentials"],
                ev["payload"],
                ev["entropy"],
                ev["user_agent"],
            ]
        )

    csv_bytes = output.getvalue().encode("utf-8")
    filename = f"sentineltrap_stix21_iocs_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_bytes,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket) -> None:
    """Real-time WebSocket stream pushing live honeypot ingest events and heartbeat metrics."""
    await ws_manager.connect(websocket)
    try:
        # Send immediate initial snapshot on connection
        await websocket.send_text(
            json.dumps(
                {
                    "type": "initial_snapshot",
                    "status": "live" if engine.running else "idle",
                    "uptime_seconds": int(time.time() - SERVER_START_TIME),
                    "metrics": db.get_metrics(),
                    "events": db.get_recent_events(limit=100),
                }
            )
        )
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "heartbeat",
                            "status": "live" if engine.running else "idle",
                            "uptime_seconds": int(time.time() - SERVER_START_TIME),
                        }
                    )
                )
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.environ.get("SENTINEL_HOST", "127.0.0.1"),
        port=int(os.environ.get("SENTINEL_WEB_PORT", "8000")),
        reload=False,
        log_level="info",
    )
