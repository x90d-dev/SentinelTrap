import asyncio
import datetime
import json
import logging
import math
import os
import re
import socket
import sqlite3
from collections import Counter
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger("sentineltrap.engine")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

DB_PATH = os.environ.get("SENTINEL_DB_PATH", "sentinel.db")

# Offline deterministic GeoIP lookup table for known simulation ranges and private/public fallbacks
KNOWN_GEO_PROFILES: List[Dict[str, Any]] = [
    {"prefix": "185.220.", "country": "Germany", "iso": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS205100 F3 Netze e.V."},
    {"prefix": "45.155.", "country": "Russia", "iso": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS49505 Selectel"},
    {"prefix": "118.25.", "country": "China", "iso": "CN", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737, "asn": "AS45090 Tencent Cloud"},
    {"prefix": "103.253.", "country": "Vietnam", "iso": "VN", "city": "Hanoi", "lat": 21.0285, "lon": 105.8542, "asn": "AS131429 Viettel Group"},
    {"prefix": "179.43.", "country": "Switzerland", "iso": "CH", "city": "Zurich", "lat": 47.3769, "lon": 8.5417, "asn": "AS51395 Privatel Ltd"},
    {"prefix": "198.98.", "country": "United States", "iso": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060, "asn": "AS53667 FranTech Solutions"},
    {"prefix": "159.89.", "country": "Singapore", "iso": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS14061 DigitalOcean"},
    {"prefix": "177.54.", "country": "Brazil", "iso": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "asn": "AS262589 Maxihost"},
    {"prefix": "91.219.", "country": "Netherlands", "iso": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "asn": "AS43350 NForce Entertainment"},
    {"prefix": "211.234.", "country": "South Korea", "iso": "KR", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "asn": "AS9318 SK Broadband"},
    {"prefix": "103.145.", "country": "Indonesia", "iso": "ID", "city": "Jakarta", "lat": -6.2088, "lon": 106.8456, "asn": "AS138840 PT Cloud Hosting"},
    {"prefix": "196.52.", "country": "South Africa", "iso": "ZA", "city": "Johannesburg", "lat": -26.2041, "lon": 28.0473, "asn": "AS37100 SEACOM"},
    {"prefix": "138.197.", "country": "Canada", "iso": "CA", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "asn": "AS14061 DigitalOcean"},
    {"prefix": "163.44.", "country": "Japan", "iso": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "asn": "AS7506 GMO Internet"},
    {"prefix": "5.188.", "country": "Bulgaria", "iso": "BG", "city": "Sofia", "lat": 42.6977, "lon": 23.3219, "asn": "AS204957 Neterra"},
    {"prefix": "41.65.", "country": "Egypt", "iso": "EG", "city": "Cairo", "lat": 30.0444, "lon": 31.2357, "asn": "AS8452 TE Data"},
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (bits per character) of an input payload string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)


def resolve_geo_from_ip(ip_address: str) -> Dict[str, Any]:
    """Deterministically resolve country, ISO code, city, coordinates, and ASN for an IP."""
    for profile in KNOWN_GEO_PROFILES:
        if ip_address.startswith(profile["prefix"]):
            return profile.copy()

    if ip_address in ("127.0.0.1", "::1", "localhost"):
        return {
            "country": "Local Sensor Loopback",
            "iso": "LO",
            "city": "Localhost",
            "lat": 0.0,
            "lon": 0.0,
            "asn": "AS00000 Internal Telemetry Node",
        }

    octets = [int(x) for x in re.findall(r"\d+", ip_address)]
    idx = sum(octets) % len(KNOWN_GEO_PROFILES) if octets else 0
    return KNOWN_GEO_PROFILES[idx].copy()


async def async_reverse_ptr(ip_address: str, simulated_ptr: Optional[str] = None) -> str:
    """Resolve reverse DNS PTR record asynchronously with fast timeout fallback."""
    if simulated_ptr:
        return simulated_ptr

    if ip_address in ("127.0.0.1", "::1", "localhost"):
        return "sensor-loopback.sentinel.internal"

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip_address),
            timeout=0.45,
        )
        return result[0]
    except Exception:
        octets = ip_address.replace(".", "-")
        geo = resolve_geo_from_ip(ip_address)
        iso_lower = geo["iso"].lower()
        return f"host-{octets}.edge.{iso_lower}.unverified.net"


def classify_attack(protocol: str, payload: str, credentials: str = "") -> Tuple[str, str]:
    """
    Classify the attack vector and assign a severity level ('Low', 'Medium', 'Critical')
    based on payload signatures, protocol, and entropy.
    """
    combined = f"{payload} {credentials}".lower()

    critical_patterns = [
        (r"(union\s+select|select\s+.*\s+from\s+information_schema|sleep\(\d+\)|benchmark\()", "SQL Injection (SQLi)"),
        (r"(\.\./\.\./|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|%2e%2e%2f)", "Directory Traversal / LFI"),
        (r"(\$\{jndi:(ldap|rmi|dns)://|cmd\.exe|/bin/sh|/bin/bash|wget\s+http|curl\s+http|;cat\s+)", "Remote Code Execution (RCE)"),
        (r"(busybox|mirai|mozi\.m|tftp\s+-g|chmod\s+777|/dev/null)", "Botnet Dropper Execution"),
        (r"(' or '1'='1|' or 1=1--|admin'--)", "Authentication Bypass SQLi"),
    ]
    for pattern, method_name in critical_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            return method_name, "Critical"

    medium_patterns = [
        (r"(root:|admin:|oracle:|postgres:|ubuntu:|support:|pi:)", "SSH Dictionary Brute-Force"),
        (r"(/wp-login\.php|/xmlrpc\.php|/\.env|/\.git/config|/actuator/env|/phpmyadmin)", "Sensitive Endpoint Recon"),
        (r"(<script>|javascript:|onerror=|onload=)", "Cross-Site Scripting (XSS) Probe"),
        (r"(bearer\s+eyj|basic\s+[a-z0-9+/=]+)", "API Token / Credential Stuffing"),
    ]
    for pattern, method_name in medium_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            return method_name, "Medium"

    if "SSH" in protocol.upper():
        if credentials and credentials != "none":
            return "SSH Credential Brute-Force", "Medium"
        return "SSH Banner & Cipher Recon", "Low"

    entropy = calculate_shannon_entropy(payload)
    if entropy >= 4.65:
        return "High-Entropy Obfuscated Payload", "Critical"
    elif entropy >= 3.95:
        return "Automated HTTP Admin Fuzzing", "Medium"

    return "Automated Service Reconnaissance", "Low"


class HoneypotDatabase:
    """SQLite persistence layer for SentinelTrap telemetry and IoC extraction."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self._get_connection() as conn:
            try:
                conn.execute("PRAGMA journal_mode=MEMORY;")
            except sqlite3.OperationalError:
                pass
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    reverse_ptr TEXT NOT NULL,
                    country TEXT NOT NULL,
                    iso_code TEXT NOT NULL,
                    city TEXT NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    asn TEXT NOT NULL,
                    targeted_protocol TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    attack_method TEXT NOT NULL,
                    credentials TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    entropy REAL NOT NULL,
                    severity TEXT NOT NULL,
                    user_agent TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON telemetry_events(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON telemetry_events(source_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON telemetry_events(severity);")
            conn.commit()

    def insert_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO telemetry_events (
                    timestamp, source_ip, reverse_ptr, country, iso_code, city,
                    latitude, longitude, asn, targeted_protocol, dst_port,
                    attack_method, credentials, payload, entropy, severity, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["source_ip"],
                    event["reverse_ptr"],
                    event["country"],
                    event["iso_code"],
                    event["city"],
                    event["latitude"],
                    event["longitude"],
                    event["asn"],
                    event["targeted_protocol"],
                    event["dst_port"],
                    event["attack_method"],
                    event["credentials"],
                    event["payload"],
                    event["entropy"],
                    event["severity"],
                    event["user_agent"],
                ),
            )
            conn.commit()
            event_copy = dict(event)
            event_copy["id"] = cursor.lastrowid
            return event_copy

    def get_recent_events(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM telemetry_events WHERE 1=1"
        params: List[Any] = []

        if severity and severity.lower() != "all":
            query += " AND LOWER(severity) = ?"
            params.append(severity.lower())

        if protocol and protocol.lower() != "all":
            query += " AND LOWER(targeted_protocol) LIKE ?"
            params.append(f"%{protocol.lower()}%")

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += """ AND (
                LOWER(source_ip) LIKE ? OR
                LOWER(country) LIKE ? OR
                LOWER(attack_method) LIKE ? OR
                LOWER(credentials) LIKE ? OR
                LOWER(payload) LIKE ? OR
                LOWER(reverse_ptr) LIKE ?
            )"""
            params.extend([term, term, term, term, term, term])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM telemetry_events").fetchone()[0]
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM telemetry_events WHERE severity = 'Critical'"
            ).fetchone()[0]
            avg_entropy_row = conn.execute("SELECT AVG(entropy) FROM telemetry_events").fetchone()[0]
            avg_entropy = round(float(avg_entropy_row), 2) if avg_entropy_row is not None else 0.0

            protocol_rows = conn.execute(
                "SELECT targeted_protocol, COUNT(*) as cnt FROM telemetry_events GROUP BY targeted_protocol"
            ).fetchall()
            top_countries = conn.execute(
                """
                SELECT country, iso_code, COUNT(*) as cnt
                FROM telemetry_events
                GROUP BY country, iso_code
                ORDER BY cnt DESC
                LIMIT 6
                """
            ).fetchall()

            return {
                "total_events": total,
                "unique_ips": unique_ips,
                "critical_breaches": critical_count,
                "avg_entropy": avg_entropy,
                "protocols": {r["targeted_protocol"]: r["cnt"] for r in protocol_rows},
                "top_countries": [dict(r) for r in top_countries],
            }

    def clear_all(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM telemetry_events")
            conn.commit()
            return cursor.rowcount


class HoneypotEngine:
    """
    Manages the asynchronous Low-Interaction Honeypot Listeners:
    1. Fake SSH Service (Port 2222) - Emulates OpenSSH banner exchange & credential capture.
    2. Fake REST Admin/API Service (Port 8080) - Inspects headers, X-Forwarded-For, Basic Auth,
       query strings, and JSON/form payloads for SQLi, LFI, RCE, and brute-force attempts.
    """

    def __init__(
        self,
        db: HoneypotDatabase,
        ssh_port: int = 2222,
        http_port: int = 8080,
        on_event_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        self.db = db
        self.ssh_port = ssh_port
        self.http_port = http_port
        self.on_event_callback = on_event_callback
        self.ssh_server: Optional[asyncio.AbstractServer] = None
        self.http_server: Optional[asyncio.AbstractServer] = None
        self.running = False

    async def start(self) -> None:
        """Start both asynchronous TCP honeypot listeners."""
        self.ssh_server = await asyncio.start_server(
            self._handle_ssh_client, host="0.0.0.0", port=self.ssh_port
        )
        self.http_server = await asyncio.start_server(
            self._handle_http_client, host="0.0.0.0", port=self.http_port
        )
        self.running = True
        logger.info(
            "SentinelTrap listeners active: SSH Honeypot on 0.0.0.0:%d | HTTP Admin Honeypot on 0.0.0.0:%d",
            self.ssh_port,
            self.http_port,
        )

    async def stop(self) -> None:
        """Gracefully close honeypot listeners."""
        self.running = False
        for srv in (self.ssh_server, self.http_server):
            if srv is not None:
                srv.close()
                await srv.wait_closed()
        logger.info("SentinelTrap honeypot listeners stopped.")

    async def record_and_broadcast(
        self,
        source_ip: str,
        targeted_protocol: str,
        dst_port: int,
        credentials: str,
        payload: str,
        user_agent: str = "OpenSSH_Client",
        simulated_geo: Optional[Dict[str, Any]] = None,
        simulated_ptr: Optional[str] = None,
        override_method: Optional[str] = None,
        override_severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Normalize, enrich, store, and broadcast a captured honeypot event."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        geo = simulated_geo if simulated_geo else resolve_geo_from_ip(source_ip)
        reverse_ptr = await async_reverse_ptr(source_ip, simulated_ptr=simulated_ptr)
        entropy = calculate_shannon_entropy(f"{credentials} {payload}".strip())
        method, severity = classify_attack(targeted_protocol, payload, credentials)

        if override_method:
            method = override_method
        if override_severity:
            severity = override_severity

        event_record = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "reverse_ptr": reverse_ptr,
            "country": geo["country"],
            "iso_code": geo["iso"],
            "city": geo["city"],
            "latitude": float(geo["lat"]),
            "longitude": float(geo["lon"]),
            "asn": geo["asn"],
            "targeted_protocol": targeted_protocol,
            "dst_port": dst_port,
            "attack_method": method,
            "credentials": credentials[:180] if credentials else "N/A",
            "payload": payload[:400] if payload else "N/A",
            "entropy": entropy,
            "severity": severity,
            "user_agent": user_agent[:160],
        }

        saved = self.db.insert_event(event_record)
        if self.on_event_callback is not None:
            try:
                await self.on_event_callback(saved)
            except Exception as exc:
                logger.debug("Event broadcast callback warning: %s", exc)
        return saved

    async def _handle_ssh_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Low-interaction SSH honeypot (port 2222).
        Presents an enterprise OpenSSH banner and accepts raw client version + auth/command frames
        or JSON-structured simulation frames from `attack_simulator.py`.
        """
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "127.0.0.1"

        try:
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
            await writer.drain()

            raw_data = await asyncio.wait_for(reader.read(2048), timeout=3.5)
            text_data = raw_data.decode("utf-8", errors="replace").strip()

            source_ip = peer_ip
            credentials = "root:********"
            payload = text_data if text_data else "SSH-2.0-Client-Probe"
            user_agent = "SSH-2.0-libssh2_1.10.0"
            sim_geo = None
            sim_ptr = None
            override_method = None
            override_severity = None

            if text_data.startswith("SIM_SSH|"):
                try:
                    meta_json = text_data.split("SIM_SSH|", 1)[1]
                    sim = json.loads(meta_json)
                    source_ip = sim.get("source_ip", peer_ip)
                    credentials = sim.get("credentials", credentials)
                    payload = sim.get("payload", payload)
                    user_agent = sim.get("user_agent", user_agent)
                    sim_geo = sim.get("geo")
                    sim_ptr = sim.get("reverse_ptr")
                    override_method = sim.get("attack_method")
                    override_severity = sim.get("severity")
                except Exception:
                    pass
            elif "AUTH" in text_data:
                parts = text_data.split()
                if len(parts) >= 3:
                    credentials = f"{parts[1]}:{parts[2]}"

            await self.record_and_broadcast(
                source_ip=source_ip,
                targeted_protocol="SSH/2222",
                dst_port=self.ssh_port,
                credentials=credentials,
                payload=payload,
                user_agent=user_agent,
                simulated_geo=sim_geo,
                simulated_ptr=sim_ptr,
                override_method=override_method,
                override_severity=override_severity,
            )

            writer.write(b"Permission denied (publickey,password).\r\n")
            await writer.drain()
        except asyncio.TimeoutError:
            await self.record_and_broadcast(
                source_ip=peer_ip,
                targeted_protocol="SSH/2222",
                dst_port=self.ssh_port,
                credentials="N/A (Handshake Timeout)",
                payload="TCP SYN / Banner Grab Timeout",
                user_agent="TCP-Scanner",
            )
        except Exception as exc:
            logger.debug("SSH honeypot socket error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_http_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Low-interaction HTTP REST Admin/API honeypot (port 8080).
        Parses HTTP request line, headers (including X-Forwarded-For & X-Sentinel-Sim),
        credentials, and body payload, then returns a realistic 401/403 JSON response.
        """
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "127.0.0.1"

        try:
            raw_bytes = await asyncio.wait_for(reader.read(4096), timeout=3.5)
            if not raw_bytes:
                return

            raw_req = raw_bytes.decode("utf-8", errors="replace")
            head_part, _, body_part = raw_req.partition("\r\n\r\n")
            lines = head_part.split("\r\n")
            request_line = lines[0] if lines else "GET / HTTP/1.1"

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            source_ip = headers.get("x-forwarded-for", peer_ip).split(",")[0].strip()
            user_agent = headers.get("user-agent", "Mozilla/5.0 (compatible; Scanner/1.0)")
            auth_header = headers.get("authorization", "")
            credentials = auth_header if auth_header else headers.get("x-api-key", "N/A")

            sim_geo = None
            sim_ptr = headers.get("x-sentinel-ptr")
            override_method = headers.get("x-sentinel-method")
            override_severity = headers.get("x-sentinel-severity")

            if "x-sentinel-geo" in headers:
                try:
                    sim_geo = json.loads(headers["x-sentinel-geo"])
                except Exception:
                    sim_geo = None

            if "x-sentinel-creds" in headers:
                credentials = headers["x-sentinel-creds"]

            full_payload = request_line
            if body_part.strip():
                full_payload = f"{request_line} | Body: {body_part.strip()}"

            await self.record_and_broadcast(
                source_ip=source_ip,
                targeted_protocol="HTTP-API/8080",
                dst_port=self.http_port,
                credentials=credentials,
                payload=full_payload,
                user_agent=user_agent,
                simulated_geo=sim_geo,
                simulated_ptr=sim_ptr,
                override_method=override_method,
                override_severity=override_severity,
            )

            resp_body = json.dumps(
                {
                    "status": 401,
                    "error": "Unauthorized",
                    "message": "Invalid administrative token or insufficient privileges. Incident logged.",
                    "trace_id": os.urandom(6).hex(),
                }
            ).encode("utf-8")

            http_response = (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Server: nginx/1.24.0 (Ubuntu)\r\n"
                b"Content-Type: application/json\r\n"
                b"WWW-Authenticate: Bearer realm=\"Enterprise-Core-Admin\"\r\n"
                b"Content-Length: " + str(len(resp_body)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n\r\n" + resp_body
            )
            writer.write(http_response)
            await writer.drain()
        except Exception as exc:
            logger.debug("HTTP honeypot socket error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
