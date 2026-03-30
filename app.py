"""
SOC Bulk IP Reputation Checker — Flask Application
====================================================
Provides endpoints for:
  /          → Dashboard UI
  /check     → Parallel AbuseIPDB lookups (POST, JSON)
  /export    → CSV download of results   (POST, JSON)
"""

import csv
import io
import ipaddress
import json
import logging
import socket
import time

import aiohttp
import asyncio
import dns.resolver
import pandas as pd
import pycountry
import requests
import whois
from flask import Flask, Response, jsonify, render_template, request

import base64
import config


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("SOC-radar")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


# ---------------------------------------------------------------------------
# Helper — classify confidence level from abuseConfidenceScore
# ---------------------------------------------------------------------------
def classify_confidence(score: int) -> str:
    """Return a human-readable confidence level string."""
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


# ---------------------------------------------------------------------------
# Trusted infrastructure keywords for BAU classification
# ---------------------------------------------------------------------------
TRUSTED_KEYWORDS = [
    "google",
    "microsoft",
    "amazon",
    "aws",
    "cloudflare",
    "paloalto",
    "palo alto",
    "yahoo",
    "vodafone",
    "airtel",
    "jio",
]


def classify_bau(domain: str, isp: str) -> str:
    """
    Return 'Don't Report' if the domain or ISP matches trusted
    infrastructure, otherwise return 'Investigate'.
    """
    combined = f"{domain} {isp}".lower()
    if any(kw in combined for kw in TRUSTED_KEYWORDS):
        return "Don't Report"
    return "Investigate"


# ---------------------------------------------------------------------------
# SOC incident sheet cache (Google Sheets CSV)
# ---------------------------------------------------------------------------
SHEET_REFRESH_SECONDS = 300
_sheet_ips: set[str] = set()
_sheet_last_refresh: float = 0.0


# ---------------------------------------------------------------------------
# AbuseIPDB API key rotation
# ---------------------------------------------------------------------------
ABUSE_API_KEYS: list[str] = [
    k for k in getattr(config, "ABUSEIPDB_API_KEYS", []) if k
] or ([config.ABUSEIPDB_API_KEY] if getattr(config, "ABUSEIPDB_API_KEY", "") else [])
_abuse_key_index: int = 0


def _get_abuse_api_key() -> str:
    """
    Return the current AbuseIPDB API key.
    Uses a safe index with wrap‑around so we never exceed the key list.
    """
    global _abuse_key_index

    if not ABUSE_API_KEYS:
        raise RuntimeError("No AbuseIPDB API keys configured.")

    if _abuse_key_index >= len(ABUSE_API_KEYS):
        _abuse_key_index = 0

    logger.info("[AbuseIPDB] Using API key index %s", _abuse_key_index)
    return ABUSE_API_KEYS[_abuse_key_index]


def _rotate_abuse_key() -> None:
    """
    Advance to the next AbuseIPDB key (round‑robin).
    """
    global _abuse_key_index
    if not ABUSE_API_KEYS:
        return
    _abuse_key_index = (_abuse_key_index + 1) % len(ABUSE_API_KEYS)
    logger.warning("[AbuseIPDB] Rotated to API key index %s", _abuse_key_index)


def _refresh_soc_sheet_cache(force: bool = False) -> None:
    """
    Download / refresh the SOC Google Sheet CSV that contains previously
    reported IPs. Uses a simple in-memory cache refreshed at most once
    every SHEET_REFRESH_SECONDS.
    """
    global _sheet_ips, _sheet_last_refresh

    url = getattr(config, "SOC_SHEET_CSV_URL", "") or ""
    if not url:
        return

    now = time.time()
    if not force and now - _sheet_last_refresh < SHEET_REFRESH_SECONDS:
        return

    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            logger.warning("[SOC-SHEET] Failed to download sheet, HTTP %s", resp.status_code)
            return

        text = resp.text
        ips: set[str] = set()

        # Detect GViz JSON format
        if "google.visualization.Query.setResponse" in text:
            # Strip JS wrapper to get raw JSON
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                logger.warning("[SOC-SHEET] Could not locate JSON object in GViz response")
                return
            payload_str = text[start : end + 1]
            try:
                payload = json.loads(payload_str)
            except json.JSONDecodeError as exc:
                logger.warning("[SOC-SHEET] Failed to decode GViz JSON: %s", exc)
                return

            table = payload.get("table") or {}
            cols = table.get("cols") or []
            rows = table.get("rows") or []

            target_label = "public source ip address"
            ip_index: int | None = None
            for idx, col in enumerate(cols):
                label = (col.get("label") or "").strip().lower()
                if label == target_label:
                    ip_index = idx
                    break

            if ip_index is None:
                logger.warning(
                    "[SOC-SHEET] 'Public Source IP address' column not found in GViz cols: %s",
                    [c.get("label") for c in cols],
                )
                return

            for row in rows:
                cells = row.get("c") or []
                if ip_index >= len(cells):
                    continue
                cell = cells[ip_index]
                if not cell:
                    continue
                value = cell.get("v")
                if value is None:
                    continue
                raw_ip = str(value).strip()
                if raw_ip:
                    ips.add(raw_ip)

            _sheet_ips = ips
            _sheet_last_refresh = now
            logger.info("[SOC-SHEET] Loaded %s IPs from GViz sheet", len(_sheet_ips))
            return

        # Fallback: treat as plain CSV using pandas for fast parsing
        try:
            df = pd.read_csv(io.StringIO(text))
        except Exception as exc:
            logger.warning("[SOC-SHEET] pandas failed to parse CSV: %s", exc)
            return

        if df.empty:
            logger.warning("[SOC-SHEET] CSV sheet is empty")
            return

        # Normalise headers: strip whitespace and lowercase
        norm_map = {str(col).strip().lower(): col for col in df.columns}
        target = "public source ip address"
        if target not in norm_map:
            logger.warning(
                "[SOC-SHEET] 'Public Source IP address' column not found in CSV headers: %s",
                list(df.columns),
            )
            return

        col_name = norm_map[target]
        series = (
            df[col_name]
            .dropna()
            .astype(str)
            .str.strip()
        )
        ips = {val for val in series if val}

        _sheet_ips = ips
        _sheet_last_refresh = now
        logger.info(
            "[SOC-SHEET] Loaded %s IPs from CSV sheet using column '%s'",
            len(_sheet_ips),
            col_name,
        )
    except Exception as exc:
        # On any error, keep existing cache so we don't break lookups.
        logger.warning("[SOC-SHEET] Error while refreshing cache: %s", exc)
        return


# Prime the SOC sheet cache once at startup (best-effort).
_refresh_soc_sheet_cache(force=True)


def get_ip_status(ip: str) -> str:
    """
    Return 'Repeated IP' if the IP appears in the cached SOC sheet,
    otherwise 'New IP'. If the cache is empty or the sheet is disabled,
    all IPs are treated as 'New IP'.
    """
    ip = (ip or "").strip()
    if not ip:
        return "New IP"
    if ip in _sheet_ips:
        return "Repeated IP"
    return "New IP"


# ---------------------------------------------------------------------------
# Helper — resolve 2-letter country code to full name + alpha-3
# ---------------------------------------------------------------------------
def resolve_country(alpha2: str) -> tuple[str, str]:
    """
    Convert a 2-letter ISO country code to (full_name, alpha_3).
    Returns ("Unknown", "N/A") if the code is missing or invalid.
    """
    if not alpha2 or alpha2 == "N/A":
        return "Unknown", "N/A"
    try:
        country = pycountry.countries.get(alpha_2=alpha2.upper())
        if country:
            return country.name, country.alpha_3
        return "Unknown", "N/A"
    except (LookupError, AttributeError):
        return "Unknown", "N/A"


# ---------------------------------------------------------------------------
# Helper — validate a single IP string
# ---------------------------------------------------------------------------
def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Helper — query AbuseIPDB for a single IP
# ---------------------------------------------------------------------------
def check_abuseipdb_ip(ip: str) -> dict:
    """
    Call the AbuseIPDB /check endpoint for *ip* and return a normalised
    result dict.  Network / API errors are caught and returned as an
    error entry so that processing of other IPs is not interrupted.
    """
    # Try each key at most once to handle rate limits gracefully.
    attempts = max(1, len(ABUSE_API_KEYS) or 1)
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.MAX_AGE_DAYS,
    }

    for _ in range(attempts):
        api_key = _get_abuse_api_key()
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        try:
            resp = requests.get(
                config.ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
                timeout=15,
            )

            # Handle HTTP-level errors (rate-limits, auth failures, etc.)
            if resp.status_code == 429:
                _rotate_abuse_key()
                continue
            if resp.status_code == 401:
                return {"ip": ip, "error": "Invalid API key. Check your configuration."}
            if resp.status_code != 200:
                return {"ip": ip, "error": f"API returned HTTP {resp.status_code}."}

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            alpha2 = data.get("countryCode", "N/A")
            country_name, country_alpha3 = resolve_country(alpha2)

            return {
                "ip": ip,
                "abuseConfidenceScore": score,
                "countryCode": alpha2,
                "countryName": country_name,
                "countryAlpha3": country_alpha3,
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "totalReports": data.get("totalReports", 0),
                "confidenceLevel": classify_confidence(score),
                "bauStatus": classify_bau(
                    data.get("domain", ""),
                    data.get("isp", ""),
                ),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
            }

        except requests.exceptions.Timeout:
            return {"ip": ip, "error": "Request timed out."}
        except requests.exceptions.ConnectionError:
            return {"ip": ip, "error": "Connection error — check your network."}
        except Exception as exc:  # noqa: BLE001
            return {"ip": ip, "error": str(exc)}

    return {"ip": ip, "error": "AbuseIPDB rate limit exceeded for all configured keys."}


# ---------------------------------------------------------------------------
# Helper — query VirusTotal for a single IP
# ---------------------------------------------------------------------------
def check_virustotal_ip(ip: str) -> dict:
    """
    Call the VirusTotal IP endpoint for *ip* and return a normalised
    result dict.
    """
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY,
    }
    url = config.VIRUSTOTAL_IP_URL.format(ip=ip)

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 429:
            return {"ip": ip, "error": "VirusTotal rate limit exceeded."}
        if resp.status_code == 401:
            return {"ip": ip, "error": "VirusTotal API key invalid."}
        if resp.status_code == 403:
            return {"ip": ip, "error": "VirusTotal access forbidden (check plan/permissions)."}
        if resp.status_code == 404:
            return {"ip": ip, "error": "VirusTotal has no data for this IP."}
        if resp.status_code != 200:
            return {"ip": ip, "error": f"VirusTotal HTTP {resp.status_code}."}

        payload = resp.json() or {}
        data = payload.get("data", {}) or {}
        attributes = data.get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}

        return {
            "ip": ip,
            "country": attributes.get("country", "N/A"),
            "network": attributes.get("network", "N/A"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "VirusTotal request timed out."}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "VirusTotal connection error."}
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)}


# ---------------------------------------------------------------------------
# Helper — query AlienVault OTX for a single IP
# ---------------------------------------------------------------------------
def check_otx_ip(ip: str) -> dict:
    """
    Call the AlienVault OTX IP general endpoint for *ip* and return a
    normalised result dict.
    """
    headers = {
        "X-OTX-API-KEY": config.OTX_API_KEY,
    }
    url = config.OTX_IP_URL.format(ip=ip)

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 429:
            return {"ip": ip, "error": "OTX rate limit exceeded."}
        if resp.status_code == 401:
            return {"ip": ip, "error": "OTX API key invalid."}
        if resp.status_code == 404:
            return {"ip": ip, "error": "OTX has no data for this IP."}
        if resp.status_code != 200:
            return {"ip": ip, "error": f"OTX HTTP {resp.status_code}."}

        data = resp.json() or {}
        # OTX returns country & ASN information in slightly different
        # shapes depending on context. Fall back gracefully.
        country = (
            data.get("country_name")
            or data.get("country_code")
            or "N/A"
        )
        asn = data.get("asn") or data.get("asn_desc") or "N/A"
        pulse_info = data.get("pulse_info") or {}
        pulse_count = (
            pulse_info.get("count")
            or pulse_info.get("pulses_count")
            or 0
        )

        return {
            "ip": ip,
            "country": country or "N/A",
            "asn": asn or "N/A",
            "pulseCount": pulse_count,
        }

    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "OTX request timed out."}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "OTX connection error."}
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)}


# ---------------------------------------------------------------------------
# Async helpers for high-throughput IP lookups
# ---------------------------------------------------------------------------
_MAX_CONCURRENT_REQUESTS = 10


async def _fetch_abuseipdb_ip(session: aiohttp.ClientSession, sem: asyncio.Semaphore, ip: str) -> dict:
    attempts = max(1, len(ABUSE_API_KEYS) or 1)
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.MAX_AGE_DAYS,
    }

    async with sem:
        last_payload: dict | None = None
        for _ in range(attempts):
            api_key = _get_abuse_api_key()
            headers = {
                "Key": api_key,
                "Accept": "application/json",
            }
            try:
                async with session.get(
                    config.ABUSEIPDB_CHECK_URL,
                    headers=headers,
                    params=params,
                    timeout=15,
                ) as resp:
                    if resp.status == 429:
                        _rotate_abuse_key()
                        last_payload = None
                        continue
                    if resp.status == 401:
                        return {"ip": ip, "error": "Invalid API key. Check your configuration."}
                    if resp.status != 200:
                        return {"ip": ip, "error": f"API returned HTTP {resp.status}."}

                    last_payload = await resp.json()
                    break
            except asyncio.TimeoutError:
                return {"ip": ip, "error": "Request timed out."}
            except aiohttp.ClientError:
                return {"ip": ip, "error": "Connection error — check your network."}
            except Exception as exc:  # noqa: BLE001
                return {"ip": ip, "error": str(exc)}

    if not last_payload:
        return {"ip": ip, "error": "AbuseIPDB rate limit exceeded for all configured keys."}

    data = (last_payload or {}).get("data", {}) or {}
    score = data.get("abuseConfidenceScore", 0)
    alpha2 = data.get("countryCode", "N/A")
    country_name, country_alpha3 = resolve_country(alpha2)

    return {
        "ip": ip,
        "abuseConfidenceScore": score,
        "countryCode": alpha2,
        "countryName": country_name,
        "countryAlpha3": country_alpha3,
        "isp": data.get("isp", "N/A"),
        "domain": data.get("domain", "N/A"),
        "totalReports": data.get("totalReports", 0),
        "confidenceLevel": classify_confidence(score),
        "bauStatus": classify_bau(
            data.get("domain", ""),
            data.get("isp", ""),
        ),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
    }


async def _fetch_virustotal_ip(session: aiohttp.ClientSession, sem: asyncio.Semaphore, ip: str) -> dict:
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY,
    }
    url = config.VIRUSTOTAL_IP_URL.format(ip=ip)

    async with sem:
        try:
            async with session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 429:
                    return {"ip": ip, "error": "VirusTotal rate limit exceeded."}
                if resp.status == 401:
                    return {"ip": ip, "error": "VirusTotal API key invalid."}
                if resp.status == 403:
                    return {"ip": ip, "error": "VirusTotal access forbidden (check plan/permissions)."}
                if resp.status == 404:
                    return {"ip": ip, "error": "VirusTotal has no data for this IP."}
                if resp.status != 200:
                    return {"ip": ip, "error": f"VirusTotal HTTP {resp.status}."}

                payload = await resp.json()
        except asyncio.TimeoutError:
            return {"ip": ip, "error": "VirusTotal request timed out."}
        except aiohttp.ClientError:
            return {"ip": ip, "error": "VirusTotal connection error."}
        except Exception as exc:  # noqa: BLE001
            return {"ip": ip, "error": str(exc)}

    data = (payload or {}).get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)

    country = attrs.get("country", "N/A")
    asn_info = attrs.get("asn", "")
    network = attrs.get("network", "N/A") or asn_info

    return {
        "ip": ip,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "country": country or "N/A",
        "network": network or "N/A",
    }


async def _fetch_otx_ip(session: aiohttp.ClientSession, sem: asyncio.Semaphore, ip: str) -> dict:
    headers = {
        "X-OTX-API-KEY": config.OTX_API_KEY,
    }
    url = config.OTX_IP_URL.format(ip=ip)

    async with sem:
        try:
            async with session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 429:
                    return {"ip": ip, "error": "OTX rate limit exceeded."}
                if resp.status == 401:
                    return {"ip": ip, "error": "OTX API key invalid."}
                if resp.status == 404:
                    return {"ip": ip, "error": "OTX has no data for this IP."}
                if resp.status != 200:
                    return {"ip": ip, "error": f"OTX HTTP {resp.status}."}

                payload = await resp.json()
        except asyncio.TimeoutError:
            return {"ip": ip, "error": "OTX request timed out."}
        except aiohttp.ClientError:
            return {"ip": ip, "error": "OTX connection error."}
        except Exception as exc:  # noqa: BLE001
            return {"ip": ip, "error": str(exc)}

    data = payload or {}
    country = (
        data.get("country_name")
        or data.get("country_code")
        or "N/A"
    )
    asn = data.get("asn") or data.get("asn_desc") or "N/A"
    pulse_info = data.get("pulse_info") or {}
    pulse_count = (
        pulse_info.get("count")
        or pulse_info.get("pulses_count")
        or 0
    )

    return {
        "ip": ip,
        "country": country or "N/A",
        "asn": asn or "N/A",
        "pulseCount": pulse_count,
    }


async def _async_lookup_ips(unique_ips: list[str], source: str) -> dict[str, list[dict]]:
    """
    High-performance async lookup across AbuseIPDB, VirusTotal or OTX
    for all *unique_ips*, restricted to the selected *source*.
    """
    results: dict[str, list[dict]] = {
        "abuseipdb": [],
        "virustotal": [],
        "otx": [],
    }

    sem = asyncio.Semaphore(_MAX_CONCURRENT_REQUESTS)

    source = (source or "abuseipdb").lower()
    if source not in ("abuseipdb", "virustotal", "otx"):
        source = "abuseipdb"

    async with aiohttp.ClientSession() as session:
        async def per_ip(ip: str) -> dict:
            if source == "abuseipdb":
                abuse = await _fetch_abuseipdb_ip(session, sem, ip)
                return {"ip": ip, "abuseipdb": abuse}
            if source == "virustotal":
                vt = await _fetch_virustotal_ip(session, sem, ip)
                return {"ip": ip, "virustotal": vt}
            otx = await _fetch_otx_ip(session, sem, ip)
            return {"ip": ip, "otx": otx}

        tasks = [per_ip(ip) for ip in unique_ips]

        for coro in asyncio.as_completed(tasks):
            per_ip_res = await coro
            ip = per_ip_res.get("ip", "N/A")
            payload = per_ip_res.get(source) or {"ip": ip, "error": "Unknown error."}
            if isinstance(payload, dict) and "ipStatus" not in payload:
                payload["ipStatus"] = get_ip_status(payload.get("ip", ""))
            results[source].append(payload)

    return results


# ---------------------------------------------------------------------------
# Helper — detailed AbuseIPDB information for a single IP (verbose view)
# ---------------------------------------------------------------------------
def get_abuseipdb_details(ip: str) -> dict:
    """
    Call the AbuseIPDB /check endpoint with verbose output enabled and
    return a rich detail object suitable for the IP details modal.
    """
    attempts = max(1, len(ABUSE_API_KEYS) or 1)
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.MAX_AGE_DAYS,
        "verbose": "true",
    }

    for _ in range(attempts):
        api_key = _get_abuse_api_key()
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        try:
            resp = requests.get(
                config.ABUSEIPDB_CHECK_URL,
                headers=headers,
                params=params,
                timeout=15,
            )

            if resp.status_code == 429:
                _rotate_abuse_key()
                continue
            if resp.status_code == 401:
                return {"ip": ip, "error": "Invalid API key. Check your configuration."}
            if resp.status_code != 200:
                return {"ip": ip, "error": f"API returned HTTP {resp.status_code}."}

            payload = resp.json() or {}
            data = payload.get("data", {}) or {}

            score = data.get("abuseConfidenceScore", 0)
            alpha2 = data.get("countryCode", "N/A")
            country_name, country_alpha3 = resolve_country(alpha2)

            # Hostnames & comments may not always be present
            hostnames = data.get("hostnames") or []
            reports = data.get("reports") or []
            comments: list[str] = []
            for rep in reports[:10]:
                comment = (rep or {}).get("comment")
                if comment:
                    comments.append(str(comment))

            return {
                "ip": ip,
                "countryCode": alpha2,
                "countryName": country_name,
                "countryAlpha3": country_alpha3,
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "usageType": data.get("usageType", "N/A"),
                "totalReports": data.get("totalReports", 0),
                "abuseConfidenceScore": score,
                "confidenceLevel": classify_confidence(score),
                "bauStatus": classify_bau(
                    data.get("domain", ""),
                    data.get("isp", ""),
                ),
                "lastReportedAt": data.get("lastReportedAt", "Never"),
                "isWhitelisted": data.get("isWhitelisted", False),
                "hostnames": hostnames,
                "comments": comments,
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
            }

        except requests.exceptions.Timeout:
            return {"ip": ip, "error": "Request timed out."}
        except requests.exceptions.ConnectionError:
            return {"ip": ip, "error": "Connection error — check your network."}
        except Exception as exc:  # noqa: BLE001
            return {"ip": ip, "error": str(exc)}

    return {"ip": ip, "error": "AbuseIPDB rate limit exceeded for all configured keys."}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_ips():
    """
    Accept JSON ``{ "ips": "1.2.3.4\\n5.6.7.8" }``, validate each IP,
    look them up in parallel via AbuseIPDB, and return a JSON array of
    result objects.
    """
    start_time = time.time()
    body = request.get_json(silent=True) or {}
    raw = body.get("ips", "").strip()

    if not raw:
        return jsonify({"error": "No IP addresses provided."}), 400

    # Refresh SOC sheet cache (if configured) --------------------------------
    _refresh_soc_sheet_cache()

    source = (body.get("source") or "abuseipdb").lower()
    if source not in ("abuseipdb", "virustotal", "otx"):
        source = "abuseipdb"

    # Deduplicate & validate -------------------------------------------------
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    seen = set()
    unique_ips: list[str] = []
    invalid_ips: list[str] = []

    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        if is_valid_ip(line):
            unique_ips.append(line)
        else:
            invalid_ips.append(line)

    if not unique_ips and not invalid_ips:
        return jsonify({"error": "No IP addresses provided."}), 400

    # Parallel look-ups ------------------------------------------------------
    results: dict[str, list[dict]] = {
        "abuseipdb": [],
        "virustotal": [],
        "otx": [],
    }

    # Add invalid IPs as error entries only to the selected source
    for ip in invalid_ips:
        err = {
            "ip": ip,
            "error": f"'{ip}' is not a valid IP address.",
            "ipStatus": get_ip_status(ip),
        }
        results[source].append(err)

    # For valid IPs, look up only the selected source using the async engine.
    if unique_ips:
        async_results = asyncio.run(_async_lookup_ips(unique_ips, source))
        for key in results:
            results[key].extend(async_results.get(key, []))

    # Sort each source-specific result set
    def sort_abuse(r: dict) -> int:
        if "error" in r:
            return -1
        return int(r.get("abuseConfidenceScore", 0) or 0)

    def sort_vt(r: dict) -> int:
        if "error" in r:
            return -1
        return int(r.get("malicious", 0) or 0)

    def sort_otx(r: dict) -> int:
        if "error" in r:
            return -1
        return int(r.get("pulseCount", 0) or 0)

    if results["abuseipdb"]:
        results["abuseipdb"].sort(key=sort_abuse, reverse=True)
    if results["virustotal"]:
        results["virustotal"].sort(key=sort_vt, reverse=True)
    if results["otx"]:
        results["otx"].sort(key=sort_otx, reverse=True)

    elapsed = time.time() - start_time
    total_ips = len(unique_ips) + len(invalid_ips)
    logger.info(
        "[PERFORMANCE] /check processed %s IP(s) for source '%s' (%s valid, %s invalid) in %.2f seconds",
        total_ips,
        source,
        len(unique_ips),
        len(invalid_ips),
        elapsed,
    )

    return jsonify({"results": results})


@app.route("/export", methods=["POST"])
def export_csv():
    """
    Accept JSON
        { "results": [ ... ], "source": "abuseipdb" | "virustotal" | "otx" }
    and return a downloadable CSV file suitable for SOC reporting.
    """
    body = request.get_json(silent=True) or {}
    rows = body.get("results", [])
    source = (body.get("source") or "abuseipdb").lower()

    if not rows:
        return jsonify({"error": "No data to export."}), 400

    if source == "virustotal":
        fieldnames = [
            "IP Address",
            "Malicious",
            "Suspicious",
            "Harmless",
            "Country",
            "Network",
        ]
    elif source == "otx":
        fieldnames = [
            "IP Address",
            "Country",
            "ASN",
            "Pulse Count",
        ]
    else:
        # AbuseIPDB (default / backwards compatible)
        fieldnames = [
            "IP Address",
            "Abuse Confidence Score",
            "Country",
            "ISP",
            "Domain",
            "Total Reports",
            "Confidence Level",
            "BAU Status",
        ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        if "error" in row:
            base = {
                "IP Address": row.get("ip", ""),
            }
            if source == "virustotal":
                base.update({
                    "Malicious": "Error",
                    "Suspicious": "",
                    "Harmless": "",
                    "Country": "",
                    "Network": "",
                })
            elif source == "otx":
                base.update({
                    "Country": "",
                    "ASN": "",
                    "Pulse Count": "Error",
                })
            else:
                base.update({
                    "Abuse Confidence Score": "Error",
                    "Country": "",
                    "ISP": "",
                    "Domain": "",
                    "Total Reports": "",
                    "Confidence Level": "",
                    "BAU Status": "",
                })
            writer.writerow(base)
        else:
            if source == "virustotal":
                writer.writerow({
                    "IP Address": row.get("ip", ""),
                    "Malicious": row.get("malicious", 0),
                    "Suspicious": row.get("suspicious", 0),
                    "Harmless": row.get("harmless", 0),
                    "Country": row.get("country", "N/A"),
                    "Network": row.get("network", "N/A"),
                })
            elif source == "otx":
                writer.writerow({
                    "IP Address": row.get("ip", ""),
                    "Country": row.get("country", "N/A"),
                    "ASN": row.get("asn", "N/A"),
                    "Pulse Count": row.get("pulseCount", 0),
                })
            else:
                cname = row.get("countryName", "Unknown")
                calpha3 = row.get("countryAlpha3", "N/A")
                country_display = f"{cname} ({calpha3})" if cname != "Unknown" else "Unknown"
                writer.writerow({
                    "IP Address": row.get("ip", ""),
                    "Abuse Confidence Score": row.get("abuseConfidenceScore", ""),
                    "Country": country_display,
                    "ISP": row.get("isp", ""),
                    "Domain": row.get("domain", ""),
                    "Total Reports": row.get("totalReports", ""),
                    "Confidence Level": row.get("confidenceLevel", ""),
                    "BAU Status": row.get("bauStatus", ""),
                })

    csv_bytes = output.getvalue()
    output.close()

    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=ip_reputation_report.csv"},
    )


@app.route("/ip-details/<ip>")
def ip_details(ip: str):
    """
    Return detailed AbuseIPDB information for a single IP.
    """
    if not is_valid_ip(ip):
        return jsonify({"ip": ip, "error": "Invalid IP address."}), 400

    details = get_abuseipdb_details(ip)
    status = 200 if "error" not in details else 502
    return jsonify(details), status


@app.route("/domain-intel", methods=["POST"])
def domain_intel() -> Response:
    """
    Accept JSON { "domain": "example.com" } and return basic WHOIS + DNS
    information for the domain.
    """
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()

    if not domain:
        return jsonify({"error": "No domain provided."}), 400

    # Very lightweight sanity check; the underlying libraries will still
    # perform their own validation.
    if " " in domain or "." not in domain:
        return jsonify({"error": "Invalid domain format."}), 400

    result: dict[str, object] = {
        "domain": domain,
        "registrar": "N/A",
        "created": "N/A",
        "name_servers": [],
        "dns_records": [],
        "hosting_ip": "N/A",
    }

    # WHOIS lookup
    try:
        w = whois.whois(domain)
        if isinstance(w, dict):
            registrar = w.get("registrar") or w.get("Registrar")
            created = w.get("creation_date") or w.get("Creation Date")
        else:
            registrar = getattr(w, "registrar", None)
            created = getattr(w, "creation_date", None)

        result["registrar"] = registrar or "Unknown"

        # creation_date can be a list or single datetime
        if isinstance(created, list) and created:
            created = created[0]
        if hasattr(created, "strftime"):
            result["created"] = created.strftime("%Y-%m-%d")
        elif created:
            result["created"] = str(created)
    except Exception:
        # WHOIS failures are non-fatal; we just leave defaults.
        result["registrar"] = "Unavailable"
        result["created"] = "Unavailable"

    # DNS records
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    dns_records: dict[str, list[str]] = {}
    try:
        resolver = dns.resolver.Resolver()
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                values: list[str] = []
                for rdata in answers:
                    values.append(str(rdata).strip())
                if values:
                    dns_records[rtype] = values
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
    except Exception:
        dns_records = {}

    result["dns_records"] = dns_records

    # Hosting IP (resolve A record)
    try:
        ip = socket.gethostbyname(domain)
        result["hosting_ip"] = ip
    except Exception:
        result["hosting_ip"] = "Unavailable"

    # Aggregate record types for quick display
    record_summary = ", ".join(sorted(dns_records.keys())) if dns_records else "None"
    result["record_summary"] = record_summary

    return jsonify(result)


def _vt_get(url: str) -> dict:
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code == 429:
        return {"error": "VirusTotal rate limit exceeded."}
    if resp.status_code in (401, 403):
        return {"error": "VirusTotal API key invalid or access forbidden."}
    if resp.status_code == 404:
        return {"error": "VirusTotal has no data for this indicator."}
    if resp.status_code != 200:
        return {"error": f"VirusTotal HTTP {resp.status_code}."}
    return resp.json() or {}


@app.route("/url-intel", methods=["POST"])
def url_intel() -> Response:
    """
    Accept JSON { "url": "https://example.com" } and return a combined
    VirusTotal + OTX view with a simplified reputation verdict.
    """
    body = request.get_json(silent=True) or {}
    url_value = (body.get("url") or "").strip()
    if not url_value:
        return jsonify({"error": "Invalid URL or Hash provided."}), 400

    vt_result: dict[str, object] = {}
    otx_pulse_count: int | None = None

    # VirusTotal URL report (v3) uses a URL-safe base64 id without padding
    try:
        encoded_id = base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8").strip("=")
        vt_url = config.VIRUSTOTAL_URL_URL.format(id=encoded_id)
        payload = _vt_get(vt_url)
        if "error" in payload:
            vt_result["error"] = payload["error"]
        else:
            data = (payload.get("data") or {})
            attrs = (data.get("attributes") or {})
            stats = (attrs.get("last_analysis_stats") or {})
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)

            total = malicious + suspicious + harmless + undetected
            vt_result.update(
                {
                    "url": url_value,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "scan_date": attrs.get("last_analysis_date"),
                    "reputation": attrs.get("reputation", 0),
                    "total_engines": total,
                }
            )
    except Exception as exc:  # noqa: BLE001
        vt_result["error"] = str(exc)

    # AlienVault OTX URL pulses
    try:
        otx_url = config.OTX_URL_URL.format(url=requests.utils.quote(url_value, safe=""))
        headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
        resp = requests.get(otx_url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json() or {}
            pulse_info = data.get("pulse_info") or {}
            otx_pulse_count = pulse_info.get("count") or pulse_info.get("pulses_count")
    except Exception:
        otx_pulse_count = None

    # Derive a simple threat level
    threat_level = "Unknown"
    if isinstance(vt_result.get("malicious"), int):
        mal = vt_result["malicious"]
        sus = int(vt_result.get("suspicious", 0) or 0)
        if mal >= 5 or (mal >= 1 and sus >= 3):
            threat_level = "Critical"
        elif mal >= 1:
            threat_level = "High"
        elif sus >= 1:
            threat_level = "Medium"
        else:
            threat_level = "Low"

    return jsonify(
        {
            "url": url_value,
            "virustotal": vt_result,
            "otx_pulse_count": otx_pulse_count,
            "threat_level": threat_level,
        }
    )


@app.route("/hash-intel", methods=["POST"])
def hash_intel() -> Response:
    """
    Accept JSON { "hash": "..." } and return VirusTotal file report summary.
    """
    body = request.get_json(silent=True) or {}
    hash_value = (body.get("hash") or "").strip()
    if not hash_value or " " in hash_value:
        return jsonify({"error": "Invalid URL or Hash provided."}), 400

    vt_url = config.VIRUSTOTAL_FILE_URL.format(hash=hash_value)
    payload = _vt_get(vt_url)
    if "error" in payload:
        return jsonify({"error": payload["error"]}), 502

    data = (payload.get("data") or {})
    attrs = (data.get("attributes") or {})
    stats = (attrs.get("last_analysis_stats") or {})

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    total = malicious + suspicious + undetected + harmless

    detection_ratio = f"{malicious}/{total or 1}"
    malware_type = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label") or "Unknown"

    if malicious >= 10:
        threat_level = "Critical"
    elif malicious >= 3:
        threat_level = "High"
    elif malicious >= 1 or suspicious >= 1:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    return jsonify(
        {
            "hash": hash_value,
            "detection_ratio": detection_ratio,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "malware_type": malware_type,
            "threat_level": threat_level,
            "scan_date": attrs.get("last_analysis_date"),
        }
    )






# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if config.ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        logger.warning("No AbuseIPDB API key configured. Update config.py or environment variables.")
    app.run(host="0.0.0.0", port=5000, debug=True)
