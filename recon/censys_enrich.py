"""
Censys Pipeline Enrichment Module

Passive OSINT enrichment using the Censys Search API v2 (hosts).
Queries host records for discovered IPv4 addresses: services, geo location,
autonomous system, and operating system metadata.

Requires CENSYS_API_ID and CENSYS_API_SECRET (HTTP Basic Auth). No key rotation
(pair credentials).
"""
from __future__ import annotations

import time
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

CENSYS_API_BASE = "https://search.censys.io/api/v2"


def _extract_ips_from_recon(combined_result: dict) -> list[str]:
    """Extract unique IPv4 addresses from domain discovery results."""
    ips: set[str] = set()
    dns_data = combined_result.get("dns", {})

    domain_dns = dns_data.get("domain", {})
    for ip in domain_dns.get("ips", {}).get("ipv4", []):
        if ip:
            ips.add(ip)

    for _sub, info in dns_data.get("subdomains", {}).items():
        for ip in info.get("ips", {}).get("ipv4", []):
            if ip:
                ips.add(ip)

    if combined_result.get("metadata", {}).get("ip_mode"):
        for ip in combined_result["metadata"].get("expanded_ips", []):
            if ip:
                ips.add(ip)

    return sorted(ips)


def _censys_os_to_str(os_val) -> str:
    if os_val is None:
        return ""
    if isinstance(os_val, dict):
        return (
            os_val.get("uniform_resource_identifier")
            or os_val.get("product")
            or os_val.get("name")
            or str(os_val)
        )
    return str(os_val)


def _censys_normalize_software(svc: dict) -> list:
    software = svc.get("software", [])
    if not isinstance(software, list):
        return [software] if software is not None else []
    out = []
    for s in software:
        if isinstance(s, dict):
            out.append(s.get("product") or s.get("name") or str(s))
        else:
            out.append(str(s))
    return out


def _censys_get_host(ip: str, api_id: str, api_secret: str) -> tuple[dict | None, bool]:
    """GET /v2/hosts/{ip} with Basic auth.

    Returns (result_or_none, rate_limited). If rate_limited, caller should stop.
    """
    url = f"{CENSYS_API_BASE}/hosts/{ip}"
    try:
        resp = requests.get(
            url,
            auth=(api_id, api_secret),
            timeout=30,
        )
        if resp.status_code == 200:
            body = resp.json()
            result = body.get("result")
            if isinstance(result, dict):
                return result, False
            logger.debug(f"Censys: unexpected body for {ip}")
            return None, False
        if resp.status_code == 404:
            logger.debug(f"Censys 404 — no host data for {ip}")
            return None, False
        if resp.status_code == 429:
            logger.warning("Censys rate limit (429) — stopping host fetches for this run")
            print("[!][Censys] Rate limit hit — skipping remaining hosts")
            return None, True
        logger.warning(f"Censys {resp.status_code} for {ip}: {resp.text[:200]}")
        return None, False
    except requests.RequestException as e:
        logger.warning(f"Censys request failed for {ip}: {e}")
        return None, False


def _build_censys_host_entry(ip: str, result: dict) -> dict:
    services_out = []
    for svc in result.get("services") or []:
        if not isinstance(svc, dict):
            continue
        services_out.append({
            "port": svc.get("port"),
            "transport_protocol": svc.get("transport_protocol") or svc.get("transport") or "",
            "service_name": svc.get("service_name") or svc.get("name") or "",
            "software": _censys_normalize_software(svc),
        })

    loc = result.get("location") or {}
    if not isinstance(loc, dict):
        loc = {}
    location = {
        "country": loc.get("country") or loc.get("country_code") or "",
        "city": loc.get("city") or "",
    }

    asn = result.get("autonomous_system") or {}
    if not isinstance(asn, dict):
        asn = {}
    autonomous_system = {
        "asn": asn.get("asn"),
        "name": asn.get("name") or "",
    }

    last_updated = (
        result.get("last_updated_at")
        or result.get("last_updated")
        or ""
    )

    return {
        "ip": ip,
        "services": services_out,
        "location": location,
        "autonomous_system": autonomous_system,
        "os": _censys_os_to_str(result.get("operating_system")),
        "last_updated": str(last_updated) if last_updated is not None else "",
    }


def run_censys_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Censys host enrichment on discovered IPv4 addresses.

    Runs after domain discovery / IP recon, before port scanning.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'censys' key added
    """
    if not settings.get("CENSYS_ENABLED", False):
        return combined_result

    api_id = settings.get("CENSYS_API_ID", "") or ""
    api_secret = settings.get("CENSYS_API_SECRET", "") or ""
    if not api_id or not api_secret:
        logger.warning("Censys API ID or secret missing — skipping enrichment")
        print("[!][Censys] CENSYS_API_ID / CENSYS_API_SECRET not configured — skipping")
        return combined_result

    print(f"\n[PHASE] Censys OSINT Enrichment")
    print("-" * 40)

    ips = _extract_ips_from_recon(combined_result)
    print(f"[+][Censys] Extracted {len(ips)} unique IPs for enrichment")

    censys_data: dict[str, Any] = {"hosts": []}

    try:
        if not ips:
            print("[*][Censys] No IPs to query — empty hosts list")
        else:
            print(f"[*][Censys] Querying host view for {len(ips)} IPs...")
            for ip in ips:
                result, rate_limited = _censys_get_host(ip, api_id, api_secret)
                if rate_limited:
                    break
                if result is None:
                    continue
                entry = _build_censys_host_entry(ip, result)
                censys_data["hosts"].append(entry)
                logger.info(f"  Censys host: {ip} — {len(entry['services'])} services")
                time.sleep(0.5)
            print(f"[+][Censys] Enrichment complete: {len(censys_data['hosts'])} hosts")

    except Exception as e:
        logger.error(f"Censys enrichment failed: {e}")
        print(f"[!][Censys] Enrichment error: {e}")
        print(f"[!][Censys] Pipeline continues with partial or empty Censys data")

    combined_result["censys"] = censys_data
    return combined_result


def run_censys_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run Censys enrichment and return only the 'censys' data dict.

    Thread-safe: does not mutate combined_result. Reads DNS/IP data from
    it but writes nothing back.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'censys' data dictionary (just the enrichment payload)
    """
    import copy
    snapshot = copy.copy(combined_result)
    run_censys_enrichment(snapshot, settings)
    return snapshot.get("censys", {})
