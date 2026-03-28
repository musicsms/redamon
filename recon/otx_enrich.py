"""
OTX (AlienVault Open Threat Exchange) Pipeline Enrichment Module

Passive OSINT via OTX indicators API: IPv4 general + passive DNS per address,
and domain general in domain mode. Optional API key rotation via OTX_KEY_ROTATOR.
"""
from __future__ import annotations

import time
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators"


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


def _otx_effective_key(settings: dict, key_rotator) -> str:
    api_key = settings.get("OTX_API_KEY", "") or ""
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return key_rotator.current_key or api_key
    return api_key


def _otx_get(
    path: str,
    api_key: str,
    key_rotator=None,
    empty_on_404: bool = False,
) -> tuple[dict | None, bool]:
    """GET OTX indicators path.

    Returns (body_or_none, rate_limited). rate_limited True means stop further calls.
    empty_on_404: if True, 404 yields ({}, False) for partial enrichment.
    """
    url = f"{OTX_API_BASE}{path}"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if key_rotator:
            key_rotator.tick()
        if resp.status_code == 429:
            logger.warning("OTX rate limit (429)")
            print("[!][OTX] Rate limit hit — stopping OTX requests for this run")
            return None, True
        if resp.status_code == 200:
            return resp.json(), False
        if empty_on_404 and resp.status_code == 404:
            logger.debug(f"OTX 404 (no data) for {path}")
            return {}, False
        logger.warning(f"OTX {resp.status_code} for {path}: {resp.text[:200]}")
        return None, False
    except requests.RequestException as e:
        logger.warning(f"OTX request failed for {path}: {e}")
        return None, False


def _otx_pulse_count(body: dict | None) -> int:
    if not body:
        return 0
    pulse = body.get("pulse_info") or {}
    if isinstance(pulse, dict):
        return int(pulse.get("count") or 0)
    return 0


def _otx_geo_from_general(body: dict | None) -> dict:
    if not body:
        return {}
    g = body.get("geo")
    if isinstance(g, dict):
        asn = g.get("asn")
        return {
            "country_name": str(g.get("country_name") or ""),
            "city": str(g.get("city") or ""),
            "asn": str(asn) if asn is not None else "",
        }
    asn = body.get("asn")
    return {
        "country_name": str(body.get("country_name") or ""),
        "city": str(body.get("city") or ""),
        "asn": str(asn) if asn is not None else "",
    }


def _otx_passive_hostnames(body: dict | None) -> list[str]:
    if not body:
        return []
    seen: set[str] = set()
    out: list[str] = []
    records = body.get("passive_dns") or body.get("records") or []
    if not isinstance(records, list):
        return out
    for rec in records:
        if not isinstance(rec, dict):
            continue
        hn = rec.get("hostname") or rec.get("host") or rec.get("domain")
        if hn and hn not in seen:
            seen.add(hn)
            out.append(str(hn))
    return out


def run_otx_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run OTX indicator enrichment for IPs and (domain mode) the root domain.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'otx' key added
    """
    if not settings.get("OTX_ENABLED", False):
        return combined_result

    key_rotator = settings.get("OTX_KEY_ROTATOR")
    api_key = _otx_effective_key(settings, key_rotator)
    if not api_key:
        logger.warning("OTX API key missing — skipping enrichment")
        print("[!][OTX] OTX_API_KEY not configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "") or ""
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)

    print(f"\n[PHASE] OTX (AlienVault) OSINT Enrichment")
    print("-" * 40)
    print(f"[+][OTX] Extracted {len(ips)} unique IPs")

    otx_data: dict[str, Any] = {
        "ip_reports": [],
        "domain_report": {"domain": "", "pulse_count": 0, "whois": {}},
    }

    try:
        stop_rl = False
        for ip in ips:
            if stop_rl:
                break
            gen, rl = _otx_get(f"/IPv4/{ip}/general", api_key, key_rotator=key_rotator)
            if rl:
                stop_rl = True
                break
            if gen is None:
                continue
            time.sleep(0.5)
            pd, rl2 = _otx_get(
                f"/IPv4/{ip}/passive_dns",
                api_key,
                key_rotator=key_rotator,
                empty_on_404=True,
            )
            if rl2:
                stop_rl = True
            hostnames = _otx_passive_hostnames(pd)
            otx_data["ip_reports"].append({
                "ip": ip,
                "pulse_count": _otx_pulse_count(gen),
                "reputation": gen.get("reputation"),
                "geo": _otx_geo_from_general(gen),
                "passive_dns_hostnames": hostnames,
            })
            logger.info(f"  OTX IPv4: {ip} — pulses {_otx_pulse_count(gen)}, pdns {len(hostnames)}")
            time.sleep(0.5)
            if rl2:
                break

        if stop_rl and otx_data["ip_reports"]:
            print("[!][OTX] Stopped early due to rate limit — partial ip_reports")

        if domain and not is_ip_mode and not stop_rl:
            dg, rl3 = _otx_get(f"/domain/{domain}/general", api_key, key_rotator=key_rotator)
            if rl3:
                print("[!][OTX] Domain general skipped (rate limit)")
            elif dg is None:
                print("[!][OTX] Domain general skipped (HTTP error)")
            else:
                whois = dg.get("whois")
                if not isinstance(whois, dict):
                    whois = {}
                otx_data["domain_report"] = {
                    "domain": domain,
                    "pulse_count": _otx_pulse_count(dg),
                    "whois": whois,
                }
                logger.info(f"  OTX domain: {domain} — pulses {otx_data['domain_report']['pulse_count']}")
            time.sleep(0.5)

        print(f"[+][OTX] Enrichment complete: {len(otx_data['ip_reports'])} IP report(s)")

    except Exception as e:
        logger.error(f"OTX enrichment failed: {e}")
        print(f"[!][OTX] Enrichment error: {e}")
        print(f"[!][OTX] Pipeline continues with partial or empty OTX data")

    combined_result["otx"] = otx_data
    return combined_result


def run_otx_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run OTX enrichment and return only the 'otx' data dict.

    Thread-safe: does not mutate combined_result.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'otx' data dictionary
    """
    import copy
    snapshot = copy.copy(combined_result)
    run_otx_enrichment(snapshot, settings)
    return snapshot.get("otx", {})
