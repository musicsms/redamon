"""
Criminal IP Pipeline Enrichment Module

IP intelligence and domain risk reports via Criminal IP API v1.
"""
from __future__ import annotations

import time
import logging

import requests

logger = logging.getLogger(__name__)

CRIMINALIP_API_BASE = "https://api.criminalip.io/v1/"


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


def _effective_key(api_key: str, key_rotator) -> str:
    if key_rotator and getattr(key_rotator, "has_keys", False):
        return (key_rotator.current_key or "").strip()
    return (api_key or "").strip()


def _cip_get(
    path: str,
    api_key: str,
    key_rotator,
    params: dict | None = None,
    timeout: int = 30,
) -> dict | None:
    """GET Criminal IP v1 with 429 retry once."""
    eff = _effective_key(api_key, key_rotator)
    if not eff:
        return None
    url = f"{CRIMINALIP_API_BASE.rstrip('/')}/{path.lstrip('/')}"
    headers = {"x-api-key": eff}
    merged = dict(params or {})

    for attempt in range(2):
        try:
            resp = requests.get(url, headers=headers, params=merged, timeout=timeout)
            if key_rotator:
                key_rotator.tick()
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    logger.warning(f"CriminalIP invalid JSON for {path}")
                    return None
            if resp.status_code == 404:
                logger.debug(f"CriminalIP 404 for {path}")
                return None
            if resp.status_code == 429:
                logger.warning("CriminalIP rate limit (429), sleeping and retrying once")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None
            logger.warning(
                f"CriminalIP {resp.status_code} for {path}: {resp.text[:200]}"
            )
            return None
        except requests.RequestException as e:
            logger.warning(f"CriminalIP request failed for {path}: {e}")
            return None
    return None


def _parse_ip_report(ip: str, body: dict | None) -> dict | None:
    if not body:
        return None
    data = body.get("data")
    if data is None:
        data = body

    score_raw = (data.get("score") if isinstance(data, dict) else None) or {}
    if not isinstance(score_raw, dict):
        score_raw = {}
    score = {
        "inbound": str(score_raw.get("inbound", "") or score_raw.get("inbound_score", "") or ""),
        "outbound": str(score_raw.get("outbound", "") or score_raw.get("outbound_score", "") or ""),
    }

    issues_raw = (data.get("issues") if isinstance(data, dict) else None) or {}
    if not isinstance(issues_raw, dict):
        issues_raw = {}
    issues = {
        "is_vpn": issues_raw.get("is_vpn"),
        "is_proxy": issues_raw.get("is_proxy"),
        "is_tor": issues_raw.get("is_tor"),
        "is_hosting": issues_raw.get("is_hosting"),
        "is_cloud": issues_raw.get("is_cloud"),
    }

    whois_raw = (data.get("whois") if isinstance(data, dict) else None) or {}
    if not isinstance(whois_raw, dict):
        whois_raw = {}
    whois = {
        "org_name": whois_raw.get("org_name") or whois_raw.get("organization"),
        "country": whois_raw.get("country") or whois_raw.get("country_code"),
    }

    ports = []
    if isinstance(data, dict):
        pl = data.get("port") or data.get("ports") or data.get("open_port_list")
        if isinstance(pl, list):
            ports = pl
        elif pl is not None:
            ports = [pl]

    return {
        "ip": ip,
        "score": score,
        "issues": issues,
        "whois": whois,
        "ports": ports,
    }


def _parse_domain_report(domain: str, body: dict | None) -> dict | None:
    if not body:
        return None
    data = body.get("data")
    if data is None:
        data = body
    if not isinstance(data, dict):
        return None

    risk = {
        "score": data.get("score") or data.get("risk_score"),
        "grade": data.get("grade") or data.get("risk_grade"),
        "abuse_record_count": data.get("abuse_record_count") or data.get("abuse_count"),
        "current_service": data.get("current_service"),
        "report": data.get("report") or data.get("risk_report"),
    }
    out = {
        "domain": domain,
        "risk": {k: v for k, v in risk.items() if v is not None},
    }
    if not out["risk"]:
        out["risk"] = dict(data)
    return out


def run_criminalip_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run Criminal IP enrichment: domain report (domain mode) and per-IP data.

    Mutates combined_result in place with key ``criminalip``.
    """
    if not settings.get("CRIMINALIP_ENABLED", False):
        return combined_result

    api_key = settings.get("CRIMINALIP_API_KEY", "")
    key_rotator = settings.get("CRIMINALIP_KEY_ROTATOR")

    if not _effective_key(api_key, key_rotator):
        print(f"[!][CriminalIP] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)

    print(f"\n[PHASE] Criminal IP OSINT Enrichment")
    print("-" * 40)
    print(f"[+][CriminalIP] Extracted {len(ips)} unique IPs for enrichment")

    cip_data: dict = {
        "ip_reports": [],
        "domain_report": None,
    }

    try:
        need_sleep = False
        if domain and not is_ip_mode:
            print(f"[*][CriminalIP] Fetching domain report for {domain}...")
            raw = _cip_get(
                "domain/report",
                api_key,
                key_rotator,
                params={"query": domain},
            )
            cip_data["domain_report"] = _parse_domain_report(domain, raw)
            if cip_data["domain_report"]:
                print(f"[+][CriminalIP] Domain report retrieved for {domain}")
            else:
                print(f"[!][CriminalIP] No domain report data for {domain}")
            need_sleep = True

        for ip in ips:
            if need_sleep:
                time.sleep(1)
            need_sleep = True
            print(f"[*][CriminalIP] Fetching IP data for {ip}...")
            raw = _cip_get("ip/data", api_key, key_rotator, params={"ip": ip})
            report = _parse_ip_report(ip, raw)
            if report:
                cip_data["ip_reports"].append(report)
                print(f"[+][CriminalIP] IP data retrieved for {ip}")
            else:
                logger.warning(f"CriminalIP: no data for {ip}")

        print(
            f"[+][CriminalIP] Enrichment complete: "
            f"{len(cip_data['ip_reports'])} IP report(s), "
            f"domain={'yes' if cip_data['domain_report'] else 'no'}"
        )
    except Exception as e:
        logger.error(f"CriminalIP enrichment failed: {e}")
        print(f"[!][CriminalIP] Enrichment error: {e}")
        print(f"[!][CriminalIP] Pipeline continues without full Criminal IP data")

    combined_result["criminalip"] = cip_data
    return combined_result


def run_criminalip_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Shallow copy of combined_result, run enrichment, return only the ``criminalip`` dict."""
    import copy

    snapshot = copy.copy(combined_result)
    run_criminalip_enrichment(snapshot, settings)
    return snapshot.get("criminalip", {})
