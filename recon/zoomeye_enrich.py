"""
ZoomEye Pipeline Enrichment Module

Host search enrichment via ZoomEye API (hostname or IP queries).
"""
from __future__ import annotations

import time
import logging

import requests

logger = logging.getLogger(__name__)

ZOOMEYE_API_BASE = "https://api.zoomeye.ai/"


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


def _geoinfo_country(geoinfo) -> str:
    if not geoinfo or not isinstance(geoinfo, dict):
        return ""
    c = geoinfo.get("country")
    if isinstance(c, str):
        return c
    if isinstance(c, dict):
        names = c.get("names")
        if isinstance(names, dict):
            return str(names.get("en") or names.get("zh") or next(iter(names.values()), ""))
        return str(c.get("code") or c.get("name") or "")
    return str(c or "")


def _zoomeye_search(
    query: str,
    api_key: str,
    key_rotator,
    max_results: int,
    timeout: int = 30,
) -> tuple[list[dict], int]:
    """
    Paginate host/search until max_results rows or no more pages.
    Returns (flattened result rows, total from API if given).
    """
    eff = _effective_key(api_key, key_rotator)
    if not eff:
        return [], 0

    url = f"{ZOOMEYE_API_BASE.rstrip('/')}/host/search"
    headers = {"API-KEY": eff}
    out: list[dict] = []
    total = 0
    page = 1

    while len(out) < max_results:
        params = {"query": query, "page": page}
        last_body = None
        for attempt in range(2):
            try:
                resp = requests.get(
                    url, headers=headers, params=params, timeout=timeout
                )
                if key_rotator:
                    key_rotator.tick()
                if resp.status_code == 200:
                    last_body = resp.json()
                    break
                if resp.status_code == 429:
                    logger.warning("ZoomEye rate limit (429), sleeping and retrying once")
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    return out, total
                logger.warning(
                    f"ZoomEye {resp.status_code} page={page}: {resp.text[:200]}"
                )
                return out, total
            except requests.RequestException as e:
                logger.warning(f"ZoomEye request failed page={page}: {e}")
                return out, total

        if not last_body:
            break

        matches = last_body.get("matches") or []
        if not matches:
            break

        try:
            total = int(last_body.get("total") or last_body.get("available") or total)
        except (TypeError, ValueError):
            pass

        for m in matches:
            if len(out) >= max_results:
                break
            portinfo = m.get("portinfo") or {}
            port = portinfo.get("port")
            if port is not None:
                try:
                    port = int(port)
                except (TypeError, ValueError):
                    port = 0
            out.append(
                {
                    "ip": str(m.get("ip") or ""),
                    "port": port,
                    "app": str(portinfo.get("app") or ""),
                    "banner": str(portinfo.get("banner") or ""),
                    "os": str(portinfo.get("os") or ""),
                    "country": _geoinfo_country(m.get("geoinfo")),
                }
            )

        if len(matches) < 1:
            break
        page += 1
        time.sleep(1)

    return out, total


def run_zoomeye_enrichment(combined_result: dict, settings: dict) -> dict:
    """
    Run ZoomEye host search (domain: hostname query; IP mode: per-IP ip: queries).

    Mutates combined_result in place with key ``zoomeye``.
    """
    if not settings.get("ZOOMEYE_ENABLED", False):
        return combined_result

    api_key = settings.get("ZOOMEYE_API_KEY", "")
    key_rotator = settings.get("ZOOMEYE_KEY_ROTATOR")
    max_results = int(settings.get("ZOOMEYE_MAX_RESULTS", 1000) or 1000)
    max_results = max(1, max_results)

    if not _effective_key(api_key, key_rotator):
        print(f"[!][ZoomEye] No API key configured — skipping")
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    ips = _extract_ips_from_recon(combined_result)

    print(f"\n[PHASE] ZoomEye OSINT Enrichment")
    print("-" * 40)

    ze_data: dict = {"results": [], "total": 0}

    try:
        if is_ip_mode:
            print(f"[+][ZoomEye] IP mode: {len(ips)} target(s)")
            grand_total = 0
            first = True
            for ip in ips:
                if not first:
                    time.sleep(1)
                first = False
                print(f"[*][ZoomEye] Searching ip:{ip}...")
                rows, t = _zoomeye_search(
                    f"ip:{ip}",
                    api_key,
                    key_rotator,
                    max_results,
                )
                ze_data["results"].extend(rows)
                grand_total = max(grand_total, t, len(rows))
                print(f"[+][ZoomEye] ip:{ip} — {len(rows)} row(s)")
            ze_data["total"] = grand_total or len(ze_data["results"])
        else:
            if not domain:
                print(f"[!][ZoomEye] No domain in combined_result — skipping")
                combined_result["zoomeye"] = ze_data
                return combined_result
            print(f"[*][ZoomEye] Searching hostname:{domain}...")
            rows, t = _zoomeye_search(
                f"hostname:{domain}",
                api_key,
                key_rotator,
                max_results,
            )
            ze_data["results"] = rows
            ze_data["total"] = t or len(rows)
            print(f"[+][ZoomEye] hostname:{domain} — {len(rows)} row(s), total≈{ze_data['total']}")

        print(f"[+][ZoomEye] Enrichment complete: {len(ze_data['results'])} results")
    except Exception as e:
        logger.error(f"ZoomEye enrichment failed: {e}")
        print(f"[!][ZoomEye] Enrichment error: {e}")
        print(f"[!][ZoomEye] Pipeline continues without full ZoomEye data")

    combined_result["zoomeye"] = ze_data
    return combined_result


def run_zoomeye_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Shallow copy of combined_result, run enrichment, return only the ``zoomeye`` dict."""
    import copy

    snapshot = copy.copy(combined_result)
    run_zoomeye_enrichment(snapshot, settings)
    return snapshot.get("zoomeye", {})
