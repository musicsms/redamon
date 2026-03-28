"""
Unit tests for VirusTotal enrichment (recon/virustotal_enrich.py).

Mocks requests.get for https://www.virustotal.com/api/v3/*.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from virustotal_enrich import run_virustotal_enrichment, run_virustotal_enrichment_isolated


def _combined_result() -> dict:
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _vt_domain_body() -> dict:
    return {
        "data": {
            "attributes": {
                "reputation": 5,
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 60,
                    "undetected": 10,
                },
                "categories": {"Forcepoint": "technology"},
                "registrar": "GoDaddy",
            },
        },
    }


def _vt_ip_body() -> dict:
    return {
        "data": {
            "attributes": {
                "reputation": -5,
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 15,
                },
                "asn": 12345,
                "as_owner": "TestOrg",
                "country": "US",
            },
        },
    }


class TestVirustotalEnrich(unittest.TestCase):
    """VirusTotal v3 enrichment with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "VIRUSTOTAL_ENABLED": True,
            "VIRUSTOTAL_API_KEY": "vt-key",
            "VIRUSTOTAL_KEY_ROTATOR": rotator,
            "VIRUSTOTAL_RATE_LIMIT": 4,
            "VIRUSTOTAL_MAX_TARGETS": 20,
        }
        base.update(overrides)
        return base

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_enrichment_success(self, mock_get, mock_sleep):
        def side_effect(url, **_kwargs):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            if "/ip_addresses/" in url:
                return _mock_response(200, _vt_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, self._settings())

        self.assertIn("virustotal", out)
        dr = out["virustotal"]["domain_report"]
        self.assertIsNotNone(dr)
        self.assertEqual(dr["domain"], "example.com")
        self.assertEqual(dr["reputation"], 5)
        self.assertEqual(dr["analysis_stats"]["malicious"], 1)
        self.assertEqual(dr["categories"].get("Forcepoint"), "technology")
        self.assertEqual(dr["registrar"], "GoDaddy")

        ipr = out["virustotal"]["ip_reports"]
        self.assertEqual(len(ipr), 1)
        self.assertEqual(ipr[0]["ip"], "1.2.3.4")
        self.assertEqual(ipr[0]["reputation"], -5)
        self.assertEqual(ipr[0]["asn"], 12345)
        self.assertEqual(ipr[0]["as_owner"], "TestOrg")
        self.assertEqual(ipr[0]["country"], "US")

        throttle_sleeps = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 15.0]
        self.assertGreaterEqual(len(throttle_sleeps), 1)

    @patch("virustotal_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, self._settings(VIRUSTOTAL_API_KEY=""))
        self.assertNotIn("virustotal", out)
        mock_get.assert_not_called()

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(401, {}, text="no")
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, self._settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(out["virustotal"]["ip_reports"], [])

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_rate_limit(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, self._settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(out["virustotal"]["ip_reports"], [])
        long_sleeps = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 65]
        self.assertGreaterEqual(len(long_sleeps), 1)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(404, {})
        cr = _combined_result()
        out = run_virustotal_enrichment(cr, self._settings())
        self.assertIsNone(out["virustotal"]["domain_report"])
        self.assertEqual(out["virustotal"]["ip_reports"], [])

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_key_rotator_tick_after_requests(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"

        def side_effect(url, **_kwargs):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            if "/ip_addresses/" in url:
                return _mock_response(200, _vt_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        run_virustotal_enrichment(_combined_result(), self._settings(rotator=rotator, VIRUSTOTAL_API_KEY=""))
        self.assertEqual(rotator.tick.call_count, 2)

    @patch("virustotal_enrich.time.sleep")
    @patch("virustotal_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, mock_sleep):
        def side_effect(url, **_kwargs):
            if "/domains/" in url:
                return _mock_response(200, _vt_domain_body())
            if "/ip_addresses/" in url:
                return _mock_response(200, _vt_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        combined = _combined_result()
        sub = run_virustotal_enrichment_isolated(combined, self._settings())
        self.assertIn("domain_report", sub)
        self.assertIn("ip_reports", sub)
        self.assertNotIn("virustotal", combined)
        throttle_sleeps = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 15.0]
        self.assertGreaterEqual(len(throttle_sleeps), 1)


if __name__ == "__main__":
    unittest.main()
