"""
Unit tests for OTX (AlienVault) enrichment (recon/otx_enrich.py).

Mocks requests.get for https://otx.alienvault.com/api/v1/indicators/*.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from otx_enrich import run_otx_enrichment, run_otx_enrichment_isolated


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


def _otx_general_body() -> dict:
    return {
        "pulse_info": {"count": 5, "pulses": [{"name": "TestPulse", "tags": ["malware"]}]},
        "reputation": 10,
        "geo": {"country_name": "US", "city": "NYC", "asn": "AS12345"},
    }


def _otx_passive_dns_body() -> dict:
    return {"passive_dns": [{"hostname": "sub.example.com"}]}


class TestOtxEnrich(unittest.TestCase):
    """OTX indicator enrichment with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "OTX_ENABLED": True,
            "OTX_API_KEY": "otx-key",
            "OTX_KEY_ROTATOR": rotator,
        }
        base.update(overrides)
        return base

    def _url_path(self, url: str) -> str:
        return url.replace("https://otx.alienvault.com/api/v1/indicators", "")

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/1.2.3.4/general" in path:
                return _mock_response(200, _otx_general_body())
            if "/IPv4/1.2.3.4/passive_dns" in path:
                return _mock_response(200, _otx_passive_dns_body())
            if "/domain/example.com/general" in path:
                return _mock_response(200, {"pulse_info": {"count": 1}, "whois": {"registrar": "r"}})
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())

        self.assertIn("otx", out)
        reports = out["otx"]["ip_reports"]
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["ip"], "1.2.3.4")
        self.assertEqual(reports[0]["pulse_count"], 5)
        self.assertEqual(reports[0]["reputation"], 10)
        self.assertEqual(reports[0]["geo"]["country_name"], "US")
        self.assertEqual(reports[0]["geo"]["city"], "NYC")
        self.assertEqual(reports[0]["passive_dns_hostnames"], ["sub.example.com"])
        self.assertEqual(out["otx"]["domain_report"]["domain"], "example.com")
        self.assertEqual(out["otx"]["domain_report"]["pulse_count"], 1)

    @patch("otx_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings(OTX_API_KEY=""))
        self.assertNotIn("otx", out)
        mock_get.assert_not_called()

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_otx_enrichment(cr, self._settings())
                self.assertEqual(out["otx"]["ip_reports"], [])

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_rate_limit(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        self.assertEqual(out["otx"]["ip_reports"], [])

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_empty_results_general_failure(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(404, {})
        cr = _combined_result()
        out = run_otx_enrichment(cr, self._settings())
        self.assertEqual(out["otx"]["ip_reports"], [])

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_key_rotator_tick_after_requests(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"

        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/1.2.3.4/general" in path:
                return _mock_response(200, _otx_general_body())
            if "/IPv4/1.2.3.4/passive_dns" in path:
                return _mock_response(200, _otx_passive_dns_body())
            if "/domain/example.com/general" in path:
                return _mock_response(200, {"pulse_info": {"count": 0}, "whois": {}})
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        run_otx_enrichment(_combined_result(), self._settings(rotator=rotator, OTX_API_KEY=""))
        self.assertGreaterEqual(rotator.tick.call_count, 3)

    @patch("otx_enrich.time.sleep")
    @patch("otx_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._url_path(url)
            if "/IPv4/1.2.3.4/general" in path:
                return _mock_response(200, _otx_general_body())
            if "/IPv4/1.2.3.4/passive_dns" in path:
                return _mock_response(200, {})
            if "/domain/example.com/general" in path:
                return _mock_response(200, {"pulse_info": {"count": 0}, "whois": {}})
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        combined = _combined_result()
        sub = run_otx_enrichment_isolated(combined, self._settings())
        self.assertIn("ip_reports", sub)
        self.assertNotIn("otx", combined)


if __name__ == "__main__":
    unittest.main()
