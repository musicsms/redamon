"""
Unit tests for Criminal IP enrichment (recon/criminalip_enrich.py).

Mocks requests.get for https://api.criminalip.io/v1/*.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from criminalip_enrich import run_criminalip_enrichment, run_criminalip_enrichment_isolated


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


def _cip_ip_body() -> dict:
    return {
        "score": {"inbound": "critical", "outbound": "safe"},
        "issues": {"is_vpn": True, "is_proxy": False, "is_tor": False},
        "whois": {"org_name": "TestOrg", "org_country_code": "US"},
        "port": [{"open_port_no": 80}, {"open_port_no": 443}],
    }


def _cip_domain_body() -> dict:
    return {"data": {"risk_score": "high"}}


class TestCriminalipEnrich(unittest.TestCase):
    """Criminal IP API enrichment with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "CRIMINALIP_ENABLED": True,
            "CRIMINALIP_API_KEY": "cip-key",
            "CRIMINALIP_KEY_ROTATOR": rotator,
        }
        base.update(overrides)
        return base

    def _path_from_url(self, url: str) -> str:
        return url.replace("https://api.criminalip.io/v1/", "")

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())

        self.assertIn("criminalip", out)
        dr = out["criminalip"]["domain_report"]
        self.assertIsNotNone(dr)
        self.assertEqual(dr["domain"], "example.com")
        self.assertIn("risk", dr)
        self.assertEqual(dr["risk"].get("score"), "high")

        ipr = out["criminalip"]["ip_reports"]
        self.assertEqual(len(ipr), 1)
        self.assertEqual(ipr[0]["ip"], "1.2.3.4")
        self.assertEqual(ipr[0]["score"]["inbound"], "critical")
        self.assertEqual(ipr[0]["score"]["outbound"], "safe")
        self.assertIs(ipr[0]["issues"]["is_vpn"], True)
        self.assertIs(ipr[0]["issues"]["is_proxy"], False)
        self.assertEqual(ipr[0]["whois"]["org_name"], "TestOrg")
        self.assertEqual(len(ipr[0]["ports"]), 2)

    @patch("criminalip_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings(CRIMINALIP_API_KEY=""))
        self.assertNotIn("criminalip", out)
        mock_get.assert_not_called()

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_criminalip_enrichment(cr, self._settings())
                self.assertIsNone(out["criminalip"]["domain_report"])
                self.assertEqual(out["criminalip"]["ip_reports"], [])

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_rate_limit(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())
        self.assertIsNone(out["criminalip"]["domain_report"])
        self.assertEqual(out["criminalip"]["ip_reports"], [])
        backoff = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 2]
        self.assertGreaterEqual(len(backoff), 1)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(404, {})
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())
        self.assertIsNone(out["criminalip"]["domain_report"])
        self.assertEqual(out["criminalip"]["ip_reports"], [])

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_key_rotator_tick_after_requests(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"

        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        run_criminalip_enrichment(_combined_result(), self._settings(rotator=rotator, CRIMINALIP_API_KEY=""))
        self.assertEqual(rotator.tick.call_count, 2)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        combined = _combined_result()
        sub = run_criminalip_enrichment_isolated(combined, self._settings())
        self.assertIn("ip_reports", sub)
        self.assertIn("domain_report", sub)
        self.assertNotIn("criminalip", combined)


if __name__ == "__main__":
    unittest.main()
