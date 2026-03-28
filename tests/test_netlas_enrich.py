"""
Unit tests for Netlas OSINT enrichment (recon/netlas_enrich.py).

Mocks requests.get for https://app.netlas.io/api/responses/.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from netlas_enrich import run_netlas_enrichment, run_netlas_enrichment_isolated


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


def _netlas_body() -> dict:
    return {
        "items": [
            {
                "data": {
                    "host": "1.2.3.4",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "protocol": "https",
                    "http": {"title": "Test"},
                    "geo": {"country": "US"},
                    "isp": "TestISP",
                },
            },
        ],
        "count": 1,
    }


class TestNetlasEnrich(unittest.TestCase):
    """Netlas responses enrichment with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "NETLAS_ENABLED": True,
            "NETLAS_API_KEY": "nl-key",
            "NETLAS_KEY_ROTATOR": rotator,
            "NETLAS_MAX_RESULTS": 100,
        }
        base.update(overrides)
        return base

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _netlas_body())
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())

        self.assertIn("netlas", out)
        rows = out["netlas"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "1.2.3.4")
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 443)
        self.assertEqual(rows[0]["protocol"], "https")
        self.assertEqual(rows[0]["title"], "Test")
        self.assertEqual(rows[0]["country"], "US")
        self.assertEqual(rows[0]["isp"], "TestISP")

        mock_get.assert_called_once()
        url = mock_get.call_args[0][0]
        self.assertTrue(url.startswith("https://app.netlas.io/api/responses/"))
        headers = mock_get.call_args[1].get("headers") or {}
        self.assertEqual(headers.get("X-API-Key"), "nl-key")

    @patch("netlas_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings(NETLAS_API_KEY=""))
        self.assertNotIn("netlas", out)
        mock_get.assert_not_called()

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_netlas_enrichment(cr, self._settings())
                self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_rate_limit(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())
        self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"items": [], "count": 0})
        cr = _combined_result()
        out = run_netlas_enrichment(cr, self._settings())
        self.assertEqual(out["netlas"]["results"], [])

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_key_rotator_tick_after_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        mock_get.return_value = _mock_response(200, _netlas_body())
        run_netlas_enrichment(_combined_result(), self._settings(rotator=rotator, NETLAS_API_KEY=""))
        rotator.tick.assert_called_once()

    @patch("netlas_enrich.time.sleep")
    @patch("netlas_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _netlas_body())
        combined = _combined_result()
        sub = run_netlas_enrichment_isolated(combined, self._settings())
        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)
        self.assertNotIn("netlas", combined)


if __name__ == "__main__":
    unittest.main()
