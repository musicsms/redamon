"""
Unit tests for ZoomEye enrichment (recon/zoomeye_enrich.py).

Mocks requests.get for https://api.zoomeye.ai/host/search.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from zoomeye_enrich import run_zoomeye_enrichment, run_zoomeye_enrichment_isolated


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


def _zoomeye_body() -> dict:
    return {
        "total": 1,
        "matches": [
            {
                "ip": "1.2.3.4",
                "portinfo": {
                    "port": 80,
                    "app": "nginx",
                    "banner": "HTTP/1.1",
                    "os": "Linux",
                },
                "geoinfo": {"country": {"names": {"en": "US"}}},
            },
        ],
    }


class TestZoomeyeEnrich(unittest.TestCase):
    """ZoomEye host search with mocked HTTP."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "ZOOMEYE_ENABLED": True,
            "ZOOMEYE_API_KEY": "ze-key",
            "ZOOMEYE_KEY_ROTATOR": rotator,
            "ZOOMEYE_MAX_RESULTS": 1,
        }
        base.update(overrides)
        return base

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings())

        self.assertIn("zoomeye", out)
        rows = out["zoomeye"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 80)
        self.assertEqual(rows[0]["app"], "nginx")
        self.assertEqual(rows[0]["banner"], "HTTP/1.1")
        self.assertEqual(rows[0]["os"], "Linux")
        self.assertEqual(rows[0]["country"], "US")

    @patch("zoomeye_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings(ZOOMEYE_API_KEY=""))
        self.assertNotIn("zoomeye", out)
        mock_get.assert_not_called()

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_zoomeye_enrichment(cr, self._settings())
                self.assertEqual(out["zoomeye"]["results"], [])

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_rate_limit(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings())
        self.assertEqual(out["zoomeye"]["results"], [])
        backoff = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 2]
        self.assertGreaterEqual(len(backoff), 1)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"total": 0, "matches": []})
        cr = _combined_result()
        out = run_zoomeye_enrichment(cr, self._settings())
        self.assertEqual(out["zoomeye"]["results"], [])

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_api_key_header_not_bearer(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        run_zoomeye_enrichment(_combined_result(), self._settings())
        headers = mock_get.call_args[1].get("headers") or {}
        self.assertEqual(headers.get("API-KEY"), "ze-key")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-API-Key", headers)

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_key_rotator_tick_after_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        run_zoomeye_enrichment(_combined_result(), self._settings(rotator=rotator, ZOOMEYE_API_KEY=""))
        rotator.tick.assert_called()

    @patch("zoomeye_enrich.time.sleep")
    @patch("zoomeye_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _zoomeye_body())
        combined = _combined_result()
        sub = run_zoomeye_enrichment_isolated(combined, self._settings())
        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)
        self.assertNotIn("zoomeye", combined)


if __name__ == "__main__":
    unittest.main()
