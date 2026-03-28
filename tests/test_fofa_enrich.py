"""
Unit tests for FOFA OSINT enrichment (recon/fofa_enrich.py).

Mocks requests.get for https://fofa.info/api/v1/search/all.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from fofa_enrich import run_fofa_enrichment, run_fofa_enrichment_isolated


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


def _fofa_success_body() -> dict:
    return {
        "error": False,
        "size": 1,
        "results": [
            [
                "1.2.3.4",
                "443",
                "example.com",
                "Test Page",
                "nginx",
                "https",
                "US",
                "NYC",
                "TestOrg",
            ],
        ],
    }


class TestFofaEnrich(unittest.TestCase):
    """FOFA enrichment with mocked HTTP and optional key rotator."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "FOFA_ENABLED": True,
            "FOFA_API_KEY": "fofa-key",
            "FOFA_KEY_ROTATOR": rotator,
            "FOFA_MAX_RESULTS": 100,
        }
        base.update(overrides)
        return base

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        cr = _combined_result()
        out = run_fofa_enrichment(cr, self._settings())

        self.assertIn("fofa", out)
        rows = out["fofa"]["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 443)
        self.assertEqual(rows[0]["host"], "example.com")
        self.assertEqual(rows[0]["title"], "Test Page")
        self.assertEqual(rows[0]["server"], "nginx")
        self.assertEqual(rows[0]["as_org"], "TestOrg")

        mock_get.assert_called_once()
        url = mock_get.call_args[0][0]
        self.assertEqual(url, "https://fofa.info/api/v1/search/all")

    @patch("fofa_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_fofa_enrichment(cr, self._settings(FOFA_API_KEY=""))
        self.assertNotIn("fofa", out)
        mock_get.assert_not_called()

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_fofa_enrichment(cr, self._settings())
                self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_rate_limit(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="slow down")
        cr = _combined_result()
        out = run_fofa_enrichment(cr, self._settings())
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"error": False, "size": 0, "results": []})
        cr = _combined_result()
        out = run_fofa_enrichment(cr, self._settings())
        self.assertEqual(out["fofa"]["results"], [])

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_key_rotator_tick_after_request(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rot-key"
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        cr = _combined_result()
        run_fofa_enrichment(cr, self._settings(rotator=rotator, FOFA_API_KEY=""))
        rotator.tick.assert_called()

    @patch("fofa_enrich.time.sleep")
    @patch("fofa_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _fofa_success_body())
        combined = _combined_result()
        sub = run_fofa_enrichment_isolated(combined, self._settings())
        self.assertIn("results", sub)
        self.assertEqual(len(sub["results"]), 1)
        self.assertNotIn("fofa", combined)


if __name__ == "__main__":
    unittest.main()
