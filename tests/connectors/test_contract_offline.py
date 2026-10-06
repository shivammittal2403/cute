"""Offline contract tests for the connector SDK.

No network: these exercise input validation, SSRF/url policy, and honest
failure behavior of every implemented connector family. Network-dependent
behavior is covered by recorded-response tests in test_contract_recorded.py.
"""
from __future__ import annotations

import pytest

from traceatlas.sources.connectors.base import CollectResult, is_safe_url
from traceatlas.sources.connectors.blockchain import (
    BlockstreamBTCConnector, EtherscanETHConnector)
from traceatlas.sources.connectors.code import GitHubConnector
from traceatlas.sources.connectors.cti_generic import CVERecordConnector, OSVConnector
from traceatlas.sources.connectors.dataset import OpenCorporatesConnector, WikidataConnector
from traceatlas.sources.connectors.geocoding import NominatimConnector
from traceatlas.sources.connectors.rss import GoogleNewsRSSConnector, RSSConnector
from traceatlas.sources.connectors.search import DuckDuckGoSearchConnector
from traceatlas.sources.connectors.username import UsernameAvailabilityConnector


class TestSafeUrlPolicy:
    def test_rejects_non_http_scheme(self):
        ok, reason = is_safe_url("file:///etc/passwd")
        assert not ok and "scheme" in reason

    def test_rejects_private_literal(self):
        ok, reason = is_safe_url("http://127.0.0.1/x")
        assert not ok

    def test_allows_public_when_dns_available(self):
        # example.com resolves publicly in CI with DNS; if DNS is absent the
        # guard fails closed, which is also acceptable — assert one of both.
        ok, reason = is_safe_url("https://example.com")
        assert ok or "dns" in reason


class TestInputValidation:
    def test_blockstream_rejects_non_btc(self):
        res = BlockstreamBTCConnector().collect("0xdeadbeef")
        assert not res.ok and "not a BTC address" in res.error

    def test_etherscan_honest_without_key(self, monkeypatch):
        monkeypatch.delenv("TRACEATLAS_ETHERSCAN_KEY", raising=False)
        res = EtherscanETHConnector().collect("0x" + "ab" * 20)
        assert not res.ok and "credential_required" in res.error

    def test_cve_connector_requires_cve_id(self):
        res = CVERecordConnector().collect("not-a-cve")
        assert not res.ok and "not a CVE" in res.error

    def test_username_validation(self):
        res = UsernameAvailabilityConnector().collect("")
        assert not res.ok and "invalid username" in res.error

    def test_github_bad_target(self):
        res = GitHubConnector().collect("no owner/repo pattern!!", capability="repo.info")
        assert not res.ok

    def test_nominatim_reverse_needs_coords(self):
        res = NominatimConnector().collect("not,coords", capability="reverse_geocode")
        assert not res.ok and "lat,lon" in res.error


class TestNetworkFailureHonesty(monkeypatch):
    """When outbound network is unavailable connectors must fail honestly
    (ok=False with an error), never fabricate observations."""

    def _boom(self, *a, **k):
        raise OSError("network disabled in test")

    def test_rss_fails_closed(self, monkeypatch):
        import httpx
        monkeypatch.setattr(httpx.Client, "get", lambda self, *a, **k: (_ for _ in ()).throw(
            httpx.ConnectError("blocked")))
        res = GoogleNewsRSSConnector().collect("acme corp")
        assert isinstance(res, CollectResult) and not res.ok and res.error

    def test_search_fails_closed(self, monkeypatch):
        import httpx
        monkeypatch.setattr(httpx.Client, "post", lambda self, *a, **k: (_ for _ in ()).throw(
            httpx.ConnectError("blocked")))
        res = DuckDuckGoSearchConnector().collect("test query")
        assert not res.ok and res.error

    def test_opencorporates_fails_closed(self, monkeypatch):
        import httpx
        monkeypatch.setattr(httpx.Client, "get", lambda self, *a, **k: (_ for _ in ()).throw(
            httpx.ConnectTimeout("blocked")))
        res = OpenCorporatesConnector().collect("Acme Inc")
        assert not res.ok

    def test_wikidata_fails_closed(self, monkeypatch):
        import httpx
        monkeypatch.setattr(httpx.Client, "get", lambda self, *a, **k: (_ for _ in ()).throw(
            httpx.ConnectError("blocked")))
        res = WikidataConnector().collect("Q475")
        assert not res.ok
