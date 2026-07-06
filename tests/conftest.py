"""Shared test fixtures.

Autouse-stubs the OSV.dev network boundary for the whole suite so no test
ever makes a real HTTP call or depends on network availability in CI. Tests
that want to exercise the real (offline) code path patch ``osv.is_offline``
or call ``osv.query_dependency`` directly instead of relying on this stub.
"""
from __future__ import annotations

import pytest

from agentscanner import osv

# Deterministic canned responses for the fixture packages used across
# tests/fixtures/bad and tests/fixtures/dep-bad.
_KNOWN_VULNS = {
    ("PyPI", "requests", "2.6.0"): [
        {
            "id": "GHSA-fixture-requests",
            "summary": "fixture vulnerability for testing",
            "database_specific": {"severity": "HIGH"},
        }
    ],
    ("npm", "lodash", "4.17.4"): [
        {
            "id": "GHSA-fixture-lodash",
            "summary": "fixture vulnerability for testing",
            "database_specific": {"severity": "HIGH"},
        }
    ],
    ("npm", "left-pad", "1.3.0"): [
        {
            "id": "GHSA-fixture-left-pad",
            "summary": "fixture vulnerability for testing",
            "database_specific": {"severity": "HIGH"},
        }
    ],
}


def _fake_query_dependency(ecosystem, name, version):
    return _KNOWN_VULNS.get((ecosystem, name, version), [])


@pytest.fixture(autouse=True)
def stub_osv_network(monkeypatch):
    monkeypatch.setattr(osv, "query_dependency", _fake_query_dependency)
    yield
