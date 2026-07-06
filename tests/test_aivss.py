"""AIVSS-Agentic scoring (OWASP AIVSS v0.5) — deterministic, no network."""
from __future__ import annotations

import pytest

from agentscanner import aivss
from agentscanner.checks import CHECK_REGISTRY
from agentscanner.models import Severity


def test_every_registered_check_has_an_archetype():
    """Guard against a new check shipping with no AIVSS coverage."""
    missing = set(CHECK_REGISTRY) - set(aivss.CHECK_ARCHETYPES)
    assert not missing, f"checks with no AIVSS archetype mapping: {sorted(missing)}"


def test_overrides_target_registered_checks():
    unknown = set(aivss.CHECK_OVERRIDES) - set(CHECK_REGISTRY)
    assert not unknown, f"CHECK_OVERRIDES references unregistered checks: {unknown}"


@pytest.mark.parametrize("check_id,vector", aivss.CHECK_OVERRIDES.items())
def test_override_vectors_are_well_formed(check_id, vector):
    assert len(vector) == len(aivss.FACTOR_NAMES)
    assert all(v in (0.0, 0.5, 1.0) for v in vector)


def test_every_archetype_used_is_defined():
    unknown = set(aivss.CHECK_ARCHETYPES.values()) - set(aivss._ARCHETYPES)
    assert not unknown, f"CHECK_ARCHETYPES references undefined archetypes: {unknown}"


@pytest.mark.parametrize("archetype,vector", aivss._ARCHETYPES.items())
def test_archetype_vectors_are_well_formed(archetype, vector):
    assert len(vector) == len(aivss.FACTOR_NAMES)
    assert all(v in (0.0, 0.5, 1.0) for v in vector)


def test_score_is_deterministic():
    a = aivss.score_finding("AS-HOOK-001", Severity.CRITICAL)
    b = aivss.score_finding("AS-HOOK-001", Severity.CRITICAL)
    assert a == b


def test_score_formula_matches_spec():
    # AS-HOOK-004 -> "hygiene" archetype: all-zero AARS vector.
    result = aivss.score_finding("AS-HOOK-004", Severity.LOW, thm=1.0)
    assert result.aars == 0.0
    assert result.cvss_base == 2.5
    assert result.score == round((2.5 + 0.0) / 2 * 1.0, 1)


def test_score_clamped_to_0_10():
    result = aivss.score_finding("AS-HOOK-001", Severity.CRITICAL, thm=1.0)
    assert 0.0 <= result.score <= 10.0


def test_unknown_check_raises():
    with pytest.raises(KeyError):
        aivss.score_finding("AS-DOES-NOT-EXIST", Severity.HIGH)


def test_default_thm_matches_spec_recommendation():
    assert aivss.DEFAULT_THM == 0.97
