"""Тесты движка скоринга: агрегация, оверлеи, пороги, списки."""
from __future__ import annotations

import pytest

from app.analyzers.heuristics import MailContext
from app.engine.scoring import ScoringEngine, build_engine
from app.schemas import ModuleReport
from app.storage import db


def make_engine() -> ScoringEngine:
    return build_engine()


def report(score: int = 0, status: str = "ok") -> ModuleReport:
    return ModuleReport(score=score, status=status)


def test_aggregation_weighted_average():
    engine = make_engine()
    modules = {
        "heuristics": report(100), "urls": report(0), "auth": report(0),
        "attachments": report(0), "ai": report(50),
    }
    result = engine.aggregate(modules)
    weights = engine.weights
    # все модули отработали: обычное взвешенное среднее
    expected = (weights["heuristics"] * 100 + weights["ai"] * 50) / sum(weights.values())
    assert result["score"] == round(expected)
    assert result["skipped_modules"] == []
    assert result["renormalized"] is False


def test_failed_module_weight_redistributed():
    engine = make_engine()
    modules = {
        "heuristics": report(80), "urls": report(80), "auth": report(80),
        "attachments": report(0, status="skipped"), "ai": report(0, status="not_configured"),
    }
    result = engine.aggregate(modules)
    # веса недоступных модулей не «сгорают»: оценка не должна просесть к нулю
    assert result["score"] == 80
    assert result["renormalized"] is True


def test_all_modules_down_returns_zero():
    engine = make_engine()
    modules = {name: report(0, status="skipped") for name in
               ("heuristics", "urls", "auth", "attachments", "ai")}
    result = engine.aggregate(modules)
    assert result["score"] == 0
    assert result["used_weight"] == 0.0


def test_threshold_bands():
    engine = make_engine()
    assert engine._band(0) == "allow"
    assert engine._band(engine.thresholds["warn"]) == "warn"
    assert engine._band(engine.thresholds["hold"]) == "hold"
    assert engine._band(engine.thresholds["quarantine"]) == "quarantine"
    assert engine._band(engine.thresholds["block"]) == "block"


def test_overlay_prompt_injection_forces_block():
    engine = make_engine()
    modules = {
        "heuristics": ModuleReport(score=5, evidence=[]),
        "urls": report(0), "auth": report(0), "attachments": report(0),
        "ai": report(0),
    }
    # вручную кладём сигнал prompt_injection
    from app.schemas import Evidence
    modules["heuristics"] = ModuleReport(
        score=34,
        evidence=[Evidence(rule_id="prompt_injection", title="inj", points=34,
                           category="ai_abuse")],
    )
    decision = engine.decide(modules, MailContext(sender_domain="x.ru"))
    assert decision["action"] == "block"
    assert decision["score"] >= engine.thresholds["block"]


def test_overlay_credential_url_forces_quarantine():
    from app.schemas import Evidence

    engine = make_engine()
    modules = {
        "heuristics": ModuleReport(score=30, evidence=[
            Evidence(rule_id="credential_harvest", title="cred", points=30,
                     category="credentials")]),
        "urls": ModuleReport(score=40, evidence=[
            Evidence(rule_id="url_suspicious", title="url", points=40,
                     category="url")]),
        "auth": report(0), "attachments": report(0), "ai": report(0),
    }
    decision = engine.decide(modules, MailContext(sender_domain="x.ru"))
    assert decision["action"] in ("quarantine", "block")
    assert decision["score"] >= engine.thresholds["quarantine"]


def test_denylist_forces_block():
    engine = make_engine()
    db.list_add("evil.ru", "deny", note="известный фишинговый домен")
    engine.patterns.clear_cache()
    ctx = MailContext(sender="a@evil.ru", sender_domain="evil.ru", body="просто текст")
    modules = {"heuristics": report(0), "urls": report(0), "auth": report(0),
               "attachments": report(0), "ai": report(0)}
    decision = engine.decide(modules, ctx, deny_hit=engine.denylist_match(ctx))
    assert decision["action"] == "block"
    assert "чёрном списке" in decision["reason"]


def test_allowlist_overrides_when_clean():
    engine = make_engine()
    db.list_add("partner.ru", "allow", note="проверенный партнёр")
    engine.patterns.clear_cache()
    ctx = MailContext(sender="a@partner.ru", sender_domain="partner.ru")
    modules = {"heuristics": report(10), "urls": report(0), "auth": report(0),
               "attachments": report(0), "ai": report(0)}
    decision = engine.decide(modules, ctx, allow_hit=engine.allowlist_match(
        ctx.sender_domain, ctx.sender))
    assert decision["action"] == "allow"
    assert decision["confidence"] >= 0.9


def test_grey_zone_flag_near_threshold():
    engine = make_engine()
    # все модули дают ровно порог warn → агрегат попадает в серую зону ±grey_zone
    warn = engine.thresholds["warn"]
    modules = {name: report(warn) for name in
               ("heuristics", "urls", "auth", "attachments", "ai")}
    decision = engine.decide(modules, MailContext(sender_domain="x.ru"))
    assert decision["score"] == warn
    assert decision["action"] == "warn"
    assert decision["grey_zone"] is True


def test_flat_evidence_has_weights():
    from app.schemas import Evidence

    engine = make_engine()
    modules = {
        "heuristics": ModuleReport(score=30, evidence=[
            Evidence(rule_id="r1", title="t", points=30, category="generic")]),
        "urls": report(0), "auth": report(0), "attachments": report(0),
        "ai": report(0),
    }
    flat = engine.flat_evidence(modules)
    assert flat[0].source == "heuristics"
    assert flat[0].weight == pytest.approx(engine.weights["heuristics"], abs=1e-3)
    assert flat[0].weighted_points == pytest.approx(
        30 * engine.weights["heuristics"], abs=0.1)
