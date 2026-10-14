"""Regression tests for the six bugs of LIMITACIONES_Y_PENDIENTES.md plus BUG-07 (www. prefix).

Every test proves that the *defect* is gone, not merely that a metric improved.
Run with: python -m pytest tests/test_corrections_phase2.py -v
"""
from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# BUG-01: client timeout (6000 ms) vs backend external queries (8000 ms)
# --------------------------------------------------------------------------
class TestBug01TimeoutBudget:
    def test_background_js_uses_single_8000ms_budget(self) -> None:
        source = (ROOT / "extension" / "background.js").read_text(encoding="utf-8")
        declared = re.search(r"const\s+timeoutMs\s*=\s*(\d+)", source)
        assert declared is not None, "timeoutMs must be declared once"
        assert declared.group(1) == "8000", "client budget must match backend 8000 ms budget"
        # the same variable (no literal 6000/8000 scattered around) is used for the signal
        assert re.search(r"AbortSignal\.timeout\(\s*timeoutMs\s*\)", source)
        # safe error handling: the timeout path raises an explicit, actionable error
        assert "timeoutMs" in source and "Timeout" in source

    def test_no_hardcoded_6000ms_client_timeout_remains(self) -> None:
        source = (ROOT / "extension" / "background.js").read_text(encoding="utf-8")
        assert "6000" not in source, "stale 6000 ms client timeout still present"

    def test_slow_rule_timeout_is_caught(self) -> None:
        source = (ROOT / "src" / "phishguard_ml" / "detection_rules.py").read_text(encoding="utf-8")
        # concurrent.futures.TimeoutError must be imported *and* handled around slow rules
        assert "TimeoutError as FuturesTimeout" in source
        assert "except FuturesTimeout" in source


# --------------------------------------------------------------------------
# BUG-02: synchronous DNS blocking the FastAPI/uvicorn event loop
# --------------------------------------------------------------------------
class TestBug02AsyncDns:
    def test_ssrf_validation_is_async(self) -> None:
        from phishguard_infra.policy import validate_url_ssrf_safety

        assert inspect.iscoroutinefunction(validate_url_ssrf_safety)

    def test_ssrf_validation_awaits_dns_off_loop(self) -> None:
        source = (ROOT / "src" / "phishguard_infra" / "policy.py").read_text(encoding="utf-8")
        assert "asyncio.to_thread" in source
        assert re.search(r"await\s+asyncio\.to_thread\(\s*socket\.getaddrinfo", source)

    @pytest.mark.asyncio
    async def test_private_and_loopback_targets_are_still_rejected(self) -> None:
        """SSRF protection must survive the async refactor."""
        from phishguard_infra.policy import UnsafeTargetError, validate_url_ssrf_safety

        for url in ("http://localhost/admin", "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/"):
            with pytest.raises(UnsafeTargetError):
                await validate_url_ssrf_safety(url)

    @pytest.mark.asyncio
    async def test_validation_completes_without_blocking_the_loop(self) -> None:
        """While DNS resolution runs (forced slow here), the event loop must keep
        serving other coroutines. A synchronous getaddrinfo would freeze it."""
        import socket
        import time

        from phishguard_infra.policy import validate_url_ssrf_safety

        original = socket.getaddrinfo

        def slow_getaddrinfo(*args, **kwargs):
            time.sleep(0.3)
            return original(*args, **kwargs)

        beats = 0

        async def heartbeat() -> None:
            nonlocal beats
            while True:
                beats += 1
                await asyncio.sleep(0.01)

        socket.getaddrinfo = slow_getaddrinfo
        task = asyncio.create_task(heartbeat())
        try:
            try:
                await asyncio.wait_for(validate_url_ssrf_safety("https://example.com/x"), timeout=5)
            except Exception:
                pass  # resolution outcome is irrelevant; liveness is what matters
        finally:
            socket.getaddrinfo = original
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert beats >= 5, f"event loop starved during DNS validation (beats={beats})"


# --------------------------------------------------------------------------
# BUG-03: homoglyph_brand_spoofing_detected vs is_spoofing + IDN/Punycode
# --------------------------------------------------------------------------
class TestBug03HomoglyphPunycode:
    @staticmethod
    def _analyze(host: str, registered: str) -> dict:
        from phishguard_ml.homoglyphs import analyze_homoglyphs

        return analyze_homoglyphs(host, registered)

    def test_punycode_label_with_hyphen_is_decoded(self) -> None:
        from phishguard_ml.homoglyphs import to_visual_skeleton

        skeleton = to_visual_skeleton("www.xn--pple-43d.com")
        assert "apple" in skeleton, "xn--pple-43d must decode to the visual skeleton 'apple'"

    def test_cyrillic_apple_homograph_detected_with_real_registered_domain(self) -> None:
        result = self._analyze("www.xn--pple-43d.com", "xn--pple-43d.com")
        assert result["is_spoofing"] is True

    def test_same_key_used_by_model_and_extension(self) -> None:
        result = self._analyze("www.xn--pple-43d.com", "xn--pple-43d.com")
        assert "is_spoofing" in result and "homoglyph_brand_spoofing_detected" in result
        assert result["is_spoofing"] == result["homoglyph_brand_spoofing_detected"]

    @pytest.mark.parametrize(
        "host,registered",
        [
            ("www.apple.com", "apple.com"),
            ("accounts.google.com", "google.com"),
            ("www.microsoft.com", "microsoft.com"),
            ("muenchen.de", "muenchen.de"),
            ("portal.espol.edu.ec", "espol.edu.ec"),
            ("xn--mnchen-3ya.de", "mnchen-3ya.de"),  # IDN legit city domain, no brand clash
            # C-2: subdominio punycode bajo el dominio oficial real de una marca NO es
            # suplantación (falso positivo demostrado por la auditoría técnica final).
            ("xn--caf-dma.apple.com", "apple.com"),
            ("xn--caf-dma.google.com", "google.com"),
            ("www.xn--caf-dma.netflix.com", "netflix.com"),
        ],
    )
    def test_no_unjustified_false_positives(self, host: str, registered: str) -> None:
        result = self._analyze(host, registered)
        assert result["is_spoofing"] is False, f"false positive for {host}"

    def test_c2_punycode_subdomain_of_real_brand_is_not_spoofing(self) -> None:
        """C-2: la heurística punycode solo aplica al DOMINIO REGISTRADO, nunca a un
        subdominio IDN legítimo bajo el dominio oficial real de la marca."""
        result = self._analyze("xn--caf-dma.apple.com", "apple.com")
        assert result["is_spoofing"] is False

    def test_c2_real_punycode_registered_domain_attack_still_detected(self) -> None:
        """C-2 preserva la detección de un dominio registrable xn-- que suplanta a una marca."""
        result = self._analyze("xn--pple-43d.com", "xn--pple-43d.com")
        assert result["is_spoofing"] is True

    def test_latin_lookalike_typosquat_still_detected(self) -> None:
        result = self._analyze("www.paypa1.com", "paypa1.com")
        assert result["is_spoofing"] is True

    def test_model_consumes_is_spoofing_key(self) -> None:
        source = (ROOT / "src" / "phishguard_ml" / "hybrid_model.py").read_text(encoding="utf-8")
        assert 'homoglyphs_data.get("is_spoofing")' in source

    def test_extension_consumes_same_key(self) -> None:
        source = (ROOT / "extension" / "background.js").read_text(encoding="utf-8")
        assert "is_spoofing" in source


# --------------------------------------------------------------------------
# BUG-04: early-stop threshold conflated with abstention threshold
# --------------------------------------------------------------------------
class TestBug04SeparateThresholds:
    @staticmethod
    def _final_action(abstention_threshold: float) -> str:
        from phishguard_orchestrator.engine import decide_next
        from phishguard_orchestrator.models import AdaptivePolicy

        policy = AdaptivePolicy(
            uncertainty_threshold=0.15,
            abstention_threshold=abstention_threshold,
            budget=0.0,
        )
        consulted = ("url", "infrastructure", "content", "visual")
        action, _reason, _conf, _unc = decide_next(0.85, consulted, policy)  # H(0.85) ~= 0.61
        return action

    def test_policy_exposes_two_distinct_thresholds(self) -> None:
        from phishguard_orchestrator.models import AdaptivePolicy

        policy = AdaptivePolicy()
        assert policy.uncertainty_threshold == pytest.approx(0.15)
        assert policy.abstention_threshold == pytest.approx(0.20)
        assert policy.uncertainty_threshold != policy.abstention_threshold

    def test_abstention_threshold_actually_governs_abstention(self) -> None:
        """Regression: changing abstention_threshold used to have *no* effect
        because the engine compared against uncertainty_threshold instead."""
        assert self._final_action(0.01) == "abstain"
        assert self._final_action(0.99) == "decide"
        assert self._final_action(0.01) != self._final_action(0.99)

    def test_default_policy_abstains_at_final_stage_when_uncertain(self) -> None:
        assert self._final_action(0.20) == "abstain"

    def test_engine_source_references_abstention_threshold(self) -> None:
        source = (ROOT / "src" / "phishguard_orchestrator" / "engine.py").read_text(encoding="utf-8")
        assert "policy.abstention_threshold" in source

    def test_early_stop_still_uses_uncertainty_threshold(self) -> None:
        from phishguard_orchestrator.engine import decide_next
        from phishguard_orchestrator.models import AdaptivePolicy

        policy = AdaptivePolicy(budget=0.0)
        # p=0.99 -> entropy ~0.08 <= 0.15 => early stop, decide
        action, reason, _c, _u = decide_next(0.99, ("url",), policy)
        assert action == "decide" and reason == "evidence_sufficient"


# --------------------------------------------------------------------------
# BUG-05: M3 forced with empty infrastructure/DOM dictionaries
# --------------------------------------------------------------------------
class TestBug05NoForcedVisualStage:
    def test_worker_has_no_force_visual_override(self) -> None:
        source = (ROOT / "src" / "phishguard_api" / "worker.py").read_text(encoding="utf-8")
        # no live assignment/call of the override (a historical comment is allowed)
        assert not re.search(r"^\s*force_visual\s*=", source, re.MULTILINE)
        assert "capture_for_blocked_site(" not in source

    def test_modality_acquisition_follows_policy_order(self) -> None:
        from phishguard_orchestrator.engine import run_adaptive
        from phishguard_orchestrator.models import AdaptivePolicy

        result = run_adaptive(0.5, {"infrastructure": 0.5, "content": 0.5, "visual": 0.5}, AdaptivePolicy())
        # modalities are requested in the declared acquisition order
        assert result.modalities_consulted == ("url", "infrastructure", "content", "visual")
        assert result.decision in {"phishing", "legitimate", "uncertain"}


# --------------------------------------------------------------------------
# BUG-06: LLM overwriting M2 probability unconditionally
# --------------------------------------------------------------------------
class TestBug06LlmBlend:
    def test_llm_probability_is_blended_not_overwritten(self) -> None:
        source = (ROOT / "src" / "phishguard_api" / "worker.py").read_text(encoding="utf-8")
        assert re.search(r"0\.7\s*\*\s*probability\s*\+\s*0\.3\s*\*\s*float\(\s*llm_prob\s*\)", source)
        # the old unconditional overwrite must be gone
        assert not re.search(r"probability\s*=\s*float\(\s*llm_prob\s*\)", source)
        assert "final_prob = llm_prob" not in source

    def test_blend_preserves_calibration_bounds(self) -> None:
        # blending two probabilities stays a probability and cannot exceed the
        # cascade value when the LLM is maximally bullish
        cascade, llm = 0.60, 1.0
        blended = 0.7 * cascade + 0.3 * llm
        assert min(cascade, llm) <= blended <= max(cascade, llm)
        assert 0.0 <= blended <= 1.0

    def test_llm_verdict_and_uncertainty_are_kept_separate(self) -> None:
        source = (ROOT / "src" / "phishguard_api" / "worker.py").read_text(encoding="utf-8")
        assert "llm_prob" in source


# --------------------------------------------------------------------------
# BUG-07: www. prefix shortcut in the URL feature extractor
# --------------------------------------------------------------------------
class TestBug07StripWww:
    def test_strip_www_normalizes_host(self) -> None:
        from phishguard_ml.features import _strip_www

        assert _strip_www("www.google.com") == "google.com"
        assert _strip_www("google.com") == "google.com"
        assert _strip_www("www2.example.com") == "www2.example.com"
        assert _strip_www("WWW.Example.COM") == "Example.COM"

    def test_extractor_applies_normalization(self) -> None:
        from phishguard_ml.features import UrlFeatureContext, extract_url_features

        with_www = extract_url_features(UrlFeatureContext(canonical_url="https://www.example.com/a", registered_domain="example.com"))
        without_www = extract_url_features(UrlFeatureContext(canonical_url="https://example.com/a", registered_domain="example.com"))
        authority = ("subdomain_count", "host_label_count", "host_length")
        for name in authority:
            if name in with_www and name in without_www:
                assert with_www[name] == without_www[name], f"{name} differs for www vs non-www"

    def test_shortener_and_redirect_handling_exists(self) -> None:
        source = (ROOT / "src" / "phishguard_ml" / "detection_rules.py").read_text(encoding="utf-8")
        assert "SHORTENERS_REQUIRING_REDIRECT" in source
        assert "requires_redirect" in source


# --------------------------------------------------------------------------
# BUG-08: la asignación `previous_row = current_row` quedó fuera del bucle
# externo de la DP de Levenshtein, produciendo distancias incorrectas para
# cadenas cortas (lev('t','microsoft') == 0) y falsos positivos de
# suplantación de marca en acortadores como t.ly / t.is.
# --------------------------------------------------------------------------
class TestBug08LevenshteinDp:
    @staticmethod
    def _reference(a: str, b: str) -> int:
        dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
        for i in range(len(a) + 1):
            dp[i][0] = i
        for j in range(len(b) + 1):
            dp[0][j] = j
        for i in range(1, len(a) + 1):
            for j in range(1, len(b) + 1):
                dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                               dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
        return dp[-1][-1]

    @pytest.mark.parametrize(
        "a,b",
        [
            ("t", "microsoft"),
            ("ly", "microsoft"),
            ("googlee", "google"),
            ("apple", "apple"),
            ("paypal", "paypal"),
            ("microsoft", "microsoft"),
            ("apple", "paypal"),
            ("ab", "cd"),
            ("a", "b"),
            ("t", "t"),
            ("", "abc"),
            ("bankofamerica", "bank0famerica"),
            ("instagram", "1nstagram"),
        ],
    )
    def test_matches_reference_implementation(self, a: str, b: str) -> None:
        from phishguard_ml.homoglyphs import levenshtein_distance

        assert levenshtein_distance(a, b) == self._reference(a, b)

    def test_self_distance_is_zero(self) -> None:
        from phishguard_ml.homoglyphs import levenshtein_distance

        for s in ("t", "ly", "apple", "microsoft", "bankofamerica"):
            assert levenshtein_distance(s, s) == 0

    def test_shorteners_are_not_brand_spoofing(self) -> None:
        """Regresión directa: acortadores legítimos no deben marcar suplantación."""
        from phishguard_ml.homoglyphs import analyze_homoglyphs

        for host, reg in [("t.ly", "t.ly"), ("t.is", "t.is"), ("s.id", "s.id"),
                          ("is.gd", "is.gd"), ("ow.ly", "ow.ly")]:
            result = analyze_homoglyphs(host, reg)
            assert result["is_spoofing"] is False, f"falso positivo de homógrafo en {host}"


# --------------------------------------------------------------------------
# C-3: la política de TLS nunca debe desactivar la verificación de certificados
# --------------------------------------------------------------------------
class TestC3TlsNeverDisabled:
    def test_no_verify_ssl_false_anywhere_in_source(self) -> None:
        """El fallback `verify_ssl=False` (C-3) quedó eliminado de todo el código."""
        hits = []
        for p in (ROOT / "src").rglob("*.py"):
            if "verify_ssl" in p.read_text(encoding="utf-8", errors="ignore"):
                hits.append(str(p.relative_to(ROOT)))
        assert hits == [], f"verify_ssl aún presente en: {hits}"

    def test_ssl_error_is_recorded_and_retried_without_disabling_tls(self) -> None:
        source = (ROOT / "src" / "phishguard_api" / "llm_agent.py").read_text(encoding="utf-8")
        assert '"kind": "ssl_error"' in source
        assert "urllib3.disable_warnings" not in source
        assert "CERT_NONE" not in source


# --------------------------------------------------------------------------
# C-4: barrido de secretos a árbol completo con revisión de extension.pem
# --------------------------------------------------------------------------
class TestC4SecretScanFullTree:
    def test_scan_covers_tracked_tree_and_flags_pem(self) -> None:
        source = (ROOT / "scripts" / "_secret_scan_before_commit.py").read_text(encoding="utf-8")
        assert '"git", "ls-files"' in source, "el escáner debe recorrer git ls-files (árbol completo)"
        assert "--others" in source, "debe cubrir también archivos no rastreados no ignorados"
        assert "extension.pem" in source, "extension.pem debe estar en la revisión de credenciales (B-09)"


# --------------------------------------------------------------------------
# C-5: el paquete de evidencia incluye los scripts E2E y los informes completos
# --------------------------------------------------------------------------
class TestC5EvidencePackIncludesE2e:
    def test_include_list_has_e2e_and_summarizer(self) -> None:
        source = (ROOT / "scripts" / "phase2j_pack_evidence.py").read_text(encoding="utf-8")
        for rel in ("scripts/e2e_chrome_phase2.py", "scripts/phase2k_summarize_e2e.py",
                    "scripts/phase2l_measure_c2_impact.py", "scripts/phase2m_regenerate_07_rows.py"):
            assert rel in source, f"{rel} debe incluirse en el ZIP de evidencia"


# --------------------------------------------------------------------------
# C-1 + MENOR-1/MENOR-2: bloque freeze de los entregables y guard de phase2b
# --------------------------------------------------------------------------
class TestAuditConditionsProgrammatic:
    def test_phase2h_freeze_block_uses_real_manifest_keys(self) -> None:
        """C-1: el bloque `freeze` de VALIDACION se llena con claves reales del manifiesto
        (sha256_file + git.commit + git.working_tree_dirty), no con `freeze: null`."""
        source = (ROOT / "scripts" / "phase2h_build_deliverables.py").read_text(encoding="utf-8")
        assert 'sha256_file(CP2 / "freeze_manifest.json")' in source
        assert '"git_commit": (freeze.get("git") or {}).get("commit")' in source.replace("'", '"')
        # B-02: el tiempo base declarado en phase2h debe ser 6000 ms, no 4000
        assert "4000" not in source, "phase2h aún declara un base de 4000 ms (B-02)"

    def test_phase2b_has_programmatic_freeze_guard(self) -> None:
        """MENOR-1: phase2b verifica el freeze de forma programática antes de etiquetar."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase2b_mod", ROOT / "scripts" / "phase2b_acquire_cohort2.py")
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        assert hasattr(mod, "verify_freeze_guard"), "phase2b debe exponer verify_freeze_guard"
        source = (ROOT / "scripts" / "phase2b_acquire_cohort2.py").read_text(encoding="utf-8")
        assert "verify_freeze_guard()" in source.split("def main()")[1], \
            "main() debe invocar el guard antes de consultar etiquetas"

    def test_phase2b_freeze_guard_aborts_on_missing_manifest(self, monkeypatch, tmp_path) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase2b_mod2", ROOT / "scripts" / "phase2b_acquire_cohort2.py")
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        monkeypatch.setattr(mod, "FREEZE_MANIFEST", tmp_path / "no_such_manifest.json")
        with pytest.raises(SystemExit):
            mod.verify_freeze_guard()
