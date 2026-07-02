#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final, Literal


class Status(str, Enum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"
    MISSING = "MISSING"


class Color(str, Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    REJECT = "REJECT"


T003: Final = "T003"
T004: Final = "T004"
T005: Final = "T005"
TESTS_ORDER: Final[tuple[str, ...]] = (T003, T004, T005)

Q0_INIT: Final = "q0"
Q1_T003: Final = "q1"
Q2_T004: Final = "q2"
Q3_T005: Final = "q3"
Q4_T006: Final = "q4"
Q4G_GUARD: Final = "q4_guard"
Q5_VERDICT: Final = "q5"
Q6_CONFLICT: Final = "q6"
Q7_MISSING: Final = "q7"
Q8_ALLOW: Final = "q8"
Q9_MANUAL: Final = "q9"
Q10_REJECT: Final = "q10"

FINAL_STATES: Final[frozenset[str]] = frozenset({Q8_ALLOW, Q9_MANUAL, Q10_REJECT})

_VERDICT_BY_STATE: Final[dict[str, Verdict]] = {
    Q8_ALLOW: Verdict.ALLOW,
    Q9_MANUAL: Verdict.MANUAL_REVIEW,
    Q10_REJECT: Verdict.REJECT,
}

EXPERT_VERDICTS: Final[frozenset[str]] = frozenset({
    "NDV_REFUTED", "NDV_NON_DESTRUCTIVE", "NDV_DESTRUCTIVE", "T006_IMPOSSIBLE",
})

_MAX_STEPS: Final = 100


@dataclass(frozen=True)
class ToolSignal:
    status: Status | None
    features: dict[str, object]

    def feat_int(self, key: str, default: int = 0) -> int:
        value = self.features.get(key, default)
        return value if isinstance(value, int) and not isinstance(value, bool) else default

    def feat_bool(self, key: str, default: bool = False) -> bool:
        value = self.features.get(key, default)
        return value if isinstance(value, bool) else default


@dataclass(frozen=True)
class Sigma:
    clamav: ToolSignal
    kvrt: ToolSignal
    yara: ToolSignal
    ripgrep: ToolSignal
    bandit: ToolSignal
    grype: ToolSignal
    zap: ToolSignal
    schema: ToolSignal


@dataclass(frozen=True)
class Context0:
    kii_category: int
    supply_verified: bool
    expert_verdict: str | None


@dataclass
class GammaState:
    test_colors: dict[str, Color | None] = field(
        default_factory=lambda: {T003: None, T004: None, T005: None}
    )
    completed_tests: set[str] = field(default_factory=set)
    missing_checks: set[str] = field(default_factory=set)
    conflict_log: list[tuple[str, str]] = field(default_factory=list)
    conflict_sources: set[str] = field(default_factory=set)

    def has_yellow(self) -> bool:
        return any(c is Color.YELLOW for c in self.test_colors.values())

    def has_red(self) -> bool:
        return any(c is Color.RED for c in self.test_colors.values())


@dataclass(frozen=True)
class Argument:
    name: str
    claim: str | None


@dataclass(frozen=True)
class ModuleResult:
    color: Color
    reason_code: str
    arguments: list[str]
    attacks: list[tuple[str, str]]
    extension: list[str]


def _grounded_extension(
    args: list[Argument],
    attacks: list[tuple[str, str]],
) -> set[str]:
    names: set[str] = {a.name for a in args}
    attackers: dict[str, set[str]] = {name: set() for name in names}
    for src, dst in attacks:
        if src in names and dst in names:
            attackers[dst].add(src)

    def f(accepted: set[str]) -> set[str]:
        result: set[str] = set()
        for name in names:
            if all(
                any(att_of_att in accepted for att_of_att in attackers[attacker])
                for attacker in attackers[name]
            ):
                result.add(name)
        return result

    current: set[str] = set()
    for _ in range(len(names) + 2):
        nxt = f(current)
        if nxt == current:
            return current
        current = nxt
    return current


def _map_extension_to_color(args: list[Argument], extension: set[str]) -> Color:
    by_name = {a.name: a for a in args}
    accepted_claims = {
        by_name[name].claim
        for name in extension
        if by_name[name].claim is not None
    }
    has_clean = "clean" in accepted_claims
    has_suspicious = "suspicious" in accepted_claims
    if has_clean and not has_suspicious:
        return Color.GREEN
    return Color.YELLOW


def module_t003(sigma: Sigma) -> ModuleResult:
    clamav, kvrt = sigma.clamav.status, sigma.kvrt.status

    a_clamav = Argument(
        "a_clamav",
        "clean" if clamav is Status.PASS else "suspicious",
    )
    a_kvrt = Argument(
        "a_kvrt",
        "clean" if kvrt is Status.PASS else "suspicious",
    )
    args = [a_clamav, a_kvrt]
    attacks = [("a_clamav", "a_kvrt"), ("a_kvrt", "a_clamav")]

    extension = _grounded_extension(args, attacks)
    color = _map_extension_to_color(args, extension)

    if clamav is Status.PASS and kvrt is Status.REVIEW:
        reason = "t003_clamav_clean_kvrt_detection"
    else:
        reason = "t003_clamav_detection_kvrt_clean"

    return ModuleResult(
        color=color,
        reason_code=reason,
        arguments=[a.name for a in args],
        attacks=attacks,
        extension=sorted(extension),
    )


def module_t004(sigma: Sigma, gamma0: Context0) -> ModuleResult:
    yara, bandit = sigma.yara.status, sigma.bandit.status
    pattern_match = sigma.ripgrep.feat_bool("pattern_match")
    kii = gamma0.kii_category

    a_yara = Argument(
        "a_yara",
        "clean" if yara is Status.PASS else "suspicious",
    )
    a_bandit = Argument(
        "a_bandit",
        "clean" if bandit is Status.PASS else "suspicious",
    )
    args: list[Argument] = [a_yara, a_bandit]
    attacks: list[tuple[str, str]] = []

    if yara is Status.REVIEW and bandit is Status.PASS:
        if (not pattern_match) and kii == 3:
            args.append(Argument("a_undercut_yara", None))
            attacks.append(("a_undercut_yara", "a_yara"))
            reason = "t004_yara_medium_no_pattern_undercut_kii_3"
        elif pattern_match:
            reason = "t004_yara_medium_with_pattern_unresolved"
        else:
            reason = "t004_yara_medium_kii_high"
    else:
        if kii == 3:
            args.append(Argument("a_undercut_bandit", None))
            attacks.append(("a_undercut_bandit", "a_bandit"))
            reason = "t004_bandit_review_undercut_kii_3"
        else:
            reason = "t004_bandit_review_kii_high"

    extension = _grounded_extension(args, attacks)
    color = _map_extension_to_color(args, extension)

    return ModuleResult(
        color=color,
        reason_code=reason,
        arguments=[a.name for a in args],
        attacks=attacks,
        extension=sorted(extension),
    )


def module_t005(sigma: Sigma, gamma0: Context0) -> ModuleResult:
    kii = gamma0.kii_category

    a_grype = Argument("a_grype", "suspicious")
    a_zap = Argument("a_zap", "clean")
    a_schema = Argument("a_schema", "clean")
    args: list[Argument] = [a_grype, a_zap, a_schema]
    attacks: list[tuple[str, str]] = []

    if kii == 3:
        args.append(Argument("a_undercut_grype", None))
        attacks.append(("a_undercut_grype", "a_grype"))
        reason = "t005_cve_not_exploited_low_kii"
    elif kii == 2:
        reason = "t005_critical_cve_kii_2"
    else:
        reason = "t005_critical_cve_kii_1"

    extension = _grounded_extension(args, attacks)
    color = _map_extension_to_color(args, extension)

    return ModuleResult(
        color=color,
        reason_code=reason,
        arguments=[a.name for a in args],
        attacks=attacks,
        extension=sorted(extension),
    )


@dataclass
class StepTrace:
    state: str
    transition: str
    next_state: str
    note: str = ""


def _modules_to_log(g: GammaState, test: str, result: ModuleResult) -> None:
    g.conflict_log.append((test, result.reason_code))


def step_q0(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    if not g0.supply_verified:
        return Q10_REJECT, "δ0.1 (supply_verified=false)"
    return Q1_T003, "δ0.2 (supply_verified=true)"


def step_q1(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    clamav, kvrt = sigma.clamav.status, sigma.kvrt.status
    g.completed_tests.add(T003)

    if clamav is Status.MISSING or kvrt is Status.MISSING:
        g.missing_checks.add(T003)
        if clamav is Status.MISSING:
            g.conflict_log.append((T003, "t003_clamav_missing"))
        if kvrt is Status.MISSING:
            g.conflict_log.append((T003, "t003_kvrt_missing"))
        return Q7_MISSING, "δ1.1 (T003 MISSING)"

    if clamav is Status.PASS and kvrt is Status.PASS:
        g.test_colors[T003] = Color.GREEN
        g.conflict_log.append((T003, "t003_both_clean"))
        return Q2_T004, "δ1.2 (T003 GREEN)"

    if clamav is Status.REVIEW and kvrt is Status.REVIEW:
        g.test_colors[T003] = Color.YELLOW
        g.conflict_log.append((T003, "t003_both_detection"))
        g.conflict_sources.add(T003)
        return Q6_CONFLICT, "δ1.3 (T003 YELLOW)"

    result = module_t003(sigma)
    g.test_colors[T003] = result.color
    _modules_to_log(g, T003, result)
    if result.color is Color.GREEN:
        return Q2_T004, "δ1.4 -> M_T003 (GREEN)"
    if result.color is Color.YELLOW:
        g.conflict_sources.add(T003)
        return Q6_CONFLICT, "δ1.4 -> M_T003 (YELLOW)"
    return Q10_REJECT, "δ1.4 -> M_T003 (RED)"


def step_q2(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    yara, bandit = sigma.yara.status, sigma.bandit.status
    g.completed_tests.add(T004)

    if yara is Status.FAIL:
        g.test_colors[T004] = Color.RED
        g.conflict_log.append((T004, "t004_known_malicious"))
        return Q10_REJECT, "δ2.1 (T004 RED, YARA FAIL)"
    if bandit is Status.FAIL:
        g.test_colors[T004] = Color.RED
        g.conflict_log.append((T004, "t004_dangerous_code"))
        return Q10_REJECT, "δ2.2 (T004 RED, Bandit FAIL)"

    if yara is Status.MISSING or bandit is Status.MISSING:
        g.missing_checks.add(T004)
        if yara is Status.MISSING:
            g.conflict_log.append((T004, "t004_yara_missing"))
        if bandit is Status.MISSING:
            g.conflict_log.append((T004, "t004_bandit_missing"))
        return Q7_MISSING, "δ2.3 (T004 MISSING)"

    if yara is Status.PASS and bandit is Status.PASS:
        g.test_colors[T004] = Color.GREEN
        g.conflict_log.append((T004, "t004_no_constructs"))
        return Q3_T005, "δ2.4 (T004 GREEN)"

    if yara is Status.REVIEW and bandit is Status.REVIEW:
        g.test_colors[T004] = Color.YELLOW
        g.conflict_log.append((T004, "t004_both_uncertain"))
        g.conflict_sources.add(T004)
        return Q6_CONFLICT, "δ2.5 (T004 YELLOW)"

    result = module_t004(sigma, g0)
    g.test_colors[T004] = result.color
    _modules_to_log(g, T004, result)
    if result.color is Color.GREEN:
        return Q3_T005, "δ2.6 -> M_T004 (GREEN)"
    if result.color is Color.YELLOW:
        g.conflict_sources.add(T004)
        return Q6_CONFLICT, "δ2.6 -> M_T004 (YELLOW)"
    return Q10_REJECT, "δ2.6 -> M_T004 (RED)"


def step_q3(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    grype, zap, schema = sigma.grype.status, sigma.zap.status, sigma.schema.status
    critical = sigma.grype.feat_int("critical")
    kev_match = sigma.grype.feat_bool("kev_match")
    zap_exit = sigma.zap.feat_int("exit_code")
    g.completed_tests.add(T005)

    if grype is Status.FAIL:
        g.test_colors[T005] = Color.RED
        g.conflict_log.append((T005, "t005_kev_exploitable"))
        return Q10_REJECT, "δ3.1 (T005 RED, Grype FAIL)"
    if zap is Status.FAIL:
        g.test_colors[T005] = Color.RED
        g.conflict_log.append((T005, "t005_runtime_vulnerability"))
        return Q10_REJECT, "δ3.2 (T005 RED, ZAP FAIL)"

    if (grype is Status.MISSING or zap is Status.MISSING
            or schema is Status.MISSING or zap_exit == 3):
        g.missing_checks.add(T005)
        if grype is Status.MISSING:
            g.conflict_log.append((T005, "t005_grype_missing"))
        if zap is Status.MISSING or zap_exit == 3:
            g.conflict_log.append((T005, "t005_zap_missing"))
        if schema is Status.MISSING:
            g.conflict_log.append((T005, "t005_schema_missing"))
        return Q7_MISSING, "δ3.3 (T005 MISSING)"

    if (grype is Status.REVIEW and critical > 0 and not kev_match
            and zap is Status.PASS and schema is Status.PASS):
        result = module_t005(sigma, g0)
        g.test_colors[T005] = result.color
        _modules_to_log(g, T005, result)
        if result.color is Color.YELLOW:
            g.conflict_sources.add(T005)
            return Q6_CONFLICT, "δ3.4 -> M_T005 (YELLOW)"
        if result.color is Color.GREEN:
            if g.has_yellow():
                return Q4G_GUARD, "δ3.4 -> M_T005 (GREEN, есть YELLOW -> q4′)"
            return Q5_VERDICT, "δ3.4 -> M_T005 (GREEN, нет YELLOW)"
        raise RuntimeError(
            f"M_T005 вернул недопустимый для δ3.4 цвет: {result.color}"
        )

    if (grype is Status.REVIEW and zap is Status.PASS
            and schema is Status.PASS and critical == 0):
        g.test_colors[T005] = Color.YELLOW
        g.conflict_log.append((T005, "t005_high_cves"))
        g.conflict_sources.add(T005)
        return Q6_CONFLICT, "δ3.5 (T005 YELLOW)"

    if (grype is Status.PASS and zap is Status.REVIEW
            and schema in (Status.PASS, Status.REVIEW)):
        g.test_colors[T005] = Color.YELLOW
        g.conflict_log.append((T005, "t005_zap_warnings"))
        g.conflict_sources.add(T005)
        return Q6_CONFLICT, "δ3.6 (T005 YELLOW)"

    if grype is Status.PASS and zap is Status.PASS and schema is Status.REVIEW:
        g.test_colors[T005] = Color.YELLOW
        g.conflict_log.append((T005, "t005_schema_issues"))
        g.conflict_sources.add(T005)
        return Q6_CONFLICT, "δ3.7 (T005 YELLOW)"

    if grype is Status.REVIEW and (zap is Status.REVIEW or schema is Status.REVIEW):
        g.test_colors[T005] = Color.YELLOW
        g.conflict_log.append((T005, "t005_multiple_uncertain"))
        g.conflict_sources.add(T005)
        return Q6_CONFLICT, "δ3.8 (T005 YELLOW)"

    if grype is Status.PASS and zap is Status.PASS and schema is Status.PASS:
        g.test_colors[T005] = Color.GREEN
        g.conflict_log.append((T005, "t005_all_clean"))
        if g.has_yellow():
            return Q4G_GUARD, "δ3.B (T005 GREEN, есть YELLOW -> q4′)"
        return Q5_VERDICT, "δ3.A (T005 GREEN, нет YELLOW)"

    raise RuntimeError(
        f"q3: неперекрытая конфигурация σ_T005 = "
        f"({grype}, {zap}, {schema}, critical={critical}, kev={kev_match})"
    )


def step_q4_guard(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    if g.missing_checks:
        return Q10_REJECT, "δ4′.1 (missing_checks != ∅ -> REJECT)"
    return Q4_T006, "δ4′.2 (missing_checks = ∅ -> q4)"


def step_q4(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    verdict = g0.expert_verdict

    if verdict is None:
        g.conflict_log.append((T006_TAG, "t006_pending_expert"))
        return Q9_MANUAL, "δ4.0 (отложенная экспертиза -> MANUAL_REVIEW)"

    yellow_tests = [t for t, c in g.test_colors.items() if c is Color.YELLOW]

    if verdict == "NDV_REFUTED":
        for t in yellow_tests:
            g.test_colors[t] = Color.GREEN
            g.conflict_log.append((t, "t006_ndv_refuted"))
        return Q5_VERDICT, "δ4.1 (NDV_REFUTED, YELLOW -> GREEN)"

    if verdict == "NDV_NON_DESTRUCTIVE":
        for t in yellow_tests:
            g.conflict_log.append((t, "t006_ndv_non_destructive"))
        return Q5_VERDICT, "δ4.2 (NDV_NON_DESTRUCTIVE, YELLOW сохранён)"

    if verdict == "NDV_DESTRUCTIVE":
        for t in yellow_tests:
            g.test_colors[t] = Color.RED
            g.conflict_log.append((t, "t006_ndv_confirmed"))
        return Q10_REJECT, "δ4.3 (NDV_DESTRUCTIVE, YELLOW -> RED)"

    for t in yellow_tests:
        g.test_colors[t] = Color.RED
        g.conflict_log.append((t, "t006_impossible"))
    return Q10_REJECT, "δ4.4 (T006_IMPOSSIBLE, YELLOW -> RED)"


def step_q5(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    if g.has_red():
        return Q10_REJECT, "δ5.1 (RED -> REJECT)"

    if g.missing_checks:
        return Q10_REJECT, "δ5.2 (missing_checks != ∅ -> REJECT)"

    if g.has_yellow():
        if g0.kii_category == 1:
            return Q10_REJECT, "δ5.3 (YELLOW, kii=1 -> REJECT)"
        return Q9_MANUAL, "δ5.4 (YELLOW, kii in {2,3} -> MANUAL_REVIEW)"

    return Q8_ALLOW, "δ5.5 (все GREEN -> ALLOW)"


def step_q6(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    if T004 not in g.completed_tests:
        return Q2_T004, "δ6.1 (T004 не пройден -> q2)"
    if T005 not in g.completed_tests:
        return Q3_T005, "δ6.2 (T005 не пройден -> q3)"
    return Q4G_GUARD, "δ6.3 (все тесты пройдены -> q4′)"


def step_q7(sigma: Sigma, g0: Context0, g: GammaState) -> tuple[str, str]:
    if T004 not in g.completed_tests:
        return Q2_T004, "δ7.1 (T004 не пройден -> q2)"
    if T005 not in g.completed_tests:
        return Q3_T005, "δ7.2 (T005 не пройден -> q3)"
    return Q10_REJECT, "δ7.3 (все тесты пройдены, missing_checks != ∅ -> REJECT)"


T006_TAG: Final = "T006"

_DISPATCH: Final = {
    Q0_INIT: step_q0,
    Q1_T003: step_q1,
    Q2_T004: step_q2,
    Q3_T005: step_q3,
    Q4G_GUARD: step_q4_guard,
    Q4_T006: step_q4,
    Q5_VERDICT: step_q5,
    Q6_CONFLICT: step_q6,
    Q7_MISSING: step_q7,
}


@dataclass
class RunResult:
    verdict: Verdict
    final_state: str
    gamma: GammaState
    trace: list[StepTrace]


def run_automaton(sigma: Sigma, g0: Context0) -> RunResult:
    g = GammaState()
    state = Q0_INIT
    trace: list[StepTrace] = []

    for _ in range(_MAX_STEPS):
        if state in FINAL_STATES:
            return RunResult(
                verdict=_VERDICT_BY_STATE[state],
                final_state=state,
                gamma=g,
                trace=trace,
            )
        step_fn = _DISPATCH.get(state)
        if step_fn is None:
            raise RuntimeError(f"нет обработчика для состояния {state}")
        next_state, label = step_fn(sigma, g0, g)
        trace.append(StepTrace(state=state, transition=label, next_state=next_state))
        state = next_state

    raise RuntimeError(
        f"автомат не завершился за {_MAX_STEPS} шагов (последнее состояние {state})"
    )


def _parse_status(value: object) -> Status | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return Status(value)
        except ValueError:
            raise ValueError(f"недопустимый статус: {value!r}")
    raise ValueError(f"недопустимый тип статуса: {value!r}")


def load_sigma(path: Path) -> Sigma:
    data = json.loads(path.read_text(encoding="utf-8"))
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("normalized.json: отсутствует или некорректна секция 'tools'")

    def signal(name: str) -> ToolSignal:
        entry = tools.get(name)
        if not isinstance(entry, dict):
            raise ValueError(f"normalized.json: отсутствует инструмент '{name}'")
        feats = entry.get("features", {})
        if not isinstance(feats, dict):
            feats = {}
        return ToolSignal(
            status=_parse_status(entry.get("status")),
            features=dict(feats),
        )

    return Sigma(
        clamav=signal("clamav"),
        kvrt=signal("kvrt"),
        yara=signal("yara"),
        ripgrep=signal("ripgrep"),
        bandit=signal("bandit"),
        grype=signal("grype"),
        zap=signal("zap"),
        schema=signal("schemathesis"),
    )


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def load_context(path: Path, overrides: dict[str, object]) -> Context0:
    data: dict[str, object] = {}
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    data.update(overrides)

    if "kii_category" not in data:
        raise ValueError("context: обязательный параметр 'kii_category' не задан")
    kii = int(data["kii_category"])  
    if kii not in (1, 2, 3):
        raise ValueError(f"context: kii_category должен быть 1/2/3, получено {kii}")

    supply_verified = _coerce_bool(data.get("supply_verified", True))

    expert_raw = data.get("expert_verdict")
    expert_verdict: str | None
    if expert_raw is None or expert_raw == "" or expert_raw == "⊥":
        expert_verdict = None
    else:
        expert_verdict = str(expert_raw)
        if expert_verdict not in EXPERT_VERDICTS:
            raise ValueError(
                f"context: недопустимый expert_verdict: {expert_verdict!r}"
            )

    return Context0(
        kii_category=kii,
        supply_verified=supply_verified,
        expert_verdict=expert_verdict,
    )


def build_output(sigma: Sigma, g0: Context0, run: RunResult) -> dict[str, object]:
    g = run.gamma
    return {
        "schema_version": "1.0",
        "verdict": run.verdict.value,
        "final_state": run.final_state,
        "context": {
            "kii_category": g0.kii_category,
            "supply_verified": g0.supply_verified,
            "expert_verdict": g0.expert_verdict,
        },
        "test_colors": {
            t: (c.value if c is not None else None)
            for t, c in g.test_colors.items()
        },
        "completed_tests": sorted(g.completed_tests),
        "missing_checks": sorted(g.missing_checks),
        "conflict_sources": sorted(g.conflict_sources),
        "conflict_log": [
            {"test": t, "reason_code": r} for t, r in g.conflict_log
        ],
        "trace": [
            {
                "state": s.state,
                "transition": s.transition,
                "next_state": s.next_state,
            }
            for s in run.trace
        ],
    }


Mode = Literal["run"]


def _parse_overrides(argv: list[str]) -> tuple[list[str], dict[str, object]]:
    positional: list[str] = []
    overrides: dict[str, object] = {}
    for arg in argv:
        if arg.startswith("--") and "=" in arg:
            key, _, value = arg[2:].partition("=")
            overrides[key.strip()] = value.strip()
        else:
            positional.append(arg)
    return positional, overrides


def main(argv: list[str]) -> int:
    positional, overrides = _parse_overrides(argv[1:])

    if not positional:
        print(
            "usage: python automaton.py NORMALIZED_JSON [CONTEXT_JSON] "
            "[OUTPUT_JSON] [--kii_category=N] ...",
            file=sys.stderr,
        )
        return 2

    normalized_path = Path(positional[0])
    context_path = Path(positional[1]) if len(positional) > 1 else Path("context.json")
    output_path = Path(positional[2]) if len(positional) > 2 else Path("verdict.json")

    if not normalized_path.is_file():
        print(f"error: normalized.json not found: {normalized_path}", file=sys.stderr)
        return 2

    try:
        sigma = load_sigma(normalized_path)
        g0 = load_context(context_path, overrides)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        run = run_automaton(sigma, g0)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output = build_output(sigma, g0, run)
    output_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"verdict: {run.verdict.value} (state {run.final_state})", file=sys.stderr)
    print(f"written: {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
