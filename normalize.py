#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, Literal, Mapping, TypedDict

SCHEMA_VERSION: Final[str] = "1.0"


class Status(str, Enum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"
    MISSING = "MISSING"


class Severity(str, Enum):
    NONE = "NONE"
    MED = "MED"
    HIGH = "HIGH"


FeatureValue = bool | int | str | None
Features = dict[str, FeatureValue]


class ToolResult(TypedDict):
    status: str | None
    features: Features


@dataclass(frozen=True)
class EnvFile:
    path: Path
    exists: bool
    raw: Mapping[str, str]

    @classmethod
    def load(cls, path: Path) -> "EnvFile":
        if not path.is_file():
            return cls(path=path, exists=False, raw={})

        parsed: dict[str, str] = {}
        text: str = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped: str = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            parsed[key.strip()] = value.strip()
        return cls(path=path, exists=True, raw=parsed)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value: str | None = self.raw.get(key)
        if value is None:
            return default
        return value.strip().lower() == "true"

    def get_int(self, key: str, default: int = 0) -> int:
        value: str | None = self.raw.get(key)
        if value is None:
            return default
        try:
            return int(value.strip())
        except ValueError:
            return default

    def has_key(self, key: str) -> bool:
        return key in self.raw


def _any_missing(*files: EnvFile) -> bool:
    return any(not f.exists for f in files)


def normalize_clamav(pre: EnvFile, post: EnvFile) -> ToolResult:
    pre_detected: bool = pre.get_int("CLAMAV_PRE_INFECTED_FILES") > 0
    post_detected: bool = post.get_int("CLAMAV_POST_INFECTED_FILES") > 0
    scan_error: bool = (
        pre.get_int("CLAMAV_PRE_EXIT_CODE") == 2
        or post.get_int("CLAMAV_POST_EXIT_CODE") == 2
    )

    features: Features = {
        "pre_detected": pre_detected,
        "post_detected": post_detected,
        "scan_error": scan_error,
    }

    status: Status
    if _any_missing(pre, post) or scan_error:
        status = Status.MISSING
    elif pre_detected or post_detected:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_kvrt(pre: EnvFile, post: EnvFile) -> ToolResult:
    detected: bool = (
        pre.get_int("KVRT_PRE_DETECTED_COUNT") > 0
        or post.get_int("KVRT_POST_DETECTED_COUNT") > 0
    )
    scan_error: bool = (
        pre.get_bool("KVRT_PRE_FATAL_ERROR_MARKER")
        or post.get_bool("KVRT_POST_FATAL_ERROR_MARKER")
        or not pre.get_bool("KVRT_PRE_SCAN_FINISHED_MARKER", default=True)
        or not post.get_bool("KVRT_POST_SCAN_FINISHED_MARKER", default=True)
    )

    features: Features = {"detected": detected, "scan_error": scan_error}

    status: Status
    if _any_missing(pre, post) or scan_error:
        status = Status.MISSING
    elif detected:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_yara(yara: EnvFile) -> ToolResult:
    match: bool = yara.get_int("YARA_MATCH_COUNT") > 0
    scan_error: bool = yara.get_bool("YARA_SCAN_ERROR")

    severity: Severity
    if yara.get_int("YARA_HIGH_SCORE_COUNT") > 0:
        severity = Severity.HIGH
    elif yara.get_int("YARA_MED_SCORE_COUNT") > 0:
        severity = Severity.MED
    else:
        severity = Severity.NONE

    features: Features = {
        "match": match,
        "rule_severity": severity.value,
        "scan_error": scan_error,
    }

    status: Status
    if not yara.exists or scan_error:
        status = Status.MISSING
    elif severity is Severity.HIGH:
        status = Status.FAIL
    elif severity is Severity.MED:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_ripgrep(yara: EnvFile) -> ToolResult:
    pattern_match: bool = yara.get_bool("RG_HAS_NONEMPTY_CATEGORIES")
    features: Features = {"pattern_match": pattern_match}
    return {"status": None, "features": features}


def normalize_bandit(bandit: EnvFile) -> ToolResult:
    n_high_high: int = bandit.get_int("BANDIT_UPDATE_SEV_HIGH_CONF_HIGH")
    n_high_any: int = (
        n_high_high
        + bandit.get_int("BANDIT_UPDATE_SEV_HIGH_CONF_MED")
        + bandit.get_int("BANDIT_UPDATE_SEV_HIGH_CONF_LOW")
    )
    scan_error: bool = (
        bandit.get_bool("BANDIT_UPDATE_SCAN_ERROR")
        or bandit.get_bool("BANDIT_UPDATE_JSON_PARSE_ERROR")
    )

    features: Features = {
        "n_high_high": n_high_high,
        "n_high_any": n_high_any,
        "scan_error": scan_error,
    }

    status: Status
    if not bandit.exists or scan_error:
        status = Status.MISSING
    elif n_high_high > 0:
        status = Status.FAIL
    elif n_high_any > 0:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_grype(sbom: EnvFile, image: EnvFile) -> ToolResult:
    critical: int = (
        sbom.get_int("GRYPE_SBOM_CRITICAL_TOTAL")
        + image.get_int("GRYPE_IMAGE_CRITICAL_TOTAL")
    )
    high: int = (
        sbom.get_int("GRYPE_SBOM_HIGH_TOTAL")
        + image.get_int("GRYPE_IMAGE_HIGH_TOTAL")
    )
    kev_match: bool = (
        sbom.get_int("GRYPE_SBOM_KEV_MATCHES") > 0
        or image.get_int("GRYPE_IMAGE_KEV_MATCHES") > 0
    )
    scan_error: bool = (
        sbom.get_bool("GRYPE_SBOM_SCAN_ERROR")
        or sbom.get_bool("GRYPE_SBOM_JSON_PARSE_ERROR")
        or image.get_bool("GRYPE_IMAGE_SCAN_ERROR")
        or image.get_bool("GRYPE_IMAGE_JSON_PARSE_ERROR")
    )

    features: Features = {
        "critical": critical,
        "high": high,
        "kev_match": kev_match,
        "scan_error": scan_error,
    }

    status: Status
    if _any_missing(sbom, image) or scan_error:
        status = Status.MISSING
    elif kev_match:
        status = Status.FAIL
    elif critical > 0 or high > 0:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_zap(zap: EnvFile) -> ToolResult:
    exit_code: int = zap.get_int("ZAP_EXIT_CODE")
    scan_error: bool = (
        zap.get_bool("ZAP_SCAN_ERROR") or zap.get_bool("ZAP_JSON_PARSE_ERROR")
    )

    features: Features = {"exit_code": exit_code, "scan_error": scan_error}

    status: Status
    if not zap.exists or scan_error or exit_code == 3:
        status = Status.MISSING
    elif exit_code == 1:
        status = Status.FAIL
    elif exit_code == 2:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


def normalize_schemathesis(schema: EnvFile) -> ToolResult:
    has_5xx: bool = schema.get_bool("SCHEMATHESIS_HAS_5XX")
    schema_violations: int = schema.get_int("SCHEMATHESIS_SCHEMA_VIOLATIONS")
    scan_error: bool = (
        schema.get_bool("SCHEMATHESIS_SCAN_ERROR")
        or schema.get_bool("SCHEMATHESIS_XML_PARSE_ERROR")
    )

    features: Features = {
        "has_5xx": has_5xx,
        "schema_violations": schema_violations,
        "scan_error": scan_error,
    }

    status: Status
    if not schema.exists or scan_error:
        status = Status.MISSING
    elif has_5xx or schema_violations > 0:
        status = Status.REVIEW
    else:
        status = Status.PASS

    return {"status": status.value, "features": features}


class NormalizedReport(TypedDict):
    schema_version: str
    tools: dict[str, ToolResult]
    sigma: dict[str, dict[str, str | None]]


_ARTIFACT_NAMES: Final[dict[str, str]] = {
    "clamav_pre": "clamav_pre.env",
    "clamav_post": "clamav_post.env",
    "kvrt_pre": "kvrt_pre.env",
    "kvrt_post": "kvrt_post.env",
    "yara": "yara.env",
    "bandit": "bandit.env",
    "grype_sbom": "grype-sbom.env",
    "grype_image": "grype-image.env",
    "zap": "zap.env",
    "schemathesis": "schemathesis.env",
}


def build_report(input_dir: Path) -> NormalizedReport:
    env: dict[str, EnvFile] = {
        key: EnvFile.load(input_dir / name)
        for key, name in _ARTIFACT_NAMES.items()
    }

    tools: dict[str, ToolResult] = {
        "clamav": normalize_clamav(env["clamav_pre"], env["clamav_post"]),
        "kvrt": normalize_kvrt(env["kvrt_pre"], env["kvrt_post"]),
        "yara": normalize_yara(env["yara"]),
        "ripgrep": normalize_ripgrep(env["yara"]),
        "bandit": normalize_bandit(env["bandit"]),
        "grype": normalize_grype(env["grype_sbom"], env["grype_image"]),
        "zap": normalize_zap(env["zap"]),
        "schemathesis": normalize_schemathesis(env["schemathesis"]),
    }

    sigma: dict[str, dict[str, str | None]] = {
        "T003": {
            "clamav": tools["clamav"]["status"],
            "kvrt": tools["kvrt"]["status"],
        },
        "T004": {
            "yara": tools["yara"]["status"],
            "bandit": tools["bandit"]["status"],
        },
        "T005": {
            "grype": tools["grype"]["status"],
            "zap": tools["zap"]["status"],
            "schema": tools["schemathesis"]["status"],
        },
    }

    return {"schema_version": SCHEMA_VERSION, "tools": tools, "sigma": sigma}


Mode = Literal["run", "stdout"]


def main(argv: list[str]) -> int:
    input_dir: Path = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    output_file: Path = Path(argv[2]) if len(argv) > 2 else Path("normalized.json")

    if not input_dir.is_dir():
        print(f"error: input dir not found: {input_dir}", file=sys.stderr)
        return 2

    report: NormalizedReport = build_report(input_dir)
    serialized: str = json.dumps(report, ensure_ascii=False, indent=2)
    output_file.write_text(serialized + "\n", encoding="utf-8")
    print(f"written: {output_file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
