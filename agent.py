#!/usr/bin/env python3
"""
dns-drift — detects unexpected changes in a domain's public DNS records.

Resolves a configured set of record types for each target domain, compares the
answer against a committed baseline snapshot, and reports any difference as a
finding.

Outcome semantics (important):
    A run that successfully checks its targets is a SUCCESS, whether or not
    drift was found. Detecting drift is the agent doing its job. Only a run
    that could not complete its work (config error, every target unresolvable,
    unexpected exception) is a FAILURE.

Usage:
    python agent.py                      # check against baseline
    python agent.py --update-baseline    # accept current state as the baseline
    python agent.py --config targets.yml --out result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import yaml

VERSION = "1.0.0"
DEFAULT_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
SUPPORTED_TYPES = DEFAULT_TYPES + ["CAA", "SRV", "PTR"]


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    domain: str
    record_type: str
    kind: str  # drift | domain_missing | domain_restored
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "domain": self.domain,
            "record_type": self.record_type,
            "kind": self.kind,
        }
        if self.added:
            d["added"] = self.added
        if self.removed:
            d["removed"] = self.removed
        if self.detail:
            d["detail"] = self.detail
        return d

    def line(self) -> str:
        if self.kind == "domain_missing":
            return f"  ! {self.domain} — does not resolve (NXDOMAIN)"
        if self.kind == "domain_restored":
            return f"  + {self.domain} — resolves again"
        parts = []
        if self.added:
            parts.append("added " + ", ".join(self.added))
        if self.removed:
            parts.append("removed " + ", ".join(self.removed))
        return f"  ~ {self.domain} {self.record_type}: {'; '.join(parts)}"


@dataclass
class TargetResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    nxdomain: bool = False

    @property
    def usable(self) -> bool:
        """True if we learned something real about this domain."""
        return self.nxdomain or bool(self.records) or len(self.errors) == 0


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    targets = raw.get("targets") or []
    if not targets:
        raise SystemExit(f"no targets defined in {path}")

    normalized = []
    for entry in targets:
        if isinstance(entry, str):
            entry = {"domain": entry}
        domain = (entry.get("domain") or "").strip().rstrip(".").lower()
        if not domain:
            raise SystemExit(f"target with no domain in {path}: {entry!r}")
        types = entry.get("record_types") or raw.get("record_types") or DEFAULT_TYPES
        types = [t.upper() for t in types]
        unknown = [t for t in types if t not in SUPPORTED_TYPES]
        if unknown:
            raise SystemExit(f"unsupported record type(s) for {domain}: {unknown}")
        normalized.append({"domain": domain, "record_types": types})

    return {
        "targets": normalized,
        "nameservers": raw.get("nameservers") or ["1.1.1.1", "8.8.8.8"],
        "timeout": float(raw.get("timeout", 5.0)),
        "ignore": {k.lower(): v for k, v in (raw.get("ignore") or {}).items()},
    }


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #


def build_resolver(nameservers: list[str], timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def normalize(record_type: str, value: str) -> str:
    value = value.strip()
    if record_type == "TXT":
        # dnspython renders TXT with surrounding quotes and splits long strings.
        return value.replace('" "', "").strip('"')
    if record_type in {"NS", "CNAME", "PTR"}:
        return value.rstrip(".").lower()
    if record_type == "MX":
        pref, _, host = value.partition(" ")
        return f"{pref} {host.rstrip('.').lower()}"
    return value.lower()


def resolve_target(
    resolver: dns.resolver.Resolver, domain: str, record_types: list[str]
) -> TargetResult:
    result = TargetResult(domain=domain)

    for rtype in record_types:
        try:
            answer = resolver.resolve(domain, rtype, raise_on_no_answer=True)
            values = sorted({normalize(rtype, r.to_text()) for r in answer})
            result.records[rtype] = values
        except dns.resolver.NoAnswer:
            result.records[rtype] = []
        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
            result.records = {}
            break
        except dns.resolver.NoNameservers as exc:
            result.errors[rtype] = f"SERVFAIL: {exc}"
        except dns.exception.Timeout:
            result.errors[rtype] = "timeout"
        except dns.exception.DNSException as exc:
            result.errors[rtype] = f"{type(exc).__name__}: {exc}"

    return result


# --------------------------------------------------------------------------- #
# comparison
# --------------------------------------------------------------------------- #


def snapshot_path(snapshot_dir: Path, domain: str) -> Path:
    safe = domain.replace("/", "_").replace("*", "_wildcard")
    return snapshot_dir / f"{safe}.json"


def load_snapshot(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  warning: unreadable snapshot {path.name} ({exc}) — treating as new")
        return None


def write_snapshot(path: Path, result: TargetResult) -> None:
    payload = {
        "domain": result.domain,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent_version": VERSION,
        "nxdomain": result.nxdomain,
        "records": result.records,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def is_ignored(ignore: dict[str, list[str]], domain: str, record_type: str) -> bool:
    entries = ignore.get(domain) or ignore.get("*") or []
    return record_type.upper() in {e.upper() for e in entries}


def compare(
    result: TargetResult, baseline: dict[str, Any], ignore: dict[str, list[str]]
) -> list[Finding]:
    findings: list[Finding] = []
    was_missing = bool(baseline.get("nxdomain"))

    if result.nxdomain and not was_missing:
        return [Finding(result.domain, "-", "domain_missing")]
    if result.nxdomain and was_missing:
        return []
    if was_missing and not result.nxdomain:
        findings.append(Finding(result.domain, "-", "domain_restored"))

    old_records: dict[str, list[str]] = baseline.get("records") or {}

    for rtype, current in result.records.items():
        if is_ignored(ignore, result.domain, rtype):
            continue
        if rtype not in old_records:
            # newly watched record type — record the baseline, don't cry drift
            continue
        previous = old_records[rtype]
        added = sorted(set(current) - set(previous))
        removed = sorted(set(previous) - set(current))
        if added or removed:
            findings.append(
                Finding(result.domain, rtype, "drift", added=added, removed=removed)
            )

    return findings


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    config = load_config(Path(args.config))
    snapshot_dir = Path(args.snapshots)
    resolver = build_resolver(config["nameservers"], config["timeout"])

    findings: list[Finding] = []
    errors: list[str] = []
    checked = 0
    records_compared = 0
    new_baselines = 0

    for target in config["targets"]:
        domain = target["domain"]
        print(f"checking {domain} ({', '.join(target['record_types'])})")
        result = resolve_target(resolver, domain, target["record_types"])

        if result.errors:
            for rtype, msg in result.errors.items():
                errors.append(f"{domain} {rtype}: {msg}")
                print(f"  error: {rtype} — {msg}")

        if not result.usable:
            continue

        checked += 1
        records_compared += sum(len(v) for v in result.records.values())
        path = snapshot_path(snapshot_dir, domain)
        baseline = load_snapshot(path)

        if baseline is None:
            new_baselines += 1
            write_snapshot(path, result)
            print("  baseline created")
            continue

        target_findings = compare(result, baseline, config["ignore"])
        for finding in target_findings:
            print(finding.line())
        findings.extend(target_findings)

        if args.update_baseline or target_findings:
            # Accept the new reality so the next run compares against it and
            # the same drift isn't reported forever.
            write_snapshot(path, result)

        if not target_findings:
            print("  no drift")

    duration_ms = int((time.monotonic() - started) * 1000)
    total_targets = len(config["targets"])
    fatal = checked == 0 and total_targets > 0

    outcome = "failure" if fatal else "success"
    summary = (
        f"{len(findings)} drift finding(s) across {checked}/{total_targets} domain(s)"
        if not fatal
        else "no domain could be resolved — check network or nameserver config"
    )

    return {
        "agent": "dns-drift",
        "version": VERSION,
        "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "outcome": outcome,
        "summary": summary,
        "metrics": {
            "targets_configured": total_targets,
            "targets_checked": checked,
            "records_compared": records_compared,
            "drifts_detected": len(findings),
            "baselines_created": new_baselines,
            "resolution_errors": len(errors),
            "duration_ms": duration_ms,
        },
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect drift in public DNS records.")
    parser.add_argument("--config", default="targets.yml", help="target config file")
    parser.add_argument("--snapshots", default="snapshots", help="snapshot directory")
    parser.add_argument("--out", default="result.json", help="machine-readable result")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="accept the current DNS state as the new baseline",
    )
    parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="exit non-zero when drift is found (off by default — drift is a "
        "successful detection, not an agent failure)",
    )
    args = parser.parse_args(argv)

    try:
        result = run(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — a crash is a reportable failure
        result = {
            "agent": "dns-drift",
            "version": VERSION,
            "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "outcome": "failure",
            "summary": f"agent crashed: {type(exc).__name__}: {exc}",
            "metrics": {},
            "findings": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
        }

    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print("\n" + result["summary"])
    for finding in result["findings"]:
        print(f"  - {finding}")

    if summary_file := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(f"### dns-drift — {result['outcome']}\n\n{result['summary']}\n\n")
            for finding in result["findings"]:
                fh.write(f"- `{finding['domain']}` {finding['record_type']} — "
                         f"{finding['kind']}\n")

    if result["outcome"] == "failure":
        return 1
    if args.fail_on_drift and result["findings"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
