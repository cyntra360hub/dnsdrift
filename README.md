# dns-drift

A small, self-hosted agent that watches your domains' public DNS records and tells you the moment something changes.

DNS changes are quiet and consequential. A dropped `MX` record kills mail. A rewritten `A` record is what a domain hijack looks like. An `NS` delegation you didn't authorise means someone else controls the zone. `dns-drift` keeps a committed baseline of what your records *should* be and reports every difference, on a schedule, for free.

## What it does

- Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` (and optionally `CAA`, `SRV`, `PTR`) for each configured domain
- Diffs the answer against a baseline snapshot stored in `snapshots/` and committed to the repo — so your DNS history is reviewable in `git log`
- Reports added and removed values per record type, plus domains that stop resolving entirely (and start again)
- Runs on GitHub Actions cron with no servers, no database, and no credentials
- Emits `result.json` with a portable outcome/metrics/findings shape for any monitoring platform

## Quick start

```bash
git clone https://github.com/<you>/dns-drift.git
cd dns-drift
pip install -r requirements.txt

# 1. list your domains
$EDITOR targets.yml

# 2. first run records the baseline
python agent.py

# 3. commit the baseline so future runs have something to compare against
git add snapshots && git commit -m "chore: initial DNS baselines" && git push
```

On GitHub, the workflow in `.github/workflows/dns-drift.yml` then runs every 6 hours and commits refreshed baselines itself. Nothing else to configure.

## Configuration

`targets.yml`:

```yaml
record_types: [A, AAAA, MX, NS, TXT]   # default for every target
timeout: 5.0
nameservers:
  - 1.1.1.1
  - 8.8.8.8

ignore:
  example.com: [TXT]                   # never report drift for these

targets:
  - domain: example.com                # uses the defaults above
  - domain: mail.example.com
    record_types: [A, MX, CAA]         # per-target override
```

| Key | Meaning |
| --- | --- |
| `record_types` | Types to watch. Global default, overridable per target. |
| `timeout` | Per-query timeout in seconds. |
| `nameservers` | Resolvers to query. Use your own if you want split-horizon views. |
| `ignore` | Domain → record types that are noisy and should never be reported. Use `"*"` as the domain for a global ignore. |

## CLI

```
python agent.py [--config targets.yml] [--snapshots snapshots] [--out result.json]
                [--update-baseline] [--fail-on-drift]
```

- `--update-baseline` — accept the current DNS state as correct for every target. Run this after an intentional DNS change.
- `--fail-on-drift` — exit `2` when drift is found. Off by default; see below.

## Exit codes and outcome semantics

| Code | Meaning |
| --- | --- |
| `0` | Run completed. Drift may or may not have been found. |
| `1` | Run failed — bad config, no domain resolvable, or an unhandled crash. |
| `2` | Drift found, and `--fail-on-drift` was passed. |

**Finding drift is a success, not a failure.** The agent's job is detection; a run that detects a hijacked `NS` record has worked perfectly. Only a run that could not do its job reports `failure`. This matters if you pipe `result.json` into a reliability tracker — conflating "found a problem" with "the agent broke" makes the agent's own record meaningless.

Baselines self-heal: once drift is reported, the new state is written to the snapshot, so you get one alert per change rather than the same alert forever. The diff stays in git.

## Reporting to a monitoring platform

`result.json` is the integration surface:

```json
{
  "agent": "dns-drift",
  "outcome": "success",
  "summary": "1 drift finding(s) across 2/2 domain(s)",
  "metrics": {
    "targets_configured": 2,
    "targets_checked": 2,
    "records_compared": 14,
    "drifts_detected": 1,
    "baselines_created": 0,
    "resolution_errors": 0,
    "duration_ms": 307
  },
  "findings": [
    {
      "domain": "iana.org",
      "record_type": "A",
      "kind": "drift",
      "added": ["192.0.43.8"],
      "removed": ["198.51.100.1"]
    }
  ],
  "errors": []
}
```

The workflow's **Report run** step is a marked placeholder. Drop in whatever your platform's connect flow gives you — most issue a ready-made workflow block plus the secret names to add. Findings are also written to the GitHub Actions run summary, so a failed check is readable without leaving the run page.

## Privacy

Only public DNS is queried, and only the domains you list. No credentials, no inbound network access, no telemetry beyond the reporting step you configure yourself.

## Contributing

Small, focused PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good first additions: `DS`/`DNSKEY` support, a Slack or webhook reporter, DNSSEC validation status as a watched property.

## Licence

MIT — see [LICENSE](LICENSE).
