# Contributing to dns-drift

Thanks for looking. This is a deliberately small agent — one file, two dependencies — and the goal is to keep it that way.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python agent.py --config targets.yml
```

To test drift handling without waiting for real DNS to change, edit a value inside a file in `snapshots/` and run the agent again. It should report the difference and then rewrite the snapshot.

## Ground rules

- **No new dependencies** unless there's no reasonable alternative. `dnspython` and `PyYAML` are the budget.
- **Detection is not failure.** A run that finds drift exits `0` and reports `outcome: success`. Please don't change this — see the README section on outcome semantics.
- **One alert per change.** Snapshots are rewritten after a finding is reported. Repeat-alerting is a regression.
- **Keep `result.json` stable.** It's a public integration contract. Additive fields are fine; renaming or removing fields is not.
- Keep PRs focused on one thing, and describe what you tested.

## Good first issues

- `DS` / `DNSKEY` record support
- A webhook / Slack reporter behind a config flag
- Report DNSSEC validation status as a watched property
- Compare answers across multiple resolvers and flag disagreement (split-horizon / poisoning detection)

## Reporting a problem

Open an issue with your `targets.yml` (redacted as needed), the output of the run, and what you expected instead. If it's a false positive on a specific record type, the exact record text is the most useful thing you can include.
