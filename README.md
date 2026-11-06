# ingest-cleanup

`ingest-cleanup` is a fail-closed command-line tool for removing source files
only after an ingestion journal proves a copy-and-preserve publication and a
fresh source/destination SHA-256 comparison succeeds. It is intended as the
separate, later cleanup boundary after a successful ingest—not as part of
publication itself.

## Requirements and installation

- Python 3.14 or newer.
- A configured ingestion tool that writes supported provenance reports.

Install from a checkout with your normal isolated Python workflow, for example:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Configuration

Copy `config.example.toml` to
`~/.config/ingest-cleanup/config.toml` (or pass `--config-file /path/to/config.toml`)
and replace every path with absolute paths for your own Incoming, library, and
tool-state locations. Roots must exist, must not be symlinks, and must not
overlap. Keep the real configuration out of version control.

## Safe workflow

```bash
ingest-cleanup config  # show the effective configured roots
ingest-cleanup status  # read-only provenance, existence, and size assessment
ingest-cleanup verify  # SHA-256 verification; saves a private 24-hour plan
ingest-cleanup show PLAN_ID
ingest-cleanup apply PLAN_ID
ingest-cleanup apply   # backwards-compatible one-shot verify/review/apply
```

`status` never declares a source deletion-ready. `verify` changes no Incoming
or library files; it writes an immutable, owner-only `verification-plan-v1`
under `$XDG_STATE_HOME/ingest-cleanup/plans/`. Plans expire after 24 hours and
are bound to the effective configuration, endpoint identities, hashes, sizes,
categories, and evidence identifiers. `apply PLAN_ID` fully rehashes the plan,
while bare `apply` retains the one-shot workflow.

Before deletion, `apply` rehashes the entire batch again, shows human-readable
and per-category totals, and requires `DELETE <count> VERIFIED SOURCES`. It
creates a crash-safe audit before deletion and atomically updates it after each
item under `$XDG_STATE_HOME/ingest-cleanup/reports/` (or
`~/.local/state/ingest-cleanup/reports/`).

The tool never treats its own audit reports as ingestion evidence. Missing,
ambiguous, changed, symlinked, hard-linked, or otherwise unsafe files are left
for review rather than deleted.

For video ingest, a completed COPY report can also identify a source that was
skipped because the canonical production item was SHA-256-identical. This is
provenance only: `status` remains non-destructive and `verify`/`apply` always
recompute both hashes before a source can become deletion-ready. User-skipped
or non-identical conflicts are never accepted as cleanup evidence.

JSONL v3 also supports mixed MOVE reports: only per-operation records whose
`source_lifecycle` is `preserved` are eligible, so moved sources remain excluded
while SHA-256-verified existing duplicates retain usable evidence. Legacy
video, music, and Kavita schemas remain readable. Unknown versions and
incomplete reports fail closed. Historical sources become eligible only after
replaying their authoritative producer; cleanup never guesses a destination.

Byte identity with production proves publication equality, not independent
backup coverage. Cleanup reports this limitation and does not infer backup
freshness from the production copy.

## Development

Run the synthetic test suite with:

```bash
pytest -q
```
