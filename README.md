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
ingest-cleanup status --json
ingest-cleanup reconcile Comics  # advisory filename/size suggestions only
ingest-cleanup compatibility --json
ingest-cleanup verify  # SHA-256 verification; saves a private 24-hour plan
ingest-cleanup show PLAN_ID
ingest-cleanup apply PLAN_ID
ingest-cleanup apply   # backwards-compatible one-shot verify/review/apply
```

`status` never declares a source deletion-ready. `verify` changes no Incoming
or library files; it writes an immutable, owner-only `verification-plan-v1`
under `$XDG_STATE_HOME/ingest-cleanup/plans/`. Plans expire after 24 hours and
are bound to the effective configuration, endpoint identities, hashes, sizes,
categories, and evidence identifiers. `apply PLAN_ID` fully rehashes the saved
plan, while bare `apply` retains the one-shot workflow.

After typed confirmation, `apply` safely reuses the just-computed hashes only
when source and destination device, inode, size, mtime, ctime and link count are
unchanged, the exact producer record is still accepted, and any required Kavita
backup proof is still current. It rechecks endpoint identity again immediately
before unlink. This avoids an unnecessary third full read without carrying a
hash across a changed filesystem or evidence boundary. Library and Incoming
changes fail closed. The command shows human-readable per-category totals and
requires `DELETE <count> VERIFIED SOURCES`. It
creates a crash-safe audit before deletion and atomically updates it after each
item under `$XDG_STATE_HOME/ingest-cleanup/reports/` (or
`~/.local/state/ingest-cleanup/reports/`).

`reconcile` is a read-only historical aid. It lists every competing accepted
mapping together and can rank extension-compatible filename/size candidates,
but inferred entries are always labelled `PLAUSIBLE_ONLY`. They cannot become
accepted evidence, enter a verification plan, or authorize deletion.

The tool never treats its own audit reports as ingestion evidence. Missing,
ambiguous, changed, symlinked, hard-linked, or otherwise unsafe files are left
for review rather than deleted.

For video ingest, a completed COPY report can also identify a source that was
skipped because the canonical production item was SHA-256-identical. This is
provenance only: `status` remains non-destructive and `verify`/`apply` always
recompute both hashes before a source can become deletion-ready. User-skipped
or non-identical conflicts are never accepted as cleanup evidence.

Video JSONL v3 also supports mixed MOVE reports: only per-operation records whose
`source_lifecycle` is `preserved` are eligible, so moved sources remain excluded
while SHA-256-verified existing duplicates retain usable evidence. Legacy
Kavita publication v3 may also represent a partial producer run: only entries
with `item_state=complete` and `cleanup_eligible=true` are consumed. Failed,
blocked, and uncertain siblings provide no evidence but do not invalidate an
independently completed item. Known video JSONL v1-v3, music v1-v2 and Kavita
v1-v3 schemas remain readable only from explicitly configured local state roots.
New `video-ingest-publication-v4`, `music-ingest-publication-v3`, and
`kavita-ingest-publication-v4` reports identify producer version and a stable,
non-secret machine instance; cleanup refuses them on another machine. Unknown
versions and incomplete reports fail closed. Historical sources become eligible
only after replaying their authoritative producer; cleanup never guesses a
destination.

`--json` emits versioned result objects for status, verify, show, explain,
reconcile, provenance status, configuration, compatibility and apply. Progress
is sent separately to stderr. Interactive terminals use one updating line;
redirected logs receive rate-limited newline updates. Phase labels distinguish
scanning, hashing, backup verification and deletion revalidation. Use
`--verbose` to include individual paths.

Byte identity with production proves publication equality, not independent
backup coverage. Cleanup reports this limitation and does not infer backup
freshness from the production copy. Kavita publications therefore stop at
`BACKUP_REQUIRED` after fresh source/destination SHA-256 verification. They are
excluded from saved deletion plans and `apply`, including plans created by an
older version.

An exact-source independent proof can be recorded only while the backup object is
on a mounted filesystem whose UUID is explicitly verified:

```bash
ingest-cleanup backup-proof /path/to/Incoming/book.epub \
  --publication /path/to/library/book.epub \
  --backup-object /mounted/independent/backup/book.epub \
  --expected-uuid EXPECTED_FILESYSTEM_UUID
```

The backup object's SHA-256 must equal the Incoming source, while current source
and publication endpoint identities, publication hash and byte relationship are
bound separately. The backup mount is identified before the object is opened and
must not be the source filesystem. A backup of a metadata-rewritten or repaired
publication cannot prove preservation of different original bytes. Proof records
are private, integrity-bound, retained by timestamp, usable while the verified
backup disk is later offline, and expire after 14 days unless reverified. Missing,
wrong-UUID, stale, changed or unmounted evidence fails closed.
Run `ingest-cleanup verify --verbose` to revalidate eligibility and display the
proof-record path used for any deletion-ready source.

Producer-owned `kavita-ingest-supersession-v1` reports can mark an older accepted
publication mapping explicitly superseded while retaining its archive identity
and hash. Cleanup then uses the still-current canonical mapping instead of
guessing between two destinations. The archived object is rehashed during full
verification; supersession never counts as independent backup proof.

## Development

Run the synthetic test suite with:

```bash
pytest -q
```
