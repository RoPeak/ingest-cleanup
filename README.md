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
ingest-cleanup verify  # read-only SHA-256 verification; can take time
ingest-cleanup apply   # lists deletion candidates and requires exact confirmation
```

`status` never declares a source deletion-ready. `verify` changes no files.
`apply` reuses the full verification result, shows the proposed count and size,
and requires `DELETE VERIFIED SOURCES` before deletion. It writes an audit
report under `$XDG_STATE_HOME/ingest-cleanup/reports/` (or
`~/.local/state/ingest-cleanup/reports/`).

The tool never treats its own audit reports as ingestion evidence. Missing,
ambiguous, changed, symlinked, hard-linked, or otherwise unsafe files are left
for review rather than deleted.

## Development

Run the synthetic test suite with:

```bash
pytest -q
```
