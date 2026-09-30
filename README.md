# ingest-cleanup

`ingest-cleanup` removes a source file only after an ingestion journal proves a COPY/PRESERVE publication and a fresh source/destination SHA-256 comparison succeeds.

Run `ingest-cleanup config` to inspect configuration, `ingest-cleanup verify` to make a read-only assessment, and `ingest-cleanup apply` for the separately confirmed deletion workflow.

The tool never treats its own audit reports as ingestion evidence.
