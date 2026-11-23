# Sentrix Phase 0.3 hardening patch

## Included
- Safer quarantine vault validation and rejection of symlink inputs/payloads.
- Rollback of quarantine moves when permission changes or database insertion fail.
- Exclusive restore destination creation (no overwrite).
- SHA-256 verification before restoration.
- Conditional database status transitions.
- `delete_pending` state so interrupted deletion can be retried/finalized.
- Guaranteed SQLite connection cleanup and rollback.
- Existing scan-history and quarantine API function names are preserved.

## Apply
From the project root, first make a backup:

```bash
cp core/quarantine.py core/quarantine.py.bak
cp core/database.py core/database.py.bak
```

Extract this ZIP into the project root, allowing it to replace:
- `core/quarantine.py`
- `core/database.py`

Then run:

```bash
python -m compileall core
pytest test_quarantine.py -v
pytest -v
```

## Important limitations
- The process lock coordinates operations only within one Python process. It is not a distributed lock across multiple Uvicorn workers/processes.
- Filesystem operations and SQLite cannot form one atomic transaction. A `delete_pending` record is intentionally recoverable; if final database update fails after payload deletion, retry the delete endpoint to finalize it.
- The current API has no authentication. Run Sentrix bound to loopback only:
  `uvicorn app.main:app --host 127.0.0.1 --port 8000`
- Do not expose the API to a LAN or public network until authentication, authorization, CSRF protections where applicable, and deployment controls are added.
- This is a hardening baseline, not a claim of protection against a privileged local attacker who can modify the process, vault, database, or parent directories concurrently.
