# Swan

Local security checks for wearable-assistant event traces, designed around Meta
Device Access Toolkit lifecycle risks. Reviews stale captures, permission changes,
device reconnects, approval drift/reuse and declared bystander consent.

```sh
python -m app.wearable_cli examples/wearable-safe.json
python -m app.wearable_cli trace.json --format sarif --output report.sarif
```

Python 3.10+. The trace auditor needs no dependencies, model, account or network.
`pip install .` also provides `swan-audit`. Exit codes: 0 = no error findings
(warnings may remain), 1 = policy violations, 2 = invalid input or I/O failure.

For the optional metadata-only local review screen, from this checkout:

```sh
python -m venv .venv
.venv/bin/pip install -e ".[review]"
.venv/bin/python -m uvicorn app.wearable_server:app --host 127.0.0.1 --port 8766
```

Open `/wearables/` on that local server. Earlier approval/OCR experiments remain in `app.main` (see `requirements.lock`). [Trace format and integration](docs/wearable-traces.md)
· [Security boundaries](SECURITY.md)

Supplied traces are metadata claims, not device attestation. Fixtures are synthetic.
Swan does not intercept Meta AI, control glasses, detect bystanders or certify an
integration as safe. Physical Meta-device execution remains unverified.

MIT for Swan code; bundled font retains its own license.
