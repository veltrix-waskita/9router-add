# Local Turnstile captcha-solver (:8877)

Vendored from x-farm `local-solver` (universal_solver.py). FastAPI + Camoufox.

## Contract

- `POST /solve` body: `{ "type": "turnstile", "url": "...", "sitekey": "..." }`
- Response: `{ "solved": true, "token": "..." }` (or `solution.token`)
- Health: `GET /health`

## Setup

```bash
cd captcha-solver
python3 -m venv venv   # or .venv
venv/bin/pip install -r requirements.txt
# camoufox may need: venv/bin/camoufox fetch
```

## Run (manual)

```bash
# preferred (matches captcha-solver.js)
venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port 8877

# or
SOLVER_ALLOW_PRIVATE=1 venv/bin/python universal_solver.py
```

`node runner.js` auto-starts this if port 8877 is free, and stops it on exit
when the runner owns the process.
