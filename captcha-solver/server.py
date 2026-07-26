"""Uvicorn entrypoint: `python -m uvicorn server:app`.

Re-exports the FastAPI app from universal_solver so captcha-solver.js
can spawn with the expected `server:app` module path.
"""
from universal_solver import app  # noqa: F401
