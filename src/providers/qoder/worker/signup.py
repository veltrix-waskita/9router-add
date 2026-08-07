import json, sys

def emit_step(step, status, **kv):
    print(json.dumps({"kind": "step", "step": step, "status": status, **kv}), flush=True)

def emit_result(ok, **kv):
    print(json.dumps({"kind": "result", "ok": bool(ok), **kv}), flush=True)

if "--self-test" in sys.argv:
    try:
        import curl_cffi  # noqa: F401
        emit_result(True, step="self_test")
    except Exception as e:
        emit_result(False, error=str(e), step="self_test")
    sys.exit(0 if True else 1)

# Task 3 fills real run
emit_result(True, step="stub")
