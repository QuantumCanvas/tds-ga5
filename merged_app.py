"""
Merged app: all 4 non-MCP exam endpoints in a single Flask process.

Routes:
  POST /charge           -> proration
  POST /guardrail/check   -> pre-tool-call guardrail
  POST /scan             -> skill safety scanner
  POST /loopguard/check   -> run budget & loop guard
  GET  /                 -> health check

Give the grader these full URLs, e.g.:
  https://your-host/charge
  https://your-host/guardrail/check
  https://your-host/scan
  https://your-host/loopguard/check
"""
from flask import Flask, request, jsonify

# Reuse the exact, already-tested logic from each standalone module.
from proration_app import compute_charge
from guardrail_app import check_bash, check_write_file, check_http_request
from scanner_app import scan_skill
from loopguard_app import evaluate as loopguard_evaluate

app = Flask(__name__)


# ---------------------------------------------------------------------------
# /charge - proration
# ---------------------------------------------------------------------------
@app.route("/charge", methods=["POST"])
def charge():
    try:
        body = request.get_json(force=True, silent=False)
        old_price = float(body["old_price"])
        new_price = float(body["new_price"])
        days_remaining = float(body["days_remaining"])
        days_in_actual_month = float(body["days_in_actual_month"])
        spec = body["spec"]

        result = compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec)
        return jsonify({"charge": round(result, 6)})
    except (KeyError, TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "internal error", "detail": str(e)}), 500


# ---------------------------------------------------------------------------
# /guardrail/check - pre-tool-call guardrail
# ---------------------------------------------------------------------------
@app.route("/guardrail/check", methods=["POST"])
def guardrail_check():
    try:
        body = request.get_json(force=True, silent=False)
        tool = body.get("tool")

        if tool == "bash":
            decision, reason = check_bash(body.get("command", ""))
        elif tool == "write_file":
            decision, reason = check_write_file(body.get("path", ""))
        elif tool == "http_request":
            decision, reason = check_http_request(body.get("url", ""))
        else:
            decision, reason = "block", f"Unknown tool type: {tool!r}"

        return jsonify({"decision": decision, "reason": reason})
    except Exception as e:
        return jsonify({"decision": "block", "reason": f"Could not evaluate request safely: {e}"}), 200


# ---------------------------------------------------------------------------
# /scan - skill safety scanner
# ---------------------------------------------------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    try:
        body = request.get_json(force=True, silent=False)
        categories = scan_skill(body["skill"])
        return jsonify({"categories": categories})
    except Exception as e:
        return jsonify({"categories": [], "error": str(e)}), 200


# ---------------------------------------------------------------------------
# /loopguard/check - run budget & loop guard
# ---------------------------------------------------------------------------
@app.route("/loopguard/check", methods=["POST"])
def loopguard_check():
    try:
        body = request.get_json(force=True, silent=False)
        budget_tokens = int(body["budget_tokens"])
        steps = body.get("steps", [])
        decision, reason = loopguard_evaluate(budget_tokens, steps)
        return jsonify({"decision": decision, "reason": reason})
    except Exception as e:
        return jsonify({"decision": "halt", "reason": f"Could not evaluate run state safely: {e}"}), 200


# ---------------------------------------------------------------------------
# health check
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "routes": ["/charge", "/guardrail/check", "/scan", "/loopguard/check"]})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
