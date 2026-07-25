"""
Combined service exposing two independent endpoints:

  POST /prorate  -> proration calculator (spec v1 legacy / v2 corrected)
  POST /check    -> deterministic pre-tool-call guardrail policy engine

Kept in one app.py so both can be deployed as a single Render web service
from the same repo.
"""

import base64
import os
import re
from urllib.parse import urlsplit

from flask import Flask, request, jsonify

app = Flask(__name__)


# =====================================================================
# /prorate — proration calculator
# =====================================================================

VALID_SPECS = {"v1", "v2"}


def compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec):
    price_delta = new_price - old_price

    if spec == "v1":
        # Legacy rule: fixed 30-day divisor, no matter the real month length.
        divisor = 30
    elif spec == "v2":
        # Corrected rule: use the actual number of days in the billing month.
        divisor = days_in_actual_month
    else:
        raise ValueError(f"Unknown spec '{spec}', expected one of {sorted(VALID_SPECS)}")

    if divisor == 0:
        raise ValueError("divisor (days in month) cannot be zero")

    return price_delta * (days_remaining / divisor)


@app.route("/prorate", methods=["POST"])
def prorate():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    required_fields = ["old_price", "new_price", "days_remaining", "days_in_actual_month", "spec"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        return jsonify({"error": f"Missing field(s): {', '.join(missing)}"}), 400

    spec = body["spec"]
    if spec not in VALID_SPECS:
        return jsonify({"error": f"spec must be one of {sorted(VALID_SPECS)}"}), 400

    try:
        old_price = float(body["old_price"])
        new_price = float(body["new_price"])
        days_remaining = float(body["days_remaining"])
        days_in_actual_month = float(body["days_in_actual_month"])
    except (TypeError, ValueError):
        return jsonify({"error": "old_price, new_price, days_remaining, days_in_actual_month must be numbers"}), 400

    try:
        charge = compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"charge": charge})


# =====================================================================
# /check — agent guardrail hook
# =====================================================================

AGENT_HOME = "/home/agent"
AGENT_WORKDIR = "/home/agent/workspace"
PROTECTED_FILE = "/home/agent/credentials.env"

# Both spellings are accepted as the allowed write root, since the spec
# names it "/workspace/output/" while the working directory is
# "/home/agent/workspace" -- we treat either as the intended sandbox.
ALLOWED_WRITE_ROOTS = [
    "/home/agent/workspace/output",
    "/workspace/output",
]

ALLOWED_HOSTS = {"huggingface.co", "raw.githubusercontent.com"}

PRIV_ESC_RE = re.compile(r"(?<![\w-])(sudo|doas|su)(?![\w-])")

# Matches a base64-looking blob of reasonable length (avoids false
# positives on short words).
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def try_base64_decode_all(text):
    """Find base64-looking substrings in text and return their decoded
    forms (best-effort; ignores anything that fails to decode as utf-8)."""
    decoded_chunks = []
    for match in BASE64_BLOB_RE.finditer(text):
        candidate = match.group(0)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
            decoded = raw.decode("utf-8", errors="strict")
            if decoded.isprintable() or "\n" in decoded:
                decoded_chunks.append(decoded)
        except Exception:
            continue
    return decoded_chunks


def normalize_path_token(token, cwd):
    """Resolve a raw path-like token (possibly using ~, $HOME, or relative
    traversal) against cwd, returning a normalized absolute path."""
    t = token.strip()
    if t.startswith("~"):
        t = AGENT_HOME + t[1:]
    t = t.replace("$HOME", AGENT_HOME).replace("${HOME}", AGENT_HOME)
    if not t.startswith("/"):
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


CREDENTIALS_TOKEN_RE = re.compile(
    r"(?:~|\$\{?HOME\}?|(?:\.\./)+|\./|/[\w./-]*|[\w.-]*)?"
    r"credentials\.env"
)


def references_protected_file(raw_command):
    """Return True if the (possibly obfuscated / base64-wrapped) command
    resolves to reading the protected credentials file."""
    texts_to_scan = [raw_command]
    texts_to_scan.extend(try_base64_decode_all(raw_command))

    for text in texts_to_scan:
        for match in CREDENTIALS_TOKEN_RE.finditer(text):
            token = match.group(0)
            resolved = normalize_path_token(token, AGENT_WORKDIR)
            if resolved == PROTECTED_FILE:
                return True
        if "credentials.env" in text:
            return True
    return False


def check_bash(command):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or invalid command."

    if references_protected_file(command):
        return "block", "This command attempts to read the protected credentials file, which is never permitted."

    if PRIV_ESC_RE.search(command):
        return "block", "Privilege escalation (sudo/su/doas) is not permitted for this agent."

    return "allow", "Command does not touch the protected secret file or attempt privilege escalation."


def check_write_file(path):
    if not isinstance(path, str) or not path.strip():
        return "block", "Empty or invalid path."

    resolved = normalize_path_token(path, AGENT_WORKDIR)

    for root in ALLOWED_WRITE_ROOTS:
        root_norm = os.path.normpath(root)
        if resolved == root_norm or resolved.startswith(root_norm + os.sep):
            return "allow", "Write target is inside the allowed output directory."

    return "block", "Writes are only permitted inside the designated output directory."


def check_http_request(url):
    if not isinstance(url, str) or not url.strip():
        return "block", "Empty or invalid URL."

    try:
        parts = urlsplit(url)
    except Exception:
        return "block", "URL could not be parsed."

    if parts.scheme not in ("http", "https"):
        return "block", "Only http/https requests are permitted."

    hostname = (parts.hostname or "").lower().rstrip(".")

    if hostname in ALLOWED_HOSTS:
        return "allow", f"Host '{hostname}' is on the exact allowlist."

    return "block", f"Host '{hostname}' is not on the exact allowlist (only huggingface.co and raw.githubusercontent.com are permitted)."


@app.route("/check", methods=["POST"])
def check():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"decision": "block", "reason": "Request body must be a JSON object."})

    tool = body.get("tool")

    if tool == "bash":
        decision, reason = check_bash(body.get("command"))
    elif tool == "write_file":
        decision, reason = check_write_file(body.get("path"))
    elif tool == "http_request":
        decision, reason = check_http_request(body.get("url"))
    else:
        decision, reason = "block", f"Unknown tool '{tool}'."

    return jsonify({"decision": decision, "reason": reason})


# =====================================================================
# Shared health check
# =====================================================================

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
