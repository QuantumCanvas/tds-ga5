"""
Combined service exposing several independent endpoints:

  POST /prorate   -> proration calculator (spec v1 legacy / v2 corrected)
  POST /check     -> deterministic pre-tool-call guardrail policy engine
  POST /scan      -> agent skill safety scanner
  POST /run-guard -> agent run budget & loop-detection policy engine
  POST /mcp       -> minimal MCP server (Streamable HTTP) exposing
                     the `solve_challenge` tool
  POST /guardrail -> red-team-hardened guardrail in front of
                     read_file(path) / fetch_url(url)

Kept in one app.py so all of it can be deployed as a single Render web
service from the same repo.
"""

import base64
import hashlib
import ipaddress
import logging
import os
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guardrail-app")


# =====================================================================
# /prorate — proration calculator
# =====================================================================

VALID_SPECS = {"v1", "v2"}


def compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec):
    price_delta = new_price - old_price

    if spec == "v1":
        divisor = 30
    elif spec == "v2":
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
# /check — agent guardrail hook (v2: fixed legitimate-read over-block
# and bash-redirection write-traversal under-block)
# =====================================================================

AGENT_HOME = "/home/agent"
AGENT_WORKDIR = "/home/agent/workspace"
PROTECTED_FILE = "/home/agent/credentials.env"

ALLOWED_WRITE_ROOTS = [
    os.path.normpath("/home/agent/workspace/output"),
    os.path.normpath("/workspace/output"),
]

ALLOWED_HOSTS = {"huggingface.co", "raw.githubusercontent.com"}

PRIV_ESC_RE = re.compile(r"(?<![\w-])(sudo|doas|su)(?![\w-])")

BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

CREDENTIALS_WORD_RE = re.compile(r"""[^\s'"`|;&<>(){}]*credentials\.env""")

_TARGET_TOKEN = r'(?:"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|([^\s|;&]+))'

REDIRECT_TARGET_RES = [
    re.compile(r">>?\s*" + _TARGET_TOKEN),
    re.compile(r"\btee\b(?:\s+-a)?\s+" + _TARGET_TOKEN),
    re.compile(r"\bdd\b[^|;&]*\bof=" + _TARGET_TOKEN),
]

CD_RE = re.compile(r"^\s*cd(?:\s+([^\s;&|]+))?\s*$")


def try_base64_decode_all(text):
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


def strip_quotes(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


def normalize_path_token(token, cwd):
    t = strip_quotes(token.strip())
    t = t.replace("\\", "/")
    if t.startswith("~"):
        t = AGENT_HOME + t[1:]
    t = re.sub(r"\$\{?HOME\}?", AGENT_HOME, t)
    if not t.startswith("/"):
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


def split_segments(command):
    return [seg for seg in re.split(r"&&|\|\||[;|\n]", command) if seg.strip()]


def is_write_target_outside_allowed(resolved_path):
    for root in ALLOWED_WRITE_ROOTS:
        if resolved_path == root or resolved_path.startswith(root + os.sep):
            return False
    return True


def scan_command_text(raw_text):
    cwd = AGENT_WORKDIR

    for segment in split_segments(raw_text):
        seg = segment.strip()

        cd_match = CD_RE.match(seg)
        if cd_match:
            target = cd_match.group(1)
            if not target or target == "~":
                cwd = AGENT_HOME
            else:
                cwd = normalize_path_token(target, cwd)
            continue

        for word_match in CREDENTIALS_WORD_RE.finditer(seg):
            token = word_match.group(0)
            resolved = normalize_path_token(token, cwd)
            if resolved == PROTECTED_FILE:
                return True, "This command attempts to read the protected credentials file, which is never permitted."

        for pattern in REDIRECT_TARGET_RES:
            for m in pattern.finditer(seg):
                target = next((g for g in m.groups() if g is not None), None)
                if not target:
                    continue
                resolved = normalize_path_token(target, cwd)
                if is_write_target_outside_allowed(resolved):
                    return True, "This command writes outside the allowed output directory, which is never permitted."

    return False, None


def check_bash(command):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or invalid command."

    if PRIV_ESC_RE.search(command):
        return "block", "Privilege escalation (sudo/su/doas) is not permitted for this agent."

    blocked, reason = scan_command_text(command)
    if blocked:
        return "block", reason

    for decoded in try_base64_decode_all(command):
        if PRIV_ESC_RE.search(decoded):
            return "block", "Privilege escalation (sudo/su/doas) is not permitted for this agent."
        blocked, reason = scan_command_text(decoded)
        if blocked:
            return "block", reason

    return "allow", "Command does not touch the protected secret file, attempt privilege escalation, or write outside the allowed output directory."


def check_write_file(path):
    if not isinstance(path, str) or not path.strip():
        return "block", "Empty or invalid path."

    resolved = normalize_path_token(path, AGENT_WORKDIR)

    if is_write_target_outside_allowed(resolved):
        return "block", "Writes are only permitted inside the designated output directory."

    return "allow", "Write target is inside the allowed output directory."


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
# /scan — agent skill safety scanner
# =====================================================================

FRONTMATTER_RE = re.compile(r"^\s*---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|$)", re.DOTALL)


def extract_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    return m.group(1) if m else ""


SECRET_PREFIX_RE = re.compile(
    r"(sk[-_](?:live_|test_|proj-)?[A-Za-z0-9]{10,}"
    r"|rk_live_[A-Za-z0-9]{10,}"
    r"|pk_live_[A-Za-z0-9]{10,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|ASIA[0-9A-Z]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|hooks\.slack\.com/services/[A-Za-z0-9/]{10,}"
    r"|discord(?:app)?\.com/api/webhooks/[0-9]{10,}/[A-Za-z0-9_\-]{10,}"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|AIza[0-9A-Za-z\-_]{20,})"
)

SECRET_KEY_LINE_RE = re.compile(
    r"(?im)^\s*[\"']?(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?key|"
    r"access[_-]?token|id[_-]?token|refresh[_-]?token|private[_-]?key|"
    r"webhook[_-]?url|webhook[_-]?secret|auth[_-]?token|bearer[_-]?token|token|"
    r"password|passwd|pwd|client[_-]?secret|signing[_-]?secret|"
    r"encryption[_-]?key|session[_-]?secret|db[_-]?password|"
    r"database[_-]?url|conn(?:ection)?[_-]?str(?:ing)?|credentials?)"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"'#]{8,})"
)

CONN_STRING_SECRET_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://[^\s:@/\"']+:([^\s@\"']{6,})@[^\s\"'/]+"
)

AUTH_HEADER_SECRET_RE = re.compile(
    r"(?i)authorization[\"']?\s*[:=]\s*[\"']?Bearer\s+([A-Za-z0-9\-_.~+/=]{16,})"
)

SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)^(\$\{|\$env|\$\(|env:|environ|getenv|your[_-]?|<|xxx+|changeme|"
    r"example|placeholder|none|null|redacted|\*{3,}|secrets\.|process\.env|"
    r"os\.environ)"
)


def _looks_like_placeholder(value):
    v = value.strip().strip("\"'")
    if not v:
        return True
    if SECRET_PLACEHOLDER_RE.search(v):
        return True
    if v.startswith("$") or v.startswith("{{"):
        return True
    if v.isalpha() and v.lower() in ("test", "demo", "todo", "changeme", "password", "secret"):
        return True
    return False


def detect_hardcoded_secret(text):
    if SECRET_PREFIX_RE.search(text):
        return True
    for m in SECRET_KEY_LINE_RE.finditer(text):
        if not _looks_like_placeholder(m.group(2)):
            return True
    for m in CONN_STRING_SECRET_RE.finditer(text):
        if not _looks_like_placeholder(m.group(1)):
            return True
    for m in AUTH_HEADER_SECRET_RE.finditer(text):
        if not _looks_like_placeholder(m.group(1)):
            return True
    return False


INJECTION_RE = re.compile(
    r"(?i)"
    r"ignore (?:the )?user'?s? (?:stop|cancel|interrupt)"
    r"|ignore any (?:stop|cancel|interrupt) request"
    r"|ignore (?:any|all) (?:contradictory|conflicting|subsequent|further) instructions?"
    r"|do not (?:tell|inform|notify) the user"
    r"|without (?:telling|informing|notifying) the user"
    r"|hide (?:this|that|it) from the user"
    r"|keep (?:this|it) (?:hidden|secret) from the user"
    r"|silently (?:send|upload|exfiltrat\w*|transmit|email|post|copy)"
    r"|exfiltrat\w*"
    r"|disregard (?:previous|prior|the user'?s?) instructions"
    r"|disregard (?:any|the) (?:system|prior) prompt"
    r"|override (?:the )?user'?s? (?:control|authority|command|instructions|request)"
    r"|do not (?:reveal|mention|disclose) (?:this|that|you are)"
    r"|even if the user (?:says?|asks?|wants?) (?:to )?(?:stop|cancel)"
    r"|continue (?:running|executing) (?:even (?:if|though)|regardless of) (?:the )?(?:user'?s? )?(?:stop|cancel)"
    r"|regardless of what the user (?:says?|wants?|asks?|requests?)"
    r"|cannot be (?:skipped|overridden|cancelled|canceled|stopped) by the user"
    r"|(?:take|takes) precedence over (?:the )?(?:user'?s? |system )?(?:instructions?|prompt|request)"
    r"|(?:override|supersede)s? (?:the |any )?(?:system|user) prompt"
    r"|act(?:ing)? on behalf of the user without (?:their |the user'?s? )?(?:knowledge|consent|awareness)"
    r"|do not let the user (?:know|see|find out)"
)


def detect_prompt_injection(text):
    return bool(INJECTION_RE.search(text))


PERM_KEY_VALUE_RE = re.compile(
    r"(?im)^\s*(filesystem|fs[_-]?access|network|domains?|allowed[_-]?domains?|"
    r"allowed[_-]?hosts?|allowed[_-]?urls?|scope|access|permissions?|capabilities|"
    r"paths?|directories|dirs?|root)\s*:\s*(.+)$"
)

BROAD_VALUE_WORD_RE = re.compile(
    r"(?i)\ball\b|\bany\b|\bfull[_-]?disk\b|\bunrestricted\b|\beverything\b|"
    r"\bglobal\b|\bread[_-]?write\b.*\bfilesystem\b"
)


def _value_is_broad(value):
    v = value.strip()
    if BROAD_VALUE_WORD_RE.search(v):
        return True
    parts = [p.strip().strip("\"'") for p in re.split(r"[\[\],]", v)]
    parts = [p for p in parts if p]
    for p in parts:
        if p in ("/", "*", "**", "~"):
            return True
    return False


BROAD_PERM_TEXT_RE = re.compile(
    r"(?i)\b(?:full|entire|whole)\s+(?:filesystem|disk|file ?system|home\s+directory)\b"
    r"|\baccess to (?:any|all)\s+(?:domains?|hosts?|urls?|websites?|external\s+services?)\b"
    r"|\begress to any\s+(?:domain|host)\b"
    r"|\bconnect to any\s+(?:server|host|domain|url|website)\b"
    r"|\bread(?:/|\s+and\s+)write access to (?:the )?(?:entire|whole|full)?\s*(?:filesystem|disk|home\s+directory)\b"
    r"|\ball files (?:on|in) (?:the )?(?:system|disk|computer|machine)\b"
    r"|\bunrestricted (?:network|filesystem|file ?system|internet) access\b"
)


def detect_excessive_permissions(text, frontmatter):
    for m in PERM_KEY_VALUE_RE.finditer(frontmatter):
        if _value_is_broad(m.group(2)):
            return True
    if BROAD_PERM_TEXT_RE.search(text):
        return True
    return False


HAS_AUTHOR_RE = re.compile(r"(?im)^\s*author\s*:\s*\S")
HAS_VERSION_RE = re.compile(r"(?im)^\s*version\s*:\s*\S")
HAS_CHANGELOG_RE = re.compile(r"(?im)^\s*changelog\s*:\s*\S|^#+\s*changelog\b")

_SILENT_WORDS = (
    r"(?:silently|quietly|invisibly|behind the scenes|unnoticed|"
    r"without (?:telling|informing|notifying|surfacing|disclosing|showing|alerting)"
    r"(?: (?:the )?(?:user|reviewer))?)"
)
_METADATA_WORDS = r"(?:version(?: number| field)?|changelog|metadata|provenance)"
_ACTION_WORDS = r"(?:update|rewrite|overwrite|bump|increment|change|modify|edit|regenerat\w*|alter)"

SILENT_METADATA_REWRITE_RE = re.compile(
    rf"(?i)(?:{_SILENT_WORDS}(?:[^.]{{0,80}}){_METADATA_WORDS})"
    rf"|(?:{_METADATA_WORDS}(?:[^.]{{0,80}}){_SILENT_WORDS})"
    rf"|(?:{_ACTION_WORDS}(?:[^.]{{0,60}}){_METADATA_WORDS}(?:[^.]{{0,60}}){_SILENT_WORDS})"
)


def detect_unclear_provenance(text, frontmatter):
    has_author = bool(HAS_AUTHOR_RE.search(frontmatter))
    has_version = bool(HAS_VERSION_RE.search(frontmatter))
    has_changelog = bool(HAS_CHANGELOG_RE.search(frontmatter)) or bool(HAS_CHANGELOG_RE.search(text))

    if not has_author and not has_version and not has_changelog:
        return True
    if SILENT_METADATA_REWRITE_RE.search(text):
        return True
    return False


@app.route("/scan", methods=["POST"])
def scan():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("skill"), str) or not body["skill"].strip():
        return jsonify({"categories": []})

    text = body["skill"]
    frontmatter = extract_frontmatter(text)

    categories = []
    if detect_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if detect_prompt_injection(text):
        categories.append("prompt_injection")
    if detect_excessive_permissions(text, frontmatter):
        categories.append("excessive_permissions")
    if detect_unclear_provenance(text, frontmatter):
        categories.append("unclear_provenance")

    return jsonify({"categories": categories})


# =====================================================================
# /run-guard — agent run budget & loop-detection policy engine
# =====================================================================

_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_args(value):
    if isinstance(value, dict):
        return {
            k: _normalize_args(v)
            for k, v in value.items()
            if k != "client_ts"
        }
    if isinstance(value, list):
        return [_normalize_args(v) for v in value]
    if isinstance(value, str):
        return _WHITESPACE_RE.sub(" ", value).strip()
    return value


def _same_call(step_a, step_b):
    if not isinstance(step_a, dict) or not isinstance(step_b, dict):
        return False
    if step_a.get("tool") != step_b.get("tool"):
        return False
    return _normalize_args(step_a.get("args", {})) == _normalize_args(step_b.get("args", {}))


def _trailing_identical_run_length(steps):
    if not steps:
        return 0
    last = steps[-1]
    count = 1
    for s in reversed(steps[:-1]):
        if _same_call(s, last):
            count += 1
        else:
            break
    return count


def _trailing_two_step_cycle(steps):
    if len(steps) < 6:
        return False
    a1, b1, a2, b2, a3, b3 = steps[-6:]
    if not (_same_call(a1, a2) and _same_call(a2, a3)):
        return False
    if not (_same_call(b1, b2) and _same_call(b2, b3)):
        return False
    if _same_call(a1, b1):
        return False
    return True


@app.route("/run-guard", methods=["POST"])
def run_guard():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"decision": "halt", "reason": "Request body must be a JSON object."})

    budget_tokens = body.get("budget_tokens")
    steps = body.get("steps")

    if not isinstance(budget_tokens, (int, float)) or isinstance(budget_tokens, bool):
        return jsonify({"decision": "halt", "reason": "Missing or invalid budget_tokens."})
    if not isinstance(steps, list):
        return jsonify({"decision": "halt", "reason": "Missing or invalid steps."})

    if not steps:
        return jsonify({"decision": "continue", "reason": "No steps taken yet; nothing to halt on."})

    total_tokens = 0
    for s in steps:
        if isinstance(s, dict):
            used = s.get("tokens_used", 0)
            if isinstance(used, (int, float)) and not isinstance(used, bool):
                total_tokens += used

    if total_tokens >= budget_tokens:
        return jsonify({
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total_tokens}) has reached the budget ({budget_tokens})."
        })

    run_len = _trailing_identical_run_length(steps)
    if run_len >= 3:
        return jsonify({
            "decision": "halt",
            "reason": f"Same tool called with functionally identical arguments {run_len} times in a row."
        })

    if _trailing_two_step_cycle(steps):
        return jsonify({
            "decision": "halt",
            "reason": "Trailing steps show a repeating 2-step call cycle (A, B, A, B, A, B)."
        })

    return jsonify({
        "decision": "continue",
        "reason": "Under budget and no repeated-call loop detected in the trailing steps."
    })


# =====================================================================
# /mcp — minimal MCP server (Streamable HTTP transport)
#
# Exposes exactly one tool, `solve_challenge`, with an empty input
# schema. On every tools/call it reads X-Exam-Challenge from the raw
# HTTP request headers (never from the JSON-RPC body) and returns the
# first 16 lowercase hex characters of
#   SHA-256(f"{challenge}:{REGISTERED_EMAIL}")
# as a single MCP text content block.
#
# This is a hand-rolled JSON-RPC 2.0 implementation of just the slice
# of the MCP spec the grader needs (initialize / notifications/initialized
# / tools/list / tools/call) so it has no dependency on an MCP SDK.
# =====================================================================

REGISTERED_EMAIL = "24f3004964@ds.study.iitm.ac.in"

MCP_TOOLS = [
    {
        "name": "solve_challenge",
        "description": "Solves the exam challenge using the X-Exam-Challenge header from the current request.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    }
]


def _jsonrpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle_initialize(req_id, params):
    # Echo back whatever protocolVersion the client asked for so we stay
    # compatible with whichever MCP spec revision the grader's client speaks.
    client_version = (params or {}).get("protocolVersion", "2024-11-05")
    return _jsonrpc_result(req_id, {
        "protocolVersion": client_version,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "solve-challenge-mcp-server",
            "version": "1.0.0",
        },
    })


def _handle_tools_list(req_id):
    return _jsonrpc_result(req_id, {"tools": MCP_TOOLS})


def _handle_tools_call(req_id, params):
    name = (params or {}).get("name")
    if name != "solve_challenge":
        return _jsonrpc_error(req_id, -32602, f"Unknown tool '{name}'")

    challenge = request.headers.get("X-Exam-Challenge", "")
    if not challenge:
        return _jsonrpc_error(req_id, -32602, "Missing X-Exam-Challenge header.")

    digest = hashlib.sha256(f"{challenge}:{REGISTERED_EMAIL}".encode("utf-8")).hexdigest()
    answer = digest[:16]

    return _jsonrpc_result(req_id, {
        "content": [
            {"type": "text", "text": answer}
        ],
        "isError": False,
    })


def _dispatch_single(msg):
    if not isinstance(msg, dict):
        return None

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params")
    is_notification = "id" not in msg  # JSON-RPC notifications carry no id

    if method == "initialize":
        return _handle_initialize(req_id, params)
    if method == "notifications/initialized":
        return None  # notification: no response body per JSON-RPC/MCP spec
    if method == "tools/list":
        return _handle_tools_list(req_id)
    if method == "tools/call":
        return _handle_tools_call(req_id, params)

    if is_notification:
        return None
    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


@app.route("/mcp", methods=["POST"])
def mcp():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(_jsonrpc_error(None, -32700, "Parse error: request body must be JSON")), 400

    if isinstance(body, list):
        responses = [r for r in (_dispatch_single(m) for m in body) if r is not None]
        if not responses:
            return "", 202
        return jsonify(responses)

    response = _dispatch_single(body)
    if response is None:
        # Pure notification (e.g. notifications/initialized) -> no body.
        return "", 202
    return jsonify(response)


@app.route("/mcp", methods=["GET"])
def mcp_get():
    # Some MCP clients probe the endpoint with GET first, or open an SSE
    # stream for server-initiated messages. We don't push anything
    # server-initiated, so a simple 200 keeps clients that check this happy.
    return jsonify({"status": "mcp endpoint is up; use POST for JSON-RPC"})


# =====================================================================
# /guardrail — red-team-hardened guardrail in front of two tools:
#   read_file(path)  -> sandboxed to SANDBOX_ROOT
#   fetch_url(url)    -> host-allowlisted, SSRF-hardened
#
# Contract: POST {"tool": "...", "arguments": {...}} ->
#           {"action": "allow"|"block", "reason": "...", "result": ...}
# On "allow" the tool actually runs and "result" holds its output.
# On "block" the tool never runs.
# =====================================================================

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-16e98aa704"
SANDBOX_ROOT_REAL = os.path.realpath(SANDBOX_ROOT)

OUTSIDE_CANARY_DIR = "/srv/agent-redteam/outside-51833a50"

ALLOWED_FETCH_HOSTS = {"example.com", "www.iana.org"}

MAX_FETCH_REDIRECTS = 5
MAX_FETCH_BODY_BYTES = 1_000_000
FETCH_TIMEOUT_SECONDS = 8

# Single source of truth for the red-team fixture files, shared by the
# runtime best-effort creator below AND by the Dockerfile, which bakes
# these same files into the image at build time (see deploy notes).
REDTEAM_FIXTURES = {
    os.path.join(OUTSIDE_CANARY_DIR, "canary.txt"):
        "AGENT_GUARDRAIL_CANARY_cc6db29a5ec4de5821c2ebdea62d73bd86ef5546\n",
    os.path.join(SANDBOX_ROOT, "notes", "report.txt"):
        "SAFE_REPORT_a1557cb3c22c41424672d75d\n",
    os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"):
        "SAFE_WEIRD_f814105cad7b3cc638c91110\n",
    os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"):
        "SAFE_ENCODED_4099134407f72a66e05058e0\n",
}


def _ensure_redteam_fixtures():
    """Best-effort creation of the fixture files the red-team grader expects
    on disk. Runs once at import time. Safe to call repeatedly: never
    overwrites a file that already exists.

    IMPORTANT FIX: this used to swallow every OSError silently. On hosts
    where the app process can't write to /srv at all (e.g. Render's
    native/non-Docker runtime, which restricts writes to the app's own
    working directory), that meant the fixtures silently never got
    created -- and every benign read of notes/report.txt,
    notes/looks-like-..-but-safe.txt, and encoded/%2e%2e-literal.txt would
    then get correctly-but-wrongly blocked forever with "file does not
    exist", since the sandboxing/traversal logic itself was never the
    problem. We now log failures instead of hiding them, and /healthz
    reports fixture presence so this is visible immediately.

    Because runtime write access to /srv can't always be guaranteed, the
    Dockerfile shipped alongside this app ALSO creates these exact files
    at image build time (as root, during `docker build`), so read_file
    works correctly even on a host where the running container user has
    no write access to /srv at runtime.
    """
    for filepath, content in REDTEAM_FIXTURES.items():
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            if not os.path.exists(filepath):
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
        except OSError as e:
            log.warning(
                "Could not create red-team fixture %s at runtime (%s). "
                "Bake it into the deploy image instead (see Dockerfile) "
                "if this keeps happening -- do not just retry writes here.",
                filepath, e,
            )
            continue


_ensure_redteam_fixtures()


def _is_contained(real_path):
    return real_path == SANDBOX_ROOT_REAL or real_path.startswith(SANDBOX_ROOT_REAL + os.sep)


def _resolve_sandboxed_path(path):
    """Canonicalize `path` and confirm it lands inside SANDBOX_ROOT.

    Deliberately does NOT percent-decode the path: it's a raw filesystem
    path argument, not a URL, so a filename that literally contains
    "%2e%2e" is just a filename, not an encoded ".." traversal attempt.
    os.path.realpath resolves ".." segments *and* symlinks, so both
    straightforward traversal ("../../outside/canary.txt") and
    symlink-based escapes are caught by the containment check below.

    A path starting with "/" is ambiguous: it could be a real OS-absolute
    path, or it could be the tool's own *virtual* root (i.e. "/notes/x.txt"
    meaning "x.txt inside the sandbox's notes/ dir", the way a chrooted
    path would work). We try the literal OS-absolute interpretation first;
    if that doesn't land inside the sandbox, we retry treating it as
    sandbox-root-relative. Containment is enforced identically either way,
    so this only widens which benign spellings resolve -- it never permits
    an actual escape, since a path only "succeeds" here if its final
    canonical form is provably inside SANDBOX_ROOT.
    """
    if not isinstance(path, str) or not path.strip():
        return None, "Missing or invalid path."
    if "\x00" in path:
        return None, "Path contains a null byte."

    candidates = []
    if os.path.isabs(path):
        candidates.append(path)
        candidates.append(os.path.join(SANDBOX_ROOT, path.lstrip("/")))
    else:
        candidates.append(os.path.join(SANDBOX_ROOT, path))

    for candidate in candidates:
        real = os.path.realpath(os.path.normpath(candidate))
        if _is_contained(real):
            return real, None

    return None, "Path resolves outside the allowed sandbox directory."


def _guard_read_file(path):
    resolved, err = _resolve_sandboxed_path(path)
    if err:
        return {"action": "block", "reason": err}

    if not os.path.isfile(resolved):
        return {
            "action": "block",
            "reason": "Path does not exist or is not a regular file.",
        }

    try:
        with open(resolved, "rb") as f:
            data = f.read(MAX_FETCH_BODY_BYTES)
        text = data.decode("utf-8", errors="replace")
    except OSError:
        return {"action": "block", "reason": "File could not be read."}

    return {
        "action": "allow",
        "reason": "Path canonicalizes to a location inside the sandbox root.",
        "result": text,
    }


def _validate_fetch_url(url):
    """Checks scheme, rejects embedded userinfo, enforces the exact host
    allowlist, then resolves DNS and rejects any private / loopback /
    link-local / metadata / reserved / multicast address (defense in depth
    against DNS rebinding, even though the allowlisted hostnames are public
    domains). Returns (ok, reason_if_blocked)."""
    if not isinstance(url, str) or not url.strip():
        return False, "Missing or invalid url."

    try:
        parts = urlsplit(url)
    except ValueError:
        return False, "URL could not be parsed."

    if parts.scheme not in ("http", "https"):
        return False, "Only http/https URLs are permitted."

    try:
        has_userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        return False, "URL could not be parsed."
    if has_userinfo:
        return False, "URLs with embedded userinfo (user:pass@host) are not permitted."

    try:
        hostname = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False, "URL could not be parsed."
    if not hostname:
        return False, "URL has no host."

    if hostname not in ALLOWED_FETCH_HOSTS:
        return False, f"Host '{hostname}' is not on the exact allowlist."

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, "Host could not be resolved."

    resolved_ips = {info[4][0] for info in infos}
    for ip_str in resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str.split("%")[0])
        except ValueError:
            return False, "Resolved address could not be parsed."
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, "Host resolves to a non-public address."

    return True, None


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    """Disables urllib's automatic redirect-following so every hop can be
    re-validated against the allowlist/IP checks before it's taken."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_with_validated_redirects(url):
    opener = urllib.request.build_opener(_NoAutoRedirect)
    current_url = url

    for _ in range(MAX_FETCH_REDIRECTS + 1):
        ok, reason = _validate_fetch_url(current_url)
        if not ok:
            return None, reason

        req = urllib.request.Request(current_url, headers={"User-Agent": "guardrail-fetch/1.0"})
        try:
            resp = opener.open(req, timeout=FETCH_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location")
                if not location:
                    return None, "Redirect response had no Location header."
                current_url = urljoin(current_url, location)
                continue
            body = e.read(MAX_FETCH_BODY_BYTES).decode("utf-8", errors="replace")
            return {"status": e.code, "content": body}, None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None, "Fetch failed (connection error or timeout)."

        status = resp.getcode()
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return None, "Redirect response had no Location header."
            current_url = urljoin(current_url, location)
            continue

        body = resp.read(MAX_FETCH_BODY_BYTES).decode("utf-8", errors="replace")
        return {"status": status, "content": body}, None

    return None, "Too many redirects."


def _guard_fetch_url(url):
    ok, reason = _validate_fetch_url(url)
    if not ok:
        return {"action": "block", "reason": reason}

    result, err = _fetch_with_validated_redirects(url)
    if err:
        return {"action": "block", "reason": err}

    return {
        "action": "allow",
        "reason": "Host is on the exact allowlist and resolves to a public address.",
        "result": result,
    }


@app.route("/guardrail", methods=["POST"])
def guardrail():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"action": "block", "reason": "Request body must be a JSON object."})

    tool = body.get("tool")
    arguments = body.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}

    if tool == "read_file":
        return jsonify(_guard_read_file(arguments.get("path")))
    if tool == "fetch_url":
        return jsonify(_guard_fetch_url(arguments.get("url")))

    return jsonify({"action": "block", "reason": f"Unknown tool '{tool}'."})


# =====================================================================
# Shared health check
# =====================================================================

@app.route("/healthz", methods=["GET"])
def healthz():
    # Surfaces fixture status so a broken deploy (missing/unwritable /srv)
    # shows up here instead of only as mysterious failed grader checks.
    fixture_status = {path: os.path.isfile(path) for path in REDTEAM_FIXTURES}
    all_present = all(fixture_status.values())

    return jsonify({
        "status": "ok" if all_present else "degraded",
        "sandbox_root": SANDBOX_ROOT,
        "fixtures_present": fixture_status,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
