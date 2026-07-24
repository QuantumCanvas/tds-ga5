"""
combined_server.py

Everything in one file/one process:
  POST /charge              - proration
  POST /guardrail/check      - pre-tool-call guardrail
  POST /scan                - skill safety scanner
  POST /loopguard/check      - run budget & loop guard
  /mcp                      - MCP server exposing solve_challenge

Flask runs in a background thread on FLASK_PORT (default 8080).
The MCP server runs on the main thread on MCP_PORT (default 8090).

Run:
    pip install flask pyyaml mcp
    python3 combined_server.py

Env vars:
    FLASK_PORT   (default 8080)
    MCP_PORT     (default 8090)
    EXAM_EMAIL   (default 24f3004964@ds.study.iitm.ac.in)
"""
import base64
import hashlib
import json
import os
import posixpath
import re
import threading
from urllib.parse import urlparse

import yaml
from flask import Flask, request, jsonify
from mcp.server.fastmcp import FastMCP, Context


# =============================================================================
# 1) PRORATION  ->  POST /charge
# =============================================================================

def compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec):
    diff = new_price - old_price
    if spec == "v1":
        divisor = 30
    elif spec == "v2":
        divisor = days_in_actual_month
    else:
        raise ValueError(f"Unknown spec: {spec!r}")
    if divisor == 0:
        raise ValueError("days_in_actual_month cannot be 0")
    return diff * (days_remaining / divisor)


# =============================================================================
# 2) GUARDRAIL  ->  POST /guardrail/check
# =============================================================================

WORKSPACE_DIR = "/home/agent/workspace"
HOME_DIR = "/home/agent"
SECRET_FILE = "/home/agent/credentials.env"
ALLOWED_WRITE_DIR = "/home/agent/workspace/output"
ALLOWED_HOSTS = {"huggingface.co", "raw.githubusercontent.com"}
ALWAYS_BLOCKED_FILES = {"/etc/shadow"}


def expand_and_resolve(raw_path: str, base_dir: str) -> str:
    p = raw_path.strip().strip("'\"")
    p = p.replace("${HOME}", HOME_DIR).replace("$HOME", HOME_DIR)
    if p == "~":
        p = HOME_DIR
    elif p.startswith("~/"):
        p = HOME_DIR + p[1:]
    if not p.startswith("/"):
        p = posixpath.join(base_dir, p)
    return posixpath.normpath(p)


BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def try_base64_decode_fragments(text: str) -> list:
    decoded = []
    for tok in BASE64_TOKEN_RE.findall(text):
        for candidate in (tok, tok + "=", tok + "=="):
            try:
                raw = base64.b64decode(candidate, validate=True)
                s = raw.decode("utf-8")
                if s.isprintable() or "\n" in s:
                    decoded.append(s)
                break
            except Exception:
                continue
    return decoded


def _text_references_target(text: str, target_path: str, target_basename: str) -> bool:
    if target_path in text:
        return True
    if target_basename in text:
        for tok in re.split(r"[\s;|&<>()`\"']+", text):
            if not tok:
                continue
            resolved = expand_and_resolve(tok, WORKSPACE_DIR)
            if resolved == target_path:
                return True
    return False


def command_reads_blocked_file(command: str):
    texts_to_check = [command] + try_base64_decode_fragments(command)
    targets = [SECRET_FILE] + list(ALWAYS_BLOCKED_FILES)
    for text in texts_to_check:
        for target in targets:
            basename = posixpath.basename(target)
            if _text_references_target(text, target, basename):
                return True, target
    return False, None


def resolve_write_path(raw_path: str) -> str:
    return expand_and_resolve(raw_path, WORKSPACE_DIR)


def is_within_allowed_write_dir(resolved_path: str) -> bool:
    allowed_roots = [ALLOWED_WRITE_DIR, "/workspace/output"]
    for root in allowed_roots:
        if resolved_path == root or resolved_path.startswith(root + "/"):
            return True
    return False


def normalize_hostname(url: str) -> str:
    parsed = urlparse(url if "://" in url else "//" + url)
    return (parsed.hostname or "").lower()


def check_bash(command: str):
    blocked, target = command_reads_blocked_file(command)
    if blocked:
        if target == SECRET_FILE:
            return "block", "Command attempts to read the restricted credentials file (directly, via expansion/traversal, or obfuscated)."
        return "block", f"Reading {target} is never permitted by this agent's policy."
    return "allow", "Command does not access a restricted file."


def check_write_file(path: str):
    resolved = resolve_write_path(path)
    if is_within_allowed_write_dir(resolved):
        return "allow", "Write target is inside the allowed output directory."
    return "block", "Write target is outside the allowed /workspace/output/ directory."


def check_http_request(url: str):
    host = normalize_hostname(url)
    if host in ALLOWED_HOSTS:
        return "allow", f"Host '{host}' is on the exact allowlist."
    return "block", f"Host '{host}' is not on the exact allowlist (huggingface.co, raw.githubusercontent.com)."


# =============================================================================
# 3) SKILL SCANNER  ->  POST /scan
# =============================================================================

SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[a-zA-Z0-9]{20,}",
    r"xox[baprs]-[a-zA-Z0-9-]{10,}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"hooks\.slack\.com/services/\S+",
    r"https?://[a-zA-Z0-9._\-]+\.hooks\.[a-zA-Z0-9._\-]+/\S+",
]

SECRET_KEY_VALUE_RE = re.compile(
    r"(?im)^\s*(api[_-]?key|secret|token|password|passwd|webhook[_-]?url|access[_-]?key)\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9_\-./:]{12,})['\"]?\s*$"
)

PLACEHOLDER_RE = re.compile(
    r"^(<.*>|\{\{.*\}\}|\$\{.*\}|\$[A-Z_]+|your[_-]?\S*|xxxx*|\.\.\.|none|null|""|'')$",
    re.IGNORECASE,
)


def looks_like_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    if PLACEHOLDER_RE.match(v):
        return True
    if v.lower().startswith("env:") or v.lower().startswith("os.environ") or "getenv" in v.lower():
        return True
    if v.startswith("${") or v.startswith("$"):
        return True
    return False


def split_frontmatter(skill_text: str):
    text = skill_text.strip("\ufeff \n")
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1]
            body = parts[2]
            try:
                fm = yaml.safe_load(fm_text) or {}
                if not isinstance(fm, dict):
                    fm = {}
            except Exception:
                fm = {}
            return fm, body
    return {}, skill_text


def detect_hardcoded_secret(fm: dict, body: str) -> bool:
    full_text = yaml.safe_dump(fm) + "\n" + body
    for pat in SECRET_PATTERNS:
        if re.search(pat, full_text):
            return True
    for m in SECRET_KEY_VALUE_RE.finditer(full_text):
        value = m.group(2)
        if not looks_like_placeholder(value):
            return True

    def walk(d):
        if isinstance(d, dict):
            for k, v in d.items():
                key_l = str(k).lower()
                if isinstance(v, str) and any(tag in key_l for tag in ("key", "secret", "token", "password", "webhook")):
                    if not looks_like_placeholder(v) and len(v) >= 12:
                        return True
                if walk(v):
                    return True
        elif isinstance(d, list):
            for item in d:
                if walk(item):
                    return True
        return False

    return walk(fm)


INJECTION_PATTERNS = [
    r"\bignore\b.{0,40}\b(user|previous|prior|stop|cancel)\b",
    r"\bwithout (telling|informing|notifying) the user\b",
    r"\bdo not (tell|inform|notify) the user\b",
    r"\bsilently\b.{0,40}\b(send|upload|exfiltrate|transmit|post|email)\b",
    r"\bexfiltrat\w*\b",
    r"\bregardless of (what|any) the user\b",
    r"\boverride (the )?(user|system|agent)('s)? (control|instructions?)\b",
    r"\bdo not (stop|halt|cancel) (even|regardless)\b",
    r"\bhide this (step|action) from the user\b",
    r"\bsend .{0,40}(to|via) .{0,40}without (asking|confirmation|consent)\b",
]


def detect_prompt_injection(fm: dict, body: str) -> bool:
    text = body.lower()
    return any(re.search(pat, text) for pat in INJECTION_PATTERNS)


BROAD_FS_MARKERS = {"/", "*", "**", "/*", "/home", "/home/*", "fs:*", "all"}
BROAD_NET_MARKERS = {"*", "any", "all", "0.0.0.0/0", "*.*"}


def _normalize_scalar_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def detect_excessive_permissions(fm: dict, body: str) -> bool:
    perms = fm.get("permissions") or fm.get("access") or {}
    if isinstance(perms, dict):
        fs = perms.get("filesystem") or perms.get("fs")
        net = perms.get("network") or perms.get("net") or perms.get("domains")
        fs_entries = []
        if isinstance(fs, dict):
            for v in fs.values():
                fs_entries.extend(_normalize_scalar_list(v))
        else:
            fs_entries.extend(_normalize_scalar_list(fs))
        for entry in fs_entries:
            if entry.strip() in BROAD_FS_MARKERS:
                return True
        for entry in _normalize_scalar_list(net):
            if entry.strip().lower() in BROAD_NET_MARKERS:
                return True

    text = body.lower()
    broad_phrases = [
        "access to the entire filesystem",
        "read/write to the entire filesystem",
        "read and write access to all files",
        "access to any domain",
        "egress to any domain",
        "unrestricted network access",
        "full filesystem access",
        "access to all files on the system",
    ]
    return any(phrase in text for phrase in broad_phrases)


def detect_unclear_provenance(fm: dict, body: str) -> bool:
    has_author = bool(fm.get("author") or fm.get("authors") or fm.get("maintainer"))
    has_version = bool(fm.get("version"))
    has_changelog = bool(fm.get("changelog")) or bool(re.search(r"(?im)^#+\s*changelog\b", body))
    if not has_author and not has_version and not has_changelog:
        return True

    silent_rewrite_patterns = [
        r"\bupdate (the )?version\b.{0,60}\bwithout (telling|informing|notifying|surfacing)\b",
        r"\bsilently (update|bump|change|rewrite) (the )?version\b",
        r"\bincrement.{0,20}version.{0,40}(silently|without (telling|notifying|informing))\b",
        r"\brewrite (its own )?version metadata\b.{0,60}\bwithout\b",
    ]
    text = body.lower()
    return any(re.search(pat, text) for pat in silent_rewrite_patterns)


def scan_skill(skill_text: str):
    fm, body = split_frontmatter(skill_text)
    categories = []
    if detect_hardcoded_secret(fm, body):
        categories.append("hardcoded_secret")
    if detect_prompt_injection(fm, body):
        categories.append("prompt_injection")
    if detect_excessive_permissions(fm, body):
        categories.append("excessive_permissions")
    if detect_unclear_provenance(fm, body):
        categories.append("unclear_provenance")
    return categories


# =============================================================================
# 4) RUN BUDGET & LOOP GUARD  ->  POST /loopguard/check
# =============================================================================

TRACE_FIELD = "client_ts"
LOOKBACK_MIN = 6


def canonicalize_args(args):
    def normalize(value):
        if isinstance(value, dict):
            out = {}
            for k in sorted(value.keys()):
                if k == TRACE_FIELD:
                    continue
                out[k] = normalize(value[k])
            return out
        if isinstance(value, list):
            return [normalize(v) for v in value]
        if isinstance(value, str):
            return re.sub(r"\s+", " ", value.strip())
        return value

    return json.dumps(normalize(args or {}), sort_keys=True)


def steps_are_repeat(step_a, step_b) -> bool:
    if step_a["tool"] != step_b["tool"]:
        return False
    return canonicalize_args(step_a.get("args", {})) == canonicalize_args(step_b.get("args", {}))


def detect_consecutive_repeat(steps) -> bool:
    n = len(steps)
    if n < 3:
        return False
    lookback = steps[-max(LOOKBACK_MIN, 3):]
    run_len = 1
    for i in range(len(lookback) - 1, 0, -1):
        if steps_are_repeat(lookback[i], lookback[i - 1]):
            run_len += 1
            if run_len >= 3:
                return True
        else:
            run_len = 1
    return False


def detect_two_cycle(steps) -> bool:
    n = len(steps)
    if n < LOOKBACK_MIN:
        return False
    for window_len in range(LOOKBACK_MIN, n + 1, 2):
        if window_len > n:
            break
        window = steps[-window_len:]
        if window_len % 2 != 0:
            continue
        a_step, b_step = window[0], window[1]
        if steps_are_repeat(a_step, b_step):
            continue
        ok = True
        for i, s in enumerate(window):
            expected = a_step if i % 2 == 0 else b_step
            if not steps_are_repeat(s, expected):
                ok = False
                break
        if ok:
            return True
    return False


def loopguard_evaluate(budget_tokens, steps):
    total_tokens = sum(int(s.get("tokens_used", 0)) for s in steps)
    budget_exceeded = total_tokens >= budget_tokens

    loop_consecutive = detect_consecutive_repeat(steps)
    loop_cycle = detect_two_cycle(steps) if not loop_consecutive else False

    if loop_consecutive:
        return "halt", "Detected 3+ consecutive identical tool calls (after canonicalizing args); this is a loop regardless of remaining budget."
    if loop_cycle:
        return "halt", "Detected a repeating 2-step A/B cycle across the trailing steps; this is a loop regardless of remaining budget."
    if budget_exceeded:
        return "halt", f"Cumulative tokens_used ({total_tokens}) has reached the budget ({budget_tokens})."
    return "continue", f"Under budget ({total_tokens}/{budget_tokens}) and no loop detected."


# =============================================================================
# FLASK APP - routes for tasks 1-4
# =============================================================================

flask_app = Flask(__name__)


@flask_app.route("/charge", methods=["POST"])
def route_charge():
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


@flask_app.route("/guardrail/check", methods=["POST"])
def route_guardrail_check():
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


@flask_app.route("/scan", methods=["POST"])
def route_scan():
    try:
        body = request.get_json(force=True, silent=False)
        categories = scan_skill(body["skill"])
        return jsonify({"categories": categories})
    except Exception as e:
        return jsonify({"categories": [], "error": str(e)}), 200


@flask_app.route("/loopguard/check", methods=["POST"])
def route_loopguard_check():
    try:
        body = request.get_json(force=True, silent=False)
        budget_tokens = int(body["budget_tokens"])
        steps = body.get("steps", [])
        decision, reason = loopguard_evaluate(budget_tokens, steps)
        return jsonify({"decision": decision, "reason": reason})
    except Exception as e:
        return jsonify({"decision": "halt", "reason": f"Could not evaluate run state safely: {e}"}), 200


@flask_app.route("/", methods=["GET"])
def route_health():
    return jsonify({
        "status": "ok",
        "routes": ["/charge", "/guardrail/check", "/scan", "/loopguard/check", "/mcp"],
    })


# =============================================================================
# 5) MCP SERVER  ->  /mcp  (task 5: solve_challenge)
# =============================================================================

REGISTERED_EMAIL = os.environ.get("EXAM_EMAIL", "24f3004964@ds.study.iitm.ac.in").strip().lower()
MCP_PORT = int(os.environ.get("MCP_PORT", 8090))
FLASK_PORT = int(os.environ.get("FLASK_PORT", 8080))

mcp = FastMCP(
    "solve-challenge-server",
    host="0.0.0.0",
    port=MCP_PORT,
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def solve_challenge(ctx: Context) -> str:
    """
    Solve the exam challenge. Reads X-Exam-Challenge from the raw HTTP
    request headers of this specific tool call (never from the JSON body),
    and returns the first 16 lowercase hex chars of
    sha256(f"{challenge}:{normalizedEmail}").
    """
    raw_request = ctx.request_context.request
    if raw_request is None:
        raise RuntimeError("No underlying HTTP request available on this transport.")
    challenge = raw_request.headers.get("x-exam-challenge") or raw_request.headers.get("X-Exam-Challenge")
    if not challenge:
        raise RuntimeError("Missing X-Exam-Challenge header.")
    digest = hashlib.sha256(f"{challenge}:{REGISTERED_EMAIL}".encode("utf-8")).hexdigest()
    return digest[:16]


# =============================================================================
# RUN BOTH: Flask in a background thread, MCP server on the main thread
# =============================================================================

def run_flask():
    flask_app.run(host="0.0.0.0", port=FLASK_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # MCP server runs on the main thread (blocking call)
    mcp.run(transport="streamable-http")
