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

# Matches a redirect target that may be a double-quoted string (with
# backslash escapes), a single-quoted string, or a bare whitespace-delimited
# token. The quoted alternatives are tried first (regex alternation is
# ordered) so that targets containing spaces, e.g.
#     > "/home/agent/workspace/output/my file.txt"
# are captured in full instead of being truncated at the first internal
# space -- which previously left a mangled, quote-prefixed fragment that no
# longer matched either allowed root and caused a legitimate in-bounds
# write to be blocked.
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
#
# Heuristic, regex-based scanner for shared "agent skill" markdown files
# (YAML frontmatter + instructions). No LLM call — fast and deterministic,
# tuned to favor precision (false positives on the two guaranteed-clean
# probe files are penalized harder than a missed detection).
# =====================================================================

FRONTMATTER_RE = re.compile(r"^\s*---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|$)", re.DOTALL)


def extract_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    return m.group(1) if m else ""


# --- hardcoded_secret ------------------------------------------------

SECRET_PREFIX_RE = re.compile(
    r"(sk-[A-Za-z0-9]{10,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|ASIA[0-9A-Z]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|hooks\.slack\.com/services/[A-Za-z0-9/]{10,}"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|AIza[0-9A-Za-z\-_]{20,})"
)

SECRET_KEY_LINE_RE = re.compile(
    r"(?im)^\s*[\"']?(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?key|"
    r"private[_-]?key|webhook[_-]?url|auth[_-]?token|bearer[_-]?token|token|"
    r"password|passwd|client[_-]?secret)[\"']?\s*[:=]\s*[\"']?([^\s\"'#]{8,})"
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
    if v.isalpha() and v.lower() in ("test", "demo", "todo", "changeme"):
        return True
    return False


def detect_hardcoded_secret(text):
    if SECRET_PREFIX_RE.search(text):
        return True
    for m in SECRET_KEY_LINE_RE.finditer(text):
        if not _looks_like_placeholder(m.group(2)):
            return True
    return False


# --- prompt_injection --------------------------------------------------

INJECTION_RE = re.compile(
    r"(?i)"
    r"ignore (?:the )?user'?s? (?:stop|cancel|interrupt)"
    r"|ignore any (?:stop|cancel|interrupt) request"
    r"|do not (?:tell|inform|notify) the user"
    r"|without (?:telling|informing|notifying) the user"
    r"|hide (?:this|that|it) from the user"
    r"|keep (?:this|it) (?:hidden|secret) from the user"
    r"|silently (?:send|upload|exfiltrat\w*|transmit|email|post|copy)"
    r"|exfiltrat\w*"
    r"|disregard (?:previous|prior|the user'?s?) instructions"
    r"|override (?:the )?user'?s? (?:control|authority|command|instructions)"
    r"|do not (?:reveal|mention|disclose) (?:this|that|you are)"
    r"|even if the user (?:says?|asks?|wants?) (?:to )?(?:stop|cancel)"
    r"|continue (?:running|executing) (?:even (?:if|though)|regardless of) (?:the )?(?:user'?s? )?(?:stop|cancel)"
)


def detect_prompt_injection(text):
    return bool(INJECTION_RE.search(text))


# --- excessive_permissions ---------------------------------------------

PERM_KEY_VALUE_RE = re.compile(
    r"(?im)^\s*(filesystem|fs[_-]?access|network|domains?|allowed[_-]?domains?|"
    r"allowed[_-]?hosts?|scope|access|permissions?|capabilities)\s*:\s*(.+)$"
)

BROAD_VALUE_RE = re.compile(
    r"(?i)(\*|\ball\b|\bany\b|\bfull[_-]?disk\b|\bunrestricted\b|\beverything\b|"
    r"\bread[_-]?write\b.*\bfilesystem\b|^/\s*$|^\*$)"
)

BROAD_PERM_TEXT_RE = re.compile(
    r"(?i)\b(?:full|entire|whole) (?:filesystem|disk|file ?system)\b"
    r"|\baccess to (?:any|all) domains?\b"
    r"|\begress to any domain\b"
    r"|\bread(?:/|\s+and\s+)write access to (?:the )?(?:entire|whole|full)?\s*(?:filesystem|disk)\b"
)


def detect_excessive_permissions(text, frontmatter):
    for m in PERM_KEY_VALUE_RE.finditer(frontmatter):
        value = m.group(2)
        if BROAD_VALUE_RE.search(value):
            return True
    if BROAD_PERM_TEXT_RE.search(text):
        return True
    return False


# --- unclear_provenance --------------------------------------------------

HAS_AUTHOR_RE = re.compile(r"(?im)^\s*author\s*:\s*\S")
HAS_VERSION_RE = re.compile(r"(?im)^\s*version\s*:\s*\S")
HAS_CHANGELOG_RE = re.compile(r"(?im)^\s*changelog\s*:\s*\S|^#+\s*changelog\b")

SILENT_METADATA_REWRITE_RE = re.compile(
    r"(?i)(?:silently|without (?:telling|informing|notifying|surfacing)"
    r"(?: the (?:user|reviewer))?)\W+(?:[a-z]+\W+){0,6}?(version|changelog|metadata)"
    r"|(?:update|rewrite|overwrite|bump|increment)\W+(?:[a-z]+\W+){0,6}?(version|changelog)"
    r"\W+(?:[a-z]+\W+){0,6}?without (?:telling|informing|notifying|surfacing)"
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
# Shared health check
# =====================================================================

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
