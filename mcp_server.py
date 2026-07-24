"""
Live MCP server exposing one tool: solve_challenge.

Deploy over HTTPS. The MCP endpoint path is /mcp (FastMCP's default for the
streamable-http transport).

On every tools/call, this reads the challenge from the HTTP request headers
(not the JSON body) and returns:

  sha256(f"{challenge}:{normalizedEmail}").hexdigest()[:16]

Run:
    python3 mcp_server.py
Env vars:
    PORT              (default 8080)
    EXAM_EMAIL         registered exam email (defaults to the one given in the task)
"""
import hashlib
import os

from mcp.server.fastmcp import FastMCP, Context

REGISTERED_EMAIL = os.environ.get("EXAM_EMAIL", "24f3004964@ds.study.iitm.ac.in").strip().lower()

PORT = int(os.environ.get("PORT", 8080))

mcp = FastMCP(
    "solve-challenge-server",
    host="0.0.0.0",
    port=PORT,
    stateless_http=True,   # simplest correct option for a single-tool, no-session-needed server
    json_response=True,    # respond with plain JSON instead of an SSE stream
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


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
