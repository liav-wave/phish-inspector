"""Entry point for `python -m phish_triage.server` or `python -m phish_triage`."""

import sys

from phish_triage.server import mcp

if __name__ == "__main__":
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "http":
        print(
            "WARNING: HTTP transport has no built-in authentication. "
            "Use behind an authenticating proxy or for local testing only.",
            file=sys.stderr,
        )
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
