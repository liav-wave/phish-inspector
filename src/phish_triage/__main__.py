"""Entry point for `python -m phish_triage`."""

import os
import sys

from phish_triage.server import mcp

if __name__ == "__main__":
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "http":
        # HTTP transport has no built-in auth. Gate it behind an explicit
        # bind-host opt-in so an accidental `python -m phish_triage http`
        # on a laptop cannot publish an unauthenticated MCP to the LAN.
        # The legacy Cloud Run path (`wip/cloud-run/Dockerfile`) sets
        # PHISH_TRIAGE_BIND_HOST=0.0.0.0 deliberately.
        bind_host = os.environ.get("PHISH_TRIAGE_BIND_HOST", "")
        if not bind_host:
            print(
                "phish-triage: HTTP transport requires PHISH_TRIAGE_BIND_HOST "
                "to be set explicitly (e.g. 127.0.0.1 for local testing, "
                "0.0.0.0 only inside a container behind an authenticating "
                "proxy). Refusing to start.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(
            f"WARNING: HTTP transport has no built-in authentication and is "
            f"binding to {bind_host}. Use only behind an authenticating proxy.",
            file=sys.stderr,
        )
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
