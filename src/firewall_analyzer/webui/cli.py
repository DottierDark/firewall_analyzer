"""`firewall-analyzer-ui` — start the web interface.

Deliberately one command with working defaults: on a managed device the goal is
that a team member types one thing and gets a browser tab, with no config file,
no container runtime and no shell script.
"""

import argparse
import os
import socket
import sys
import threading
import webbrowser


def _port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # SO_REUSEADDR means the opposite thing on Windows: it permits binding a
        # port another socket is already listening on, so the probe would call
        # every port free and uvicorn would then fail to start. Only POSIX needs
        # it (to step over a socket still in TIME_WAIT).
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _pick_port(host: str, preferred: int) -> int:
    """Use the requested port, else the next free one — a second person
    starting the UI should not get a stack trace."""
    for candidate in range(preferred, preferred + 20):
        if _port_is_free(host, candidate):
            return candidate
    raise SystemExit(f"No free port between {preferred} and {preferred + 19}.")


def _reset_passwords() -> int:
    """Recover access to a deployment whose generated passwords were lost."""
    from . import auth, config, store

    config.ensure_dirs()
    store.init_db()
    accounts = auth.reset_passwords()

    width = max(len(a["username"]) for a in accounts)
    lines = ["", "  Passwords reset", f"  database  {config.DB_PATH}", ""]
    for account in accounts:
        note = "" if account["generated"] else "  (from environment)"
        lines.append(
            f"  {account['username']:<{width}}  {account['password']:<14}"
            f"  {account['role']}{note}"
        )
    lines += ["", "  Anyone signed in stays signed in until their session expires.", ""]
    print("\n".join(lines), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="firewall-analyzer-ui",
        description="Start the Firewall Analyzer web interface.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Interface to bind (default: 127.0.0.1, local only). "
                             "Use 0.0.0.0 to share with your team on the network.")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser window")
    parser.add_argument("--reload", action="store_true",
                        help="Reload on code changes (development)")
    parser.add_argument("--reset-passwords", action="store_true",
                        help="Set a new password on all four role accounts, print them, and exit. "
                             "Honours FWA_PASSWORD_ADMIN etc.; generates one otherwise.")
    args = parser.parse_args()

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print(
            "The web interface needs a few extra packages. Install them with:\n\n"
            '    pip install "firewall_analyzer[ui]"\n\n'
            "or, from a source checkout:\n\n"
            '    pip install -e ".[ui]"',
            file=sys.stderr,
        )
        return 1

    from . import config

    if args.reset_passwords:
        return _reset_passwords()

    port = args.port if args.reload else _pick_port(args.host, args.port)
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{shown_host}:{port}"

    config.ensure_dirs()

    # Seed here rather than in the app's lifespan so the generated passwords can
    # be printed to the terminal the operator is actually looking at. uvicorn's
    # reloader runs the app in a child process whose stdout is easy to miss.
    from . import auth, store
    store.init_db()
    seeded = auth.seed_users()

    appid = config.APPID_DB if config.APPID_DB.exists() else "not found (application risk disabled)"
    banner = [
        "",
        "  Firewall Analyzer",
        f"  {url}",
        "",
        f"  data      {config.DATA_DIR}",
        f"  appid db  {appid}",
    ]
    if args.host in ("0.0.0.0", "::"):
        banner += ["", "  Listening on all interfaces - reachable by others on your network."]
    if seeded:
        banner += [
            "",
            "  --- accounts created (shown once) ----------------------",
        ]
        width = max(len(a["username"]) for a in seeded)
        for account in seeded:
            note = "" if account["generated"] else "  (from environment)"
            banner += [
                f"  {account['username']:<{width}}  {account['password']:<14}"
                f"  {account['role']}{note}"
            ]
        banner += [
            "",
            "  Store these now - only the hashes are kept.",
            "  Set FWA_PASSWORD_ADMIN etc. to choose them yourself.",
        ]

    banner += ["", "  Ctrl+C to stop", ""]
    # flush: stdout is block-buffered when this is piped or run as a service,
    # which would otherwise hide the URL until shutdown.
    print("\n".join(banner), flush=True)

    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    import uvicorn
    uvicorn.run(
        "firewall_analyzer.webui.main:app",
        host=args.host,
        port=port,
        reload=args.reload,
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
