"""
RFT GUI Launcher
----------------
Starts the Flask web server and (on the distro) opens Chromium in kiosk mode.
Also prints the local network URL so you can access from another device.
"""

import os
import platform
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path


PORT = int(os.environ.get("RFT_PORT", 5000))
HOST = "0.0.0.0"


def get_local_ip() -> str:
    """Get the LAN IP so users can access from another device."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def load_saved_api_key():
    """Pre-load API key from settings file if present."""
    settings_path = Path("/opt/rft/settings.json")
    if settings_path.exists():
        try:
            import json
            s = json.loads(settings_path.read_text())
            if "api_key" in s and not os.environ.get("ANTHROPIC_API_KEY"):
                os.environ["ANTHROPIC_API_KEY"] = s["api_key"]
        except Exception:
            pass


def open_browser(url: str, kiosk: bool = False):
    """Open the GUI in a browser window."""
    time.sleep(2)  # Give Flask time to start

    # Skip if no display is available (headless server, SSH session)
    if not os.environ.get("DISPLAY") and not kiosk:
        return

    is_pi = platform.machine().startswith("arm") or platform.machine().startswith("aarch")
    is_linux = sys.platform == "linux"

    if is_linux and (is_pi or kiosk or os.environ.get("RFT_KIOSK")):
        # Try Chromium kiosk mode (standard on Raspberry Pi OS)
        for browser in ("chromium-browser", "chromium", "google-chrome"):
            try:
                subprocess.Popen([
                    browser,
                    "--kiosk",
                    "--no-sandbox",
                    "--disable-infobars",
                    "--disable-session-crashed-bubble",
                    "--disable-restore-session-state",
                    "--autoplay-policy=no-user-gesture-required",
                    url
                ])
                return
            except FileNotFoundError:
                continue

        # Fallback: Firefox fullscreen
        try:
            subprocess.Popen(["firefox", "--kiosk", url])
            return
        except FileNotFoundError:
            pass

    # Normal browser open (dev mode / desktop)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def print_banner(local_ip: str):
    lines = [
        "",
        "  ╔══════════════════════════════════════════════╗",
        "  ║   Ransomware Forensics Toolkit  v1.0         ║",
        "  ╚══════════════════════════════════════════════╝",
        "",
        f"  Local:    http://127.0.0.1:{PORT}",
        f"  Network:  http://{local_ip}:{PORT}",
        "",
        "  Opening browser... (Ctrl+C to stop)",
        "",
    ]
    for line in lines:
        print(line)


def run_server(debug: bool = False):
    """Start the Flask/Gunicorn server."""
    from rft.web.app import app

    if debug:
        app.run(host=HOST, port=PORT, debug=True, use_reloader=False, threaded=True)
    else:
        try:
            from gunicorn.app.wsgiapp import run as gunicorn_run
            # Build argv for gunicorn
            sys.argv = [
                "gunicorn",
                f"--bind={HOST}:{PORT}",
                "--workers=2",
                "--threads=4",
                "--timeout=300",
                "--worker-class=gthread",
                "rft.web.app:app",
            ]
            gunicorn_run()
        except ImportError:
            # Fallback to Flask dev server
            app.run(host=HOST, port=PORT, debug=False, threaded=True)


def main():
    debug = "--debug" in sys.argv or os.environ.get("RFT_DEBUG") == "1"
    kiosk = "--kiosk" in sys.argv or os.environ.get("RFT_KIOSK") == "1"

    load_saved_api_key()
    local_ip = get_local_ip()
    url = f"http://127.0.0.1:{PORT}"

    print_banner(local_ip)

    # Open browser in background thread
    threading.Thread(target=open_browser, args=(url, kiosk), daemon=True).start()

    # Run server (blocking)
    run_server(debug=debug)


if __name__ == "__main__":
    main()
