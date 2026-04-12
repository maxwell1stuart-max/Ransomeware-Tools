"""
APT Web GUI — Flask application
Automated Penetration Toolkit web interface.
Runs on port 5001 (RFT runs on 5000).
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, make_response, redirect, render_template, request, send_file, stream_with_context, url_for

app = Flask(__name__)
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.environ.get("APT_OUTPUT", Path.home() / ".apt" / "output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CASES_INDEX = OUTPUT_DIR / "cases_index.json"
_SETTINGS_PATH = Path(os.environ.get("APT_SETTINGS", "/opt/apt/settings.json"))
_COOKIE_NAME = "apt_session"
_VALID_CASE_ID = re.compile(r'^APT-\d{8}-\d{6}$')
_VALID_FMT     = {"txt", "json", "pdf"}

_IN_PROGRESS = {"discovery", "enumeration", "vulnscan", "webscan", "credtest", "exploitation", "reporting"}

# Thread lock for active_cases dict (modified by Flask threads + background workers)
_cases_lock = threading.Lock()


# ── Settings & auth ───────────────────────────────────────────────────────────

def _load_settings() -> dict:
    if _SETTINGS_PATH.exists():
        try:
            return json.loads(_SETTINGS_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_settings(data: dict):
    _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_PATH.write_text(json.dumps(data, indent=2))
    _SETTINGS_PATH.chmod(0o600)
    _SETTINGS_PATH.parent.chmod(0o755)


def _get_access_token() -> str:
    """Return the access token, generating and persisting one on first run."""
    s = _load_settings()
    if s.get("api_key"):
        os.environ["ANTHROPIC_API_KEY"] = s["api_key"]
    if s.get("access_token"):
        return s["access_token"]
    # First run — generate and persist
    token = secrets.token_hex(24)
    s["access_token"] = token
    _save_settings(s)
    logger.warning("=" * 60)
    logger.warning("APT ACCESS TOKEN (required to log in):")
    logger.warning(f"  {token}")
    logger.warning(f"  Token also saved to: {_SETTINGS_PATH}")
    logger.warning("=" * 60)
    return token


def _init_secret_key() -> str:
    """Load or generate a persistent Flask secret key."""
    s = _load_settings()
    if s.get("flask_secret"):
        return s["flask_secret"]
    key = secrets.token_hex(32)
    s["flask_secret"] = key
    _save_settings(s)
    return key


app.secret_key = _init_secret_key()
_ACCESS_TOKEN = _get_access_token()


def _require_auth(f):
    """Decorator: require valid session cookie or X-APT-Token header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token_cookie = request.cookies.get(_COOKIE_NAME, "")
        token_header = request.headers.get("X-APT-Token", "")
        if not secrets.compare_digest(token_cookie, _ACCESS_TOKEN) and \
           not secrets.compare_digest(token_header, _ACCESS_TOKEN):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ── Persistence ───────────────────────────────────────────────────────────────


def _load_cases() -> dict:
    if CASES_INDEX.exists():
        try:
            cases = json.loads(CASES_INDEX.read_text())
            for cid, c in cases.items():
                findings_path = OUTPUT_DIR / cid / "findings.json"
                report_path = OUTPUT_DIR / cid / "apt_report.txt"
                if report_path.exists():
                    c["status"] = "complete"
                    if not c.get("findings") and findings_path.exists():
                        try:
                            c["findings"] = json.loads(findings_path.read_text())
                        except Exception:
                            pass
                elif c.get("status") in _IN_PROGRESS:
                    c["status"] = "interrupted"
                    c["error"] = "Service restarted during scan"
                c.setdefault("log", [])
            return cases
        except Exception:
            pass
    return {}


def _save_cases():
    with _cases_lock:
        slim = {}
        for cid, c in active_cases.items():
            entry = {}
            for k, v in c.items():
                if k in ("log",):
                    continue
                try:
                    json.dumps(v, default=str)
                    entry[k] = v
                except Exception:
                    entry[k] = str(v)
            slim[cid] = entry
    try:
        CASES_INDEX.write_text(json.dumps(slim, indent=2, default=str))
        CASES_INDEX.chmod(0o600)
    except Exception as e:
        logger.warning(f"Failed to save cases index: {e}")


active_cases: dict = _load_cases()


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_async(coro):
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_until_complete, args=(coro,), daemon=True)
    t.start()
    return t


# ── Routes: Login ─────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        if secrets.compare_digest(token, _ACCESS_TOKEN):
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie(_COOKIE_NAME, token, httponly=True, samesite="Strict", max_age=86400 * 30)
            return resp
        error = "Invalid access token."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login_page")))
    resp.delete_cookie(_COOKIE_NAME)
    return resp


# ── Routes: Pages ─────────────────────────────────────────────────────────────

@app.route("/sw.js")
def service_worker():
    """Serve service worker from root so it has full-scope cache control."""
    from flask import send_from_directory
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), "static"),
        "sw.js",
        mimetype="application/javascript",
    )


@app.route("/")
@_require_auth
def index():
    return render_template("index.html")


@app.route("/scan")
@_require_auth
def scan_page():
    return render_template("scan.html")


@app.route("/cases")
@_require_auth
def cases_page():
    return render_template("cases.html")


@app.route("/report/<case_id>")
@_require_auth
def report_page(case_id):
    if not _VALID_CASE_ID.match(case_id):
        return "Invalid case ID", 400
    return render_template("report.html", case_id=case_id)


@app.route("/settings")
@_require_auth
def settings_page():
    return render_template("settings.html")


# ── API: Tool status ──────────────────────────────────────────────────────────

@app.route("/api/tool-status")
@_require_auth
def tool_status():
    import shutil
    import os as _os
    is_root = _os.getuid() == 0
    tools = [
        {"name": "nmap",          "required": True,  "desc": "Host discovery & vulnerability scanning"},
        {"name": "hydra",         "required": True,  "desc": "Credential brute force testing"},
        {"name": "msfconsole",    "required": False, "desc": "Metasploit exploitation (aggressive mode only)"},
        {"name": "nikto",         "required": False, "desc": "Web application scanning"},
        {"name": "enum4linux-ng", "required": False, "desc": "SMB/AD enumeration (also: enum4linux)"},
        {"name": "netexec",       "required": False, "desc": "Windows network enumeration (also: crackmapexec, cme)"},
        {"name": "whatweb",       "required": False, "desc": "Web technology fingerprinting"},
    ]
    for t in tools:
        t["installed"] = bool(shutil.which(t["name"]))
    # enum4linux aliases
    if not tools[5]["installed"]:
        tools[5]["installed"] = bool(shutil.which("enum4linux"))
    # netexec/crackmapexec aliases
    if not tools[6]["installed"]:
        tools[6]["installed"] = bool(shutil.which("crackmapexec") or shutil.which("cme") or shutil.which("nxc"))
    return jsonify({
        "tools": tools,
        "is_root": is_root,
        "root_warning": None if is_root else "Not running as root — nmap OS detection and SYN scanning disabled. Run as root for full capabilities.",
    })


# ── API: Cancel scan ─────────────────────────────────────────────────────────

@app.route("/api/scan/<case_id>/cancel", methods=["POST"])
@_require_auth
def cancel_scan(case_id):
    if not _VALID_CASE_ID.match(case_id):
        return jsonify({"error": "Invalid case ID"}), 400
    with _cases_lock:
        case = active_cases.get(case_id)
        if not case:
            return jsonify({"error": "Case not found"}), 404
        if case.get("status") not in _IN_PROGRESS:
            return jsonify({"ok": True, "note": "Scan already finished"})
        case["status"] = "cancelled"
        case["error"] = "Cancelled by user"
        case["completed_at"] = datetime.now().isoformat()
    _save_cases()
    return jsonify({"ok": True})


# ── API: Network detection ────────────────────────────────────────────────────

@app.route("/api/detect-network")
@_require_auth
def detect_network():
    try:
        from apt.scanner.discovery import get_local_ip, ip_to_subnet
        local_ip = get_local_ip()
        subnet = ip_to_subnet(local_ip) if local_ip else ""
        return jsonify({"local_ip": local_ip, "subnet": subnet})
    except Exception as e:
        return jsonify({"error": str(e), "local_ip": "", "subnet": ""})


# ── API: Start scan ───────────────────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
@_require_auth
def start_scan():
    data = request.json or {}
    subnet = data.get("subnet", "").strip()
    authorized_by = data.get("authorized_by", "").strip()
    authorization_notes = data.get("authorization_notes", "").strip()
    aggression = data.get("aggression", "normal")
    skip_ping = bool(data.get("skip_ping", False))
    enable_creds = bool(data.get("enable_creds", True))
    enable_exploit = bool(data.get("enable_exploit", False))

    if not subnet:
        return jsonify({"error": "No subnet specified"}), 400
    # Validate subnet is proper CIDR notation
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return jsonify({"error": f"Invalid subnet CIDR: {subnet!r}"}), 400
    if aggression not in ("passive", "normal", "aggressive"):
        return jsonify({"error": "Invalid aggression level"}), 400
    if not authorized_by:
        return jsonify({"error": "Authorization name required"}), 400

    case_id = f"APT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    active_cases[case_id] = {
        "case_id": case_id,
        "subnet": subnet,
        "authorized_by": authorized_by,
        "authorization_notes": authorization_notes,
        "aggression": aggression,
        "started_at": datetime.now().isoformat(),
        "status": "discovery",
        "progress": 0,
        "log": [],
        "findings": None,
        "error": None,
    }
    _save_cases()

    run_async(_run_scan(
        case_id, subnet, authorized_by, authorization_notes,
        aggression, skip_ping, enable_creds, enable_exploit,
    ))
    return jsonify({"case_id": case_id, "status": "started"})


# ── Scan pipeline ─────────────────────────────────────────────────────────────

async def _run_scan(case_id, subnet, authorized_by, authorization_notes,
                    aggression, skip_ping, enable_creds, enable_exploit):
    case = active_cases[case_id]
    scan_start = datetime.now().isoformat()

    def log(msg: str, level: str = "info"):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg}
        case["log"].append(entry)

    try:
        os.nice(10)
    except Exception:
        pass

    # Pre-flight checks
    import shutil as _shutil
    is_root = os.getuid() == 0
    if not is_root:
        log("WARNING: Not running as root — nmap OS detection disabled, SYN scan unavailable. Run as root for full capabilities.", "warn")
    if not _shutil.which("nmap"):
        log("WARNING: nmap not found — install with: sudo apt-get install nmap", "warn")
    if not _shutil.which("hydra"):
        log("INFO: hydra not found — credential testing will be skipped. Install: sudo apt-get install hydra", "info")
    log(f"Starting 7-phase automated assessment of {subnet}...", "info")

    discovery_result = None
    enum_results = []
    vuln_results = []
    cred_result = None
    exploit_result = None

    def _is_cancelled():
        return active_cases.get(case_id, {}).get("status") == "cancelled"

    try:
        # Phase 1: Discovery
        log(f"Starting host discovery on {subnet}...")
        case["status"] = "discovery"
        case["progress"] = 5
        from apt.scanner.discovery import discover_hosts
        discovery_result = discover_hosts(
            subnet,
            fast=(aggression != "aggressive"),
            skip_ping=skip_ping,
            log_callback=log,
        )
        if _is_cancelled(): return
        host_count = len(discovery_result.hosts)
        log(f"Discovery complete: {host_count} live host(s) found", "success" if host_count else "warn")
        case["progress"] = 20

        if not discovery_result.hosts:
            log("No hosts found. Verify subnet and network connectivity.", "warn")
            case["status"] = "complete"
            case["progress"] = 100
            _finalize(case, case_id, discovery_result, [], [], None, None,
                      authorized_by, authorization_notes, subnet, scan_start, log)
            return

        # Phase 2: Enumeration
        log(f"Enumerating services on {host_count} host(s)...")
        case["status"] = "enumeration"
        from apt.scanner.enumeration import enumerate_hosts
        enum_results = enumerate_hosts(
            discovery_result.hosts,
            top_ports=(aggression != "aggressive"),
            log_callback=log,
        )
        if _is_cancelled(): return
        log(f"Enumeration complete", "success")
        case["progress"] = 40

        # Phase 3: Vulnerability scan
        log("Scanning for vulnerabilities...")
        case["status"] = "vulnscan"
        from apt.scanner.vulnscan import scan_vulnerabilities
        vuln_results = scan_vulnerabilities(enum_results, log_callback=log)
        if _is_cancelled(): return
        total_vulns = sum(len(r.vulnerabilities) for r in vuln_results)
        log(f"Vulnerability scan complete: {total_vulns} finding(s)", "success" if total_vulns else "info")
        case["progress"] = 60

        # Phase 4: Credential testing
        if enable_creds and aggression in ("normal", "aggressive"):
            log("Testing common credentials...")
            case["status"] = "credtest"
            from apt.scanner.credtest import test_credentials
            cred_result = test_credentials(enum_results, log_callback=log)
            if _is_cancelled(): return
            log(f"Credential testing complete: {len(cred_result.findings)} valid pair(s)",
                "success" if cred_result.findings else "info")
            case["progress"] = 75
        elif not enable_creds:
            log("Credential testing skipped (disabled in options)", "info")

        # Phase 5: Exploitation
        if enable_exploit and aggression == "aggressive":
            log("Attempting exploitation of confirmed vulnerabilities...")
            case["status"] = "exploitation"
            from apt.scanner.exploitation import attempt_exploitation
            exploit_result = attempt_exploitation(vuln_results, cred_result.findings if cred_result else [], log_callback=log)
            if _is_cancelled(): return
            compromised = sum(1 for r in exploit_result.results if r.success)
            log(f"Exploitation complete: {compromised} system(s) compromised",
                "success" if compromised else "info")
            case["progress"] = 88
        elif not enable_exploit:
            log("Exploitation skipped (disabled — set aggression to Aggressive to enable)", "info")

        # Phase 6: Generate report
        log("Generating penetration test report...")
        case["status"] = "reporting"
        case["progress"] = 92
        from apt.reporting.report_gen import generate_report, save_report_json, save_report_text, save_report_pdf
        report = generate_report(
            discovery_result=discovery_result,
            enum_results=enum_results,
            vuln_results=vuln_results,
            cred_result=cred_result,
            exploit_result=exploit_result,
            case_id=case_id,
            authorized_by=authorized_by,
            scope=subnet,
            authorization_notes=authorization_notes,
            scan_start=scan_start,
        )

        case_out = OUTPUT_DIR / case_id
        case_out.mkdir(parents=True, exist_ok=True)
        save_report_json(report, str(case_out / "apt_report.json"))
        save_report_text(report, str(case_out / "apt_report.txt"))
        pdf_path = str(case_out / "apt_report.pdf")
        if not save_report_pdf(report, pdf_path):
            pdf_path = None

        log(f"Report saved — Risk: {report.risk_rating} ({report.risk_score}/100)", "success")

        # Build findings for UI
        with _cases_lock:
            case["findings"] = {
                "risk_score": report.risk_score,
                "risk_rating": report.risk_rating,
                "hosts_discovered": report.hosts_discovered,
                "hosts_vulnerable": report.hosts_vulnerable,
                "critical_vulns": report.critical_vulns,
                "high_vulns": report.high_vulns,
                "medium_vulns": report.medium_vulns,
                "low_vulns": report.low_vulns,
                "credentials_found": report.credentials_found,
                "systems_compromised": report.systems_compromised,
                "hosts": report.hosts,
                "vulnerabilities": report.vulnerabilities,
                # Passwords masked — raw credentials never leave the server
                "credential_findings": [
                    {k: ("*" * len(str(v))) if k == "password" else v
                     for k, v in f.items()}
                    for f in report.credential_findings
                ],
                "exploit_results": report.exploit_results,
                "critical_recommendations": report.critical_recommendations,
                "general_recommendations": report.general_recommendations,
                "phases_completed": report.phases_completed,
                "report_txt": str(case_out / "apt_report.txt"),
                "report_json": str(case_out / "apt_report.json"),
                "report_pdf": pdf_path,
                "subnet": subnet,
                "authorized_by": authorized_by,
            }

        # Save findings to disk (owner read/write only — contains sensitive data)
        try:
            fp = case_out / "findings.json"
            fp.write_text(json.dumps(case["findings"], indent=2, default=str))
            fp.chmod(0o600)
        except Exception as e:
            logger.warning(f"Could not save findings cache: {e}")

        case["status"] = "complete"
        case["progress"] = 100
        case["completed_at"] = datetime.now().isoformat()
        log("Scan complete!", "success")

    except Exception as e:
        case["status"] = "error"
        case["error"] = str(e)
        case["completed_at"] = datetime.now().isoformat()
        log(f"ERROR: {e}", "error")
        logger.exception(f"Scan {case_id} failed")

    finally:
        _save_cases()


def _finalize(case, case_id, discovery_result, enum_results, vuln_results,
              cred_result, exploit_result, authorized_by, auth_notes, subnet, scan_start, log):
    """Build minimal findings when no hosts found."""
    case["findings"] = {
        "risk_score": 0,
        "risk_rating": "Low",
        "hosts_discovered": len(discovery_result.hosts) if discovery_result else 0,
        "hosts_vulnerable": 0,
        "critical_vulns": 0, "high_vulns": 0, "medium_vulns": 0, "low_vulns": 0,
        "credentials_found": 0,
        "systems_compromised": 0,
        "hosts": [], "vulnerabilities": [],
        "credential_findings": [],
        "exploit_results": [],
        "critical_recommendations": [],
        "general_recommendations": ["Verify network connectivity and subnet configuration."],
        "phases_completed": ["discovery"],
        "subnet": subnet,
        "authorized_by": authorized_by,
        "report_txt": None, "report_json": None, "report_pdf": None,
    }
    case["completed_at"] = datetime.now().isoformat()
    _save_cases()


# ── API: Status & streaming ───────────────────────────────────────────────────

@app.route("/api/scan/<case_id>/status")
@_require_auth
def scan_status(case_id):
    if not _VALID_CASE_ID.match(case_id):
        return jsonify({"error": "Invalid case ID"}), 400
    with _cases_lock:
        case = active_cases.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    # Never return raw credentials in findings — mask passwords
    findings = case.get("findings")
    if findings and findings.get("credential_findings_raw"):
        findings = {k: v for k, v in findings.items() if k != "credential_findings_raw"}
    return jsonify({
        "status": case["status"],
        "progress": case.get("progress", 0),
        "log": case["log"][-50:],
        "error": case.get("error"),
        "findings": findings,
    })


@app.route("/api/scan/<case_id>/stream")
@_require_auth
def scan_stream(case_id):
    if not _VALID_CASE_ID.match(case_id):
        return jsonify({"error": "Invalid case ID"}), 400
    import time as _time

    def _gen():
        sent = 0
        while True:
            case = active_cases.get(case_id)
            if not case:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Case not found'})}\n\n"
                return

            logs = case.get("log", [])
            while sent < len(logs):
                entry = logs[sent]
                yield f"data: {json.dumps({'type': 'log', 'level': entry['level'], 'msg': entry['msg'], 'time': entry['time']})}\n\n"
                sent += 1

            status = case.get("status")
            progress = case.get("progress", 0)
            yield f"data: {json.dumps({'type': 'status', 'status': status, 'progress': progress})}\n\n"

            if status in ("complete", "error", "interrupted", "cancelled"):
                yield f"data: {json.dumps({'type': 'done', 'status': status, 'case_id': case_id})}\n\n"
                return

            _time.sleep(0.5)

    return Response(stream_with_context(_gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API: Cases ────────────────────────────────────────────────────────────────

@app.route("/api/cases")
@_require_auth
def list_cases():
    summary = []
    for cid, c in active_cases.items():
        f = c.get("findings") or {}
        summary.append({
            "case_id": cid,
            "subnet": c.get("subnet", ""),
            "authorized_by": c.get("authorized_by", ""),
            "started_at": c.get("started_at", ""),
            "completed_at": c.get("completed_at", ""),
            "status": c.get("status", ""),
            "risk_rating": f.get("risk_rating", ""),
            "risk_score": f.get("risk_score", 0),
            "hosts_discovered": f.get("hosts_discovered", 0),
            "critical_vulns": f.get("critical_vulns", 0),
            "credentials_found": f.get("credentials_found", 0),
            "has_report": bool(f.get("report_txt")),
        })
    return jsonify({"cases": sorted(summary, key=lambda x: x["started_at"] or "", reverse=True)})


@app.route("/api/case/<case_id>/download/<fmt>")
@_require_auth
def download_report(case_id, fmt):
    if not _VALID_CASE_ID.match(case_id):
        return jsonify({"error": "Invalid case ID"}), 400
    if fmt not in _VALID_FMT:
        return jsonify({"error": "Invalid format"}), 400
    with _cases_lock:
        case = active_cases.get(case_id)
    if not case or not case.get("findings"):
        return jsonify({"error": "Report not ready"}), 404
    f = case["findings"]
    path_map = {
        "txt": f.get("report_txt"),
        "json": f.get("report_json"),
        "pdf": f.get("report_pdf"),
    }
    raw_path = path_map.get(fmt)
    if not raw_path:
        if fmt == "pdf":
            return jsonify({"error": "PDF not available — install reportlab: sudo pip3 install reportlab"}), 404
        return jsonify({"error": f"Format '{fmt}' not available"}), 404
    # Path traversal guard: ensure file is within the expected case output dir
    expected_dir = (OUTPUT_DIR / case_id).resolve()
    resolved = Path(raw_path).resolve()
    if not str(resolved).startswith(str(expected_dir)):
        return jsonify({"error": "Access denied"}), 403
    if not resolved.exists():
        return jsonify({"error": f"Report file not found"}), 404
    return send_file(str(resolved), as_attachment=True, download_name=f"APT_{case_id}.{fmt}")


# ── API: Settings ─────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET", "POST"])
@_require_auth
def settings():
    if request.method == "POST":
        data = request.json or {}
        existing = _load_settings()
        # Only allow updating these specific keys
        for key in ("api_key", "examiner_name"):
            if key in data:
                existing[key] = str(data[key])
        _save_settings(existing)
        if existing.get("api_key"):
            os.environ["ANTHROPIC_API_KEY"] = existing["api_key"]
        return jsonify({"ok": True})
    else:
        existing = _load_settings()
        safe = {k: v for k, v in existing.items()
                if k not in ("api_key", "access_token", "flask_secret")}
        if "api_key" in existing:
            safe["api_key_set"] = True
        return jsonify(safe)


def create_app():
    return app


def run_server(host="0.0.0.0", port=5001, debug=False):
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_server(debug=True)
