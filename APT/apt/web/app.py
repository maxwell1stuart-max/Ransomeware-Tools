"""
APT Web GUI — Flask application
Automated Penetration Toolkit web interface.
Runs on port 5001 (RFT runs on 5000).
"""

import asyncio
import json
import logging
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

app = Flask(__name__)
app.secret_key = os.urandom(24)
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.environ.get("APT_OUTPUT", Path.home() / ".apt" / "output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CASES_INDEX = OUTPUT_DIR / "cases_index.json"
_SETTINGS_PATH = Path("/opt/apt/settings.json")

_IN_PROGRESS = {"discovery", "enumeration", "vulnscan", "webscan", "credtest", "exploitation", "reporting"}


# ── Persistence ───────────────────────────────────────────────────────────────

def _load_settings():
    if _SETTINGS_PATH.exists():
        try:
            s = json.loads(_SETTINGS_PATH.read_text())
            if s.get("api_key"):
                os.environ["ANTHROPIC_API_KEY"] = s["api_key"]
        except Exception:
            pass


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
    slim = {}
    for cid, c in active_cases.items():
        entry = {}
        for k, v in c.items():
            if k == "log":
                continue
            try:
                json.dumps(v, default=str)
                entry[k] = v
            except Exception:
                entry[k] = str(v)
        slim[cid] = entry
    try:
        CASES_INDEX.write_text(json.dumps(slim, indent=2, default=str))
    except Exception as e:
        logger.warning(f"Failed to save cases index: {e}")


_load_settings()
active_cases: dict = _load_cases()


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_async(coro):
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_until_complete, args=(coro,), daemon=True)
    t.start()
    return t


# ── Routes: Pages ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan_page():
    return render_template("scan.html")


@app.route("/cases")
def cases_page():
    return render_template("cases.html")


@app.route("/report/<case_id>")
def report_page(case_id):
    case = active_cases.get(case_id, {})
    return render_template("report.html", case_id=case_id)


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ── API: Network detection ────────────────────────────────────────────────────

@app.route("/api/detect-network")
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
def start_scan():
    data = request.json or {}
    subnet = data.get("subnet", "").strip()
    authorized_by = data.get("authorized_by", "").strip()
    authorization_notes = data.get("authorization_notes", "").strip()
    aggression = data.get("aggression", "normal")   # passive / normal / aggressive
    skip_ping = data.get("skip_ping", False)
    enable_creds = data.get("enable_creds", True)
    enable_exploit = data.get("enable_exploit", False)

    if not subnet:
        return jsonify({"error": "No subnet specified"}), 400
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

    discovery_result = None
    enum_results = []
    vuln_results = []
    cred_result = None
    exploit_result = None

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
        log(f"Enumeration complete", "success")
        case["progress"] = 40

        # Phase 3: Vulnerability scan
        log("Scanning for vulnerabilities...")
        case["status"] = "vulnscan"
        from apt.scanner.vulnscan import scan_vulnerabilities
        vuln_results = scan_vulnerabilities(enum_results, log_callback=log)
        total_vulns = sum(len(r.vulnerabilities) for r in vuln_results)
        log(f"Vulnerability scan complete: {total_vulns} finding(s)", "success" if total_vulns else "info")
        case["progress"] = 60

        # Phase 4: Credential testing
        if enable_creds and aggression in ("normal", "aggressive"):
            log("Testing common credentials...")
            case["status"] = "credtest"
            from apt.scanner.credtest import test_credentials
            cred_result = test_credentials(enum_results, log_callback=log)
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
            "credential_findings": [
                {k: v if k != "password" else "*" * len(v) for k, v in f.items()}
                for f in report.credential_findings
            ],
            "credential_findings_raw": report.credential_findings,
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

        # Save findings to disk
        try:
            (case_out / "findings.json").write_text(
                json.dumps(case["findings"], indent=2, default=str)
            )
        except Exception:
            pass

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
def scan_status(case_id):
    case = active_cases.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({
        "status": case["status"],
        "progress": case.get("progress", 0),
        "log": case["log"][-50:],
        "error": case.get("error"),
        "findings": case.get("findings"),
    })


@app.route("/api/scan/<case_id>/stream")
def scan_stream(case_id):
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

            if status in ("complete", "error", "interrupted"):
                yield f"data: {json.dumps({'type': 'done', 'status': status, 'case_id': case_id})}\n\n"
                return

            _time.sleep(0.5)

    return Response(stream_with_context(_gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API: Cases ────────────────────────────────────────────────────────────────

@app.route("/api/cases")
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
def download_report(case_id, fmt):
    case = active_cases.get(case_id)
    if not case or not case.get("findings"):
        return jsonify({"error": "Report not ready"}), 404
    f = case["findings"]
    path_map = {
        "txt": f.get("report_txt"),
        "json": f.get("report_json"),
        "pdf": f.get("report_pdf"),
    }
    path = path_map.get(fmt)
    if not path or not Path(path).exists():
        if fmt == "pdf":
            return jsonify({"error": "PDF not available — install reportlab: sudo pip3 install reportlab"}), 404
        return jsonify({"error": f"Format '{fmt}' not available"}), 404
    return send_file(path, as_attachment=True, download_name=f"APT_{case_id}.{fmt}")


# ── API: Settings ─────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        data = request.json or {}
        _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if _SETTINGS_PATH.exists():
            try:
                existing = json.loads(_SETTINGS_PATH.read_text())
            except Exception:
                pass
        existing.update(data)
        _SETTINGS_PATH.write_text(json.dumps(existing, indent=2))
        return jsonify({"ok": True})
    else:
        existing = {}
        if _SETTINGS_PATH.exists():
            try:
                existing = json.loads(_SETTINGS_PATH.read_text())
            except Exception:
                pass
        if "api_key" in existing:
            existing["api_key_set"] = True
            del existing["api_key"]
        return jsonify(existing)


def create_app():
    return app


def run_server(host="0.0.0.0", port=5001, debug=False):
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_server(debug=True)
