"""
RFT Web GUI — Flask application
Auto-launches in Chromium kiosk mode for graphical distro use.
Also accessible from any browser on the local network.
"""

import asyncio
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory session store (cases survive until reboot; for persistence use KB)
active_cases: dict[str, dict] = {}

# Output dir for reports
OUTPUT_DIR = Path(os.environ.get("RFT_OUTPUT", Path.home() / ".rft" / "output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ─── Helper: run async in background thread ──────────────────────────────────

def run_async(coro):
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_until_complete, args=(coro,), daemon=True)
    t.start()
    return t


# ─── Routes: Pages ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze")
def analyze_page():
    return render_template("analyze.html")


@app.route("/cases")
def cases_page():
    return render_template("cases.html")


@app.route("/report/<case_id>")
def report_page(case_id):
    case = active_cases.get(case_id, {})
    return render_template("report.html", case_id=case_id, case=case)


@app.route("/knowledge")
def knowledge_page():
    return render_template("knowledge.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ─── API: Drive Discovery ──────────────────────────────────────────────────────

@app.route("/api/drives")
def list_drives():
    """Return list of attached drives and their partitions, excluding the OS drive."""
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,MOUNTPOINT,HOTPLUG"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)

        # Find root device to exclude it
        root_result = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "/"],
            capture_output=True, text=True
        )
        root_dev = root_result.stdout.strip().replace("/dev/", "")
        # Strip partition suffix to get disk name: sda1 → sda
        root_disk = root_dev.rstrip("0123456789")

        drives = []
        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            if dev["name"] == root_disk or dev["name"] in root_dev:
                continue  # Skip OS drive

            disk_device = f"/dev/{dev['name']}"
            partitions = dev.get("children", [])

            if partitions:
                # Offer each mountable partition individually
                for p in partitions:
                    if p.get("type") not in ("part", "lvm"):
                        continue
                    drives.append({
                        "device": f"/dev/{p['name']}",
                        "size": p.get("size", "?"),
                        "model": f"{dev.get('model', 'Drive')} — partition {p['name']}",
                        "fstype": p.get("fstype") or "unknown",
                        "label": p.get("label") or "",
                        "mounted": bool(p.get("mountpoint")),
                        "parent_disk": disk_device,
                    })
            else:
                # No partitions — offer the raw disk
                drives.append({
                    "device": disk_device,
                    "size": dev.get("size", "?"),
                    "model": dev.get("model") or "Unknown Drive",
                    "fstype": dev.get("fstype") or "unknown",
                    "label": dev.get("label") or "",
                    "mounted": bool(dev.get("mountpoint")),
                    "parent_disk": disk_device,
                })

        return jsonify({"drives": drives, "error": None})
    except Exception as e:
        return jsonify({"drives": [], "error": str(e)})


# ─── API: Start Analysis ───────────────────────────────────────────────────────

@app.route("/api/analyze/start", methods=["POST"])
def start_analysis():
    """Begin forensic analysis of a selected drive."""
    data = request.json or {}
    device = data.get("device")
    use_ai = data.get("use_ai", True)
    acquire_image = data.get("acquire_image", False)
    skip_hash = data.get("skip_hash", False)

    if not device:
        return jsonify({"error": "No device specified"}), 400

    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    active_cases[case_id] = {
        "case_id": case_id,
        "device": device,
        "started_at": datetime.now().isoformat(),
        "status": "mounting",
        "progress": 0,
        "log": [],
        "findings": None,
        "error": None,
        "use_ai": use_ai,
        "skip_hash": skip_hash,
    }

    # Run analysis in background thread
    run_async(_run_analysis(case_id, device, use_ai, acquire_image, skip_hash))

    return jsonify({"case_id": case_id, "status": "started"})


async def _run_analysis(case_id: str, device: str, use_ai: bool, acquire_image: bool, skip_hash: bool = False):
    """Full analysis pipeline — runs in background thread."""
    case = active_cases[case_id]

    def log(msg: str, level: str = "info"):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg}
        case["log"].append(entry)

    try:
        # Step 1: Mount drive read-only
        log(f"Mounting {device} with write protection...")
        case["status"] = "mounting"
        case["progress"] = 5

        from rft.forensics.safe_mount import mount_drive_readonly
        if skip_hash:
            log("Quick Mode: skipping SHA-256 hash (chain of custody not established)", "warn")
        mounted = mount_drive_readonly(device, "/mnt/forensics", case_id, skip_hash=skip_hash)
        if not mounted:
            raise RuntimeError(f"Failed to mount {device} — unknown error")

        log(f"Drive mounted at {mounted.mount_point}", "success")
        log(f"SHA-256: {mounted.hash_before[:16]}...", "info")
        case["progress"] = 15
        case["mount_point"] = mounted.mount_point
        case["hash_before"] = mounted.hash_before

        # Optional: acquire image
        if acquire_image:
            log("Acquiring forensic image (DD)...")
            case["status"] = "imaging"
            from rft.forensics.disk_image import acquire_image as do_image
            img_record = do_image(device, str(OUTPUT_DIR / case_id), case_id)
            if img_record:
                log(f"Image saved: {img_record.image_path}", "success")
                case["image_path"] = img_record.image_path
            case["progress"] = 30

        # Step 2: Collect artifacts
        log("Scanning for ransomware artifacts...")
        case["status"] = "collecting"
        case["progress"] = 35

        from rft.forensics.artifact_collector import collect_artifacts
        case_output_dir = str(OUTPUT_DIR / case_id)
        Path(case_output_dir).mkdir(parents=True, exist_ok=True)
        collection = collect_artifacts(mounted.mount_point, case_output_dir)

        log(f"Found {len(collection.ransom_notes)} ransom note(s)", "success" if collection.ransom_notes else "warn")
        log(f"Found {len(collection.encrypted_files)} encrypted file(s)")
        log(f"Found {len(collection.event_logs)} Windows Event Log(s)")
        case["progress"] = 50

        # Step 3: Extract IOCs
        log("Extracting IOCs (wallets, IPs, Tor addresses)...")
        case["status"] = "extracting_iocs"

        from rft.analysis.ioc_extractor import extract_iocs
        note_texts = [
            Path(n.absolute_path).read_text(errors="replace")
            for n in collection.ransom_notes[:5]
        ]
        ioc_report = extract_iocs(note_texts)

        family = ioc_report.identified_family
        log(f"Family identified: {family or 'Unknown'}", "success" if family else "warn")
        log(f"Bitcoin wallets: {len(ioc_report.bitcoin_addresses)}")
        log(f"Tor addresses: {len(ioc_report.tor_addresses)}")
        case["progress"] = 60

        # Step 4: Event log analysis
        log_analysis = None
        if collection.event_logs:
            log("Analyzing Windows Event Logs...")
            case["status"] = "analyzing_logs"
            from rft.analysis.log_analyzer import analyze_event_logs
            evtx_paths = [a.absolute_path for a in collection.event_logs]
            log_analysis = analyze_event_logs(evtx_paths)
            log(f"Attack timeline: {len(log_analysis.timeline)} events")
            log(f"Failed logons: {log_analysis.failed_logon_count}")
        case["progress"] = 70

        # Step 5: Synthesis
        log("Synthesizing attack chain...")
        case["status"] = "synthesizing"
        from rft.analysis.ransomware_analyzer import analyze_ransomware_incident
        analysis = analyze_ransomware_incident(collection, log_analysis, ioc_report, case_id)

        log(f"Attack vector: {analysis.attack_vector.primary_vector if analysis.attack_vector else 'unknown'}", "success")
        log(f"Encrypted scope: {analysis.estimated_files_encrypted} files")
        case["progress"] = 75

        # Step 5b: Shadow Copy Recovery
        log("Scanning for surviving shadow copies (VSS)...")
        case["status"] = "shadow_copies"
        shadow_result = None
        try:
            from rft.forensics.shadow_copy import scan_shadow_copies
            shadow_result = scan_shadow_copies(mounted.mount_point, str(OUTPUT_DIR / case_id))
            if shadow_result.snapshots_found > 0:
                log(f"Found {shadow_result.snapshots_found} VSS snapshot(s)!", "success")
                if shadow_result.vss_deletion_failed:
                    log("Attacker tried to delete shadow copies but FAILED — files may be recoverable!", "success")
                if shadow_result.recovered_files:
                    log(f"Recovered {len(shadow_result.recovered_files)} files from shadow copies", "success")
            elif shadow_result.vss_deleted:
                log("Attacker successfully deleted all shadow copies", "warn")
            else:
                log("No shadow copies found on this volume", "info")
        except Exception as e:
            log(f"Shadow copy scan skipped: {e}", "warn")

        # Step 5c: Attack Timeline
        log("Building attack timeline...")
        case["status"] = "timeline"
        timeline_result = None
        try:
            from rft.forensics.timeline import build_attack_timeline
            timeline_result = build_attack_timeline(
                mounted.mount_point,
                str(OUTPUT_DIR / case_id),
                log_analysis=log_analysis,
                collection=collection,
            )
            if timeline_result.encryption_start_time:
                log(f"Encryption started: {timeline_result.encryption_start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", "success")
            if timeline_result.patient_zero_path:
                log(f"Patient zero (first encrypted file): {Path(timeline_result.patient_zero_path).name}", "success")
            if timeline_result.encryption_duration_minutes:
                log(f"Encryption duration: {timeline_result.encryption_duration_minutes:.0f} minutes")
        except Exception as e:
            log(f"Timeline build skipped: {e}", "warn")

        # Step 5d: Memory analysis
        log("Scanning for memory dumps and hibernation files...")
        case["status"] = "memory_analysis"
        memory_result = None
        try:
            from rft.forensics.memory_analysis import analyze_memory
            memory_result = analyze_memory(
                mounted.mount_point,
                str(OUTPUT_DIR / case_id),
                ransomware_family=analysis.ransomware_family,
            )
            if memory_result.memory_files_found:
                log(f"Memory files found: {len(memory_result.memory_files_found)}", "success")
                if memory_result.potential_keys:
                    log(f"Potential encryption key material found in memory: {len(memory_result.potential_keys)} candidates", "success")
                if memory_result.credentials:
                    log(f"Credentials found in memory: {len(memory_result.credentials)}", "success")
            else:
                log("No memory dumps found (connect a live RAM dump for key recovery)", "info")
        except Exception as e:
            log(f"Memory analysis skipped: {e}", "warn")

        # Step 5e: Deleted file recovery
        log("Attempting deleted file recovery from unallocated space...")
        case["status"] = "file_recovery"
        recovery_result = None
        try:
            from rft.forensics.file_recovery import attempt_file_recovery
            recovery_result = attempt_file_recovery(
                device,
                str(OUTPUT_DIR / case_id),
            )
            if recovery_result.total_recovered > 0:
                log(f"Recovered {recovery_result.total_recovered} deleted file(s)!", "success")
            elif recovery_result.mft_deleted_entries:
                log(f"Found {len(recovery_result.mft_deleted_entries)} deleted MFT entries — install ntfsundelete to recover", "warn")
            else:
                log("No recoverable deleted files found", "info")
        except Exception as e:
            log(f"File recovery skipped: {e}", "warn")

        case["progress"] = 80

        # Step 6: AI analysis
        ai_result = None
        if use_ai and os.environ.get("ANTHROPIC_API_KEY"):
            log("Running AI analysis (Claude Opus)... this may take 1-2 minutes")
            case["status"] = "ai_analysis"
            try:
                from rft.ai.engine import AIEngine
                engine = AIEngine()

                def _stream_cb(chunk: str):
                    log(chunk[:120], "ai")

                ai_result = await engine.analyze(analysis, stream_callback=_stream_cb)
                log("AI analysis complete", "success")
            except Exception as e:
                log(f"AI analysis failed: {e}", "warn")
        elif use_ai:
            log("No ANTHROPIC_API_KEY set — skipping AI analysis", "warn")
        case["progress"] = 90

        # Step 7: Generate FBI report
        log("Generating FBI IC3 report...")
        case["status"] = "reporting"
        from rft.reporting.fbi_report import generate_fbi_report
        from rft.reporting.fbi_report import VictimInfo

        victim = VictimInfo(
            name=case.get("victim_name", ""),
            organization=case.get("victim_org", ""),
            email=case.get("victim_email", ""),
            phone=case.get("victim_phone", ""),
            city=case.get("victim_city", ""),
            state=case.get("victim_state", ""),
        )
        report = generate_fbi_report(analysis, ai_result, victim, output_dir=str(OUTPUT_DIR / case_id))
        log(f"Reports saved to: output/{case_id}/", "success")

        # Build findings summary for the UI
        case["findings"] = {
            "family": analysis.ransomware_family or "Unknown",
            "attack_vector": analysis.attack_vector.primary_vector if analysis.attack_vector else "unknown",
            "encrypted_count": analysis.estimated_files_encrypted,
            "ransom_notes": [a.absolute_path for a in collection.ransom_notes],
            "iocs": {
                "bitcoin": [i.value for i in ioc_report.bitcoin_addresses],
                "monero": [i.value for i in ioc_report.monero_addresses],
                "tor": [i.value for i in ioc_report.onion_addresses],
                "emails": [i.value for i in ioc_report.email_addresses],
                "ips": [i.value for i in ioc_report.ip_addresses[:20]],
            },
            "mitre_techniques": [],
            "timeline": [
                {
                    "time": e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp),
                    "event": e.description,
                    "event_id": getattr(e, 'event_id', None),
                }
                for e in (log_analysis.timeline[:30] if log_analysis else [])
            ],
            "ai_summary": ai_result.summary if ai_result else None,
            "critical_facts": ai_result.critical_facts if ai_result else [],
            "recovery_feasibility": analysis.encryption_analysis.decryption_likelihood if analysis.encryption_analysis else "Unknown",
            "recommendations": analysis.recovery_recommendations,
            # Investigation findings
            "shadow_copies": {
                "found": shadow_result.snapshots_found if shadow_result else 0,
                "recovered_files": len(shadow_result.recovered_files) if shadow_result else 0,
                "attacker_tried_delete": shadow_result.vss_deleted if shadow_result else False,
                "deletion_failed": shadow_result.vss_deletion_failed if shadow_result else False,
            } if shadow_result else None,
            "attack_timeline": {
                "encryption_start": timeline_result.encryption_start_time.isoformat() if timeline_result and timeline_result.encryption_start_time else None,
                "encryption_end": timeline_result.encryption_end_time.isoformat() if timeline_result and timeline_result.encryption_end_time else None,
                "duration_minutes": timeline_result.encryption_duration_minutes if timeline_result else None,
                "patient_zero": timeline_result.patient_zero_path if timeline_result else None,
                "total_events": timeline_result.total_events if timeline_result else 0,
                "phases": [{"name": p.name, "description": p.description, "events": len(p.events)} for p in (timeline_result.phases if timeline_result else [])],
            },
            "memory_analysis": {
                "files_found": memory_result.memory_files_found if memory_result else [],
                "potential_keys": len(memory_result.potential_keys) if memory_result else 0,
                "credentials": len(memory_result.credentials) if memory_result else 0,
                "c2_indicators": len(memory_result.c2_indicators) if memory_result else 0,
                "notes": memory_result.notes if memory_result else [],
            } if memory_result else None,
            "file_recovery": {
                "total_recovered": recovery_result.total_recovered if recovery_result else 0,
                "tool_used": recovery_result.tool_used if recovery_result else "",
                "mft_deleted_entries": len(recovery_result.mft_deleted_entries) if recovery_result else 0,
                "notes": recovery_result.notes if recovery_result else [],
            } if recovery_result else None,
            "report_txt": str(OUTPUT_DIR / case_id / f"{case_id}_fbi_report.txt"),
            "report_json": str(OUTPUT_DIR / case_id / f"{case_id}_fbi_report.json"),
            "report_pdf": str(OUTPUT_DIR / case_id / f"{case_id}_fbi_report.pdf"),
        }

        case["status"] = "complete"
        case["progress"] = 100
        log("Analysis complete!", "success")

        # Verify drive integrity
        from rft.forensics.safe_mount import verify_mount_integrity
        intact = verify_mount_integrity(mounted)
        log(f"Drive integrity: {'VERIFIED — no writes occurred' if intact else 'WARNING: hash mismatch!'}",
            "success" if intact else "error")

    except Exception as e:
        case["status"] = "error"
        case["error"] = str(e)
        log(f"ERROR: {e}", "error")


# ─── API: Case Status (polling) ────────────────────────────────────────────────

@app.route("/api/case/<case_id>/status")
def case_status(case_id):
    case = active_cases.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({
        "status": case["status"],
        "progress": case["progress"],
        "log": case["log"][-50:],  # Last 50 log entries
        "error": case.get("error"),
        "findings": case.get("findings"),
    })


# ─── API: Server-Sent Events for real-time log streaming ──────────────────────

@app.route("/api/case/<case_id>/stream")
def case_stream(case_id):
    """SSE endpoint — streams log entries to the browser in real time."""
    def generate():
        last_idx = 0
        while True:
            case = active_cases.get(case_id)
            if not case:
                yield "data: {\"error\": \"case not found\"}\n\n"
                break

            logs = case["log"]
            if len(logs) > last_idx:
                for entry in logs[last_idx:]:
                    yield f"data: {json.dumps(entry)}\n\n"
                last_idx = len(logs)

            if case["status"] in ("complete", "error"):
                yield f"data: {json.dumps({'done': True, 'status': case['status']})}\n\n"
                break

            import time
            time.sleep(0.5)

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── API: Update victim info ───────────────────────────────────────────────────

@app.route("/api/case/<case_id>/victim", methods=["POST"])
def update_victim(case_id):
    case = active_cases.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    data = request.json or {}
    for field in ("victim_name", "victim_org", "victim_email", "victim_phone", "victim_city", "victim_state"):
        if field in data:
            case[field] = data[field]
    return jsonify({"ok": True})


# ─── API: Download report ──────────────────────────────────────────────────────

@app.route("/api/case/<case_id>/download/<fmt>")
def download_report(case_id, fmt):
    case = active_cases.get(case_id)
    if not case or not case.get("findings"):
        return jsonify({"error": "Report not ready"}), 404

    findings = case["findings"]
    path_map = {
        "txt": findings.get("report_txt"),
        "json": findings.get("report_json"),
        "pdf": findings.get("report_pdf"),
    }
    path = path_map.get(fmt)
    if not path or not Path(path).exists():
        return jsonify({"error": f"Report format '{fmt}' not available"}), 404

    return send_file(path, as_attachment=True)


# ─── API: List all cases ───────────────────────────────────────────────────────

@app.route("/api/cases")
def list_cases():
    summary = []
    for cid, c in active_cases.items():
        summary.append({
            "case_id": cid,
            "device": c.get("device"),
            "started_at": c.get("started_at"),
            "status": c.get("status"),
            "family": (c.get("findings") or {}).get("family", "Unknown"),
        })
    return jsonify({"cases": sorted(summary, key=lambda x: x["started_at"], reverse=True)})


# ─── API: Knowledge base stats ────────────────────────────────────────────────

@app.route("/api/knowledge")
def knowledge_stats():
    try:
        from rft.knowledge_base.manager import KnowledgeBase
        kb = KnowledgeBase()
        stats = kb.get_statistics()
        kb.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})


# ─── API: Quick identify from ransom note text ────────────────────────────────

@app.route("/api/identify", methods=["POST"])
def quick_identify():
    data = request.json or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400
    try:
        from rft.analysis.ioc_extractor import extract_iocs
        ioc_report = extract_iocs([text])
        family = ioc_report.identified_family
        return jsonify({
            "family": family,
            "confidence": ioc_report.family_confidence,
            "iocs": {
                "bitcoin": ioc_report.bitcoin_addresses,
                "tor": ioc_report.tor_addresses,
                "emails": ioc_report.email_addresses,
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ─── API: System settings ─────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    settings_path = Path.home() / ".rft" / "settings.json"
    if request.method == "POST":
        data = request.json or {}
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if settings_path.exists():
            existing = json.loads(settings_path.read_text())
        existing.update(data)
        settings_path.write_text(json.dumps(existing, indent=2))
        # Apply API key to environment if provided
        if "api_key" in data:
            os.environ["ANTHROPIC_API_KEY"] = data["api_key"]
        return jsonify({"ok": True})
    else:
        existing = {}
        if settings_path.exists():
            existing = json.loads(settings_path.read_text())
        # Mask API key
        if "api_key" in existing:
            existing["api_key_set"] = True
            del existing["api_key"]
        return jsonify(existing)


def create_app():
    """Application factory."""
    return app


def run_server(host="0.0.0.0", port=5000, debug=False):
    """Start the Flask development server."""
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_server(debug=True)
