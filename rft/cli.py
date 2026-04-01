"""
RFT Command-Line Interface

Main entry point for the Ransomware Forensics Toolkit.

Usage:
  sudo rft analyze                   # Full interactive analysis
  sudo rft analyze --device /dev/sdb # Analyze specific device
  sudo rft analyze --image case.dd   # Analyze a disk image
  sudo rft report --case CASE_001    # Regenerate FBI report
  sudo rft learn                     # Show knowledge base stats
  sudo rft export-iocs               # Export IOC feed

Requires root for drive mounting and write-blocking.
"""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt

console = Console()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.version_option(version="1.0.0")
def cli(debug: bool):
    """Ransomware Forensics Toolkit — Evidence-grade ransomware analysis."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command()
@click.option("--device", "-d", default=None, help="Block device to analyze (e.g. /dev/sdb)")
@click.option("--image", "-i", default=None, help="Path to a disk image file (.dd, .E01)")
@click.option("--case-id", "-c", default=None, help="Case identifier (auto-generated if omitted)")
@click.option("--output", "-o", default=None, help="Output directory for artifacts and reports")
@click.option("--no-image", is_flag=True, help="Skip forensic imaging (not recommended)")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis (no API key required)")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", default=None, help="Anthropic API key")
@click.option("--shallow", is_flag=True, help="Quick scan — skip entropy analysis for speed")
def analyze(
    device: str,
    image: str,
    case_id: str,
    output: str,
    no_image: bool,
    no_ai: bool,
    api_key: str,
    shallow: bool,
):
    """
    Full ransomware forensic analysis pipeline.

    Mounts the infected drive read-only, collects artifacts, runs AI analysis,
    and generates an FBI IC3 report.

    Requires root privileges for drive mounting.
    """
    from rft.ui.dashboard import (
        print_banner, print_drive_table, print_mount_status,
        print_collection_summary, print_analysis_findings,
        print_ioc_table, print_log_analysis, print_recommendations,
        prompt_victim_info, stream_ai_analysis, make_analysis_progress,
    )

    print_banner()

    # Generate case ID
    if not case_id:
        case_id = f"CASE_{int(time.time())}"

    # Output directory
    if not output:
        output = str(Path.home() / "rft_cases" / case_id)
    Path(output).mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Case ID:[/] [cyan]{case_id}[/]")
    console.print(f"[bold]Output:[/]  [cyan]{output}[/]\n")

    # ── Step 1: Drive selection ────────────────────────────────────────────────
    mount_point = None
    mount_record = None

    if image:
        # Working from a pre-existing disk image
        console.print(f"[bold]Working from image:[/] [cyan]{image}[/]")
        # Mount the image as a loop device
        mount_point = _mount_image(image, output, case_id)
        if not mount_point:
            console.print("[red]Failed to mount disk image.[/]")
            sys.exit(1)
    else:
        # Working from a live drive
        if os.geteuid() != 0:
            console.print("[red]Error: Root privileges required for drive mounting.[/]")
            console.print("[dim]Run with: sudo rft analyze[/]")
            sys.exit(1)

        from rft.forensics.safe_mount import list_available_drives, mount_drive_readonly

        drives = list_available_drives()
        print_drive_table(drives)

        if not drives:
            console.print("[red]No external drives found. Connect the infected drive and retry.[/]")
            sys.exit(1)

        if device:
            selected_device = device
        else:
            # Interactive selection
            console.print()
            choice = Prompt.ask(
                "[bold]Select drive number to analyze[/]",
                choices=[str(i) for i in range(1, len(drives) + 1)]
            )
            selected_device = drives[int(choice) - 1]["device"]

            # Confirm before proceeding
            console.print(f"\n[bold yellow]⚠ WARNING:[/] You are about to analyze [bold red]{selected_device}[/]")
            console.print("[dim]The drive will be write-protected and mounted read-only.[/]")
            if not Confirm.ask("[bold]Proceed?[/]"):
                console.print("[dim]Aborted.[/]")
                sys.exit(0)

        # ── Step 2: Forensic Imaging (optional but recommended) ───────────────
        if not no_image:
            console.print(f"\n[bold cyan]Creating forensic image of {selected_device}...[/]")
            console.print("[dim]This preserves evidence and may take several minutes.[/]")
            _create_forensic_image(selected_device, output, case_id)

        # ── Step 3: Mount write-protected ─────────────────────────────────────
        console.print(f"\n[bold cyan]Mounting {selected_device} read-only...[/]")
        mounted = mount_drive_readonly(selected_device, output + "/mounts", case_id)
        if not mounted:
            console.print(f"[red]Failed to mount {selected_device}. Check permissions and try again.[/]")
            sys.exit(1)

        mount_record = mounted.record
        mount_point = mounted.record.mount_point
        print_mount_status(
            selected_device,
            mount_point,
            mounted.record.sha256_hash
        )

    # ── Step 4: Artifact collection ────────────────────────────────────────────
    console.print("[bold cyan]Collecting ransomware artifacts...[/]")
    from rft.forensics.artifact_collector import collect_artifacts

    with make_analysis_progress() as progress:
        task = progress.add_task("Scanning filesystem...", total=None)
        collection = collect_artifacts(
            mount_point=mount_point,
            output_dir=output + "/artifacts",
            deep_scan=not shallow,
        )
        progress.update(task, completed=True)

    print_collection_summary(collection)

    # ── Step 5: IOC extraction ─────────────────────────────────────────────────
    console.print("\n[bold cyan]Extracting indicators of compromise...[/]")
    from rft.analysis.ioc_extractor import extract_iocs

    note_texts = [
        (a.content_preview, a.path)
        for a in collection.ransom_notes
        if a.content_preview
    ]
    # Also scan scripts and suspicious files
    script_texts = [
        (Path(a.absolute_path).read_text(errors="replace"), a.path)
        for a in collection.suspicious_scripts[:5]
        if Path(a.absolute_path).exists()
    ]
    ioc_report = extract_iocs(note_texts + script_texts)
    print_ioc_table(ioc_report)

    # ── Step 6: Event log analysis ────────────────────────────────────────────
    console.print("\n[bold cyan]Analyzing Windows Event Logs...[/]")
    from rft.analysis.log_analyzer import analyze_event_logs

    evtx_paths = [a.absolute_path for a in collection.event_logs]
    log_result = analyze_event_logs(evtx_paths)
    print_log_analysis(log_result)

    # ── Step 7: Ransomware analysis synthesis ─────────────────────────────────
    console.print("\n[bold cyan]Synthesizing forensic analysis...[/]")
    from rft.analysis.ransomware_analyzer import analyze_ransomware_incident

    analysis = analyze_ransomware_incident(
        collection=collection,
        log_analysis=log_result,
        ioc_report=ioc_report,
        case_id=case_id,
    )
    print_analysis_findings(analysis)
    print_recommendations(analysis)

    # ── Step 8: AI analysis ────────────────────────────────────────────────────
    ai_result = None
    if not no_ai:
        if not api_key:
            console.print(
                "\n[yellow]⚠ No Anthropic API key found.[/]\n"
                "[dim]Set ANTHROPIC_API_KEY environment variable or use --api-key for AI analysis.[/]\n"
                "[dim]Continuing with rule-based analysis only.[/]"
            )
        else:
            from rft.knowledge_base.manager import KnowledgeBase
            from rft.ai.engine import AIEngine

            kb = KnowledgeBase()
            engine = AIEngine(api_key=api_key, knowledge_base=kb)

            ai_result = asyncio.run(
                stream_ai_analysis(engine, analysis)
            )

            # Store in knowledge base
            if ai_result:
                kb.store_case(
                    case_id=case_id,
                    family=analysis.ransomware_family,
                    attack_vector=analysis.attack_vector.primary_vector if analysis.attack_vector else "unknown",
                    files_encrypted=analysis.estimated_files_encrypted,
                    ai_summary=ai_result.family_assessment[:500] if ai_result else "",
                )
                kb.store_iocs(case_id, ioc_report)
                kb.close()

    # ── Step 9: FBI Report generation ─────────────────────────────────────────
    console.print("\n[bold cyan]Generating FBI IC3 Report...[/]")

    victim_data = prompt_victim_info()

    from rft.reporting.fbi_report import (
        FBIReport, VictimInfo, generate_fbi_report,
        save_report_json, save_report_text, save_report_pdf
    )

    victim = VictimInfo(**victim_data)
    report = generate_fbi_report(
        ransomware_analysis=analysis,
        ai_result=ai_result,
        victim_info=victim,
        examiner="RFT Forensic Toolkit",
    )

    # Save all formats
    reports_dir = Path(output) / "reports"
    reports_dir.mkdir(exist_ok=True)

    json_path = str(reports_dir / f"{case_id}_fbi_report.json")
    txt_path = str(reports_dir / f"{case_id}_fbi_report.txt")
    pdf_path = str(reports_dir / f"{case_id}_fbi_report.pdf")

    save_report_json(report, json_path)
    save_report_text(report, txt_path)
    pdf_saved = save_report_pdf(report, pdf_path)

    console.print()
    console.print("[bold green]═" * 60 + "[/]")
    console.print("[bold green]ANALYSIS COMPLETE[/]")
    console.print("[bold green]═" * 60 + "[/]")
    console.print()
    console.print(f"[bold]Case ID:[/]        [cyan]{case_id}[/]")
    console.print(f"[bold]Artifacts:[/]      [cyan]{output}/artifacts[/]")
    console.print(f"[bold]FBI Report TXT:[/] [cyan]{txt_path}[/]")
    console.print(f"[bold]FBI Report JSON:[/][cyan]{json_path}[/]")
    if pdf_saved:
        console.print(f"[bold]FBI Report PDF:[/] [cyan]{pdf_path}[/]")
    console.print()
    console.print("[bold red]NEXT STEPS:[/]")
    console.print("  1. [bold]File IC3 complaint at:[/] [link=https://www.ic3.gov]https://www.ic3.gov[/link]")
    console.print("  2. [bold]Report to CISA at:[/]    [link=https://www.cisa.gov/report]https://www.cisa.gov/report[/link]")
    console.print("  3. [bold]Check for free decryptors:[/] [link=https://www.nomoreransom.org]https://www.nomoreransom.org[/link]")
    console.print()


@cli.command()
def learn():
    """Show knowledge base statistics."""
    from rft.knowledge_base.manager import KnowledgeBase
    from rft.ui.dashboard import print_kb_stats
    from rft.ui.dashboard import print_banner

    print_banner()

    with KnowledgeBase() as kb:
        stats = kb.get_statistics()
        print_kb_stats(stats)


@cli.command()
@click.option("--output", "-o", default="rft_ioc_feed.json", help="Output file path")
@click.option("--types", "-t", multiple=True, default=None,
              help="IOC types to export (bitcoin, onion, email, ip, domain)")
def export_iocs(output: str, types: tuple):
    """Export all tracked IOCs as a STIX-compatible JSON feed."""
    from rft.knowledge_base.manager import KnowledgeBase

    with KnowledgeBase() as kb:
        ioc_types = list(types) if types else None
        count = kb.export_ioc_feed(output, ioc_types)
        console.print(f"[green]Exported {count} IOCs to {output}[/]")


@cli.command()
@click.argument("note_file")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", default=None)
def identify(note_file: str, api_key: str):
    """Quick-identify ransomware family from a ransom note file."""
    note_path = Path(note_file)
    if not note_path.exists():
        console.print(f"[red]File not found: {note_file}[/]")
        sys.exit(1)

    note_text = note_path.read_text(errors="replace")

    # Rule-based identification first
    from rft.analysis.ioc_extractor import identify_ransomware_family, extract_iocs
    family_result = identify_ransomware_family(note_text)

    console.print(f"\n[bold]Rule-Based Analysis:[/]")
    if family_result:
        family, confidence = family_result
        console.print(f"  Family: [bold red]{family}[/] ({confidence:.0%} confidence)")
    else:
        console.print("  [dim]Family not identified by rule engine.[/]")

    ioc_report = extract_iocs([(note_text, note_file)])
    console.print(f"\n[bold]IOCs Extracted:[/]")
    ioc_summary = ioc_report.summary()
    for k, v in ioc_summary.items():
        if v > 0 and k != "total":
            console.print(f"  {k}: {v}")

    # AI analysis if API key available
    if api_key:
        console.print(f"\n[bold cyan]AI Analysis (Claude)...[/]")
        from rft.ai.engine import AIEngine
        engine = AIEngine(api_key=api_key)
        result = asyncio.run(engine.analyze_ransom_note(note_text))
        console.print(json.dumps(result, indent=2))


def _create_forensic_image(device: str, output_dir: str, case_id: str) -> None:
    """Create a forensic image of the device."""
    from rft.forensics.disk_image import acquire_image
    from rich.progress import Progress, SpinnerColumn, TextColumn

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
        task = p.add_task(f"Imaging {device}...", total=None)
        record = acquire_image(
            source_device=device,
            output_dir=output_dir + "/images",
            case_id=case_id,
            image_format="dd",
        )
        p.update(task, completed=True)

    if record:
        if record.integrity_ok:
            console.print(f"[green]✓ Image created and verified: {record.image_path}[/]")
        else:
            console.print(f"[red]⚠ Image integrity check FAILED — evidence may be compromised[/]")
    else:
        console.print("[yellow]⚠ Imaging failed — continuing with live drive analysis[/]")


def _mount_image(image_path: str, output_dir: str, case_id: str) -> str:
    """Mount a disk image as a loop device for analysis."""
    import subprocess
    from pathlib import Path

    mount_point = Path(output_dir) / "mounts" / case_id / "image_0"
    mount_point.mkdir(parents=True, exist_ok=True)

    # Attempt to mount as loop device
    result = subprocess.run(
        ["mount", "-o", "loop,ro,noatime", image_path, str(mount_point)],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        return str(mount_point)

    # Try with offset for partition images
    console.print(f"[yellow]Direct mount failed: {result.stderr.strip()}[/]")
    console.print("[dim]Trying kpartx for partition images...[/]")

    kpartx = subprocess.run(
        ["kpartx", "-av", image_path],
        capture_output=True, text=True
    )
    if kpartx.returncode == 0:
        # Find the mapped device
        import re
        m = re.search(r"loop(\d+)p1", kpartx.stdout)
        if m:
            loop_dev = f"/dev/mapper/loop{m.group(1)}p1"
            subprocess.run(["mount", "-o", "ro,noatime", loop_dev, str(mount_point)])
            return str(mount_point)

    return None


def main():
    cli()


if __name__ == "__main__":
    main()
