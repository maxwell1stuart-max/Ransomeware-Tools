"""
RFT Terminal Dashboard

Rich-powered interactive TUI for the Ransomware Forensics Toolkit.
Designed for a Raspberry Pi connected to a small HDMI display,
or any terminal over SSH.

Layout:
  ┌─────────────────────────────────────────────────────────┐
  │  RFT — Ransomware Forensics Toolkit v1.0                │
  ├──────────────┬──────────────────────────────────────────┤
  │ DRIVES       │ ANALYSIS STATUS                          │
  │ [sdb] 500GB  │ ● Mount verified (SHA-256)               │
  │ [sdc] 1TB    │ ● Artifacts collected (847 files)        │
  │              │ ● Event logs parsed                      │
  ├──────────────┴──────────────────────────────────────────┤
  │ FINDINGS                                                │
  │ Family: LockBit 3.0 (92% confidence)                    │
  │ Vector: RDP Brute Force (192.168.1.105)                 │
  │ IOCs: 1 BTC wallet, 2 onion addresses, 3 IPs            │
  ├─────────────────────────────────────────────────────────┤
  │ AI ANALYSIS STREAM                                      │
  │ > Analyzing attack chain...                             │
  └─────────────────────────────────────────────────────────┘

Requires: rich >= 13.7.0
"""

import asyncio
import time
from typing import Optional

from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn, TimeElapsedColumn)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


def print_banner() -> None:
    """Print the RFT startup banner."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold red]██████╗ ███████╗████████╗[/]\n"
            "[bold red]██╔══██╗██╔════╝╚══██╔══╝[/]\n"
            "[bold red]██████╔╝█████╗     ██║   [/]\n"
            "[bold red]██╔══██╗██╔══╝     ██║   [/]\n"
            "[bold red]██║  ██║██║        ██║   [/]\n"
            "[bold red]╚═╝  ╚═╝╚═╝        ╚═╝   [/]\n"
            "\n[bold white]Ransomware Forensics Toolkit v1.0[/]\n"
            "[dim]Raspberry Pi Edition — Forensic Analysis Platform[/]\n"
            "[dim]Evidence-grade. Chain-of-custody enabled. AI-powered.[/]",
            justify="center"
        ),
        title="[bold red]RFT[/]",
        border_style="red",
        padding=(1, 4),
    ))
    console.print()


def print_drive_table(drives: list[dict]) -> None:
    """Display available drives in a formatted table."""
    if not drives:
        console.print("[yellow]No external drives detected.[/]")
        console.print("[dim]Connect the infected drive via USB and re-run.[/]")
        return

    table = Table(
        title="[bold]Available Drives[/] — [red]NEVER mount without write-blocking[/]",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Device", style="bold white")
    table.add_column("Model", style="cyan")
    table.add_column("Size", style="green", justify="right")
    table.add_column("Partitions", style="yellow")

    for i, drive in enumerate(drives, 1):
        partitions = ", ".join(
            f"{p['device']} ({p.get('fstype', '?')})"
            for p in drive.get("partitions", [])
        ) or "None detected"
        table.add_row(
            str(i),
            drive["device"],
            drive.get("model", "Unknown"),
            drive.get("size", "Unknown"),
            partitions,
        )

    console.print(table)


def print_mount_status(device: str, mount_point: str, sha256: str) -> None:
    """Print drive mount status."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"[bold green]✓ Drive Mounted Read-Only (Write-Blocked)[/]\n\n"
            f"[bold]Device:[/]      [cyan]{device}[/]\n"
            f"[bold]Mount Point:[/] [cyan]{mount_point}[/]\n"
            f"[bold]SHA-256:[/]     [dim]{sha256[:32]}...[/]\n\n"
            f"[dim]Chain of custody hash recorded. Drive is write-protected.[/]"
        ),
        title="[green]Mount Status[/]",
        border_style="green",
    ))
    console.print()


def make_analysis_progress() -> Progress:
    """Create a Rich progress display for the analysis pipeline."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_collection_summary(result) -> None:
    """Print artifact collection results."""
    table = Table(
        title="[bold]Artifact Collection Results[/]",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
    )
    table.add_column("Artifact Type", style="bold")
    table.add_column("Count", justify="right", style="bold green")
    table.add_column("Status")

    rows = [
        ("Ransom Notes", result.ransom_notes, "red" if result.ransom_notes else "dim"),
        ("Encrypted File Samples", result.encrypted_files, "yellow"),
        ("Windows Event Logs", result.event_logs, "cyan"),
        ("Registry Hives", result.registry_hives, "cyan"),
        ("Suspicious Scripts", result.suspicious_scripts, "yellow"),
        ("Scheduled Tasks", result.scheduled_tasks, "dim"),
        ("Errors", result.errors, "red" if result.errors else "green"),
    ]

    for name, items, color in rows:
        count = len(items)
        status = (
            "[green]✓ Collected[/]" if count > 0
            else "[dim]Not found[/]"
        )
        if name == "Errors" and count > 0:
            status = "[red]⚠ See log[/]"
        table.add_row(
            f"[{color}]{name}[/]",
            f"[{color}]{count}[/]",
            status
        )

    console.print(table)


def print_analysis_findings(analysis) -> None:
    """Print the ransomware analysis findings in a rich panel."""
    ioc = analysis.ioc_report

    # Family identification
    family_text = (
        f"[bold red]{analysis.ransomware_family}[/]"
        if analysis.ransomware_family
        else "[dim]Unknown[/]"
    )
    confidence_bar = "█" * int(analysis.family_confidence * 20) + "░" * (20 - int(analysis.family_confidence * 20))
    confidence_color = (
        "green" if analysis.family_confidence > 0.7
        else "yellow" if analysis.family_confidence > 0.4
        else "red"
    )

    content = Text()
    content.append("RANSOMWARE IDENTIFICATION\n", style="bold cyan underline")
    content.append(f"  Family:     ", style="bold")
    content.append(f"{analysis.ransomware_family or 'Unknown'}\n", style="bold red")
    content.append(f"  Variant:    ", style="bold")
    content.append(f"{analysis.ransomware_variant or 'Unknown'}\n", style="yellow")
    content.append(f"  Confidence: ", style="bold")
    content.append(f"[{confidence_bar}] {analysis.family_confidence:.0%}\n", style=confidence_color)

    content.append("\nATTACK VECTOR\n", style="bold cyan underline")
    if analysis.attack_vector:
        av = analysis.attack_vector
        content.append(f"  Method:     ", style="bold")
        content.append(f"{av.primary_vector}\n", style="red")
        content.append(f"  Confidence: ", style="bold")
        content.append(f"{av.confidence:.0%}\n", style="yellow")
        if av.initial_ip:
            content.append(f"  Source IP:  ", style="bold")
            content.append(f"{av.initial_ip}\n", style="red bold")
        for evidence in av.supporting_evidence[:3]:
            content.append(f"  Evidence:   {evidence}\n", style="dim")

    content.append("\nENCRYPTION\n", style="bold cyan underline")
    if analysis.encryption_analysis:
        enc = analysis.encryption_analysis
        content.append(f"  Algorithm:  ", style="bold")
        content.append(f"{', '.join(enc.detected_algorithms)}\n", style="yellow")
        content.append(f"  Decryption: ", style="bold")
        content.append(f"{enc.decryption_likelihood}\n",
                       style="red" if "unlikely" in enc.decryption_likelihood else "green")

    content.append("\nINDICATORS OF COMPROMISE\n", style="bold cyan underline")
    ioc_items = [
        ("Bitcoin Wallets", ioc.bitcoin_addresses, "yellow"),
        ("Tor Addresses", ioc.onion_addresses, "magenta"),
        ("Contact Emails", ioc.email_addresses, "cyan"),
        ("External IPs", ioc.ip_addresses, "red"),
    ]
    for name, items, color in ioc_items:
        count = len(items)
        if count > 0:
            content.append(f"  {name}: ", style="bold")
            content.append(f"{count} found\n", style=color)
            for item in items[:2]:
                content.append(f"    → {item.value[:60]}\n", style=f"dim {color}")

    console.print(Panel(
        content,
        title="[bold]Forensic Analysis Findings[/]",
        border_style="red",
        padding=(1, 2),
    ))


def print_ioc_table(ioc_report) -> None:
    """Print all IOCs in a formatted table."""
    all_iocs = ioc_report.all_iocs()
    if not all_iocs:
        console.print("[dim]No IOCs extracted.[/]")
        return

    table = Table(
        title=f"[bold]Indicators of Compromise[/] — {len(all_iocs)} total",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="red",
    )
    table.add_column("Type", style="bold cyan", width=20)
    table.add_column("Value", style="white", max_width=60)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Source", style="dim", max_width=20)

    type_styles = {
        "bitcoin_address": "yellow",
        "monero_address": "yellow",
        "onion_address": "magenta",
        "email_address": "cyan",
        "ipv4_address": "red",
        "ransomware_family": "bold red",
    }

    for ioc in all_iocs:
        style = type_styles.get(ioc.ioc_type, "white")
        conf_bar = "●" * round(ioc.confidence * 5)
        table.add_row(
            f"[{style}]{ioc.ioc_type.replace('_', ' ').title()}[/]",
            f"[{style}]{ioc.value[:60]}[/]",
            f"[green]{conf_bar}[/] {ioc.confidence:.0%}",
            ioc.source_file[:20],
        )

    console.print(table)


def print_log_analysis(log_result) -> None:
    """Print event log analysis highlights."""
    console.print()
    console.print(Rule("[bold cyan]Event Log Analysis[/]"))

    stats = log_result.stats

    # Summary table
    table = Table(box=box.SIMPLE_HEAD, header_style="bold")
    table.add_column("Finding")
    table.add_column("Count", justify="right")
    table.add_column("Severity")

    data = [
        ("Successful Logon Events", stats.get("total_logon_events", 0), "dim"),
        ("Failed Logon Events", stats.get("total_failed_logons", 0),
         "red" if stats.get("total_failed_logons", 0) > 10 else "yellow"),
        ("Security Logs Cleared", stats.get("logs_cleared", 0),
         "bold red" if stats.get("logs_cleared", 0) > 0 else "dim"),
        ("New Services Installed", stats.get("new_services", 0),
         "red" if stats.get("new_services", 0) > 0 else "dim"),
        ("PowerShell Executions", stats.get("powershell_executions", 0),
         "yellow" if stats.get("powershell_executions", 0) > 0 else "dim"),
        ("New User Accounts", stats.get("new_accounts", 0),
         "red" if stats.get("new_accounts", 0) > 0 else "dim"),
        ("RDP Sessions", stats.get("rdp_sessions", 0),
         "yellow" if stats.get("rdp_sessions", 0) > 0 else "dim"),
    ]

    for name, count, style in data:
        severity_icon = "🔴" if "red" in style else "🟡" if "yellow" in style else "⚪"
        table.add_row(f"[{style}]{name}[/]", f"[{style}]{count}[/]", severity_icon)

    console.print(table)

    # Brute force IPs
    bf_ips = stats.get("brute_force_ips", {})
    if bf_ips:
        console.print(f"\n[bold red]⚠ BRUTE FORCE IPs DETECTED:[/]")
        for ip, count in sorted(bf_ips.items(), key=lambda x: -x[1]):
            console.print(f"  [red]{ip}[/] — {count} failed logons")


async def stream_ai_analysis(
    ai_engine,
    analysis,
    on_complete=None
) -> None:
    """Stream AI analysis output to terminal in real time."""
    console.print()
    console.print(Rule("[bold magenta]AI Forensic Analysis — Claude Opus 4.6[/]"))
    console.print("[dim]Analyzing with extended reasoning enabled...[/]")
    console.print()

    buffer = ""

    async def display_chunk(chunk: str):
        nonlocal buffer
        buffer += chunk
        console.print(chunk, end="", highlight=False)

    try:
        result = await ai_engine.analyze(
            analysis,
            stream_callback=display_chunk
        )
        console.print()
        console.print()
        if on_complete:
            on_complete(result)
        return result
    except Exception as e:
        console.print(f"\n[red]AI analysis error: {e}[/]")
        console.print("[dim]Continuing with rule-based analysis only.[/]")
        return None


def print_recommendations(analysis) -> None:
    """Print recovery recommendations."""
    console.print()
    console.print(Rule("[bold yellow]Recovery Recommendations[/]"))

    for rec in analysis.recovery_recommendations:
        # Color code by urgency
        if "FBI" in rec or "REPORT" in rec:
            console.print(f"  [bold red]{rec}[/]")
        elif "DO NOT" in rec or "NEVER" in rec:
            console.print(f"  [bold red]{rec}[/]")
        elif "immediately" in rec.lower() or "isolate" in rec.lower():
            console.print(f"  [yellow]{rec}[/]")
        else:
            console.print(f"  [white]{rec}[/]")


def print_kb_stats(stats: dict) -> None:
    """Print knowledge base statistics."""
    table = Table(
        title="[bold]Knowledge Base Statistics[/]",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
    )
    table.add_column("Metric")
    table.add_column("Value", justify="right", style="bold green")

    table.add_row("Known Ransomware Families", str(stats.get("families", 0)))
    table.add_row("Analyzed Cases", str(stats.get("cases", 0)))
    table.add_row("Tracked IOCs", str(stats.get("iocs", 0)))
    table.add_row("MITRE Technique Observations", str(stats.get("mitre_techniques", 0)))

    console.print(table)

    if stats.get("top_families"):
        console.print("\n[bold]Most Seen Families:[/]")
        for f in stats["top_families"]:
            console.print(f"  {f['family']}: {f['count']} case(s)")


def prompt_victim_info() -> dict:
    """Interactive prompt to collect victim information for the FBI report."""
    console.print()
    console.print(Panel(
        "[bold]Victim Information Required for FBI Report[/]\n"
        "[dim]This information will be included in your IC3 complaint.[/]",
        border_style="cyan"
    ))

    def ask(prompt: str, default: str = "") -> str:
        result = console.input(f"  [cyan]{prompt}[/] [{dim_default(default)}]: ").strip()
        return result or default

    def dim_default(d: str) -> str:
        return f"[dim]{d}[/]" if d else "required"

    org_name = ask("Organization Name")
    contact_name = ask("Your Name")
    contact_email = ask("Your Email")
    contact_phone = ask("Your Phone")
    org_type = ask("Organization Type (business/healthcare/government/education/individual)", "business")
    sector = ask("Industry Sector (e.g., Healthcare, Finance, Manufacturing)", "")
    state = ask("State/Province")
    critical = ask("Critical Infrastructure? (yes/no)", "no").lower() in ("yes", "y")

    return {
        "organization_name": org_name,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "contact_phone": contact_phone,
        "organization_type": org_type,
        "sector": sector,
        "state": state,
        "country": "United States",
        "critical_infrastructure": critical,
    }
