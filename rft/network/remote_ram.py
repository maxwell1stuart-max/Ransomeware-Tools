"""
Remote RAM Acquisition
----------------------
Connects to Windows machines on the network and acquires RAM dumps
using winpmem deployed over SMB (no agent pre-installed required).

Requirements on Pi:
    pip install impacket

winpmem binary is bundled in rft/network/tools/winpmem_mini_x64.exe
Downloaded from: https://github.com/Velocidex/WinPmem/releases

Flow:
    1. Connect to target via SMB using provided credentials
    2. Upload winpmem to \\target\ADMIN$\Temp\winpmem.exe
    3. Execute winpmem via smbexec/psexec to write dump to C:\Windows\Temp\mem.raw
    4. Download mem.raw back to Pi output directory
    5. Delete winpmem and mem.raw from target
    6. Feed mem.raw into memory_analysis.py

Alternative: WinRM (PowerShell remoting) if SMB is blocked.
"""

import logging
import os
import subprocess
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Path to bundled winpmem binary
WINPMEM_PATH = Path(__file__).parent / "tools" / "winpmem_mini_x64.exe"
WINPMEM_DOWNLOAD_URL = "https://github.com/Velocidex/WinPmem/releases/latest/download/winpmem_mini_x64_rc2.exe"


@dataclass
class AcquisitionResult:
    """Result of a remote RAM acquisition attempt."""
    target_ip: str
    success: bool = False
    dump_path: Optional[str] = None      # Local path on Pi where dump was saved
    dump_size_bytes: int = 0
    method_used: str = ""                # "smb", "winrm", "ssh"
    error: Optional[str] = None
    log: list[str] = field(default_factory=list)


def acquire_remote_ram(
    target_ip: str,
    username: str,
    password: str,
    output_dir: str,
    domain: str = "",
    method: str = "auto",
) -> AcquisitionResult:
    """
    Remotely acquire RAM from a Windows machine over the network.

    Args:
        target_ip: IP address of the target Windows machine
        username: Windows username (local admin or domain admin)
        password: Password for the account
        output_dir: Where to save the RAM dump on the Pi
        domain: Windows domain (leave blank for local accounts)
        method: "smb", "winrm", or "auto" (tries SMB first)

    Returns:
        AcquisitionResult with path to the dump file
    """
    result = AcquisitionResult(target_ip=target_ip)
    output_path = Path(output_dir) / "ram_dumps"
    output_path.mkdir(parents=True, exist_ok=True)
    dump_dest = output_path / f"{target_ip.replace('.', '_')}_ram.raw"

    def log(msg: str):
        logger.info(msg)
        result.log.append(msg)

    log(f"Starting remote RAM acquisition from {target_ip}")

    # Ensure winpmem is available
    winpmem = _get_winpmem()
    if not winpmem:
        result.error = (
            "winpmem not found. Run: sudo rft-download-tools "
            "or manually place winpmem_mini_x64.exe in rft/network/tools/"
        )
        return result

    # Try methods in order
    if method in ("auto", "smb"):
        if _try_smb_acquisition(target_ip, username, password, domain,
                                 winpmem, str(dump_dest), result, log):
            return result

    if method in ("auto", "winrm"):
        if _try_winrm_acquisition(target_ip, username, password, domain,
                                   winpmem, str(dump_dest), result, log):
            return result

    if not result.success:
        result.error = result.error or "All acquisition methods failed"

    return result


def _try_smb_acquisition(
    target_ip: str,
    username: str,
    password: str,
    domain: str,
    winpmem_path: Path,
    dump_dest: str,
    result: AcquisitionResult,
    log,
) -> bool:
    """Deploy winpmem via SMB and pull back the RAM dump using impacket."""
    try:
        from impacket.smbconnection import SMBConnection
        from impacket import smbconnection
    except ImportError:
        result.error = "impacket not installed. Run: pip3 install impacket"
        return False

    remote_tool_path = "Windows\\Temp\\rft_pmem.exe"
    remote_dump_path = "Windows\\Temp\\rft_mem.raw"

    try:
        log(f"Connecting to {target_ip} via SMB...")
        smb = SMBConnection(target_ip, target_ip, timeout=15)
        smb.login(username, password, domain)
        log(f"SMB authentication successful as {domain}\\{username}" if domain else f"SMB auth OK as {username}")

        # Upload winpmem to target
        log("Uploading winpmem to target...")
        with open(winpmem_path, "rb") as f:
            smb.putFile("ADMIN$", remote_tool_path, f.read)
        log("winpmem uploaded")

        # Execute winpmem remotely via smbexec
        log("Executing memory acquisition (this takes 1-5 minutes)...")
        cmd = f"C:\\Windows\\{remote_tool_path} C:\\Windows\\{remote_dump_path}"
        exec_result = _smb_exec(smb, target_ip, username, password, domain, cmd)
        log(f"winpmem finished (exit: {exec_result})")

        # Wait a moment for file to be fully written
        time.sleep(2)

        # Download the dump
        log(f"Downloading RAM dump from {target_ip}...")
        total_downloaded = 0
        with open(dump_dest, "wb") as f:
            def write_chunk(data):
                nonlocal total_downloaded
                f.write(data)
                total_downloaded += len(data)
            smb.getFile("ADMIN$", remote_dump_path, write_chunk)

        result.dump_size_bytes = total_downloaded
        log(f"RAM dump downloaded: {total_downloaded // (1024**3):.1f} GB")

        # Clean up remote files
        try:
            smb.deleteFile("ADMIN$", remote_tool_path)
            smb.deleteFile("ADMIN$", remote_dump_path)
            log("Cleaned up remote files")
        except Exception:
            log("Warning: could not clean up remote temp files")

        smb.logoff()

        result.success = True
        result.dump_path = dump_dest
        result.method_used = "smb"
        return True

    except Exception as e:
        result.error = f"SMB acquisition failed: {e}"
        log(f"SMB failed: {e}")
        return False


def _try_winrm_acquisition(
    target_ip: str,
    username: str,
    password: str,
    domain: str,
    winpmem_path: Path,
    dump_dest: str,
    result: AcquisitionResult,
    log,
) -> bool:
    """Use WinRM (PowerShell remoting) as fallback acquisition method."""
    try:
        import winrm
    except ImportError:
        log("pywinrm not installed — skipping WinRM method")
        return False

    try:
        log(f"Connecting to {target_ip} via WinRM...")
        protocol = "http"  # Try HTTP first (port 5985)
        session = winrm.Session(
            f"{protocol}://{target_ip}:5985/wsman",
            auth=(f"{domain}\\{username}" if domain else username, password),
            transport="ntlm",
        )

        # Check connectivity
        test = session.run_cmd("whoami")
        if test.status_code != 0:
            return False
        log(f"WinRM connected as: {test.std_out.decode().strip()}")

        # Upload winpmem via base64-encoded PowerShell
        log("Uploading winpmem via WinRM...")
        with open(winpmem_path, "rb") as f:
            import base64
            encoded = base64.b64encode(f.read()).decode()

        upload_script = f"""
$bytes = [Convert]::FromBase64String('{encoded}')
[IO.File]::WriteAllBytes('C:\\Windows\\Temp\\rft_pmem.exe', $bytes)
"""
        # Upload in chunks to avoid WinRM size limits
        chunk_size = 100000
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            mode = ">" if i == 0 else ">>"
            session.run_ps(f'[IO.File]::AppendAllText("C:\\Windows\\Temp\\pmem_b64.txt", "{chunk}")')
        session.run_ps(
            '$bytes = [Convert]::FromBase64String((Get-Content C:\\Windows\\Temp\\pmem_b64.txt -Raw));'
            '[IO.File]::WriteAllBytes("C:\\Windows\\Temp\\rft_pmem.exe", $bytes);'
            'Remove-Item C:\\Windows\\Temp\\pmem_b64.txt'
        )
        log("winpmem uploaded via WinRM")

        # Execute
        log("Running memory acquisition...")
        run_result = session.run_cmd(
            "C:\\Windows\\Temp\\rft_pmem.exe C:\\Windows\\Temp\\rft_mem.raw"
        )
        log(f"winpmem exit code: {run_result.status_code}")

        # Download via PowerShell base64
        log("Downloading RAM dump...")
        dl = session.run_ps(
            '[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\\Windows\\Temp\\rft_mem.raw"))'
        )
        import base64
        dump_data = base64.b64decode(dl.std_out.strip())
        with open(dump_dest, "wb") as f:
            f.write(dump_data)

        result.dump_size_bytes = len(dump_data)
        result.dump_path = dump_dest
        result.method_used = "winrm"
        result.success = True

        # Cleanup
        session.run_ps("Remove-Item C:\\Windows\\Temp\\rft_pmem.exe, C:\\Windows\\Temp\\rft_mem.raw -Force")
        log("Remote files cleaned up")
        return True

    except Exception as e:
        result.error = f"WinRM acquisition failed: {e}"
        log(f"WinRM failed: {e}")
        return False


def _smb_exec(smb, target_ip, username, password, domain, command):
    """Execute a command on the remote machine via SMB (psexec-style)."""
    try:
        from impacket.examples.smbexec import SMBEXEC
        executer = SMBEXEC(
            username, password, domain, None, None,
            "445", smb
        )
        executer.run(target_ip)
        return 0
    except Exception:
        # Fallback: use sc.exe via SMB to create/run a service
        try:
            from impacket.dcerpc.v5 import transport, scmr
            string_binding = f"ncacn_np:{target_ip}[\\pipe\\svcctl]"
            trans = transport.DCERPCTransportFactory(string_binding)
            trans.set_credentials(username, password, domain)
            dce = trans.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            service_name = "RFTAcquire"
            scmr.hRCreateServiceW(
                dce,
                scmr.hROpenSCManagerW(dce)["lpScHandle"],
                service_name,
                service_name,
                lpBinaryPathName=command,
            )
            return 0
        except Exception as e:
            logger.error(f"Remote exec failed: {e}")
            return 1


def _get_winpmem() -> Optional[Path]:
    """Return path to winpmem binary, downloading if needed."""
    tools_dir = Path(__file__).parent / "tools"
    tools_dir.mkdir(exist_ok=True)

    # Check for existing binary
    for name in ("winpmem_mini_x64.exe", "winpmem_mini_x64_rc2.exe", "winpmem.exe"):
        p = tools_dir / name
        if p.exists():
            return p

    # Try to download
    logger.info("winpmem not found — attempting download...")
    try:
        dest = tools_dir / "winpmem_mini_x64.exe"
        result = subprocess.run(
            ["wget", "-q", "-O", str(dest), WINPMEM_DOWNLOAD_URL],
            capture_output=True, timeout=60
        )
        if result.returncode == 0 and dest.exists():
            logger.info(f"winpmem downloaded to {dest}")
            return dest
    except Exception as e:
        logger.error(f"winpmem download failed: {e}")

    return None


def download_tools(output_dir: Optional[str] = None) -> dict:
    """Download winpmem and other acquisition tools."""
    tools_dir = Path(output_dir) if output_dir else Path(__file__).parent / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    # winpmem
    winpmem_dest = tools_dir / "winpmem_mini_x64.exe"
    try:
        proc = subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(winpmem_dest), WINPMEM_DOWNLOAD_URL],
            capture_output=False, timeout=120
        )
        results["winpmem"] = "ok" if proc.returncode == 0 else "failed"
    except Exception as e:
        results["winpmem"] = f"error: {e}"

    return results
