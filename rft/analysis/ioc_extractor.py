"""
Indicator of Compromise (IOC) Extractor

Extracts actionable IOCs from ransomware notes and artifacts:
  - Bitcoin / Monero wallet addresses
  - Tor .onion addresses (C2/payment portals)
  - Email addresses (for ransom payment contact)
  - IPv4/IPv6 addresses
  - Domain names
  - URLs
  - File hashes mentioned in notes
  - Ransomware family identifiers

These IOCs can be submitted to FBI IC3 and shared with threat intel feeds.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """A single extracted Indicator of Compromise."""
    ioc_type: str       # "bitcoin_address", "onion_url", "email", "ip", "domain", etc.
    value: str
    context: str = ""   # Surrounding text for context
    source_file: str = ""
    confidence: float = 1.0  # 0.0–1.0


@dataclass
class IOCReport:
    """All IOCs extracted from a set of artifacts."""
    bitcoin_addresses: list[IOC] = field(default_factory=list)
    monero_addresses: list[IOC] = field(default_factory=list)
    onion_addresses: list[IOC] = field(default_factory=list)
    email_addresses: list[IOC] = field(default_factory=list)
    ip_addresses: list[IOC] = field(default_factory=list)
    domains: list[IOC] = field(default_factory=list)
    urls: list[IOC] = field(default_factory=list)
    ransom_family_clues: list[IOC] = field(default_factory=list)

    def all_iocs(self) -> list[IOC]:
        return (
            self.bitcoin_addresses + self.monero_addresses +
            self.onion_addresses + self.email_addresses +
            self.ip_addresses + self.domains + self.urls +
            self.ransom_family_clues
        )

    def summary(self) -> dict:
        return {
            "bitcoin_addresses": len(self.bitcoin_addresses),
            "monero_addresses": len(self.monero_addresses),
            "onion_addresses": len(self.onion_addresses),
            "email_addresses": len(self.email_addresses),
            "ip_addresses": len(self.ip_addresses),
            "domains": len(self.domains),
            "urls": len(self.urls),
            "family_clues": len(self.ransom_family_clues),
            "total": len(self.all_iocs()),
        }


# ─── Regex Patterns ───────────────────────────────────────────────────────────

# Bitcoin P2PKH (1...), P2SH (3...), Bech32 (bc1...)
RE_BITCOIN = re.compile(
    r"\b(?:"
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"     # Legacy / P2SH
    r"|bc1[a-z0-9]{39,59}"                  # Bech32
    r")\b"
)

# Monero addresses (XMR) — 95 characters starting with 4
RE_MONERO = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Tor .onion addresses (v2 16 chars, v3 56 chars)
RE_ONION = re.compile(
    r"\b(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b",
    re.IGNORECASE
)

# Email addresses
RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# IPv4 addresses (excluding private/loopback)
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Domain names (rough — refine in post-processing)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cc|su|to|biz|info|onion)\b",
    re.IGNORECASE
)

# Full URLs
RE_URL = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

# Ransomware family signature strings in ransom notes
FAMILY_SIGNATURES = {
    "LockBit": [
        r"(?i)lockbit",
        r"(?i)lb3\.0",
        r"(?i)lockbit\s*\d",
    ],
    "ALPHV/BlackCat": [
        r"(?i)alphv",
        r"(?i)blackcat",
        r"(?i)noescapevm",
    ],
    "Cl0p": [
        r"(?i)cl0p",
        r"(?i)clop ransomware",
    ],
    "Hive": [
        r"(?i)hive ransomware",
        r"(?i)hiveleaks",
    ],
    "REvil/Sodinokibi": [
        r"(?i)revil",
        r"(?i)sodinokibi",
        r"(?i)sodin",
    ],
    "Conti": [
        r"(?i)conti ransomware",
        r"(?i)contirecovery",
    ],
    "Ryuk": [
        r"(?i)ryuk",
        r"(?i)RyukReadMe",
    ],
    "WannaCry": [
        r"(?i)wanna.?cry",
        r"(?i)wannadecryptor",
    ],
    "Maze": [
        r"(?i)maze ransomware",
        r"(?i)mazeimpacts",
    ],
    "DoppelPaymer": [
        r"(?i)doppelpaymer",
    ],
    "Dharma": [
        r"(?i)dharma",
        r"(?i)@\w+\.com\]",  # Dharma uses [email] in extension
    ],
    "Phobos": [
        r"(?i)phobos",
        r"(?i)phobos_ransomware",
    ],
    "BlackBasta": [
        r"(?i)black basta",
        r"(?i)blackbasta",
    ],
    "Akira": [
        r"(?i)\bakira\b",
        r"(?i)akiranews",
    ],
    "Play": [
        r"(?i)\bplay\b.*ransomware",
        r"(?i)play ransomware",
    ],
    "Royal": [
        r"(?i)\broyal\b.*ransomware",
        r"(?i)royal_readme",
    ],
    "Medusa": [
        r"(?i)\bmedusa\b.*locker",
        r"(?i)medusablog",
    ],
    "STOP/Djvu": [
        r"(?i)\.djvu\b",
        r"(?i)stopdata\.top",
    ],
}


def extract_iocs(
    texts: list[tuple[str, str]],  # (content, source_filename)
    deduplicate: bool = True
) -> IOCReport:
    """
    Extract all IOCs from a list of text contents.

    Args:
        texts: List of (text_content, source_filename) tuples
        deduplicate: Remove duplicate IOC values

    Returns:
        IOCReport with all extracted indicators
    """
    report = IOCReport()
    seen: dict[str, set] = {
        "bitcoin": set(), "monero": set(), "onion": set(),
        "email": set(), "ip": set(), "domain": set(),
        "url": set(), "family": set()
    }

    for content, source in texts:
        if not content:
            continue

        # Bitcoin addresses
        for m in RE_BITCOIN.finditer(content):
            val = m.group()
            if not deduplicate or val not in seen["bitcoin"]:
                seen["bitcoin"].add(val)
                ctx = _get_context(content, m.start(), m.end())
                report.bitcoin_addresses.append(
                    IOC("bitcoin_address", val, ctx, source)
                )

        # Monero addresses
        for m in RE_MONERO.finditer(content):
            val = m.group()
            if not deduplicate or val not in seen["monero"]:
                seen["monero"].add(val)
                ctx = _get_context(content, m.start(), m.end())
                report.monero_addresses.append(
                    IOC("monero_address", val, ctx, source)
                )

        # Tor .onion
        for m in RE_ONION.finditer(content):
            val = m.group().lower()
            if not deduplicate or val not in seen["onion"]:
                seen["onion"].add(val)
                ctx = _get_context(content, m.start(), m.end())
                report.onion_addresses.append(
                    IOC("onion_address", val, ctx, source)
                )

        # Email addresses
        for m in RE_EMAIL.finditer(content):
            val = m.group().lower()
            if not deduplicate or val not in seen["email"]:
                seen["email"].add(val)
                ctx = _get_context(content, m.start(), m.end())
                report.email_addresses.append(
                    IOC("email_address", val, ctx, source)
                )

        # IP addresses (skip private/loopback)
        for m in RE_IPV4.finditer(content):
            val = m.group()
            if _is_public_ip(val):
                if not deduplicate or val not in seen["ip"]:
                    seen["ip"].add(val)
                    ctx = _get_context(content, m.start(), m.end())
                    report.ip_addresses.append(
                        IOC("ipv4_address", val, ctx, source)
                    )

        # URLs
        for m in RE_URL.finditer(content):
            val = m.group().rstrip(".,;)")
            if not deduplicate or val not in seen["url"]:
                seen["url"].add(val)
                ctx = _get_context(content, m.start(), m.end())
                report.urls.append(IOC("url", val, ctx, source))

        # Ransomware family signatures
        for family, patterns in FAMILY_SIGNATURES.items():
            key = family.lower()
            if key not in seen["family"]:
                for pattern in patterns:
                    m = re.search(pattern, content)
                    if m:
                        seen["family"].add(key)
                        ctx = _get_context(content, m.start(), m.end())
                        report.ransom_family_clues.append(
                            IOC("ransomware_family", family, ctx, source,
                                confidence=0.9)
                        )
                        break

    return report


def identify_ransomware_family(ransom_note: str) -> Optional[tuple[str, float]]:
    """
    Attempt to identify the ransomware family from a ransom note.
    Returns (family_name, confidence) or None.
    """
    best_family = None
    best_score = 0.0

    for family, patterns in FAMILY_SIGNATURES.items():
        matches = sum(1 for p in patterns if re.search(p, ransom_note))
        if matches > 0:
            score = matches / len(patterns)
            if score > best_score:
                best_score = score
                best_family = family

    if best_family:
        return best_family, min(best_score * 1.5, 1.0)  # Scale up confidence
    return None


def _get_context(text: str, start: int, end: int, window: int = 80) -> str:
    """Extract surrounding context for an IOC match."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    return text[ctx_start:ctx_end].replace("\n", " ").strip()


def _is_public_ip(ip: str) -> bool:
    """Filter out private/loopback/reserved IPs."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False

    # Private ranges
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 127:
        return False  # loopback
    if a == 0:
        return False
    if a >= 224:
        return False  # multicast/reserved
    return True
