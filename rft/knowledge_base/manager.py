"""
Knowledge Base Manager

SQLite-backed learning system that improves with every analyzed case.

Features:
  - Stores all IOCs seen across cases (cross-referenced for pattern detection)
  - Tracks MITRE ATT&CK techniques associated with each ransomware family
  - Learns new signatures from AI analysis results
  - Provides relevant context to the AI engine for better identification
  - Exports IOC feeds in STIX/TAXII-compatible format
  - Seeds a comprehensive initial dataset of known ransomware families
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".rft" / "knowledge_base.db"

# Seed data for known ransomware families
KNOWN_FAMILIES = [
    {
        "name": "LockBit",
        "aliases": ["LockBit 2.0", "LockBit 3.0", "LockBit Black"],
        "first_seen_date": "2019-09",
        "status": "active",
        "encryption_scheme": "AES-256+RSA-2048",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1566", "T1190", "T1021.001", "T1486", "T1490", "T1489"],
        "typical_ransom_usd": 100000,
        "notes": "Most prolific RaaS operation. Uses .lockbit extension. Known for fast encryption.",
    },
    {
        "name": "ALPHV/BlackCat",
        "aliases": ["BlackCat", "ALPHV", "Noberus"],
        "first_seen_date": "2021-11",
        "status": "defunct",
        "encryption_scheme": "ChaCha20+RSA-4096",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1566", "T1190", "T1486", "T1041", "T1490"],
        "typical_ransom_usd": 500000,
        "notes": "Written in Rust. FBI seized infrastructure in 2024. Double extortion.",
    },
    {
        "name": "Cl0p",
        "aliases": ["CL0P", "Clop"],
        "first_seen_date": "2019-02",
        "status": "active",
        "encryption_scheme": "AES-256+RSA-2048",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1190", "T1059.001", "T1486", "T1041"],
        "typical_ransom_usd": 2000000,
        "notes": "Exploits MFT file transfer software (GoAnywhere, MOVEit). Mass exploitation.",
    },
    {
        "name": "Hive",
        "aliases": ["HiveLeaks"],
        "first_seen_date": "2021-06",
        "status": "defunct",
        "encryption_scheme": "Elliptic Curve+RSA",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1021.001", "T1566", "T1486", "T1490"],
        "typical_ransom_usd": 150000,
        "notes": "FBI infiltrated and obtained decryption keys in Jan 2023. 1500+ victims.",
    },
    {
        "name": "Conti",
        "aliases": ["ContiLocker"],
        "first_seen_date": "2020-07",
        "status": "defunct",
        "encryption_scheme": "AES-256+RSA-4096",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1566.001", "T1021.001", "T1486", "T1490", "T1059.001"],
        "typical_ransom_usd": 300000,
        "notes": "Source code leaked 2022. Successor groups: Black Basta, Royal, Akira.",
    },
    {
        "name": "REvil/Sodinokibi",
        "aliases": ["REvil", "Sodinokibi", "UNKN"],
        "first_seen_date": "2019-04",
        "status": "defunct",
        "encryption_scheme": "Salsa20+Curve25519",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1190", "T1566", "T1486", "T1490"],
        "typical_ransom_usd": 500000,
        "notes": "RaaS. Notable: Kaseya attack (2021). Russian members arrested Jan 2022.",
    },
    {
        "name": "Ryuk",
        "aliases": ["RyukReadMe"],
        "first_seen_date": "2018-08",
        "status": "defunct",
        "encryption_scheme": "AES-256+RSA-4096",
        "exfil_before_encrypt": 0,
        "att_techniques": ["T1566.001", "T1021.001", "T1486", "T1490", "T1489"],
        "typical_ransom_usd": 500000,
        "notes": "Operated by Russian group WIZARD SPIDER. Evolved into Conti.",
    },
    {
        "name": "BlackBasta",
        "aliases": ["Black Basta"],
        "first_seen_date": "2022-04",
        "status": "active",
        "encryption_scheme": "ChaCha20+RSA-4096",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1566.001", "T1059.001", "T1486", "T1490", "T1021.001"],
        "typical_ransom_usd": 200000,
        "notes": "Conti successor. Uses Qakbot for initial access. Fast encryption.",
    },
    {
        "name": "Akira",
        "aliases": ["Akira Ransomware"],
        "first_seen_date": "2023-03",
        "status": "active",
        "encryption_scheme": "ChaCha20+RSA-4096",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1190", "T1021.001", "T1486", "T1041"],
        "typical_ransom_usd": 200000,
        "notes": "Targets Cisco VPN vulnerabilities. Double extortion. Conti-linked.",
    },
    {
        "name": "Phobos",
        "aliases": ["Phobos Ransomware"],
        "first_seen_date": "2019-01",
        "status": "active",
        "encryption_scheme": "AES-256+RSA-1024",
        "exfil_before_encrypt": 0,
        "att_techniques": ["T1021.001", "T1486", "T1490"],
        "typical_ransom_usd": 10000,
        "notes": "RaaS. Primarily targets SMBs via RDP. Uses email in file extension.",
    },
    {
        "name": "Dharma",
        "aliases": ["CrySiS", "Dharma"],
        "first_seen_date": "2016-11",
        "status": "active",
        "encryption_scheme": "AES-256+RSA-1024",
        "exfil_before_encrypt": 0,
        "att_techniques": ["T1021.001", "T1486"],
        "typical_ransom_usd": 5000,
        "notes": "Long-running RaaS. Targets via exposed RDP. .id-[ID].[email].dharma ext.",
    },
    {
        "name": "STOP/Djvu",
        "aliases": ["STOP", "Djvu", "STOP Ransomware"],
        "first_seen_date": "2018-12",
        "status": "active",
        "encryption_scheme": "Salsa20+RSA-1024",
        "exfil_before_encrypt": 0,
        "att_techniques": ["T1566.001", "T1486"],
        "typical_ransom_usd": 490,
        "notes": "Highest volume ransomware. Primarily consumer-targeted via pirated software.",
        "known_decryptors": ["STOPDecryptor by Emsisoft — works for older offline keys"],
    },
    {
        "name": "WannaCry",
        "aliases": ["WannaCrypt", "WCry"],
        "first_seen_date": "2017-05",
        "status": "active_legacy",
        "encryption_scheme": "AES-128+RSA-2048",
        "exfil_before_encrypt": 0,
        "att_techniques": ["T1210", "T1486", "T1490"],
        "typical_ransom_usd": 300,
        "notes": "North Korean (Lazarus Group). EternalBlue exploit. Still active on unpatched systems.",
    },
    {
        "name": "Play",
        "aliases": ["PlayCrypt"],
        "first_seen_date": "2022-06",
        "status": "active",
        "encryption_scheme": "AES-256+RSA",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1190", "T1021.001", "T1486"],
        "typical_ransom_usd": 300000,
        "notes": "Targets ProxyNotShell (Exchange). No data leak site initially.",
    },
    {
        "name": "Royal",
        "aliases": ["Royal Ransomware"],
        "first_seen_date": "2022-09",
        "status": "rebranded",
        "encryption_scheme": "AES-256+RSA",
        "exfil_before_encrypt": 1,
        "att_techniques": ["T1566", "T1190", "T1486"],
        "typical_ransom_usd": 1000000,
        "notes": "Conti successor. Rebranded as BlackSuit in 2023.",
    },
]


class KnowledgeBase:
    """
    SQLite-backed knowledge base for ransomware intelligence.

    Grows smarter with every analyzed case. Provides AI context and
    generates IOC feeds for threat sharing.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or DEFAULT_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._initialize()

    def _get_conn(self) -> sqlite3.Connection:
        if not self._conn:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _initialize(self) -> None:
        """Create tables and seed initial data."""
        conn = self._get_conn()

        # Load schema
        schema_path = Path(__file__).parent / "db_schema.sql"
        if schema_path.exists():
            conn.executescript(schema_path.read_text())
        else:
            self._create_minimal_schema(conn)

        conn.commit()

        # Seed known families if not already present
        cursor = conn.execute("SELECT COUNT(*) FROM families")
        if cursor.fetchone()[0] == 0:
            self._seed_families(conn)
            logger.info(f"Knowledge base seeded with {len(KNOWN_FAMILIES)} known ransomware families")

    def _seed_families(self, conn: sqlite3.Connection) -> None:
        """Insert initial ransomware family data."""
        for family in KNOWN_FAMILIES:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO families
                    (name, aliases, first_seen_date, status, encryption_scheme,
                     exfil_before_encrypt, att_techniques, typical_ransom_usd, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    family["name"],
                    json.dumps(family.get("aliases", [])),
                    family.get("first_seen_date"),
                    family.get("status", "active"),
                    family.get("encryption_scheme"),
                    family.get("exfil_before_encrypt", 0),
                    json.dumps(family.get("att_techniques", [])),
                    family.get("typical_ransom_usd"),
                    family.get("notes"),
                ))
            except Exception as e:
                logger.warning(f"Failed to seed family {family['name']}: {e}")
        conn.commit()

    def get_family_info(self, family_name: str) -> Optional[dict]:
        """Get detailed info about a known ransomware family."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM families WHERE name = ? OR aliases LIKE ?",
            (family_name, f"%{family_name}%")
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_relevant_context(
        self,
        family: Optional[str],
        iocs: list[str]
    ) -> str:
        """
        Get knowledge base context relevant to the current analysis.
        Used to prime the AI engine with prior case knowledge.
        """
        context_parts = []

        # Family-specific context
        if family:
            info = self.get_family_info(family)
            if info:
                context_parts.append(
                    f"KNOWN FAMILY: {family}\n"
                    f"  Encryption: {info.get('encryption_scheme')}\n"
                    f"  Status: {info.get('status')}\n"
                    f"  Notes: {info.get('notes')}\n"
                    f"  MITRE ATT&CK: {info.get('att_techniques')}"
                )

            # Cases we've seen before with this family
            cases = self.get_cases_by_family(family, limit=3)
            if cases:
                context_parts.append(
                    f"\nPREVIOUS CASES ({family}): {len(cases)} seen\n" +
                    "\n".join(
                        f"  [{c['case_id']}] Vector: {c['attack_vector']}, "
                        f"Files: {c['files_encrypted']:,}"
                        for c in cases
                    )
                )

        # Check if any IOCs match known cases
        if iocs:
            for ioc in iocs[:5]:
                match = self.lookup_ioc(ioc)
                if match:
                    context_parts.append(
                        f"\nKNOWN IOC MATCH: {ioc}\n"
                        f"  Previously seen in: {match.get('case_id')}\n"
                        f"  Family: {match.get('family', 'unknown')}"
                    )

        return "\n".join(context_parts) if context_parts else ""

    def get_cases_by_family(self, family: str, limit: int = 10) -> list[dict]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM cases WHERE family = ? ORDER BY analyzed_at DESC LIMIT ?",
            (family, limit)
        )
        return [dict(row) for row in cursor.fetchall()]

    def lookup_ioc(self, value: str) -> Optional[dict]:
        """Check if an IOC has been seen in a previous case."""
        conn = self._get_conn()
        cursor = conn.execute(
            """SELECT i.*, c.family FROM iocs i
               JOIN cases c ON i.case_id = c.case_id
               WHERE i.value = ? LIMIT 1""",
            (value,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def store_case(
        self,
        case_id: str,
        family: Optional[str],
        attack_vector: str,
        files_encrypted: int,
        notes: str = "",
        ai_summary: str = "",
        ransom_btc: Optional[str] = None,
        ransom_usd: Optional[str] = None,
    ) -> None:
        """Store a completed case analysis in the knowledge base."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO cases
                (case_id, analyzed_at, family, attack_vector, files_encrypted,
                 notes, ai_summary, ransom_btc, ransom_usd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id, time.time(), family, attack_vector,
                files_encrypted, notes, ai_summary, ransom_btc, ransom_usd
            ))
            conn.commit()
            logger.info(f"Case {case_id} stored in knowledge base")
        except Exception as e:
            logger.error(f"Failed to store case {case_id}: {e}")

    def store_iocs(self, case_id: str, ioc_report) -> None:
        """Store all IOCs from a case."""
        conn = self._get_conn()
        now = time.time()

        ioc_tuples = []
        for ioc in ioc_report.all_iocs():
            ioc_tuples.append((
                case_id, ioc.ioc_type, ioc.value,
                ioc.confidence, now, now, ioc.context
            ))

        try:
            conn.executemany("""
                INSERT OR REPLACE INTO iocs
                (case_id, ioc_type, value, confidence, first_seen, last_seen, context)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ioc_tuples)
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to store IOCs for case {case_id}: {e}")

    def store_mitre_techniques(
        self, case_id: str, techniques: list[str], family: Optional[str]
    ) -> None:
        """Store MITRE ATT&CK technique observations."""
        conn = self._get_conn()
        try:
            conn.executemany("""
                INSERT INTO mitre_techniques (case_id, technique_id, family, confidence)
                VALUES (?, ?, ?, ?)
            """, [(case_id, t, family, 0.8) for t in techniques])
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to store MITRE techniques: {e}")

    async def learn_from_case(self, case_data: dict) -> None:
        """
        Called after AI analysis to update the knowledge base with new learnings.
        This is the core "learning" function — the KB gets smarter over time.
        """
        family = case_data.get("family")
        case_id = case_data.get("case_id", f"case_{int(time.time())}")

        # Update case record
        self.store_case(
            case_id=case_id,
            family=family,
            attack_vector=case_data.get("attack_vector", "unknown"),
            files_encrypted=case_data.get("files_encrypted", 0),
            ai_summary=case_data.get("ai_family_assessment", ""),
        )

        # Update MITRE techniques
        if case_data.get("mitre_techniques"):
            self.store_mitre_techniques(
                case_id, case_data["mitre_techniques"], family
            )

        # Learn new signatures
        if family:
            self._update_family_attack_patterns(
                family,
                case_data.get("attack_vector", "unknown"),
                case_data.get("mitre_techniques", [])
            )

        logger.info(f"Knowledge base updated from case {case_id}")

    def _update_family_attack_patterns(
        self,
        family: str,
        attack_vector: str,
        techniques: list[str]
    ) -> None:
        """Update or create attack pattern frequency data for a family."""
        conn = self._get_conn()
        try:
            # Upsert attack pattern
            cursor = conn.execute(
                "SELECT id, frequency FROM attack_patterns WHERE family = ? AND description = ?",
                (family, attack_vector)
            )
            existing = cursor.fetchone()
            if existing:
                conn.execute(
                    "UPDATE attack_patterns SET frequency = ? WHERE id = ?",
                    (existing["frequency"] + 1, existing["id"])
                )
            else:
                conn.execute("""
                    INSERT INTO attack_patterns (family, pattern_type, description, frequency)
                    VALUES (?, ?, ?, 1)
                """, (family, "initial_access", attack_vector))
            conn.commit()
        except Exception as e:
            logger.warning(f"Pattern update failed: {e}")

    def export_ioc_feed(self, output_path: str, ioc_types: list[str] = None) -> int:
        """
        Export IOCs as a JSON feed for threat sharing.
        Compatible with basic STIX/TAXII consumers.
        """
        conn = self._get_conn()
        query = "SELECT * FROM iocs"
        params = []
        if ioc_types:
            placeholders = ",".join("?" * len(ioc_types))
            query += f" WHERE ioc_type IN ({placeholders})"
            params = ioc_types

        cursor = conn.execute(query, params)
        iocs = [dict(row) for row in cursor.fetchall()]

        feed = {
            "type": "bundle",
            "id": f"bundle--rft-export-{int(time.time())}",
            "spec_version": "2.0",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{i['id']}",
                    "name": f"{i['ioc_type']}: {i['value']}",
                    "pattern": f"[{i['ioc_type']} = '{i['value']}']",
                    "confidence": int(i.get("confidence", 1.0) * 100),
                    "first_seen": i.get("first_seen"),
                    "context": i.get("context", ""),
                }
                for i in iocs
            ]
        }

        with open(output_path, "w") as f:
            json.dump(feed, f, indent=2)

        return len(iocs)

    def get_statistics(self) -> dict:
        """Get overall knowledge base statistics."""
        conn = self._get_conn()
        stats = {}
        for table in ["cases", "iocs", "families", "mitre_techniques"]:
            cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]

        # Most common families
        cursor = conn.execute(
            "SELECT family, COUNT(*) as count FROM cases WHERE family IS NOT NULL "
            "GROUP BY family ORDER BY count DESC LIMIT 5"
        )
        stats["top_families"] = [dict(row) for row in cursor.fetchall()]

        # Most common attack vectors
        cursor = conn.execute(
            "SELECT attack_vector, COUNT(*) as count FROM cases "
            "GROUP BY attack_vector ORDER BY count DESC LIMIT 5"
        )
        stats["top_vectors"] = [dict(row) for row in cursor.fetchall()]

        return stats

    def _create_minimal_schema(self, conn: sqlite3.Connection) -> None:
        """Fallback schema creation if sql file not found."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                analyzed_at REAL NOT NULL,
                family TEXT,
                attack_vector TEXT,
                files_encrypted INTEGER DEFAULT 0,
                notes TEXT,
                ai_summary TEXT,
                ransom_btc TEXT,
                ransom_usd TEXT
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                first_seen REAL,
                last_seen REAL,
                context TEXT,
                UNIQUE(value, ioc_type)
            );
            CREATE TABLE IF NOT EXISTS families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                aliases TEXT,
                first_seen_date TEXT,
                status TEXT DEFAULT 'active',
                encryption_scheme TEXT,
                exfil_before_encrypt INTEGER DEFAULT 0,
                att_techniques TEXT,
                typical_ransom_usd INTEGER,
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                family TEXT,
                confidence REAL DEFAULT 0.8
            );
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                family TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                description TEXT NOT NULL,
                frequency INTEGER DEFAULT 1,
                mitre_technique TEXT,
                details TEXT
            );
        """)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
