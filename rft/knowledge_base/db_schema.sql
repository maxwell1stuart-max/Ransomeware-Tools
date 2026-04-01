-- RFT Knowledge Base Schema
-- SQLite database that grows with every analyzed case.
-- This enables the AI to learn patterns and improve accuracy over time.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─── Cases Table ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT UNIQUE NOT NULL,
    analyzed_at     REAL NOT NULL,          -- Unix timestamp
    family          TEXT,                   -- "LockBit", "ALPHV", etc.
    variant         TEXT,
    attack_vector   TEXT,
    ransom_btc      TEXT,
    ransom_usd      TEXT,
    files_encrypted INTEGER DEFAULT 0,
    notes           TEXT,                   -- Free-form examiner notes
    ai_summary      TEXT,                   -- AI-generated case summary
    UNIQUE(case_id)
);

-- ─── IOCs Table ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES cases(case_id),
    ioc_type    TEXT NOT NULL,              -- "bitcoin", "onion", "email", "ip", "domain"
    value       TEXT NOT NULL,
    confidence  REAL DEFAULT 1.0,
    first_seen  REAL,
    last_seen   REAL,
    context     TEXT,
    UNIQUE(value, ioc_type)                 -- Deduplicate across cases
);

-- ─── MITRE Techniques Table ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT NOT NULL REFERENCES cases(case_id),
    technique_id    TEXT NOT NULL,          -- "T1566.001", "T1486", etc.
    technique_name  TEXT,
    family          TEXT,
    confidence      REAL DEFAULT 0.8
);

-- ─── Ransomware Families Table ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS families (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT UNIQUE NOT NULL,
    aliases             TEXT,               -- JSON array of alternate names
    first_seen_date     TEXT,
    status              TEXT DEFAULT 'active',  -- "active", "defunct", "rebranded"
    encryption_scheme   TEXT,               -- "AES-256+RSA-2048", etc.
    exfil_before_encrypt INTEGER DEFAULT 0, -- 1 if double extortion
    known_iocs          TEXT,               -- JSON object of known IOCs
    note_signatures     TEXT,               -- JSON array of regex patterns
    att_techniques      TEXT,               -- JSON array of MITRE technique IDs
    typical_ransom_usd  INTEGER,
    payment_portals     TEXT,               -- JSON array of known .onion portals
    known_decryptors    TEXT,               -- JSON array of free decryptor info
    notes               TEXT
);

-- ─── Attack Patterns Table ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_patterns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    family          TEXT NOT NULL,
    pattern_type    TEXT NOT NULL,          -- "initial_access", "lateral_movement", etc.
    description     TEXT NOT NULL,
    frequency       INTEGER DEFAULT 1,      -- Times seen across cases
    mitre_technique TEXT,
    details         TEXT                    -- JSON
);

-- ─── Learned Signatures Table ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learned_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_type    TEXT NOT NULL,      -- "file_extension", "note_pattern", "registry_key"
    value       TEXT NOT NULL,
    family      TEXT,
    confidence  REAL DEFAULT 0.5,
    seen_count  INTEGER DEFAULT 1,
    created_at  REAL NOT NULL,
    UNIQUE(sig_type, value)
);

-- ─── Examiner Notes Table ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS examiner_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT REFERENCES cases(case_id),
    timestamp   REAL NOT NULL,
    note        TEXT NOT NULL,
    category    TEXT DEFAULT 'general'  -- "finding", "timeline", "recommendation"
);

-- ─── Indexes ─────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_cases_family ON cases(family);
CREATE INDEX IF NOT EXISTS idx_mitre_technique ON mitre_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_family ON mitre_techniques(family);
