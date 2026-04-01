"""
AI Analysis Engine — Claude-Powered Ransomware Intelligence

Uses the Anthropic API (claude-opus-4-6 with adaptive thinking) to:
  1. Deeply analyze ransomware artifacts and suggest attack vectors
  2. Cross-reference with known TTPs (MITRE ATT&CK)
  3. Suggest recovery paths and law enforcement reporting details
  4. Learn from each analyzed case (feeds knowledge base)
  5. Generate natural-language summaries for FBI reports

The AI is given structured evidence and asked to reason about it with
adaptive thinking enabled for complex multi-step analysis.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

import anthropic

from rft.analysis.ransomware_analyzer import RansomwareAnalysis

logger = logging.getLogger(__name__)

# System prompt defining the AI's forensic role
FORENSIC_SYSTEM_PROMPT = """You are an expert ransomware forensic analyst with deep knowledge of:
- Ransomware families, their TTPs (Tactics, Techniques, and Procedures), and evolving variants
- MITRE ATT&CK framework for ransomware attack chains
- Windows forensic artifacts: event logs, registry hives, prefetch files, VSS deletion
- Cryptographic analysis of ransomware encryption schemes
- Law enforcement reporting requirements (FBI IC3, CISA)
- Threat intelligence: IOC analysis, dark web payment portals, cryptocurrency tracing
- Incident response and recovery procedures

Your role is to analyze evidence from a ransomware incident and provide:
1. Confident identification of the ransomware family and variant
2. Detailed attack chain reconstruction (MITRE ATT&CK mapping)
3. Assessment of credential theft and lateral movement
4. Encryption analysis and recovery feasibility
5. Specific IOCs for law enforcement submission
6. Evidence-based recommendations prioritized for the victim

Be direct, specific, and evidence-driven. Acknowledge uncertainty when present.
Format your response with clear section headers for easy parsing.
This analysis will be used in an FBI IC3 report — accuracy is critical."""


@dataclass
class AIAnalysisResult:
    """Structured output from AI analysis."""
    # Core findings
    family_assessment: str
    attack_chain_summary: str
    mitre_techniques: list[str]

    # Detailed sections
    initial_access_analysis: str
    persistence_analysis: str
    encryption_assessment: str
    exfiltration_indicators: str

    # IOC assessment
    ioc_assessment: str
    notable_iocs: list[str]

    # Recovery and reporting
    recovery_assessment: str
    fbi_report_key_points: list[str]
    immediate_actions: list[str]

    # Learning
    new_knowledge_items: list[dict] = field(default_factory=list)

    # Raw AI response
    raw_response: str = ""
    thinking_summary: str = ""
    tokens_used: int = 0

    def to_report_text(self) -> str:
        """Format as human-readable report section."""
        sections = [
            "## AI FORENSIC ANALYSIS",
            "",
            "### Ransomware Family Assessment",
            self.family_assessment,
            "",
            "### Attack Chain Reconstruction",
            self.attack_chain_summary,
            "",
            "### MITRE ATT&CK Techniques Identified",
        ]
        for t in self.mitre_techniques:
            sections.append(f"  - {t}")
        sections.extend([
            "",
            "### Initial Access Analysis",
            self.initial_access_analysis,
            "",
            "### Persistence & Lateral Movement",
            self.persistence_analysis,
            "",
            "### Encryption Assessment",
            self.encryption_assessment,
            "",
            "### IOC Assessment",
            self.ioc_assessment,
            "",
            "### Recovery Feasibility",
            self.recovery_assessment,
            "",
            "### Key Points for FBI Report",
        ])
        for point in self.fbi_report_key_points:
            sections.append(f"  • {point}")
        sections.extend([
            "",
            "### Immediate Actions Required",
        ])
        for action in self.immediate_actions:
            sections.append(f"  → {action}")

        return "\n".join(sections)


class AIEngine:
    """
    Claude-powered ransomware analysis engine.

    Usage:
        engine = AIEngine(api_key="...", knowledge_base=kb)
        result = await engine.analyze(ransomware_analysis)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        knowledge_base=None,   # KnowledgeBase instance (optional)
        model: str = "claude-opus-4-6"
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.knowledge_base = knowledge_base
        self._client: Optional[anthropic.AsyncAnthropic] = None

    def _get_client(self) -> anthropic.AsyncAnthropic:
        if not self._client:
            if not self.api_key:
                raise ValueError(
                    "No Anthropic API key provided. "
                    "Set ANTHROPIC_API_KEY environment variable or pass api_key to AIEngine."
                )
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    async def analyze(
        self,
        analysis: RansomwareAnalysis,
        stream_callback=None,   # Optional async callback(text_chunk: str)
    ) -> AIAnalysisResult:
        """
        Perform deep AI analysis of a ransomware incident.

        Uses adaptive thinking for complex multi-step reasoning about the
        attack chain, then generates structured findings.

        Args:
            analysis: Structured ransomware analysis from the analyzer module
            stream_callback: Optional async function called with each text chunk

        Returns:
            AIAnalysisResult with detailed findings
        """
        client = self._get_client()

        # Build the analysis prompt with all available evidence
        prompt = self._build_analysis_prompt(analysis)

        # Add relevant knowledge base context if available
        kb_context = ""
        if self.knowledge_base:
            kb_context = self.knowledge_base.get_relevant_context(
                family=analysis.ransomware_family,
                iocs=[i.value for i in analysis.ioc_report.all_iocs()[:20]]
            )

        # Build messages
        messages = [{"role": "user", "content": prompt}]
        if kb_context:
            messages[0]["content"] = (
                f"KNOWLEDGE BASE CONTEXT (from previous cases):\n{kb_context}\n\n"
                f"---\n\n{prompt}"
            )

        logger.info(f"Sending analysis to Claude ({self.model}) with adaptive thinking...")

        # Use streaming for long analysis + adaptive thinking
        full_text = ""
        thinking_text = ""
        total_tokens = 0

        async with client.messages.stream(
            model=self.model,
            max_tokens=8192,
            thinking={"type": "adaptive"},
            system=FORENSIC_SYSTEM_PROMPT,
            messages=messages,
        ) as stream:
            async for event in stream:
                if event.type == "content_block_delta":
                    if event.delta.type == "thinking_delta":
                        thinking_text += event.delta.thinking
                    elif event.delta.type == "text_delta":
                        full_text += event.delta.text
                        if stream_callback:
                            await stream_callback(event.delta.text)

            final = await stream.get_final_message()
            total_tokens = final.usage.input_tokens + final.usage.output_tokens

        logger.info(f"AI analysis complete. Tokens used: {total_tokens:,}")

        # Parse the structured response
        result = self._parse_response(full_text, thinking_text, total_tokens)

        # Learn from this case
        if self.knowledge_base and result:
            await self._update_knowledge_base(analysis, result)

        return result

    async def analyze_ransom_note(self, note_text: str) -> dict:
        """
        Quick analysis of a single ransom note for rapid family identification.
        Uses lower token budget for speed.
        """
        client = self._get_client()

        prompt = f"""Analyze this ransom note and provide a JSON response with:
1. ransomware_family: identified family name (or "unknown")
2. variant: specific variant if identifiable
3. confidence: 0.0-1.0 confidence in identification
4. key_iocs: list of IOCs found (bitcoin addresses, emails, onion URLs)
5. payment_instructions: summary of payment method
6. deadline_hours: payment deadline in hours if specified (null if not)
7. encryption_mentioned: list of encryption algorithms mentioned
8. threat_type: "data_encryption_only", "double_extortion", "triple_extortion"
9. mitre_initial_access: best guess at initial access technique

RANSOM NOTE:
{note_text[:4000]}

Respond with valid JSON only."""

        response = await client.messages.create(
            model=self.model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            text = next(b.text for b in response.content if b.type == "text")
            # Strip markdown code fences if present
            text = text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except Exception as e:
            logger.error(f"Failed to parse AI JSON response: {e}")
            return {"error": str(e), "raw": response.content[0].text if response.content else ""}

    async def get_recovery_advice(
        self,
        family: str,
        encryption_algos: list[str],
        backup_status: str = "unknown"
    ) -> str:
        """Get specific recovery advice for the identified ransomware family."""
        client = self._get_client()

        prompt = f"""A victim has been hit by {family} ransomware using {', '.join(encryption_algos)}.
Backup status: {backup_status}.

Provide specific, actionable recovery advice including:
1. Is there a free decryptor available? (check nomoreransom.org)
2. Law enforcement agencies that specifically track this family
3. Key evidence to preserve for FBI investigation
4. Specific steps to recover operations safely
5. How this family typically spreads (for prevention of reinfection)

Be specific and direct. Lives and livelihoods depend on this advice."""

        response = await client.messages.create(
            model=self.model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        return next(b.text for b in response.content if b.type == "text")

    async def stream_analysis_summary(
        self, analysis: RansomwareAnalysis
    ) -> AsyncGenerator[str, None]:
        """Stream a concise executive summary for display."""
        client = self._get_client()

        prompt = f"""Provide a 3-paragraph executive summary of this ransomware incident for a non-technical victim:
- What happened (ransomware family, how they got in)
- What the attackers encrypted and demanded
- What the victim should do RIGHT NOW (top 3 actions)

Incident data:
{json.dumps(analysis.to_summary_dict(), indent=2)[:3000]}

Use plain language. Be compassionate but direct."""

        async with client.messages.stream(
            model=self.model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            async for text in stream.text_stream:
                yield text

    def _build_analysis_prompt(self, analysis: RansomwareAnalysis) -> str:
        """Build the detailed analysis prompt from all available evidence."""
        summary = analysis.to_summary_dict()
        iocs = summary.get("iocs", {})

        note_preview = analysis.ransom_note_content[:3000] if analysis.ransom_note_content else "No ransom note recovered"

        return f"""RANSOMWARE INCIDENT FORENSIC ANALYSIS REQUEST
Case ID: {analysis.case_id}

═══ RANSOMWARE IDENTITY ═══
Detected Family: {summary.get('ransomware_family', 'Unknown')}
Variant: {summary.get('ransomware_variant', 'Unknown')}
Identification Confidence: {summary.get('family_confidence', 0):.0%}

═══ ATTACK VECTOR ═══
Primary Vector: {summary.get('attack_vector', 'Unknown')}
Vector Confidence: {summary.get('attack_vector_confidence', 0):.0%}
Supporting Evidence:
{chr(10).join('  - ' + e for e in summary.get('attack_supporting_evidence', []))}

═══ ENCRYPTION ═══
Detected Algorithms: {', '.join(summary.get('encryption_algorithms', ['Unknown']))}
Decryption Likelihood: {summary.get('decryption_likelihood', 'Unknown')}

═══ INDICATORS OF COMPROMISE ═══
Bitcoin Addresses: {', '.join(iocs.get('bitcoin_addresses', [])) or 'None detected'}
Monero Addresses: {', '.join(iocs.get('monero_addresses', [])) or 'None detected'}
Tor .onion Addresses: {', '.join(iocs.get('onion_addresses', [])) or 'None detected'}
Contact Emails: {', '.join(iocs.get('email_addresses', [])) or 'None detected'}
External IPs: {', '.join(iocs.get('ip_addresses', [])) or 'None detected'}

═══ TIMELINE ═══
Earliest Indicator: {summary.get('earliest_indicator', 'Unknown')}
Estimated Encryption Time: {summary.get('estimated_encryption_time', 'Unknown')}
Lateral Movement Detected: {summary.get('lateral_movement', False)}

═══ SCOPE ═══
Estimated Files Encrypted: {summary.get('estimated_files_encrypted', 0):,}
Ransom Amount (BTC): {analysis.ransom_amount_btc or 'Not specified'}
Ransom Amount (USD): {analysis.ransom_amount_usd or 'Not specified'}
Payment Deadline: {analysis.payment_deadline or 'Not specified'}

═══ RANSOM NOTE ═══
{note_preview}

═══ ANALYSIS REQUEST ═══
Please provide a comprehensive forensic analysis covering:

1. **Family Assessment**: Confirm or refine the ransomware family identification with your reasoning

2. **Attack Chain (MITRE ATT&CK)**: Map the complete attack chain with specific ATT&CK technique IDs

3. **Initial Access**: Analyze how the attacker gained entry — be specific about the method

4. **Persistence & Lateral Movement**: What techniques did the attacker use to maintain access and spread?

5. **Encryption Assessment**: Analyze the encryption approach and any known weaknesses

6. **IOC Assessment**: Evaluate the extracted IOCs and flag any that are particularly valuable for law enforcement

7. **Exfiltration Indicators**: Based on the family and TTPs, was data likely exfiltrated before encryption?

8. **Recovery Feasibility**: Honest assessment of recovery options

9. **FBI Report Key Points**: The 5 most critical facts for the FBI IC3 report

10. **Immediate Actions**: Top 5 actions the victim must take in the next 24 hours

Format your response with these exact section headers."""

    def _parse_response(
        self,
        text: str,
        thinking: str,
        tokens: int
    ) -> AIAnalysisResult:
        """Parse the structured AI response into an AIAnalysisResult."""

        def _extract_section(header: str) -> str:
            """Extract text under a specific section header."""
            import re
            pattern = rf"#+\s*{re.escape(header)}[^\n]*\n(.*?)(?=\n#+\s|\Z)"
            m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            return m.group(1).strip() if m else ""

        def _extract_bullets(section_text: str) -> list[str]:
            """Extract bullet points from a section."""
            bullets = []
            for line in section_text.split("\n"):
                line = line.strip()
                if line.startswith(("- ", "• ", "→ ", "* ", "  - ")):
                    bullets.append(line.lstrip("-•→* ").strip())
                elif line and line[0].isdigit() and ". " in line:
                    bullets.append(line.split(". ", 1)[1].strip())
            return bullets if bullets else [section_text[:200]] if section_text else []

        # Extract MITRE techniques
        mitre_text = _extract_section("Attack Chain")
        mitre_techniques = []
        import re
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", mitre_text + text):
            t = m.group()
            if t not in mitre_techniques:
                mitre_techniques.append(t)

        return AIAnalysisResult(
            family_assessment=_extract_section("Family Assessment"),
            attack_chain_summary=_extract_section("Attack Chain"),
            mitre_techniques=mitre_techniques,
            initial_access_analysis=_extract_section("Initial Access"),
            persistence_analysis=_extract_section("Persistence"),
            encryption_assessment=_extract_section("Encryption Assessment"),
            exfiltration_indicators=_extract_section("Exfiltration"),
            ioc_assessment=_extract_section("IOC Assessment"),
            notable_iocs=_extract_bullets(_extract_section("IOC Assessment")),
            recovery_assessment=_extract_section("Recovery Feasibility"),
            fbi_report_key_points=_extract_bullets(_extract_section("FBI Report")),
            immediate_actions=_extract_bullets(_extract_section("Immediate Actions")),
            raw_response=text,
            thinking_summary=thinking[:500] if thinking else "",
            tokens_used=tokens,
        )

    async def _update_knowledge_base(
        self,
        analysis: RansomwareAnalysis,
        ai_result: AIAnalysisResult
    ) -> None:
        """Store new learnings in the knowledge base for future cases."""
        if not self.knowledge_base:
            return

        try:
            await self.knowledge_base.learn_from_case({
                "family": analysis.ransomware_family,
                "variant": analysis.ransomware_variant,
                "attack_vector": analysis.attack_vector.primary_vector,
                "mitre_techniques": ai_result.mitre_techniques,
                "iocs": {
                    "bitcoin": [i.value for i in analysis.ioc_report.bitcoin_addresses],
                    "onion": [i.value for i in analysis.ioc_report.onion_addresses],
                    "email": [i.value for i in analysis.ioc_report.email_addresses],
                },
                "encryption_algorithms": analysis.encryption_analysis.detected_algorithms,
                "ai_family_assessment": ai_result.family_assessment[:500],
                "case_id": analysis.case_id,
            })
        except Exception as e:
            logger.warning(f"Failed to update knowledge base: {e}")
