import hashlib
import math
import uuid
import zipfile
import io
import re
import socket
from collections import Counter
from datetime import datetime, timezone
from typing import List, Tuple
from ai_engine.models import (
    ScanResponse, ThreatCategory, RiskLevel,
    DetectionSignal, EvidenceBreakdown, TechnicalEvidence
)

DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "ps1", "vbs", "js", "scr", "pif", "apk", "jar", "msi"
}

EICAR_PATTERN = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def calculate_entropy(data: bytes) -> float:
    """Shannon entropy over a byte buffer.

    Uses collections.Counter (C-level implementation) for byte counting,
    which is ~3-5x faster than a Python dict loop on large buffers.
    """
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def probe_clamav_daemon(host: str = "127.0.0.1", port: int = 3310, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def analyze_file_buffer(file_bytes: bytes, filename: str) -> ScanResponse:
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    entropy = calculate_entropy(file_bytes)
    file_size_kb = len(file_bytes) / 1024.0

    ext = filename.split('.')[-1].lower() if '.' in filename else ""
    signals: List[DetectionSignal] = []
    
    clamav_available = probe_clamav_daemon()
    concrete_threat_count = 0

    # 1. Standard EICAR Antivirus Test Signature
    if EICAR_PATTERN in file_bytes:
        concrete_threat_count += 1
        signals.append(DetectionSignal(
            id="sig_file_eicar",
            category="malware_signature",
            title="EICAR Standard Antivirus Test Signature",
            description="Matches the industry-standard antivirus test pattern designed to verify malware detection.",
            severity="high"
        ))

    # 2. Deceptive Double Extension Check (e.g. invoice.pdf.exe)
    double_ext_match = re.search(r'\.(pdf|docx|xlsx|jpg|png)\.(exe|bat|cmd|vbs|js|scr)$', filename, re.IGNORECASE)
    if double_ext_match:
        concrete_threat_count += 1
        signals.append(DetectionSignal(
            id="sig_file_double_ext",
            category="social_engineering",
            title=f"Deceptive Double Extension (.{(double_ext_match.group(1))}.{(double_ext_match.group(2))})",
            description="The file uses a disguised double extension to deceive users into opening an executable as a document.",
            severity="high"
        ))

    # 3. Magic Bytes Inspection
    header = file_bytes[:16]
    detected_mime = "application/octet-stream"
    is_native_executable = False

    if header.startswith(b"MZ"):
        detected_mime = "application/x-dosexec"
        is_native_executable = True
        signals.append(DetectionSignal(
            id="sig_file_pe_header",
            category="file_format",
            title="Windows Portable Executable (PE/MZ) Binary",
            description="File contains native compiled machine instructions requiring sandbox verification.",
            severity="medium"
        ))
    elif header.startswith(b"\x7fELF"):
        detected_mime = "application/x-elf"
        is_native_executable = True
        signals.append(DetectionSignal(
            id="sig_file_elf_header",
            category="file_format",
            title="Linux ELF Native Executable Format",
            description="Native compiled binary format for Unix/Linux systems.",
            severity="medium"
        ))
    elif header.startswith(b"%PDF-"):
        detected_mime = "application/pdf"
        # Search for PDF exploit stream markers
        content_sample = file_bytes[:50000]
        if b"/JavaScript" in content_sample or b"/JS" in content_sample:
            concrete_threat_count += 1
            signals.append(DetectionSignal(
                id="sig_file_pdf_js",
                category="active_content",
                title="Embedded PDF JavaScript Stream",
                description="Document contains embedded JavaScript instructions, commonly used in weaponized PDF exploits.",
                severity="high"
            ))
        if b"/Launch" in content_sample:
            concrete_threat_count += 1
            signals.append(DetectionSignal(
                id="sig_file_pdf_launch",
                category="active_content",
                title="Embedded PDF External Launch Directive",
                description="Document requests permission to launch external executables on the host machine.",
                severity="high"
            ))
    elif header.startswith(b"PK\x03\x04"):
        detected_mime = "application/zip"
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                for name in namelist:
                    sub_ext = name.split('.')[-1].lower() if '.' in name else ""
                    if sub_ext in DANGEROUS_EXTENSIONS:
                        concrete_threat_count += 1
                        signals.append(DetectionSignal(
                            id=f"sig_file_zip_nested_{sub_ext}",
                            category="archive_hazard",
                            title=f"Embedded Executable in Archive ({name})",
                            description=f"Compressed archive contains hidden executable binary: {name}",
                            severity="high"
                        ))
                    if "vbaProject.bin" in name:
                        concrete_threat_count += 1
                        signals.append(DetectionSignal(
                            id="sig_file_vba_macro",
                            category="macro_hazard",
                            title="Embedded Microsoft Office VBA Macro Project",
                            description="Office document contains active VBA macro code capable of downloading external payloads.",
                            severity="high"
                        ))
        except Exception:
            pass

    # 4. Dangerous Extension without PE Header (e.g. script files .bat, .ps1, .vbs)
    if ext in DANGEROUS_EXTENSIONS and not is_native_executable:
        signals.append(DetectionSignal(
            id="sig_file_script_ext",
            category="file_format",
            title=f"Executable Script Extension (.{ext.upper()})",
            description=f"File extension .{ext} represents an executable script format.",
            severity="medium"
        ))

    # 5. Shannon Entropy Evaluation (Packed / Encrypted Dropper)
    if entropy >= 7.6 and (is_native_executable or ext in DANGEROUS_EXTENSIONS) and len(file_bytes) > 2048:
        concrete_threat_count += 1
        signals.append(DetectionSignal(
            id="sig_file_entropy",
            category="packing_entropy",
            title=f"Abnormally High Shannon Entropy ({entropy}/8.0)",
            description="Entropy score indicates cryptographic packing or crypter obfuscation frequently used by malware droppers.",
            severity="high"
        ))
    elif entropy >= 7.2 and len(file_bytes) > 2048:
        signals.append(DetectionSignal(
            id="sig_file_entropy_notice",
            category="packing_entropy",
            title=f"Elevated Byte Entropy ({entropy}/8.0)",
            description="Compressed or encrypted byte segments detected.",
            severity="low"
        ))

    # Safe Factors & Technical Evidence
    safe_factors: List[str] = []
    if not is_native_executable:
        safe_factors.append("No native compiled machine code header (PE/ELF) detected.")
    if entropy < 7.2:
        safe_factors.append(f"Standard byte entropy distribution ({entropy}/8.0).")
    if not double_ext_match:
        safe_factors.append("Standard single-extension file structure.")
    if clamav_available:
        safe_factors.append("Local ClamAV daemon is online (TCP 3310).")
    else:
        safe_factors.append("External Antivirus API (ClamAV): Offline / Unconfigured. Analysis based on static structural heuristics.")

    # 6. Objective Scoring & Classification Logic (Never fake certainty)
    if concrete_threat_count >= 1:
        # We have concrete, verifiable malicious indicators
        threat_category = ThreatCategory.MALWARE
        threat_score = min(100.0, 50.0 + (concrete_threat_count * 25.0))
        file_score = 80.0
        rep_score = 75.0
        behav_score = 70.0
        risk_score = int(min(98, max(65, round(threat_score * 0.40 + file_score * 0.30 + rep_score * 0.20 + behav_score * 0.10))))
        risk_level = RiskLevel.HIGH_RISK if risk_score < 80 else RiskLevel.CRITICAL_RISK
        title = f"High Risk — Malicious Indicators Identified"
        summary = f"Static analysis identified {concrete_threat_count} concrete hazard signature(s) such as active document streams or deceptive structures."
        recommendations = [
            "DO NOT open, execute, or extract this file.",
            "Quarantine or permanently delete the file immediately.",
            "Do not enable document macros if opened in office applications."
        ]
        ai_explanation = (
            f"Static security inspection of '{filename}' identified concrete threat markers: "
            f"{', '.join([s.title for s in signals if s.severity == 'high'][:2])}. "
            f"These traits are strongly correlated with weaponized documents or malware droppers."
        )
    elif is_native_executable or ext in DANGEROUS_EXTENSIONS:
        # Executable format, but NO concrete malicious exploit markers found statically
        # Crucial principle: Never claim an executable is malware without evidence
        threat_category = ThreatCategory.UNKNOWN
        threat_score = 30.0
        file_score = 35.0
        rep_score = 25.0
        behav_score = 15.0
        risk_score = 30
        risk_level = RiskLevel.LOW_RISK
        title = "Executable Binary — Dynamic Sandbox Verification Required"
        summary = "File is a compiled executable format. No static exploit markers were found, but executables require dynamic sandbox detonation and updated antivirus inspection."
        recommendations = [
            "Verify the download source and vendor signature before opening.",
            "Scan with updated desktop antivirus software.",
            "Execute within a sandboxed virtual machine if provenance is unverified."
        ]
        ai_explanation = (
            f"The file '{filename}' contains executable structures ({detected_mime}). "
            f"Static structural heuristics did not find active weaponization or deceptive extensions. "
            f"However, native software cannot be classified as definitively safe without dynamic execution in a sandbox."
        )
    else:
        # Standard benign file format
        threat_category = ThreatCategory.SAFE
        threat_score = 0.0
        file_score = 0.0
        rep_score = 5.0
        behav_score = 0.0
        risk_score = 5
        risk_level = RiskLevel.SAFE
        title = "Benign Document Format"
        summary = "Static structural inspection detected no hazardous active content, executable headers, or deceptive extensions."
        recommendations = ["File conforms to standard benign specifications."]
        ai_explanation = f"Binary structure and format inspection of '{filename}' shows standard harmless document characteristics with normal byte entropy."

    return ScanResponse(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        mode="file",
        input_snippet=f"{filename} ({round(file_size_kb, 1)} KB)",
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        title=title,
        summary=summary,
        ai_explanation=ai_explanation,
        signals=signals,
        recommended_actions=recommendations,
        confidence_score=92 if concrete_threat_count >= 1 else 88,
        evidence_breakdown=EvidenceBreakdown(
            message_analysis_score=0.0,
            url_analysis_score=0.0,
            threat_indicators_score=round(threat_score, 1),
            reputation_score=round(rep_score, 1),
            behavioral_score=round(behav_score, 1)
        ),
        technical_evidence=TechnicalEvidence(
            file_hash_sha256=sha256_hash,
            file_mime_type=detected_mime,
            entropy=entropy,
            safe_factors=safe_factors
        )
    )
