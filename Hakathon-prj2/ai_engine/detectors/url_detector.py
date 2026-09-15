import re
import uuid
import functools
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from ai_engine.models import (
    ScanResponse, ThreatCategory, RiskLevel,
    DetectionSignal, EvidenceBreakdown, TechnicalEvidence
)

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "buzz", "cam", "work", "loan", "cfd", "zip", "mov", "gq", "ml", "tk", "ga"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"
}

POPULAR_BRANDS = [
    "paypal", "apple", "google", "facebook", "telegram", "binance",
    "microsoft", "netflix", "amazon", "instagram", "acleda", "chase",
    "ababank", "wingbank", "canadia", "coinbase", "metamask", "dhl", "fedex"
]

COMPOUND_CCTLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "edu.au",
    "gov.kh", "edu.kh", "com.kh", "org.kh", "co.jp", "com.sg", "co.in"
}

def extract_base_domain(hostname: str) -> Tuple[str, str]:
    parts = hostname.lower().split('.')
    if len(parts) <= 2:
        return hostname, ""
    
    potential_compound = f"{parts[-2]}.{parts[-1]}"
    if potential_compound in COMPOUND_CCTLDS and len(parts) >= 3:
        base_domain = f"{parts[-3]}.{potential_compound}"
        subdomain = ".".join(parts[:-3])
        return base_domain, subdomain
    
    base_domain = f"{parts[-2]}.{parts[-1]}"
    subdomain = ".".join(parts[:-2])
    return base_domain, subdomain

@functools.lru_cache(maxsize=512)
def levenshtein_distance(s1: str, s2: str) -> int:
    """Cached Levenshtein distance — repeated (domain_label, brand) pairs cost O(1)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

def analyze_url(raw_url: str) -> ScanResponse:
    cleaned_url = (raw_url or "").strip()
    if not cleaned_url or len(cleaned_url) < 3:
        return ScanResponse(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            mode="url",
            input_snippet=(raw_url or "")[:100],
            risk_score=0,
            risk_level=RiskLevel.SAFE,
            threat_category=ThreatCategory.UNKNOWN,
            title="Empty or Invalid URL Input",
            summary="The submitted input is empty or too short to represent a valid web address.",
            ai_explanation="Please enter a valid URL, domain name, or web link to initiate security analysis.",
            signals=[DetectionSignal(
                id="sig_url_empty",
                category="input_validation",
                title="Invalid Input Length",
                description="Input string is insufficient to parse a hostname.",
                severity="low"
            )],
            recommended_actions=["Provide a complete URL such as https://example.com"],
            confidence_score=99,
            evidence_breakdown=EvidenceBreakdown(),
            technical_evidence=TechnicalEvidence(safe_factors=["No remote host contacted."])
        )

    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "https://" + cleaned_url

    parsed = urlparse(cleaned_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))

    if not hostname or ("." not in hostname and not is_ip and hostname != "localhost"):
        return ScanResponse(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            mode="url",
            input_snippet=raw_url[:100],
            risk_score=0,
            risk_level=RiskLevel.SAFE,
            threat_category=ThreatCategory.UNKNOWN,
            title="Malformed URL — Missing Valid Domain",
            summary="The provided input could not be resolved into a valid registered domain name or IP address.",
            ai_explanation="A valid URL requires a registered domain (such as .com, .org, or .com.kh) or a valid numeric IP address.",
            signals=[DetectionSignal(
                id="sig_url_syntax",
                category="input_validation",
                title="Unrecognized Domain Syntax",
                description="Unable to parse a recognized top-level domain from the input string.",
                severity="low"
            )],
            recommended_actions=["Check the spelling of the domain and include a valid TLD."],
            confidence_score=95,
            evidence_breakdown=EvidenceBreakdown(),
            technical_evidence=TechnicalEvidence(safe_factors=["Malformed URL was not transmitted."])
        )

    signals: List[DetectionSignal] = []
    base_domain, subdomain = extract_base_domain(hostname)
    tld = hostname.split('.')[-1] if '.' in hostname else ""
    
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
    is_shortener = hostname in KNOWN_SHORTENERS
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    has_at_symbol = "@" in raw_url
    hyphen_count = hostname.count("-")
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    is_http_only = parsed.scheme == "http"

    # 1. IP address hostname check
    if is_ip:
        signals.append(DetectionSignal(
            id="sig_url_ip",
            category="url_anomaly",
            title="Raw Numeric IP Address Hostname",
            description=f"URL points directly to an IP address ({hostname}) rather than a registered domain name, common in malware hosting.",
            severity="high"
        ))

    # 2. Suspicious Top-Level Domain
    if is_suspicious_tld:
        signals.append(DetectionSignal(
            id="sig_url_tld",
            category="url_anomaly",
            title=f"High-Abuse Top-Level Domain (.{tld})",
            description=f"The domain uses the .{tld} extension, statistically recognized for low-cost registrar scam campaigns.",
            severity="medium"
        ))

    # 3. URL Shortener
    if is_shortener:
        signals.append(DetectionSignal(
            id="sig_url_shortener",
            category="url_anomaly",
            title="URL Shortening Service Detected",
            description=f"Shortener ({hostname}) masks the true final destination link.",
            severity="medium"
        ))

    # 4. Excessive Subdomains
    if subdomain_count >= 3:
        signals.append(DetectionSignal(
            id="sig_url_subdomain",
            category="url_anomaly",
            title="Excessive Subdomain Depth",
            description=f"Domain contains {subdomain_count} subdomain levels, often used to bypass basic domain reputation filters.",
            severity="medium"
        ))

    # 5. Dangerous characters
    if has_at_symbol:
        signals.append(DetectionSignal(
            id="sig_url_at_symbol",
            category="url_anomaly",
            title="Embedded Userinfo '@' in URL",
            description="The '@' sign redirects browsers to the host after the symbol, disguising the actual destination.",
            severity="high"
        ))

    if hyphen_count >= 3:
        signals.append(DetectionSignal(
            id="sig_url_hyphens",
            category="url_anomaly",
            title="Multi-Hyphenated Domain Structure",
            description="High frequency of hyphens in hostname is typical of spoofed domain registrations.",
            severity="medium"
        ))

    # 6. Typosquatting / Brand Impersonation check
    typosquatting_found = False
    domain_label = base_domain.split('.')[0] if '.' in base_domain else base_domain
    for brand in POPULAR_BRANDS:
        if brand in hostname and brand != domain_label:
            signals.append(DetectionSignal(
                id=f"sig_typo_{brand}",
                category="impersonation",
                title=f"Brand Mimicry: '{brand.capitalize()}' in Unofficial Domain",
                description=f"Hostname references '{brand}' but root domain is '{base_domain}', indicating credential theft or impersonation.",
                severity="high"
            ))
            typosquatting_found = True
            break
        elif 1 <= levenshtein_distance(domain_label, brand) <= 2:
            signals.append(DetectionSignal(
                id=f"sig_lev_{brand}",
                category="impersonation",
                title=f"Possible Typosquatting Target: '{brand.capitalize()}'",
                description=f"Domain '{domain_label}' is 1–2 characters distinct from official '{brand}'.",
                severity="high"
            ))
            typosquatting_found = True
            break

    # 7. Sensitive login or verification paths
    login_patterns = r'/(login|signin|account|auth|verify|secure|update|wallet|banking)'
    if re.search(login_patterns, path):
        if is_http_only or is_ip or typosquatting_found or is_suspicious_tld:
            signals.append(DetectionSignal(
                id="sig_url_fake_login",
                category="data_harvesting",
                title="Sensitive Authentication Form on Suspicious Host",
                description="URL requests login/verification credentials on an unverified or high-risk domain.",
                severity="high"
            ))

    # 8. Executable payload in path
    if re.search(r'\.(exe|apk|bat|cmd|vbs|scr|pif|jar)$', path):
        signals.append(DetectionSignal(
            id="sig_url_executable_payload",
            category="malware",
            title="Direct Executable Payload Hosted in URL Path",
            description=f"URL path requests immediate download of executable binary: {path.split('/')[-1]}",
            severity="high"
        ))

    # 9. Suspicious query parameters (open redirects or credential harvesting)
    if any(param in query for param in ["redirect=", "url=", "next=", "target=", "dest=", "return_to="]):
        signals.append(DetectionSignal(
            id="sig_url_open_redirect",
            category="url_anomaly",
            title="Potential Open Redirect Parameter in Query",
            description="URL query contains destination redirection parameters.",
            severity="medium"
        ))

    # Scoring
    high_count = sum(1 for s in signals if s.severity == "high")
    med_count = sum(1 for s in signals if s.severity == "medium")
    
    url_score = min(100.0, (high_count * 55.0) + (med_count * 25.0))
    if is_ip:
        url_score = max(url_score, 70.0)
    threat_score = min(100.0, (high_count * 45.0) + (med_count * 20.0))
    rep_score = 85.0 if (is_ip or is_suspicious_tld or typosquatting_found) else 15.0
    behav_score = 80.0 if ("login" in path or "verify" in path or any("Executable" in s.title for s in signals)) else 10.0

    raw_risk = (
        (url_score * 0.40) +
        (threat_score * 0.30) +
        (rep_score * 0.20) +
        (behav_score * 0.10)
    )
    risk_score = int(min(100, max(0, round(raw_risk))))

    # Category & Risk Level
    if typosquatting_found or any("Credential" in s.title or "Authentication" in s.title for s in signals):
        threat_category = ThreatCategory.PHISHING
    elif is_ip:
        threat_category = ThreatCategory.MALWARE
    elif risk_score >= 60:
        threat_category = ThreatCategory.PHISHING
    elif risk_score >= 20:
        threat_category = ThreatCategory.OTHER
    else:
        threat_category = ThreatCategory.SAFE

    if risk_score >= 80:
        risk_level = RiskLevel.CRITICAL_RISK
    elif risk_score >= 60:
        risk_level = RiskLevel.HIGH_RISK
    elif risk_score >= 40:
        risk_level = RiskLevel.MEDIUM_RISK
    elif risk_score >= 20:
        risk_level = RiskLevel.LOW_RISK
    else:
        risk_level = RiskLevel.SAFE

    recommendations = []
    if risk_score >= 60:
        title = f"High Risk — Deceptive Link ({threat_category.value.replace('_', ' ').title()})"
        summary = "Technical analysis identified strong indicators of domain impersonation, suspicious infrastructure, or credential harvesting."
        recommendations = [
            "Do NOT visit this URL in your web browser.",
            "Do not input passwords, credit card info, or personal information.",
            "If you received this via email or message, block and report the sender."
        ]
        ai_explanation = (
            f"Technical parsing flagged {len(signals)} domain anomalies for {hostname}, "
            f"including: {', '.join([s.title for s in signals[:2]])}. This infrastructure conforms to phishing patterns."
        )
    elif risk_score >= 20:
        title = "Suspicious URL Structure"
        summary = "The link exhibits several unusual formatting traits such as URL shortening or non-standard TLD extensions."
        recommendations = [
            "Proceed with extreme caution.",
            "Ensure the URL expands to a recognized corporate root domain before interacting."
        ]
        ai_explanation = f"Detected {len(signals)} moderate indicators. Destination should be validated independently."
    else:
        title = "Likely Safe URL"
        summary = "No anomalous domain characteristics, typosquatting variants, or IP hosting markers were discovered."
        recommendations = ["URL appears standard. Always confirm HTTPS padlock icon before submitting data."]
        ai_explanation = "Domain structure conforms to legitimate registration practices with no brand spoofing signals."

    safe_factors = []
    if not is_ip:
        safe_factors.append("Uses registered domain name rather than bare IP address.")
    if parsed.scheme == "https":
        safe_factors.append("Encrypted HTTPS transport protocol active.")
    if not is_shortener:
        safe_factors.append("Direct domain link (no link obfuscation or shortening).")

    return ScanResponse(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        mode="url",
        input_snippet=raw_url,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        title=title,
        summary=summary,
        ai_explanation=ai_explanation,
        signals=signals,
        recommended_actions=recommendations,
        confidence_score=95 if len(signals) >= 2 else 90,
        evidence_breakdown=EvidenceBreakdown(
            message_analysis_score=0.0,
            url_analysis_score=round(url_score, 1),
            threat_indicators_score=round(threat_score, 1),
            reputation_score=round(rep_score, 1),
            behavioral_score=round(behav_score, 1)
        ),
        technical_evidence=TechnicalEvidence(
            domain_evaluated=hostname,
            ip_detected=is_ip,
            typosquatting_detected=typosquatting_found,
            safe_factors=safe_factors
        )
    )
