import re
import uuid
from datetime import datetime, timezone
from typing import List, Tuple
from ai_engine.models import (
    ScanResponse, ThreatCategory, RiskLevel,
    DetectionSignal, EvidenceBreakdown, TechnicalEvidence
)
from ai_engine.detectors.language import detect_language

# URL extraction pattern — compiled once at module load
_URL_RE = re.compile(r'https?://[^\s]+')

# Scam detection pattern definitions.
# Tuple format: (raw_pattern_str, title, severity)
# Patterns are pre-compiled into re.Pattern objects at module load to avoid
# repeated compilation overhead on every analyze_message() call.
_RAW_PATTERNS = {
    "urgency": [
        (r'\b(immediately|urgent|act now|hurry|within 24 hours|account suspended|final notice|expires? (today|soon)|before it expires)\b', "Urgency Pressure (EN)", "high"),
        (r'(បន្ទាន់|ជាបន្ទាន់|ក្នុងរយៈពេល|គណនីត្រូវបានផ្អាក|ដំណឹងចុងក្រោយ|ផុតកំណត់)', "Urgency Pressure (KM)", "high")
    ],
    "credentials_otp": [
        (r'\b(password|otp|one-time password|pin code|security code|verify your credentials|login here)\b', "Credential / OTP Request (EN)", "high"),
        (r'(ពាក្យសម្ងាត់|លេខកូដ|កូដ otp|លេខសម្ងាត់|ផ្ទៀងផ្ទាត់គណនី|ចូលប្រើប្រាស់)', "Credential / OTP Request (KM)", "high")
    ],
    "prize_lottery": [
        (r'\b(congratulations|you won|won \$|claim reward|lottery prize|lucky draw|free gift)\b', "Unrealistic Prize / Reward (EN)", "high"),
        (r'(អបអរសាទរ|អ្នកឈ្នះ|ឈ្នះរង្វាន់|ទទួលរង្វាន់|ចាប់ឆ្នោត|កាដូឥតគិតថ្លៃ)', "Unrealistic Prize / Reward (KM)", "high")
    ],
    "job_scam": [
        (r'\b(earn \$[0-9]+ per day|work from home|telegram job|daily payout|like youtube videos|part-time job hiring)\b', "Deceptive Job / Task Offer (EN)", "high"),
        (r'(ការងារក្រៅម៉ោង|រកចំណូល|ប្រាក់ចំណូលខ្ពស់|ធ្វើការតាមផ្ទះ|ការងារ telegram|ចុច like បានលុយ)', "Deceptive Job / Task Offer (KM)", "high")
    ],
    "investment_crypto": [
        (r'\b(guaranteed returns|crypto investment|bitcoin doubling|forex trading|high profit|passive income|usdt)\b', "Unrealistic Investment Scheme (EN)", "high"),
        (r'(ការវិនិយោគ|ចំណេញ១០០%|គ្រីបតូ|ទ្វេដង|ប្រាក់ចំណេញខ្ពស់|ជួញដូរ)', "Unrealistic Investment Scheme (KM)", "high")
    ],
    "impersonation_bank": [
        (r'\b(aba bank|acleda|paypal|apple support|netflix billing|customs department|security alert)\b', "Brand / Bank Impersonation (EN)", "medium"),
        (r'(ធនាគារ aba|ធនាគារ អេស៊ីលីដា|នគរបាល|គយ|សន្តិសុខធនាគារ)', "Brand / Bank Impersonation (KM)", "medium")
    ],
    "payment_pressure": [
        (r'\b(wire transfer|send (money|funds|cash|\$?\d+|usdt|btc|crypto)|transfer \$?[0-9]+|pay fee|gift card|western union|deposit required)\b', "Payment / Wire Solicitation (EN)", "high"),
        (r'(ផ្ទេរប្រាក់|បង់ប្រាក់|បង់ថ្លៃសេវា|កក់ប្រាក់|ដាក់ប្រាក់|ផ្ញើលុយ|ផ្ទេរលុយ)', "Payment / Wire Solicitation (KM)", "high")
    ],
    "threats": [
        (r'\b(arrest|police|lawsuit|legal action|court|warrant|block account permanently)\b', "Intimidation & Coercion (EN)", "high"),
        (r'(ជាប់គុក|ប៉ូលីស|តុលាការ|ចាត់វិធានការច្បាប់|បិទគណនីជាអចិន្ត្រៃយ៍)', "Intimidation & Coercion (KM)", "high")
    ],
    "romance_scam": [
        (r'\b(sorry wrong number|let\'s chat on (whatsapp|telegram)|are you the coach|meet on whatsapp|chat privately)\b', "Romance / Pig Butchering Pretext (EN)", "high"),
        (r'(សុំទោសច្រឡំលេខ|ជជែកគ្នាតាម telegram|ជជែកគ្នាតាម whatsapp)', "Romance / Pig Butchering Pretext (KM)", "high")
    ],
    "account_takeover": [
        (r'\b(account (has been|is) (suspended|locked|frozen|compromised)|unauthorized login detected|security lockout|reactivate your account)\b', "Account Takeover / Suspension Alert (EN)", "high"),
        (r'(គណនីត្រូវបានផ្អាក|គណនីត្រូវបានចាក់សោ|រកឃើញការលួចចូល)', "Account Takeover / Suspension Alert (KM)", "high")
    ],
    "suspicious_payment": [
        (r'\b(buy (apple|steam|amazon) gift cards|pay via bitcoin|send (\d+\s*)?usdt to (wallet|address)|pay via western union)\b', "Suspicious Payment Instructions (EN)", "high"),
        (r'(ទិញកាត gift|បង់តាម bitcoin|ផ្ញើតាម usdt)', "Suspicious Payment Instructions (KM)", "high")
    ],
    "link_clicks": [
        (r'\b(click (here|the link|below)|tap (here|this link)|follow the link|open the link|click to (verify|confirm|claim|unlock))\b', "Link Click Solicitation (EN)", "medium"),
        (r'(ចុចទីនេះ|ចុចលើតំណភ្ជាប់|បើក link|ចុច link ខាងក្រោម)', "Link Click Solicitation (KM)", "medium")
    ]
}

# Pre-compile all patterns at import time for zero per-call overhead
PATTERNS = {
    category: [
        (re.compile(raw_pattern, re.IGNORECASE), title, severity)
        for raw_pattern, title, severity in rules
    ]
    for category, rules in _RAW_PATTERNS.items()
}

def analyze_message(content: str) -> ScanResponse:
    lang = detect_language(content)
    signals: List[DetectionSignal] = []
    category_scores = {
        ThreatCategory.PHISHING: 0,
        ThreatCategory.PRIZE_SCAM: 0,
        ThreatCategory.JOB_SCAM: 0,
        ThreatCategory.INVESTMENT_SCAM: 0,
        ThreatCategory.ROMANCE_SCAM: 0,
        ThreatCategory.IMPERSONATION: 0,
        ThreatCategory.PAYMENT_SCAM: 0,
        ThreatCategory.ACCOUNT_TAKEOVER: 0,
        ThreatCategory.SOCIAL_ENGINEERING: 0
    }

    lower_text = content.lower()

    # Match patterns — use pre-compiled re.Pattern objects (.search has no compilation overhead)
    for category_key, rules in PATTERNS.items():
        for compiled_pattern, title, severity in rules:
            if compiled_pattern.search(lower_text):
                sig_id = f"sig_{len(signals) + 1}"
                if category_key == "credentials_otp":
                    signals.append(DetectionSignal(
                        id=sig_id, category="credentials", title=title,
                        description="Direct request for authentication credentials, passwords, or single-use OTP codes.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.ACCOUNT_TAKEOVER] += 40
                    category_scores[ThreatCategory.PHISHING] += 35
                elif category_key == "prize_lottery":
                    signals.append(DetectionSignal(
                        id=sig_id, category="reward", title=title,
                        description="Promises unexpected financial rewards or prizes commonly used as bait.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.PRIZE_SCAM] += 45
                elif category_key == "job_scam":
                    signals.append(DetectionSignal(
                        id=sig_id, category="employment", title=title,
                        description="Advertises unrealistic high-payout or task-based remote work schemes.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.JOB_SCAM] += 50
                elif category_key == "investment_crypto":
                    signals.append(DetectionSignal(
                        id=sig_id, category="financial", title=title,
                        description="Claims guaranteed investment profits, crypto duplication, or forex trading.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.INVESTMENT_SCAM] += 50
                elif category_key == "urgency":
                    signals.append(DetectionSignal(
                        id=sig_id, category="psychological", title=title,
                        description="Creates artificial time pressure to bypass critical thinking.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.SOCIAL_ENGINEERING] += 25
                    category_scores[ThreatCategory.PHISHING] += 20
                elif category_key == "impersonation_bank":
                    signals.append(DetectionSignal(
                        id=sig_id, category="identity", title=title,
                        description="References a recognized bank, platform, or authority to build false trust.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.IMPERSONATION] += 35
                elif category_key == "payment_pressure":
                    signals.append(DetectionSignal(
                        id=sig_id, category="payment", title=title,
                        description="Instructs recipient to transfer funds or upfront fees.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.PAYMENT_SCAM] += 40
                elif category_key == "threats":
                    signals.append(DetectionSignal(
                        id=sig_id, category="coercion", title=title,
                        description="Uses threats of arrest, legal prosecution, or permanent account forfeiture.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.SOCIAL_ENGINEERING] += 40
                elif category_key == "romance_scam":
                    signals.append(DetectionSignal(
                        id=sig_id, category="romance", title=title,
                        description="Pretexting intimacy or accidental contact to build trust for financial extraction.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.ROMANCE_SCAM] += 45
                elif category_key == "account_takeover":
                    signals.append(DetectionSignal(
                        id=sig_id, category="account_takeover", title=title,
                        description="False alert claiming account suspension or unauthorized access to harvest login credentials.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.ACCOUNT_TAKEOVER] += 45
                    category_scores[ThreatCategory.PHISHING] += 30
                elif category_key == "suspicious_payment":
                    signals.append(DetectionSignal(
                        id=sig_id, category="payment", title=title,
                        description="Instructions to transfer money via untraceable methods (gift cards, crypto, money transfer).",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.PAYMENT_SCAM] += 40
                elif category_key == "link_clicks":
                    signals.append(DetectionSignal(
                        id=sig_id, category="link_clicks", title=title,
                        description="Explicit solicitation urging the user to click external links.",
                        severity=severity
                    ))
                    category_scores[ThreatCategory.PHISHING] += 30

    # Embedded URL check — use pre-compiled module-level pattern
    urls_found = _URL_RE.findall(content)
    if urls_found:
        signals.append(DetectionSignal(
            id=f"sig_url_{len(signals)+1}",
            category="url_presence",
            title="Embedded Web Link Detected",
            description=f"Message contains link: {urls_found[0][:40]}...",
            severity="medium"
        ))
        category_scores[ThreatCategory.PHISHING] += 25

    # Calculate evidence weights
    high_sigs = sum(1 for s in signals if s.severity == "high")
    med_sigs = sum(1 for s in signals if s.severity == "medium")
    
    msg_weight = min(100.0, (high_sigs * 55.0) + (med_sigs * 25.0))
    url_weight = 75.0 if urls_found else 0.0
    threat_weight = min(100.0, (high_sigs * 45.0) + (med_sigs * 20.0))
    rep_weight = 70.0 if (high_sigs >= 2) else (45.0 if high_sigs == 1 else 10.0)
    
    top_cat_score = max(category_scores.values()) if category_scores else 0
    behav_weight = min(100.0, top_cat_score * 1.5)

    if urls_found:
        raw_risk = (
            (msg_weight * 0.25) +
            (url_weight * 0.30) +
            (threat_weight * 0.20) +
            (rep_weight * 0.15) +
            (behav_weight * 0.10)
        )
    else:
        # Dynamic normalization for text-only messages: 40% message, 30% indicators, 15% reputation, 15% behavioral
        raw_risk = (
            (msg_weight * 0.40) +
            (threat_weight * 0.30) +
            (rep_weight * 0.15) +
            (behav_weight * 0.15)
        )
    risk_score = int(min(100, max(0, round(raw_risk))))

    # Determine Threat Category
    if risk_score < 20 and len(signals) == 0:
        threat_category = ThreatCategory.SAFE
        risk_level = RiskLevel.SAFE
    else:
        # Find dominant category
        sorted_cats = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        dominant_cat, top_score = sorted_cats[0]
        if top_score > 0:
            threat_category = dominant_cat
        else:
            threat_category = ThreatCategory.OTHER

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

    # Recommendations & Titles
    recommendations = []
    if risk_score >= 60:
        title = f"High Risk — Possible {threat_category.value.replace('_', ' ').title()}"
        summary = "This message demonstrates prominent indicators of deceptive social engineering or fraudulent manipulation."
        recommendations = [
            "Do not click on links or verify credentials via provided prompts.",
            "Never send one-time verification passwords (OTP) or money transfers.",
            "Contact the official institution directly through verified channels."
        ]
        ai_explanation = (
            f"The message was identified as {lang.upper()} text containing {len(signals)} strong threat indicators, "
            f"notably {', '.join([s.title for s in signals[:2]])}. It attempts to create urgency or solicit sensitive actions."
        )
    elif risk_score >= 20:
        title = f"Suspicious Activity Detected ({threat_category.value.replace('_', ' ').title()})"
        summary = "Certain language traits resemble promotional unsolicited contact or unverified claims."
        recommendations = [
            "Exercise caution before replying or following any instructions.",
            "Verify the sender's true identity through a separate contact method."
        ]
        ai_explanation = (
            f"Analyzed content contains mild risk indicators ({len(signals)} found). "
            f"While not definitively malicious, caution is advised before sharing information."
        )
    else:
        title = "Likely Safe Message"
        summary = "No overt indicators of phishing, fraudulent solicitation, or high-pressure scamming were detected."
        recommendations = [
            "Content appears standard. Continue practicing normal security hygiene."
        ]
        ai_explanation = "No known deceptive social engineering patterns or suspicious credential prompts were found."

    safe_factors = []
    if not urls_found:
        safe_factors.append("No suspicious embedded hyperlinks detected.")
    if len(signals) == 0:
        safe_factors.append("No urgency or credential harvesting keywords found.")

    return ScanResponse(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        mode="message",
        input_snippet=content[:120] + ("..." if len(content) > 120 else ""),
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        title=title,
        summary=summary,
        ai_explanation=ai_explanation,
        signals=signals,
        recommended_actions=recommendations,
        confidence_score=92 if len(signals) >= 2 else (85 if len(signals) == 1 else 90),
        evidence_breakdown=EvidenceBreakdown(
            message_analysis_score=round(msg_weight, 1),
            url_analysis_score=round(url_weight, 1),
            threat_indicators_score=round(threat_weight, 1),
            reputation_score=round(rep_weight, 1),
            behavioral_score=round(behav_weight, 1)
        ),
        technical_evidence=TechnicalEvidence(
            language_detected=lang,
            safe_factors=safe_factors
        )
    )
