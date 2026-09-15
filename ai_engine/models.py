from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class ThreatCategory(str, Enum):
    SAFE = "SAFE"
    PHISHING = "PHISHING"
    INVESTMENT_SCAM = "INVESTMENT_SCAM"
    JOB_SCAM = "JOB_SCAM"
    ROMANCE_SCAM = "ROMANCE_SCAM"
    FAKE_SHOP = "FAKE_SHOP"
    IMPERSONATION = "IMPERSONATION"
    PAYMENT_SCAM = "PAYMENT_SCAM"
    PRIZE_SCAM = "PRIZE_SCAM"
    MALWARE = "MALWARE"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN / NEEDS_REVIEW"

class RiskLevel(str, Enum):
    SAFE = "SAFE"                 # 0–19
    LOW_RISK = "LOW_RISK"         # 20–39
    MEDIUM_RISK = "MEDIUM_RISK"   # 40–59
    HIGH_RISK = "HIGH_RISK"       # 60–79
    CRITICAL_RISK = "CRITICAL_RISK" # 80–100

class DetectionSignal(BaseModel):
    id: str
    category: str
    title: str
    description: str
    severity: str = "medium"  # low, medium, high

class EvidenceBreakdown(BaseModel):
    message_analysis_score: float = Field(0.0, description="Message Analysis (25% weight)")
    url_analysis_score: float = Field(0.0, description="URL Analysis (30% weight)")
    threat_indicators_score: float = Field(0.0, description="Threat Indicators (20% weight)")
    reputation_score: float = Field(0.0, description="Reputation Data (15% weight)")
    behavioral_score: float = Field(0.0, description="Behavioral Signals (10% weight)")

class TechnicalEvidence(BaseModel):
    language_detected: str = "en"
    domain_evaluated: Optional[str] = None
    ip_detected: bool = False
    typosquatting_detected: bool = False
    qr_payload_extracted: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_mime_type: Optional[str] = None
    entropy: Optional[float] = None
    safe_factors: List[str] = Field(default_factory=list)

class ScanResponse(BaseModel):
    id: str
    timestamp: str
    mode: str
    input_snippet: str
    risk_score: int  # 0 to 100
    risk_level: RiskLevel
    threat_category: ThreatCategory
    title: str
    summary: str
    ai_explanation: str
    signals: List[DetectionSignal]
    recommended_actions: List[str]
    confidence_score: int
    evidence_breakdown: EvidenceBreakdown
    technical_evidence: TechnicalEvidence

# Request models
class MessageScanRequest(BaseModel):
    content: str
    language_hint: Optional[str] = None

class UrlScanRequest(BaseModel):
    url: str

class QrScanRequest(BaseModel):
    image_base64: Optional[str] = None
    raw_text: Optional[str] = None

class FeedbackRequest(BaseModel):
    scan_id: str
    is_correct: bool
    suggested_category: Optional[str] = None
    comments: Optional[str] = None

class TrainingItem(BaseModel):
    id: str
    content: str
    content_type: str  # message, url, qr, file
    language: str      # en, km, km-en
    category: str
    risk_score: int
    source: str
    verified: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AdminStatsResponse(BaseModel):
    total_scans: int
    scams_detected: int
    high_risk_urls: int
    false_positive_rate: float
    most_common_threat: str
    category_distribution: Dict[str, int]
    language_distribution: Dict[str, int]

class ModelMetricsResponse(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positives: int
    false_negatives: int
    false_positive_rate: float
    false_negative_rate: float
    total_evaluated: int

class DatasetSplitsResponse(BaseModel):
    total_samples: int
    train_count: int
    validation_count: int
    test_count: int
    train_samples: List[TrainingItem]
    validation_samples: List[TrainingItem]
    test_samples: List[TrainingItem]

class ExplanationSignalItem(BaseModel):
    signal: str
    detail: str
    severity: str = "medium"
    source_detector: Optional[str] = None

class ExplanationScamType(BaseModel):
    category: str
    name: str
    description: str
    threat_level: str

class ExplanationUncertainty(BaseModel):
    is_uncertain: bool
    reason: str
    missing_information: List[str] = Field(default_factory=list)
    confidence_level: str = "medium"

class AiStructuredExplanationResponse(BaseModel):
    why_suspicious: str
    triggered_signals: List[ExplanationSignalItem] = Field(default_factory=list)
    scam_type: ExplanationScamType
    actionable_advice: List[str] = Field(default_factory=list)
    uncertainty_notes: ExplanationUncertainty
    grounded_in_evidence: bool = True
    evidence_summary: str
    summary: str
    recommended_actions: List[str] = Field(default_factory=list)
    generated_by: str = "ai_model"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ExplainRequest(BaseModel):
    content: Optional[str] = None
    target_type: str = "TEXT"
    threat_category: str = "UNKNOWN"
    risk_score: int = 0
    indicators: List[str] = Field(default_factory=list)
    language: Optional[str] = "en"

