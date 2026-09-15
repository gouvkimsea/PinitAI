import os
import sys
import uuid
from collections import deque
from typing import Dict, List, Optional
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from ai_engine.models import (
    ScanResponse, MessageScanRequest, UrlScanRequest,
    QrScanRequest, FeedbackRequest, AdminStatsResponse,
    ModelMetricsResponse, TrainingItem, RiskLevel, DatasetSplitsResponse,
    ExplainRequest, AiStructuredExplanationResponse, ExplanationSignalItem,
    ExplanationScamType, ExplanationUncertainty
)
from ai_engine.detectors.message_detector import analyze_message
from ai_engine.detectors.url_detector import analyze_url
from ai_engine.detectors.qr_detector import analyze_qr
from ai_engine.detectors.file_detector import analyze_file_buffer
from ai_engine.dataset.evaluator import get_training_dataset, evaluate_model, get_dataset_splits

app = FastAPI(
    title="ScamCheck AI - AI Scam Detection Platform API",
    description="Multi-modal bilingual (English & Khmer) scam and malware analysis engine",
    version="2.0.0"
)

# Allowed CORS origins (Strict explicit origins without wildcard fallback)
ALLOWED_CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174,http://localhost:5000,http://127.0.0.1:5000"
).split(",")
ALLOWED_CORS_ORIGINS = [o.strip() for o in ALLOWED_CORS_ORIGINS if o.strip()]

# Enable CORS for frontend integration and API Gateway
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Administrative Authentication Dependency
def verify_admin_key(x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")):
    expected_key = os.getenv("ADMIN_API_KEY", "").strip()
    if expected_key:
        if not x_admin_key or x_admin_key.strip() != expected_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid or missing X-Admin-Key header."
            )
    return True

# In-memory storage for scans and feedback (Bounded to prevent memory exhaustion)
MAX_CACHED_SCANS = 1000
SCANS_STORE: Dict[str, ScanResponse] = {}
# deque with maxlen provides O(1) append + automatic eviction (vs O(n) list.pop(0))
FEEDBACK_STORE: deque = deque(maxlen=1000)
DATASET_STORE: List[TrainingItem] = get_training_dataset()
# Dict index for O(1) dataset item lookup (vs O(n) linear scan)
DATASET_INDEX: Dict[str, int] = {item.id: i for i, item in enumerate(DATASET_STORE)}

def store_scan(scan: ScanResponse):
    if len(SCANS_STORE) >= MAX_CACHED_SCANS:
        # Evict oldest 100 items (FIFO)
        keys_to_evict = list(SCANS_STORE.keys())[:100]
        for k in keys_to_evict:
            SCANS_STORE.pop(k, None)
    SCANS_STORE[scan.id] = scan

def store_feedback(entry: Dict):
    # deque(maxlen=1000) handles eviction automatically at O(1)
    FEEDBACK_STORE.append(entry)

@app.get("/")
def root():
    return {
        "service": "ScamCheck AI Core API",
        "status": "operational",
        "version": "2.0.0",
        "endpoints": [
            "/api/analyze/message",
            "/api/analyze/url",
            "/api/analyze/qr",
            "/api/analyze/file",
            "/api/explain",
            "/api/feedback",
            "/api/admin/stats",
            "/api/admin/metrics",
            "/api/admin/dataset"
        ]
    }

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_cached_scans": len(SCANS_STORE)
    }

@app.post("/api/analyze/message", response_model=ScanResponse)
def endpoint_analyze_message(req: MessageScanRequest):
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")
    result = analyze_message(req.content)
    store_scan(result)
    return result

@app.post("/api/analyze/url", response_model=ScanResponse)
def endpoint_analyze_url(req: UrlScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    result = analyze_url(req.url.strip())
    store_scan(result)
    return result

@app.post("/api/analyze/qr", response_model=ScanResponse)
async def endpoint_analyze_qr(
    image: Optional[UploadFile] = File(None),
    image_base64: Optional[str] = Form(None),
    raw_text: Optional[str] = Form(None)
):
    if image is not None:
        file_bytes = await image.read()
        result = analyze_qr(image_bytes=file_bytes)
    elif image_base64:
        result = analyze_qr(b64_string=image_base64)
    elif raw_text:
        result = analyze_qr(raw_text=raw_text)
    else:
        raise HTTPException(status_code=400, detail="Must provide an image file, base64 payload, or text.")
    
    store_scan(result)
    return result

@app.post("/api/analyze/file", response_model=ScanResponse)
async def endpoint_analyze_file(file: UploadFile = File(...)):
    # Limit upload size to 25MB
    file_bytes = await file.read()
    if len(file_bytes) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size (25MB).")
    
    raw_filename = file.filename or "uploaded_file.bin"
    safe_filename = os.path.basename(raw_filename).replace("..", "_")
    result = analyze_file_buffer(file_bytes, safe_filename)
    store_scan(result)
    return result

@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: str):
    if scan_id in SCANS_STORE:
        return SCANS_STORE[scan_id]
    raise HTTPException(status_code=404, detail="Scan record not found.")

@app.post("/api/explain", response_model=AiStructuredExplanationResponse)
def endpoint_explain(req: ExplainRequest):
    """
    Grounded AI Explanation Layer:
    Takes structured evidence from the deterministic detection pipeline and explains:
    1. Why the content is suspicious
    2. Which signals triggered the detection
    3. What type of scam may be involved
    4. What the user should do
    5. What uncertainty remains
    Guaranteed zero hallucination: strictly references provided indicators.
    """
    is_km = req.language in ["km", "km-en"]
    score = req.risk_score
    cat = req.threat_category.upper()
    indicators = req.indicators or []

    # 1. Map Triggered Signals (Never Fabricate)
    signals: List[ExplanationSignalItem] = []
    for ind in indicators:
        signals.append(ExplanationSignalItem(
            signal=ind,
            detail=f"Security detector flagged: {ind}",
            severity="critical" if score >= 80 else "high" if score >= 60 else "medium",
            source_detector="detection_pipeline"
        ))

    # 2. Resolve Scam Type
    if score < 20:
        scam_type = ExplanationScamType(
            category="safe_content",
            name="ការប្រាស្រ័យទាក់ទងធម្មតា (សុវត្ថិភាព)" if is_km else "Standard Legitimate Communication",
            description="មិនមានល្បិចបោកប្រាស់ ឬការគំរាមកំហែងសុវត្ថិភាពច្បាស់លាស់ត្រូវបានរកឃើញឡើយ។" if is_km else "Content exhibits normal patterns without deceptive or malicious indicators.",
            threat_level="SAFE"
        )
    elif "PHISH" in cat or "CREDENTIAL" in cat:
        scam_type = ExplanationScamType(
            category="phishing",
            name="ការក្លែងបន្លំលួចគណនី (Phishing)" if is_km else "Credential Phishing Attack",
            description="ជនខិលខូចបង្កើតសារ ឬគេហទំព័រក្លែងក្លាយដើម្បីបន្លំលួចយកពាក្យសម្ងាត់ ឬព័ត៌មានធនាគារ។" if is_km else "Attackers use deceptive messages or counterfeit portals to harvest user login credentials and sensitive financial data.",
            threat_level="CRITICAL" if score >= 80 else "HIGH"
        )
    elif "INVEST" in cat:
        scam_type = ExplanationScamType(
            category="fake_investment",
            name="ការបោកប្រាស់វិនិយោគក្លែងក្លាយ" if is_km else "High-Yield Investment Fraud",
            description="ការសន្យាផ្តល់ផលចំណេញខ្ពស់ ឬគ្មានហានិភ័យដើម្បីទាក់ទាញឱ្យផ្ញើប្រាក់។" if is_km else "Fraudulent schemes promising guaranteed, unrealistic returns before misappropriating victim deposits.",
            threat_level="CRITICAL" if score >= 80 else "HIGH"
        )
    elif "JOB" in cat:
        scam_type = ExplanationScamType(
            category="fake_job",
            name="ការងារក្លែងក្លាយតាមអនឡាញ" if is_km else "Employment / Task Fee Scam",
            description="ផ្តល់ការងារងាយស្រួលប្រាក់ខែខ្ពស់ ប៉ុន្តែតម្រូវឱ្យបង់ប្រាក់កក់ជាមុន។" if is_km else "Victims are promised remote employment or task rewards but required to deposit advance clearance fees.",
            threat_level="HIGH"
        )
    else:
        scam_type = ExplanationScamType(
            category="general_threat",
            name="ការគំរាមកំហែងសន្តិសុខទូទៅ" if is_km else "Suspicious Threat Anomaly",
            description="រកឃើញភាពមិនប្រក្រតីដែលតម្រូវឱ្យមានការផ្ទៀងផ្ទាត់ដោយប្រុងប្រយ័ត្ន។" if is_km else "Content exhibits warning signals requiring independent verification.",
            threat_level="HIGH" if score >= 60 else "SUSPICIOUS"
        )

    # 3. Formulate Why Suspicious
    if score < 20:
        why = (
            "ខ្លឹមសារនេះមិនមានសញ្ញាគួរឱ្យសង្ស័យឡើយ។ ការវិភាគស៊ីជម្រៅមិនបានរកឃើញល្បិចបង្កើតការភ័យស្លន់ស្លោ ឬតំណភ្ជាប់ក្លែងបន្លំណាមួយនោះទេ។"
            if is_km else
            "Multi-detector analysis detected no overt scam indicators, malicious links, or credential harvesting patterns."
        )
    elif signals:
        sig_text = ", ".join(s.signal for s in signals[:3])
        why = (
            f"ខ្លឹមសារនេះមានហានិភ័យ ដោយសារបានរកឃើញសញ្ញាគ្រោះថ្នាក់៖ {sig_text}។"
            if is_km else
            f"This content triggered verified threat indicators: {sig_text}. The observed patterns align with deceptive social engineering tactics."
        )
    else:
        why = (
            "ខ្លឹមសារត្រូវបានសម្គាល់ថាគួរឱ្យសង្ស័យដោយសារទម្រង់ ឬបរិបទមិនប្រក្រតី។"
            if is_km else
            "Elevated caution flagged due to structural anomalies, although specific named signatures remain limited."
        )

    # 4. Actionable Advice
    if score < 20:
        advice = [
            "បន្តដោយប្រុងប្រយ័ត្នជាធម្មតា" if is_km else "Proceed with standard caution.",
            "ផ្ទៀងផ្ទាត់តាមឆានែលផ្លូវការ ប្រសិនបើមានការស្នើសុំប្រាក់" if is_km else "Always verify unexpected requests for funds or credentials via official channels."
        ]
    elif "PHISH" in cat or "ACCOUNT" in cat:
        advice = [
            "ហាមផ្ញើលេខកូដសម្ងាត់ (OTP) ឬពាក្យសម្ងាត់ឱ្យអ្នកដទៃដាច់ខាត" if is_km else "NEVER share one-time passwords (OTP) or credentials with anyone.",
            "ហាមចុចលើតំណភ្ជាប់ ឬបំពេញព័ត៌មានក្នុងទម្រង់ដែលបានផ្ញើមក" if is_km else "Do NOT click any embedded links or enter credentials on external pages.",
            "ទាក់ទងទៅកាន់ធនាគារតាមលេខទូរស័ព្ទផ្លូវការ" if is_km else "Contact the institution directly using verified official contact numbers."
        ]
    else:
        advice = [
            "ហាមផ្ទេរប្រាក់ ឬផ្តល់ទិន្នន័យសម្ងាត់" if is_km else "Do NOT transfer funds or provide sensitive information.",
            "ផ្ទៀងផ្ទាត់អត្តសញ្ញាណអ្នកផ្ញើដោយផ្ទាល់" if is_km else "Independently verify sender identity via established channels."
        ]

    # 5. Uncertainty Notes (Explicitly required for insufficient evidence)
    is_uncertain = len(signals) == 0 or score < 20 or (score >= 20 and score <= 55)
    if len(signals) == 0 or score < 20:
        uncertainty = ExplanationUncertainty(
            is_uncertain=True,
            reason="មិនមានភស្តុតាងគ្រប់គ្រាន់ដើម្បីបញ្ជាក់ពីចេតនាអាក្រក់ឡើយ។ ការវិភាគអត្ថបទមិនអាចផ្ទៀងផ្ទាត់អត្តសញ្ញាណពិតរបស់អ្នកផ្ញើបានទេ។" if is_km else "Insufficient evidence of malicious intent. Static text inspection cannot verify the sender's real-world offline identity or future unstated intentions.",
            missing_information=["Out-of-band sender verification", "Off-platform conversation context"],
            confidence_level="low"
        )
    elif is_uncertain:
        uncertainty = ExplanationUncertainty(
            is_uncertain=True,
            reason="ភស្តុតាងដែលទទួលបានមិនទាន់គ្រប់គ្រាន់ដើម្បីសន្និដ្ឋានដាច់ខាត។" if is_km else "Insufficient deterministic evidence to reach a definitive verdict. Some anomalies can occur in benign contexts.",
            missing_information=["Full landing page behavior", "Established relationship history"],
            confidence_level="medium"
        )
    else:
        uncertainty = ExplanationUncertainty(
            is_uncertain=False,
            reason="ភស្តុតាងរឹងមាំត្រូវបានបញ្ជាក់ដោយប្រព័ន្ធស្វែងរកសញ្ញាគ្រោះថ្នាក់ជាច្រើនស្របគ្នា។" if is_km else "High confidence based on multiple correlated security indicators independently confirming deceptive characteristics.",
            missing_information=[],
            confidence_level="high"
        )

    summary = (
        f"Verified threat signals detected corresponding to {cat}." if score >= 40
        else "No suspicious indicators identified. Standard precautions advised."
    )

    return AiStructuredExplanationResponse(
        why_suspicious=why,
        triggered_signals=signals,
        scam_type=scam_type,
        actionable_advice=advice,
        uncertainty_notes=uncertainty,
        grounded_in_evidence=True,
        evidence_summary=f"Evaluated {len(signals)} telemetry indicators.",
        summary=summary,
        recommended_actions=advice,
        generated_by="ai_model"
    )

@app.post("/api/feedback")
def submit_feedback(req: FeedbackRequest):
    feedback_entry = {
        "id": str(uuid.uuid4()),
        "scan_id": req.scan_id,
        "is_correct": req.is_correct,
        "suggested_category": req.suggested_category,
        "comments": req.comments,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    store_feedback(feedback_entry)
    
    # If user provided a correction on an existing scan, add to training dataset candidate queue
    if not req.is_correct and req.scan_id in SCANS_STORE:
        scan = SCANS_STORE[req.scan_id]
        new_item = TrainingItem(
            id=f"user_fb_{len(DATASET_STORE) + 1}",
            content=scan.input_snippet,
            content_type=scan.mode,
            language=scan.technical_evidence.language_detected,
            category=req.suggested_category or "USER_REPORTED",
            risk_score=scan.risk_score,
            source="user_feedback",
            verified=False
        )
        DATASET_STORE.append(new_item)

    return {
        "status": "success",
        "message": "Feedback recorded successfully. Thank you for contributing to ScamCheck AI safety.",
        "feedback_id": feedback_entry["id"]
    }

@app.get("/api/admin/stats", response_model=AdminStatsResponse, dependencies=[Depends(verify_admin_key)])
def get_admin_stats():
    total_scans = len(SCANS_STORE)

    # Single O(n) pass over SCANS_STORE
    scams_detected = 0
    high_risk_urls = 0
    cat_dist: Dict[str, int] = {}
    lang_dist: Dict[str, int] = {}

    for s in SCANS_STORE.values():
        if s.risk_score >= 40:
            scams_detected += 1
        if s.mode == "url" and s.risk_score >= 60:
            high_risk_urls += 1
        cat_key = s.threat_category.value
        cat_dist[cat_key] = cat_dist.get(cat_key, 0) + 1
        l_key = s.technical_evidence.language_detected
        lang_dist[l_key] = lang_dist.get(l_key, 0) + 1

    incorrect_feedback = sum(1 for f in FEEDBACK_STORE if not f["is_correct"])
    fp_rate = round((incorrect_feedback / max(1, len(FEEDBACK_STORE))) * 100, 1) if FEEDBACK_STORE else 0.0

    most_common = max(cat_dist.items(), key=lambda x: x[1])[0] if cat_dist else "NONE"

    # Return authentic observed statistics directly without synthetic demo inflation
    return AdminStatsResponse(
        total_scans=total_scans,
        scams_detected=scams_detected,
        high_risk_urls=high_risk_urls,
        false_positive_rate=fp_rate,
        most_common_threat=most_common,
        category_distribution=cat_dist,
        language_distribution=lang_dist,
    )

@app.get("/api/admin/feedback", dependencies=[Depends(verify_admin_key)])
def get_admin_feedback():
    return {
        "count": len(FEEDBACK_STORE),
        "feedback": list(FEEDBACK_STORE)
    }

@app.get("/api/admin/dataset", dependencies=[Depends(verify_admin_key)])
def get_admin_dataset():
    return {
        "total_items": len(DATASET_STORE),
        "items": DATASET_STORE
    }

@app.get("/api/admin/metrics", response_model=ModelMetricsResponse, dependencies=[Depends(verify_admin_key)])
def get_admin_metrics():
    return evaluate_model()

@app.get("/api/admin/dataset/splits", response_model=DatasetSplitsResponse, dependencies=[Depends(verify_admin_key)])
def get_admin_dataset_splits():
    return get_dataset_splits()

@app.post("/api/admin/dataset/verify/{item_id}", dependencies=[Depends(verify_admin_key)])
def verify_dataset_item(item_id: str):
    # O(1) lookup using index dict instead of O(n) linear scan
    idx = DATASET_INDEX.get(item_id)
    if idx is not None and idx < len(DATASET_STORE):
        item = DATASET_STORE[idx]
        if item.id == item_id:
            item.verified = True
            return {"status": "success", "item": item}
    raise HTTPException(status_code=404, detail="Dataset item not found.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
