import cv2
import numpy as np
import base64
import uuid
from typing import Optional
from datetime import datetime, timezone
from ai_engine.models import (
    ScanResponse, ThreatCategory, RiskLevel,
    DetectionSignal, EvidenceBreakdown, TechnicalEvidence
)
from ai_engine.detectors.url_detector import analyze_url
from ai_engine.detectors.message_detector import analyze_message

# Maximum permitted base64 payload length (~15MB encoded ≈ 11MB raw image)
MAX_BASE64_BYTES = 15 * 1024 * 1024

def decode_qr_image_bytes(image_bytes: bytes) -> str:
    """
    Decodes QR code from raw image bytes using OpenCV QRCodeDetector.
    """
    if not image_bytes:
        return ""
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return ""
        
        # Cap image resolution to max dimension 1920 to prevent memory spikes & slow OpenCV operations
        h, w = img.shape[:2]
        max_dim = 1920
        if max(h, w) > max_dim:
            scale = max_dim / float(max(h, w))
            new_w = int(w * scale)
            new_h = int(h * scale)
            img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        return data.strip() if data else ""
    except Exception:
        return ""

def decode_qr_base64(b64_string: str) -> str:
    """
    Decodes QR code from base64 string with input size validation.
    """
    if not b64_string or len(b64_string) > MAX_BASE64_BYTES:
        return ""
    try:
        if "," in b64_string:
            b64_string = b64_string.split(",", 1)[1]
        image_bytes = base64.b64decode(b64_string, validate=False)
        return decode_qr_image_bytes(image_bytes)
    except Exception:
        return ""

def analyze_qr(image_bytes: Optional[bytes] = None, b64_string: Optional[str] = None, raw_text: Optional[str] = None) -> ScanResponse:
    decoded_payload = ""
    if raw_text:
        decoded_payload = raw_text.strip()
    elif image_bytes:
        decoded_payload = decode_qr_image_bytes(image_bytes)
    elif b64_string:
        decoded_payload = decode_qr_base64(b64_string)

    if not decoded_payload:
        return ScanResponse(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            mode="qr",
            input_snippet="Unreadable or Empty QR Code",
            risk_score=50,
            risk_level=RiskLevel.MEDIUM_RISK,
            threat_category=ThreatCategory.UNKNOWN,
            title="Unreadable or Empty QR Code",
            summary="The provided image could not be decoded as a valid QR code symbol. Barcode may be obscured, corrupted, or formatted unconventionally.",
            ai_explanation="The image does not contain readable QR matrix patterns or has insufficient contrast/resolution. Treat unverified barcodes with caution.",
            signals=[
                DetectionSignal(
                    id="qr-unreadable",
                    category="anomaly",
                    title="Unverified Barcode Matrix",
                    description="QR decoding algorithm failed to locate standard finder patterns or error-correction blocks.",
                    severity="medium"
                )
            ],
            recommended_actions=[
                "Do not interact with or scan distorted or obscured barcodes.",
                "Ensure the image is clear, unobstructed, and contains a standard QR matrix code."
            ],
            confidence_score=75,
            evidence_breakdown=EvidenceBreakdown(behavioral_score=50),
            technical_evidence=TechnicalEvidence(safe_factors=[])
        )

    # If payload is a URL
    if decoded_payload.startswith(("http://", "https://", "www.")) or ("." in decoded_payload and "/" in decoded_payload):
        resp = analyze_url(decoded_payload)
        resp.mode = "qr"
        resp.input_snippet = f"QR Payload: {decoded_payload}"
        resp.technical_evidence.qr_payload_extracted = decoded_payload
        resp.title = f"[QR Code Analysis] {resp.title}"
        resp.ai_explanation = f"Decoded QR code target: '{decoded_payload}'. " + resp.ai_explanation
        return resp

    # Otherwise analyze as message/text
    resp = analyze_message(decoded_payload)
    resp.mode = "qr"
    resp.input_snippet = f"QR Payload: {decoded_payload}"
    resp.technical_evidence.qr_payload_extracted = decoded_payload
    resp.title = f"[QR Code Analysis] {resp.title}"
    resp.ai_explanation = f"Decoded QR code message text. " + resp.ai_explanation
    return resp
