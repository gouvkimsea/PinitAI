import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ai_engine.main import app
from ai_engine.detectors.language import detect_language
from ai_engine.detectors.message_detector import analyze_message
from ai_engine.detectors.url_detector import analyze_url
from ai_engine.detectors.file_detector import analyze_file_buffer
from ai_engine.detectors.qr_detector import analyze_qr

client = TestClient(app)

def test_language_detection():
    assert detect_language("Hello world, this is an appointment reminder.") == "en"
    assert detect_language("សួស្តីបង តើថ្ងៃស្អែកបងទំនេរទេ?") == "km"
    assert detect_language("Congratulations អ្នកឈ្នះ $500 ចុច link នេះ") == "km-en"

def test_message_scam_english():
    resp = analyze_message("URGENT: Your PayPal account has been suspended! Enter password now http://paypal.top/login")
    assert resp.risk_score >= 60
    assert resp.threat_category in ["PHISHING", "SOCIAL_ENGINEERING", "ACCOUNT_TAKEOVER"]
    assert len(resp.signals) >= 2

def test_message_scam_khmer():
    resp = analyze_message("អបអរសាទរ! អ្នកឈ្នះរង្វាន់ទឹកប្រាក់ $500 សូមចុច link នេះជាបន្ទាន់ដើម្បីទទួលរង្វាន់ http://aba-lucky.top")
    assert resp.risk_score >= 60
    assert resp.technical_evidence.language_detected in ["km", "km-en"]
    assert len(resp.signals) >= 2

def test_message_safe():
    resp = analyze_message("Hi Mom, I'm heading home right now. See you soon!")
    assert resp.risk_score < 20
    assert resp.threat_category == "SAFE"

def test_url_detector_phishing():
    resp = analyze_url("https://paypal-security-update.top/login")
    assert resp.risk_score >= 60
    assert resp.threat_category == "PHISHING"
    assert resp.technical_evidence.typosquatting_detected is True

def test_url_detector_ip():
    resp = analyze_url("http://192.168.1.100/download.exe")
    assert resp.risk_score >= 60
    assert resp.technical_evidence.ip_detected is True

def test_url_detector_safe():
    resp = analyze_url("https://www.apple.com/support")
    assert resp.risk_score < 20
    assert resp.threat_category == "SAFE"

def test_file_detector_deceptive_double_ext():
    # Disguised executable payload
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + (b"\x00" * 100)
    resp = analyze_file_buffer(fake_exe, "urgent_invoice.pdf.exe")
    assert resp.risk_score >= 65
    assert resp.threat_category == "MALWARE"
    assert any("Double Extension" in s.title for s in resp.signals)

def test_file_detector_standard_pe_caution():
    # Clean standard executable dummy without deceptive markers
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + (b"\x00" * 100)
    resp = analyze_file_buffer(fake_exe, "clean_installer.exe")
    # Never fake certainty: standard PE without exploit markers is UNKNOWN / caution
    assert resp.threat_category == "UNKNOWN / NEEDS_REVIEW"
    assert resp.risk_score == 30

def test_file_detector_benign_pdf():
    fake_pdf = b"%PDF-1.5\n%Trailer\nstartxref\n%%EOF"
    resp = analyze_file_buffer(fake_pdf, "annual_report.pdf")
    assert resp.threat_category == "SAFE"
    assert resp.risk_score <= 10

def test_url_detector_invalid():
    resp = analyze_url("not_a_valid_url")
    assert resp.threat_category == "UNKNOWN / NEEDS_REVIEW"
    assert resp.risk_score == 0
    assert any("Malformed" in s.title or "Syntax" in s.title for s in resp.signals)

def test_qr_text_analysis():
    resp = analyze_qr(raw_text="https://paypal-verify-account.top/login")
    assert resp.mode == "qr"
    assert resp.risk_score >= 60
    assert resp.technical_evidence.qr_payload_extracted is not None

def test_qr_unreadable_not_safe():
    resp = analyze_qr(raw_text="")
    assert resp.mode == "qr"
    assert resp.risk_score == 50
    assert resp.risk_level.value == "MEDIUM_RISK"
    assert resp.threat_category.value == "UNKNOWN / NEEDS_REVIEW"
    assert any("qr-unreadable" in s.id for s in resp.signals)

def test_api_message_endpoint():
    response = client.post("/api/analyze/message", json={"content": "Congratulations you won $1000 prize!"})
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert data["threat_category"] == "PRIZE_SCAM"

def test_api_feedback_and_admin():
    # Submit message scan
    scan_res = client.post("/api/analyze/message", json={"content": "Your account is suspended immediately"}).json()
    scan_id = scan_res["id"]

    # Submit feedback
    fb_res = client.post("/api/feedback", json={
        "scan_id": scan_id,
        "is_correct": True,
        "comments": "Accurate detection"
    })
    assert fb_res.status_code == 200
    assert fb_res.json()["status"] == "success"

    # Admin stats
    stats_res = client.get("/api/admin/stats")
    assert stats_res.status_code == 200
    assert "total_scans" in stats_res.json()

    # Admin metrics with false positive/negative rates
    metrics_res = client.get("/api/admin/metrics")
    assert metrics_res.status_code == 200
    m_data = metrics_res.json()
    assert m_data["accuracy"] >= 0.8
    assert "false_positive_rate" in m_data
    assert "false_negative_rate" in m_data

    # Admin dataset splits
    splits_res = client.get("/api/admin/dataset/splits")
    assert splits_res.status_code == 200
    s_data = splits_res.json()
    assert s_data["total_samples"] >= 30
    assert s_data["train_count"] > 0
    assert s_data["validation_count"] > 0
    assert s_data["test_count"] > 0

def test_admin_auth_protection(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "super_secret_test_admin_key")
    # Without header -> 401
    res = client.get("/api/admin/stats")
    assert res.status_code == 401
    assert "detail" in res.json()

    # With invalid header -> 401
    res_bad = client.get("/api/admin/stats", headers={"X-Admin-Key": "wrong_key"})
    assert res_bad.status_code == 401

    # With valid header -> 200
    res_ok = client.get("/api/admin/stats", headers={"X-Admin-Key": "super_secret_test_admin_key"})
    assert res_ok.status_code == 200

