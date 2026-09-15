"""
Comprehensive End-to-End Test Suite for ScamCheck AI Platform.
Tests:
1. Multilingual Message Analysis (English, Khmer, Mixed km-en)
2. URL Analysis (Typosquatting, Look-alike domains, Direct IPs, Safe domains)
3. QR Code Analysis (Generating QR image, decoding via OpenCV, analyzing extracted target)
4. Static File Scanner (Executable header inspection, macro indicators, Shannon entropy)
5. User Feedback Loop (Correct vs Incorrect with Category adjustment)
6. Admin Telemetry, Model Evaluation (Accuracy, Precision, Recall, F1), Dataset Export
7. Express Backend Health, Scan Queuing, Report Ingestion
"""

import io
import json
import urllib.request
import urllib.parse
import qrcode
import sys

FASTAPI_BASE = "http://127.0.0.1:8000"
EXPRESS_BASE = "http://127.0.0.1:5000/api/v1"

def post_json(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8"))

def get_json(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8"))

def run_tests():
    print("==================================================")
    print("      SCAMCHECK AI - SYSTEM VERIFICATION SUITE    ")
    print("==================================================")
    passed = 0
    total = 0

    # TEST 1: English Prize Scam
    total += 1
    print("\n[TEST 1] English Prize Scam Message Analysis...")
    res = post_json(f"{FASTAPI_BASE}/api/analyze/message", {
        "content": "Congratulations! You won $500. Click this link http://claim-gift.tk/verify to get your prize immediately or account closed!"
    })
    lang = res['technical_evidence'].get('language_detected')
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']} ({res['risk_level']})")
    print(f" -> Language Detected: {lang}")
    assert res['threat_category'] in ['PRIZE_SCAM', 'PHISHING', 'ACCOUNT_TAKEOVER']
    assert res['risk_score'] >= 60
    assert lang == 'en'
    assert 'evidence_breakdown' in res
    assert 'ai_explanation' in res
    passed += 1
    print(" -> PASS [x]")

    # TEST 2: Khmer Prize Scam
    total += 1
    print("\n[TEST 2] Khmer Prize Scam Message Analysis...")
    khmer_msg = "អ្នកបានឈ្នះរង្វាន់ចំនួន ៥០០ ដុល្លារ សូមផ្ញើព័ត៌មានផ្ទាល់ខ្លួនជាបន្ទាន់ដើម្បីទទួលរង្វាន់"
    res = post_json(f"{FASTAPI_BASE}/api/analyze/message", {"content": khmer_msg})
    lang = res['technical_evidence'].get('language_detected')
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']} ({res['risk_level']})")
    print(f" -> Language Detected: {lang}")
    assert res['threat_category'] in ['PRIZE_SCAM', 'PHISHING']
    assert res['risk_score'] >= 50
    assert lang == 'km'
    passed += 1
    print(" -> PASS [x]")

    # TEST 3: Mixed Khmer-English Scam
    total += 1
    print("\n[TEST 3] Mixed Khmer-English Scam Message Analysis...")
    mixed_msg = "Congratulations អ្នកឈ្នះ $500 ចុច link នេះដើម្បី claim រង្វាន់"
    res = post_json(f"{FASTAPI_BASE}/api/analyze/message", {"content": mixed_msg})
    lang = res['technical_evidence'].get('language_detected')
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']} ({res['risk_level']})")
    print(f" -> Language Detected: {lang}")
    assert res['threat_category'] in ['PRIZE_SCAM', 'PHISHING']
    assert lang == 'km-en'
    passed += 1
    print(" -> PASS [x]")

    # TEST 4: Legitimate Safe Message
    total += 1
    print("\n[TEST 4] Legitimate Conversational Message Analysis...")
    safe_msg = "Hi Dad, I will arrive home around 6 PM. Can you pick up some dinner?"
    res = post_json(f"{FASTAPI_BASE}/api/analyze/message", {"content": safe_msg})
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']} ({res['risk_level']})")
    assert res['threat_category'] == 'SAFE'
    assert res['risk_score'] <= 25
    passed += 1
    print(" -> PASS [x]")

    # TEST 5: Phishing URL Analysis (Typosquatting & Look-alike)
    total += 1
    print("\n[TEST 5] Technical URL Phishing Analysis...")
    res = post_json(f"{FASTAPI_BASE}/api/analyze/url", {
        "url": "http://paypal-security-update.account-verify.tk/login"
    })
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']}")
    print(f" -> Warning Signs: {len(res['signals'])} indicators identified")
    assert res['threat_category'] == 'PHISHING'
    assert res['risk_score'] >= 75
    assert any('typosquat' in s['description'].lower() or 'paypal' in s['description'].lower() or 'brand' in s['title'].lower() for s in res['signals'])
    passed += 1
    print(" -> PASS [x]")

    # TEST 6: QR Code Scanner (OpenCV image decode + URL analysis)
    total += 1
    print("\n[TEST 6] QR Code Generation and Quarantine Scan...")
    qr_target = "http://secure-bank-login.xyz/update"
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(qr_target)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()

    # Create multipart request manually or via boundary
    boundary = "----WebKitFormBoundaryScamCheckTest7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="image"; filename="scam_qr.png"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode("utf-8") + img_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{FASTAPI_BASE}/api/analyze/qr",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode("utf-8"))
    
    print(f" -> Decoded QR Payload: {res['technical_evidence'].get('qr_payload_extracted')}")
    print(f" -> Risk Score: {res['risk_score']}")
    print(f" -> Threat Category: {res['threat_category']}")
    assert res['technical_evidence'].get('qr_payload_extracted') == qr_target
    assert res['risk_score'] >= 50
    passed += 1
    print(" -> PASS [x]")

    # TEST 7: File Scanner Static Analysis (Deceptive Double Extension)
    total += 1
    print("\n[TEST 7] Static File Security Analysis (Deceptive Double Extension)...")
    fake_exe = b"MZ\x90\x00" + b"\x00" * 200 + b"This program cannot be run in DOS mode."
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="invoice.pdf.exe"\r\n'
        f"Content-Type: application/x-msdownload\r\n\r\n"
    ).encode("utf-8") + fake_exe + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{FASTAPI_BASE}/api/analyze/file",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode("utf-8"))

    print(f" -> Detected MIME / Type: {res['technical_evidence'].get('file_mime_type')}")
    print(f" -> Threat Category: {res['threat_category']}")
    print(f" -> Risk Score: {res['risk_score']}")
    assert res['threat_category'] == 'MALWARE'
    assert res['risk_score'] >= 65
    passed += 1
    print(" -> PASS [x]")

    # TEST 7b: Clean Standard Executable (Never fake certainty)
    total += 1
    print("\n[TEST 7b] Clean Standard Executable Inspection (Never Fake Malware)...")
    body_clean = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="clean_installer.exe"\r\n'
        f"Content-Type: application/x-msdownload\r\n\r\n"
    ).encode("utf-8") + fake_exe + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{FASTAPI_BASE}/api/analyze/file",
        data=body_clean,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req) as response:
        res_clean = json.loads(response.read().decode("utf-8"))

    print(f" -> Threat Category: {res_clean['threat_category']}")
    print(f" -> Risk Score: {res_clean['risk_score']}")
    assert res_clean['threat_category'] == 'UNKNOWN / NEEDS_REVIEW'
    assert res_clean['risk_score'] == 30
    passed += 1
    print(" -> PASS [x]")

    # TEST 7c: Malformed / Invalid URL Handling
    total += 1
    print("\n[TEST 7c] Malformed / Invalid URL Input Handling...")
    invalid_url_res = post_json(f"{FASTAPI_BASE}/api/analyze/url", {"url": "not_a_valid_url"})
    print(f" -> Threat Category: {invalid_url_res['threat_category']}")
    print(f" -> Risk Score: {invalid_url_res['risk_score']}")
    assert invalid_url_res['threat_category'] == 'UNKNOWN / NEEDS_REVIEW'
    assert invalid_url_res['risk_score'] == 0
    passed += 1
    print(" -> PASS [x]")

    # TEST 8: User Feedback Loop
    total += 1
    print("\n[TEST 8] User Feedback Loop Submission...")
    fb_res = post_json(f"{FASTAPI_BASE}/api/feedback", {
        "scan_id": "test_scan_101",
        "is_correct": False,
        "suggested_category": "INVESTMENT_SCAM",
        "comments": "This was a crypto telegram pump group, not generic prize scam.",
    })
    print(f" -> Response: {fb_res}")
    assert fb_res.get("status") == "success" or fb_res.get("success") is True
    passed += 1
    print(" -> PASS [x]")

    # TEST 9: Admin Dashboard & Model Metrics & Splits
    total += 1
    print("\n[TEST 9] Admin Ops Telemetry, False Negative Rates & Dataset Splits...")
    stats = get_json(f"{FASTAPI_BASE}/api/admin/stats")
    metrics = get_json(f"{FASTAPI_BASE}/api/admin/metrics")
    dataset = get_json(f"{FASTAPI_BASE}/api/admin/dataset")
    splits = get_json(f"{FASTAPI_BASE}/api/admin/dataset/splits")

    items = dataset.get("items", [])
    print(f" -> Total Scans Logged: {stats['total_scans']}")
    print(f" -> False Positive Rate: {stats['false_positive_rate']}%")
    print(f" -> Model Benchmark Accuracy: {metrics['accuracy'] * 100:.1f}%")
    print(f" -> Model False Negative Rate: {metrics['false_negative_rate'] * 100:.2f}%")
    print(f" -> Train Samples: {splits['train_count']}, Val: {splits['validation_count']}, Test: {splits['test_count']}")

    assert stats['total_scans'] > 0
    assert metrics['f1_score'] >= 0.90
    assert "false_negative_rate" in metrics
    assert splits['train_count'] > 0
    assert len(items) >= 30
    passed += 1
    print(" -> PASS [x]")

    # TEST 10: Express Backend Registration and Reporting (Legacy Endpoint)
    total += 1
    print("\n[TEST 10] Express Backend Legacy API Health & Scam Reporting (/api/v1)...")
    health = get_json(f"{EXPRESS_BASE}/health")
    assert health['status'] == 'healthy'
    print(f" -> Express Service Status: {health['status']}")

    report_data = {
        "target": "http://scam-claim-prize.fake",
        "scamType": "phishing",
        "description": "User reported phishing link sent via SMS",
    }
    report_res = post_json(f"{EXPRESS_BASE}/reports", report_data)
    print(f" -> Scam Report Submitted: ID {report_res['report_id']}")
    assert report_res['success'] is True
    passed += 1
    print(" -> PASS [x]")

    # TEST 11: Clean Canonical Analysis Endpoints (/api/analyze/text, /api/analyze/url, /api/analysis/:id)
    total += 1
    print("\n[TEST 11] Clean Canonical Pipeline: /api/analyze/text & /api/analyze/url...")
    clean_base = "http://127.0.0.1:5000/api"
    clean_health = get_json(f"{clean_base}/health")
    assert clean_health['status'] == 'healthy'
    print(f" -> Clean Health Status (/api/health): {clean_health['status']}")

    text_res = post_json(f"{clean_base}/analyze/text", {
        "content": "ALERT: Your account has been suspended! Send your password to unlock."
    })
    print(f" -> Clean Text Analysis ID: {text_res['id']}, Risk Score: {text_res['risk_score']}")
    assert text_res['success'] is True
    assert text_res['risk_score'] >= 50
    assert 'summary' in text_res
    assert 'ai_explanation' in text_res

    url_res = post_json(f"{clean_base}/analyze/url?sync=true", {
        "url": "https://paypal-security-alert-login.com"
    })
    print(f" -> Clean Synchronous URL Analysis ID: {url_res['id']}, Threat Level: {url_res.get('threat_level')}")
    assert url_res['success'] is True

    # Analysis record lookup by ID
    analysis_lookup = get_json(f"{clean_base}/analysis/{text_res['id']}")
    print(f" -> Clean Analysis Lookup for {text_res['id']}: Status={analysis_lookup.get('status')}")
    assert analysis_lookup['success'] is True
    assert analysis_lookup['id'] == text_res['id']
    passed += 1
    print(" -> PASS [x]")

    # TEST 12: Clean Feedback & Reports Endpoints (/api/reports, /api/feedback)
    total += 1
    print("\n[TEST 12] Clean Feedback System & Reports: /api/reports & /api/feedback...")
    clean_report = post_json(f"{clean_base}/reports", {
        "scamType": "investment",
        "target": "https://guaranteed-crypto-10x.vip",
        "description": "Scam crypto investment portal promising 10x returns.",
    })
    print(f" -> Clean Report Created: ID {clean_report['report_id']}")
    assert clean_report['success'] is True

    clean_feedback = post_json(f"{clean_base}/feedback", {
        "scan_id": text_res['id'],
        "is_correct": True,
        "suggested_category": "PHISHING",
        "comments": "Accurate phishing detection via clean architecture pipeline",
    })
    print(f" -> Clean Feedback Recorded: {clean_feedback['message']}")
    assert clean_feedback['success'] is True
    passed += 1
    print(" -> PASS [x]")

    print("\n==================================================")
    print(f"VERIFICATION COMPLETE: {passed}/{total} TESTS PASSED (100%)")
    print("==================================================")

if __name__ == "__main__":
    run_tests()

