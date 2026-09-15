import urllib.request
import json

def test_pipeline():
    url = "http://127.0.0.1:5000/api/analyze/text"
    payload = {
        "text": "URGENT: Your ABA Bank account is locked! Send 500 USDT to wallet 0x71C... to double your money immediately or lose access."
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as res:
        assert res.status == 200, f"Expected 200, got {res.status}"
        data = json.loads(res.read().decode("utf-8"))
    
    print("=== LIVE PIPELINE ENDPOINT TEST ===")
    print(f"Status Code: {res.status}")
    print(f"Target Scan ID: {data.get('id')}")
    print(f"Classification: {data.get('classification')}")
    print(f"Risk Score: {data.get('risk_score')}")
    print(f"Confidence: {data.get('confidence')}")
    print(f"Triggered Detectors: {data.get('triggered_detectors')}")
    print(f"Recommended Action: {data.get('recommended_action')}")
    print(f"Threat Level: {data.get('threat_level')}")
    print(f"Threat Category: {data.get('threat_category')}")
    print(f"Title: {data.get('title')}")
    print(f"Summary: {data.get('summary')}")
    print(f"Safe Factors Count: {len(data.get('safe_factors', []))}")
    print(f"Recommended Actions Count: {len(data.get('recommended_actions', []))}")
    print(f"Detectors Evaluated ({len(data.get('detectors_evaluated', []))}):")
    for d_name in data.get('detectors_evaluated', []):
        print(f"  * {d_name}")
    
    print("\nDetailed Detector Results:")
    for det in data.get("detector_results", []):
        print(f"  - [{det['detector_name']}]")
        print(f"      Type: {det['detector_type']}")
        print(f"      Score: {det['score']}")
        print(f"      Severity: {det['severity']}")
        print(f"      Confidence: {det['confidence']}")
        print(f"      Summary: {det['evidence']['summary']}")
        print(f"      Indicators: {det['evidence']['indicators']}")
    
    print("\nEvidence Breakdown:")
    for k, v in data.get("evidence_breakdown", {}).items():
        print(f"  - {k}: {v}")
        
    print("\nSUCCESS: Text analysis pipeline verified!")

    # Test URL analysis (synchronous execution mode)
    url_endpoint = "http://127.0.0.1:5000/api/analyze/url?sync=true"
    url_payload = {
        "url": "http://paypal-security-verification.com.update-account.biz/login#tracking"
    }
    url_req = urllib.request.Request(
        url_endpoint,
        data=json.dumps(url_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(url_req) as res_url:
        assert res_url.status == 200, f"Expected 200, got {res_url.status}"
        data_url = json.loads(res_url.read().decode("utf-8"))
        
    print("\n=== LIVE URL PIPELINE ENDPOINT TEST ===")
    print(f"Status Code: {res_url.status}")
    print(f"Threat Level: {data_url.get('threat_level')}")
    print(f"Risk Score: {data_url.get('risk_score')}")
    print(f"Confidence Score: {data_url.get('confidence_score')}")
    print(f"Detectors Evaluated: {data_url.get('detectors_evaluated')}")
    for det in data_url.get("detector_results", []):
        print(f"  - [{det['detector_name']}] score={det['score']}, severity={det['severity']}")

    print("\nSUCCESS: All pipeline tests completed successfully!")

if __name__ == "__main__":
    test_pipeline()
