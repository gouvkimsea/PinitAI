import urllib.request
import json

def run_url_tests():
    endpoint = "http://127.0.0.1:5000/api/analyze/url?sync=true"

    test_cases = [
        {
            "name": "Typosquatting & Phishing Path (paypa1.com)",
            "url": "http://paypa1.com/signin",
            "expect_impersonation": True,
            "min_score": 60,
            "max_score": 100,
        },
        {
            "name": "Combisquatting & Phishing Path (paypal-security-verification.com)",
            "url": "https://paypal-security-verification.com/login",
            "expect_impersonation": True,
            "min_score": 60,
            "max_score": 100,
        },
        {
            "name": "Direct IP Address URL",
            "url": "http://45.33.32.156/portal/login",
            "expect_ip": True,
            "min_score": 40,
        },
        {
            "name": "URL Shortener Service (bit.ly)",
            "url": "https://bit.ly/example-clean-link",
            "expect_shortener": True,
            "max_score": 40, # Anti-unilateral: single shortener without other indicators should not exceed mild/suspicious
        },
        {
            "name": "Anti-Unilateral Test: Plain HTTP on Legitimate Personal Blog",
            "url": "http://johndoe-travelblog.com",
            "max_score": 40, # Single minor signal must not trigger high or critical
            "expect_not_threat": ["MALICIOUS", "HIGH_RISK"],
        },
        {
            "name": "SSRF Protection: Block Cloud Metadata Service (169.254.169.254)",
            "url": "http://169.254.169.254/latest/meta-data/",
            "expect_threat_level": "MALICIOUS",
            "min_score": 85,
        },
        {
            "name": "Legitimate Official Domain (paypal.com)",
            "url": "https://paypal.com/signin",
            "max_score": 25,
            "expect_threat_level": "SAFE",
        }
    ]

    print("==================================================")
    print("   URL INTELLIGENCE LIVE API TEST SUITE           ")
    print("==================================================")

    for tc in test_cases:
        print(f"\n[*] Testing: {tc['name']}")
        print(f"    Target: {tc['url']}")
        req = urllib.request.Request(
            endpoint,
            data=json.dumps({"url": tc["url"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            assert res.status == 200, f"Expected 200, got {res.status}"
            data = json.loads(res.read().decode("utf-8"))

        risk_score = data.get("risk_score", 0)
        threat_level = data.get("threat_level", "")
        classification = data.get("classification", "")
        print(f"    - Risk Score: {risk_score}")
        print(f"    - Threat Level: {threat_level}")
        print(f"    - Classification: {classification}")
        print(f"    - Recommended Action: {data.get('recommended_action', '')[:80]}...")

        # Assertions
        if "min_score" in tc:
            assert risk_score >= tc["min_score"], f"Score {risk_score} is lower than expected min {tc['min_score']}"
        if "max_score" in tc:
            assert risk_score <= tc["max_score"], f"Score {risk_score} exceeds expected max {tc['max_score']}"
        if "expect_threat_level" in tc:
            assert threat_level == tc["expect_threat_level"], f"Expected threat level {tc['expect_threat_level']}, got {threat_level}"
        if "expect_not_threat" in tc:
            assert threat_level not in tc["expect_not_threat"], f"Threat level {threat_level} should not be in {tc['expect_not_threat']}"

        print("    -> PASS")

    print("\n==================================================")
    print("ALL LIVE URL INTELLIGENCE TESTS PASSED! (7/7)")
    print("==================================================")

if __name__ == "__main__":
    run_url_tests()
