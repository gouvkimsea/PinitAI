import urllib.request
import json

def run_test():
    url = "http://127.0.0.1:5000/api/analyze/text"
    
    test_cases = [
        {
            "name": "1. Urgency",
            "text": "ACT NOW! Limited time only, this exclusive deal expires today.",
            "expect_patterns": ["Urgency"],
            "expect_phrases": True,
        },
        {
            "name": "2. Threats (Intimidation / Arrest)",
            "text": "This is the police department. A warrant for your arrest has been issued. Pay legal penalties or face jail time.",
            "expect_patterns": ["Threats"],
            "expect_phrases": True,
            "min_severity": "critical"
        },
        {
            "name": "3. Requests for money",
            "text": "Please send money or wire transfer 500 dollars to cover processing costs.",
            "expect_patterns": ["Requests for money"],
            "expect_phrases": True,
        },
        {
            "name": "4. Requests for passwords or OTPs",
            "text": "Security verification: Enter OTP and bank credentials to authorize login.",
            "expect_patterns": ["Requests for passwords or OTPs"],
            "expect_phrases": True,
            "min_severity": "critical"
        },
        {
            "name": "5. Fake prizes",
            "text": "Congratulations! You won $10,000 lottery prize in our annual sweepstakes draw.",
            "expect_patterns": ["Fake prizes"],
            "expect_phrases": True,
            "expected_category": "PRIZE_SCAM"
        },
        {
            "name": "6. Fake jobs",
            "text": "Part-time job offer: earn $300 per day working from home by liking youtube videos.",
            "expect_patterns": ["Fake jobs"],
            "expect_phrases": True,
            "expected_category": "JOB_SCAM"
        },
        {
            "name": "7. Investment scams",
            "text": "Guaranteed daily returns! Invest in our crypto investment pool to double your crypto.",
            "expect_patterns": ["Investment scams"],
            "expect_phrases": True,
            "expected_category": "INVESTMENT_SCAM"
        },
        {
            "name": "8. Romance scams",
            "text": "Sorry wrong number! But you seem kind. Let's chat on WhatsApp or Telegram.",
            "expect_patterns": ["Romance scams"],
            "expect_phrases": True,
            "expected_category": "ROMANCE_SCAM"
        },
        {
            "name": "9. Account takeover attempts",
            "text": "Alert: Your account has been suspended due to unauthorized login detected.",
            "expect_patterns": ["Account takeover attempts"],
            "expect_phrases": True,
            "expected_category": "ACCOUNT_TAKEOVER"
        },
        {
            "name": "10. Impersonation",
            "text": "Notice from ABA Bank customer service: urgent system upgrade notice.",
            "expect_patterns": ["Impersonation"],
            "expect_phrases": True,
            "expected_category": "IMPERSONATION"
        },
        {
            "name": "11. Suspicious payment instructions",
            "text": "Payment instructions: Buy Apple gift cards or send USDT to wallet address 0x71C.",
            "expect_patterns": ["Suspicious payment instructions"],
            "expect_phrases": True,
            "expected_category": "PAYMENT_SCAM"
        },
        {
            "name": "12. Requests to click suspicious links",
            "text": "Click here or open the link below to view your security statement.",
            "expect_patterns": ["Requests to click suspicious links"],
            "expect_phrases": True,
        },
        {
            "name": "13. Khmer Language Scam (Fake Prize + Links + Money)",
            "text": "សូមអបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ 5,000$ ពីធនាគារ ABA។ ចុចទីនេះ ដើម្បីផ្ទេរប្រាក់ ជាបន្ទាន់",
            "expect_patterns": ["Fake prizes", "Impersonation", "Requests to click suspicious links", "Requests for money", "Urgency"],
            "expect_phrases": True,
            "expected_category": "PRIZE_SCAM"
        },
        {
            "name": "14. Borderline / Ambiguous Message (Needs Review)",
            "text": "Hello team, please reply within 24 hours regarding our meeting agenda.",
            "expect_needs_review": True
        },
        {
            "name": "15. Clean Normal Message",
            "text": "Good morning! Can you review the draft proposal when you have a moment?",
            "expect_safe": True
        }
    ]

    print("==================================================")
    print("   TEXT SCAM DETECTION LIVE API TEST SUITE        ")
    print("==================================================")

    for tc in test_cases:
        print(f"\n[*] Testing: {tc['name']}")
        req = urllib.request.Request(
            url,
            data=json.dumps({"text": tc["text"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            assert res.status == 200, f"Expected 200, got {res.status}"
            data = json.loads(res.read().decode("utf-8"))

        # Verify all required top-level fields are present
        required_fields = [
            "detected_patterns",
            "suspicious_phrases",
            "scam_category",
            "severity",
            "confidence",
            "evidence",
            "recommended_action"
        ]
        for f in required_fields:
            assert f in data, f"Missing required field '{f}' in response: {list(data.keys())}"

        print(f"    - scam_category: {data['scam_category']}")
        print(f"    - severity: {data['severity']}")
        print(f"    - confidence: {data['confidence']}")
        print(f"    - detected_patterns: {data['detected_patterns']}")
        safe_phrases = [p.encode('ascii', 'backslashreplace').decode('ascii') for p in data['suspicious_phrases']]
        print(f"    - suspicious_phrases: {safe_phrases}")
        safe_action = data['recommended_action'][:80].encode('ascii', 'backslashreplace').decode('ascii')
        print(f"    - recommended_action: {safe_action}...")

        # Specific assertions
        if tc.get("expect_needs_review"):
            assert data["severity"] == "needs_review", f"Expected severity 'needs_review', got {data['severity']}"
            assert data["scam_category"] == "needs_review", f"Expected scam_category 'needs_review', got {data['scam_category']}"
            print("    -> PASS [Needs Review successfully flagged]")
        elif tc.get("expect_safe"):
            assert data["severity"] == "safe", f"Expected severity 'safe', got {data['severity']}"
            assert data["scam_category"] == "SAFE", f"Expected scam_category 'SAFE', got {data['scam_category']}"
            assert len(data["detected_patterns"]) == 0
            assert len(data["suspicious_phrases"]) == 0
            print("    -> PASS [Clean Message successfully passed]")
        else:
            if tc.get("expected_category"):
                assert data["scam_category"] == tc["expected_category"], f"Expected {tc['expected_category']}, got {data['scam_category']}"
            if tc.get("expect_patterns"):
                for pat in tc["expect_patterns"]:
                    assert pat in data["detected_patterns"], f"Expected pattern '{pat}' in {data['detected_patterns']}"
            if tc.get("expect_phrases"):
                assert len(data["suspicious_phrases"]) > 0, "Expected non-empty suspicious_phrases"
            print("    -> PASS [Pattern and phrase extraction verified]")

    print("\n==================================================")
    print("ALL LIVE TESTS PASSED SUCCESSFULLY! (15/15)")
    print("==================================================")

if __name__ == "__main__":
    run_test()
