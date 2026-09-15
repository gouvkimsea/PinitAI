import sys
import os
sys.path.insert(0, os.path.abspath("."))
from ai_engine.dataset.evaluator import RAW_DATASET
from ai_engine.detectors.message_detector import analyze_message
from ai_engine.detectors.url_detector import analyze_url

for item in RAW_DATASET:
    if item["is_malicious"]:
        if item["content_type"] == "url":
            res = analyze_url(item["content"])
        else:
            res = analyze_message(item["content"])
        if res.risk_score < 40:
            print(f"MISSED: {item['id']} score={res.risk_score} signals={len(res.signals)}")
            print(f"Content: {item['content']}")
            print("-" * 50)
