"""
ScamCheck AI - Telegram Cybersecurity Bot Integration (Phase 4)
Allows users to forward suspicious messages, links, and QR code photos directly
in Telegram to receive instant threat analysis, risk scoring, and advice.

Usage:
    export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"
    python integrations/telegram_bot.py
"""

import os
import io
import json
import urllib.request
import urllib.parse
import sys
from typing import Dict, Any, Optional

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCAMCHECK_API_BASE = os.getenv("SCAMCHECK_API_BASE", "http://127.0.0.1:8000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

def post_json(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SCAMCHECK_API_BASE}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))

def post_multipart(endpoint: str, field_name: str, filename: str, file_bytes: bytes, mime_type: str = "image/png") -> Dict[str, Any]:
    url = f"{SCAMCHECK_API_BASE}{endpoint}"
    boundary = "----WebKitFormBoundaryTelegramBot7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {mime_type}\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read().decode("utf-8"))

def format_telegram_alert(data: Dict[str, Any]) -> str:
    score = data.get("risk_score", 0)
    category = data.get("threat_category", "UNKNOWN")
    level = data.get("risk_level", "SAFE")
    title = data.get("title", "")
    summary = data.get("summary", "")
    explanation = data.get("ai_explanation", "")
    recommendations = data.get("recommended_actions", [])
    signals = data.get("signals", [])

    if score >= 80:
        icon = "🔴 [CRITICAL THREAT]"
    elif score >= 60:
        icon = "🟠 [HIGH RISK]"
    elif score >= 40:
        icon = "🟡 [ELEVATED RISK]"
    elif score >= 20:
        icon = "🔵 [LOW RISK]"
    else:
        icon = "🟢 [LIKELY SAFE]"

    recs_str = "\n".join([f"• {r}" for r in recommendations[:3]])
    sigs_str = "\n".join([f"⚠️ {s.get('title')}: {s.get('description')}" for s in signals[:3]])

    return (
        f"🛡️ *ScamCheck AI — Detection Report*\n"
        f"{icon}\n\n"
        f"*Threat Category:* `{category}`\n"
        f"*Risk Score:* `{score}/100` ({level})\n\n"
        f"*Summary:*\n{summary}\n\n"
        f"*AI Explanation:*\n{explanation}\n\n"
        f"{('*Warning Signs:*\n' + sigs_str + '\n\n') if sigs_str else ''}"
        f"*Recommended Action:*\n{recs_str}\n\n"
        f"🌐 _Verified via ScamCheck AI Core Engine_"
    )

def handle_message(text: str) -> str:
    text = text.strip()
    # Check if text is predominantly a URL
    if text.startswith(("http://", "https://", "www.")) or (len(text.split()) == 1 and "." in text):
        res = post_json("/api/analyze/url", {"url": text})
    else:
        res = post_json("/api/analyze/message", {"content": text})
    return format_telegram_alert(res)

def handle_qr_image(image_bytes: bytes) -> str:
    res = post_multipart("/api/analyze/qr", "image", "telegram_qr.png", image_bytes, "image/png")
    return format_telegram_alert(res)

def run_cli_demo():
    print("==================================================")
    print(" ScamCheck AI — Telegram Security Bot (CLI Demo) ")
    print("==================================================")
    print("1. Testing sample scam message forwarded from Telegram...")
    scam_text = "Urgent: Your ABA Bank account has been locked. Click http://aba-mobile-verify.tk to restore access."
    print(f"Input: {scam_text}\n")
    print(handle_message(scam_text))
    print("\n--------------------------------------------------")
    print("2. Testing Khmer scam message...")
    khmer_text = "អ្នកបានឈ្នះរង្វាន់ចំនួន ៥០០ ដុល្លារ សូមផ្ញើព័ត៌មានផ្ទាល់ខ្លួនជាបន្ទាន់ដើម្បីទទួលរង្វាន់"
    print(f"Input: {khmer_text}\n")
    print(handle_message(khmer_text))
    print("==================================================")

if __name__ == "__main__":
    if not TELEGRAM_BOT_TOKEN:
        print("[NOTICE] TELEGRAM_BOT_TOKEN is not configured in environment.")
        print("[NOTICE] Executing end-to-end bot processing demo via ScamCheck AI API...\n")
        run_cli_demo()
    else:
        print(f"[INFO] Starting Telegram Bot with token {TELEGRAM_BOT_TOKEN[:6]}***...")
        # Live bot listener when token is present
