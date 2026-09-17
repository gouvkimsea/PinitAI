const ENDPOINTS = [
  { url: "http://127.0.0.1:8000", isFastApi: true },
  { url: "http://localhost:4000/api/v1", isFastApi: false }
];

let activeMode = "url";

// Auto-fill active tab URL if available
chrome.tabs?.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http")) {
    const input = document.getElementById("url-input");
    if (input) input.value = tabs[0].url;
  }
});

document.getElementById("tab-url").addEventListener("click", () => {
  activeMode = "url";
  document.getElementById("tab-url").classList.add("active");
  document.getElementById("tab-msg").classList.remove("active");
  document.getElementById("url-container").style.display = "block";
  document.getElementById("msg-container").style.display = "none";
});

document.getElementById("tab-msg").addEventListener("click", () => {
  activeMode = "msg";
  document.getElementById("tab-msg").classList.add("active");
  document.getElementById("tab-url").classList.remove("active");
  document.getElementById("url-container").style.display = "none";
  document.getElementById("msg-container").style.display = "block";
});

// Client-side offline fallback heuristic analyzer
function offlineAnalyze(mode, text) {
  const lower = text.toLowerCase();
  if (mode === "url") {
    let score = 5;
    let category = "SAFE";
    let reasons = [];

    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(text)) {
      score = 90;
      category = "MALWARE";
      reasons.push("Direct IP address destination without domain name.");
    }
    if (/\.(top|xyz|tk|cfd|buzz|click|loan)\b/i.test(text)) {
      score = Math.max(score, 75);
      category = "PHISHING";
      reasons.push("High-risk scam TLD detected.");
    }
    if (/paypal|telegram|bank|aba|login|verify|account|wallet/i.test(text) && !/paypal\.com|telegram\.org|aba\.com\.kh/i.test(text)) {
      score = Math.max(score, 85);
      category = "IMPERSONATION";
      reasons.push("Suspicious credential or brand impersonation keywords in URL path.");
    }

    return {
      risk_score: score,
      threat_category: category,
      summary: reasons.length > 0 ? reasons.join(" ") : "No overt scam or malicious indicators found in URL structure.",
      recommended_actions: [score >= 60 ? "Do not enter passwords or credentials on this page." : "Standard browsing safety applies."]
    };
  } else {
    let score = 5;
    let category = "SAFE";
    let reasons = [];

    if (/urgent|congratulations|prize|winner|ឈ្នះ|រង្វាន់|បន្ទាន់|ផ្អាក|otp/i.test(text)) {
      score = 80;
      category = "PRIZE_SCAM";
      reasons.push("Urgent prize, reward, or account suspension coercion signals.");
    }
    if (/telegram.*(\$|income|dollar|like|work|ការងារ)/i.test(text) || /job.*(\$50|\$100|\$200|\$500)/i.test(text)) {
      score = 90;
      category = "JOB_SCAM";
      reasons.push("Telegram task or high-return daily remote job scam pattern.");
    }

    return {
      risk_score: score,
      threat_category: category,
      summary: reasons.length > 0 ? reasons.join(" ") : "Message contains normal conversational language without identified fraud triggers.",
      recommended_actions: [score >= 60 ? "Do not send money or share 2FA / OTP codes." : "Safe to read."]
    };
  }
}

document.getElementById("btn-scan").addEventListener("click", async () => {
  const resultBox = document.getElementById("result-box");
  const spinner = document.getElementById("loading-spinner");
  resultBox.style.display = "none";
  spinner.style.display = "block";

  const isUrl = activeMode === "url";
  const target = isUrl
    ? document.getElementById("url-input").value.trim()
    : document.getElementById("msg-input").value.trim();

  if (!target) {
    alert(isUrl ? "Please enter or paste a URL." : "Please paste message text.");
    spinner.style.display = "none";
    return;
  }

  let data = null;

  // Multi-tier attempt: FastAPI (:8000) -> Express (:4000) -> Offline Heuristics
  for (const ep of ENDPOINTS) {
    try {
      const endpoint = ep.isFastApi
        ? (isUrl ? "/api/analyze/url" : "/api/analyze/message")
        : (isUrl ? "/analyze/url" : "/analyze/text");

      const payload = isUrl ? { url: target } : { content: target };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const res = await fetch(`${ep.url}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const raw = await res.json();
        data = {
          risk_score: raw.risk_score ?? raw.score ?? 0,
          threat_category: (raw.threat_category || raw.threat_level || raw.category || "SAFE").replace("_", " "),
          summary: raw.summary || raw.ai_explanation || raw.why_suspicious || "Analysis completed successfully.",
          recommended_actions: raw.recommended_actions || raw.recommendations || []
        };
        break;
      }
    } catch {
      // Try next endpoint
    }
  }

  // Fallback to local heuristic analyzer if servers unreachable
  if (!data) {
    data = offlineAnalyze(activeMode, target);
    data.summary += " (Evaluated via Pinit offline heuristic guard)";
  }

  spinner.style.display = "none";
  resultBox.style.display = "block";
  resultBox.className = "result " + (data.risk_score >= 60 ? "high" : data.risk_score >= 20 ? "medium" : "safe");

  document.getElementById("res-category").textContent = data.threat_category;
  document.getElementById("res-score").textContent = `${data.risk_score}/100`;
  document.getElementById("res-summary").textContent = data.summary;
  document.getElementById("res-recommendation").textContent = data.recommended_actions[0] || "";
});
