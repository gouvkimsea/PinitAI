const API_BASE = "http://127.0.0.1:8000";

let activeMode = "url";

// Auto-fill active tab URL if available
chrome.tabs?.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http")) {
    document.getElementById("url-input").value = tabs[0].url;
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

document.getElementById("btn-scan").addEventListener("click", async () => {
  const resultBox = document.getElementById("result-box");
  const spinner = document.getElementById("loading-spinner");
  resultBox.style.display = "none";
  spinner.style.display = "block";

  try {
    let endpoint = "/api/analyze/url";
    let payload = {};

    if (activeMode === "url") {
      const url = document.getElementById("url-input").value.trim();
      if (!url) {
        alert("Please enter or paste a URL.");
        spinner.style.display = "none";
        return;
      }
      payload = { url };
    } else {
      const content = document.getElementById("msg-input").value.trim();
      if (!content) {
        alert("Please paste message text.");
        spinner.style.display = "none";
        return;
      }
      endpoint = "/api/analyze/message";
      payload = { content };
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Analysis failed");
    const data = await res.json();

    spinner.style.display = "none";
    resultBox.style.display = "block";
    resultBox.className = "result " + (data.risk_score >= 60 ? "high" : data.risk_score >= 20 ? "medium" : "safe");

    document.getElementById("res-category").textContent = data.threat_category.replace("_", " ");
    document.getElementById("res-score").textContent = `${data.risk_score}/100`;
    document.getElementById("res-summary").textContent = data.summary;
    document.getElementById("res-recommendation").textContent = (data.recommended_actions && data.recommended_actions[0]) || "";
  } catch (err) {
    console.error("Scan error:", err);
    spinner.style.display = "none";
    alert("Could not reach ScamCheck AI engine (http://127.0.0.1:8000). Ensure the backend is running.");
  }
});
