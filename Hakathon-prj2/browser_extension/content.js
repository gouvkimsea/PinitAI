// ScamCheck AI - Real-time Link Hover Warning Content Script
(() => {
  const SUSPICIOUS_TLDS = [".tk", ".xyz", ".top", ".click", ".buzz", ".cfd", ".ml", ".ga", ".gq", ".loan"];
  const IP_REGEX = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;

  let tooltipEl = null;

  function createTooltip() {
    if (tooltipEl) return tooltipEl;
    tooltipEl = document.createElement("div");
    tooltipEl.id = "scamcheck-link-tooltip";
    tooltipEl.style.position = "fixed";
    tooltipEl.style.zIndex = "2147483647";
    tooltipEl.style.background = "#0f172a";
    tooltipEl.style.color = "#f8fafc";
    tooltipEl.style.border = "1px solid #ef4444";
    tooltipEl.style.borderRadius = "6px";
    tooltipEl.style.padding = "6px 10px";
    tooltipEl.style.fontSize = "11px";
    tooltipEl.style.fontFamily = "system-ui, -apple-system, sans-serif";
    tooltipEl.style.boxShadow = "0 10px 15px -3px rgba(0, 0, 0, 0.4)";
    tooltipEl.style.pointerEvents = "none";
    tooltipEl.style.display = "none";
    document.body.appendChild(tooltipEl);
    return tooltipEl;
  }

  function evaluateLink(url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      if (IP_REGEX.test(url)) {
        return { suspicious: true, reason: "Raw numeric IP address destination" };
      }
      for (const tld of SUSPICIOUS_TLDS) {
        if (host.endsWith(tld)) {
          return { suspicious: true, reason: `High-abuse registrar TLD (${tld})` };
        }
      }
      if (host.includes("paypal") && !host.endsWith("paypal.com")) {
        return { suspicious: true, reason: "Possible brand impersonation (PayPal look-alike)" };
      }
      if (host.includes("telegram") && !host.endsWith("telegram.org") && !host.endsWith("t.me")) {
        return { suspicious: true, reason: "Possible brand impersonation (Telegram look-alike)" };
      }
    } catch {
      // Invalid URL
    }
    return { suspicious: false };
  }

  document.addEventListener("mouseover", (e) => {
    const anchor = e.target.closest("a");
    if (!anchor || !anchor.href) return;

    const evaluation = evaluateLink(anchor.href);
    if (evaluation.suspicious) {
      const tip = createTooltip();
      tip.innerHTML = `⚠️ <strong style="color:#f87171">ScamCheck Warning:</strong> ${evaluation.reason}`;
      tip.style.display = "block";
      tip.style.left = `${Math.min(window.innerWidth - 300, Math.max(10, e.clientX + 10))}px`;
      tip.style.top = `${Math.min(window.innerHeight - 50, e.clientY + 15)}px`;
    }
  });

  document.addEventListener("mouseout", (e) => {
    const anchor = e.target.closest("a");
    if (anchor && tooltipEl) {
      tooltipEl.style.display = "none";
    }
  });
})();
