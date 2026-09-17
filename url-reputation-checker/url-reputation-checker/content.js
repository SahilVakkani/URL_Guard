// content.js — injects a warning banner for malicious/suspicious sites.
// All dynamic text (including anything sourced from third-party APIs) is
// escaped before insertion to avoid any possibility of markup injection.

const BANNER_ID = "url-reputation-guard-banner";

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function removeBanner() {
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showBanner(result) {
  removeBanner();
  if (!result) return;
  if (result.overall !== "malicious" && result.overall !== "suspicious") return;

  const isMalicious = result.overall === "malicious";
  const flagSummary = result.flags
    .map((f) => escapeHtml(f.source))
    .join(", ");

  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.className = isMalicious ? "urg-banner urg-danger" : "urg-banner urg-warning";

  const label = isMalicious
    ? `⚠ Flagged MALICIOUS by: ${flagSummary}`
    : `⚠ Flagged SUSPICIOUS by: ${flagSummary}`;

  // safe: every dynamic piece above is escaped; only our own static markup is raw
  banner.innerHTML = `
    <span class="urg-banner-text">${label}</span>
    <button class="urg-banner-details" type="button">Details</button>
    <button class="urg-banner-close" type="button" title="Dismiss">✕</button>
  `;

  document.documentElement.appendChild(banner);
  banner.querySelector(".urg-banner-close").addEventListener("click", removeBanner);
  banner.querySelector(".urg-banner-details").addEventListener("click", () => {
    alert(
      "Open the URL Reputation Guard toolbar icon for the full per-source breakdown and report links."
    );
  });
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "VT_RESULT") {
    showBanner(message.result);
  }
});

// ask background for a result immediately in case it already finished
// before this content script finished loading
chrome.runtime.sendMessage({ type: "GET_RESULT_FOR_ACTIVE_TAB" }, (response) => {
  if (chrome.runtime.lastError) return; // extension context may be reloading — ignore
  if (response?.result) showBanner(response.result);
});
