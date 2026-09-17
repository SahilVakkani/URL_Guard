const statusArea = document.getElementById("statusArea");
const urlText = document.getElementById("urlText");

document.getElementById("optionsLink").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const OVERALL_LABELS = {
  clean: "✅ Clean",
  suspicious: "⚠️ Suspicious",
  malicious: "🛑 Malicious",
  unknown: "❔ Unknown / not enough data",
  not_configured: "🔑 No sources configured",
};

function sourceChip(cssClass, label) {
  return `<span class="chip ${cssClass}">${escapeHtml(label)}</span>`;
}

function renderVTRow(vt) {
  if (!vt.configured) {
    return { chip: sourceChip("not_configured", "Not set up"), detail: "Add a VirusTotal API key in Settings" };
  }
  if (vt.error) return { chip: sourceChip("error", "Error"), detail: escapeHtml(vt.error) };
  if (vt.notFound) return { chip: sourceChip("unknown", "Unscanned"), detail: "Not yet scanned by VirusTotal" };
  const { malicious, suspicious, harmless, undetected } = vt.stats;
  const total = malicious + suspicious + harmless + undetected;
  const dateStr = vt.lastAnalysisDate ? new Date(vt.lastAnalysisDate).toLocaleDateString() : "unknown date";
  return {
    chip: sourceChip(vt.verdict, vt.verdict),
    detail: `${malicious}/${total} vendors flagged · scanned ${escapeHtml(dateStr)}`,
    link: vt.permalink,
  };
}

function renderGSBRow(gsb) {
  if (!gsb.configured) {
    return { chip: sourceChip("not_configured", "Not set up"), detail: "Add a Safe Browsing API key in Settings" };
  }
  if (gsb.error) return { chip: sourceChip("error", "Error"), detail: escapeHtml(gsb.error) };
  if (gsb.verdict === "malicious") {
    return { chip: sourceChip("malicious", "malicious"), detail: escapeHtml(gsb.threats.join(", ")) };
  }
  return { chip: sourceChip("clean", "clean"), detail: "No known threats listed" };
}

function renderURLhausRow(urlhaus) {
  if (!urlhaus.configured) {
    return { chip: sourceChip("not_configured", "Optional"), detail: escapeHtml(urlhaus.note || "Add an Auth-Key in Settings for full access") };
  }
  if (urlhaus.error) return { chip: sourceChip("error", "Error"), detail: escapeHtml(urlhaus.error) };
  if (urlhaus.notFound) return { chip: sourceChip("unknown", "No data"), detail: "Not listed in URLhaus" };
  const detail = urlhaus.threat
    ? `${escapeHtml(urlhaus.threat)} (${escapeHtml(urlhaus.status)})`
    : escapeHtml(urlhaus.status || "");
  return { chip: sourceChip(urlhaus.verdict, urlhaus.verdict), detail, link: urlhaus.permalink };
}

function renderOTXRow(otx) {
  if (!otx.configured) {
    return { chip: sourceChip("not_configured", "Not set up"), detail: "Add an OTX API key in Settings" };
  }
  if (otx.error) return { chip: sourceChip("error", "Error"), detail: escapeHtml(otx.error) };
  const count = otx.pulseCount || 0;
  return {
    chip: sourceChip(otx.verdict, otx.verdict),
    detail: count > 0 ? `${count} threat intel pulse${count === 1 ? "" : "s"}` : "No threat pulses found",
    link: otx.permalink,
  };
}

function sourceRowHtml(name, row) {
  const linkHtml = row.link
    ? ` · <a href="${escapeHtml(row.link)}" target="_blank" rel="noopener noreferrer">report</a>`
    : "";
  return `
    <div class="source-row">
      <span class="source-name">${escapeHtml(name)}</span>
      ${row.chip}
    </div>
    <div class="stats-inline" style="margin: -4px 0 8px 2px;">${row.detail}${linkHtml}</div>
  `;
}

function render(result, url) {
  urlText.textContent = url || "";

  if (!url) {
    statusArea.innerHTML = `<div class="empty-state">Open a website to see its reputation.</div>`;
    return;
  }

  if (!result) {
    statusArea.innerHTML = `
      <div class="verdict unknown">⏳ Checking…</div>
      <div class="hint">If this doesn't update, make sure at least one API key is set in Settings.</div>
    `;
    return;
  }

  const overallLabel = OVERALL_LABELS[result.overall] || OVERALL_LABELS.unknown;
  let html = `<div class="verdict ${result.overall}">${overallLabel}</div>`;

  if (result.overall === "not_configured") {
    html += `<button id="goToSettings">Add an API key to get started</button>`;
    statusArea.innerHTML = html;
    document.getElementById("goToSettings").addEventListener("click", () => chrome.runtime.openOptionsPage());
    return;
  }

  if (result.flags && result.flags.length > 0) {
    html += `<ul class="flag-list">`;
    for (const f of result.flags) {
      html += `<li><strong>${escapeHtml(f.source)}</strong> (${escapeHtml(f.level)}): ${escapeHtml(f.detail)}</li>`;
    }
    html += `</ul>`;
  }

  html += `<div class="sources-title">Sources checked</div>`;
  html += sourceRowHtml("VirusTotal", renderVTRow(result.sources.vt));
  html += sourceRowHtml("Google Safe Browsing", renderGSBRow(result.sources.gsb));
  html += sourceRowHtml("URLhaus", renderURLhausRow(result.sources.urlhaus));
  html += sourceRowHtml("AlienVault OTX", renderOTXRow(result.sources.otx));

  statusArea.innerHTML = html;

  // "Scan now" is offered independently of the overall verdict, whenever
  // VirusTotal specifically hasn't analyzed this URL yet
  if (result.sources.vt.configured && result.sources.vt.notFound) {
    const scanBtn = document.createElement("button");
    scanBtn.textContent = "Scan this URL on VirusTotal now";
    scanBtn.className = "btn-secondary";
    scanBtn.addEventListener("click", () => {
      scanBtn.textContent = "Submitting… this can take ~20s";
      scanBtn.disabled = true;
      chrome.runtime.sendMessage({ type: "SCAN_NOW", url }, (resp) => {
        render(resp?.result, url);
      });
    });
    statusArea.appendChild(scanBtn);
  }
}

chrome.runtime.sendMessage({ type: "GET_RESULT_FOR_ACTIVE_TAB" }, (response) => {
  if (chrome.runtime.lastError) return;
  render(response?.result, response?.url);
});
