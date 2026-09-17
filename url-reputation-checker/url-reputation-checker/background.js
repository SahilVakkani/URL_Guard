// background.js — URL Reputation Guard
// Aggregates VirusTotal, Google Safe Browsing, URLhaus (abuse.ch), and
// AlienVault OTX into a single verdict per URL. Handles caching, per-source
// error isolation, request de-duplication, timeouts, and periodic cache
// cleanup so the extension stays fast and stays within free-tier API limits.

const VT_BASE = "https://www.virustotal.com/api/v3";
const GSB_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1/url/";
const OTX_BASE = "https://otx.alienvault.com/api/v1/indicators/url";

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour per URL
const CACHE_CLEANUP_ALARM = "cleanupCache";
const CACHE_CLEANUP_PERIOD_MIN = 360; // sweep stale cache entries every 6 hours
const VT_MIN_GAP_MS = 16000; // VirusTotal free tier = 4 req/min
const FETCH_TIMEOUT_MS = 10000; // don't let a slow API hang the whole check

let vtQueue = [];
let vtProcessing = false;
let vtLastRequestAt = 0;

// tracks URLs currently being checked so a near-simultaneous
// tabs.onUpdated + tabs.onActivated pair doesn't fire duplicate API calls
const inFlight = new Map();

// ---------- helpers ----------

function isCheckableUrl(url) {
  if (!url) return false;
  return url.startsWith("http://") || url.startsWith("https://");
}

// Returns a normalized URL string, or null if the input isn't a valid URL.
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    u.hash = ""; // fragments don't change how any of these services see the URL
    return u.toString();
  } catch (e) {
    return null;
  }
}

function urlToId(url) {
  const b64 = btoa(unescape(encodeURIComponent(url)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function getKeys() {
  const store = await chrome.storage.local.get([
    "vtApiKey",
    "gsbApiKey",
    "otxApiKey",
    "urlhausAuthKey",
  ]);
  return {
    vt: store.vtApiKey || null,
    gsb: store.gsbApiKey || null,
    otx: store.otxApiKey || null,
    urlhaus: store.urlhausAuthKey || null, // optional — URLhaus works without one for basic lookups on many deployments
  };
}

async function getCached(url) {
  const key = "cache:" + url;
  const store = await chrome.storage.local.get(key);
  const entry = store[key];
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) return null;
  return entry;
}

async function setCached(url, result) {
  const key = "cache:" + url;
  await chrome.storage.local.set({ [key]: { ...result, ts: Date.now() } });
}

async function cleanupExpiredCache() {
  const all = await chrome.storage.local.get(null);
  const staleKeys = Object.keys(all).filter((k) => {
    if (!k.startsWith("cache:")) return false;
    const entry = all[k];
    return !entry?.ts || Date.now() - entry.ts > CACHE_TTL_MS;
  });
  if (staleKeys.length > 0) await chrome.storage.local.remove(staleKeys);
}

// ---------- VT rate-limited queue (VT is the tightest limit: 4/min) ----------

function enqueueVT(task) {
  return new Promise((resolve) => {
    vtQueue.push({ task, resolve });
    processVTQueue();
  });
}

async function processVTQueue() {
  if (vtProcessing) return;
  vtProcessing = true;
  while (vtQueue.length > 0) {
    const wait = Math.max(0, VT_MIN_GAP_MS - (Date.now() - vtLastRequestAt));
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const { task, resolve } = vtQueue.shift();
    vtLastRequestAt = Date.now();
    try {
      resolve(await task());
    } catch (e) {
      resolve({ configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message });
    }
  }
  vtProcessing = false;
}

// ---------- Source: VirusTotal ----------

async function fetchVT(url, apiKey) {
  if (!apiKey) return { configured: false };
  try {
    const id = urlToId(url);
    const resp = await fetchWithTimeout(`${VT_BASE}/urls/${id}`, {
      headers: { "x-apikey": apiKey },
    });
    if (resp.status === 404) return { configured: true, notFound: true };
    if (resp.status === 401) return { configured: true, error: "Invalid API key" };
    if (resp.status === 429) return { configured: true, error: "Rate limited" };
    if (!resp.ok) return { configured: true, error: `HTTP ${resp.status}` };
    const json = await resp.json();
    const attrs = json?.data?.attributes;
    if (!attrs) return { configured: true, error: "Malformed response" };
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    let verdict = "clean";
    if (malicious > 0) verdict = "malicious";
    else if (suspicious > 0) verdict = "suspicious";
    return {
      configured: true,
      verdict,
      stats: {
        malicious,
        suspicious,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
      },
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      permalink: `https://www.virustotal.com/gui/url/${id}`,
    };
  } catch (e) {
    return { configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message };
  }
}

async function submitVTAndPoll(url, apiKey) {
  try {
    const submitResp = await fetchWithTimeout(`${VT_BASE}/urls`, {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
    });
    if (!submitResp.ok) return { configured: true, error: `Submit failed (HTTP ${submitResp.status})` };
    const submitJson = await submitResp.json();
    const analysisId = submitJson?.data?.id;
    if (!analysisId) return { configured: true, error: "No analysis ID returned" };

    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 4000));
      const pollResp = await fetchWithTimeout(`${VT_BASE}/analyses/${analysisId}`, {
        headers: { "x-apikey": apiKey },
      });
      if (!pollResp.ok) continue;
      const pollJson = await pollResp.json();
      if (pollJson?.data?.attributes?.status === "completed") {
        return await fetchVT(url, apiKey);
      }
    }
    return { configured: true, error: "Scan still pending — check back shortly" };
  } catch (e) {
    return { configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message };
  }
}

// ---------- Source: Google Safe Browsing ----------

async function fetchGSB(url, apiKey) {
  if (!apiKey) return { configured: false };
  try {
    const resp = await fetchWithTimeout(`${GSB_BASE}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "url-reputation-guard", clientVersion: "1.1.0" },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
    if (resp.status === 400) return { configured: true, error: "Invalid API key" };
    if (!resp.ok) return { configured: true, error: `HTTP ${resp.status}` };
    const json = await resp.json();
    const matches = json?.matches || [];
    if (matches.length > 0) {
      return {
        configured: true,
        verdict: "malicious",
        threats: [...new Set(matches.map((m) => m.threatType))],
      };
    }
    return { configured: true, verdict: "clean", threats: [] };
  } catch (e) {
    return { configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message };
  }
}

// ---------- Source: URLhaus (abuse.ch) ----------

async function fetchURLhaus(url, authKey) {
  try {
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (authKey) headers["Auth-Key"] = authKey;
    const resp = await fetchWithTimeout(URLHAUS_BASE, {
      method: "POST",
      headers,
      body: `url=${encodeURIComponent(url)}`,
    });
    if (resp.status === 401 || resp.status === 403) {
      return { configured: false, note: "Auth-Key required or invalid — see abuse.ch" };
    }
    if (!resp.ok) return { configured: true, error: `HTTP ${resp.status}` };
    const json = await resp.json();
    if (json.query_status !== "ok") {
      return { configured: true, verdict: "unknown", notFound: true };
    }
    const verdict = json.url_status === "online" ? "malicious" : "suspicious";
    return {
      configured: true,
      verdict,
      status: json.url_status,
      threat: json.threat,
      tags: Array.isArray(json.tags) ? json.tags : [],
      permalink: json.urlhaus_reference,
    };
  } catch (e) {
    return { configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message };
  }
}

// ---------- Source: AlienVault OTX ----------

async function fetchOTX(url, apiKey) {
  if (!apiKey) return { configured: false };
  try {
    const resp = await fetchWithTimeout(`${OTX_BASE}/${encodeURIComponent(url)}/general`, {
      headers: { "X-OTX-API-KEY": apiKey },
    });
    if (resp.status === 403) return { configured: true, error: "Invalid API key" };
    if (!resp.ok) return { configured: true, error: `HTTP ${resp.status}` };
    const json = await resp.json();
    const count = json?.pulse_info?.count || 0;
    let verdict = "clean";
    if (count >= 3) verdict = "malicious";
    else if (count >= 1) verdict = "suspicious";
    return {
      configured: true,
      verdict,
      pulseCount: count,
      permalink: `https://otx.alienvault.com/indicator/url/${encodeURIComponent(url)}`,
    };
  } catch (e) {
    return { configured: true, error: e.name === "AbortError" ? "Request timed out" : e.message };
  }
}

// ---------- Aggregation ----------

function aggregate(url, vt, gsb, urlhaus, otx) {
  const flags = [];

  if (vt.verdict === "malicious")
    flags.push({ source: "VirusTotal", level: "malicious", detail: `${vt.stats.malicious} vendors flagged this` });
  else if (vt.verdict === "suspicious")
    flags.push({ source: "VirusTotal", level: "suspicious", detail: `${vt.stats.suspicious} vendors flagged this` });

  if (gsb.verdict === "malicious")
    flags.push({ source: "Google Safe Browsing", level: "malicious", detail: gsb.threats.join(", ") || "listed threat" });

  if (urlhaus.verdict === "malicious")
    flags.push({ source: "URLhaus", level: "malicious", detail: urlhaus.threat || "active malware URL" });
  else if (urlhaus.verdict === "suspicious")
    flags.push({ source: "URLhaus", level: "suspicious", detail: "previously listed malware URL (now offline)" });

  if (otx.verdict === "malicious")
    flags.push({ source: "AlienVault OTX", level: "malicious", detail: `${otx.pulseCount} threat intel pulses` });
  else if (otx.verdict === "suspicious")
    flags.push({ source: "AlienVault OTX", level: "suspicious", detail: `${otx.pulseCount} threat intel pulse` });

  let overall = "unknown";
  if (flags.some((f) => f.level === "malicious")) overall = "malicious";
  else if (flags.some((f) => f.level === "suspicious")) overall = "suspicious";
  else if (vt.verdict === "clean" || gsb.verdict === "clean") overall = "clean";

  const anyConfigured = [vt, gsb, urlhaus, otx].some((s) => s.configured);

  return {
    url,
    overall: anyConfigured ? overall : "not_configured",
    flags,
    sources: { vt, gsb, urlhaus, otx },
  };
}

// ---------- badge + messaging ----------

function setBadge(tabId, result) {
  let text = "";
  let color = "#9e9e9e";

  if (!result || result.overall === "not_configured") {
    text = "!";
    color = "#9e9e9e";
  } else if (result.overall === "malicious") {
    text = String(result.flags.length);
    color = "#d32f2f";
  } else if (result.overall === "suspicious") {
    text = String(result.flags.length);
    color = "#f9a825";
  } else if (result.overall === "clean") {
    text = "✓";
    color = "#2e7d32";
  } else {
    text = "?";
    color = "#9e9e9e";
  }

  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

async function notifyContentScript(tabId, result) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "VT_RESULT", result });
  } catch (e) {
    // content script may not be ready yet (e.g. chrome:// pages) — safe to ignore
  }
}

// ---------- main check flow ----------

async function runCheck(url) {
  const keys = await getKeys();
  const [vt, gsb, urlhaus, otx] = await Promise.all([
    enqueueVT(() => fetchVT(url, keys.vt)),
    fetchGSB(url, keys.gsb),
    fetchURLhaus(url, keys.urlhaus),
    fetchOTX(url, keys.otx),
  ]);
  const result = aggregate(url, vt, gsb, urlhaus, otx);
  await setCached(url, result);
  return result;
}

async function checkUrl(tabId, rawUrl) {
  if (!isCheckableUrl(rawUrl)) return;
  const url = normalizeUrl(rawUrl);
  if (!url) return;

  const cached = await getCached(url);
  if (cached) {
    setBadge(tabId, cached);
    notifyContentScript(tabId, cached);
    return;
  }

  // de-duplicate: if this exact URL is already being checked (e.g. onUpdated
  // and onActivated both fired for the same navigation), reuse that request
  if (inFlight.has(url)) {
    const result = await inFlight.get(url);
    setBadge(tabId, result);
    notifyContentScript(tabId, result);
    return;
  }

  const promise = runCheck(url);
  inFlight.set(url, promise);
  try {
    const result = await promise;
    setBadge(tabId, result);
    notifyContentScript(tabId, result);
  } finally {
    inFlight.delete(url);
  }
}

// user-triggered submit-and-scan for URLs VT hasn't seen yet
async function scanNowVT(rawUrl) {
  const url = normalizeUrl(rawUrl);
  if (!url) return { error: "Invalid URL" };

  const keys = await getKeys();
  if (!keys.vt) return { error: "No VirusTotal API key set" };

  const vt = await enqueueVT(() => submitVTAndPoll(url, keys.vt));

  const cached = await getCached(url);
  const gsb = cached?.sources?.gsb || { configured: false };
  const urlhaus = cached?.sources?.urlhaus || { configured: false };
  const otx = cached?.sources?.otx || { configured: false };

  const result = aggregate(url, vt, gsb, urlhaus, otx);
  await setCached(url, result);
  return result;
}

// ---------- lifecycle: cache cleanup ----------

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(CACHE_CLEANUP_ALARM, { periodInMinutes: CACHE_CLEANUP_PERIOD_MIN });
  cleanupExpiredCache();
});

chrome.runtime.onStartup.addListener(() => {
  cleanupExpiredCache();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CACHE_CLEANUP_ALARM) cleanupExpiredCache();
});

// ---------- event listeners ----------

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    checkUrl(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url) checkUrl(tabId, tab.url);
  } catch (e) {
    // tab may have closed before this resolved — safe to ignore
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT_FOR_ACTIVE_TAB") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !isCheckableUrl(tab.url)) {
        sendResponse({ result: null, url: tab?.url || null });
        return;
      }
      const url = normalizeUrl(tab.url);
      const cached = url ? await getCached(url) : null;
      sendResponse({ result: cached, url });
    })();
    return true; // keep the message channel open for the async response
  }

  if (message.type === "SCAN_NOW") {
    (async () => {
      const result = await scanNowVT(message.url);
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        setBadge(tab.id, result);
        notifyContentScript(tab.id, result);
      }
      sendResponse({ result });
    })();
    return true;
  }
});
