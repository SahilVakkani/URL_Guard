const fields = ["vtApiKey", "gsbApiKey", "otxApiKey", "urlhausAuthKey"];
const status = document.getElementById("status");

chrome.storage.local.get(fields, (stored) => {
  for (const f of fields) {
    if (stored[f]) document.getElementById(f).value = stored[f];
  }
});

function showStatus(text) {
  status.textContent = text;
  setTimeout(() => (status.textContent = ""), 2500);
}

document.getElementById("save").addEventListener("click", () => {
  const values = {};
  for (const f of fields) {
    values[f] = document.getElementById(f).value.trim();
  }
  chrome.storage.local.set(values, () => {
    showStatus("Saved. Reload any open tabs to apply.");
  });
});

document.getElementById("clearAll").addEventListener("click", () => {
  if (!confirm("Clear all saved API keys? This can't be undone.")) return;
  chrome.storage.local.remove(fields, () => {
    for (const f of fields) document.getElementById(f).value = "";
    showStatus("All keys cleared.");
  });
});
