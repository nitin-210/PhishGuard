const DEFAULT_BACKEND = "http://127.0.0.1:8000";
const input = document.getElementById("backend");
const ok = document.getElementById("ok");

chrome.storage.sync.get({ backend: DEFAULT_BACKEND }, (v) => {
  input.value = v.backend || DEFAULT_BACKEND;
});

document.getElementById("save").onclick = () => {
  const backend = (input.value || DEFAULT_BACKEND).trim().replace(/\/$/, "");
  chrome.storage.sync.set({ backend }, () => {
    ok.style.display = "block";
    setTimeout(() => (ok.style.display = "none"), 1500);
  });
};
