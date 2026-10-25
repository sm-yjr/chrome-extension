const statusEl = document.getElementById("status");
const statusText = document.getElementById("statusText");
const retryBtn = document.getElementById("retry");

function updateUI(state) {
  if (state.connected) {
    statusEl.className = "status connected";
    const count = state.instanceCount || 1;
    statusText.textContent = `Connected (${count} instance${count > 1 ? "s" : ""})`;
  } else {
    statusEl.className = "status disconnected";
    statusText.textContent = "Disconnected";
  }
}

chrome.runtime.sendMessage({ type: "getState" }, (response) => {
  if (response) updateUI(response);
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "stateUpdate") {
    updateUI(msg);
  }
});

retryBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "retry" });
});

const tokenInput = document.getElementById("bridgeToken");
const pairStatus = document.getElementById("pairStatus");
document.getElementById("pairForm").addEventListener("submit", async event => {
  event.preventDefault();
  const token = tokenInput.value.trim();
  if (!/^[a-f0-9]{64}$/.test(token)) { pairStatus.textContent = "Enter a 64-character hex token."; return; }
  await chrome.storage.local.set({ bridgeToken: token });
  tokenInput.value = "";
  pairStatus.textContent = "Paired. Only servers with this token can connect.";
});
document.getElementById("unpair").addEventListener("click", async () => {
  await chrome.storage.local.remove("bridgeToken");
  pairStatus.textContent = "Unpaired.";
});
