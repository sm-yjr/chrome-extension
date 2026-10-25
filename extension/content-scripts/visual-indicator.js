(function () {
  if (globalThis.__claudeVisualIndicator) return;

  let overlayContainer = null;
  let statusBadge = null;

  function getContainer() {
    if (overlayContainer) return overlayContainer;
    let host = document.getElementById("claude-overlay-host");
    if (host && host.shadowRoot) {
      overlayContainer = host.shadowRoot;
      return overlayContainer;
    }
    host = document.createElement("div");
    host.id = "claude-overlay-host";
    host.style.cssText = "all: initial; position: fixed; z-index: 2147483647; pointer-events: none;";
    overlayContainer = host.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = `
      @keyframes claude-pulse {
        0%, 100% {
          border-color: #4CAF50;
          box-shadow: 0 0 5px rgba(76, 175, 80, 0.5);
        }
        50% {
          border-color: #81C784;
          box-shadow: 0 0 20px rgba(76, 175, 80, 0.8);
        }
      }
      @keyframes claude-click-ripple {
        0% {
          width: 8px; height: 8px; opacity: 0.6;
        }
        100% {
          width: 24px; height: 24px; opacity: 0;
        }
      }
      @keyframes claude-badge-fade {
        0% { opacity: 1; }
        80% { opacity: 1; }
        100% { opacity: 0; }
      }
    `;
    overlayContainer.appendChild(style);
    document.body.appendChild(host);
    return overlayContainer;
  }

  function highlightElement(elOrRef, color, durationMs) {
    const duration = durationMs || 1500;
    const borderColor = color || "#4CAF50";
    let el;

    if (typeof elOrRef === "string") {
      const a11y = globalThis.__claudeA11yTree;
      if (!a11y) return;
      el = a11y.getElementByRef(elOrRef);
    } else {
      el = elOrRef;
    }
    if (!el) return;

    const rect = el.getBoundingClientRect();
    const container = getContainer();

    const overlay = document.createElement("div");
    overlay.setAttribute("data-claude-overlay", "highlight");
    overlay.style.cssText = `
      position: fixed;
      left: ${rect.left - 3}px;
      top: ${rect.top - 3}px;
      width: ${rect.width + 6}px;
      height: ${rect.height + 6}px;
      border: 2px solid ${borderColor};
      border-radius: ${window.getComputedStyle(el).borderRadius || "4px"};
      background: ${borderColor}1a;
      pointer-events: none;
      z-index: 2147483646;
      animation: claude-pulse 1s ease-in-out infinite;
      box-sizing: border-box;
    `;
    container.appendChild(overlay);

    setTimeout(() => {
      overlay.style.opacity = "0";
      overlay.style.transition = "opacity 0.3s ease";
      setTimeout(() => overlay.remove(), 300);
    }, duration);
  }

  function showClickFeedback(x, y) {
    const container = getContainer();
    const ripple = document.createElement("div");
    ripple.setAttribute("data-claude-overlay", "click");
    ripple.style.cssText = `
      position: fixed;
      left: ${x - 4}px;
      top: ${y - 4}px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #4285f4;
      pointer-events: none;
      z-index: 2147483646;
      animation: claude-click-ripple 0.4s ease-out forwards;
    `;
    container.appendChild(ripple);
    setTimeout(() => ripple.remove(), 500);
  }

  function showStatusBadge(text, type) {
    const colors = {
      info: "#2196F3",
      success: "#4CAF50",
      warning: "#FF9800",
      error: "#f44336",
    };
    const bgColor = colors[type] || colors.info;
    const container = getContainer();

    // Remove existing badge
    if (statusBadge) {
      statusBadge.remove();
      statusBadge = null;
    }

    const badge = document.createElement("div");
    badge.setAttribute("data-claude-overlay", "status");
    badge.style.cssText = `
      position: fixed;
      top: 16px;
      right: 16px;
      background: ${bgColor};
      color: white;
      padding: 8px 16px;
      border-radius: 6px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      font-weight: 500;
      pointer-events: none;
      z-index: 2147483647;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
      animation: claude-badge-fade 2s ease forwards;
    `;
    badge.textContent = text;
    container.appendChild(badge);
    statusBadge = badge;

    setTimeout(() => {
      if (badge.parentNode) badge.remove();
      if (statusBadge === badge) statusBadge = null;
    }, 2000);
  }

  function removeAllOverlays() {
    const container = getContainer();
    const overlays = container.querySelectorAll("[data-claude-overlay]");
    overlays.forEach(o => o.remove());
    statusBadge = null;
  }

  // --- Message handler ---

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
      case "SHOW_HIGHLIGHT":
        highlightElement(msg.ref || msg.selector, msg.color, msg.duration);
        sendResponse({ success: true });
        break;
      case "HIDE_HIGHLIGHT":
        removeAllOverlays();
        sendResponse({ success: true });
        break;
      case "SHOW_STATUS":
        showStatusBadge(msg.text || msg.status, msg.badgeType || "info");
        sendResponse({ success: true });
        break;
      case "HIDE_STATUS":
        if (statusBadge) { statusBadge.remove(); statusBadge = null; }
        sendResponse({ success: true });
        break;
      case "HIDE_ALL":
        removeAllOverlays();
        sendResponse({ success: true });
        break;
      default:
        sendResponse({ success: false });
    }
    return true;
  });

  // Cleanup on navigation
  window.addEventListener("beforeunload", () => {
    removeAllOverlays();
  });

  globalThis.__claudeVisualIndicator = {
    highlightElement,
    showClickFeedback,
    showStatusBadge,
    removeAllOverlays,
  };
})();
