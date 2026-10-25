(function () {
  if (globalThis.__claudeA11yTree) return;

  const refMap = new Map(); // ref_N -> WeakRef<Element>
  let refCounter = 1;

  // --- Role mapping ---

  function getImplicitRole(el) {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    const explicit = el.getAttribute("role");
    if (explicit) return explicit;

    switch (tag) {
      case "a":
        return el.hasAttribute("href") ? "link" : null;
      case "button":
        return "button";
      case "input":
        switch (type) {
          case "text": case "email": case "password": case "search":
          case "tel": case "url": case "":
            return "textbox";
          case "checkbox":
            return "checkbox";
          case "radio":
            return "radio";
          case "range":
            return "slider";
          case "number":
            return "spinbutton";
          case "submit": case "reset": case "button": case "image":
            return "button";
          case "file":
            return "button";
          default:
            return "textbox";
        }
      case "select":
        return (el.size && el.size > 1) ? "listbox" : "combobox";
      case "textarea":
        return "textbox";
      case "h1": case "h2": case "h3": case "h4": case "h5": case "h6":
        return "heading";
      case "img":
        return el.getAttribute("alt") === "" ? "presentation" : "image";
      case "ul": case "ol":
        return "list";
      case "li":
        return "listitem";
      case "table":
        return "table";
      case "tr":
        return "row";
      case "td":
        return "cell";
      case "th":
        return "columnheader";
      case "nav":
        return "navigation";
      case "main":
        return "main";
      case "header":
        return "banner";
      case "footer":
        return "contentinfo";
      case "aside":
        return "complementary";
      case "form":
        return getAccessibleName(el, "form") ? "form" : null;
      case "section":
        return getAccessibleName(el, "region") ? "region" : null;
      case "dialog":
        return "dialog";
      case "details":
        return "group";
      case "progress":
        return "progressbar";
      case "meter":
        return "meter";
      case "article":
        return "article";
      default:
        return null;
    }
  }

  // --- Accessible name ---

  function getAccessibleName(el, _role) {
    const ariaLabel = el.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.trim();

    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const parts = labelledBy.split(/\s+/).map(id => {
        const ref = document.getElementById(id);
        return ref ? ref.textContent.trim() : "";
      }).filter(Boolean);
      if (parts.length) return parts.join(" ").slice(0, 100);
    }

    if (el.tagName === "IMG") {
      const alt = el.getAttribute("alt");
      if (alt) return alt.trim().slice(0, 100);
    }

    // Label association for inputs
    const tag = el.tagName.toLowerCase();
    if (["input", "select", "textarea"].includes(tag)) {
      if (el.id) {
        const label = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (label) return label.textContent.trim().slice(0, 100);
      }
      // Ancestor label
      const ancestorLabel = el.closest("label");
      if (ancestorLabel) return ancestorLabel.textContent.trim().slice(0, 100);
    }

    const placeholder = el.getAttribute("placeholder");
    if (placeholder) return placeholder.trim().slice(0, 100);

    const title = el.getAttribute("title");
    if (title) return title.trim().slice(0, 100);

    // For buttons, links, headings: use textContent
    if (["button", "a", "h1", "h2", "h3", "h4", "h5", "h6", "label"].includes(tag)) {
      const text = el.textContent.trim();
      if (text) return text.slice(0, 80);
    }
    // For elements with button/link roles
    const role = el.getAttribute("role");
    if (role && ["button", "link", "tab", "menuitem", "option"].includes(role)) {
      const text = el.textContent.trim();
      if (text) return text.slice(0, 80);
    }

    return "";
  }

  // --- Visibility ---

  function isVisible(el) {
    if (el.getAttribute("aria-hidden") === "true") return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none") return false;
    if (style.visibility === "hidden") return false;
    // Fixed/sticky elements have no offsetParent but are visible
    if (el.offsetParent === null && style.position !== "fixed" && style.position !== "sticky") {
      // Could be in a non-rendered tree
      if (el.offsetWidth === 0 && el.offsetHeight === 0) return false;
    }
    return true;
  }

  // --- Should assign ref ---

  const SKIP_TAGS = new Set(["script", "style", "noscript", "svg", "path", "link", "meta", "br", "hr"]);

  const INTERACTIVE_ROLES = new Set([
    "button", "link", "textbox", "searchbox", "combobox", "checkbox", "radio",
    "slider", "spinbutton", "menuitem", "menuitemcheckbox", "menuitemradio",
    "option", "tab", "switch", "treeitem"
  ]);

  const LANDMARK_ROLES = new Set([
    "navigation", "main", "banner", "contentinfo", "complementary", "region",
    "search", "dialog", "alertdialog", "form"
  ]);

  function shouldAssignRef(el, role) {
    if (!role) return false;
    if (INTERACTIVE_ROLES.has(role)) return true;
    if (LANDMARK_ROLES.has(role)) return true;
    // Headings
    const tag = el.tagName.toLowerCase();
    if (["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag)) return true;
    // Elements with tabindex
    const tabindex = el.getAttribute("tabindex");
    if (tabindex !== null && parseInt(tabindex) >= 0) return true;
    // contenteditable
    if (el.isContentEditable && el.getAttribute("contenteditable") !== "false") return true;
    // onclick
    if (el.onclick || el.getAttribute("onclick")) return true;
    return false;
  }

  // --- Tree building ---

  function clearRefs() {
    refMap.clear();
    refCounter = 1;
  }

  function assignRef(el) {
    // Check if element already has a ref
    for (const [ref, weakRef] of refMap) {
      if (weakRef.deref() === el) return ref;
    }
    const ref = `ref_${refCounter++}`;
    refMap.set(ref, new WeakRef(el));
    return ref;
  }

  function generate(options) {
    const maxDepth = (options && options.maxDepth) || 15;
    const rootSelector = options && options.root;

    clearRefs();

    const rootEl = rootSelector ? document.querySelector(rootSelector) : document.body;
    if (!rootEl) {
      return { structure: null, refCount: 0 };
    }

    function buildNode(el, depth, inShadow) {
      if (depth > maxDepth) return null;
      const tag = el.tagName ? el.tagName.toLowerCase() : null;
      if (!tag) return null;
      if (SKIP_TAGS.has(tag)) return null;
      if (!isVisible(el)) return null;

      // Iframes: the child document lives in a separate frame (possibly a
      // different process), so never recurse here. Keep the node with its
      // URL so the background can graft that frame's own tree onto it.
      if (tag === "iframe" || tag === "frame") {
        const frameNode = { tag };
        if (inShadow) frameNode.shadow = true;
        frameNode.src = el.src || "";
        const frameTitle = el.getAttribute("title");
        if (frameTitle) frameNode.name = frameTitle;
        return frameNode;
      }

      const role = getImplicitRole(el);
      const name = getAccessibleName(el, role);
      const hasRef = shouldAssignRef(el, role);

      const node = { tag };
      if (inShadow) node.shadow = true;
      if (role) node.role = role;
      if (name) node.name = name;

      if (hasRef) {
        node.ref = assignRef(el);
      }

      // States
      if (el.disabled) node.disabled = true;
      if (el.checked !== undefined && el.checked) node.checked = true;
      if (el.getAttribute("aria-expanded") !== null) {
        node.expanded = el.getAttribute("aria-expanded") === "true";
      }
      if (el.selected) node.selected = true;
      if (el.required) node.required = true;
      if (el.readOnly) node.readOnly = true;

      // Value for inputs
      if (tag === "input" || tag === "textarea" || tag === "select") {
        if (el.value) node.value = el.type === "password" || /password|one-time-code|cc-number|cc-csc/.test(el.autocomplete || "") ? "[redacted]" : el.value.slice(0, 100);
        if (el.placeholder) node.placeholder = el.placeholder;
      }

      // href for links
      if (tag === "a" && el.href) {
        node.href = el.getAttribute("href");
      }

      // Children, then open shadow trees. Closed shadow roots are not
      // visible to content scripts and are intentionally skipped.
      const children = [];
      for (const child of el.children) {
        const childNode = buildNode(child, depth + 1, inShadow);
        if (childNode) children.push(childNode);
      }
      if (el.shadowRoot) {
        for (const child of el.shadowRoot.children) {
          const childNode = buildNode(child, depth + 1, true);
          if (childNode) children.push(childNode);
        }
      }

      if (children.length) {
        node.children = children;
      }

      // Prune: if no ref and no children with refs, and not a landmark/heading, skip container
      if (!node.ref && !role && !children.some(c => c.ref || c.children)) {
        // Pure container with no interactive descendants - collapse
        if (!children.length) {
          // Leaf non-interactive - skip entirely unless it has meaningful text
          const text = el.textContent.trim();
          if (text && text.length > 0 && text.length <= 200) {
            // Keep as text node
            node.text = text.slice(0, 120);
            return node;
          }
          return null;
        }
        // Has children but no refs in subtree - still include for structure
      }

      return node;
    }

    const tree = buildNode(rootEl, 0, false);
    return { structure: tree, refCount: refMap.size };
  }

  // --- Element access ---

  function getElementByRef(ref) {
    const weakRef = refMap.get(ref);
    if (!weakRef) return null;
    const el = weakRef.deref();
    if (!el) {
      refMap.delete(ref);
      return null;
    }
    // document.contains() is false for open-shadow nodes. isConnected is
    // true for any node still attached, including those inside a shadow root.
    if (!el.isConnected) {
      refMap.delete(ref);
      return null;
    }
    return el;
  }

  function getRefForElement(el) {
    for (const [ref, weakRef] of refMap) {
      if (weakRef.deref() === el) return ref;
    }
    // Create new ref
    const ref = `ref_${refCounter++}`;
    refMap.set(ref, new WeakRef(el));
    return ref;
  }

  function getElementCoordinates(ref) {
    const el = getElementByRef(ref);
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    return {
      x: rect.left + rect.width / 2,
      y: rect.top + rect.height / 2,
      width: rect.width,
      height: rect.height,
    };
  }

  function resolveRef(ref) {
    return getElementByRef(ref);
  }

  // --- Public API ---

  globalThis.__claudeA11yTree = {
    generate,
    getElementByRef,
    getRefForElement,
    getElementCoordinates,
    resolveRef,
    clearRefs,
    get refCount() { return refMap.size; },
  };
})();
