/**
 * Browser lab for post-quantum key agreement.
 * Loaded on demand from pqcBoot.ts. Not an OpenPGP or ML-DSA login key.
 */
import {
  PQC_KEM_SUITES,
  PQC_SUITE_ID,
  clearPqcSecret,
  decapsulateWithLocal,
  encapsulateToPeer,
  generatePqcKeyPair,
  isPqcKemId,
  pqcKemSuite,
  pqcSelfTest,
  type PqcKemId,
  type PqcLocalPublic,
} from "./pqc";

let localKey: PqcLocalPublic | null = null;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function field(label: string, area: HTMLTextAreaElement): HTMLLabelElement {
  const wrap = el("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:10px 0";
  const span = el("span", label);
  span.style.cssText = "font-size:12px;color:#c9ffe4";
  area.spellcheck = false;
  area.style.cssText = [
    "width:100%",
    "box-sizing:border-box",
    "min-height:72px",
    "resize:vertical",
    "font:11px/1.35 ui-monospace,monospace",
    "color:#e8fff4",
    "background:#0c1612",
    "border:1px solid rgba(61,255,168,0.28)",
    "border-radius:6px",
    "padding:8px",
  ].join(";");
  wrap.append(span, area);
  return wrap;
}

function button(label: string): HTMLButtonElement {
  const node = el("button", label);
  node.type = "button";
  node.style.cssText = [
    "padding:8px 12px",
    "border-radius:8px",
    "border:1px solid rgba(61,255,168,0.4)",
    "background:#16382c",
    "color:#e7fff3",
    "cursor:pointer",
    "font:600 13px/1.2 system-ui,sans-serif",
  ].join(";");
  return node;
}

export function mountPqcLab(): void {
  if (document.getElementById("globe-pqc-lab")) return;

  const root = el("section");
  root.id = "globe-pqc-lab";
  root.style.cssText = [
    "position:fixed",
    "right:max(12px, env(safe-area-inset-right))",
    "bottom:max(12px, env(safe-area-inset-bottom))",
    "z-index:10000",
    "width:min(420px, calc(100vw - 24px))",
    "max-height:min(80vh, 720px)",
    "overflow:auto",
    "padding:14px",
    "border-radius:12px",
    "border:1px solid rgba(61,255,168,0.35)",
    "background:rgba(10,24,20,0.96)",
    "color:#e7fff3",
    "box-shadow:0 12px 40px rgba(0,0,0,0.35)",
    "font:14px/1.4 system-ui,sans-serif",
  ].join(";");

  const title = el("h2", "Post-quantum key agreement");
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const hint = el("p", "");
  hint.id = "globe-pqc-hint";
  hint.style.cssText = "margin:0 0 10px;color:#b7e8d2;font-size:13px";

  const suiteLabel = el("label");
  suiteLabel.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:0 0 10px";
  const suiteSpan = el("span", "Suite");
  suiteSpan.style.cssText = "font-size:12px;color:#c9ffe4";
  const suiteSelect = el("select");
  suiteSelect.id = "globe-pqc-suite";
  suiteSelect.style.cssText = [
    "min-height:44px",
    "font:16px/1.2 system-ui,sans-serif",
    "color:#e7fff3",
    "background:#0c1612",
    "border:1px solid rgba(61,255,168,0.35)",
    "border-radius:8px",
    "padding:8px",
  ].join(";");
  for (let i = 0; i < PQC_KEM_SUITES.length; i++) {
    const suite = PQC_KEM_SUITES[i]!;
    const option = el("option", suite.label);
    option.value = suite.id;
    if (suite.id === PQC_SUITE_ID) option.selected = true;
    suiteSelect.append(option);
  }
  suiteLabel.append(suiteSpan, suiteSelect);

  const status = el("p", "");
  status.id = "globe-pqc-status";
  status.style.cssText = "min-height:1.2em;margin:8px 0;font-size:13px";

  const row = el("div");
  row.style.cssText = "display:flex;flex-wrap:wrap;gap:8px";
  const generate = button("Generate key");
  const selfTest = button("Self-test all suites");
  const close = button("Close");
  row.append(generate, selfTest, close);

  const publicArea = el("textarea");
  publicArea.readOnly = true;
  publicArea.rows = 4;
  const peerArea = el("textarea");
  peerArea.rows = 4;
  peerArea.placeholder = "Paste a peer public key for the selected suite";
  const encapsulate = button("Encapsulate to peer");
  const cipherArea = el("textarea");
  cipherArea.readOnly = true;
  cipherArea.rows = 4;
  const incomingArea = el("textarea");
  incomingArea.rows = 4;
  incomingArea.placeholder = "Paste a ciphertext encapsulated to your public key";
  const decapsulate = button("Decapsulate");
  const clear = button("Clear secret");
  const fp = el("code", "");
  fp.style.cssText = "display:block;word-break:break-all;font:12px/1.35 ui-monospace,monospace;color:#9af0d0";

  const actions = el("div");
  actions.hidden = true;
  actions.append(
    field("Your public key (base64) — share this", publicArea),
    field("Peer public key (base64)", peerArea),
    encapsulate,
    field("Ciphertext (base64) — send this to the peer", cipherArea),
    field("Incoming ciphertext (base64)", incomingArea),
    decapsulate,
    clear,
  );

  const fpBlock = el("div");
  fpBlock.hidden = true;
  fpBlock.append(el("strong", "Shared secret fingerprint (SHA-256)"), fp);

  root.append(title, hint, suiteLabel, row, status, actions, fpBlock);
  document.body.append(root);

  const selectedSuite = (): PqcKemId => {
    const value = suiteSelect.value;
    return isPqcKemId(value) ? value : PQC_SUITE_ID;
  };
  const refreshHint = () => {
    const suite = pqcKemSuite(selectedSuite());
    hint.textContent = `${suite.label} in pure JavaScript (@noble/post-quantum). Public key ${suite.publicKey} bytes, ciphertext ${suite.cipherText} bytes. The secret stays in this page. The shared secret is shown only as a SHA-256 fingerprint. This is not a sign-in key.`;
  };
  const setStatus = (message: string, isError = false) => {
    status.textContent = message;
    status.style.color = isError ? "#ffb4b4" : "#d8ffe8";
    if (!isError && message.startsWith("Self-test passed")) {
      status.dataset.pqcSelfTest = "pass";
    } else {
      delete status.dataset.pqcSelfTest;
    }
  };
  const setBusy = (busy: boolean) => {
    const nodes = [generate, selfTest, encapsulate, decapsulate, clear, close, suiteSelect];
    for (let i = 0; i < nodes.length; i++) nodes[i]!.disabled = busy;
  };
  const showFp = (hex: string) => {
    fp.textContent = hex;
    fpBlock.hidden = hex.length === 0;
  };
  const clearLocal = (message: string) => {
    if (localKey) clearPqcSecret(localKey.id);
    localKey = null;
    publicArea.value = "";
    peerArea.value = "";
    cipherArea.value = "";
    incomingArea.value = "";
    showFp("");
    actions.hidden = true;
    setStatus(message);
  };

  refreshHint();

  suiteSelect.addEventListener("change", () => {
    if (localKey && localKey.suite !== selectedSuite()) {
      clearLocal("Cleared the previous suite secret from this page.");
    }
    refreshHint();
  });

  generate.addEventListener("click", () => {
    setBusy(true);
    try {
      if (localKey) clearPqcSecret(localKey.id);
      localKey = generatePqcKeyPair(selectedSuite());
      publicArea.value = localKey.publicKeyB64;
      cipherArea.value = "";
      showFp("");
      actions.hidden = false;
      setStatus("Key ready. Share the public key. This is not a sign-in key.");
    } catch (error) {
      localKey = null;
      actions.hidden = true;
      setStatus(error instanceof Error ? error.message : "Generate failed", true);
    } finally {
      setBusy(false);
    }
  });

  encapsulate.addEventListener("click", () => {
    const suite = selectedSuite();
    setBusy(true);
    void encapsulateToPeer(peerArea.value, suite)
      .then((agreed) => {
        cipherArea.value = agreed.cipherTextB64 || "";
        showFp(agreed.sharedSecretSha256Hex);
        setStatus("Encapsulated. Share the ciphertext. Raw shared bits are not shown.");
      })
      .catch((error: unknown) => {
        cipherArea.value = "";
        showFp("");
        setStatus(error instanceof Error ? error.message : "Encapsulate failed", true);
      })
      .finally(() => setBusy(false));
  });

  decapsulate.addEventListener("click", () => {
    if (!localKey) {
      setStatus("Generate a local key first.", true);
      return;
    }
    if (localKey.suite !== selectedSuite()) {
      setStatus("Switch the suite back to the generated key before decapsulating.", true);
      return;
    }
    const id = localKey.id;
    setBusy(true);
    void decapsulateWithLocal(id, incomingArea.value)
      .then((agreed) => {
        showFp(agreed.sharedSecretSha256Hex);
        setStatus("Decapsulated. A matching fingerprint means both sides agreed.");
      })
      .catch((error: unknown) => {
        showFp("");
        setStatus(error instanceof Error ? error.message : "Decapsulate failed", true);
      })
      .finally(() => setBusy(false));
  });

  selfTest.addEventListener("click", () => {
    setBusy(true);
    setStatus("Running self-test…");
    void pqcSelfTest()
      .then(() => {
        showFp("");
        setStatus("Self-test passed. All key-agreement suites matched, and a flipped ciphertext did not.");
      })
      .catch((error: unknown) => {
        showFp("");
        setStatus(error instanceof Error ? error.message : "Self-test failed", true);
      })
      .finally(() => setBusy(false));
  });

  clear.addEventListener("click", () => {
    clearLocal("Cleared the key-agreement secret from this page.");
  });

  close.addEventListener("click", () => {
    if (localKey) clearPqcSecret(localKey.id);
    localKey = null;
    root.remove();
    window.dispatchEvent(new Event("globe-pqc-closed"));
  });
}
