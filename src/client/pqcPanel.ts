/**
 * Browser lab for post-quantum key agreement.
 * Loaded on demand from pqcBoot.ts. Sign-in sends a MAC, not the secret.
 */
import {
  PQC_KEM_SUITES,
  PQC_SUITE_ID,
  clearPqcSecret,
  copyPqcSecret,
  decapsulateWithLocal,
  encapsulateToPeer,
  generatePqcKeyPair,
  isPqcKemId,
  kemLoginProof,
  kemLoginProofFromSecret,
  pqcKemSuite,
  pqcSelfTest,
  type PqcKemId,
  type PqcLocalPublic,
} from "./pqc";
import { loadLabMaterial, signInWithLabKey } from "./labVault";

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
    "margin-top:16px",
    "width:100%",
    "box-sizing:border-box",
    "max-height:min(52dvh, 560px)",
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
  const signIn = button("Sign in with this key");
  signIn.id = "globe-pqc-lab-signin";
  const savedSignIn = button("Sign in with saved lab key");
  savedSignIn.id = "globe-pqc-lab-saved-signin";
  const selfTest = button("Self-test all suites");
  const close = button("Close");
  row.append(generate, signIn, savedSignIn, selfTest, close);

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
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (modal instanceof HTMLElement) modal.append(root);
  else document.body.append(root);

  const selectedSuite = (): PqcKemId => {
    const value = suiteSelect.value;
    return isPqcKemId(value) ? value : PQC_SUITE_ID;
  };
  const refreshHint = () => {
    const suite = pqcKemSuite(selectedSuite());
    hint.textContent = `${suite.label} in pure JavaScript (@noble/post-quantum). Public key ${suite.publicKey} bytes, ciphertext ${suite.cipherText} bytes. The secret stays on this device. Sign in from this lab sends a proof, not the secret. The shared secret is shown only as a SHA-256 fingerprint.`;
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
    const nodes = [generate, signIn, savedSignIn, selfTest, encapsulate, decapsulate, clear, close, suiteSelect];
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
      setStatus("Key ready. Share the public key, or sign in with it. The secret stays on this device.");
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

  const signInBusy = (message: string, run: () => Promise<void>) => {
    setBusy(true);
    setStatus(message);
    void run()
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "Lab sign-in failed.", true);
        setBusy(false);
      });
  };
  signIn.addEventListener("click", () => {
    if (!localKey) {
      setStatus("Generate a key first.", true);
      return;
    }
    const current = localKey;
    const secret = copyPqcSecret(current.id);
    if (!secret) {
      setStatus("Generate a key first.", true);
      return;
    }
    signInBusy("Checking the key-agreement sign-in…", async () => {
      try {
        await signInWithLabKey({
          family: "kem",
          suite: current.suite,
          publicKeyB64: current.publicKeyB64,
          material: secret,
          prove: (message, token) => kemLoginProof(current.id, token, message),
        });
      } finally {
        secret.fill(0);
      }
    });
  });
  savedSignIn.addEventListener("click", () => {
    const suite = selectedSuite();
    signInBusy("Checking the saved lab key…", async () => {
      const saved = await loadLabMaterial("kem", suite);
      if (!saved) throw new Error("No saved key for this suite on this device.");
      try {
        await signInWithLabKey({
          family: "kem",
          suite,
          publicKeyB64: saved.publicKeyB64,
          material: saved.material,
          prove: (message, token) => kemLoginProofFromSecret(suite, saved.material, token, message),
        });
      } finally {
        saved.material.fill(0);
      }
    });
  });

  close.addEventListener("click", () => {
    if (localKey) clearPqcSecret(localKey.id);
    localKey = null;
    const parent = root.parentElement;
    root.remove();
    if (parent instanceof HTMLElement && parent.classList.contains("auth-modal")) {
      delete parent.dataset.globePqcLab;
      if (!parent.querySelector("#globe-pqc-open")) {
        const reopen = button("PQC key lab");
        reopen.id = "globe-pqc-open";
        reopen.style.width = "100%";
        reopen.style.marginTop = "12px";
        reopen.addEventListener("click", () => {
          reopen.remove();
          mountPqcLab();
        });
        parent.append(reopen);
      }
    }
  });
}
