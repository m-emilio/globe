(function () {
  const userNode = document.getElementById("market-user");
  const cartLines = document.getElementById("cart-lines");
  const statusNode = document.getElementById("market-status");
  const checkoutButton = document.getElementById("checkout");
  const catalogList = document.getElementById("catalog-list");
  const cartKey = "globe-market-cart";
  let catalog = [];
  let cart = [];

  function money(cents) {
    return (cents / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });
  }

  function setStatus(text, kind) {
    if (!statusNode) return;
    statusNode.textContent = text;
    statusNode.className = "status" + (kind ? " " + kind : "");
  }

  function readCart() {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(cartKey) || "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((id) => catalog.some((item) => item.id === id));
    } catch (err) {
      return [];
    }
  }

  function writeCart() {
    sessionStorage.setItem(cartKey, JSON.stringify(cart));
  }

  function paintCart() {
    if (!cartLines || !checkoutButton) return;
    if (!cart.length) {
      cartLines.textContent = "Your cart is empty.";
      checkoutButton.disabled = true;
      return;
    }
    cartLines.replaceChildren();
    cart.forEach((id) => {
      const item = catalog.find((row) => row.id === id);
      if (!item) return;
      const line = document.createElement("div");
      line.textContent = item.name + " — " + money(item.amountCents);
      cartLines.append(line);
    });
    checkoutButton.disabled = false;
  }

  function paintCatalog() {
    if (!catalogList) return;
    catalogList.replaceChildren();
    catalog.forEach((item) => {
      const card = document.createElement("article");
      card.className = "listing";
      const title = document.createElement("h3");
      title.textContent = item.name;
      const copy = document.createElement("p");
      copy.textContent = item.summary;
      const price = document.createElement("p");
      price.textContent = money(item.amountCents);
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = cart.indexOf(item.id) === -1 ? "Add to cart" : "In cart";
      button.disabled = cart.indexOf(item.id) !== -1;
      button.addEventListener("click", function () {
        if (cart.indexOf(item.id) !== -1) return;
        cart.push(item.id);
        writeCart();
        paintCatalog();
        paintCart();
      });
      card.append(title, copy, price, button);
      catalogList.append(card);
    });
  }

  function stripeUrl(value) {
    let parsed;
    try { parsed = new URL(value); } catch (err) { return null; }
    const host = parsed.hostname.toLowerCase();
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) return null;
    if (host !== "checkout.stripe.com" && host !== "buy.stripe.com") return null;
    return parsed.toString();
  }

  async function loadSession() {
    if (!userNode) return;
    try {
      const response = await fetch("/api/auth/me", { credentials: "same-origin", headers: { accept: "application/json" } });
      const body = await response.json();
      userNode.textContent = body && body.authenticated === true ? "Signed in" : "Guest — sign in on Globe to check out";
    } catch (err) {
      userNode.textContent = "Guest — sign in on Globe to check out";
    }
  }

  async function loadCatalog() {
    const response = await fetch("/api/billing/market-catalog", { headers: { accept: "application/json" } });
    const body = await response.json();
    if (!response.ok || !body || !Array.isArray(body.items)) throw new Error("catalog");
    catalog = body.items.filter((item) => item && typeof item.id === "string" && typeof item.name === "string" && typeof item.summary === "string" && typeof item.amountCents === "number");
    cart = readCart();
    paintCatalog();
    paintCart();
  }

  async function showReturn() {
    const params = new URLSearchParams(location.search);
    const checkout = params.get("checkout");
    if (checkout === "cancel") {
      setStatus("Checkout canceled. The cart is still here.", "");
      history.replaceState(null, "", "/market");
      return;
    }
    if (checkout !== "success") return;
    const sessionId = params.get("session_id") || "";
    history.replaceState(null, "", "/market");
    if (!/^cs_(test_|live_)?[a-zA-Z0-9]{8,200}$/.test(sessionId)) {
      setStatus("Stripe did not return a checkout session.", "bad");
      return;
    }
    const response = await fetch("/api/billing/market-order?session_id=" + encodeURIComponent(sessionId), {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const body = await response.json().catch(function () { return {}; });
    if (response.status === 401) {
      setStatus("Sign in with the same Globe account that started checkout.", "bad");
      return;
    }
    if (!response.ok || !body || body.paid !== true) {
      setStatus("Payment is not recorded yet. Refresh this page in a moment.", "bad");
      return;
    }
    const names = Array.isArray(body.names) ? body.names.filter((name) => typeof name === "string") : [];
    const amount = typeof body.amountTotal === "number" ? money(body.amountTotal) : "";
    setStatus("Paid " + amount + (names.length ? " for " + names.join(", ") : "") + ".", "ok");
    cart = [];
    writeCart();
    paintCatalog();
    paintCart();
  }

  if (checkoutButton) {
    checkoutButton.addEventListener("click", async function () {
      setStatus("", "");
      checkoutButton.disabled = true;
      try {
        const response = await fetch("/api/billing/market-checkout", {
          method: "POST",
          credentials: "same-origin",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ items: cart }),
        });
        const body = await response.json().catch(function () { return {}; });
        if (response.status === 401) {
          setStatus("Sign in on Globe, then return here to check out.", "bad");
          checkoutButton.disabled = false;
          return;
        }
        const next = body && typeof body.url === "string" ? stripeUrl(body.url) : null;
        if (!response.ok || !next) {
          setStatus("Stripe checkout did not open.", "bad");
          checkoutButton.disabled = false;
          return;
        }
        setStatus("Redirecting to Stripe Checkout…", "");
        window.location.href = next;
      } catch (err) {
        setStatus("Stripe checkout did not open.", "bad");
        checkoutButton.disabled = false;
      }
    });
  }

  loadSession();
  loadCatalog().then(showReturn).catch(function () {
    setStatus("The price list did not load.", "bad");
  });
})();
