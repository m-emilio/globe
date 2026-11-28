import { escapeHtml } from "./purpleTeamTools";

type PurpleTeamPage = {
  title: string;
  navigation: string;
  content: string;
  status?: number;
  certificateInspector?: boolean;
  theme?: "red";
};

// Opt-in red identity for the Red Team Recon page. Other pages never pass a theme, so their output is unchanged.
const RED_THEME_CSS = `
      :root{--bg:#120709;--panel:#1e0d11;--line:#5a2029;--text:#fff1f1;--muted:#e6bcc0;--link:#ff9ea6;--green:#8fe3b8;--warn:#ffc277;--red:#ff3b4f}
      body{background:radial-gradient(ellipse at top left,#4f0f1a,transparent 38rem),var(--bg)}
      header.heading{border-bottom:3px solid #e5142f;padding-bottom:.9rem}
      h1{color:var(--red)}
      h1::before{content:"";display:inline-block;width:.7rem;height:.7rem;margin-right:.55rem;border-radius:50%;background:#ff1f3d;box-shadow:0 0 .8rem #ff1f3d;vertical-align:middle}
      .panel,.notice{border-color:var(--line);border-left:4px solid #c8102e}
      .query input,.certificate-form textarea{border-color:#8c2a36}
      .names li{background:#3a1219}
      button{border-color:#e5142f;background:#e5142f;color:#fff}
      button:hover{background:#ff3b4f;border-color:#ff3b4f}
      .secondary{background:#3a1219;color:var(--text);border-color:#8c2a36}
      .secondary:hover{background:#561b25}
      .save-option input{accent-color:#ff3b4f}
      :focus-visible{outline-color:#ffc2c8}
      .authorized{border:1px solid #ff3b4f;border-left-width:6px;background:#2b0b11;color:var(--text)}
      .authorized strong{color:#ff7a88}
      .sev{display:inline-block;min-width:4.6rem;text-align:center;border-radius:.3rem;padding:.06rem .5rem;font-size:.72rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#fff}
      .sev-critical{background:#b3001b}.sev-high{background:#d9341f}.sev-medium{background:#a85b00}.sev-low{background:#6b5a14}.sev-info{background:#3b3b46}
      .sev-none{background:#1f6b4a}
      .rt-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(8rem,1fr));gap:.6rem;margin:.8rem 0}
      .rt-metrics div{border-left:3px solid #c8102e;padding:.15rem .65rem;background:#170a0d}
      .rt-metrics dt{font-size:.8rem;color:var(--muted)}
      .rt-metrics dd{margin:0;font-size:1.5rem;font-weight:800;font-variant-numeric:tabular-nums}
      .rt-list{list-style:none;padding:0;margin:.6rem 0 0}
      .rt-list>li{border-top:1px solid var(--line);padding:.75rem 0;overflow-wrap:anywhere}
      .rt-list h3{display:inline;margin:0 0 0 .5rem;font-size:1rem}
      .rt-tag{font-size:.75rem;color:var(--muted);margin-left:.4rem}
      .export-row{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:.6rem}
      @media print{
        :root{color-scheme:light;--bg:#fff;--panel:#fff;--line:#d8c6c8;--text:#201014;--muted:#4a3a3d;--link:#8a1020;--warn:#7c460a;--red:#a00018}
        body{background:#fff}.names li{background:#fff}.rt-metrics div{background:#fff}.authorized{background:#fff}
      }`;

export function purpleTeamPage(
  { title, navigation, content, status = 200, certificateInspector = false, theme }: PurpleTeamPage,
  applySecurityHeaders: (headers: Headers) => void,
): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "content-security-policy": certificateInspector
      ? "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
      : "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "referrer-policy": "same-origin",
  });
  applySecurityHeaders(headers);
  return new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)} · Globe</title>
    <style>
      :root{color-scheme:dark;--bg:#100d19;--panel:#1b1529;--line:#3f3453;--text:#f3ebff;--muted:#c9bdd8;--link:#d0b0ff;--green:#9ce8c7;--warn:#ffd291}
      *{box-sizing:border-box}
      body{margin:0;background:radial-gradient(ellipse at top left,#261839,transparent 36rem),var(--bg);color:var(--text);font:1rem/1.5 system-ui,sans-serif}
      main{max-width:64rem;margin:auto;padding:clamp(1rem,3.5vw,2.6rem)}
      h1{margin:0;font-size:clamp(2rem,4.6vw,3rem);line-height:1.12;letter-spacing:-.04em}
      h2{margin:0;font-size:1.18rem}
      p{margin:.45rem 0;color:var(--muted)}
      a{color:var(--link);text-underline-offset:.2em}
      header{margin-bottom:1.2rem}
      nav,.controls,.heading,.check-head{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem .85rem}
      nav,.small{font-size:.875rem;color:var(--muted)}
      .heading{justify-content:space-between}
      .panel,.notice{padding:clamp(.9rem,2vw,1.25rem);margin:0 0 .85rem;background:var(--panel);border:1px solid var(--line);border-radius:.8rem}
      .notice{color:var(--text)}
      .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(7.5rem,1fr));gap:.75rem;margin:.9rem 0}
      .metrics div{border-left:2px solid var(--line);padding-left:.65rem}
      .metrics dt{font-size:.85rem;color:var(--muted)}
      .metrics dd{margin:.1rem 0 0;font-size:1.45rem;font-variant-numeric:tabular-nums;font-weight:750}
      form{margin:0}
      .domain-form label{display:block;font-weight:700;margin-bottom:.35rem}
      .query{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.55rem;max-width:42rem}
      .query input{min-width:0;padding:.5rem .65rem;border:1px solid #684f85;border-radius:.45rem;color:var(--text);background:var(--bg);font:inherit}
      .recon-toolbar{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:0 .85rem}
      .recon-toolbar>.panel,.certificate-form{min-width:0;overflow-wrap:anywhere}
      .pki-host{border-top:1px solid var(--line);margin-top:.85rem;padding-top:.55rem;overflow-wrap:anywhere}
      .connection-rows{display:grid;grid-template-columns:minmax(0,7.5rem) minmax(0,1fr);gap:.28rem .6rem;margin:.65rem 0}
      .connection-rows dt{color:var(--muted)}.connection-rows dd{margin:0;overflow-wrap:anywhere}
      .certificate-form>label{display:block;font-weight:650;margin-top:.75rem}
      .certificate-form textarea{padding:.55rem;width:100%;resize:vertical;background:var(--bg);color:var(--text);border:1px solid #684f85;border-radius:.4rem;font:inherit}
      .certificate-form input[type=file]{max-width:100%}
      .certificate-status{min-height:1.5rem;margin-bottom:.2rem}
      .domain-form .save-option{font-size:.9rem;font-weight:500;margin:.75rem 0 .25rem}
      .save-option input{accent-color:#cba8ff}
      .domain-form .mail-options{margin:.45rem 0 0}
      .mail-options .query{grid-template-columns:minmax(0,1fr);max-width:20rem}
      .recon-results{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.15fr);gap:0 .85rem;overflow-wrap:anywhere}
      .dns-results{margin:0}
      .dns-results>div{display:grid;grid-template-columns:4.2rem minmax(0,1fr);gap:.35rem;border-top:1px solid var(--line);padding:.55rem 0}
      .dns-results dt{font-weight:700}
      .dns-results dd{margin:0}
      .dns-results code{display:block}
      .names{list-style:none;display:flex;flex-wrap:wrap;gap:.3rem .55rem;padding:0;max-height:13rem;overflow:auto}
      .names li{padding:.12rem .38rem;border-radius:.35rem;background:#2e2442}
      @media(max-width:45rem){.recon-results,.recon-toolbar{grid-template-columns:minmax(0,1fr)}}
      @media(max-width:27rem){.query{grid-template-columns:minmax(0,1fr)}}
      button{min-height:2.5rem;padding:.45rem .75rem;border:1px solid #cba8ff;border-radius:.45rem;font:inherit;font-size:.9rem;font-weight:700;cursor:pointer;background:#cba8ff;color:#200d34}
      button:hover{background:#e0c6ff}
      .secondary{background:#2e2442;color:var(--text);border-color:#684f85}
      .secondary:hover{background:#443057}
      :focus-visible{outline:2px solid #f2dbff;outline-offset:3px}
      .status{border:1px solid currentColor;border-radius:1rem;padding:.04rem .5rem;font-size:.75rem;font-weight:750;color:var(--muted)}
      .pass{color:var(--green)} .review{color:var(--warn)} .unknown{color:var(--link)}
      .checks,.rows{list-style:none;padding:0;margin:.65rem 0 0}
      .checks li,.rows li{border-top:1px solid var(--line);padding:.75rem 0;overflow-wrap:anywhere}
      .checks li:last-child,.rows li:last-child{padding-bottom:0}
      details{margin-top:1rem}
      summary{color:var(--link);cursor:pointer;font-size:.9rem;font-weight:650}
      #results,#inbox{scroll-margin-top:.75rem;overflow-wrap:anywhere}
      code{color:var(--link)}
      @media print{
        :root{color-scheme:light;--bg:#fff;--panel:#fff;--line:#d0d5df;--text:#141125;--muted:#373446;--link:#463078;--warn:#7c460a}
        body{background:#fff}main{padding:0}.recon-results{display:block}
        .names{max-height:none;overflow:visible}.names li{background:#fff}
        nav,form{display:none}
      }
    ${theme === "red" ? RED_THEME_CSS : ""}</style></head><body><main>
      <header class="heading">
        <h1>${escapeHtml(title)}</h1>
        <nav aria-label="${theme === "red" ? "Red Team" : "Purple Team"} navigation">${navigation}</nav>
      </header>
      ${content}
    </main>${certificateInspector ? '<script type="module" src="/dist/reconCertificate.js?v=1"></script>' : ""}</body></html>`, { status, headers });
}
