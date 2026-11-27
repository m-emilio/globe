import { escapeHtml } from "./purpleTeamTools";

type PurpleTeamPage = {
  title: string;
  navigation: string;
  content: string;
  status?: number;
};

export function purpleTeamPage(
  { title, navigation, content, status = 200 }: PurpleTeamPage,
  applySecurityHeaders: (headers: Headers) => void,
): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
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
      @media(max-width:45rem){.recon-results{grid-template-columns:minmax(0,1fr)}}
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
    </style></head><body><main>
      <header class="heading">
        <h1>${escapeHtml(title)}</h1>
        <nav aria-label="Purple Team navigation">${navigation}</nav>
      </header>
      ${content}
    </main></body></html>`, { status, headers });
}
