export type ToolFinding = {
  check: string;
  status: "pass" | "review" | "unknown";
  evidence: string;
  remediation?: string;
};

export type ToolResult = {
  title: string;
  findings: ToolFinding[];
  runId?: string;
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

export function showChecks(findings: ToolFinding[]): string {
  const labels = { pass: "Pass", review: "Review", unknown: "Unknown" };
  return `<ul class="checks">${findings.map(({ check, status, evidence, remediation }) => {
    const state = status === "pass" || status === "review" ? status : "unknown";
    return `
    <li>
      <div class="check-head"><strong>${escapeHtml(check)}</strong><span class="status ${state}">${labels[state]}</span></div>
      <p>${escapeHtml(evidence)}</p>
      ${remediation ? `<p>${escapeHtml(remediation)}</p>` : ""}
    </li>`;
  }).join("")}</ul>`;
}
