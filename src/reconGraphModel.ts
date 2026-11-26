// Authenticated, read-only adapter for the deployed recon JSON contract.
// The caller supplies the existing server-side admin gate and rate limit.
export type ReconNode = { id: string; label: string; type: string };
export type ReconEdge = { from: string; to: string; relationship: string };
export type ReconReport = {
  target: {kind: string; value: string};
  observedAt: string;
  graph: {nodes: ReconNode[]; edges: ReconEdge[]};
  sources?: {source:string;status:string}[];
};
export function parseReconReport(value: unknown): ReconReport {
  if (!value || typeof value !== "object") throw new Error("Invalid recon response");
  const x = value as Partial<ReconReport>;
  if (!x.target || typeof x.target.value !== "string" || typeof x.target.kind !== "string" ||
    typeof x.observedAt !== "string" || !x.graph || !Array.isArray(x.graph.nodes) || !Array.isArray(x.graph.edges)) {
    throw new Error("Recon response does not contain a relationship graph");
  }
  const nodes = x.graph.nodes.slice(0,24).filter(n => n && typeof n.id === "string" && typeof n.label === "string" && typeof n.type === "string");
  const ids = new Set(nodes.map(n=>n.id));
  const edges = x.graph.edges.slice(0,80).filter(e=>e && ids.has(e.from) && ids.has(e.to) && typeof e.relationship === "string");
  if (!nodes.length) throw new Error("No relationship nodes returned");
  return {target:x.target,observedAt:x.observedAt,graph:{nodes,edges},sources:Array.isArray(x.sources)?x.sources.slice(0,60).filter(s=>s&&typeof s.source==="string"&&typeof s.status==="string"):[]};
}
