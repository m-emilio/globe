import React, {useEffect,useRef,useState} from "react";
import {authFetch} from "./pgpAuth";
import {parseReconReport,type ReconReport} from "../reconGraphModel";

export function ReconGlobeOverlay({enabled}:{enabled:boolean}) {
  const [open,setOpen]=useState(false),[query,setQuery]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState(""),[report,setReport]=useState<ReconReport|null>(null),[selected,setSelected]=useState("");
  const controller=useRef<AbortController|null>(null);
  useEffect(()=>{if(!enabled){controller.current?.abort();setOpen(false);setReport(null);setSelected("");setQuery("");setError("");setBusy(false);}return ()=>controller.current?.abort();},[enabled]);
  if(!enabled)return null;
  const run=async()=>{controller.current?.abort();const ac=new AbortController();controller.current=ac;setBusy(true);setError("");setReport(null);setSelected("");
    try{
      const response=await authFetch("/admin/purple-team/recon",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded","accept":"application/json"},body:new URLSearchParams({target:query.trim(),action:"export"}).toString(),signal:ac.signal});
      if(!response.ok)throw new Error(response.status===401||response.status===403?"Administrator session and allowed device required.":"Recon request failed (HTTP "+response.status+").");
      if(!(response.headers.get("content-type")||"").includes("application/json"))throw new Error("Unified recon API is not available on this deployment.");
      const data=parseReconReport(await response.json());if(!ac.signal.aborted){setReport(data);setSelected("target");}
    }catch(e){if(!ac.signal.aborted)setError(e instanceof Error?e.message:"Recon unavailable");}
    finally{if(!ac.signal.aborted)setBusy(false);}
  };
  const nodes=report?.graph.nodes||[],outer=nodes.filter(n=>n.id!=="target");
  const points=new Map(nodes.map((n)=>{if(n.id==="target")return [n.id,{x:180,y:145}] as const;const i=outer.indexOf(n),a=i*2*Math.PI/Math.max(1,outer.length)-Math.PI/2;return [n.id,{x:180+115*Math.cos(a),y:145+100*Math.sin(a)}] as const;}));
  return <aside aria-label="Private infrastructure reconnaissance" style={{position:"absolute",top:12,right:12,zIndex:8,width:open?"min(380px, calc(100vw - 32px))":"auto",maxHeight:"min(75vh, 640px)",overflow:"auto",background:"#160f23",border:"1px solid #594179",borderRadius:12,padding:12,color:"#eee5ff",boxShadow:"0 6px 24px #0008",pointerEvents:"auto"}}>
    <button type="button" onClick={()=>{if(open){controller.current?.abort();setBusy(false);setReport(null);setSelected("");setQuery("");setError("");}setOpen(!open);}} aria-expanded={open}>{open?"Close recon":"Infrastructure recon"}</button>
    {open&&<><p>Logical relationships over the original globe. Node placement is not geographic.</p>
      <form onSubmit={e=>{e.preventDefault();void run();}}><label>Domain / IP / ASN <input value={query} onChange={e=>setQuery(e.target.value)} maxLength={253} required autoComplete="off" style={{width:"100%"}}/></label><button type="submit" disabled={busy}>{busy?"Loading…":"Run public recon"}</button></form>
      {error&&<p role="alert">{error}</p>}
      {report&&<><p>{report.target.value} · {report.observedAt}</p><svg viewBox="0 0 360 290" role="img" aria-label="Logical infrastructure relationship overlay" style={{width:"100%",background:"#0d0a14",borderRadius:8}}>
        {report.graph.edges.map((e,i)=>{const a=points.get(e.from),b=points.get(e.to);return a&&b?<line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={selected===e.from||selected===e.to?"#e2b9ff":"#74628a"} strokeWidth={1.5}/>:null;})}
        {nodes.map(n=>{const p=points.get(n.id);return p?<g key={n.id} role="button" tabIndex={0} aria-label={n.label} onClick={()=>setSelected(n.id)} onKeyDown={e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();setSelected(n.id);}}}><title>{n.label}</title><circle cx={p.x} cy={p.y} r={n.id==="target"?13:8} fill={selected===n.id?"#e4bcff":"#847bd8"}/><text x={p.x} y={p.y+20} fill="#eee5ff" textAnchor="middle" fontSize="8">{n.label.slice(0,22)}</text></g>:null;})}
      </svg><label>Relationship evidence <select value={selected} onChange={e=>setSelected(e.target.value)} style={{maxWidth:"100%"}}>{nodes.map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select></label>
      <ul>{report.graph.edges.filter(e=>e.from===selected||e.to===selected).map((e,i)=><li key={i}>{nodes.find(n=>n.id===e.from)?.label} — {e.relationship} — {nodes.find(n=>n.id===e.to)?.label}</li>)}</ul>
      <details><summary>Source status</summary>{report.sources?.map((s,i)=><div key={i}>{s.source}: {s.status}</div>)}</details></>}
      <p><a href="/admin/purple-team/recon">Full reconnaissance workspace</a></p><details><summary>Secondary utilities</summary><ul><li><a href="/admin/purple-team">Authorized asset assessments</a></li><li><a href="/admin/purple-team/operations">Incident operations</a></li><li><a href="/admin/purple-team/assessment">Vulnerability intelligence</a></li><li><a href="/admin/purple-team/dependency-audit">Dependency audit</a></li></ul></details></>}
  </aside>;
}
