import {useState} from 'react';
import type {EvidenceView,Flow,Report} from './types';
import {Badge,CopyValue,FlowView,Panel,StateBadge} from './ui';

export function evidenceSummary(view:EvidenceView){
 const flows=[...view.records.map(e=>e.flow),...(view.queried_flows||[]).map(r=>r.flow)];
 const unique=new Map(flows.map(f=>[f.record_id,f]));
 const exact=new Set(view.records.filter(e=>e.association_status==='exact_record').map(e=>e.related_record_id));
 if(view.anchor&&unique.has(view.anchor.record_id))exact.add(view.anchor.record_id);
 const queries=new Map<string,typeof view.pages[number]>();
 for(const p of view.pages){const {limit,offset,...scope}=p.parameters;void limit;void offset;queries.set(JSON.stringify([p.tool,scope]),p)}
 return {loaded:flows.length,unique:unique.size,exact:exact.size,candidate:unique.size-exact.size,
   sources:new Set(flows.map(f=>f.source_sha256)).size,queries:[...queries.values()],hasMore:view.pages.some(p=>p.has_more)};
}
function delta(anchor:Flow|null,flow:Flow){
 if(!anchor?.timestamp||!flow.timestamp)return '时间差未知';
 // Both source times share an unverified local wall-clock basis; Z is used only for arithmetic.
 const ms=Date.parse(flow.timestamp+'Z')-Date.parse(anchor.timestamp+'Z');
 return Number.isFinite(ms)?`${ms>=0?'+':''}${(ms/1000).toFixed(3)} 秒（源时间差）`:'时间差未知';
}
function FlowCard({flow,anchor,reason,status,reference}:{flow:Flow;anchor:Flow|null;reason:string;status:string;reference?:string}){
 const shared=[...new Set([anchor?.source_ip,anchor?.destination_ip].filter(ip=>ip&&[flow.source_ip,flow.destination_ip].includes(ip)))];
 return <article className="evidence-card"><div className="context-line"><strong>{flow.source_ip||'源IP缺失'}:{flow.source_port??'?'} → {flow.destination_ip||'目标IP缺失'}:{flow.destination_port??'?'}</strong><StateBadge value={status}/></div><p>协议 {flow.protocol===6?'TCP':flow.protocol===17?'UDP':flow.protocol??'未知'} · {flow.timestamp||'时间缺失'} · {delta(anchor,flow)}</p><p>{reason}</p><p className="muted">共享端点：{shared.join('、')||'无可核验端点'} · 源时间时区未验证</p><details><summary>记录标识与来源详情</summary><FlowView flow={flow}/>{reference&&<CopyValue value={reference}/>}</details></article>
}
export function EvidencePanel({view,report}:{view:EvidenceView;report?:Report|null}){
 const knowledge=view.knowledge_references??report?.knowledge_references??[];const s=evidenceSummary(view);const [all,setAll]=useState(false);const rows=new Map<string,{flow:Flow;reason:string;status:string;reference?:string}>();
 for(const e of view.records)rows.set(e.related_record_id,{flow:e.flow,reason:e.match_reason,status:e.association_status,reference:e.evidence_id});
 for(const r of view.queried_flows||[])if(!rows.has(r.flow.record_id))rows.set(r.flow.record_id,{flow:r.flow,reason:'来自受控主机Flow查询；关联仍需人工复核',status:r.flow.record_id===view.anchor?.record_id?'exact_record':'candidate_unverified'});
 const list=[...rows.values()];
 return <Panel title="Evidence 覆盖与记录"><div className="mini-stats">{[[s.loaded,'加载记录出现次数'],[s.unique,'唯一证据记录'],[s.exact,'确定性记录'],[s.candidate,'未确认候选'],[s.sources,'不同源文件'],[report?.evidence_references.length??0,'报告引用（非独立记录）']].map(([n,label])=><span key={String(label)}><strong>{n}</strong>{label}</span>)}</div>{s.queries.map((p,i)=><p key={i}>{p.tool}：查询总命中 <strong>{p.total}</strong>；本页加载 {p.returned}；offset {p.offset}。{p.has_more?'尚有分页未加载，未逐条审查。':'本页范围已加载。'}</p>)}{s.queries.length>1&&<p className="muted">不同查询可能重叠，命中数不相加；唯一记录按record_id去重。</p>}<p>RAG：{knowledge.length} 个知识chunk，来自 {new Set(knowledge.map(k=>k.document_id)).size} 份原始知识文档；知识不计入网络证据记录。</p>{list.slice(0,all?list.length:5).map(r=><FlowCard key={r.flow.record_id} {...r} anchor={view.anchor}/>)}{list.length>5&&<button onClick={()=>setAll(!all)}>{all?'收起已加载记录':`展开其余 ${list.length-5} 条已加载记录`}</button>}{!list.length&&<p>本次没有加载证据记录。</p>}<details><summary>全部原始Evidence ID及查询页审计</summary><pre>{JSON.stringify({pages:view.pages,evidence_ids:view.records.map(e=>e.evidence_id)},null,2)}</pre></details></Panel>
}
export function ReportOverview({report,onSource}:{report:Report;onSource:(id:string)=>void}){
 const chosen=report.observed_facts.filter(f=>['source_ip','destination_ip','query_total_including_anchor','host_query_total'].includes(f.field)).slice(0,4);
 return <Panel title="调查结论与复核建议" action={<Badge tone="amber">证据不足</Badge>}><h3>证据不足以确认攻击，等待人工复核</h3><p>{report.model_id} · {report.model_status} · {report.reasoning_mode}；分数未校准。</p><ul>{chosen.map(f=><li key={f.fact_id}>{f.field}：{f.value??'缺失'} <button className="text-button" onClick={()=>onSource(f.reference_id)}>查看来源 ↗</button></li>)}</ul><p>重要缺失：{report.missing_evidence.join('；')}</p><p>下一步：{report.recommended_next_steps[0]}</p></Panel>
}
