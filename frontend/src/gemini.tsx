import {useState} from 'react';
import {useNavigate} from 'react-router-dom';
import {useMutation,useQuery} from '@tanstack/react-query';
import {api,ApiError} from './api';
import type {GeminiExecution,InvestigationMode} from './types';
import {Badge,ErrorBox,Notice,Panel} from './ui';

export function ModeSelector({mode,onChange}:{mode:InvestigationMode;onChange:(mode:InvestigationMode)=>void}) {
 const provider=useQuery({queryKey:['gemini-provider'],queryFn:api.gemini,retry:false,staleTime:30000});
 return <div className="mode-selector"><label>调查模式<select aria-label="调查模式" value={mode} onChange={e=>onChange(e.target.value as InvestigationMode)}><option value="offline">Deterministic Offline</option><option value="gemini_llm" disabled={!provider.data?.ready}>Gemini LLM Agent</option><option value="gemini_multistep" disabled={!provider.data?.ready}>Gemini Evidence-driven Multi-step</option><option value="enhanced_deterministic_baseline">Enhanced Deterministic Baseline</option></select></label><p className="muted">Provider: Google Gemini · {provider.data?.model||provider.data?.requested_model||'未选择模型'} · 配置来源：{provider.data?.config_source||'历史/测试配置'} · {provider.data?.status||'连接状态未知'} {provider.isPending?'（正在读取后端连接状态）':provider.data?.ready?'（目录可访问；实际生成仍受配额限制）':'（Gemini 当前不可用）'}</p>{provider.error&&<ErrorBox error={provider.error}/>}</div>
}

export function WorkspaceMode({alertId}:{alertId:string}) {
 const [mode,setMode]=useState<InvestigationMode>('offline');const nav=useNavigate();
 const start=useMutation({mutationFn:async()=>{
   const list=await api.investigations(alertId);if(list.truncated)throw new ApiError(0,'调查列表受限，请先人工核对。');
   const existing=list.records.find(i=>i.reasoning_mode===(mode==='offline'?'deterministic_offline':mode));
   return existing?.investigation_id||(await api.start(alertId,mode)).investigation_id;
 },onSuccess:iid=>nav('/investigations/'+iid)});
 return <Panel title="同一告警的调查模式"><ModeSelector mode={mode} onChange={setMode}/><button disabled={start.isPending} onClick={()=>start.mutate()}>{start.isPending?'执行中…':'打开或启动所选模式'}</button>{start.error&&<ErrorBox error={start.error}/>}</Panel>
}

const reasons:Record<string,string>={inspect_candidate_relations:'检查候选关联',compare_endpoint_activity:'比较端点活动',avoid_redundant_queries:'避免重复查询',insufficient_metadata:'元数据不足',budget_or_sufficient_context:'已有上下文或预算足以停止'};
export function GeminiTelemetry({execution:g}:{execution:GeminiExecution}) {
 const total=g.calls.reduce((sum,c)=>sum+(c.total_tokens||0),0);const failed=g.calls[g.calls.length-1];
 return <Panel title="Gemini 实际执行"><div className="report-meta"><Badge>Google Gemini</Badge><code>{g.model}</code><Badge tone={g.status==='completed'?'green':'red'}>{g.status}</Badge></div><p>{g.generation_verified?'已完成真实生成请求':'尚未验证生成成功'} · {g.calls.length} / {g.request_limit||3} 次请求 · {total} 已知 Tokens{g.calls.some(c=>c.total_tokens===null)?'（存在未返回用量，实际总量未知）':''} · {(g.duration_ms/1000).toFixed(2)} 秒</p>{g.failure&&<Notice>失败：{g.failure}{failed?.http_status?` · HTTP ${failed.http_status}`:''} · {failed?.status==='quota_or_rate_limit'?'配额或速率受限':failed?.status==='gateway_timeout'||failed?.status==='timeout'?'模型调用超时':failed?.status==='provider_unavailable'?'模型服务暂时不可用':failed?.status==='validated'?'本地契约校验失败':failed?.status||'本地校验失败'}；未生成替代的离线报告；如有恢复，实际尝试记录见下方。</Notice>}<p><strong>{g.verification_status||'NOT_VERIFIED'}</strong>{g.live_provider_verified===false?' · 未确认真实Provider成功':''}</p>{g.verification_status==='PARTIALLY_VERIFIED'&&<Notice>仅部分步骤通过：已保存规划与工具结果，尚不能宣称完整调查成功。</Notice>}<p>报告引用校验：{g.report_validated?'通过':'未通过或尚未完成'}</p><p>已选择：{g.decisions.flatMap(d=>d.actions.map(a=>String(a.tool))).join(' → ')||'尚无已验证动作'}</p><details><summary>展开规划、用量明细与节点耗时（执行后回放）</summary>{g.decisions.map((d,i)=><div key={i} className="tool-call"><strong>规划 {d.iteration} · {reasons[d.reason]||d.reason}</strong><pre>{JSON.stringify(d.actions,null,2)}</pre></div>)}{g.step_timings?.map((t,i)=><p key={i}>{t.step} · {t.duration_ms.toFixed(1)} ms</p>)}{g.calls.map(c=><p key={c.request_number}>请求 {c.request_number} · {c.purpose} · {c.status} · {c.duration_ms} ms · 输入 {c.input_tokens??'未知'} / 输出 {c.output_tokens??'未知'} / 总计 {c.total_tokens??'未知'} · HTTP尝试 {c.http_attempt_count??'未观测'} {c.http_status?`· HTTP ${c.http_status}`:''} {c.provider_message||''}</p>)}</details><p className="muted">以上为持久化执行后的回放，非实时流式进度。模型返回有限决策与调用统计，不是隐藏思维链。报告采用受约束的事实引用与段落组织。</p></Panel>
}
