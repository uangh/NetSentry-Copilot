import type {Investigation} from './types';
import {Panel,Notice,Badge} from './ui';

export interface DecisionRound {
 observation_ids_used?:string[];new_observation_ids?:string[];model_name?:string;request_duration_ms?:number;known_total_tokens?:number|null;tool_http_trace_id?:string|null;
 iteration:number;investigation_goal:string;tool_selected:string;tool_arguments:Record<string,unknown>;
 question:string;reason:string;expected_information:string;observations_before:Record<string,unknown>[];
 new_observations_after:Record<string,unknown>|null;evidence_references:string[];missing_evidence:string[];
 remaining_budget:Record<string,number>;decision_to_continue_or_stop:string;actual_execution_status:string;
 new_record_ids:string[];result_observation_id?:string;decision_source:string;
}
const names:Record<string,string>={summarize_host_behavior:'主机行为摘要',analyze_port_distribution:'端口分布',
 analyze_temporal_bursts:'采样 Flow 记录密度',build_flow_timeline:'可追溯 Flow 时间线',expand_evidence_page:'Evidence 分页覆盖',
 query_host_flows:'主机流记录',query_related_evidence:'候选关联',search_security_knowledge:'本地知识参考',stop:'停止调查'};

export function ToolResultCard({round:d,fullResult}:{round:DecisionRound;fullResult?:Record<string,unknown>}) {
 const result=d.new_observations_after;if(!result)return <p>没有新增工具结果 · {d.actual_execution_status}</p>;
 const stats=(result.statistics||{}) as Record<string,unknown>;
 const entries=Object.entries(stats).filter(([,v])=>typeof v!=='object');
 return <div className="tool-result-card"><h4>{names[d.tool_selected]||d.tool_selected}</h4>
 <p>命中 {String(result.total??'不适用')} · 实际统计 {String(result.analyzed_count??'不适用')} · 本页加载 {String(result.loaded??0)}</p>
 <p>新增唯一记录 <strong>{d.new_record_ids.length}</strong>（不等于信息增益或独立攻击证据）</p>
 {entries.map(([k,v])=><span className="analysis-stat" key={k}>{k}: <strong>{String(v)}</strong> </span>)}
 {['top_ports','buckets','timeline'].map(key=>Array.isArray(stats[key])&&<div key={key}><h4>{key}</h4><ul>{(stats[key] as Record<string,unknown>[]).map((row,i)=><li key={i}>{Object.entries(row).map(([k,v])=>`${k}: ${String(v)}`).join(' · ')}</li>)}</ul><small>此处是有界摘要；完整结果见对应 HTTP 观察。</small></div>)}
 {!!result.has_more&&<Notice>仍有未加载记录，不能视为已逐条调查。</Notice>}
 <details><summary>来源、记录身份与技术详情</summary><p>来源 SHA256: {String(result.source_sha256||'见原工具轨迹')}</p><p>观察 ID: {d.result_observation_id||'本地知识'}</p><pre>{JSON.stringify({result:fullResult||result,arguments:d.tool_arguments,new_record_ids:d.new_record_ids},null,2)}</pre></details></div>
}

export function DecisionTimeline({state:s}:{state:Investigation}) {
 if(!s.multistep)return null;
 return <Panel title="Investigation Decision Timeline"><p>持久化决策回放 · {s.multistep.baseline?'增强确定性规则基线':'Gemini 多轮调查'} · 非实时流式过程</p>
 <p>规划 {s.planning_iterations} / {s.multistep.planning_limit||3} · M3 {s.external_calls_used} / 8 · 停止原因：{s.stop_reason||'尚未停止'}</p>
 <Notice>以下理由是模型或规则的行动说明，不是已验证的攻击事实。统计仅覆盖公开抽样记录。</Notice>
 {(s.decision_trace||[]).map(d=><section className="decision-round" key={d.iteration}>
 <h3>Round {d.iteration} · {d.question}</h3><Badge>{d.investigation_goal}</Badge> <code>{d.tool_selected}</code>
 <p>选择理由：{d.reason}</p><p>预期观察：{d.expected_information}</p>
 <p>依据：{d.evidence_references.length?`${d.evidence_references.length} 个已返回观察`:'初始告警与锚点'}</p>
 {d.observation_ids_used&&<p>本轮合法观察引用：{d.observation_ids_used.join(' · ')}<br/>新增观察：{d.new_observation_ids?.join(' · ')||'无'} · 模型 {d.model_name} · {d.known_total_tokens??'未知'} Tokens · {d.request_duration_ms??'未知'} ms</p>}
 <p>决定：{d.decision_to_continue_or_stop} · 执行：{d.actual_execution_status}</p>
 <ToolResultCard round={d} fullResult={s.analysis_results?.find(o=>o.call_id===d.result_observation_id)?.result}/><p>仍缺少：{d.missing_evidence.join('；')||'见报告边界'}</p>
 <details><summary>查看上一轮观察与决策依赖</summary><pre>{JSON.stringify({observations_before:d.observations_before,references:d.evidence_references,remaining_budget:d.remaining_budget},null,2)}</pre></details>
 </section>)}{s.observation_registry&&<details><summary>观察引用注册表与真实来源映射</summary><pre>{JSON.stringify(s.observation_registry,null,2)}</pre></details>}{s.planning_attempts?.some(p=>p.validation_error)&&<Notice>规划校验未通过：{s.planning_attempts.filter(p=>p.validation_error).map(p=>p.validation_error?.code).join('；')}。未以规则动作代替。</Notice>}{!s.decision_trace?.length&&<p>没有可用规划轨迹，请查看元数据限制或失败原因。</p>}</Panel>
}
