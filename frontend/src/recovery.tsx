import {useRef} from 'react';
import {useMutation,useQueryClient} from '@tanstack/react-query';
import {api} from './api';
import type {Investigation} from './types';
import {Panel,Notice,ErrorBox} from './ui';

export interface RecoveryStatus {
 checkpoint_id:string;eligible:boolean;can_resume:boolean;read_only:boolean;
 failure:{source:string;stage:string;code:string;http_status:number|null}|null;
 last_completed_step:string;saved_observations:number;calls_used:number;generation_limit:number;
 known_total_tokens:number;unknown_usage_requests:number;active_seconds_remaining:number;
 interrupted_requires_reconciliation:boolean;
 attempts:{attempt_id:string;request_id:string;status:string;started_at:string;finished_at:string|null;stage:string;reserved_requests:number}[];
}

export function RecoveryPanel({state}:{state:Investigation}) {
 const client=useQueryClient();const cached=useRef<{checkpoint:string;request_id:string}|null>(null);
 const r=state.recovery;
 const resume=useMutation({mutationFn:()=>{
  if(!r?.can_resume)throw Error('当前状态不支持恢复');
  if(cached.current?.checkpoint!==r.checkpoint_id)cached.current={checkpoint:r.checkpoint_id,request_id:crypto.randomUUID().replaceAll('-','')};
  return api.resume(state.investigation_id,{request_id:cached.current.request_id,expected_checkpoint:r.checkpoint_id});
 },onSuccess:async result=>{client.setQueryData(['investigation',state.investigation_id],result);await client.invalidateQueries({queryKey:['investigation-evidence',state.investigation_id]});},onError:()=>{void client.invalidateQueries({queryKey:['investigation',state.investigation_id]})}});
 if(!r)return null;
 return <Panel title="Checkpoint Recovery">
  {r.failure&&<Notice>{r.failure.source==='provider'?'Provider unavailable':r.failure.source} · {r.failure.code} · {r.failure.http_status||'本地错误'} · 失败阶段 {r.failure.stage}</Notice>}
  <p>Last completed step: {r.last_completed_step} · Saved observations: {r.saved_observations}</p>
  <p>Resume attempt number: {r.attempts.length} · Model calls used: {r.calls_used}/{r.generation_limit}</p>
  <p>{r.known_total_tokens} 已知 Tokens · {r.unknown_usage_requests} 次用量未知 · 剩余执行时间 {r.active_seconds_remaining.toFixed(1)} 秒</p>
  {r.eligible&&<button className="primary" disabled={!r.can_resume||resume.isPending} onClick={()=>resume.mutate()}>{resume.isPending?'正在恢复已保存调查…':'Resume Investigation'}</button>}
  {r.read_only&&<p>只读演示：恢复操作不可用。</p>}
  {r.interrupted_requires_reconciliation&&<Notice>存在未确定完成状态的恢复请求，已停止；需核对请求记录后处理，不自动重发。</Notice>}
  {!r.eligible&&!r.read_only&&<p>当前状态不支持继续恢复。</p>}
  {resume.error&&<ErrorBox error={resume.error}/>}
  {r.attempts.map(a=><details key={a.attempt_id}><summary>恢复 {a.attempt_id} · {a.status} · {a.stage}</summary><p>{a.started_at} → {a.finished_at||'尚未结束'} · 请求预留 {a.reserved_requests}</p></details>)}
 </Panel>;
}
