"""显式恢复失败节点：同一thread、持久化幂等键、累计预算、原观察不重跑。"""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib,json,os,sqlite3,time
from typing import Annotated,Literal
from uuid import uuid4
from pydantic import Field
from langsmith import tracing_context
from netsentry.api.schemas import StrictModel,Identifier
from .registry_engine import RegistryEngine
from .observation_registry import register
from .gemini_adapter import GeminiError,GeminiAdapter
from .engine import BusyError


class RecoveryConflict(ValueError):pass


class ResumeRequest(StrictModel):
    request_id: Identifier
    expected_checkpoint: Annotated[str,Field(min_length=1,max_length=80)]
    max_retries: Literal[0,1]=0
    backoff_seconds: Annotated[int,Field(ge=1,le=30)]=5


def failure_info(state: dict) -> dict:
    stop=state.get('stop_reason');calls=state.get('gemini',{}).get('calls',[])
    call=calls[-1] if calls else {};http=call.get('http_status')
    stage='report' if stop in ('gemini_report_failed','report_validation_failed') else 'planning'
    if stop in ('multistep_tool_failed','tool_unavailable_or_invalid'):
        return {'source':'tool_execution','stage':'execute_tool','code':stop,'http_status':None,'recoverable':False}
    if http in (400,403,429,503,504) and call.get('status')!='validated':
        code={400:'invalid_request',403:'access_denied',429:'quota_or_rate_limit',503:'provider_unavailable',504:'gateway_timeout'}[http]
        return {'source':'provider','stage':stage,'code':code,'http_status':http,'recoverable':http in (429,503,504)}
    if call.get('status')=='timeout':return {'source':'provider','stage':stage,'code':'timeout','http_status':None,'recoverable':True}
    return {'source':'report_contract' if stage=='report' else 'planning_contract','stage':stage,
            'code':state.get('multistep',{}).get('rejection_reason') or stop,'http_status':http,'recoverable':False}


class RecoveryEngine(RegistryEngine):
    def __init__(self,*args,recovery_enabled: bool | None=None,**kwargs):
        self.recovery_enabled=(os.environ.get('NETSENTRY_ENABLE_RECOVERY')=='1') if recovery_enabled is None else recovery_enabled
        self.resume_clock=None;self.resume_prior_seconds=0.;self.attempt_id=None
        super().__init__(*args,**kwargs)
        # LangGraph在后台线程提交checkpoint，账本必须独立连接，不能共享事务。
        db=self.connection.execute('PRAGMA database_list').fetchone()[2]
        self.ledger=sqlite3.connect(db,check_same_thread=False,timeout=5,isolation_level=None)
        self.ledger.executescript('''CREATE TABLE IF NOT EXISTS recovery_runs(
          iid TEXT NOT NULL,request_id TEXT NOT NULL,payload_sha TEXT NOT NULL,attempt_id TEXT NOT NULL,
          status TEXT NOT NULL,started_at TEXT NOT NULL,finished_at TEXT,stage TEXT NOT NULL,
          reserved_requests INTEGER NOT NULL DEFAULT 0,events TEXT NOT NULL DEFAULT '[]',
          PRIMARY KEY(iid,request_id));
          CREATE UNIQUE INDEX IF NOT EXISTS recovery_single_running ON recovery_runs(iid) WHERE status='running';''')

    def close(self) -> None:
        self.ledger.close();super().close()

    def attempts(self,iid: str) -> list[dict]:
        rows=self.ledger.execute('SELECT request_id,attempt_id,status,started_at,finished_at,stage,reserved_requests,events FROM recovery_runs WHERE iid=? ORDER BY started_at',(iid,)).fetchall()
        return [dict(zip(('request_id','attempt_id','status','started_at','finished_at','stage','reserved_requests','request_events'),r[:-1]+(json.loads(r[-1]),))) for r in rows]

    def recovery_status(self,state: dict,checkpoint_id: str) -> dict:
        calls=state.get('gemini',{}).get('calls',[]);history=self.attempts(state['investigation_id']);failure=failure_info(state)
        used=state.get('recovery',{}).get('active_seconds_used',state.get('gemini',{}).get('duration_ms',0)/1000)
        cap=state.get('recovery',{}).get('generation_limit',state.get('gemini',{}).get('request_limit',4)+2)
        remaining=max(0,state['limits']['total_seconds']-used)
        blocked=any(a['status'] in ('running','interrupted') for a in history)
        eligible=bool(state['mode']=='gemini_multistep' and state.get('observation_registry') and state['review_status']=='failed'
                      and failure['recoverable'] and not state.get('draft_report') and len(calls)<cap
                      and remaining>0 and len(history)<state.get('recovery',{}).get('attempt_limit',2) and not blocked)
        completed='execute_tool' if any(d['actual_execution_status']=='executed' for d in state.get('decision_trace',[])) else 'validate_context'
        if failure['stage']=='report':completed='retrieve_knowledge'
        if state.get('draft_report'):completed='validate_report'
        return {'checkpoint_id':checkpoint_id,'eligible':eligible,'can_resume':eligible and self.recovery_enabled,
            'read_only':not self.recovery_enabled,'failure':failure if state['review_status']=='failed' else None,
            'last_completed_step':completed,'saved_observations':len(state.get('observation_registry',[])),
            'attempts':history,'calls_used':len(calls),'generation_limit':cap,'retry_allowance':2,
            'active_seconds_used':used,'active_seconds_remaining':remaining,
            'known_total_tokens':sum(c.get('total_tokens') or 0 for c in calls),
            'unknown_usage_requests':sum(c.get('total_tokens') is None for c in calls),
            'interrupted_requires_reconciliation':blocked}

    def status(self,iid: str) -> dict:
        result=super().status(iid);snapshot=self.graph.get_state(self.config(iid));state=dict(snapshot.values)
        if state['mode']=='gemini_multistep':
            result['recovery']=self.recovery_status(state,snapshot.config['configurable']['checkpoint_id'])
            # 历史原件保留；只读展示纠正旧版把503统称validation_error的文案。
            projected=deepcopy(result.get('planning_attempts',[]))
            planning_calls=[c for c in state['gemini']['calls'] if c['purpose']=='multistep_planning']
            for attempt,call in zip(projected,planning_calls):
                if call.get('http_status') in (400,403,429,503,504) and call['status']!='validated':
                    attempt.pop('validation_error',None);attempt['status']='provider_failed'
                    attempt['provider_failure']={'http_status':call['http_status'],'code':call['status']}
            result['planning_attempts']=projected
        return result

    def sync(self,state: dict) -> None:
        super().sync(state)
        if self.resume_clock is not None:
            seconds=self.resume_prior_seconds+time.monotonic()-self.resume_clock
            state['recovery']['active_seconds_used']=seconds
            state['gemini']['duration_ms']=round(seconds*1000,2)

    def can_plan(self,state: dict) -> bool:
        # 显式验收额度内预留一次报告调用，不重置历史计数或原有逻辑轮数。
        if state.get('recovery',{}).get('acceptance_grants') and self.active:
            if len(self.active.calls)>=self.active.max_requests-1:return False
        return super().can_plan(state)

    def node_retrieve_knowledge(self,state: dict) -> dict:
        # 固定知识查询已有成功结果时复用；明确选择知识工具仍由原执行器处理。
        if self.resume_clock is not None and state['knowledge_references'] and not state['pending_actions']:
            return state
        return super().node_retrieve_knowledge(state)

    def node_plan_investigation(self,state: dict) -> dict:
        state=super().node_plan_investigation(state)
        if state['mode']=='gemini_multistep' and state.get('planning_attempts'):
            attempt=state['planning_attempts'][-1];attempt['attempt_id']=self.attempt_id
            if state['decision_trace'] and state['decision_trace'][-1]['iteration']==state['plan_iterations']:
                state['decision_trace'][-1]['attempt_id']=self.attempt_id
            if state['gemini']['status']=='failed':
                failure=failure_info(state);attempt['failure']=failure
                if failure['source']=='provider':
                    attempt.pop('validation_error',None);attempt['status']='provider_failed'
        return state

    def _wrap_requests(self,iid: str,attempt_id: str) -> None:
        """调用前持久化reservation。进程中断后禁止盲目重发未确定结果的请求。"""
        busy=False
        for name in ('generate','narrate'):
            original=getattr(self.active,name)
            def wrapped(*args,_original=original,**kwargs):
                nonlocal busy
                if busy:return _original(*args,**kwargs)
                if len(self.active.calls)>=self.active.max_requests:raise GeminiError('generation_budget_exhausted')
                busy=True;started=datetime.now(timezone.utc).isoformat();before=len(self.active.calls)
                self.ledger.execute('UPDATE recovery_runs SET reserved_requests=reserved_requests+1 WHERE attempt_id=?',(attempt_id,));self.ledger.commit()
                try:return _original(*args,**kwargs)
                finally:
                    events=json.loads(self.ledger.execute('SELECT events FROM recovery_runs WHERE attempt_id=?',(attempt_id,)).fetchone()[0])
                    events.append({'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
                                   'new_calls':deepcopy(self.active.calls[before:]),'result_known':len(self.active.calls)>before})
                    self.ledger.execute('UPDATE recovery_runs SET events=? WHERE attempt_id=?',(json.dumps(events),attempt_id));self.ledger.commit();busy=False
            setattr(self.active,name,wrapped)

    def resume_failed_investigation(self,iid: str,request: ResumeRequest) -> dict:
        if not self.lock.acquire(timeout=.1):raise BusyError('investigation_busy')
        try:
            result=self._resume_once(iid,request)
            if request.max_retries and result['recovery']['can_resume'] and result['recovery']['failure']['http_status']==503:
                # 一个显式授权的退避重试；不在SDK里隐藏，不对429/504自动重试。
                retry_id=hashlib.sha256((request.request_id+':retry').encode()).hexdigest()[:32]
                existing=any(a['request_id']==retry_id for a in result['recovery']['attempts'])
                if not existing:
                    time.sleep(request.backoff_seconds)
                    return self._resume_once(iid,ResumeRequest(request_id=retry_id,expected_checkpoint=result['recovery']['checkpoint_id']))
            return result
        finally:self.lock.release()

    def _resume_once(self,iid: str,request: ResumeRequest) -> dict:
        current=self.status(iid);payload_sha=hashlib.sha256(request.model_dump_json().encode()).hexdigest()
        if not current.get('recovery'):raise RecoveryConflict('mode_does_not_support_recovery')
        previous=self.ledger.execute('SELECT payload_sha FROM recovery_runs WHERE iid=? AND request_id=?',(iid,request.request_id)).fetchone()
        if previous:
            if previous[0]!=payload_sha:raise RecoveryConflict('idempotency_payload_conflict')
            return current
        info=current['recovery']
        if not info['can_resume'] or request.expected_checkpoint!=info['checkpoint_id']:raise RecoveryConflict('not_resumable_or_stale')
        state=deepcopy(dict(self.graph.get_state(self.config(iid)).values));register(state)
        stage=info['failure']['stage'];attempt_id=uuid4().hex
        try:
            self.ledger.execute('BEGIN IMMEDIATE')
            self.ledger.execute('INSERT INTO recovery_runs(iid,request_id,payload_sha,attempt_id,status,started_at,stage) VALUES(?,?,?,?,?,?,?)',
                (iid,request.request_id,payload_sha,attempt_id,'running',datetime.now(timezone.utc).isoformat(),stage))
            latest=self.ledger.execute("SELECT MAX(checkpoint_id) FROM checkpoints WHERE thread_id=? AND checkpoint_ns=''",(iid,)).fetchone()[0]
            if latest!=request.expected_checkpoint:
                self.ledger.rollback();raise RecoveryConflict('stale_checkpoint_after_claim')
            self.ledger.commit()
        except sqlite3.IntegrityError:
            self.ledger.rollback();raise RecoveryConflict('recovery_already_running') from None
        self.attempt_id=attempt_id;outcome='interrupted'
        try:
            # 恢复生产调查固定到checkpoint模型；测试工厂仍执行既有模型一致性检查。
            self.active=GeminiAdapter(model=state['gemini']['model']) if self.adapter_factory is GeminiAdapter else self.adapter_factory()
            if self.adapter_factory is GeminiAdapter:self.active.connection['config_source']='checkpoint'
            self.provider_status=self.active.probe()
            if not self.provider_status['ready'] or self.active.model!=state['gemini']['model']:raise GeminiError('provider_not_ready_or_model_changed')
            self.active.calls=deepcopy(state['gemini']['calls']);self.active.max_requests=info['generation_limit']
            self.active.connection['generation_verified']=any(c['status']=='validated' for c in self.active.calls)
            self._wrap_requests(iid,attempt_id)
            self.resume_prior_seconds=info['active_seconds_used'];self.resume_clock=time.monotonic()
            recovery=state.setdefault('recovery',{})
            recovery.update(generation_limit=info['generation_limit'],active_seconds_used=self.resume_prior_seconds)
            recovery.setdefault('failure_history',[]).append({'attempt_id':attempt_id,'failure':info['failure'],
                'checkpoint_id':info['checkpoint_id'],'prior_call_count':len(self.active.calls)})
            state['deadline']=time.time()+info['active_seconds_remaining'];state['gemini']['request_limit']=info['generation_limit']
            state['gemini']['status']='running';state['gemini'].pop('failure',None);state['gemini'].pop('active_step',None)
            state['review_status']='running';state['stop_reason']=None;state['pending_actions']=[]
            if stage=='planning':state['plan_iterations']-=1  # 同一失败逻辑轮，HTTP尝试仍累计。
            elif state['decision_trace']:
                last=state['decision_trace'][-1]
                state['stop_reason']=last['decision_to_continue_or_stop'] if last['tool_selected']=='stop' else 'planning_budget_exhausted'
            with tracing_context(enabled=False):
                self.graph.update_state(self.config(iid),state,as_node='validate_context' if stage=='planning' else 'retrieve_knowledge')
                self.graph.invoke(None,self.config(iid))
            outcome='completed' if self.status(iid)['review_status']=='pending_review' else 'failed'
        except GeminiError as exc:
            outcome='provider_preflight_failed'
            self.ledger.execute('UPDATE recovery_runs SET events=? WHERE attempt_id=?',(json.dumps([{
                'stage':'provider_preflight','code':str(exc),'http_status':self.provider_status.get('http_status'),
                'generation_sent':False}]),attempt_id));self.ledger.commit()
            raise
        finally:
            self.ledger.execute('UPDATE recovery_runs SET status=?,finished_at=? WHERE attempt_id=?',(outcome,datetime.now(timezone.utc).isoformat(),attempt_id));self.ledger.commit()
            if self.active:self.active.close()
            self.active=None;self.resume_clock=None;self.attempt_id=None
        return self.status(iid)
