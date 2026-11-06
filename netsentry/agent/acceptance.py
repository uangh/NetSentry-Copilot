"""一次性验收授权与底层 HTTP 账本；复用 RecoveryEngine，不创建新执行引擎。"""
from copy import deepcopy
from datetime import datetime,timezone
import json,secrets
from pathlib import Path
from .recovery_engine import RecoveryConflict
from .observation_registry import register


def grant_acceptance(engine, iid: str, run_id: str, allowance: int, contract_sha: str) -> None:
    if not 1<=allowance<=8:raise ValueError('invalid_acceptance_allowance')
    state=deepcopy(dict(engine.graph.get_state(engine.config(iid)).values))
    if state.get('review_status')!='failed' or state.get('draft_report'):raise RecoveryConflict('only_failed_checkpoint')
    register(state)
    recovery=state.setdefault('recovery',{})
    if any(g['run_id']==run_id for g in recovery.get('acceptance_grants',[])):raise RecoveryConflict('grant_already_applied')
    history=engine.attempts(iid)
    if any(a['status'] in ('running','interrupted') for a in history):raise RecoveryConflict('unreconciled_attempt')
    used=len(state['gemini']['calls'])
    recovery.setdefault('acceptance_grants',[]).append({'run_id':run_id,'new_allowance':allowance,
        'historical_business_calls':used,'historical_recovery_attempts':len(history),
        'contract_sha256':contract_sha,'granted_at':datetime.now(timezone.utc).isoformat()})
    recovery.update(generation_limit=used+allowance,attempt_limit=len(history)+2)
    engine.graph.update_state(engine.config(iid),state,as_node='failed')


class AcceptanceBudget:
    """请求发送前持久化；不确定结果也占用额度，重启不清零。"""
    def __init__(self,path: Path,limit: int=8) -> None:
        self.path=path;self.limit=limit
        self.records=json.loads(path.read_text(encoding='utf-8'))['attempts'] if path.exists() else []

    def reserve(self,branch: str,model: str,branch_cap: int) -> None:
        if len(self.records)>=self.limit or sum(r['branch']==branch for r in self.records)>=branch_cap:
            raise RuntimeError('acceptance_http_budget_exhausted')
        if any(r['branch']==branch and r['model']!=model for r in self.records):raise RuntimeError('branch_model_changed')
        self.records.append({'sequence':len(self.records)+1,'branch':branch,'model':model,
            'started_at':datetime.now(timezone.utc).isoformat(),'outcome':'reserved_before_send'})
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.write_text(json.dumps({'limit':self.limit,'attempts':self.records},indent=2),encoding='utf-8')


def backup_allowed(conditions: dict) -> bool:
    return all(conditions.get(k) is True for k in ('structured_outputs','official_free_standard_text',
        'project_free_tier_confirmed','project_access'))


def retry_delay(failure: dict,remaining: float) -> float | None:
    if failure.get('http_status',503)!=503:return None
    delay=failure.get('retry_after_seconds')
    if delay is None:delay=4+secrets.randbelow(2001)/1000
    return float(delay) if 0<=delay<=30 and delay<remaining else None


def acceptance_levels(state: dict,browser_verified: bool=False) -> dict:
    trace=state.get('decision_trace',[]);attempts=state.get('planning_attempts',[])
    first=next((d for d in trace if d['iteration']==1),{})
    second=next((d for d in trace if d['iteration']==2),{})
    accepted=any(a.get('round_number')==2 and a.get('status')=='contract_validated' for a in attempts)
    planning_calls=[c for c in state.get('gemini',{}).get('calls',[]) if c.get('purpose')=='multistep_planning']
    received=accepted or any(a.get('round_number')==2 and any(h.get('status')==200 for h in c.get('http_attempts',[])) for a,c in zip(attempts,planning_calls))
    early=second.get('tool_selected')=='stop' and second.get('actual_execution_status')=='stopped_without_external_call'
    return {'initial_planning_accepted':bool(first),'first_tool_executed':first.get('actual_execution_status')=='executed',
        'observation_feedback_sent':any(a.get('round_number')==2 and bool(a.get('latest_tool_observation_id')) for a in attempts),
        'second_planning_response_received':bool(received),'second_planning_accepted':accepted,
        'second_tool_executed':second.get('actual_execution_status')=='executed','valid_early_stop':early,
        'report_validated':bool(state.get('gemini',{}).get('report_validated')),
        'pending_review':state.get('review_status')=='pending_review','browser_replay_verified':browser_verified}
