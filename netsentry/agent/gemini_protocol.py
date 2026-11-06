"""Minimal wire contracts; all security limits remain enforced locally."""
from copy import deepcopy
from typing import Annotated, Literal
from pydantic import Field
from netsentry.api.schemas import StrictModel


class ActionArguments(StrictModel):
    endpoint: Literal['source','destination']
    window_seconds: Annotated[int,Field(ge=1,le=60)]
    limit: Annotated[int,Field(ge=1,le=10)]


class InvestigationAction(StrictModel):
    action: Literal['query_related_evidence','query_host_flows','stop']
    arguments: ActionArguments
    reason: Literal['inspect_candidate_relations','compare_endpoint_activity','avoid_redundant_queries',
                    'insufficient_metadata','budget_or_sufficient_context']

    def as_plan(self) -> dict:
        return {'actions':[{'tool':self.action,**self.arguments.model_dump(),'offset':0}],'reason':self.reason}


def wire_schema(schema: type) -> dict:
    """Inline finite references and remove defaults/titles; no weakening of local validation."""
    root=deepcopy(schema.model_json_schema());definitions=root.pop('$defs',{})
    def expand(value):
        if isinstance(value,list):return [expand(v) for v in value]
        if not isinstance(value,dict):return value
        if '$ref' in value:return expand(definitions[value['$ref'].rsplit('/',1)[-1]])
        return {k:expand(v) for k,v in value.items() if k not in ('default','title')}
    return expand(root)


def planning_context(state: dict) -> dict:
    flow=state['anchor_flow']
    return {'model_prediction':state['model_context']|{'predicted_class':state['alert_detail']['alert']['predicted_label'],
                'score_is_calibrated_probability':False},
        'anchor':{k:flow.get(k) for k in ('source_ip','destination_ip','source_port','destination_port','protocol','timestamp')},
        'iteration':state['plan_iterations'],'remaining_http_calls':6-state['calls_used'],
        'summaries':state['summaries'][:4],
        'already_executed':[{'tool':o['tool'],'parameters':o['parameters']} for o in state['observations'][-6:]],
        'available_tools':['query_related_evidence','query_host_flows','stop'],
        'limits':{'max_rows':10,'max_window_seconds':60,'max_planning_turns':state['limits']['max_plans']},
        'rules':'Choose one useful read-only action or stop. Arguments endpoint, window_seconds and limit are required. '
                'Both query tools filter by the selected anchor endpoint IP appearing on either side of a flow. '
                'window_seconds is total span: related evidence uses closed +/- floor(span/2); host query uses half-open +/- span/2. '
                'No authentication evidence. Candidate relationships are unverified.'}


def report_context(state: dict, facts: list[dict]) -> dict:
    # Full evidence remains in SQLite and in the deterministic report validator, not in the LLM prompt.
    selected=facts[:8]+[f for f in facts[8:] if f['field'] in ('total','returned_count','has_more')][:4]
    if len(selected)<12:selected+=facts[len(selected):12]
    selected=list({f['fact_id']:f for f in selected}.values())[:12]
    return {'facts':[{k:f.get(k) for k in ('fact_id','field','value','scope')} for f in selected],
        'omitted_facts':len(facts)-len(selected),'query_summaries':state['summaries'][:4],
        'knowledge':[{'chunk_id':k['chunk_id'],'title':k['title'][:100],'text':k['text'][:240]} for k in state['knowledge_references'][:3]],
        'limitations':[str(x)[:160] for x in state['confidence_limitations'][:4]],
        'missing':[str(x)[:160] for x in state['missing_information'][:4]],
        'rules':'Choose only supplied fact IDs. Omitted observations remain available to the human reviewer. '
                'Knowledge is reference material, not evidence of this attack. Keep insufficient_evidence.'}
