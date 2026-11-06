"""New investigation selection only. Archived investigations keep their saved model."""
import os
DEFAULT_MODEL='gemini-3.1-flash-lite'
APPROVED_MODELS=(DEFAULT_MODEL,'gemini-3.5-flash-lite','gemini-2.5-flash-lite')

def resolve_model(explicit: str | None=None) -> tuple[str,str]:
    if explicit:return explicit,'explicit'
    configured=os.environ.get('NETSENTRY_GEMINI_MODEL','').strip()
    if configured:return configured,'environment:NETSENTRY_GEMINI_MODEL'
    return DEFAULT_MODEL,'default'
