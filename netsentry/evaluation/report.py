"""Small, denominator-aware comparison artifact builder."""
import json
from pathlib import Path

def comparison(cases: list[dict]) -> dict:
    groups={}
    for item in cases:
        key=item['case_id'];groups.setdefault(key,{})[item['mode']]=item
    return {'scope':'same frozen input per pair; descriptive observations, no human-efficiency or significance claim',
        'pairs':groups,'case_count':len(groups),'report_count':sum(bool(i['metrics']['report_available']) for i in cases)}

def save(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
