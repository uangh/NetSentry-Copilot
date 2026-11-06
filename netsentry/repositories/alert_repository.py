"""固定SQL、参数绑定、唯一键保证并发检测幂等。"""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from netsentry.api.schemas import Alert, AlertFilters

RULE_VERSION='score_at_least_fixed_threshold.v1'


class AlertRepository:
    def __init__(self, path: Path) -> None:
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        # 已有未知SQLite不能被静默扩展为告警库。
        with closing(self.connect()) as c,c:
            tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables!={'alerts'}:raise ValueError('拒绝覆盖非告警数据库')
            c.execute('''CREATE TABLE IF NOT EXISTS alerts(
                alert_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, model_id TEXT NOT NULL,
                model_version TEXT NOT NULL, rule_version TEXT NOT NULL, alert_status TEXT NOT NULL,
                score REAL NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL,
                UNIQUE(record_id,model_id,model_version,rule_version))''')
            c.execute('CREATE INDEX IF NOT EXISTS alert_score ON alerts(score,alert_id)')
            c.execute('CREATE INDEX IF NOT EXISTS alert_created ON alerts(created_at)')

    def connect(self) -> sqlite3.Connection:
        connection=sqlite3.connect(self.path,timeout=10)
        connection.execute('PRAGMA busy_timeout=10000')
        return connection

    def create(self, prediction: dict, flow: dict) -> tuple[dict,bool]:
        if prediction['prediction']!='attack-related' or prediction['attack_related_score']<prediction['threshold']:
            raise ValueError('未满足候选告警触发规则')
        now=datetime.now(timezone.utc).isoformat(timespec='microseconds')
        alert={'alert_id':uuid4().hex,'record_id':flow['record_id'],'prediction_id':prediction['prediction_id'],
            'predicted_label':prediction['prediction'],'attack_related_score':prediction['attack_related_score'],
            'threshold':prediction['threshold'],'model_id':prediction['model_id'],'model_version':prediction['model_version'],
            'model_status':prediction['prediction_status'],'feature_contract_version':prediction['feature_contract_version'],
            'source_dataset':flow['dataset_id'],'source_sha256':flow['source_sha256'],'alert_status':'candidate',
            'created_at':now,'updated_at':now,'trigger_rule_version':RULE_VERSION}
        alert=Alert.model_validate(alert).model_dump()
        with closing(self.connect()) as c,c:
            cursor=c.execute('''INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_id,model_id,model_version,rule_version) DO NOTHING''',
                (alert['alert_id'],alert['record_id'],alert['model_id'],alert['model_version'],RULE_VERSION,'candidate',
                 alert['attack_related_score'],now,json.dumps(alert,allow_nan=False)))
            created=cursor.rowcount==1
            row=c.execute('SELECT payload FROM alerts WHERE record_id=? AND model_id=? AND model_version=? AND rule_version=?',
                (alert['record_id'],alert['model_id'],alert['model_version'],RULE_VERSION)).fetchone()
        return json.loads(row[0]),created

    def get(self, alert_id: str) -> dict:
        with closing(self.connect()) as c:
            row=c.execute('SELECT payload FROM alerts WHERE alert_id=?',(alert_id,)).fetchone()
        if row is None:raise KeyError('alert not found')
        return json.loads(row[0])

    def list(self, filters: AlertFilters) -> dict:
        clauses=[];params=[]
        for column in ('alert_status','model_id'):
            value=getattr(filters,column)
            if value is not None:clauses.append(column+'=?');params.append(value)
        if filters.start is not None:
            clauses.extend(['created_at>=?','created_at<?'])
            params.extend([filters.start.isoformat(timespec='microseconds'),filters.end.isoformat(timespec='microseconds')])
        where=' WHERE '+' AND '.join(clauses) if clauses else ''
        order={'score_desc':'score DESC,alert_id','score_asc':'score ASC,alert_id','created_desc':'created_at DESC,alert_id'}[filters.sort]
        with closing(self.connect()) as c:
            total=c.execute('SELECT COUNT(*) FROM alerts'+where,params).fetchone()[0]
            rows=c.execute('SELECT payload FROM alerts'+where+' ORDER BY '+order+' LIMIT ? OFFSET ?',
                           (*params,filters.limit,filters.offset)).fetchall()
        return {'alerts':[json.loads(row[0]) for row in rows],'total':total,'limit':filters.limit,
                'offset':filters.offset,'has_more':filters.offset+len(rows)<total}
