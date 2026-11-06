"""M1.7 两种用途：事件库只读查询；离线库提供特征和独立训练目标。"""
from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
import json
from pathlib import Path
import sqlite3

from .flow_query import FlowQuery


def local_time(value: str) -> str:
    if not isinstance(value,str) or len(value)>40:raise ValueError('时间须为源文件本地ISO文本')
    try:parsed=datetime.fromisoformat(value)
    except ValueError as exc:raise ValueError('非法ISO时间') from exc
    if parsed.tzinfo is not None:raise ValueError('源时区未核验，不能混入UTC或偏移时间')
    return parsed.isoformat(timespec='microseconds')


class LabeledFlowQuery(FlowQuery):
    """复用M1.6连接生命周期/分页边界，查询有独立schema的无标签事件库。"""
    def __init__(self,database: str | Path):
        self.connection=sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro',uri=True)
        self.connection.execute('PRAGMA query_only=ON')
        self.connection.execute('PRAGMA cache_size=-4096')
        try:
            row=self.connection.execute("SELECT value FROM metadata WHERE name='contract'").fetchone()
            contract=json.loads(row[0])
            if contract.get('schema_version')!='netsentry.labeled.v1' or contract.get('store_kind')!='events_only' or contract.get('labels_present') is not False:
                raise ValueError('不是允许的无标签事件库')
        except (sqlite3.Error,TypeError,ValueError,KeyError) as exc:
            self.close();raise ValueError('拒绝离线标签库或未知数据库') from exc

    def _envelope(self,rule: str) -> dict:
        return {'rule':rule,'association_status':'unverified','time_basis':'source_local_unverified',
                'limitations':['候选相关记录不证明同一次攻击','无认证日志或攻击成功证据','来源详情通过受控离线目录解析']}

    def _page(self,where: str,params: list,*,rule: str,limit: int,offset: int) -> dict:
        self._bounds((0,1),limit,offset)
        # SQL结构只由本类固定方法构造；任何调用者值都使用参数。
        total=self.connection.execute('SELECT COUNT(*) FROM events WHERE '+where,params).fetchone()[0]
        rows=self.connection.execute('SELECT record FROM events WHERE '+where+' ORDER BY timestamp,record_id LIMIT ? OFFSET ?',(*params,limit,offset)).fetchall()
        return {**self._envelope(rule),'records':[json.loads(row[0]) for row in rows],
                'total':total,'limit':limit,'offset':offset,'has_more':offset+len(rows)<total}

    def get_flow_detail(self,record_id: str) -> dict:
        if not isinstance(record_id,str) or len(record_id)>128:raise ValueError('非法record_id')
        row=self.connection.execute('SELECT record FROM events WHERE record_id=?',(record_id,)).fetchone()
        return {**self._envelope('exact internal record_id'),'record':json.loads(row[0]) if row else None}

    def get_flow_provenance(self,record_id: str) -> dict:
        if not isinstance(record_id,str) or len(record_id)>128:raise ValueError('非法record_id')
        row=self.connection.execute('SELECT provenance FROM events WHERE record_id=?',(record_id,)).fetchone()
        return {**self._envelope('exact record_id; opaque source hash + original row reference'),
                'record':json.loads(row[0]) if row else None}

    def _query(self,role: str,address: str,time_range: tuple[str,str],*,limit: int=100,offset: int=0,
               source_port: int | None=None,destination_port: int | None=None) -> dict:
        if not isinstance(address,str) or '%' in address:raise ValueError('需要合法IP，不接受匿名化符号或zone')
        address=str(ipaddress.ip_address(address))
        if not isinstance(time_range,(tuple,list)) or len(time_range)!=2:raise ValueError('需要[start,end)时间范围')
        start,end=map(local_time,time_range)
        if start>=end:raise ValueError('开始时间必须早于结束时间')
        if role=='host':where='(source_ip=? OR destination_ip=?)';params=[address,address]
        elif role in ('source_ip','destination_ip'):where=role+'=?';params=[address]
        else:raise ValueError('非法查询角色')
        where+=' AND timestamp>=? AND timestamp<?';params.extend([start,end])
        for name,value in [('source_port',source_port),('destination_port',destination_port)]:
            if value is not None:
                if type(value) is not int or not 0<=value<=65535:raise ValueError('非法端口')
                where+=' AND '+name+'=?';params.append(value)
        return self._page(where,params,rule=f'exact {role} IP; flow START in [start,end); exact optional ports',limit=limit,offset=offset)

    def query_flows_by_source_ip(self,source_ip: str,time_range: tuple[str,str],**options) -> dict:
        return self._query('source_ip',source_ip,time_range,**options)

    def query_flows_by_destination_ip(self,destination_ip: str,time_range: tuple[str,str],**options) -> dict:
        return self._query('destination_ip',destination_ip,time_range,**options)

    def query_flows_by_host_ip(self,ip: str,time_range: tuple[str,str],**options) -> dict:
        return self._query('host',ip,time_range,**options)

    def query_related_flows(self,record_id: str,time_window: int,*,limit: int=100,offset: int=0) -> dict:
        if type(time_window) is not int or not 0<=time_window<=86400:raise ValueError('窗口须为0..86400整数秒')
        self._bounds((0,1),limit,offset)
        anchor=self.get_flow_detail(record_id)['record']
        rule='share either valid endpoint IP; START within closed anchor +/- window seconds; exclude anchor'
        if anchor is None or anchor['timestamp'] is None:
            return {**self._envelope(rule),'records':[],'total':0,'has_more':False,'anchor_usable':False}
        ips=list(dict.fromkeys(ip for ip in [anchor['source_ip'],anchor['destination_ip']] if ip is not None))
        if not ips:return {**self._envelope(rule),'records':[],'total':0,'has_more':False,'anchor_usable':False}
        stamp=datetime.fromisoformat(anchor['timestamp'])
        try:start=(stamp-timedelta(seconds=time_window)).isoformat(timespec='microseconds');end=(stamp+timedelta(seconds=time_window)).isoformat(timespec='microseconds')
        except OverflowError as exc:raise ValueError('时间窗口超出日期范围') from exc
        placeholders=','.join('?' for _ in ips)
        where=f'record_id<>? AND timestamp>=? AND timestamp<=? AND (source_ip IN ({placeholders}) OR destination_ip IN ({placeholders}))'
        result=self._page(where,[record_id,start,end,*ips,*ips],rule=rule,limit=limit,offset=offset)
        return {**result,'anchor_usable':True,'anchor_record_id':record_id}


class OfflineFlowStore:
    """只供离线开发/监督评测；不注册为Agent工具。"""
    def __init__(self,database: str | Path):
        self.connection=sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro',uri=True)
        self.connection.execute('PRAGMA query_only=ON')
        try:
            row=self.connection.execute("SELECT value FROM metadata WHERE name='report'").fetchone()
            self.report=json.loads(row[0])
            if self.report['schema_version']!='netsentry.labeled.v1':raise ValueError('版本不支持')
        except (sqlite3.Error,ValueError,TypeError,KeyError) as exc:
            self.close();raise ValueError('不是离线流记录库') from exc

    def close(self) -> None:self.connection.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def get_record(self,record_id: str) -> dict | None:
        row=self.connection.execute('SELECT record FROM records WHERE record_id=?',(record_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get_model_view(self,record_id: str) -> dict:
        row=self.connection.execute('SELECT record,model_ready FROM records WHERE record_id=?',(record_id,)).fetchone()
        if row is None:return {'record_id':record_id,'X':None,'eligible':False,'reason':'not_found'}
        record=json.loads(row[0]);eligible=bool(row[1])
        # X是唯一可送入未来估计器的部分；record_id仅用于系统关联，不作为特征。
        ordered={name:record['features'][name] for name in self.report['feature_order']}
        return {'record_id':record_id,'X':ordered if eligible else None,'eligible':eligible,
                'feature_order':self.report['feature_order'],'reason':None if eligible else 'invalid_or_missing_numeric_feature'}

    def get_training_target(self,record_id: str) -> dict:
        row=self.connection.execute('SELECT label FROM records WHERE record_id=?',(record_id,)).fetchone()
        return {'record_id':record_id,'label':row[0] if row else None,'purpose':'offline_supervision_only'}
