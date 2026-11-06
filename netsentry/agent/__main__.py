"""CLI真实调查：连接已启动M3，默认OFFLINE，持久化等待审核。"""
import argparse
import json
import os
from pathlib import Path

from .engine import InvestigationEngine
from .tools import M3Tools


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--alert-id',required=True)
    parser.add_argument('--mode',choices=['offline','llm_agent'],default='offline')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[2]
    engine=InvestigationEngine(root/'outputs/m4/checkpoints.sqlite',M3Tools(os.environ.get('NETSENTRY_M3_URL','http://127.0.0.1:8000')))
    try:print(json.dumps(engine.start(args.alert_id,args.mode),ensure_ascii=False,indent=2))
    finally:engine.close()


if __name__=='__main__':main()
