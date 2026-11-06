"""M3+M4同一回环HTTP服务；禁止公网host和自动LLM启用。"""
import argparse
import logging
from pathlib import Path
import uvicorn

from .api import create_app


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--checkpoint',type=Path)
    args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('非法本地端口')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    app=create_app(base_url=f'http://127.0.0.1:{args.port}',checkpoint=args.checkpoint)
    uvicorn.run(app,host='127.0.0.1',port=args.port,access_log=False,proxy_headers=False,limit_concurrency=32)


if __name__=='__main__':main()
