"""受限启动器：只绑定127.0.0.1，不接受公网host。"""
import argparse
import logging
import uvicorn

from .main import create_app


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8000)
    args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('端口范围1024..65535')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    uvicorn.run(create_app(),host='127.0.0.1',port=args.port,access_log=False,proxy_headers=False,
                limit_concurrency=32,timeout_keep_alive=5)


if __name__=='__main__':main()
