"""从官方匿名 ZIP 只取一个成员，流式验证并保存确定性子集；不下载整个归档。"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zlib

URL = 'https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-001.zip'
CAP = 200*1024*1024


def fetch_range(start: int, length: int, index: dict, destination: Path) -> dict:
    if not 0 <= start < index['archive_bytes'] or not 0 < length <= CAP or start+length > index['archive_bytes']:
        raise ValueError('非法范围或超过下载预算')
    headers=destination.with_suffix('.headers')
    command=['curl.exe' if os.name=='nt' else 'curl','--disable','--fail','--silent','--show-error',
             '--proto','=https','--max-time','300','--range',f'{start}-{start+length-1}',
             '--header','If-Match: '+index['etag'],'--max-filesize',str(length),
             '--dump-header',str(headers),'--output',str(destination),URL]
    result=subprocess.run(command,capture_output=True,text=True,timeout=310)
    if result.returncode:
        raise ValueError(f'官方范围请求失败: {result.stderr.strip()}')
    text=headers.read_text(encoding='iso-8859-1')
    status=re.findall(r'HTTP/\S+ (\d+)',text)[-1]
    values={k.lower():v.strip() for k,v in re.findall(r'^([^:\r\n]+):\s*([^\r\n]*)',text,re.M)}
    expected=f'bytes {start}-{start+length-1}/{index["archive_bytes"]}'
    if status!='206' or values.get('content-range')!=expected or values.get('etag')!=index['etag'] or destination.stat().st_size!=length:
        raise ValueError('拒绝非精确206响应/对象变化/短下载')
    with destination.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'start':start,'length':length,'sha256':digest,'content_range':expected,'etag':index['etag']}


def save_subset(compressed: Path, target: Path, member: dict, every: int) -> dict:
    """CRC、完整成员 SHA 在解压时计算；仅选中行落盘，父成员不落盘。"""
    decoder=zlib.decompressobj(-15)
    digest=hashlib.sha256()
    crc=total=selected=rows=0
    capture=[]
    started=time.monotonic()
    def lines():
        nonlocal crc,total
        pending=b''
        with compressed.open('rb') as stream:
            while data:=stream.read(65536):
                while data:
                    plain=decoder.decompress(data,65536)
                    data=decoder.unconsumed_tail
                    total+=len(plain)
                    if total>member['uncompressed_bytes'] or total>1536*1024*1024 or time.monotonic()-started>600:
                        raise ValueError('解压大小/时间预算超限')
                    digest.update(plain);crc=zlib.crc32(plain,crc)
                    pending+=plain
                    while b'\n' in pending:
                        line,pending=pending.split(b'\n',1)
                        line+=b'\n'
                        capture.append(line)
                        if sum(map(len,capture))>1024*1024:
                            raise ValueError('CSV单记录超过1MiB')
                        yield line.decode('utf-8')
                    if len(pending)>1024*1024:raise ValueError('CSV单行超过1MiB')
        if pending:
            capture.append(pending)
            yield pending.decode('utf-8')
        if not decoder.eof or decoder.unused_data or total!=member['uncompressed_bytes'] or crc!=member['crc32']:
            raise ValueError('成员长度/CRC/压缩结束校验失败')
    with target.open('xb') as output:
        reader=csv.reader(lines(),strict=True)
        header=next(reader)
        output.write(b''.join(capture));capture.clear()
        for original_row,row in enumerate(reader,2):
            rows+=1
            if len(row)!=len(header):raise ValueError(f'CSV第{original_row}条记录列宽不同')
            if (original_row-2)%every==0:
                output.write(b''.join(capture));selected+=1
                if output.tell()>CAP:raise ValueError('子集超过200MiB')
            capture.clear()
    return {'original_member_rows':rows,'selected_rows':selected,'original_member_sha256':digest.hexdigest(),
            'crc32_verified':True,'method':'systematic_every_nth_record','every':every,'first_original_row_number':2,
            'row_number_definition':'logical CSV record, header=1; multiline record counts once',
            'random_seed':None,'bias':'deterministic systematic sampling may alias periodic traffic and miss rare classes; not a population estimate'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index',type=Path,required=True)
    parser.add_argument('--member',default='CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv')
    parser.add_argument('--every',type=int,default=100)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.index.stat().st_size>1024*1024 or not 1<=args.every<=10000:raise ValueError('索引/步长预算错误')
    index=json.loads(args.index.read_text())
    if index['url']!=URL or not re.fullmatch(r'"[a-zA-Z0-9-]+"',index['etag']):raise ValueError('只接受官方URL和固定ETag')
    member=next(m for m in index['members'] if m['name']==args.member)
    if not re.fullmatch(r'CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week[1-4]\.csv',member['name']):raise ValueError('仅允许指定内部网络流量成员')
    if member['method']!=8 or member['flags']&1 or member['compressed_bytes']+2*1024*1024>CAP or member['uncompressed_bytes']>1536*1024*1024:raise ValueError('不支持加密/格式/成员超过预算')
    if args.out.exists():raise ValueError('不覆盖已存在输出目录')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(args.out.parent).free<2*CAP+16*1024*1024:raise ValueError('磁盘不足')
    with tempfile.TemporaryDirectory(prefix='.cidds-',dir=args.out.parent) as tmp:
        scratch=Path(tmp)
        evidence=[fetch_range(member['header_offset'],30,index,scratch/'header.bin')]
        header=(scratch/'header.bin').read_bytes()
        fields=struct.unpack('<4s5H3I2H',header)
        if fields[0]!=b'PK\x03\x04' or fields[3]!=8:raise ValueError('本地成员标题不符')
        extra_size=fields[-2]+fields[-1]
        evidence.append(fetch_range(member['header_offset']+30,extra_size,index,scratch/'name.bin'))
        name=(scratch/'name.bin').read_bytes()[:fields[-2]].decode('utf-8' if fields[2]&2048 else 'cp437')
        if name!=args.member:raise ValueError('成员名字与目录不符')
        evidence.append(fetch_range(member['header_offset']+30+extra_size,member['compressed_bytes'],index,scratch/'member.deflate'))
        ready=scratch/'ready';ready.mkdir()
        filename=Path(args.member).stem+f'.every{args.every}.csv'
        target=ready/filename
        selection=save_subset(scratch/'member.deflate',target,member,args.every)
        with target.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        manifest={'dataset_id':'CIDDS-001','dataset_version':'official public release; object Last-Modified 2024-11-04',
                  'provenance':'public_dataset','source_url':URL,'original_file':args.member,'file_name':filename,
                  'size_bytes':target.stat().st_size,'sha256':sha,'archive_sha256':None,'archive_size_bytes':index['archive_bytes'],
                  'etag':index['etag'],'retrieved_at_utc':datetime.now(timezone.utc).isoformat(),'selection':selection,
                  'range_requests':evidence,'network_body_bytes_this_run':sum(e['length'] for e in evidence),
                  'prior_archive_index_bytes':index['metadata_bytes_downloaded'],'source_index_sha256':hashlib.sha256(args.index.read_bytes()).hexdigest(),
                  'source_verification':'official HTTPS endpoint; ETag fixed across exact range requests; member length/CRC/full-uncompressed SHA checked; not full archive SHA',
                  'license_url':'https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/',
                  'usage':'cite Ring et al. 2017; public addresses anonymized; labels not independently revalidated'}
        assert manifest['network_body_bytes_this_run']+index['metadata_bytes_downloaded']<CAP
        (ready/'source.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        ready.rename(args.out)
        print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
