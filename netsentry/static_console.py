"""Serve only built public files and known React routes; APIs never fall through to HTML."""
from pathlib import Path
import re
from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse

def mount_console(app: FastAPI,dist: Path) -> None:
    dist=dist.resolve()
    if not (dist/'index.html').is_file():raise FileNotFoundError('Missing frontend build: '+str(dist))
    @app.get('/{public_path:path}',include_in_schema=False)
    def console(public_path: str):
        if public_path.split('/')[0] in ('api','health','docs','redoc','openapi.json'):raise HTTPException(404,'not_found')
        if '\\' in public_path or any(p in ('.','..') or p.startswith('.') for p in public_path.split('/') if p):raise HTTPException(404,'not_found')
        target=(dist/public_path).resolve()
        if not target.is_relative_to(dist):raise HTTPException(404,'not_found')
        if target.is_file():return FileResponse(target)
        if re.fullmatch(r'(?:|data|alerts(?:/[0-9a-f]{32})?|investigations(?:/[0-9a-f]{32}(?:/report)?)?)',public_path):return FileResponse(dist/'index.html')
        raise HTTPException(404,'not_found')
