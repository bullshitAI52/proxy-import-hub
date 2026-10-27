"""Unified private share portal. Separate state and deployment from both originals."""
import base64
import importlib.util
import json
import re
import secrets
import client_formats
from pathlib import Path
from urllib.parse import quote
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
spec=importlib.util.spec_from_file_location('surge_core',Path(__file__).parent/'apps/surge/server.py')
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
app.middleware('http')(core.privacy)
SUPPORTED={'ss','ssr','vmess','vless','trojan','hysteria2','hy2','tuic'}

def normalize(data):
    text=data.decode('utf-8-sig').strip()
    if not re.match(r'^[a-z0-9]+://',text):
        try:text=base64.b64decode(text+'===',validate=False).decode().strip()
        except Exception:raise ValueError('目前接受节点分享链接或 Base64 节点订阅；不接受 Clash YAML/完整客户端配置')
    lines=[line.strip() for line in text.splitlines() if line.strip()]
    if not lines or len(lines)>1000:raise ValueError('节点为空或超过1000条')
    for line in lines:
        if line.split('://',1)[0] not in SUPPORTED or '://' not in line or any(c.isspace() for c in line):
            raise ValueError('包含无效节点行或不支持的源格式')
    return '\n'.join(lines)+'\n'

def source(key):
    with core.db() as con:row=con.execute('SELECT secret FROM subs WHERE id=?',(key,)).fetchone()
    if not row:raise HTTPException(404,'分享已撤销或不存在')
    value=core.CRYPT.decrypt(row[0]).decode()
    try:
        return normalize(base64.b64decode(value[7:]) if value.startswith('inline:') else core.fetch(value))
    except Exception:raise HTTPException(502,'无法读取源订阅，请检查链接、格式或有效期')

@app.get('/')
def home():return HTMLResponse(Path(__file__).with_name('index.html').read_text())

@app.get('/api/shares')
def listing(request:Request):
    core.auth(request)
    with core.db() as con:rows=con.execute('SELECT id,name FROM subs').fetchall()
    return [{'id':k,'name':n,'url':core.BASE+'/share/'+k} for k,n in rows]

@app.post('/api/shares')
async def create(request:Request):
    core.auth(request);body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>core.MAX:raise HTTPException(413,'内容过大')
    try:
        item=json.loads(body);value=item['source'].strip();name=str(item.get('name','我的节点'))[:80]
    except Exception:raise HTTPException(400,'请填写源链接')
    import asyncio
    def save():
        if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
        try:
            with core.db() as con:
                if con.execute('SELECT count(*) FROM subs').fetchone()[0]>=20:raise HTTPException(400,'最多20个分享')
            if value.startswith('https://'):
                core.validate_url(value);raw=normalize(core.fetch(value));stored=value
            else:
                raw=normalize(value.encode());stored='inline:'+base64.b64encode(raw.encode()).decode()
            key=secrets.token_urlsafe(32)
            with core.db() as con:con.execute('INSERT INTO subs VALUES (?,?,?)',(key,name,core.CRYPT.encrypt(stored.encode())))
            return {'url':core.BASE+'/share/'+key,'count':len(raw.splitlines())}
        except HTTPException:raise
        except ValueError as e:raise HTTPException(400,str(e))
        except Exception:raise HTTPException(502,'无法获取源链接；未记录私密内容')
        finally:core.LOCK.release()
    return await asyncio.to_thread(save)

@app.delete('/api/shares/{key}')
def revoke(key:str,request:Request):return core.delete(key,request)

@app.get('/feed/{key}/{platform}.conf')
def surge(key:str,platform:str):return core.feed(key,platform)

@app.get('/raw/{key}')
def raw(key:str):
    if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
    try:return PlainTextResponse(base64.b64encode(source(key).encode()).decode())
    finally:core.LOCK.release()

@app.get('/converted/{key}/{target}')
def converted(key:str,target:str):
    if target not in {'quanx','clash'}:raise HTTPException(404)
    if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
    try:
        text=source(key)
        try:result=client_formats.convert(core,text,target)
        except Exception:raise HTTPException(502,'转换失败或没有兼容节点，请保留原配置；请管理员检查转换引擎和协议支持')
        return PlainTextResponse(result,media_type='application/yaml' if target=='clash' else 'text/plain')
    finally:core.LOCK.release()

@app.get('/share/{key}')
def share(key:str):
    with core.db() as con:row=con.execute('SELECT id FROM subs WHERE id=?',(key,)).fetchone()
    if not row:raise HTTPException(404,'分享已撤销')
    template=Path(__file__).with_name('share.html').read_text()
    template=template.replace('</main>',Path(__file__).with_name('extra_clients.html').read_text()+'</main>')
    raw_url=core.BASE+'/raw/'+key
    qx_url=core.BASE+'/converted/'+key+'/quanx'
    clash_url=core.BASE+'/converted/'+key+'/clash'
    import html
    values={
        'MAC':'surgeconfig:///install-config?url='+quote(core.links(key)['mac'],safe=''),
        'IOS':'surge:///install-config?url='+quote(core.links(key)['ios'],safe=''),
        'ROCKET':'shadowrocket://add/'+raw_url,
        'RAW':raw_url,
        'QX_URL':qx_url,'CLASH_URL':clash_url,
        'QX':'quantumult-x:///add-resource?remote-resource='+quote(json.dumps({'server_remote':[qx_url+', tag=Proxy-Import-Hub']},separators=(',',':')),safe=''),
        'CLASH':'clash://install-config?url='+quote(clash_url,safe='')}
    for name,value in values.items():template=template.replace('{{'+name+'}}',html.escape(value,quote=True))
    return HTMLResponse(template)
