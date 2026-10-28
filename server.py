"""Unified private share portal. Separate state and deployment from both originals."""
import base64
import importlib.util
import json
import re
import secrets
import time
import hashlib
from contextlib import contextmanager
import client_formats
from subscription_input import detect
from compatibility import inspect
from resource_limits import CACHE,LIMITER
from subscription_groups import resolve
from pathlib import Path
from urllib.parse import quote
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, JSONResponse
spec=importlib.util.spec_from_file_location('surge_core',Path(__file__).parent/'apps/surge/server.py')
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
app.middleware('http')(core.privacy)
SUPPORTED={'ss','ssr','vmess','vless','trojan','hysteria2','hy2','tuic'}

@app.middleware('http')
async def limits(request,call_next):
    allowed=LIMITER.allow('global',240)
    if allowed and request.method=='POST':allowed=LIMITER.allow('writes',20)
    if not allowed:return JSONResponse({'detail':'请求过于频繁，请等待一分钟再试'},status_code=429,
        headers={'Retry-After':'60','Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    return await call_next(request)

@contextmanager
def db():
    with core.db() as con:
        con.execute('CREATE TABLE IF NOT EXISTS share_meta (id TEXT PRIMARY KEY, expires_at INTEGER)')
        yield con

def active(key):
    with db() as con:
        row=con.execute('SELECT s.secret,m.expires_at FROM subs s LEFT JOIN share_meta m ON s.id=m.id WHERE s.id=?',(key,)).fetchone()
    if not row:
        CACHE.drop(key)
        raise HTTPException(404,'分享已撤销或不存在')
    if row[1] is not None and time.time()>=row[1]:
        CACHE.drop(key)
        raise HTTPException(410,'分享已到期，请联系分享者')
    return row

def normalize(data):
    return detect(data)['text']

def resolve_input(data,root_url=None):
    return resolve(data,core.fetch,core.validate_url,root_url=root_url)

def read_input(value):
    if value.startswith('https://'):
        core.validate_url(value)
        key=('input',hashlib.sha256(value.encode()).hexdigest())
        cached=CACHE.get(key)
        if cached is not None:return json.loads(cached)
        info=resolve_input(core.fetch(value),root_url=value)
        CACHE.put(key,json.dumps(info))
        return info
    return resolve_input(value.encode())

@app.post('/api/check')
async def check(request:Request):
    core.auth(request)
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>core.MAX:raise HTTPException(413,'内容过大')
    try:value=json.loads(body)['source'].strip()
    except Exception:raise HTTPException(400,'请填写源链接')
    import asyncio
    def run():
        if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
        try:
            info=read_input(value)
            return {k:v for k,v in info.items() if k!='text'}|{'compatibility':inspect(info['text'])}
        except ValueError as e:raise HTTPException(400,str(e))
        except HTTPException:raise
        except Exception:raise HTTPException(502,'读取订阅失败，请检查源链接')
        finally:core.LOCK.release()
    return await asyncio.to_thread(run)

def source(key):
    row=active(key)
    cached=CACHE.get((key,'source'))
    if cached is not None:return cached
    value=core.CRYPT.decrypt(row[0]).decode()
    try:
        if value.startswith('inline:'):text=normalize(base64.b64decode(value[7:]))
        elif value.startswith('group:'):text=resolve_input(base64.b64decode(value[6:]))['text']
        else:text=resolve_input(core.fetch(value),root_url=value)['text']
    except Exception:raise HTTPException(502,'无法读取源订阅，请检查链接、格式或有效期')
    active(key)
    CACHE.put((key,'source'),text)
    return text

@app.get('/')
def home():return HTMLResponse(Path(__file__).with_name('index.html').read_text())

@app.get('/api/shares')
def listing(request:Request):
    core.auth(request)
    with db() as con:rows=con.execute('SELECT s.id,s.name,m.expires_at FROM subs s LEFT JOIN share_meta m ON s.id=m.id').fetchall()
    return [{'id':k,'name':n,'url':core.BASE+'/share/'+k,'expires_at':e,'expired':e is not None and time.time()>=e} for k,n,e in rows]

@app.post('/api/shares')
async def create(request:Request):
    core.auth(request);body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>core.MAX:raise HTTPException(413,'内容过大')
    try:
        item=json.loads(body);value=item['source'].strip();name=str(item.get('name','我的节点'))[:80]
        days=item.get('expires_days',0)
        if type(days) is not int or days not in {0,7,30}:raise ValueError()
    except Exception:raise HTTPException(400,'请填写源链接')
    import asyncio
    def save():
        if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
        try:
            with core.db() as con:
                if con.execute('SELECT count(*) FROM subs').fetchone()[0]>=20:raise HTTPException(400,'最多20个分享')
            if value.startswith('https://'):
                info=read_input(value);stored=value
            else:
                info=read_input(value)
                stored=('group:'+base64.b64encode(value.encode()).decode()) if info.get('providers') else ('inline:'+base64.b64encode(info['text'].encode()).decode())
            key=secrets.token_urlsafe(32)
            expiry=int(time.time())+days*86400 if days else None
            with db() as con:
                con.execute('INSERT INTO subs VALUES (?,?,?)',(key,name,core.CRYPT.encrypt(stored.encode())))
                con.execute('INSERT INTO share_meta VALUES (?,?)',(key,expiry))
            return {'url':core.BASE+'/share/'+key,'count':info['count'],'format':info['format'],'warnings':info['warnings'],'compatibility':inspect(info['text']),'expires_at':expiry,'qr_url':core.BASE+'/qr/'+key+'.svg'}
        except HTTPException:raise
        except ValueError as e:raise HTTPException(400,str(e))
        except Exception:raise HTTPException(502,'无法获取源链接；未记录私密内容')
        finally:core.LOCK.release()
    return await asyncio.to_thread(save)

@app.delete('/api/shares/{key}')
def revoke(key:str,request:Request):
    core.auth(request)
    with db() as con:
        con.execute('DELETE FROM subs WHERE id=?',(key,))
        con.execute('DELETE FROM share_meta WHERE id=?',(key,))
    core.CACHE.pop(key,None)
    CACHE.drop(key)
    return {'ok':True}

@app.get('/feed/{key}/{platform}.conf')
def surge(key:str,platform:str):
    if platform not in {'mac','ios'}:raise HTTPException(404)
    if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
    try:
        text=source(key)
        cachekey=(key,'surge',platform,hashlib.sha256(text.encode()).hexdigest())
        result=CACHE.get(cachekey)
        try:
            if result is None:
                result=core.profile(core.convert(text.encode()),key,platform)
                CACHE.put(cachekey,result)
        except Exception:raise HTTPException(502,'没有兼容节点或转换失败，请保留原配置并检查转换引擎')
        active(key)
        return PlainTextResponse(result)
    finally:core.LOCK.release()

@app.get('/raw/{key}')
def raw(key:str):
    if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
    try:
        result=base64.b64encode(source(key).encode()).decode()
        active(key)
        return PlainTextResponse(result)
    finally:core.LOCK.release()

@app.get('/converted/{key}/{target}')
def converted(key:str,target:str):
    if target not in {'quanx','clash'}:raise HTTPException(404)
    if not core.LOCK.acquire(blocking=False):raise HTTPException(429,'请稍后重试')
    try:
        text=source(key)
        cachekey=(key,target,hashlib.sha256(text.encode()).hexdigest())
        result=CACHE.get(cachekey)
        try:
            if result is None:
                result=client_formats.convert(core,text,target)
                CACHE.put(cachekey,result)
        except Exception:raise HTTPException(502,'转换失败或没有兼容节点，请保留原配置；请管理员检查转换引擎和协议支持')
        active(key)
        return PlainTextResponse(result,media_type='application/yaml' if target=='clash' else 'text/plain')
    finally:core.LOCK.release()

@app.get('/share/{key}')
def share(key:str):
    row=active(key)
    template=Path(__file__).with_name('share.html').read_text()
    raw_url=core.BASE+'/raw/'+key
    qx_url=core.BASE+'/converted/'+key+'/quanx'
    clash_url=core.BASE+'/converted/'+key+'/clash'
    import html
    expiry=time.strftime('%Y-%m-%d %H:%M UTC',time.gmtime(row[1])) if row[1] else '永久（撤销前有效）'
    template=template.replace('<h1>', '<p>有效期：'+expiry+'。到期不能再读取订阅，但不会停用已下载的节点账号。</p><h1>',1)
    values={
        'MAC_URL':core.links(key)['mac'],'IOS_URL':core.links(key)['ios'],
        'MAC':'surgeconfig:///install-config?url='+quote(core.links(key)['mac'],safe=''),
        'IOS':'surge:///install-config?url='+quote(core.links(key)['ios'],safe=''),
        'ROCKET':'shadowrocket://add/'+raw_url,
        'RAW':raw_url,
        'QX_URL':qx_url,'CLASH_URL':clash_url,
        'QX':'quantumult-x:///add-resource?remote-resource='+quote(json.dumps({'server_remote':[qx_url+', tag=Proxy-Import-Hub']},separators=(',',':')),safe=''),
        'CLASH':'clash://install-config?url='+quote(clash_url,safe='')}
    for name,value in values.items():template=template.replace('{{'+name+'}}',html.escape(value,quote=True))
    return HTMLResponse(template)

@app.get('/qr/{key}.svg')
def qr(key:str):
    active(key)
    import io
    import qrcode
    import qrcode.image.svg
    result=CACHE.get((key,'qr'))
    if result is None:
        image=qrcode.make(core.BASE+'/share/'+key,image_factory=qrcode.image.svg.SvgPathImage,border=4)
        output=io.BytesIO();image.save(output)
        result=output.getvalue();CACHE.put((key,'qr'),result)
    active(key)
    return Response(result,media_type='image/svg+xml')
