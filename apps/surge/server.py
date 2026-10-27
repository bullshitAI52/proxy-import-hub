"""Private subscription gateway. Never expose the conversion engine publicly."""
import hashlib
import base64
from contextlib import contextmanager
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, urljoin, quote

import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

STATE = Path(os.environ.get('SUB_STATE', '/var/lib/proxy-import-hub'))
INPUT = Path('/opt/proxy-import-hub/engine/input')
BASE = os.environ['SUB_PUBLIC_URL'].rstrip('/')
DENIED_IPS = set(os.environ.get('SUB_DENIED_IPS', '').split(','))
ADMIN = os.environ['SUB_ADMIN_KEY']
CRYPT = Fernet(os.environ['SUB_ENCRYPTION_KEY'].encode())
MAX = 2 * 1024 * 1024
LOCK = threading.Lock()
CACHE = {}
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@contextmanager
def db():
    con = sqlite3.connect(STATE/'subscriptions.db')
    con.execute('CREATE TABLE IF NOT EXISTS subs (id TEXT PRIMARY KEY, name TEXT, secret BLOB)')
    try:
        with con:
            yield con
    finally:
        con.close()

def auth(request):
    value = request.headers.get('Authorization', '')
    if not hmac.compare_digest(value, 'Bearer '+ADMIN):
        raise HTTPException(401, '访问密钥不正确')

def validate_url(url):
    p = urlsplit(url)
    if (len(url)>4096 or p.scheme!='https' or not p.hostname or p.username or p.password
            or p.port not in (None,443) or p.fragment or any(ord(c)<33 for c in url)):
        raise ValueError('仅接受 HTTPS 订阅网址（443 端口），不接受本地文件或内网地址')
    return p

def public_addresses(host):
    addresses = list(dict.fromkeys(r[4][0] for r in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(a).is_global or a in DENIED_IPS for a in addresses):
        raise ValueError('禁止访问内网、保留地址或本站服务器')
    return addresses

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, timeout=20, context=ssl.create_default_context())
        self.address=address
    def connect(self):
        sock=socket.create_connection((self.address,443),timeout=self.timeout)
        self.sock=self._context.wrap_socket(sock,server_hostname=self.host)

def fetch(url):
    for _ in range(4):
        p=validate_url(url)
        conn=PinnedHTTPS(p.hostname,public_addresses(p.hostname)[0])
        try:
            conn.request('GET',p.path+('?' + p.query if p.query else '') or '/',headers={
                'User-Agent':'Surge/5.0 PrivateSubscription', 'Accept-Encoding':'identity'})
            res=conn.getresponse()
            if res.status in (301,302,303,307,308):
                url=urljoin(url,res.getheader('Location',''));continue
            if res.status!=200: raise ValueError('订阅服务商返回错误，请检查链接是否有效')
            data=res.read(MAX+1)
            if len(data)>MAX: raise ValueError('订阅超过 2 MB，已拒绝')
            if not data.strip(): raise ValueError('订阅为空')
            return data
        finally: conn.close()
    raise ValueError('订阅跳转次数过多')

def convert(data):
    # Only the trusted gateway creates file paths. The engine cannot access the Internet.
    try:
        decoded=base64.b64decode(data+b'===').decode('utf-8')
    except Exception:
        decoded=data.decode('utf-8',errors='replace')
    if data.strip().startswith(b'vless://'): decoded=data.decode('utf-8',errors='replace')
    protocols=re.findall(r'(?m)^([a-z0-9-]+)://',decoded)
    if protocols and set(protocols)=={'vless'}:
        raise ValueError(f'此订阅只有 {len(protocols)} 个 VLESS 节点，当前 Surge 转换不支持；请向服务商获取 Trojan、Shadowsocks 或 VMess 等兼容订阅。')
    if re.match(rb'^(ss|ssr|vmess|trojan|vless|hysteria2|hy2|tuic)://',data.strip()):
        data=base64.b64encode(data)
    fd,name=tempfile.mkstemp(prefix='input-',dir=INPUT)
    try:
        with os.fdopen(fd,'wb') as out: out.write(data)
        with httpx.Client(timeout=30,trust_env=False) as client:
            r=client.get('http://127.0.0.1:25502/sub',params={
                'target':'surge','ver':'4','url':'input/'+Path(name).name,'list':'true','insert':'false',
                'emoji':'false','append_info':'false','udp':'true'})
        if r.status_code!=200 or len(r.content)>MAX: raise ValueError('转换引擎无法读取该订阅')
        lines=[]
        for line in r.text.splitlines():
            line=line.strip()
            if not line or line.startswith(('#',';','[')): continue
            if '=' not in line or ',' not in line: raise ValueError('转换结果格式异常')
            label,config=line.split('=',1)
            kind=config.split(',',1)[0].strip()
            if kind not in {'ss','vmess','trojan','http','https','socks5','socks5-tls','snell','tuic','tuic-v5','hysteria2'}:
                raise ValueError('转换结果包含不支持的协议')
            # Assign safe names to prevent source names injecting groups or rules.
            safe=re.sub(r'[\x00-\x1f\x7f,=\[\]#;"\\]', '_', label).strip()[:80]
            lines.append(f'N{len(lines)+1:03d} {safe} = {config.strip()}')
        if not lines: raise ValueError('没有可转换的 Surge 节点；可能是 VLESS/Reality 等不兼容协议')
        return lines
    finally: Path(name).unlink(missing_ok=True)

def links(key):
    return {platform:f'{BASE}/feed/{key}/{platform}.conf' for platform in ('mac','ios')}

def profile(lines,key,platform):
    names=[line.split('=',1)[0].strip() for line in lines]
    return (f'#!MANAGED-CONFIG {links(key)[platform]} interval=86400 strict=false\n'
        f'# Private subscription — Surge {platform}\n'
        '# Compatible common subset. Unsupported source nodes may be omitted.\n'
        '[General]\nloglevel = notify\n\n[Proxy]\n'+'\n'.join(lines)+
        '\n\n[Proxy Group]\nProxy = select, '+', '.join(names)+', DIRECT\n\n[Rule]\n'
        'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n'
        'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve\nIP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n'
        'FINAL,Proxy\n')

@app.middleware('http')
async def privacy(request,call_next):
    try: response=await call_next(request)
    except Exception: return PlainTextResponse('服务暂时不可用，请稍后重试',status_code=503)
    response.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
        'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
        'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"})
    return response

@app.get('/')
def home(): return HTMLResponse(Path(__file__).with_name('index.html').read_text())

@app.get('/api/subscriptions')
def listing(request:Request):
    auth(request)
    with db() as con: rows=con.execute('SELECT id,name FROM subs').fetchall()
    return [{'id':key,'name':name,'links':links(key)} for key,name in rows]

@app.post('/api/subscriptions')
async def create(request:Request):
    auth(request)
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>8192: raise HTTPException(413,'请求过大')
    try:
        item=json.loads(body); url=item['url'].strip(); name=item.get('name','我的订阅').strip()[:80]
        validate_url(url)
    except Exception: raise HTTPException(400,'请填写有效 HTTPS 订阅网址')
    import asyncio
    return await asyncio.to_thread(create_sync,url,name)

def create_sync(url,name):
    if not LOCK.acquire(blocking=False): raise HTTPException(429,'正在转换，请稍后重试')
    try:
        with db() as con:
            if con.execute('SELECT count(*) FROM subs').fetchone()[0]>=20: raise HTTPException(400,'最多保存20个订阅')
        lines=convert(fetch(url)); key=secrets.token_urlsafe(32)
        with db() as con: con.execute('INSERT INTO subs VALUES (?,?,?)',(key,name,CRYPT.encrypt(url.encode())))
        CACHE[key]=(time.time(),lines)
        return {'id':key,'name':name,'links':links(key),'count':len(lines),
                'warning':'只输出引擎支持的 Surge 节点，其他协议可能被省略。节点名称已编号；不保证每个节点可连接。'}
    except HTTPException: raise
    except ValueError as e: raise HTTPException(400,str(e))
    except Exception: raise HTTPException(502,'获取或转换失败，请检查订阅有效期、网络和协议；详细凭据不会记录')
    finally: LOCK.release()

@app.delete('/api/subscriptions/{key}')
def delete(key:str,request:Request):
    auth(request)
    with db() as con: con.execute('DELETE FROM subs WHERE id=?',(key,))
    CACHE.pop(key,None)
    return {'ok':True}

@app.get('/feed/{key}/{platform}.conf')
def feed(key:str,platform:str):
    if platform not in ('mac','ios'): raise HTTPException(404)
    with db() as con: row=con.execute('SELECT secret FROM subs WHERE id=?',(key,)).fetchone()
    if not row: raise HTTPException(404,'订阅不存在或已撤销')
    if not LOCK.acquire(blocking=False): raise HTTPException(429,'请稍后更新')
    try:
        cached=CACHE.get(key)
        if not cached or time.time()-cached[0]>300:
            source=CRYPT.decrypt(row[0]).decode()
            raw=base64.b64decode(source[7:]) if source.startswith('inline:') else fetch(source)
            cached=(time.time(),convert(raw))
            CACHE[key]=cached
        return PlainTextResponse(profile(cached[1],key,platform))
    except Exception: raise HTTPException(502,'上游暂时不可用；请保留已有配置，稍后更新')
    finally: LOCK.release()

@app.get('/install/{key}/{platform}')
def install(key:str,platform:str):
    if platform not in ('mac','ios'): raise HTTPException(404)
    with db() as con: row=con.execute('SELECT id FROM subs WHERE id=?',(key,)).fetchone()
    if not row: raise HTTPException(404,'链接已撤销')
    url=links(key)[platform]
    scheme='surgeconfig' if platform=='mac' else 'surge'
    action=scheme+':///install-config?url='+quote(url,safe='')
    return HTMLResponse('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Surge 配置导入</title><main style="max-width:650px;margin:60px auto;padding:24px;font:18px/1.8 system-ui">'
        '<h1>我的 VPS · '+('Mac' if platform=='mac' else 'iPhone')+'</h1>'
        '<p>先安装 Surge，保留原配置，再点击导入。节点数量及协议以生成的配置为准。</p>'
        '<p><a style="background:#235ca4;color:white;padding:16px;border-radius:12px" href="'+html.escape(action,quote=True)+'">一键导入 Surge</a></p>'
        '<p>若内置浏览器无法唤起，请用 Safari 打开。仍不支持时，在 Surge 配置管理中从 URL 导入下面的地址：</p>'
        '<textarea readonly style="width:100%;height:110px">'+html.escape(url)+'</textarea>'
        '<p>此链接包含访问凭据，请勿转发。默认局域网直连，其余流量走所选节点。节点凭据修改后需要重新生成。</p></main>')
