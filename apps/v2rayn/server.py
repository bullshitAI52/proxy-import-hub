"""Small private v2rayN import portal, stdlib only; no public administration API."""
import base64
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

STATE=Path(os.environ.get('V2N_STATE','/var/lib/v2rayn-import/state.json'))
BASE=os.environ['V2N_PUBLIC_URL'].rstrip('/')

def state():
    data=json.loads(STATE.read_text())
    if len(data['token'])<32 or not data['nodes']: raise ValueError('Invalid state')
    return data

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        try:
            data=state()
            parts=urlsplit(self.path).path.strip('/').split('/')
            if len(parts)>2 or not hmac.compare_digest(parts[0],data['token']):
                return self.respond(404,b'Not found','text/plain')
            kind=parts[1] if len(parts)==2 else ''
            raw=('\n'.join(data['nodes'])+'\n').encode()
            if kind=='subscription': return self.respond(200,base64.b64encode(raw),'text/plain')
            if kind=='nodes': return self.respond(200,raw,'text/plain')
            if kind: return self.respond(404,b'Not found','text/plain')
            if not urlsplit(self.path).path.endswith('/'):
                self.send_response(302);self.send_header('Location',BASE+'/'+data['token']+'/');self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer');self.end_headers();return
            return self.respond(200,Path(__file__).with_name('index.html').read_bytes(),'text/html')
        except Exception: return self.respond(503,b'Temporarily unavailable','text/plain')
    def respond(self,code,body,mime):
        self.send_response(code)
        for k,v in {'Content-Type':mime+'; charset=utf-8','Content-Length':str(len(body)),
                    'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
                    'X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body)

if __name__=='__main__':
    state()
    ThreadingHTTPServer(('127.0.0.1',int(os.environ.get('V2N_PORT','8772'))),Handler).serve_forever()
