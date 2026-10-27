"""Import your own node text file, encrypted at rest. Never alters a proxy server."""
import argparse
import base64
import os
import secrets
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('file',help='Private local file containing node URIs or a supported subscription')
p.add_argument('--name',required=True)
a=p.parse_args()
os.umask(0o077)
os.environ.update(dict(l.split('=',1) for l in Path('/etc/private-sub.env').read_text().splitlines() if '=' in l))
import server
with open(a.file,'rb') as f: raw=f.read(server.MAX+1)
if len(raw)>server.MAX: raise SystemExit('Input too large')
lines=server.convert(raw)
key=secrets.token_urlsafe(32)
with server.db() as con:
    if con.execute('SELECT 1 FROM subs WHERE name=?',(a.name,)).fetchone(): raise SystemExit('Name already exists; unchanged')
    con.execute('INSERT INTO subs VALUES (?,?,?)',(key,a.name,server.CRYPT.encrypt(b'inline:'+base64.b64encode(raw))))
print('Imported',len(lines),'nodes. Sign into the portal for links; test actual connectivity in Surge.')
