"""Export explicit existing VMess TLS inbounds. Read-only access to x-ui."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import uuid

def nodes_from_db(db,ids,host,sni,client_index=0):
    result=[]
    with sqlite3.connect(Path(db).resolve().as_uri()+'?mode=ro',uri=True) as con:
        for ident in ids:
            row=con.execute('SELECT port,protocol,enable,settings,stream_settings FROM inbounds WHERE id=?',(ident,)).fetchone()
            if not row or row[1]!='vmess' or not row[2]: raise ValueError(f'Inbound {ident} must be enabled VMess')
            port,_,_,settings,stream=row; settings=json.loads(settings);stream=json.loads(stream)
            net=stream.get('network','tcp')
            if net not in ('tcp','ws') or stream.get('security')!='tls': raise ValueError('Only TCP/WS TLS is supported')
            clients=settings.get('clients',[])
            if not 0<=client_index<len(clients): raise ValueError('Invalid client index')
            client=clients[client_index]
            uuid.UUID(client['id'])
            ws=stream.get('wsSettings',{})
            node={'v':'2','ps':f'My-VPS-{net}-{port}','add':host,'port':str(port),'id':client['id'],
                  'aid':str(client.get('alterId',0)),'scy':'auto','net':net,'type':'none','tls':'tls','sni':sni,
                  'host':ws.get('headers',{}).get('Host',''),'path':ws.get('path','') if net=='ws' else ''}
            result.append('vmess://'+base64.b64encode(json.dumps(node).encode()).decode())
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',default='/etc/x-ui/x-ui.db');p.add_argument('--ids',required=True)
    p.add_argument('--host',required=True);p.add_argument('--sni',required=True)
    p.add_argument('--output',default='/var/lib/v2rayn-import/state.json')
    p.add_argument('--client-index',type=int,default=0)
    p.add_argument('--update',action='store_true',help='Keep token and update nodes')
    p.add_argument('--rotate-token',action='store_true',help='Revoke old portal and subscription URLs')
    a=p.parse_args();os.umask(0o077)
    ids=[int(x) for x in a.ids.split(',')]
    if not ids or len(set(ids))!=len(ids):raise SystemExit('Provide unique inbound IDs')
    nodes=nodes_from_db(a.db,ids,a.host,a.sni,a.client_index)
    target=Path(a.output)
    if target.exists() and not (a.update or a.rotate_token):raise SystemExit('Existing state preserved; use --update or --rotate-token explicitly')
    old=json.loads(target.read_text()) if target.exists() else {}
    token=old.get('token') if old and not a.rotate_token else secrets.token_urlsafe(32)
    target.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=target.parent)
    with os.fdopen(fd,'w') as f:json.dump({'token':token,'nodes':nodes},f)
    if target.exists(): os.chown(tmp,target.stat().st_uid,target.stat().st_gid)
    os.replace(tmp,target)
    print('Exported',len(nodes),'nodes. No x-ui configuration was changed. Protect the state file.')
