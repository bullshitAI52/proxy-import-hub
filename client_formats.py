"""Convert node lists locally; do not fetch remote configuration templates."""
import base64
import os
import re
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit,parse_qs,unquote
import httpx
import yaml

def vless_clash(line):
    from subscription_input import node_uri
    p=urlsplit(line)
    if p.scheme!='vless' or not p.hostname or not p.port or p.password:raise ValueError('Invalid VLESS')
    params=parse_qs(p.query,keep_blank_values=True)
    allowed={'encryption','type','security','sni','fp','alpn','flow','pbk','sid','path','host'}
    if set(params)-allowed or any(len(v)!=1 for v in params.values()):raise ValueError('Unsupported VLESS parameter')
    q={k:v[0] for k,v in params.items()}
    security=q.get('security','none');network=q.get('type','tcp')
    if security not in {'none','tls','reality'}:raise ValueError('Unsupported security')
    if q.get('encryption','none')!='none':raise ValueError('Unsupported encryption')
    if security!='reality' and any(k in q for k in ('pbk','sid')):raise ValueError('Unexpected Reality parameters')
    if network!='ws' and any(k in q for k in ('path','host')):raise ValueError('Unexpected WS parameters')
    node={'name':unquote(p.fragment) or 'VLESS','type':'vless','server':p.hostname,'port':p.port,
          'uuid':str(uuid.UUID(p.username or '')),'network':network,'tls':security!='none'}
    for a,b in [('sni','servername'),('fp','client-fingerprint'),('flow','flow')]:
        if a in q:node[b]=q[a]
    if 'alpn' in q:node['alpn']=q['alpn'].split(',')
    if security=='reality':node['reality-opts']={'public-key':q.get('pbk',''),'short-id':q.get('sid','')}
    if network=='ws':node['ws-opts']={'path':q.get('path','/'),'headers':{'Host':q['host']} if q.get('host') else {}}
    node_uri(node)  # Reuse strict validation; never silently discard unknown parameters.
    if security=='reality':node.setdefault('client-fingerprint','chrome')
    return node

def convert(core, text, target):
    if target not in {'quanx', 'clash'}:
        raise ValueError('Unsupported target')
    direct=[]
    if target=='clash':
        remaining=[]
        for line in text.splitlines():
            if line.startswith('vless://'):direct.append(vless_clash(line))
            else:remaining.append(line)
        text='\n'.join(remaining)
        if not text.strip():return validate(yaml.safe_dump({'proxies':direct}),'clash')
    fd, name = tempfile.mkstemp(prefix='input-', dir=core.INPUT)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(base64.b64encode(text.encode()))
        with httpx.Client(timeout=30, trust_env=False) as client:
            response = client.get('http://127.0.0.1:25502/sub', params={
                'target': target, 'url': 'input/'+Path(name).name,
                'list': 'true', 'insert': 'false', 'emoji': 'false',
                'append_info': 'false', 'udp': 'true'})
        if response.status_code != 200 or len(response.content) > core.MAX:
            raise ValueError('Conversion failed')
        output=response.text
        if direct:
            parsed=yaml.safe_load(output)
            if not isinstance(parsed,dict) or not isinstance(parsed.get('proxies'),list):raise ValueError('Invalid conversion')
            parsed['proxies'].extend(direct)
            output=yaml.safe_dump(parsed)
        return validate(output, target)
    finally:
        Path(name).unlink(missing_ok=True)

def validate(text, target):
    if target == 'quanx':
        lines = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.lstrip().startswith(('#', ';', '['))]
        if not lines or any(not re.match(r'^(shadowsocks|vmess|trojan|http|socks5|vless)\s*=.+,.*\btag\s*=', line) for line in lines):
            raise ValueError('No valid Quantumult X nodes')
        return '\n'.join(lines)+'\n'
    data = yaml.safe_load(text)
    nodes = data.get('proxies') if isinstance(data, dict) else None
    if not isinstance(nodes, list) or not nodes or len(nodes) > 1000:
        raise ValueError('No valid Clash nodes')
    for i, node in enumerate(nodes):
        if not isinstance(node, dict) or not isinstance(node.get('server'), str) or not isinstance(node.get('port'), int) or not 1 <= node['port'] <= 65535 or node.get('type') not in {'ss', 'ssr', 'vmess', 'trojan', 'vless', 'hysteria', 'hysteria2', 'tuic', 'http', 'socks5', 'snell'}:
            raise ValueError('Invalid Clash node')
        node['name'] = f'Node-{i+1:03d}'
    # Build our own minimal profile; never inherit external providers or rules.
    return yaml.safe_dump({'mixed-port': 7890, 'allow-lan': False,
        'mode': 'rule', 'log-level': 'warning', 'proxies': nodes,
        'proxy-groups': [{'name': 'Proxy', 'type': 'select',
                          'proxies': [n['name'] for n in nodes]}],
        'rules': ['IP-CIDR,127.0.0.0/8,DIRECT', 'IP-CIDR,10.0.0.0/8,DIRECT',
                  'IP-CIDR,172.16.0.0/12,DIRECT', 'IP-CIDR,192.168.0.0/16,DIRECT',
                  'MATCH,Proxy']}, allow_unicode=True, sort_keys=False)
