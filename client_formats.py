"""Convert node lists locally; do not fetch remote configuration templates."""
import base64
import os
import re
import tempfile
from pathlib import Path
import httpx
import yaml

def convert(core, text, target):
    if target not in {'quanx', 'clash'}:
        raise ValueError('Unsupported target')
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
        return validate(response.text, target)
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
