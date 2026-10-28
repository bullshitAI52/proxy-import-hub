"""Bounded format detection. Never follow provider URLs or execute YAML tags."""
import base64
import json
import re
import uuid
from urllib.parse import quote, urlencode
import yaml

SCHEMES={'ss','ssr','vmess','vless','trojan','hysteria2','hy2','tuic'}

def node_uri(node):
    if not isinstance(node,dict):raise ValueError('节点不是对象')
    kind=node.get('type')
    common={'name','type','server','port','udp'}
    extra={'ss':{'cipher','password'},'trojan':{'password','sni'},
           'vmess':{'uuid','alterId','cipher','tls','servername','network','ws-opts'},
           'vless':{'uuid','tls','servername','network','ws-opts','flow','reality-opts','client-fingerprint','alpn','encryption'}}
    if kind not in extra:raise ValueError('该 YAML 节点协议暂不支持')
    if set(node)-common-extra[kind]:raise ValueError('含暂不支持的高级参数')
    host=node.get('server');port=node.get('port')
    if not isinstance(host,str) or not host or re.search(r'[\s/@?#\[\]]',host):raise ValueError('服务器地址异常')
    if type(port) is not int or not 1<=port<=65535:raise ValueError('端口异常')
    address=('['+host+']' if ':' in host else host)+':'+str(port)
    label=quote(str(node.get('name','Node')),safe='')
    if kind in {'ss','trojan'}:
        password=node.get('password')
        if not isinstance(password,str) or not password:raise ValueError('缺少密码')
        if kind=='ss':
            cipher=node.get('cipher')
            if not isinstance(cipher,str) or not cipher:raise ValueError('缺少加密方式')
            auth=base64.urlsafe_b64encode((cipher+':'+password).encode()).decode().rstrip('=')
            return 'ss://'+auth+'@'+address+'#'+label
        sni=node.get('sni',host)
        if not isinstance(sni,str):raise ValueError('SNI 异常')
        return 'trojan://'+quote(password,safe='')+'@'+address+'?'+urlencode({'security':'tls','sni':sni})+'#'+label
    identifier=str(uuid.UUID(node.get('uuid','')))
    network=node.get('network','tcp')
    if network not in {'tcp','ws'}:raise ValueError('暂不支持此传输方式')
    tls=node.get('tls',False)
    if type(tls) is not bool:raise ValueError('TLS 参数异常')
    ws=node.get('ws-opts',{})
    if not isinstance(ws,dict) or set(ws)-{'path','headers'} or (ws and network!='ws'):raise ValueError('WebSocket 参数暂不支持')
    headers=ws.get('headers',{})
    if not isinstance(headers,dict) or set(headers)-{'Host'}:raise ValueError('WebSocket 请求头暂不支持')
    if kind=='vless':
        params={'encryption':'none','type':network,'security':'tls' if tls else 'none'}
        if node.get('encryption','none') not in ('','none'):raise ValueError('暂不支持 VLESS 加密扩展')
        for field,param in [('servername','sni'),('client-fingerprint','fp')]:
            if field in node:
                if not isinstance(node[field],str) or not node[field]:raise ValueError('TLS 字段异常')
                params[param]=node[field]
        if 'alpn' in node:
            alpn=node['alpn']
            if not isinstance(alpn,list) or not alpn or any(not isinstance(x,str) or not x or ',' in x for x in alpn):raise ValueError('ALPN 异常')
            params['alpn']=','.join(alpn)
        if not tls and any(k in node for k in ('servername','client-fingerprint','alpn','reality-opts')):raise ValueError('TLS 参数与开关不一致')
        flow=node.get('flow','')
        if flow not in ('','xtls-rprx-vision') or (flow and (not tls or network!='tcp')):raise ValueError('Flow 与传输不兼容')
        if flow:params['flow']=flow
        if 'reality-opts' in node:
            reality=node['reality-opts']
            if network!='tcp' or not isinstance(reality,dict) or set(reality)-{'public-key','short-id'}:raise ValueError('暂只支持基础 TCP Reality')
            public=reality.get('public-key','');sid=reality.get('short-id','')
            if not isinstance(public,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',public):raise ValueError('Reality 公钥异常')
            if len(base64.urlsafe_b64decode(public+'='))!=32:raise ValueError('Reality 公钥异常')
            if not isinstance(sid,str) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}',sid):raise ValueError('Reality short-id 异常，请使用带引号的十六进制文本')
            if not params.get('sni'):raise ValueError('Reality 缺少 servername')
            params.update(security='reality',pbk=public,sid=sid)
            params.setdefault('fp','chrome')
        if network=='ws':
            if not isinstance(ws.get('path','/'),str) or not isinstance(headers.get('Host',''),str):raise ValueError('WebSocket 参数异常')
            params['path']=ws.get('path','/')
            if headers.get('Host'):params['host']=headers['Host']
        return 'vless://'+identifier+'@'+address+'?'+urlencode(params)+'#'+label
    aid=node.get('alterId',0)
    if type(aid) is not int or aid<0:raise ValueError('alterId 异常')
    for value in (ws.get('path','/'),headers.get('Host',''),node.get('servername',''),node.get('cipher','auto')):
        if not isinstance(value,str):raise ValueError('节点参数类型异常')
    payload={'v':'2','ps':str(node.get('name','Node')),'add':host,'port':str(port),'id':identifier,
             'aid':str(aid),'scy':node.get('cipher','auto'),'net':network,'type':'none',
             'host':headers.get('Host',''),'path':ws.get('path','/') if network=='ws' else '',
             'tls':'tls' if tls else '', 'sni':node.get('servername','')}
    return 'vmess://'+base64.b64encode(json.dumps(payload,ensure_ascii=False).encode()).decode()

def detect(data):
    if len(data)>2*1024*1024:raise ValueError('订阅超过 2 MB')
    try:text=data.decode('utf-8-sig').strip()
    except UnicodeError:raise ValueError('订阅不是 UTF-8 文本')
    if not text:raise ValueError('订阅为空')
    if text.startswith('<'):raise ValueError('链接返回网页或登录页，不是订阅内容')
    if re.search(r'(?mi)^\[(Proxy|General|server_remote|server_local)\]',text):
        raise ValueError('识别到 Surge/圈 X 配置，暂不支持作为输入；请获取通用节点订阅')
    fmt='节点链接列表'
    if not re.match(r'^[a-z0-9]+://',text):
        compact=re.sub(r'\s','',text)
        if re.fullmatch(r'[A-Za-z0-9+/_=-]+',compact):
            try:
                text=base64.b64decode(compact+'='*((-len(compact))%4),altchars=b'-_',validate=True).decode('utf-8-sig').strip()
                fmt='Base64 节点订阅'
            except (ValueError,UnicodeError):raise ValueError('Base64 订阅编码无效')
        else:
            try:
                # Reject aliases/anchors and deeply nested documents before construction.
                depth=0
                for event in yaml.parse(text):
                    if isinstance(event,yaml.events.AliasEvent) or getattr(event,'anchor',None):raise ValueError('不接受 YAML 锚点或别名')
                    if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):
                        depth+=1
                        if depth>16:raise ValueError('YAML 嵌套过深')
                    if isinstance(event,(yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)):depth-=1
                config=yaml.safe_load(text)
            except yaml.YAMLError:raise ValueError('无法识别订阅格式或 YAML 语法有误')
            if not isinstance(config,dict):raise ValueError('无法识别订阅格式')
            nodes=config.get('proxies')
            if not nodes and 'proxy-providers' in config:raise ValueError('识别到 Clash provider 配置，但没有内嵌节点；不会自动访问外部 provider')
            if not isinstance(nodes,list) or not 1<=len(nodes)<=1000:raise ValueError('Clash YAML 必须包含 1–1000 个内嵌 proxies 节点')
            result=[];skipped=[]
            for i,node in enumerate(nodes):
                try:result.append(node_uri(node))
                except (ValueError,TypeError,AttributeError):skipped.append(i+1)
            if skipped:
                # Fail closed: do not silently lose advanced parameters or nodes.
                raise ValueError('识别到 Clash YAML，但第 '+','.join(map(str,skipped[:10]))+' 项含不支持的协议、参数或无效字段；未创建分享。支持基础 SS、Trojan TCP/TLS、VMess/VLESS TCP/WS 和 VLESS TCP Reality；不支持其他高级扩展')
            return {'text':'\n'.join(result)+'\n','format':'Clash YAML','count':len(result),
                    'warnings':['只提取内嵌节点，不导入原配置的分流规则、DNS、脚本或外部 providers']}
    lines=[line.strip() for line in text.splitlines() if line.strip()]
    if not 1<=len(lines)<=1000:raise ValueError('节点为空或超过1000条')
    if any(line.split('://',1)[0] not in SCHEMES or '://' not in line or any(c.isspace() for c in line) for line in lines):
        raise ValueError('包含无效节点行或不支持的订阅格式')
    return {'text':'\n'.join(lines)+'\n','format':fmt,'count':len(lines),'warnings':[]}
