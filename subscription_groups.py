"""Resolve bounded HTTPS provider trees without importing rules or executing scripts."""
import base64
import json
import time
import re
import yaml
from subscription_input import detect

def config_document(data):
    if len(data)>2*1024*1024:raise ValueError('单份订阅超过 2 MB')
    try:text=data.decode('utf-8-sig').strip()
    except UnicodeError:raise ValueError('订阅不是 UTF-8 文本')
    # Node lists and HTML must retain the original detector's diagnostics.
    if re.match(r'^[a-z0-9]+://',text):return None
    if 'proxy-providers' not in text:return None
    try:
        depth=0
        for event in yaml.parse(text):
            if isinstance(event,yaml.events.AliasEvent) or getattr(event,'anchor',None):raise ValueError('不接受 YAML 锚点或别名')
            if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):
                depth+=1
                if depth>16:raise ValueError('YAML 嵌套过深')
            if isinstance(event,(yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)):depth-=1
        value=yaml.safe_load(text)
    except yaml.YAMLError:raise ValueError('订阅组 YAML 语法有误')
    return value if isinstance(value,dict) and 'proxy-providers' in value else None

def identity(line):
    if line.startswith('vmess://'):
        try:
            obj=json.loads(base64.b64decode(line[8:]+'==='))
            if isinstance(obj,dict):
                obj.pop('ps',None)
                return 'vmess:'+json.dumps(obj,sort_keys=True,separators=(',',':'))
        except (ValueError,UnicodeError):pass
    return line.split('#',1)[0]

def resolve(data,fetch,validate_url,root_url=None):
    started=time.monotonic();visited=set();memo={};warnings=[]
    totals={'bytes':0,'requests':0,'nodes':0}
    if root_url:visited.add(root_url)
    def walk(body,depth):
        if depth>2:raise ValueError('订阅组嵌套超过 2 层，请简化订阅')
        totals['bytes']+=len(body)
        if totals['bytes']>8*1024*1024:raise ValueError('订阅组总内容超过 8 MB')
        group=config_document(body)
        if group is None:
            info=detect(body);warnings.extend(info['warnings']);lines=info['text'].splitlines()
        else:
            providers=group.get('proxy-providers')
            if not isinstance(providers,dict) or not providers or len(providers)>8:raise ValueError('订阅组需包含 1–8 个 provider')
            lines=[]
            if group.get('proxies'):
                info=detect(yaml.safe_dump({'proxies':group['proxies']}).encode())
                lines.extend(info['text'].splitlines());warnings.extend(info['warnings'])
            for number,provider in enumerate(providers.values(),1):
                if not isinstance(provider,dict) or provider.get('type')!='http':raise ValueError(f'第 {number} 个子订阅不是 HTTP provider；不读取本地文件或 inline provider')
                # Avoid silently ignoring filtering/authentication/node mutation semantics.
                if set(provider)-{'type','url','path','interval','health-check','size-limit'}:
                    raise ValueError(f'第 {number} 个子订阅含过滤、覆盖或自定义请求头等未支持参数')
                url=provider.get('url')
                if not isinstance(url,str):raise ValueError(f'第 {number} 个子订阅缺少 URL')
                try:validate_url(url)
                except Exception:raise ValueError(f'第 {number} 个子订阅必须使用公开 HTTPS 地址及 443 端口')
                if url in visited:raise ValueError('订阅组存在循环引用，已停止读取')
                if url in memo:
                    lines.extend(memo[url]);continue
                if totals['requests']>=8:raise ValueError('订阅组最多读取 8 个不同子订阅')
                if time.monotonic()-started>60:raise ValueError('订阅组处理时间过长，请减少子订阅')
                totals['requests']+=1;visited.add(url)
                try:child=fetch(url)
                except Exception:raise ValueError(f'第 {number} 个子订阅读取失败；整组未生成，请检查有效期或地址')
                child_lines=walk(child,depth+1)
                visited.remove(url);memo[url]=child_lines;lines.extend(child_lines)
            warnings.append('只合并节点；忽略原分组、分流、DNS、provider 健康检查及更新间隔，不执行脚本或读取本地 path')
        totals['nodes']+=len(lines)
        if len(lines)>1000 or totals['nodes']>3000:raise ValueError('订阅组节点数量过多（合并前最多1000条）')
        return lines
    lines=walk(data,0);seen=set();unique=[]
    for line in lines:
        key=identity(line)
        if key not in seen:seen.add(key);unique.append(line)
    removed=len(lines)-len(unique)
    if not unique:raise ValueError('订阅组没有可用的节点内容')
    if len(('\n'.join(unique)+'\n').encode())>2*1024*1024:raise ValueError('合并后的节点文本超过 2 MB')
    if removed:warnings.append(f'已合并 {removed} 条重复节点（保留首次出现的名称）')
    if totals['requests']:
        fmt='Clash HTTPS 订阅组'
    else:fmt=detect(data)['format'] if config_document(data) is None else 'Clash HTTPS 订阅组'
    return {'text':'\n'.join(unique)+'\n','format':fmt,'count':len(unique),
            'warnings':list(dict.fromkeys(warnings)),'providers':totals['requests'],'duplicates':removed}
