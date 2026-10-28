"""Conservative, static guidance; never promises device or network success."""
from collections import Counter
from urllib.parse import urlsplit, parse_qs
from client_formats import vless_clash

CLIENTS=('Surge','Shadowrocket','v2rayN','Quantumult X','Clash')

def inspect(text):
    rows=[]
    for index,line in enumerate(text.splitlines(),1):
        protocol=line.split('://',1)[0]
        try:reality=parse_qs(urlsplit(line).query).get('security')==['reality']
        except ValueError:reality=False
        clients={}
        for client in CLIENTS:
            if client in {'Surge','Quantumult X','Clash'}:
                if protocol in {'ss','vmess','trojan'}:
                    state='待转换验证';reason='属于常见转换协议；具体传输参数仍需引擎及客户端验证'
                elif protocol=='vless':
                    state='当前转换链不支持';reason='当前 subconverter v0.9.0 链路不承诺 VLESS/Reality；不能靠改格式改变协议'
                    if client=='Clash':
                        try:
                            vless_clash(line)
                            state='可生成，待客户端验证';reason='本项目直接生成基础 VLESS/Reality YAML，需要 Mihomo 等支持此协议的内核'
                        except (ValueError,TypeError,AttributeError):
                            state='参数暂不支持';reason='该 VLESS 链接包含无效或尚未支持的字段，不会静默删掉参数'
                else:
                    state='需确认';reason='当前转换引擎或客户端版本可能不支持，不能保证保留该节点'
            else:
                state='可透传，待客户端验证'
                reason='保留原始节点链接；需要客户端版本支持协议及传输参数'
                if reality:reason+='，尤其是 Reality'
            clients[client]={'status':state,'reason':reason}
        rows.append({'index':index,'protocol':protocol,'reality':reality,'clients':clients})
    return {'notice':'静态协议预检查，不测试连通性，不保证可用，也不代替实机验收。Clash 的 VLESS 输出需要支持相应协议的 Mihomo 等内核。',
            'summary':{client:dict(Counter(row['clients'][client]['status'] for row in rows)) for client in CLIENTS},
            'nodes':rows}
