# Proxy Import Hub · 统一导入分享页

[English](README_EN.md)

**这是一个新仓库，尚未部署。旧 Surge、v2rayN 仓库、线上服务、已有链接均未修改。**

## 大白话流程
管理员输入管理密钥 → 粘贴 HTTPS 订阅或节点链接 → 生成私有分享网页 → 朋友打开网页 → 选择自己使用的软件导入。

| 软件 | 当前入口 | 边界 |
|---|---|---|
| Surge Mac / iPhone | URL Scheme 导入按钮 | 协议不兼容时转换失败或省略节点 |
| Shadowrocket 小火箭 | shadowrocket://add/ 按钮 + 复制订阅备用 | 未实机验收，版本和系统可能限制唤起 |
| v2rayN | 复制 HTTPS 订阅，再 Ctrl+V 或手动添加 | 不承诺网页直接唤起所有版本 |

不会自动点击、绕过客户端确认或替朋友开启 VPN。网页按钮只是提出导入请求，成功生成配置不等于代理实际可用。

## 包含什么
- 根目录 server.py / index.html / share.html：统一创建、查看、撤销分享，以及三类客户端入口。
- apps/surge：原 Surge 项目的脱敏源码快照。统一服务复用了其认证、加密、SSRF防护和转换代码，并使用新路径及引擎端口。
- apps/v2rayn：原 v2rayN 项目的脱敏源码快照，包括只读 3x-ui 导出器。
- 一个根级测试工作流；子目录保留的工作流仅作历史参考，不会在根仓库触发。

源格式：节点 URI 或 Base64 节点订阅。当前统一入口不支持 Clash YAML 或完整客户端配置。HTTPS源在访问订阅时刷新，直接粘贴节点则保存为快照。VLESS可以透传给支持的客户端，但不意味着能转换到Surge。

## 独立部署说明（不要覆盖旧项目）
需要 Linux、Python 3.10+、systemd 和独立 HTTPS 路径。建议：
- 程序 /opt/proxy-import-hub
- 状态 /var/lib/proxy-import-hub（700，运行用户所有）
- 网关监听 127.0.0.1:8773
- 新 subconverter v0.9.0 引擎监听 127.0.0.1:25502
- 环境文件 /etc/proxy-import-hub.env（600，不入Git）

1. 创建独立无登录权限用户 proxy-import-hub，将本仓库放到程序目录，创建venv并安装 requirements.txt。
2. 下载 [subconverter v0.9.0](https://github.com/tindy2013/subconverter/releases/tag/v0.9.0) 对应平台发行包，放在新程序目录的 engine/；保留许可证。不要复用或修改线上旧引擎目录。
3. 复制 apps/surge/pref.ini 到新 engine/pref.ini，**把端口25501改为25502**。创建 engine/input，权限700且由新用户拥有。
4. 在新的600环境文件设置 SUB_PUBLIC_URL（例如 https://YOUR-DOMAIN/import）、SUB_ADMIN_KEY（随机长密钥）、SUB_ENCRYPTION_KEY（Fernet密钥）、SUB_DENIED_IPS（服务器公网IP）。用 Python secrets.token_urlsafe(32) 和 Fernet.generate_key() 生成，不使用示例密码。
5. 为新网关和引擎创建独立systemd单元。参考 apps/surge 的单元，但必须改用户、环境文件、目录、服务名称；网关从根目录运行 uvicorn server:app --host 127.0.0.1 --port 8773 --no-access-log --log-level critical。引擎保持仅回环网络隔离。不要直接启用子目录的旧服务名。
6. 在已有HTTPS server内新增 /import/ location，proxy_pass http://127.0.0.1:8773/，关闭该路径access/error日志、设置请求限流和2MB请求限制。**不修改原listen/default_server**。先备份、nginx -t，通过再reload。
7. 检查未授权 /api/shares 返回401、假令牌返回404、三个客户端备用导入流程和旧网站。

本次只归档新项目，没有执行以上部署操作。

## 私密信息与朋友账号
- 不包含真实节点、密码、订阅地址、运行数据库或服务器域名配置。
- 所有分享链接和订阅链接都是访问凭据，拿到链接即可读取节点。
- 撤销分享使网页和所有导入入口失效，但不能删除别人已经下载的节点密码。给朋友最好使用3x-ui独立客户端账号。
- 源内容加密存数据库，运行时转换临时文件仍可能短暂含明文；异常退出可能需要清理。数据库和加密密钥需分别安全备份。
- 继承的公网HTTPS获取逻辑会校验并固定DNS地址、限制大小，不允许任意内网目标。引擎应通过systemd限制对外联网。
- 当前没有过期自动撤销、额度管理或自动创建3x-ui账号功能。

## 测试
`python -m unittest test_hub -v`
覆盖：认证、私有页面、三端按钮、原始订阅透传、格式拒绝、加密存储、撤销后的404。单元测试不代表客户端实机导入或实际网络验收。

## 来源和版本
合并来源：surge-private-subscription d1e29af、v2rayn-private-import d9423af；均为独立快照，旧仓库保持不变。
[Surge URL Scheme](https://manual.nssurge.com/tools/url-scheme.html)、[v2rayN 官方导入说明](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui)。Shadowrocket按钮采用常见 add URL 格式，未得到当前安装版本的官方兼容性验证，保留手动添加订阅作为兜底。
