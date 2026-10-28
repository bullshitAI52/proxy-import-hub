# Proxy Import Hub · 五客户端订阅分享页

[English](README_EN.md)

**新项目尚未部署。代码公开不等于分享链接公开；旧仓库、线上服务和旧链接均未修改。**

## 大白话：你怎么用

### 配合自建转换工具使用

[打开现有的自建 Surge 订阅转换管理页](https://pic-tg.shuanghai.shop:2087/subscription/)

这是旧版 Surge 工具的管理入口，需要管理员自己的管理密钥，**不是公开免费转换站，也不是新版五软件分享页**。地址公开不代表任何人都能生成订阅。

- 只给 Surge 用户使用时，可以继续在旧工具中转换并生成对应设备的导入链接。
- 需要给不同软件的朋友分享时，等本项目独立部署后，将**原始订阅或支持的节点内容**粘贴到新版管理页，生成五软件分享页，再把分享链接或二维码发给朋友。
- 两个工具可按场景配合使用，不是把旧工具生成的 Surge 完整配置再输入新版；新版目前不接受 Surge 完整配置作为输入。旧工具的内部转换引擎也没有开放成供新版直接调用的公共 API。
- 新版仍需按下方说明独立部署，不能把上面的旧管理地址当成新版地址。朋友不需要管理密钥；请勿公开密钥、真实节点或私人分享链接。

### 新版操作步骤

1. 部署后打开管理页，填写管理密钥，粘贴 HTTPS 订阅地址、节点文本、Clash YAML 或包含 HTTPS 子订阅的订阅组。
2. 点“先检查格式与兼容性”。界面显示格式、节点数和五个软件的逐条提示；这只是静态预检查，不测试网络连通性。
3. 填名称，选择永久、7 天或 30 天，再点“确认生成分享网页”。直接点主按钮也会先检查，再让你确认。
4. 点“复制分享链接”发给朋友，或让朋友扫描二维码。管理密钥自己保管，不发给朋友。
5. 在已有分享列表查看到期时间、复制或撤销。修改源文本后必须重新检查。

## 朋友怎么导入

分享页按 Surge → 小火箭 → v2rayN → 圈 X → Clash 顺序排列为五张独立卡片，顶部可跳转。每张卡片有自己的导入/复制按钮、备用地址和就地提示；Surge 单独区分 Mac 与 iPhone。小火箭与 v2rayN 虽共用通用订阅格式，但各有自己的按钮，不用跨栏寻找。v2rayN 明确标为复制后到客户端粘贴。

先安装对应软件，在系统浏览器打开分享页。网页不会自动批准 VPN 权限或替你开启代理。

| 软件 | 操作 | 注意 |
|---|---|---|
| Surge Mac / iPhone | 点设备对应的导入按钮，在软件中确认 | 当前转换链不支持 VLESS/Reality；其他协议仍需验证 |
| 小火箭 Shadowrocket | 尝试按钮导入；失败则复制通用订阅地址手动添加、更新 | 唤起按钮尚未实机验证 |
| v2rayN | 复制订阅，在服务器列表按 Ctrl+V，或到订阅管理中新增并更新 | **不是浏览器直接一键导入** |
| 圈 X Quantumult X | 点“添加节点订阅”，再更新资源和选择节点 | 追加节点资源，不替换原规则；当前转换链不支持 VLESS |
| Clash 兼容客户端 | 点导入按钮，或复制专用 YAML 地址从 URL 导入 | 需要注册 clash://；VLESS/Reality 要求支持相应协议的 Mihomo 等内核 |

Surge、圈 X 和大多数 Clash 节点由独立 subconverter 引擎转换；本项目直接生成基础 VLESS/Reality 的 Clash YAML，不依赖旧引擎处理 VLESS。不支持的参数会拒绝，不会靠改格式改变节点协议。Clash 输出只包含简单规则：IPv4 局域网直连，其他走所选节点；端口 7890，禁止局域网访问代理监听。它不是原服务商的完整分流策略。部分 Clash 版本可能直接启用新配置，先备份原配置。

## 新增功能与边界

### 1. 生成前兼容性预检查

显示各软件的节点统计及逐条原因，不展示节点密码。“可透传”“可生成”“待验证”均不代表已经联网。纯协议分析不能保证节点账号、额度、证书、传输参数或软件版本可用。正式使用仍需要真实转换引擎和客户端验收。

### 2. 分享有效期

可选永久、7 天、30 天，从创建时起计算。过期后分享页、原始订阅、全部转换入口和二维码都返回 410；撤销返回 404，缓存不能绕过检查。旧数据库中没有有效期的分享按永久处理。过期记录保留用于查看，可手动撤销以释放 20 个分享名额。

**到期/撤销只禁止以后读取，不会让已经下载的节点账号自动停用。** 需要停用账号时请在节点服务端操作。

### 3. 二维码

由自建服务本地生成 SVG，不使用第三方二维码接口。二维码指向分享页，不是直接连接 VPN，也不是节点密码二维码；拿到它仍相当于拿到分享凭据。网页里显示二维码，朋友可扫码打开并选择软件。

### 4. 自动识别与 VLESS/Reality

支持节点 URI、标准/URL-safe Base64，以及基础 Clash YAML 内嵌节点：
- SS（无插件）、Trojan TCP/TLS、VMess TCP/WS（可带 TLS）。
- VLESS TCP/WS，以及 VLESS TCP + TLS + Reality；保留 UUID、SNI、指纹、公钥、short-id、Vision flow 等支持字段。
- 不支持 gRPC、xhttp、VLESS 加密扩展、packet-encoding 等未实现字段；未知参数导致整份 YAML 拒绝，并提示节点序号，不偷偷删节点。
- Reality short-id 必须是带引号的偶数长度十六进制字符串，最多 16 个字符；省略客户端指纹时默认 chrome。
- Surge/圈 X 完整配置、HTML 登录页、空内容、无效编码明确报错。

### 5. 限流与短时缓存

默认单进程：每分钟最多 240 个请求，其中 POST 预检查/生成合计最多 20 次；超限返回 429 和 Retry-After。只允许一个读取/转换任务同时执行，忙时提示重试，不无限排队。限流为服务全局，不依赖可伪造的转发 IP。

成功的预检查、源文本、转换结果及二维码缓存最多 5 分钟，LRU 最多 128 条、有效载荷总量最多 16 MiB（不含 Python 对象额外开销）。不缓存失败；撤销或到期先检查再读取缓存。上游修改最多延迟约 5 分钟反映；重启会清空内存缓存和限流窗口。必须使用一个应用 worker；多进程需要外部共享限流/缓存，本版本未实现。部署时仍应给 Nginx 和 systemd 配置独立的请求/资源限制。

## 订阅组自动展开：不用逐个复制

支持 Clash `proxy-providers` 中 `type: http`、URL 为公开 HTTPS/443 的子订阅。根输入可以是网址或粘贴的组配置；子订阅可以是节点列表、Base64、支持的 YAML 或两层以内的嵌套组。自动抓取、合并、去重，保留首次出现的名称；普通 URI 比较去掉备注后的内容，VMess 比较去掉 ps 名称后的 JSON，不承诺所有不同编码形式都能识别成同一节点。

限制：最多 8 个不同子订阅、每份 2 MB、总下载内容 8 MB、最终文本 2 MB、合并前最多 1000 条节点。每次发起子请求前检查 60 秒处理预算（不是可强制打断当前网络请求的硬截止）；现有网络读取超时保护继续生效。重复 URL 只抓一次；循环引用、过深嵌套、内网地址、非 HTTPS、本地文件 provider、别名/锚点、自定义头、过滤/覆盖、加密 provider 等会拒绝。HTTPS 获取在每次重定向后重新校验并固定公网 DNS 地址。

**任一子订阅失败，整组不生成/更新，不静默跳过。** 错误只提示序号，不回显私密 URL。旧客户端已下载的配置保留不受影响。只合并节点，不照搬原策略组、规则、DNS、脚本、provider 健康检查或更新间隔；`path` 不读取本地文件。粘贴的组配置会加密保存并在缓存到期后重新读取子订阅；普通粘贴节点为静态快照，HTTPS 根订阅会重新读取。

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


## 隐私、备份与排错

- 分享链接、订阅地址和二维码都是凭据，勿发到公开仓库或截图。仓库仅含示例和代码，没有实际节点、密钥或运行数据库。
- 密钥不保存到浏览器本地存储。源内容在数据库中加密，数据库与加密密钥应分开备份；运行中内存缓存与转换临时文件可能包含明文。
- 建议给朋友创建独立节点账号。本项目不自动创建 3x-ui 账号，也不管理流量配额。
- 链接打不开：检查是否部署、是否到期/撤销。GitHub 代码仓库地址不是分享页。
- 能导入但不能联网：检查服务器、节点账号、协议、客户端版本；生成成功不是连通性证明。
- 429：等待一分钟或当前转换完成再试。502：检查源订阅和独立转换引擎，不要删除客户端已有配置。

## 测试与验证范围

`python -m unittest test_hub test_features test_groups -v`

26 项自动化测试覆盖格式、加密存储、权限、兼容性报告、到期与撤销、二维码、VLESS/Reality 参数往返、缓存/限流、订阅组去重/循环/失败/内网拒绝。转换引擎路径主要使用模拟响应；基础 VLESS→Clash 走真实本地解析。已在本地浏览器用虚拟节点检查生成前提示、7 天有效期、结果和二维码，未完成真实客户端导入或代理联网验收。未部署到 VPS。

## 来源

独立快照来自 surge-private-subscription d1e29af、v2rayn-private-import d9423af，保存在 apps/；旧项目不随此仓库更新。根目录是统一服务，子目录的历史服务文件不能直接启用。

[Surge](https://manual.nssurge.com/tools/url-scheme.html) · [圈 X](https://github.com/crossutility/Quantumult-X/blob/master/url-scheme.md) · [Clash Verge Rev](https://www.clashverge.dev/guide/url_schemes.html) · [v2rayN](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui) · [Mihomo VLESS](https://wiki.metacubex.one/en/config/proxies/vless/) · [Proxy providers](https://wiki.metacubex.one/en/config/proxy-providers/)
