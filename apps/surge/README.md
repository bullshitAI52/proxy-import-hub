# Surge Private Subscription
私有订阅转换与 Surge 一键导入，支持 Mac 和 iPhone。 [English](README_EN.md)

## 能做什么
- 将支持的订阅转换为 Surge 配置，分别生成 Mac / iPhone 导入页面。
- 原订阅 URL 或本地节点内容加密保存，管理接口需要密钥。
- 随机订阅链接可撤销；不会把节点发给公共转换网站。
- 使用自建 subconverter v0.9.0 引擎，限制在本机运行。
- 支持导入 3x-ui 导出的兼容节点文件；不修改面板、不降级核心、不删除旧节点。

## 大白话使用
1. 打开你部署的 /subscription/ 页面，用管理密钥解锁。
2. 输入服务商的 HTTPS 订阅，生成 Mac 和 iPhone 链接。
3. 点一键导入，在 Surge 确认安装；内置浏览器不能唤起时用 Safari。
4. 先备份原配置，再实际测试节点；复制 URL 导入是备用方式。
5. 不用时撤销订阅。已经下载到设备的节点密码不会因此被远程清除。

## 部署（Ubuntu / systemd）
以下以 /opt/private-sub 为安装目录，执行前自行检查端口 8771、25501 未被占用。
不要覆盖现有网站，也不要改变 Nginx 默认入口。

1. 安装 Python 3.10+、venv、Nginx、curl、tar。创建无登录权限的 private-sub 系统用户。
2. 将本仓库放在 /opt/private-sub。执行：
```sh
python3 -m venv /opt/private-sub/venv
/opt/private-sub/venv/bin/pip install -r /opt/private-sub/requirements.txt
install -d -o private-sub -g private-sub -m 700 /var/lib/private-sub
```
3. 从 [subconverter v0.9.0 官方发行版](https://github.com/tindy2013/subconverter/releases/tag/v0.9.0)下载匹配架构的二进制，解压后的目录放到 /opt/private-sub/engine。保留上游许可证。本仓库不包含二进制。
4. 将 pref.ini 复制到 engine/pref.ini，创建共享临时目录：
```sh
install -d -o private-sub -g private-sub -m 700 /opt/private-sub/engine/input
```
5. 生成独立密钥，替换下面的示例网址和服务器 IP：
```sh
/opt/private-sub/venv/bin/python /opt/private-sub/setup_credentials.py https://YOUR-DOMAIN/subscription YOUR-VPS-IP
```
密钥位于 /etc/private-sub.env，登录说明位于 /opt/private-sub/access.txt。不要上传它们。已有环境文件不会被覆盖。更新旧版部署时，要明确补齐 SUB_PUBLIC_URL 和 SUB_DENIED_IPS。
6. 将两个 .service 文件安装到 /etc/systemd/system/，然后：
```sh
systemctl daemon-reload
systemctl enable --now private-sub-engine private-sub
```
7. 将 nginx-location.example.conf 中的 location 添加到已有 HTTPS server 块。先备份、运行 nginx -t，通过后 reload。不要替换整个原配置。生产环境应另外设置请求速率限制；引擎端口不可暴露公网。
8. 检查主页返回 200、未授权管理接口返回 401、旧网站仍正常。

## 自己的 3x-ui 节点
从面板导出 VMess TCP/WS TLS、SS、Trojan 等引擎与 Surge 均支持的节点到私有文件。
```sh
cd /opt/private-sub
/opt/private-sub/venv/bin/python import_nodes.py /PRIVATE/PATH/nodes.txt --name "My VPS"
```
然后在网页解锁查看导入入口。此操作导入的是快照；面板修改密码、UUID、端口后应撤销并重新导入。保护好原节点文件。程序不会自动从面板数据库提取凭据。

## 限制与安全
- 转换格式不等于转换协议。VLESS / Reality 等可能无法导出为 Surge；不保证所有新协议支持。部分不支持的节点可能被省略。
- 两端使用同一兼容节点集、分别管理 URL。默认仅局域网直连，其余走所选节点；不是智能国内外分流，不启用 MITM。
- 配置生成通过不等于节点可连接。必须在实际设备测试；服务端证书、续期、端口开放需自行维护。
- 管理密钥不写浏览器存储；原文转换时短暂存在600权限文件中，正常结束删除，异常退出可能遗留。
- 仅接受公网 HTTPS 443 上游；DNS固定IP连接、每次重定向校验、最大2MB。SUB_DENIED_IPS 应包含本机公网IP。
- 加密密钥与数据库应分开保管；服务器被完全控制后，加密不能阻止管理员读取凭据。
- 转换链接、导入链接都是访问凭据，不能公开分享。
- 不记录应用访问日志；配置示例关闭该路径的 Nginx 日志。启用CDN时请求仍经过CDN。
- systemd 的 IPAddressDeny 依赖系统支持；上线前验证隔离，不能只看配置文件。公网只开放HTTPS。

## 测试与备份
```sh
python -m unittest test_server -v
# 完整引擎测试需以可读取临时目录的用户运行，并先启动引擎：
SUB_TEST_ENGINE=1 SUB_TEST_ROOT=/var/lib/private-sub python -m unittest test_server -v
```
备份 /var/lib/private-sub/subscriptions.db 与 /etc/private-sub.env，必须加密。丢失加密密钥无法恢复源订阅。
仓库仅存放通用源码与说明，不包含真实域名配置、节点密码、订阅地址或数据库。

## 参考
[Surge URL Scheme](https://manual.nssurge.com/tools/url-scheme.html) · [subconverter](https://github.com/tindy2013/subconverter)
