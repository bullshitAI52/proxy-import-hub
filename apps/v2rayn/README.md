# v2rayN 私有快捷导入

[English](README_EN.md) · 独立于 Surge 项目，只使用 Python 标准库。

## 大白话怎么用
1. 打开管理员给你的私有入口，点“一键复制全部节点”。
2. 切换到 v2rayN 主界面，在服务器列表空白处按 Ctrl+V，或选择“从剪贴板导入分享链接”。
3. 也可以复制订阅地址，添加到订阅设置，再更新订阅。
4. 测试节点延迟和实际连接后，再设为活动服务器。

**不是网页自动唤起客户端**：按官方文档实现剪贴板导入与标准 Base64 订阅，不虚构浏览器安装协议。

## 功能
- 一键复制多个节点、复制订阅地址，自动复制失败时提供手动复制框。
- 只读导出明确选定的 3x-ui VMess TCP/WS TLS 节点，不更改数据库、核心、端口或旧节点。
- 高强度随机入口，支持保留链接更新节点或轮换令牌撤销旧链接。
- 独立服务、仅监听本机，不影响现有网站默认入口。

## 部署（Linux）
1. 把项目放到 /opt/v2rayn-import。安装 Python 3.10+，创建无登录权限的 v2rayn-import 系统用户。
2. 创建状态目录，并导出你明确选中的节点；示例中的 ID、地址及 SNI 必须替换成自己的：
```sh
install -d -m 700 -o v2rayn-import -g v2rayn-import /var/lib/v2rayn-import
python3 /opt/v2rayn-import/export_xui.py --ids 1,2 --host YOUR_VPS_IP --sni CERTIFICATE_NAME
chown v2rayn-import:v2rayn-import /var/lib/v2rayn-import/state.json
chmod 600 /var/lib/v2rayn-import/state.json
```
3. 创建 root 所有、权限600的 /etc/v2rayn-import.env，填写：
```ini
V2N_PUBLIC_URL=https://YOUR_DOMAIN/v2rayn
```
4. 安装 v2rayn-import.service 到 /etc/systemd/system，daemon-reload 后 enable --now v2rayn-import。
5. 将 Nginx 示例的 location 加入已有 HTTPS server 块，先备份并 nginx -t，通过再 reload。不要覆盖整个 server，不要改变 default_server。建议加请求速率限制。
6. 私下读取 state.json 的 token，入口为 PUBLIC_URL/TOKEN/，订阅为 PUBLIC_URL/TOKEN/subscription。不要在截图或公开日志中展示。

## 更新 / 撤销
重复导出默认拒绝覆盖。明确传 --update 可保留 token 更新节点；--rotate-token 会让旧入口和旧订阅地址失效。新状态会原子替换并保留原文件所有者。服务每次请求重新读取，不需重启。

此导出是快照，不自动同步 3x-ui。修改 UUID、端口或 TLS 配置后要重新导出。初次导出读取所选入站的第一个客户端，可用 --client-index 指定其他客户端。

## 安全与限制
- state.json **明文包含节点凭据**，只存于权限700目录、文件权限600，不能提交 GitHub。备份必须加密；获得入口的人能读取节点。
- 撤销入口不能撤销已下载的节点密码，需在 3x-ui 另行轮换客户端凭据。
- 不记录请求 URL；反向代理也关闭此路径的日志。HTTPS 若经过 CDN，CDN 仍处于传输路径。
- 导出器仅处理启用的 VMess TCP/WS TLS，不声称支持所有协议或面板版本；不绕过证书校验。
- 本项目不会降级核心，也不会删除旧节点。节点客户端额度、证书续期、防火墙与实际网络可用性需自行检查。
- 配置生成和本地测试不等于已在 Windows v2rayN 实机验收。

测试：`python3 -m unittest test_portal -v`。

参考：[官方剪贴板导入说明](https://github.com/2dust/v2rayN/wiki/Description-of-some-ui)、[官方订阅说明](https://github.com/2dust/v2rayN/wiki/Description-of-subscription)。
