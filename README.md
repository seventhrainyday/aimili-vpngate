<div align="center">

# AimiliVPN

**面向 Linux VPS 的 VPNGate 节点管理与 HTTP / HTTPS / SOCKS5 代理网关**

[![正式版本](https://img.shields.io/github/v/release/baoweise-bot/aimili-vpngate?style=flat-square&label=正式版&color=16a34a)](https://github.com/baoweise-bot/aimili-vpngate/releases/latest)
[![Docker](https://img.shields.io/badge/Docker-amd64%20%7C%20386%20%7C%20arm64%20%7C%20armv7-0ea5e9?style=flat-square&logo=docker&logoColor=white)](https://github.com/baoweise-bot/aimili-vpngate/pkgs/container/aimili-vpngate)
[![License](https://img.shields.io/badge/License-GPL--3.0-334155?style=flat-square)](LICENSE)

**简体中文** · [English](docs/README.en.md) · [日本語](docs/README.ja.md) · [한국어](docs/README.ko.md)

[快速安装](#quick-install) · [完整安装](#installation) · [连接使用](#connection) · [社区入口](#community) · [法律声明](#legal)

> **Fork 说明**：本分支基于上游 `OpenMili/aimili-vpngate` 修改，包含以下修复与新增功能（上游未合并）：
>
> **节点检测与存储**
> - 节点检测加速：周期检测不再找到 3 个可用节点就停，改为测完所有节点；并发从 5 提到 10；新增 TCP 端口 3 秒预检，死节点跳过 12 秒 OpenVPN 握手等待
> - 节点累积存储：拉取新节点时不再清空老节点，改为累积模式（记录 `first_seen_at` / `last_seen_at`）；仅在超过 1000 个时按策略淘汰
> - 中文徽章评级：节点按 优质 > 良好 > 一般 > 机房 > 注意 > 未知 排序，自动切换同样按此顺序挑节点
> - IP 评分列：节点列表新增评分列，一键跳转 iplark / ippure / ipsuper 检测节点 IP
> - 长期不可用自动删除：连续 N 天不可用自动删除节点（默认 7 天，填 0 不删），代理设置中可配置
>
> **代理与连接**
> - 代理监听地址可配置：默认 `0.0.0.0`，便于外部设备直连
> - 账号密码认证：HTTP/SOCKS5 可选账号密码，公网暴露时建议开启
> - 多出口管理：每个可用节点可建独立出口（独立端口 + 独立 tun 网卡），支持自定义端口、独立自动切换、独立路由模式（自动/固定IP/固定地区）、独立 IP 类型过滤
> - 连接后自动测速：连上后自动测速，低于阈值自动换节点（代理设置中开关，默认关闭）
> - 稳定节点优先：连续在线 30 分钟标记为稳定节点，排序和自动切换优先选择
>
> **监控与统计**
> - 实时流量曲线：主页显示下载/上传实时速率曲线（绿下载/橙上传）
> - 节点健康度：每次探测自动累计，表格显示可用率，悬停看累计探测/成功次数
> - 连接历史时间线：记录每次连接/断开/切换的时间、节点、原因，保留最近 500 条
> - 每日报告：统计切换次数、连接/断开数、总流量、每节点流量，可按日期查看，每天 23:59 推送昨日日报（Telegram/Bark）
> - 一键诊断：检查 OpenVPN 进程、tun0、代理端口、出口 IP、DNS
>
> **管理功能**
> - 黑名单：手动拉黑节点，30 天内不再使用，右上角菜单可管理
> - 导出 .ovpn：每行下载按钮，直接下载节点 OpenVPN 配置
> - 断线通知：自动切换或彻底断开时推送 Bark / Telegram，可发送测试通知
> - 节点收藏、测速、筛选：主页直接操作
>
> **UI 改进**
> - 底部导航栏：首页 / 节点 / 出口 / 我的，一键切换
> - 流量曲线点开放大：查看最近 5 分钟大图
> - 代理设置分组 Tab：代理 / 路由 / 通知 / 检测清理
>
> **个性化与隐蔽**
> - 面板名称自定义：代理设置中修改，标题和浏览器 tab 同步变更
> - 进程名伪装：自定义进程名，`ps` 中不再显示 vpngate/openvpn 关键词（需重启生效）
>
> **其他**
> - 移除上游 VPS 购买推荐广告（含 affiliate 链接）
> - 本分支安装链接已指向本 fork，无需额外打补丁

## 更新日志

### 2026-10-07
- `b0f63b9` 修复手机端头部状态栏文字截断：.status 加 flex-wrap 和 word-break，代理地址不再显示为 http://0.0.0:52051
- `9bdf6ec` 修复弹窗重开后保存按钮卡死：openNetworkModal/openCredentialsModal 打开时重置按钮状态
- `5096d8c` 清理 update_settings 调试日志
- `a49c7b2` 加 update_settings 后端日志：定位保存卡死问题（已确认服务器正常返回 200，系客户端网络丢响应包）
- `5aaeeb8` 修复代理设置改端口后按钮卡死：重启等待从固定 4 秒改为轮询 `/api/ping`（新增）直到服务器回来再刷新
- `bb01098` ARM/Alpine 真因：musl 的 IPv6 双栈有问题，默认绑定改为 IPv4 `0.0.0.0`（之前 `::` 会导致 API 连接被掐）；恢复 panel_name/process_name 代码（排查证明不是它的锅）
- `1dc94fe` 临时禁用 panel_name/process_name 后端处理：排查 ARM 上 update_settings 崩溃问题（已恢复）
- `3a84124` 修复代理设置误触发重启：`expected_proxy_port` 可能是字符串，`int != str` 恒为 True 导致每次保存都 `os._exit(0)` 自杀（ARM 上响应没刷出去就被杀）
- `e72caaf` do_GET/do_POST 加最外层异常兜底：任何未捕获异常都返回 500 JSON，不再静默掐连接（ARM/Alpine 排查）
- `7bfad44` NAT 兼容：响应加 `Connection: close`，避免复用连接被 NAT 网关掐掉
- `d990e77` Alpine/musl 兼容：显式设置线程栈 8MB，避免请求线程栈溢出
- `0ab139d` ARM 兼容：`send_bytes` 加 `wfile.flush()`，`HTTPServer` 加 `daemon_threads`
- `2f70eb8` 代理设置表单加 `novalidate`：彻底禁用浏览器原生验证
- `5873df4` 修复代理设置保存点不了：去掉隐藏 tab 中必填字段的 `required` 属性
- `e2db19f` 修复：代理账号密码移回代理 tab（误放在通知 tab）
- `d732ece` 修复测试通知：force 绕过 notify_enabled 检查，未启用也能测试
- `a113f50` 修复一键诊断 DNS 检查：改用 reverse/isp 字段，不再显示"未知"
- `fe22096` 修复底部导航按钮函数名：showXModal → openXModal
- `d463c38` 新增：面板名称自定义 + 进程名伪装（主进程 re-exec 假名，openvpn 子进程 argv[0] 伪装）
- `f6dbc97` 底部导航图标调大到 26px 并统一样式
- `f3eef0d` UI 三件套：底部导航栏 + 流量曲线点开放大（5 分钟大图）+ 代理设置分组 Tab
- `66f7850` 更新 README：完整功能列表 + 更新日志
- `7de9681` 新增：连续 N 天不可用自动删除节点（默认 7 天，0=不删），代理设置中可配置；探测成功时记录 `last_available_at`
- `552914f` 流量曲线移到下载速度右侧网格内，与其他卡片同尺寸
- `d67e939` 删除 network_modal 多余的闭合 `div`（导致保存按钮错位）
- `faab824` 移动端 modal 适配：小屏幕下减小 padding、调整宽度
- `ae2bded` 修复流量曲线 JS 只在登录页：补到 INDEX_HTML；修复表单 label 移动端逐字换行
- `bdfc0aa` 流量曲线改为独立卡片；修复自动测速布局错乱
- `136ed89` 修复自动测速 UI 的 HTML 结构错乱（div 未闭合导致不显示）
- `5562650` 修复黑名单 GET 路由放错方法（从 do_POST 移到 do_GET）；修复一键诊断 407 代理认证
- `8dc8a39` 修复一键诊断 407 错误：诊断请求带上代理认证信息
- `a563d5a` 四合一：实时流量曲线 + 稳定节点优先 + 连接后自动测速 + 一键诊断
- `229ec35` 移除上游 VPS 购买推荐广告（悬浮按钮 + Modal + affiliate 链接 + 捐赠地址）

### 2026-10-06
- `bd26544` 修复日报 API 路由放错方法：`/api/daily_report` 和 `/api/conn_history` 从 do_POST 移到 do_GET
- `05a67f3` 修复 `apiUrl` 定义在错误的 HTML 模板（从 LOGIN_HTML 移到 INDEX_HTML）
- `5bde004` 前端 API 路径动态适配 secret_path：新增 `apiBase`/`apiUrl`，解决自定义 secret_path 导致的 404
- `83b65d5` 修复日报/多出口 API 硬编码 `/shi` 路径，改为相对路径；修复日报默认日期 UTC 时差
- `ea12a62` 修复日报弹窗打不开：`openModal`/`closeModal` 改为 `showModal`/`hideModal`
- `669a33e` 连接历史时间线 + 每日报告功能
- `c25cc34` 多出口增强：自定义端口 + 独立自动切换 + 路由模式 + IP 类型过滤
- `56c1e84` 四合一：节点健康度 + 黑名单 + 导出 .ovpn + 断线通知（Bark/Telegram）
- `38e6afb` 自动切换改用徽章排序
- `a2bf87b` 测速和流量挪到主页面
- `6d80857` 三合一：收藏 + 测速 + 流量 + 筛选
- `9001ed9` 排序改为按中文徽章评级
- `aba467e` 排序改为：评分 → 拉取时间 → 延迟 → 住宅/移动 IP
- `98ed5b9` 排序调整 + 修复多出口节点选择器
- `731657b` 修复多出口参数化不完整导致代理失败（`create_connection` 漏 `device` 参数）
- `7decec5` 修复多出口代码导致登录失败
- `3959bc2` 多出口功能：一个端口对应一个节点（独立 OpenVPN + 代理端口 + tun 网卡）
- `7a67627` 代理监听地址可配置 + 账号密码认证
- `26ad6ae` 节点列表新增 IP 评分列与三站一键检测外链（iplark/ippure/ipsuper）
- `a2cc769` README 与安装链指向 fork 修复分支
- `5bca680` 节点检测加速与累积存储（分支起点）

[![项目网站](https://img.shields.io/badge/项目网站-339936.xyz-f97316?style=for-the-badge)](https://339936.xyz)
[![Telegram](https://img.shields.io/badge/Telegram-交流群-229ED9?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/arestemple)
[![YouTube](https://img.shields.io/badge/YouTube-视频教程-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=s-ATfXR8BpI)

</div>

AimiliVPN 使用 Python 标准库管理 VPNGate 节点，提供节点获取与检测、连接切换、Web 管理后台，以及共用一个端口的 HTTP、HTTPS 网站代理和 SOCKS5 代理服务。

| 项目 | 默认值或支持范围 |
| --- | --- |
| Web 管理后台 | TCP `8787` + 独立安全路径 + 账号密码 |
| 本机代理 | `127.0.0.1:7928`，支持 HTTP、HTTPS `CONNECT` 和 SOCKS5 |
| 源码部署 | x64、x86、ARM64、ARM32 Linux |
| Docker 镜像 | `linux/amd64`、`linux/386`、`linux/arm64`、`linux/arm/v7` |
| 更新通道 | GitHub `main` 正式分支 / 最新正式 Release |

> [!IMPORTANT]
> **网络可用性提示：** 不同地区、数据中心和网络服务商可能限制 DNS、VPNGate API、GitHub 镜像或 VPN 协议。镜像与本地缓存只能提高节点列表的可用性，不能保证所有机型都能建立连接。部署前请确认所在地法律和 VPS 服务商条款允许使用 VPN/TUN。

<a id="quick-install"></a>
## 快速安装

使用 `root` 用户在受支持的 Linux VPS 上执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/seventhrainyday/aimili-vpngate/enhanced/install.sh)
```

安装完成后，终端会显示 Web 后台完整地址、随机安全路径、登录账号和密码。输入 `ml` 可打开管理菜单。

无人值守安装可显式跳过首次参数询问，并自动生成安全路径和登录凭据：

```bash
AIMILIVPN_NONINTERACTIVE=1 bash <(curl -Ls https://raw.githubusercontent.com/seventhrainyday/aimili-vpngate/enhanced/install.sh)
```

> [!TIP]
> 安装前请在 VPS 控制面板启用 TUN/TAP，并确认 `/dev/net/tun` 存在。Web 默认使用 TCP `8787`，安全组建议只允许自己的 IP 访问。

<a id="installation"></a>
## 完整安装

### 运行条件

- 操作系统：Ubuntu、Debian、Alpine、CentOS、RHEL、Rocky Linux、AlmaLinux、Fedora、Oracle Linux 或 Amazon Linux。
- 权限与组件：`root`、OpenVPN、iptables、策略路由和 TUN/TAP。
- Windows 与 macOS 可作为代理客户端，但不能直接运行完整网关；Docker Desktop 也不等同于具备宿主机 TUN 能力的 Linux VPS。

### 方式一：一键源码安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/seventhrainyday/aimili-vpngate/enhanced/install.sh)
```

安装器会部署到 `/opt/aimilivpn` 并注册系统服务。常用命令：

```bash
ml                 # 打开管理菜单
ml status          # 查看状态、Web 地址和账号
ml logs            # 查看实时日志
ml restart         # 重启服务
ml password        # 重设 Web 账号密码
ml update          # 从 main 正式分支更新
ml uninstall       # 卸载
```

需要先审查脚本时：

```bash
git clone --branch enhanced --single-branch https://github.com/seventhrainyday/aimili-vpngate.git
cd aimili-vpngate
sudo bash install.sh
```

通用 Linux 源码包与 SHA-256 校验文件可在 [GitHub Releases](https://github.com/baoweise-bot/aimili-vpngate/releases/latest) 下载，版本变更记录也统一放在 Release Notes 中。

### 方式二：Docker Compose

Docker 主机需要 `/dev/net/tun`、host 网络以及 `NET_ADMIN`、`NET_RAW` 权限。

```bash
git clone --branch enhanced --single-branch https://github.com/seventhrainyday/aimili-vpngate.git
cd aimili-vpngate
docker compose pull
docker compose up -d
docker logs -f aimilivpn
```

正式镜像：`ghcr.io/baoweise-bot/aimili-vpngate:2.1`

更新容器：

```bash
docker compose pull
docker compose up -d
```

<details>
<summary><strong>查看 docker run 命令</strong></summary>

```bash
docker run -d \
  --name aimilivpn \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -e UI_HOST=0.0.0.0 \
  -e UI_PORT=8787 \
  -e LOCAL_PROXY_HOST=127.0.0.1 \
  -e LOCAL_PROXY_PORT=7928 \
  -v aimilivpn-data:/data \
  ghcr.io/baoweise-bot/aimili-vpngate:2.1
```

</details>

<details>
<summary><strong>无法拉取 GHCR 时在 VPS 本地构建</strong></summary>

```bash
git clone --branch enhanced --single-branch https://github.com/seventhrainyday/aimili-vpngate.git
cd aimili-vpngate
docker compose build
docker compose up -d
```

</details>

<a id="connection"></a>
## 连接与使用

### 1. 登录 Web 后台

源码安装完成后，使用终端输出的地址访问：

```text
http://VPS_IP:8787/随机安全路径/
```

忘记地址时执行 `ml status`；需要重设账号密码时执行 `ml password`。

Docker 用户可以读取首次启动时保存的 Web 配置：

```bash
docker exec aimilivpn cat /data/ui_auth.json
```

使用其中的 `secret_path`、`username` 和 `password` 登录，并在首次登录后修改安全路径和凭据。

### 2. 获取并连接节点

1. 登录后台，等待首次节点加载完成，或点击“更新节点”。
2. 按国家筛选节点，并使用“测试”检查本机实测延迟与可用性。
3. 点击目标节点的“切换”；目标预检失败时，程序会尽量保留当前可用连接。
4. 根据需要选择智能自动、固定国家或固定 IP 模式。
5. 在状态区域确认 VPN 已连接，并核对当前出口 IP。

### 3. 在 VPS 本机使用代理

HTTP、HTTPS 网站代理和 SOCKS5 共用 `127.0.0.1:7928`。HTTPS 网站通过 HTTP 代理的 `CONNECT` 方法访问，代理地址仍填写 `http://127.0.0.1:7928`。

```bash
# HTTP / HTTPS
curl -x http://127.0.0.1:7928 https://api.ipify.org

# SOCKS5，并通过代理解析域名
curl --proxy socks5h://127.0.0.1:7928 https://api.ipify.org
```

<details>
<summary><strong>查看 Shell 环境变量与 Python 示例</strong></summary>

```bash
export http_proxy="http://127.0.0.1:7928"
export https_proxy="http://127.0.0.1:7928"
curl https://api.ipify.org
```

```python
import requests

proxies = {
    "http": "http://127.0.0.1:7928",
    "https": "http://127.0.0.1:7928",
}

response = requests.get("https://api.ipify.org", proxies=proxies, timeout=20)
print(response.text)
```

</details>

### 4. 从电脑或其他设备连接

代理默认只监听 VPS 回环地址。推荐使用 SSH 隧道，不要直接暴露代理端口：

```bash
ssh -N \
  -L 8787:127.0.0.1:8787 \
  -L 7928:127.0.0.1:7928 \
  root@VPS_IP
```

隧道建立后：

- Web：`http://127.0.0.1:8787/随机安全路径/`
- HTTP / HTTPS 代理：`127.0.0.1:7928`
- SOCKS5 代理：`127.0.0.1:7928`，支持时选择远程 DNS 或 `socks5h`

> [!WARNING]
> `7928` 默认没有面向公网的用户认证。请勿在没有防火墙、来源 IP 限制或其他可靠访问控制的情况下将其直接开放到公网。

<a id="community"></a>
## 网站、社群与视频

| 入口 | 用途 | 链接 |
| --- | --- | --- |
| 项目网站 / 交流论坛 | 公告、经验交流与讨论 | [339936.xyz](https://339936.xyz) |
| Telegram 群 | 即时交流 | [t.me/arestemple](https://t.me/arestemple) |
| YouTube 教程 | 安装和使用视频 | [观看视频](https://www.youtube.com/watch?v=s-ATfXR8BpI) |
| GitHub Issues | 可复现的问题与功能建议 | [提交 Issue](https://github.com/baoweise-bot/aimili-vpngate/issues) |

<a id="legal"></a>
## 使用范围与法律声明

> [!CAUTION]
> 下载、部署或使用本项目即表示您应自行确认用途符合所在地法律、VPS 所在地法律、网络服务商条款及 VPNGate 的相关规则。以下内容是项目使用边界，不构成法律意见，也不能保证免除任何个人或组织依法应承担的责任。

1. **限定用途**：本项目仅用于合法的网络研究、教育、开发测试、隐私保护和经授权的网络访问，不得用于绕过依法实施的监管措施、未授权访问、攻击、扫描、垃圾信息、欺诈、侵权或其他违法活动。
2. **网络与地区限制**：不同地区和数据中心可能限制 VPNGate、GitHub 镜像或远端 VPN 节点。本项目不承诺任何地区或机型始终可用；仅应在当地法律和服务商条款允许的环境中合理使用。
3. **第三方节点**：VPNGate 节点由第三方志愿者运营，本项目不拥有、不控制也不审核这些节点，无法保证其稳定性、速度、安全性、隐私政策或日志行为。请勿通过不可信节点传输账号密码、金融信息、商业机密等敏感数据。
4. **用户责任**：节点选择、流量内容、部署位置、端口开放和账号安全均由使用者负责。因违法使用、配置不当、第三方节点、服务中断、数据泄露或账号滥用产生的后果，由使用者依法承担。
5. **无保证提供**：软件按“现状”提供，在适用法律允许的最大范围内，维护者不对可用性、适销性、特定用途适用性或间接损失作出保证。无法依法排除的责任不受本声明影响。
6. **不确定时停止使用**：如无法确认当地法律或服务商是否允许，请停止部署和使用，并咨询当地有执业资格的法律专业人士。

<div align="center">

[正式版本](https://github.com/baoweise-bot/aimili-vpngate/releases/latest) · [问题反馈](https://github.com/baoweise-bot/aimili-vpngate/issues) · [GPL-3.0 License](LICENSE)

</div>
