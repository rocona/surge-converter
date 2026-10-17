# Surge 节点订阅转换器

一个轻量的 Node.js 服务：给它一个 HTTP(S) 订阅地址或单个分享链接，服务会将能转换的节点整理成 Surge 配置，并提供一个可在 Surge 中持续更新的订阅 URL。根路径返回最小完整配置，`/node` 只返回节点定义。

## 支持范围

- 分享链接：Shadowsocks、VMess、Trojan、Hysteria2、TUIC。
- Clash YAML：以上协议，以及 HTTP、SOCKS5 节点。
- 其他协议和不能安全映射的传输方式会跳过；例如 VLESS、SSR、VMess gRPC。
- 如果源订阅没有可转换的节点，会返回 HTTP 422 和简短说明，不会返回空节点列表。

节点能否连接仍取决于 Surge 版本及节点参数。转换器不修改节点信息，也不提供代理服务。

## 部署到 Zeabur

1. 将本目录推送到 Git 仓库。
2. 在 Zeabur 新建项目并从该仓库创建服务，根目录选择本项目目录（若仓库根目录就是本项目则无需设置）。Zeabur 会检测并构建 `Dockerfile`。
3. 为服务生成域名。服务默认监听 `0.0.0.0:8080`，同时兼容 Zeabur 提供的 `PORT` 环境变量；无需填写其他密钥或环境变量。
4. 打开部署域名的根路径，粘贴你的订阅 URL，页面会生成 Surge 可拉取的转换地址。

也可以直接使用：

```text
https://你的-zeabur-域名/?url=https%3A%2F%2F订阅地址
```

`url` 参数必须经过 URL 编码。根路径（`/?url=...`）返回完整 Surge 配置；`/node?url=...` 只返回节点定义。为了兼容旧用法，`/sub?url=...` 和 `/convert?url=...` 仍然是节点列表别名。`/healthz` 可用于健康检查。订阅源可为 HTTP(S) 地址，也可为一个 `ss://`、`vmess://`、`trojan://`、`hysteria2://` 或 `tuic://` 分享链接。

## 在 Surge 中使用

根路径返回可直接导入的最小完整配置，包含 `[General]`、`[Proxy]`、`[Proxy Group]` 和 `[Rule]`：

```text
https://你的-zeabur-域名/?url=编码后的订阅地址
```

如果你已有主配置，只想让策略组定期拉取节点，可以使用 `/node`：

```ini
[Proxy Group]
自动选择 = select, policy-path=https://你的-zeabur-域名/node?url=编码后的订阅地址, update-interval=86400
```

`update-interval` 是可选的刷新间隔（秒）；按需设置为 `0` 或省略。参考 Surge 的 [第三方代理提供商说明](https://kb.nssurge.com/surge-knowledge-base/guidelines/proxy-provider) 和 [Policy Including 手册](https://manual.nssurge.com/policy-groups/policy-including.html)。

将节点订阅 URL 与源 URL 都视为密码：任意拿到该转换 URL 的人都可能读取节点凭据；部署平台、反向代理和服务器访问日志也可能记录请求 URL。生产使用时请查看日志保留设置，并避免公开分享转换链接。

## 本地运行

需要 Node.js 22 或更新版本：

```sh
npm ci
npm test
npm start
```

服务默认监听 `http://localhost:8080`。也可以通过环境变量 `PORT` 和 `HOST` 更改监听端口和地址。

Docker 本地运行：

```sh
docker build -t surge-node-converter .
docker run --rm -p 8080:8080 surge-node-converter
```

## 发布 Docker 镜像

仓库包含 `scripts/publish-docker.sh`，默认发布到 `ghcr.io/rocona/surge-converter`，构建 `linux/amd64` 和 `linux/arm64` 两个平台，并推送版本标签和 `latest`：

```sh
docker login ghcr.io
IMAGE=ghcr.io/rocona/surge-converter TAG=v1.0.0 bash scripts/publish-docker.sh
```

常用参数：

- `IMAGE`：镜像地址，默认 `ghcr.io/rocona/surge-converter`。
- `TAG`：版本标签，默认当前 Git 短 SHA；同时会更新 `latest`（当标签不是 `latest` 时）。
- `PLATFORMS`：目标平台，默认 `linux/amd64,linux/arm64`。
- `PUSH=0`：只构建不推送；此时必须指定单个平台，例如 `PUSH=0 PLATFORMS=linux/amd64`。

GitHub Actions 工作流位于 `.github/workflows/docker-publish.yml`。推送到 `main` 或 `v*.*.*` 标签时，会使用 `GITHUB_TOKEN` 自动登录 GHCR 并发布多架构镜像。首次使用时，请在 GitHub 仓库的 **Settings → Actions → General** 确认允许工作流写入 packages。

Zeabur 仍然可以直接从仓库的 `Dockerfile` 构建，不需要先发布镜像。

## 安全与隐私

- 只抓取 HTTP(S) 公网地址，拒绝私有/本地 IP、内网主机名、带用户名密码的源 URL，以及 HTTPS 降级重定向。
- 最多跟随 3 次重定向；请求超时为 15 秒，订阅响应上限为 2 MiB。
- 响应禁用缓存。请自行评估 Zeabur 及其代理层的访问日志策略。
- 转换在每次拉取时实时进行；服务不会主动保存源订阅或转换结果。
