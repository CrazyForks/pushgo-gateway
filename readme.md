# PushGo Gateway

PushGo Gateway is a lightweight push gateway for PushGo. It manages channel subscriptions, receives push requests, and sends notifications directly to APNs and FCM.

## Project Links

- Gateway (this repo): https://github.com/AldenClark/pushgo-gateway
- Apple platforms (iOS/macOS/watchOS): https://github.com/AldenClark/pushgo
- Android app: https://github.com/AldenClark/pushgo-android

## Binary Roles

This repository builds two binaries:

- `pushgo` (public gateway): requires APNs/FCM credentials and serves Token APIs.
- `pushgo-gateway` (self-hosted gateway): fetches Tokens and sends notifications directly to APNs/FCM.

Only `pushgo-gateway` is published in OSS releases and Docker images.

## Public Gateway vs Self-Hosted

By default, a self-hosted gateway pulls APNs/FCM Tokens from the public gateway at `https://gateway.pushgo.dev`, then sends notifications directly to APNs/FCM.

## Configuration

All options can be set via env vars or CLI flags (where available).

- `PUSHGO_HTTP_ADDR` (optional, HTTP bind address, default: `127.0.0.1:6666`; for Docker use `0.0.0.0:6666`)
- `PUSHGO_TOKEN` (optional, auth Token, required if you enable gateway authentication)
- `PUSHGO_GATEWAY_URL` (optional, public gateway URL, default: `https://gateway.pushgo.dev`)
- `MAX_CONCURRENT` (optional, max concurrent requests, default: `200`, set to 0 to disable rate limits)
- `DATA_PATH` (optional, redb data path, only used when database is `redb`, default: `./data`)
- `PUSHGO_DB_URL` (optional; supports `postgres`/`mysql`; empty uses `redb`)

## Deployment

### Docker

GHCR and Docker Hub are both supported.

GHCR:

```bash
docker run --rm -p 6666:6666   -e PUSHGO_TOKEN=YOUR_TOKEN   ghcr.io/aldenclark/pushgo-gateway:latest
```

Docker Hub:

```bash
docker run --rm -p 6666:6666   -e PUSHGO_TOKEN=YOUR_TOKEN   aldenclark/pushgo-gateway:latest
```

### Systemd

This section deploys `pushgo-gateway` as a systemd service. It assumes you have a `pushgo-gateway` binary from a release or a local build.

`deploy/pushgo-gateway.service` is a systemd service example. Edit the environment variables inside if needed.

1. Create a dedicated user and directories:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pushgo
sudo mkdir -p /var/lib/pushgo-gateway
sudo chown -R pushgo:pushgo /var/lib/pushgo-gateway
```

2. Install the binary:

```bash
sudo install -m 0755 ./pushgo-gateway /usr/local/bin/pushgo-gateway
```

3. Install the service file and start:

```bash
sudo cp ./deploy/pushgo-gateway.service /etc/systemd/system/pushgo-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now pushgo-gateway
```

Check status:

```bash
systemctl status pushgo-gateway
```

## Authentication

If you set a Token, all API requests must include the header:

```
Authorization: Bearer <token>
```

# PushGo Gateway（中文）

PushGo Gateway 是为 PushGo 开发的轻量推送网关。它管理客户端的频道订阅数据，接收消息推送请求，并直接向 APNs 和 FCM 发送通知。

## 项目链接

- 网关（本仓库）：https://github.com/AldenClark/pushgo-gateway
- Apple 平台（iOS/macOS/watchOS）：https://github.com/AldenClark/pushgo
- Android App：https://github.com/AldenClark/pushgo-android

## 二进制角色说明

本仓库会生成两个二进制：

- `pushgo`（公共网关）：需要 APNs/FCM 证书，提供 Token 服务接口。
- `pushgo-gateway`（自部署网关）：获取 Token 并直接向 APNs/FCM 发起推送。

开源镜像与发布包只提供 `pushgo-gateway`。

## 公共网关与自部署关系

默认情况下，自部署网关从公共网关 `https://gateway.pushgo.dev` 获取 APNs/FCM Token，并直连 APNs 和 FCM 发送通知。

## 配置

所有选项支持环境变量或 CLI 参数（如有）。

- `PUSHGO_HTTP_ADDR`（可选，HTTP监听地址，默认：`127.0.0.1:6666`）
- `PUSHGO_TOKEN`（可选，认证令牌，启用网关鉴权时必填）
- `PUSHGO_GATEWAY_URL`（可选，公共网关地址，默认：`https://gateway.pushgo.dev`）
- `MAX_CONCURRENT`（可选，网关最大允许并发处理的请求书，默认：200，设为 0 关闭限流 ）
- `DATA_PATH`（可选，redb数据库文件路径，仅数据库为redb时有效，默认：`./data`）
- `PUSHGO_DB_URL`（可选；支持 `postgres`/`mysql` ，为空则默认 `redb`）

## 部署

### Docker

GHCR 与 Docker Hub 两个镜像源可选。

GHCR：

```bash
docker run --rm -p 6666:6666 \
  -e PUSHGO_TOKEN=YOUR_TOKEN \
  ghcr.io/aldenclark/pushgo-gateway:latest
```

Docker Hub：

```bash
docker run --rm -p 6666:6666 \
  -e PUSHGO_TOKEN=YOUR_TOKEN \
  aldenclark/pushgo-gateway:latest
```

### Systemd

该方式部署 `pushgo-gateway` 的 systemd 服务，假设你已获得 `pushgo-gateway` 二进制（release 或本地构建）。

`deploy/pushgo-gateway.service` 是systemd service示例，如有需要，请自行修改其内容。

1. 创建用户与目录：

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pushgo
sudo mkdir -p /var/lib/pushgo-gateway
sudo chown -R pushgo:pushgo /var/lib/pushgo-gateway
```

2. 安装二进制：

```bash
sudo install -m 0755 ./pushgo-gateway /usr/local/bin/pushgo-gateway
```

3. 安装服务文件并按需修改其中的环境变量：

```bash
sudo cp ./deploy/pushgo-gateway.service /etc/systemd/system/pushgo-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now pushgo-gateway
```

查看状态：

```bash
systemctl status pushgo-gateway
```

## 鉴权

如果设置了 Token，所有 API 请求需要携带以下请求头：

```
Authorization: Bearer <token>
```
