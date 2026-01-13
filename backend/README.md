# Backend - Kiro API 代理服务

Rust 后端服务，将 Anthropic API 请求转换为 Kiro API 请求。

## 目录结构

| 文件/目录 | 地位 | 功能 |
|----------|------|------|
| `src/main.rs` | 入口 | 程序启动、路由配置 |
| `src/db.rs` | 核心 | SQLite 数据库管理 |
| `src/jwt.rs` | 核心 | JWT 认证 |
| `src/token.rs` | 功能 | count_tokens 处理 |
| `src/http_client.rs` | 工具 | HTTP 客户端构建 |
| `src/model/` | 核心 | 配置和参数模型 |
| `src/model/config.rs` | 核心 | 启动配置（.env） |
| `src/model/runtime_config.rs` | 核心 | 运行时配置（数据库） |
| `src/model/arg.rs` | 核心 | 命令行参数 |
| `src/anthropic/` | 核心 | Anthropic API 兼容层 |
| `src/kiro/` | 核心 | Kiro API 客户端实现 |
| `src/admin/` | 功能 | Admin API 管理接口 |
| `src/common/` | 工具 | 通用工具函数 |
| `Cargo.toml` | 配置 | Rust 项目配置 |
| `.env.example` | 配置 | 环境变量示例 |
| `Dockerfile` | 部署 | Docker 构建配置 |

## 快速开始

```bash
# 复制配置文件
cp .env.example .env

# 构建
cargo build --release

# 运行
./target/release/kiro-rs
```

## 配置说明

### 启动配置（.env）

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `HOST` | 否 | `127.0.0.1` | 监听地址 |
| `PORT` | 否 | `8080` | 监听端口 |
| `API_KEY` | 是 | - | API 密钥 |
| `ADMIN_USERNAME` | 否 | `admin` | 初始管理员用户名 |
| `ADMIN_PASSWORD` | 否 | `admin123` | 初始管理员密码 |
| `DB_PATH` | 否 | `data.db` | 数据库路径 |
| `JWT_SECRET` | 否 | 自动生成 | JWT 密钥 |
| `JWT_EXPIRY_HOURS` | 否 | `24` | JWT 过期时间（小时） |

### 运行时配置（数据库）

以下配置存储在数据库中，通过 Admin 后台管理：

| 键 | 默认值 | 说明 |
|----|--------|------|
| `kiro_version` | `0.8.0` | Kiro 版本号 |
| `system_version` | `darwin#24.6.0` | 系统版本 |
| `node_version` | `v22.12.0` | Node.js 版本 |
| `proxy_url` | - | HTTP 代理地址 |
| `count_tokens_api_url` | - | count_tokens API 地址 |
| `count_tokens_api_key` | - | count_tokens API 密钥 |
| `count_tokens_auth_type` | `x-api-key` | count_tokens 认证类型 |
| `min_usage_threshold` | `5` | 最小使用量阈值 |
