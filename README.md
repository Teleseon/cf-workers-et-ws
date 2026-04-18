# EasyTier WebSocket for Cloudflare Workers

## 项目简介

该项目是 EasyTier 的第三方服务端实现。EasyTier 是一个去中心化 P2P 组网程序，官方代码使用 Rust 实现。本项目使用 Cloudflare Worker + Durable Object 实现了 JavaScript 版本的 WebSocket 服务端，支持网络转发与 P2P 打洞信息交换。

项目使用 Claude/Deepseek/Gemini 进行开发，目前处于早期阶段，还存在很多问题。

> **注意：本项目仅供学习交流使用**

## 🚀 核心改进特性

### ✅ 彻底消灭幽灵节点
- **秒级断线检测**：最快 25 秒检测到断线设备
- **实时设备列表刷新**：断线设备立即从所有客户端消失
- **全局单调递增版本号**：防止 P2P 交叉污染和版本回退

### ✅ 增强网络稳定性
- **延迟优先模式**：特权标志位加速路由收敛
- **私有网络支持**：通过环境变量配置私有模式
- **更好的客户端兼容性**：修复 Protobuf 握手包问题


## 技术架构

- 基于 Cloudflare Workers 和 Durable Objects
- 使用 WebSocket 协议进行实时通信
- 采用 Protocol Buffers 进行高效序列化
- 支持消息加密与完整性保护
- 模块化设计，便于扩展和维护

## 开发环境搭建

### 前置要求

- Node.js (>= 16.0.0)
- pnpm (推荐) 或 npm
- Wrangler CLI (Cloudflare Workers 工具链)

### 一键安装

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=[https://github.com/Teleseon/cf-workers-et-ws])

### 手动安装步骤

1. 克隆项目仓库：
```bash
git clone <your-repo-url>
cd easytier-ws-relay
```

2. 安装依赖：
```bash
pnpm install
# 或者使用 npm
npm install
```

3. 安装 Wrangler CLI：
```bash
npm install -g wrangler
```

4. 登录 Cloudflare：
```bash
wrangler login
```

## 本地开发

### 启动开发服务器

```bash
# 启动本地开发服务器
pnpm run dev
# 或者
wrangler dev --ip 0.0.0.0
```

### 直接启动（不监听文件变化）

```bash
pnpm run start
# 或者
wrangler dev
```

## 部署到 Cloudflare

### 部署命令

```bash
# 部署到 Cloudflare Workers
wrangler deploy
```

### 配置说明

项目使用 [wrangler.toml](file:///Users/runner/work/easytier/easytier/easytier-v3/easytier-ws-relay/wrangler.toml#L0-L0) 文件进行配置，主要配置项包括：

- [name](file:///Users/runner/work/easytier/easytier/easytier-v3/easytier/src/cli/main.rs#L0-L0): Worker 名称
- [main](file:///Users/runner/work/easytier/easytier/easytier-v3/easytier/src/cli/main.rs#L0-L0): 入口文件路径
- [compatibility_date](file:///Users/runner/work/easytier/easytier/easytier-v3/easytier/src/cli/main.rs#L0-L0): 兼容性日期
- Durable Objects 配置
- 环境变量配置

## 项目结构

```
easytier-ws-relay/
├── protos/                 # Protocol Buffers 定义
│   ├── google
│   │   └── protobuf
│   │       └── timestamp.proto
│   ├── common.proto        # 通用协议定义
│   ├── error.proto         # 错误协议定义
│   └── peer_rpc.proto      # 对等节点 RPC 协议定义
├── src/
│   ├── worker/             # Worker 实现
│   │   ├── core/           # Worker 核心功能
│   │   │   ├── basic_handlers.js   # 基础处理器
│   │   │   ├── compress.js         # 压缩功能
│   │   │   ├── constants.js        # 常量定义
│   │   │   ├── crypto.js           # 加密功能
│   │   │   ├── packet.js           # 数据包处理
│   │   │   ├── peer_manager.js     # 对等节点管理
│   │   │   ├── protos.js           # Protobuf 相关功能
│   │   │   ├── global_state.js     # 全局状态管理器
│   │   │   ├── protos_generated.js # Protobuf 生成的代码
│   │   │   └── rpc_handler.js      # RPC 处理器
│   │   └── relay_room.js           # 中继房间实现
│   └── worker.js                   # Worker 入口文件
├── package.json            # 项目配置
├── wrangler.toml           # Cloudflare Workers 配置
└── README.md               # 项目说明
```

## 功能特性

- WebSocket 双向通信中继
- 基于 Room 的连接管理
- 使用 Protobuf 进行高效序列化
- 消息加密与完整性保护
- 客户端状态管理与心跳维持
- RPC 请求/响应处理机制

## 🔧 技术实现亮点

### 幽灵节点问题彻底解决

原版代码存在严重的"幽灵节点"问题：设备断线后仍然显示在列表中。本版本通过以下核心修复彻底解决了这个问题：

### 私有网络支持
- **网络名称校验**：配置私有网络名后，客户端必须使用相同网络名才能连接
- **动态服务器标志**：根据配置自动判断是否为公开服务器
- **更好的兼容性**：移除 `features` 字段，避免与官方客户端冲突

## 环境变量配置

在 `wrangler.toml` 的 `[vars]` 中配置以下参数：

### 基础配置
- `EASYTIER_DISABLE_RELAY`: `"1"` 开启纯 P2P，默认 `"0"`
- `EASYTIER_COMPRESS_RPC`: `"0"` 关闭 RPC 压缩（调试用），默认 `"1"`
- `WS_PATH`: WebSocket 路径，默认 `"ws"`

### 心跳与超时配置（解决幽灵节点问题）
- `EASYTIER_HEARTBEAT_INTERVAL`: 心跳间隔（毫秒），默认 `10000`（10 秒）
- `EASYTIER_CONNECTION_TIMEOUT`: 连接超时（毫秒），默认 `25000`（25 秒）

### 高级功能配置
- `EASYTIER_NETWORK_NAME`: 私有网络名称，留空为公开服务器
- `EASYTIER_LATENCY_FIRST`: `"1"` 开启延迟优先模式，默认 `"0"`

修改完配置后按正常方式运行 `wrangler dev` 测试或 `wrangler deploy` 部署即可生效。

## Durable Object 地区配置

Durable Object 默认会根据请求来源自动选择最近的地区部署。如需指定地区，可在 `wrangler.toml` 的 `[vars]` 中配置：

- `LOCATION_HINT`: Durable Object 的位置提示，可选值如下：

| 参数 | 地区 |
|------|------|
| `wnam` | 西部地区（北美） |
| `enam` | 东部地区（北美） |
| `sam` | 南美洲 |
| `weur` | 西欧 |
| `eeur` | 东欧 |
| `apac` | 亚太地区（默认） |
| `oc` | 大洋洲 |
| `afr` | 非洲 |
| `me` | 中东 |

> 详细说明请参考 [Cloudflare 官方文档](https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1)

修改完配置后按正常方式运行 `wrangler dev` 测试或 `wrangler deploy` 部署即可生效。

## 客户端连接说明

部署后，EasyTier 客户端连接地址需要添加路径 `/ws`。

默认情况下，WebSocket路径为`/ws`，该路径可以在`wrangler.toml`中通过`WS_PATH`变量进行自定义。

easytier中端口号使用0为使用协议默认端口，ws对应80，wss对应443。

开发模式:
```
ws://your-network-ip:0/ws
```
部署后:
```
wss://your-deployment.workers.dev:0/ws
```

## 贡献

本项目在 IceSoulHanxi/easytier-ws-relay 的基础上进行了重大改进，主要解决了原版存在的"幽灵节点"问题。

### 主要改进内容

1. **彻底修复幽灵节点问题**
   - 秒级断线检测和实时设备列表刷新
   - 全局单调递增版本号机制
   - 主动清理和防抖保护

2. **增强网络稳定性**
   - 延迟优先模式
   - 私有网络支持
   - 更好的客户端兼容性


欢迎提交 Issue 和 Pull Request 来进一步改进本项目。

## 许可证

[MIT License](./LICENSE)

## 免责声明

本项目仅供学习交流使用，请勿用于任何商业用途或非法用途。使用本项目代码造成的任何后果，原作者概不负责。
