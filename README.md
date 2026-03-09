# Distributed Scanner

基于 Go + Temporal 的综合分布式安全扫描器。

## 功能特性

- **端口扫描** — naabu 封装，支持 SYN/Connect/UDP，Full/Top100/Top1000/自定义端口策略，按 IP×端口段分片并行
- **子域名枚举** — subfinder 封装，聚合 crt.sh + DNS 爆破，支持前端配置各数据源 API Key
- **指纹识别** — httpx 封装，技术栈检测、网页截图、响应去重，Host 维度展开支持虚拟主机
- **目录爆破** — ffuf 封装，自定义字典上传/管理，AutoCalibrate 自动过滤误报
- **Web 爬虫** — Rad 封装（CLI），基于 Chromium 智能爬取 SPA/AJAX，结果喂给漏洞扫描
- **漏洞扫描** — nuclei 封装，指纹驱动模板选择，max_time 优雅超时保证结果回传
- **暴力破解** — 协议爆破 (SSH/FTP/RDP/MySQL/MSSQL/Oracle/PostgreSQL/Redis/SMB/Telnet/MongoDB) + Web 表单爆破
- **AWVS 集成** — Fire-and-forget ChildWorkflow，不阻塞主流程，异步轮询结果
- **插件系统** — Go Plugin + YAML PoC 双模式
- **报告导出** — HTML/PDF/JSON 格式

## 架构

```
MasterScanWorkflow
  ├─ 阶段1: 子域名枚举 + DNS 解析 (并行)
  ├─ 阶段2: 构建 Host→IP 映射矩阵
  ├─ 阶段3: 端口扫描 (naabu，分片 Fan-out)
  ├─ 阶段4: 两条并行线
  │   ├─ 线路A: 协议暴力破解
  │   └─ 线路B: Httpx → [ffuf + Rad + Web爆破 + AWVS] → Nuclei
  ├─ 阶段8: 汇合
  └─ 阶段9: 报告生成
```

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Go 1.22+, Gin, Temporal Go SDK, MongoDB Driver |
| 扫描 | naabu, httpx, subfinder, ffuf, nuclei, Rad |
| 爆破 | Go crypto/ssh, 原生协议库 |
| 前端 | React 18, TypeScript, Ant Design, Vite |
| 部署 | Docker, Docker Compose |

## 快速开始

### 前置要求

- Go 1.22+
- Node.js 18+
- Docker & Docker Compose
- MongoDB

### 开发环境

```bash
# 1. 启动基础设施
docker-compose -f deployments/docker-compose.yml up -d temporal temporal-db temporal-ui mongodb

# 2. 启动 API 服务
go run cmd/api/main.go -config configs/config.yaml

# 3. 启动 Worker
go run cmd/worker/main.go -config configs/config.yaml

# 4. 启动前端
cd web && npm install && npm run dev
```

### Docker 一键部署

```bash
docker-compose -f deployments/docker-compose.yml up -d
```

访问:
- 前端: http://localhost
- API: http://localhost:8080
- Temporal UI: http://localhost:8233

## 项目结构

```
├── cmd/
│   ├── api/          # API 服务入口
│   ├── worker/       # Temporal Worker 入口
│   └── cli/          # CLI 工具
├── internal/
│   ├── api/          # HTTP API 层 (Gin)
│   ├── workflow/     # Temporal Workflows
│   ├── activity/     # Temporal Activities
│   ├── scanner/      # 扫描器实现
│   │   ├── naabu/    ├── httpx/    ├── subfinder/
│   │   ├── ffuf/     ├── rad/      ├── nuclei/
│   │   ├── bruteforce/ └── awvs/
│   ├── plugin/       # 插件系统
│   ├── model/        # 数据模型
│   ├── store/        # MongoDB 存储层
│   └── report/       # 报告生成
├── web/              # React 前端
├── configs/          # 配置文件
├── deployments/      # Docker 部署文件
└── dictionaries/     # 内置字典
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/v1/tasks | 创建扫描任务 |
| GET | /api/v1/tasks | 列出任务 |
| GET | /api/v1/tasks/:id | 任务详情 |
| PUT | /api/v1/tasks/:id/pause | 暂停任务 |
| PUT | /api/v1/tasks/:id/resume | 恢复任务 |
| DELETE | /api/v1/tasks/:id | 取消/删除任务 |
| GET | /api/v1/tasks/:id/results | 获取扫描结果 |
| GET | /api/v1/providers | 列出数据源配置 |
| PUT | /api/v1/providers/:name | 配置数据源 API Key |
| GET | /api/v1/dictionaries | 列出字典 |
| POST | /api/v1/dictionaries | 上传字典 |

## License

MIT
