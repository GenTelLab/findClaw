# 君同·抓虾 FindClaw

企业桌面智能体资产发现平台 —— 通过网络扫描与智能指纹识别，自动发现企业内网中的 Claw 家族桌面智能体。

## 快速部署

### Docker Compose（推荐）

```bash
# 克隆项目
cd findclaw

# 一键启动（应用 + PostgreSQL）
docker-compose up -d

# 访问
open http://localhost:8080
```

### 本地开发

```bash
# 安装依赖
pip install -r requirements.txt

# 确保 PostgreSQL 运行，配置环境变量
export FINDCLAW_DATABASE_URL=postgresql+asyncpg://findclaw:findclaw123@localhost:5432/findclaw

# 确保 Nmap 已安装
which nmap

# 启动
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## 技术栈

| 层级 | 技术 |
|------|------|
| 语言 | Python 3.11+ |
| 框架 | FastAPI + Uvicorn |
| ORM | SQLAlchemy 2.0 (async) + asyncpg |
| 数据库 | PostgreSQL 16 |
| 扫描 | Nmap (subprocess) |
| HTTP 探测 | httpx (async) |
| 定时任务 | APScheduler |
| Excel | openpyxl |
| 前端 | 单页 HTML + 原生 JS |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FINDCLAW_DATABASE_URL` | `postgresql+asyncpg://findclaw:findclaw123@localhost:5432/findclaw` | 数据库连接 |
| `FINDCLAW_SERVER_PORT` | `8080` | 服务端口 |
| `FINDCLAW_NMAP_PATH` | `/usr/bin/nmap` | Nmap 路径 |
| `FINDCLAW_NMAP_NSE_SCRIPT_PATH` | `docker/nmap-scripts/claw-detect.nse` | 自定义 NSE 脚本路径 |
| `FINDCLAW_DEFAULT_SCAN_PORTS` | 18 个端口（核心 Claw 架构端口 + 反代端口） | 默认端口 |
| `FINDCLAW_DEFAULT_SCAN_RATE` | `1000` | 默认速率 |
| `FINDCLAW_FINGERPRINT_EXTERNAL_PATH` | 空 | 外部指纹文件路径 |

## 功能

- **全网发现**：输入 IP/网段，两阶段扫描定位 Claw 服务
- **指纹识别**：专属指纹库，精准识别 OpenClaw / AutoClaw / MiniClaw
- **双级研判**：已确认 + 疑似，附置信度评分
- **资产台账**：多维筛选、分页查询、Excel 导出
- **周期巡检**：Cron 定时扫描 + 自动变更感知
- **趋势追溯**：资产数量随时间变化的可视化
- **NSE 侧信号**：结合 `claw-detect.nse` 探测 `/tools/invoke`、`/v1/chat/completions` 等真实 Gateway 端点

## API 文档

启动后访问 `http://localhost:8080/docs` 查看自动生成的 Swagger 文档。
