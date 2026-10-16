# 智慧校园平台越权漏洞审计 — 授权测试方法学与工具链

> ⚠️ **免责声明 / Disclaimer**
>
> 本项目是**已授权安全测试**的方法论沉淀与教学复现。所有数据均已**脱敏处理**：
> 人名替换为虚构姓名、用户 ID 做稳定哈希替换、目标域名统一为 `TARGET.example.edu`、
> 会话凭据与 JWT 全量清除。**不包含任何可用于识别真实个人、学校或系统的原始信息。**
>
> 本项目仅用于安全研究与防御目的。请勿将其中方法用于未授权系统。

---

## 📌 项目简介

对一套智慧校园平台（SSO 单点登录 + 业务网关架构）的完整授权安全评估产出。
核心发现是一个**平台级鉴权配置缺陷**：SSO 签发的 JWT 中，所有学生角色账号的
`menuPermission` 被统一赋值为 `*:*:*` 通配全权限，导致低权限学生会话可以读取
全校教职工名录、请假记录、住宿管理、校长信箱等敏感业务数据。

| 项目 | 内容 |
|------|------|
| 漏洞类型 | 水平/垂直越权 + 鉴权配置缺陷（Broken Access Control） |
| 根因 | JWT 权限声明 `menuPermission: ["*:*:*"]` 通配赋权 |
| 影响面 | 平台全部 `roleAlias=1`（学生）账号 |
| 危害等级 | 高危（未授权读取批量个人敏感信息） |
| 目标 SchoolID | `SCHOOL-REDACTED` |

---

## 🔍 核心发现

### 1. 根因：JWT 通配授权

对 SSO 的 `auth_token`（HS256 JWT，payload 未验签即可读）做离线解析，
发现 **4 个学生账号**的权限声明如下：

| 账号 | userId | memberId | roleAlias | menuPermission | rolePermission |
|---|---|---|---|---|---|
| 学生 A | -1903234 | 2177485 | 1（学生） | `["*:*:*"]` | `["1"]` |
| 学生 B | -4898513 | 5467804 | 1（学生） | `["*:*:*"]` | `["1"]` |
| 学生 C | -1718693 | 2743935 | 1（学生） | `["*:*:*"]` | `["1"]` |
| 学生 D | **8646974** | 8721727 | 1（学生） | `["*:*:*"]` | `["1"]` |

**4 个账号的 `menuPermission` 全部是 `*:*:*` —— 通配全权限。**

> **一处值得注意的结构差异**
> 前三个账号 `userId` 为**负数**，第四个为**正数**，且 `memberId` 段位也不同。
> 说明平台内**存在两套 `userId` 命名空间**，因此
> **`userId` 的正负号不能作为账号类型的判据** —— 第四个账号虽为正数，
> `roleAlias` 仍为 `1`（学生），权限声明与其余三个完全一致。
> 这印证了缺陷与账号来源、开户渠道无关。

### 2. 实际放行的敏感接口

以学生身份会话实际探测（1041 个接口 CODE，排除写操作 253 个）：

| 接口 CODE | 数据内容 | 返回条数 | 判定 |
|---|---|---|---|
| `I_CORE_QUERY_TEACHER_LIST` | 教职工名录（姓名 + 手机号） | 746 | ⚠ 放行 |
| `I_OA_QUERY_LEAVE_LIST` | 请假记录（含病假/产假事由） | 5 | ⚠ 放行 |
| `I_MULTI_OVERNIGHT_PAGE` | 学生留宿记录（含原因） | 5 | ⚠ 放行 |
| `I_DORM_DORM_QUIT_PAGE` | 学生退宿记录（含原房间号） | 5 | ⚠ 放行 |
| `I_REST_DORMITORY_PAGE` | 学生调宿记录 | 5 | ⚠ 放行 |
| `I_REPORT_BOX_LIST` | 校长信箱来信全文 | 5 | ⚠ 放行 |
| `I_CONSUME_..._EXPORT` | 导出任务列表（含 `respUrl` 下载链接） | 5 | ⚠ 放行 |

### 3. 鉴权对照组（有差分）

| 测试条件 | rescode | 返回条数 | 服务端消息 |
|---|---|---|---|
| 完整会话 | 10000 | 2 | SUCCESS |
| **去掉 JWT (authorization)** | 10000 | 2 | SUCCESS |
| x-token 置空 | 406 | 0 | 鉴权失败,请重试[01] |

**结论：** JWT 授权头缺失**不影响数据返回** —— JWT 鉴权在该链路上形同虚设；
真正的拦截点是 `x-token`。

---

## 🔬 方法论亮点

### 三态判定口径（避免误判）

本次审计刻意区分三种状态，**禁止把「未能判定」当作「已安全」**：

| 状态 | 含义 | 处置 |
|---|---|---|
| ⚠ **放行** | 会话成功读到数据 | 确为越权，需整改 |
| **已拦截** | 服务端明确拒绝（403/406） | 鉴权生效 |
| **未能判定** | 服务端报「参数不足」 | ≠ 安全，需补参数复测 |

### 自查工具的自我审计（诚实边界）

配套的 `校方自查工具` 承诺「不调用写操作接口」，通过正则过滤：

```python
WRITE_VERBS = re.compile(
    r"_(ADD|EDIT|UPDATE|DELETE|SAVE|MODIFY|CREATE|IMPORT|SET|BIND|"
    r"REMOVE|RESET|GRANT|REVOKE|EXPORT|SYNC|PUSH|CANCEL|AUDIT|APPROVE|"
    r"SUBMIT|INSERT|DROP|CLEAR|MOVE|COPY|SEND)(?=_|$)", re.I)
```

**但该承诺不成立** —— 正则只覆盖 25 个动词，网关实际写动词远不止。
漏判的动词包括：

| 漏掉的动词 | 语义 | 漏判示例 |
|---|---|---|
| `HANDLE` | 处理/审批（改状态） | `I_REST_DORMITORY_HANDLE` |
| `COMPLETE` | 办结（改状态） | `I_MULTI_OVERNIGHT_COMPLETE` |
| `EXECUTE` | 执行流程 | `I_ACTIVITI_FLOWTASK_FLOWTASKEXECUTE` |
| `_PROC` | 流程处理 | `I_OA_LEAVE_HANDLE_PROC` |
| `CONFIRM` | 确认（改状态） | `I_NZP_REST_VISITOR_ORDER_CONFIRMVISITORIN` |
| `RECYCLE` | 回收/删除 | `I_DOC_DOC_RECYCLEBIN_RECYCLE` |
| `LOCK` / `VALIDATE` | 锁定 / 校验落库 | `I_DOC_DOC_LOCK_FILE` |

> **教训：** 用正则黑名单做写操作隔离是**不安全的设计** —— 应采用
> **白名单**（仅允许显式读语义）而非黑名单。

---

## 🛠️ 工具链

| 脚本 | 功能 |
|---|---|
| `recon/js*.py`, `recon/jsdeep.py` | 前端 JS 逆向：抽取 API path、密钥、隐藏路由 |
| `recon/jwt_idor.py`, `recon/jwt2.py` | JWT 离线解析与权限声明提取 |
| `recon/gw_*.py` | 业务网关 CODE 枚举、调用与差分测试 |
| `recon/privesc*.py` | 垂直越权/提权路径试探 |
| `recon/authz.py`, `recon/auth_test.py` | 鉴权矩阵探测 |
| `recon/xss.py`, `recon/lfi.py`, `recon/inject.py` | 常规 Web 漏洞验证 |
| `校方自查工具_越权检测.py` | 提供给甲方的自查脚本（含上述写操作过滤缺陷） |

---

## 📂 目录结构

```
.
├── README.md                         本文件
├── 资产/                             接口清单、靶标列表
├── 报告/                             正式报告（md / pdf / html）
├── js/                               提取的前端 JS（.save）
└── hsfz-audit-2026-09-20/
    ├── 华附官网安全评估报告.md
    ├── 校方通报_智慧校园越权漏洞.md
    ├── 梯队接口可达性复测报告.md
    ├── recon/                        探测脚本与原始输出
    └── 自查结果/                     脱敏后的结果数据集（csv / json）
```

---

## 💡 给防御方的建议

1. **最小权限原则**：`menuPermission` 应按角色粒度下发，禁止 `*:*:*` 通配
2. **服务端鉴权**：SSO JWT 只做身份传递，**业务网关必须独立做权限校验**（勿信赖 payload 中的权限字段）
3. **失效鉴权要拦截**：JWT 授权头缺失时应返回 401，而非放行
4. **敏感列表默认脱敏**：名录类接口默认对手机号等字段掩码
5. **写操作隔离用白名单**：不要用正则黑名单过滤写动词

---

## 👤 Author

**Harrison Yin** — Security Researcher

- GitHub: [@itsyhx](https://github.com/itsyhx)
- 方向：黑盒 SRC 挖洞 / 白盒代码审计 / IoT 安全

技术若有害则用之有度，若有利则用之无尽。
