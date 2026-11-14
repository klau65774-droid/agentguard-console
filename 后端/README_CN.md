# LLM Guardrails Gateway（大模型运行时安全护栏与策略治理网关）

> 本项目基于开源项目 [`MANIGAAA27/agentguard`](https://github.com/MANIGAAA27/agentguard)（MIT License）复现并面向中文企业场景及 OWASP LLM Top 10 (2025) 完成深度增强，定位为与离线红队评测集（如 `llm-redteam-portfolio`）及多模型路由层（如 `agent-model-router`）形成闭环的**在线实时防御与 AI 治理控制平面（Control Plane）**。

## 1. 核心架构与请求生命周期

系统采用 **FastAPI + Pydantic v2 + asyncio** 构建单进程高并发微内核控制面，将大模型请求与 Agent 行动全链路拆解为 9 个解耦子系统与三道串并联防线：

```text
用户请求 / Agent 调用
  │
  ├─► HTTP 中间件链 (CorrelationIdMiddleware -> TenantContextMiddleware -> GuardrailLatencyHeaderMiddleware)
  │
  ├─► [1. 输入护栏 Engine] asyncio.gather 7 路并发检查
  │     ├─ prompt_injection (中英文指令覆盖 + Base64 混淆还原, OWASP LLM01)
  │     ├─ jailbreak (中英文越狱/沙盒绕过识别, OWASP LLM01)
  │     ├─ pii_detection (中美敏感信息 + 身份证 ISO 7064 校验码脱敏, OWASP LLM02)
  │     ├─ secret_detection (AWS / GitHub / sk- / 阿里云 LTAI AK 扫描, OWASP LLM02)
  │     ├─ toxicity / restricted_topics / data_exfiltration
  │     └─ 决策聚合器: block > escalate > safe-complete-only > redact > allow
  │
  ├─► [2. Prompt 工程与检索增强]
  │     ├─ prompt_framework (版本化提示词包编译 + RAG_QA/TOOL_USE Linter)
  │     └─ retrieval/grounding (中英文双语 Hybrid BM25 + 词覆盖率溯源检索)
  │
  ├─► [3. 模型网关路由] model_router (OpenAI/Anthropic/Local 适配 + SSE 流式转发 + Redis/内存限流)
  │
  ├─► [4. 输出校验 Engine] asyncio.gather 8 路并发检查 + SlopScore 量化
  │     ├─ schema_validity / citation_check / policy_check / unsafe_language / confidence_threshold
  │     ├─ hallucination_proxy (中英文数值/日期核验 + CJK/ASCII 2-gram Jaccard 重合度)
  │     ├─ canary_leak (Canary 令牌 + 提示词 4-gram 泄露 + <think> 推理标签剥离修复, OWASP LLM07)
  │     ├─ slop_score (四维加权输出质量风险评分 [0, 1])
  │     └─ 决策聚合器: reject > escalate > repair > pass
  │
  └─► [5. Agent 行动治理与合规审计]
        ├─ action_governance (工具白名单 + 参数校验 + 嵌套 SQLi/CMDi/路径穿越深度扫描 + 人工审批)
        ├─ policy/engine (YAML Declarative Policy-as-Code 多条件规则引擎)
        └─ observability (结构化 JSONL 审计日志 / Prometheus 指标 / 评估接口)
```

## 2. 本仓库实现的五项核心工程优化

1. **中英文双语防注入与 Base64 混淆还原 (`LLM01:2025`)**
   - 文件：`src/agentguard/input_guardrails/checks/prompt_injection.py`、`src/agentguard/input_guardrails/checks/jailbreak.py`
   - 机制：`_decode_obfuscated_payloads()` 自动识别并解码可疑 Base64 片段（长度 >= 24、UTF-8 可打印字符占比 >= 85%），将原文与还原载荷合并扫描；补充中文“忽略此前规则/输出系统提示词”、行首 `系统指令：` 角色篡改以及“无限制模式/小说推演绕过”等越狱模式。

2. **中国本地化 PII 精确脱敏与国产云密钥拦截 (`LLM02:2025`)**
   - 文件：`src/agentguard/input_guardrails/checks/pii_detection.py`、`src/agentguard/input_guardrails/checks/secret_detection.py`
   - 机制：新增中国大陆手机号 `phone_cn`（负向数字边界防长串误匹配）与 18 位身份证号 `id_card_cn`，并在触发判定前执行 **ISO 7064:1983 MOD 11-2 校验码**（`_is_valid_cn_id_card`），过滤伪造或普通 18 位订单号误报；在 `secret_detection.py` 新增 OpenAI/DeepSeek `sk-` 与阿里云 `LTAI` AccessKey 规则。

3. **Canary 令牌防泄漏与 `<think>` 推理链脱敏 (`LLM07:2025`)**
   - 文件：`src/agentguard/output_validation/checks/canary_leak.py`、`engine.py`、`schemas.py`、`router.py`
   - 机制：并行输出校验从 7 路升级为 8 路，支持自定义 `canary_tokens` 与 `CANARY-`/`SECRET-CANARY-` 前缀捕获（直接 `reject`）、中英文系统提示词 4-gram 重合度阈值检测（`>= 0.50` `reject`），并针对 DeepSeek-R1 类推理模型检测 `<think>...</think>` 内含敏感提示词或规则泄露时触发 `repair` 并输出剥离后的安全 `repaired_text`。

4. **双语 Hybrid BM25 检索溯源与中文幻觉校验**
   - 文件：`src/agentguard/retrieval/grounding.py`、`src/agentguard/output_validation/checks/hallucination_proxy.py`
   - 机制：引入零外部依赖的 `_tokenize_bilingual`（ASCII 词 + CJK 单字与相邻双字切片），在 `search_documents` 中实现 Hybrid BM25（`k1=1.5, b=0.75`）与查询覆盖率融合置信度评分，内置 3 篇中文企业合规与算力网关知识库文档及 `register_documents` 动态注册接口；同时拓展 `hallucination_proxy` 支持中文人民币金额（`¥/￥/RMB`）、中文日期（`YYYY年M月D日`）与中文双字 Jaccard 重合度检测。

5. **Agent 工具嵌套参数高危载荷扫描与自动化红队基准测试**
   - 文件：`src/agentguard/action_governance/risk_scorer.py`、`scripts/benchmark_redteam_defense.py`
   - 机制：在 `score_action` 中接入 `_scan_param_payload_risk()`，递归遍历多层嵌套字典/列表中的字符串参数值，识别命令注入（`; rm -rf` / `| bash` / `` `...` `` / `$(...)`）、路径穿越（`../` / `/etc/passwd` / `win.ini`）与 SQL 注入（`UNION SELECT` / `DROP TABLE` / `' OR '1'='1`），触发即强制拉升风险分至 `>= 0.90`（`RiskLevel.CRITICAL`）。配套零依赖基准评测脚本生成量化指标报告 `reports/benchmark_summary.json`。

## 3. 快速上手与测试验证

### 安装与启动

```bash
pip install -e ".[dev]"
uvicorn agentguard.main:app --reload
```

### 运行全量测试与红队防线基准脚本

```bash
# 运行全部 100 条单元测试与端到端集成测试
pytest -v

# 检查改写及新增模块代码规范与严格类型
ruff check src/agentguard/input_guardrails/checks/prompt_injection.py \
  src/agentguard/input_guardrails/checks/jailbreak.py \
  src/agentguard/input_guardrails/checks/pii_detection.py \
  src/agentguard/input_guardrails/checks/secret_detection.py \
  src/agentguard/output_validation/checks/canary_leak.py \
  src/agentguard/output_validation/checks/hallucination_proxy.py \
  src/agentguard/output_validation/engine.py \
  src/agentguard/output_validation/schemas.py \
  src/agentguard/output_validation/router.py \
  src/agentguard/retrieval/grounding.py \
  src/agentguard/action_governance/risk_scorer.py \
  tests/test_bilingual_optimizations.py scripts/benchmark_redteam_defense.py

# 运行中英文红队防线量化基准并生成 reports/benchmark_summary.json
python scripts/benchmark_redteam_defense.py
```

## 4. 本地实测基准数据（`reports/benchmark_summary.json`）

| 评估维度 | 实测结果 |
|---|---|
| 全量测试集 (`pytest -v`) | **100 passed, 0 failed**（80 条基线测试 + 20 条增强回归与 API 集成测试） |
| 攻击样本拦截 / 脱敏 / 修复率 | **100.0%（16 / 16）**（涵盖中英文注入、Base64 混淆、越狱、中国 PII/AK、Canary/Think 泄露、工具嵌套注入） |
| 正常对照样本误杀率 (FPR) | **0.0%（0 / 5）**（含伪造 18 位订单号误报防线验证） |
| 单请求本地检查平均延迟 / P95 | **0.08 ms**（平均）/ **0.113 ms**（P95） |

## 5. 关键 API 端点一览

- `POST /v1/guardrails/evaluate-input` — 输入安全护栏并发评估（返回决策、逐项结果与 PII 脱敏文本）
- `POST /v1/outputs/validate` — 输出质量与防泄露并发校验（支持 `system_prompt`、`canary_tokens`、`include_quality_risk_score`）
- `POST /v1/retrieval/search` — 双语知识检索溯源与置信度打包
- `POST /v1/actions/authorize` — Agent 工具调用白名单、嵌套风险评分与审批授权
- `POST /v1/policies/evaluate` — Declarative YAML 策略决策评估
- `POST /v1/gateway/complete` — 带护栏前置/后置拦截的模型推理网关（支持 SSE 流式输出）
- `GET /v1/metrics` — 网关运行期统计指标
