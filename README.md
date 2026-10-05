# Audit Log — 公开契约（baseline）

**可验证审计日志**：条目成链（每条提交前一条的哈希），并发布 Merkle 根与**包含证明**，第三方可离线校验单条条目。
本次基线只实现最小可用子集，后续任务在此契约之上继续建设。

## 运行

```bash
PYTHONPATH=src python3 -m auditlog.app --port 18899
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Python 3.12，**仅标准库**；`127.0.0.1`；状态在进程内存中。

## 哈希与树（必须逐字实现，否则证明不可互验）

- 规范化 JSON：`sort_keys=True, separators=(",", ":")`，UTF-8。
- 叶哈希：`sha256(0x00 || canonical_json(payload))`
- 内部节点：`sha256(0x01 || left_hex || right_hex)`
- **条目哈希**：`sha256(prev_entry_hash_hex || leaf_hash_hex)`（链）
- Merkle 根：自底向上两两配对；**某层为奇数时复制最后一个节点**；空日志的根是 `64 个 0`。

## 接口

### `GET /health`
`200 {"status":"ok"}`

### `POST /v1/entries`
请求体：`{"payload": <JSON 对象或数组>}` → **`201`** `{"entry": {"index","hash","prev_hash","payload"}, "root": <hex>, "size": <int>}`。
`payload` 缺失/为 null/是标量 ⇒ `400 invalid_request`。

### `GET /v1/entries/{index}`
`200 {"index","hash","prev_hash","payload"}`；越界 ⇒ `404 not_found`；`index` 非非负整数 ⇒ `400`。

### `GET /v1/proof/inclusion/{index}`
`200 {"index","entry_hash","size","root","proof":[{"position":"left|right","hash":<hex>}, ...]}`
（`position` 表示**兄弟节点在左还是在右**；校验时按此顺序拼接）。

### `GET /v1/root`
`200 {"root": <hex>, "size": <int>}`

## 错误语义

```json
{"error": {"code": "invalid_request|not_found|internal_error", "message": "<可读说明>"}}
```

## 未实现（后续任务候选，非固定题单）

一致性证明（两个大小之间）、封存与外部锚定、证据导出与离线校验器、签名与密钥轮换、保留策略与裁剪、
并发追加下的树一致性、批量校验与分页、与外部时间源绑定、失败注入与审计。
