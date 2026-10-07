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

### `GET /v1/proofs/inclusion?snapshot_size=<n>&start=<i>&limit=<m>`
按**固定条目前缀**分页读取包含证明，用于批量证据导出与离线逐条校验。
- 三个参数各出现一次：`snapshot_size`、`start` 为非负十进制整数，`limit` 为 1–100 的十进制整数；
  不得有空白、正负号、小数、指数、非十进制字符、重复参数或未知参数，否则 `400 invalid_request`，且不返回部分页。
- 服务端只按**前 `snapshot_size` 条**条目构造前缀 Merkle 根与证明；日志不足 `snapshot_size`、`start` 大于 `snapshot_size` 均为 `400`。
- 每页在一次锁定读取中确定前缀、根与全部证明；后续追加只会扩大日志，不改变旧 `snapshot_size` 的结果。
- `200`：
```json
{"snapshot_size": <int>, "root": <hex>, "start": <int>, "count": <int>, "next_start": <int|null>,
 "proofs": [{"index","entry_hash","size","root","proof"}, ...]}
```
  `proofs` 按 `index` 升序，每项结构同单条证明，其中 `size`、`root` 对应本页快照；
  `start + count < snapshot_size` 时 `next_start` 为二者之和，否则为 `null`；
  `start == snapshot_size` 时允许 `count` 为 0、`proofs` 为空。同一 `snapshot_size` 的不同页根相同，
  调用方可用返回的 `root` 直接经 `verify_inclusion` 离线校验每项。

### `GET /v1/root`
`200 {"root": <hex>, "size": <int>}`

### `GET /v1/proof/consistency?from=<m>&to=<n>`
两个日志大小之间的 **Merkle 一致性证明**：确认大小为 `m` 的旧前缀仍是大小为 `n` 的新根下的同一段前缀。
- `from`、`to` 各出现一次，为非负十进制整数；不得有空白、正负号、小数、指数、非十进制字符、
  重复参数或未知参数，否则 `400 invalid_request`。`from > to` 或 `to` 超过当前条目数亦为 `400`。
- `200`：`{"from": <int>, "to": <int>, "old_root": <hex>, "new_root": <hex>, "proof": [{"position","hash"}, ...]}`；
  `from == to` 时 `proof` 为空且 `old_root == new_root`；`proof` 节点按**从底到顶**排列，
  `position` 为 `left|right`，`hash` 为 64 位十六进制。根与证明在一次锁定读取中确定，后续追加不改变已返回的结果。
- 离线校验：`verify_consistency(old_size, new_size, old_root, new_root, proof) -> bool`，
  纯函数，只依赖 `leaf_hash`/`node_hash`/`merkle_root` 与上述字段；非法输入（尺寸、长度或十六进制格式错误、
  节点被替换、顺序颠倒等）一律返回 `False`，不抛异常。

## 错误语义

```json
{"error": {"code": "invalid_request|not_found|internal_error", "message": "<可读说明>"}}
```

## 未实现（后续任务候选，非固定题单）

封存与外部锚定、证据导出与离线校验器、签名与密钥轮换、保留策略与裁剪、
并发追加下的树一致性、与外部时间源绑定、失败注入与审计。
