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
- 封存标识：`sha256(0x02 || canonical_json({external_ref, external_time, root, size}))`
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

### `GET /v1/evidence/{index}`
可移植的**单条证据导出**：一次返回第三方离线校验所需的完整材料。
- `index` 只接受十进制非负整数（`0-9`，无空白、正负号、小数、指数或其他进制写法），否则 `400 invalid_request`；
  `index >= 当前条目数` 返回 `404 not_found`。
- `200`：
```json
{"entry": {"index","hash","prev_hash","payload"}, "size": <int>, "root": <hex>,
 "proof": [{"position":"left|right","hash":<hex>}, ...]}
```
  `entry` 结构同追加入口返回；`size`、`root` 为请求处理时**一次锁定读取**得到的前缀大小与 Merkle 根；
  `proof` 为该条目到根的包含证明（从叶到根，`position` 表示兄弟节点在当前节点左侧或右侧，`hash` 为
  64 位小写十六进制）。后续追加只扩大日志，不改变已返回证据的有效性。
- 离线校验：`verify_entry_evidence(evidence) -> bool`，纯函数，不访问网络或进程状态，只凭证据对象与
  上述哈希规则判断。字段缺失/多余、类型错误、非法 `size`/`index`/哈希、`payload` 不是 JSON 对象或数组
  （空对象 `{}` 与空数组 `[]` 合法）、首条 `prev_hash` 不为 64 个 0、`entry.hash` 与
  `sha256(prev_hash || leaf_hash(payload))` 不一致、或包含证明结合 `size` 重算不等于 `root`，
  一律返回 `False`，且不抛异常；合法证据还要求 `index < size`。

### `GET /v1/evidence/by-hash/{entry_hash}`
与按索引导出**完全等价**的单条证据，只是用条目链哈希（`entry.hash`）寻址，供只知道某条链哈希、
不知道其在本次日志中下标的外部校验方使用。
- 路径只能是 `/v1/evidence/by-hash/<64 字符>`：`entry_hash` 只接受由 `0-9`、`a-f` 组成的恰好 64 位
  小写十六进制字符串；大写、空白、正负号、短长度、长长度、非十六进制字符或其他写法一律
  `400 invalid_request`。缺少/增加路径段（如 `/v1/evidence/by-hash`、`/v1/evidence/by-hash/<hash>/x`）
  或附带任何查询参数（含空查询串）同样 `400 invalid_request`。请求体不参与匹配，GET 不读取请求体，
  也不得改变命中、未命中或格式错误的结果。
- 格式正确但当前日志中不存在该链哈希 ⇒ `404 not_found`；查询为只读：不追加、不消耗新索引，
  命中失败不留下任何可观察状态。
- `200`：响应对象与 `GET /v1/evidence/{index}` **结构完全相同**——
```json
{"entry": {"index","hash","prev_hash","payload"}, "size": <int>, "root": <hex>,
 "proof": [{"position":"left|right","hash":<hex>}, ...]}
```
  `entry.index` 是该链哈希在本次日志中的唯一下标；`size`、`root`、`proof` 与 `entry` 在**一次锁定
  读取**的同一前缀快照上确定，并发追加不会把不同前缀的材料拼进同一响应。`proof` 可直接交给
  `verify_entry_evidence` 离线验证；后续追加只扩大日志，已返回证据的 `size`、`root`、`proof` 固定
  不变，证据长期有效。

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

### `POST /v1/seals`
可验证的**封存与外部锚定**：把调用方提供的外部引用与外部时间绑定到创建时一次锁定的当前 `(size, root)`。
- 请求体**只能**含 `external_ref` 与 `external_time` 两个字段（多、少均为 `400 invalid_request`）：
  - `external_ref`：非空字符串；
  - `external_time`：严格 UTC RFC3339 的 `YYYY-MM-DDTHH:MM:SSZ`（真实合法日期时间），不接受本地时间、
    时区偏移、小数秒、空白或任何非标准写法。
- 服务不引入网络时间源、持久化文件或签名密钥，也不修改冻结文档；时间与引用完全由调用方提供。
- **`201`**：
```json
{"seal_id": <hex64>, "size": <int>, "root": <hex>,
 "external_ref": <string>, "external_time": "YYYY-MM-DDTHH:MM:SSZ"}
```
  返回记录**只含**上述五个字段；`size`、`root` 为本次调用在一次锁定读取中确定的前缀大小与 Merkle 根
  （空日志为 `size: 0` 与 64 个 0 的根）。后续追加不得改变已返回的封存记录。
- `seal_id`：对字段 `external_ref`、`external_time`、`root`、`size` 的对象按
  `sort_keys=True, separators=(",", ":")`、`ensure_ascii=False` 生成 UTF-8 规范 JSON，再计算
  `sha256(0x02 || canonical_json)` 的 64 位小写十六进制值。

### `GET /v1/seals/{seal_id}`
- `seal_id` 只接受 64 位小写十六进制；格式错误（含大写、长度不符、非 hex 字符）⇒ `400 invalid_request`；
  不存在 ⇒ `404 not_found`。
- `200`：返回与创建时一致的完整封存记录（五个字段，值不变）。
- 离线校验：`verify_seal(seal) -> bool`，纯函数，不访问网络、进程状态或日志，只凭传入对象判断，且不抛异常。
  对象必须**恰好**有 `seal_id`、`size`、`root`、`external_ref`、`external_time` 五个字段；`size` 为非负整数
  且不是布尔值，`root` 与 `seal_id` 为 64 位小写十六进制，`external_ref` 为非空字符串，
  `external_time` 符合同一严格 UTC 格式，且 `seal_id` 与按上述规则重算的值一致。任何字段缺失/多余、
  类型或格式错误、摘要不一致，一律返回 `False`。

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

签名与密钥轮换、保留策略与裁剪、
并发追加下的树一致性、与外部时间源绑定、失败注入与审计。
