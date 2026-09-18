# Fingerprint regression gate

## Goal

分别验证补丁内容、恢复源码、启动能力与实际接口行为，不用 stock Chrome、旧二进制或 ready stamp 替代当前构建证据。

## Plan

1. 编译前核验实际源文件，防止继续编译旧缓存中的失效补丁。
2. 打包后固定解包 native executable 的 hash、完整版本和探针输入。
3. 所有独立 suite 都运行；失败、超时和缺报告不能掩盖后续诊断。
4. 诊断与发布 ZIP 分开上传，保持发布器只接收 ZIP + SHA256SUMS 的契约。

## Implementation

### 编译前：源码凭据

完成 patch、migration 和 domain substitution 后运行：

```powershell
python -X utf8 tools/verify_patch_stack.py `
  --src C:/build/src --repo D:/C++/Chromix `
  --core C:/build/tooling/ungoogled-chromium `
  --platform-tooling C:/build/tooling/ungoogled-chromium-windows `
  --platform windows --output C:/diagnostics/source-new.json
```

输出必须是 SRC 外的新文件。校验器复制 patch targets 到 scratch，完整 reverse/
forward series，检查新增文件完整删除、逐文件 roundtrip、源 bytes/mtime 和输入
patch hash。CRLF 仅在副本内归一化。未完成标记、错版源码、symlink 或不匹配
hunk 直接失败，不修改 SRC/ready stamp。这是当前 hunks/新文件的结构证明，不是
完整 upstream 或二进制的签名证明。

Windows run `34614380682` 的 StrictNumeric 旧表达式有窄范围幂等迁移；新的
snapshot/display 补丁仍需干净匹配来源，不能靠重写缓存键升级旧源树。

### 打包后：二进制门禁

```powershell
python -X utf8 -m pip install -r tools/fingerprint-requirements.txt
$browser = 'C:/verified/chromix/chrome.exe'
$hash = (Get-FileHash -LiteralPath $browser -Algorithm SHA256).Hash.ToLowerInvariant()
python -X utf8 tools/fingerprint_acceptance.py `
  --browser $browser --expected-sha256 $hash --expected-version 152.0.7977.82 `
  --source-report C:/diagnostics/source-new.json --source-root C:/build/src `
  --output-dir C:/diagnostics/acceptance-new
```

依赖文件只安装测试驱动/解码器，不下载浏览器。必须传 native executable，不是
launcher、ZIP 或 archive hash。上例本地 hash 固定被测文件，不认证其来源。
CI 另负责同一构建的 package 校验和 source receipt 关联。

| Suite | 覆盖 |
|---|---|
| identity | 既有 UA/CH/locale/worker/restart 与基础 surface smoke |
| device | 五 context 执行、SAB/Atomics、GPU 操作、CDP font samples |
| canvas | 既有五 context、三次启动的 codec/color/alpha audit |
| runtime | CDP 几何、真实 OOPIF、时间、生命周期、音频及显式 fake media |
| display_backend | 无初始 CDP viewport，要求 launch UXR 后端生效，再覆盖/缩放 |
| backend_policy | CSS 实际样式、touch/key dispatch、跨 context 时钟/DST/生命周期、音频图种子重启、受限字体及原生能力 |
| media_policy | native/禁用/仅 VP8：WebCodecs、文件/MSE 解码、MediaRecorder 和实际本地 RTC；音频独立录制 |
| transport | 回环 full ClientHello、ALPN、H2 SETTINGS/伪首部、JS/header |
| transport_lifecycle | ClientHello/连接绑定、TLS 1.3 ticket resumption、H2 GOAWAY 与复用；身份请求也绑定实际恢复连接 |
| quic | 强制自有回环 QUIC v1/H3，实际 transport parameters、SETTINGS、独立请求 stream 和复用 |
| sdk_cookies | 两个独立浏览器进程的加密 Cookie 迁移、属性回读及 sibling context 隔离 |
| socks_auth | 原生 RFC 1929 TCP、window/iframe/worker、错误密码与认证降级拒绝 |
| font_provenance | 实际 shaped-run typeface 表摘要与 SFNT/TTC 文件关联；不证明栅格等价 |
| render | ImageBitmap、导出快照、worker ownership、WebGL loss、WebGPU boundaries |
| gpu_backend | A/A-restart/B-conflict 原生策略；五 scope Canvas 色域/类型、GL client/PBO stride、WebGPU adapter/格式/MSAA/销毁重建、CDP GPU 库存 |

每项默认 240 秒，可配置 30–1800 秒。Windows 使用 gated child + kill-on-close
Job Object；POSIX 使用独立进程组和 psutil 后代身份跟踪，只清理本次拥有的进程。
POSIX 后代发现依赖采样，不能宣称能追踪任意瞬间脱离父树的 daemon。缺报告、
启动异常、cleanup 错误和原始观测不符均失败。每项 JSON/log 与总报告保存退出码、
用时、hash、错误和 gap，不因其它 suite 失败而删除。

前后复核 binary、patch series、probe/helper、依赖版本和源码凭据。
`--source-root` 复核全部当前 patch target 的源 hash；ARM64 原生后验只消费同一
GitHub run 的 producer receipt，报告明确标为 `producer-receipt-only`。

### 结果语义

- `status=failed`：至少一项错误，退出非零。
- `status=incomplete`：必需检查通过，optional 能力有明确 gap。
- `ci_gate_passed=true`：非 control、source/binary 身份通过、十五项完整执行且无
  required failure。允许记录的 optional gap，不表示完整设备验收。
- `full_acceptance=false`：没有真实硬件、font-file/glyph 或外部 proxy/DNS/
  QUIC/TURN 的完整证据，不自动升级为全量验收。
- `--control`：仅用于探针校准，无需 source receipt，永远不能通过 CI gate。

TLS fixture 关闭 session tickets，只比较完整握手，不删除 PSK extension 制造
一致。GREASE 值归一化但保留数量/有序向量位置；扩展排列随机化不当作失败。
另外的 `transport_lifecycle` 开启 tickets 并验证恢复连接和复用；`quic` 单独使用
强制回环 origin。两项都重新核验服务器观测，而非相信结果标签。外部路由、
QUIC migration、0-RTT 和 Alt-Svc 不属于这些 fixture 的证明范围。

`backend_policy` 和 `media_policy` 需要当前新增补丁。缺原生硬件 codec 时，
没有可重放的数据不能计作实际拒绝测试；必需的 VP8 控制或任何已声明支持的操作
失败均为错误。BFCache/Temporal/Local Font Access 的可选缺口重新从原始数据派生。
参数、接线和运行边界见 [后端策略](backend-policy.md)。

## Verification

```powershell
$env:CXX = 'C:/Program Files/LLVM/bin/clang++.exe'
$env:PATH = 'C:/Program Files/Git/usr/bin;' + $env:PATH
python -X utf8 -m pytest -q tools/tests/test_persona_snapshot.py `
  tools/tests/test_webgpu_restore_alignment.py tools/tests/test_verify_patch_stack.py `
  tools/tests/test_fingerprint_protocols.py tools/tests/test_fingerprint_runtime_audits.py `
  tools/tests/test_fingerprint_acceptance.py tools/tests/test_fingerprint_subprocess.py `
  tools/tests/test_fingerprint_corpus_review.py sdk/python/tests/test_persona.py
python -X utf8 tools/check_patches.py
npm test --prefix sdk/node
```

这些是算法、验证器和编排测试，不是 Chromium 编译。此前 Chrome 153 control 完整跑完
当时的七项：device、TLS/H2、extended render 通过，identity/Canvas 和两种 runtime 模式
失败。真实 OOPIF 屏幕/DPR 断言保留失败；stock Chrome 本身不实现 launch UXR
后端。结果不能作为匹配 Chromix 152 的验收通过。

新增三项的独立 stock 对照及最终聚焦测试见
[functionality-followup.md](functionality-followup.md)。字体关联 gap 从原始摘要和
文件记录重新计算；重复的 family/script 样本、零 glyph count 和无效文件凭据
不能算有效证据。Cookie 必须保留测试夹具的 host-only/domain、有效期、HttpOnly、
priority 和 CHIPS 属性，而非只保留四个名字。SOCKS 拒绝路径即使没有应用请求，
只要错误密码认证成功或降级后发送了 CONNECT，也会失败。

[GPU backend audit](gpu-backend.md) 保留既有操作检查，不以 renderer 名称
相等或库存列出多块 GPU 当作统一后端证明。`native` 是不可变的共享策略；
不同 API/adapter request 可以选不同 GPU。probe-v4 准入重新校验原始格式、
padding、生命周期和 CDP 证据，旧 probe-v3 bundle 需重采。本机 stock GPU
对照仍失败；33-cell 设备矩阵目前没有 reviewed 样本。这些状态不随源码/
SDK 契约 CI 通过而自动升级。

新增四项的结果校验由 `test_backend_audits.py` 和 `test_transport_lifecycle.py`
覆盖，包含实际 Python/OpenSSL ticket 恢复与 aioquic H3 交换；测试客户端不是
Chromium。匹配合并后 216-patch 浏览器的四项新 suite 尚未执行，不能沿用旧 control 结果。
