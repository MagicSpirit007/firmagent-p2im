# 完整可复现实验手册 (`firmagent-p2im`)

本手册面向独立研究者：在一台干净的 **Ubuntu 22.04 / 24.04 LTS（或 Windows 11 WSL2 Ubuntu 24.04）** x86_64 Linux 机器上，从零拉取公开上游依赖、编译工具链、校验 10 个未修补原版固件 ELF、验证零模型与 DeepSeek 闭环运行、并在 Agent 会话完全结束后运行盲测隔离的 `L5` 离线计分器与防泄漏检查。

> **核心约定**：
> 1. 全程**不修改**任何被测固件 ELF 的一个字节（运行前严格校验 SHA256）。
> 2. 所有模糊测试工作目录放在 **Linux 原生 ext4 短路径**（如 `/tmp/fa-p2im` 或 `/home/<user>/m3std`），严禁放在 `/mnt/c`、`/mnt/d` 等 WSL 9p 挂载目录或超长路径下。
> 3. 真值文件（`P2IM_patching_notes.md` 与论文附录文本）严禁进入 Agent 上下文或提示词，仅由离线宿主进程 `scripts/score_l5.py` 读取。

---

## 1. 宿主环境要求与系统预检

### 1.1 硬件与操作系统
- **架构与 OS**：x86_64 Linux（实测 Ubuntu 24.04.3 LTS / WSL2 kernel 6.x），建议 >= 4 vCPU、>= 8 GiB RAM、>= 15 GiB 可用 ext4 磁盘空间。
- **软件栈**：
  - Python >= 3.10（实测 Python 3.12.3）
  - Node.js >= `22.19.0`（见 `package.json` `engines` 字段）
  - GCC / G++ / GNU Make / pkg-config / Patch
  - `psmisc`（提供 `me.py` / `cov.py` 调用的 `killall`）
  - `binutils-arm-none-eabi`（提供 `/usr/bin/arm-none-eabi-objdump`、`nm`、`readelf`；建模与切片需要反汇编与符号表，不需要重新交叉编译固件）
  - `libglib2.0-dev`、`libpixman-1-dev`、`libfdt-dev`、`zlib1g-dev`、`libjansson-dev`（重编 `qemu-system-gnuarmeclipse` 必需）
  - `gdb-multiarch`（可选，开启配置项 `"gdb_watch": true` 时用于写越界断点观测）

### 1.2 安装系统依赖与 Node.js

在 Ubuntu Bash 终端执行（若使用 Windows，请先执行 `wsl -d Ubuntu-24.04` 进入 Linux 盘，不要在 PowerShell 中直接粘贴以下命令）：

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential git pkg-config python3 psmisc \
  binutils-arm-none-eabi \
  libglib2.0-dev libpixman-1-dev libfdt-dev zlib1g-dev libjansson-dev \
  gdb-multiarch
```

确认 Node.js 版本 >= `22.19.0`（如系统源版本过低，请通过 NodeSource 或官方 `node-v22.x-linux-x64.tar.xz` 安装到 `~/.local/opt/node-v22.19.0` 并加入 `PATH`）：

```bash
node -v    # 期望 >= v22.19.0
arm-none-eabi-objdump --version | head -n 1
which killall pkg-config
```

### 1.3 `core_pattern` 与 AFL 启动环境预检

AFL 2.06b 检查 `/proc/sys/kernel/core_pattern`：若首字符为 `|`（WSL2 或桌面 Ubuntu 默认管道转储），可能导致 AFL 拒绝启动或在外部转储延迟下把慢执行误判为崩溃。建议每次重启后在宿主机执行：

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern   # 期望输出: core
```

> 若在无 root 权限环境运行：`tools/p2im_oracle.py` 与 `p2im-shim/wsl_compat.py` 已注入 `AFL_SKIP_CPUFREQ=1`、`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`、`AFL_NO_AFFINITY=1`、`AFL_SKIP_CRASHES=1`，可在一定程度上绕过容器/WSL 检查；但若在 `Reflow_Oven` 等快干跑目标上遇到干跑误判，请优先配置 `core_pattern=core`。

---

## 2. 需联网获取的公开上游资源清单

本开源仓库仅包含本项目自研代码、轻量补丁、契约单测与文档；以下第三方开源依赖与公开基准固件按**固定 Git Commit** 自动从 GitHub / npm 拉取：

| 资源 | 公开来源 | 固定版本 / Commit | 用途 |
|---|---|---|---|
| npm 依赖（`@earendil-works/pi-coding-agent`、`@earendil-works/pi-ai`、`typebox`、`typescript`） | npm Registry (`package-lock.json`) | Pi SDK `0.85.1`, TypeBox `1.3.7`, TS `5.9.3` | 受控 Pi Agent 运行时与编译构建 |
| P2IM 主仓库 | `https://github.com/RiS3-Lab/p2im.git` | `0e64506a371b9c66ff67ed64a3fa65fa7e197e21` | AFL 2.06b、`model_instantiation/`、`qemu/src/qemu.git` 源码 |
| P2IM 官方真实固件子模块 | `RiS3-Lab/p2im` (`externals/p2im-real_firmware`) | `d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7` | 9 个含 `svc 0x3f` 的未修补原版 ELF（`PLC`..`Steering_Control`） |
| Hoedur 实验仓库（稀疏检出） | `https://github.com/fuzzware-fuzzer/hoedur-experiments.git` | `2babc78b72b1331b3122c11f170e9367132b8aa2` | 第 10 个固件未修补原版 `Soldering_Iron.elf`（无 `svc 0x3f`）与离线 `L5` 真值 `P2IM_patching_notes.md` |

> **说明**：原版 `RiS3-Lab/p2im` 仓库中 `externals/p2im-real_firmware/README.md` 指出其当时尚未清洗好 `Soldering_Iron`，故第 10 个未修补固件取自公开 `hoedur-experiments` 的 `targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf`，并通过 QEMU 侧可选 PC 钩子实现**零修改跑通**。

---

## 3. 一键环境构建与 10/10 固件 SHA256 锁定

在克隆本仓库并进入仓库根目录（推荐放在 Linux 原生分区，例如 `~/firmagent-p2im`）后：

```bash
git clone https://github.com/MagicSpirit007/firmagent-p2im.git ~/firmagent-p2im
cd ~/firmagent-p2im

# 可选环境变量自定义目录（以下为默认值，均保证短路径）
export DEPS_ROOT="$HOME/deps"
export P2IM_ROOT="$DEPS_ROOT/p2im"
export HOEDUR_EXPERIMENTS_ROOT="$DEPS_ROOT/hoedur-experiments"
export P2IM_TOOLS_ROOT="$HOME/p2im-tools"
export P2IM_WORK_ROOT="/tmp/fa-p2im"

# 一键拉取上游、编译 AFL 与 QEMU 补丁版、安装 Python 3.12 脚本、校验 10 个 ELF SHA256、生成 configs/m3/*.json
bash scripts/setup_upstreams.sh
```

`setup_upstreams.sh` 执行的每一步透明可审（如需手工逐步构建，可对照 `scripts/setup_upstreams.sh` 与 [`docs/BUILD_QEMU.md`](BUILD_QEMU.md) 执行）：
1. 检查宿主工具与头文件；
2. 拉取并检出指定 commit 的 `p2im`、`p2im-real_firmware` 与稀疏检出 `hoedur-experiments`；
3. 编译 `$P2IM_ROOT/afl/afl-fuzz`；
4. 对 `$P2IM_ROOT/qemu/src/qemu.git` 应用 [`patches/p2im-qemu-auto-forkserver.patch`](../patches/p2im-qemu-auto-forkserver.patch)（16 个文件），禁用 SDL 构建headless版 `qemu-system-gnuarmeclipse`，安装到 `$P2IM_TOOLS_ROOT/qemu/` 并通过 `nm` 确认存在符号 `p2im_maybe_auto_forkserver`；
5. 复制 `fuzz.py`/`me.py`/`cov.py`/`statFp3.py` 到 `$P2IM_TOOLS_ROOT/scripts/`，归一化 LF 后应用 [`patches/p2im-python312-scripts.patch`](../patches/p2im-python312-scripts.patch)，并部署 `wsl_compat.py` 与 `me` 包装脚本；
6. 对照 [`docs/P2IM_10_UNPATCHED_MANIFEST.json`](P2IM_10_UNPATCHED_MANIFEST.json) 逐一核验 10 个未修补 ELF 哈希，然后调用 `scripts/generate_configs.py` 生成 10 份配置至 `configs/m3/`（且自动断言模型路径 `< 100` 字节限制）。

### 10 个未修补固件完整性校验期望值

| 目标 | 锁定板卡 / MCU | 期望完整 SHA256 |
|---|---|---|
| `PLC` | `STM32F429I-Discovery` / `STM32F429ZI` | `783108cf8b9cf7f703a4164dfee7d12d9a9f79d663328a21454a70a7003c2b08` |
| `CNC` | `STM32F429I-Discovery` / `STM32F429ZI` | `b5eb4e58c9a14abe37118210e33c918af56ebfbd6fe39da5e34480045e1b1d76` |
| `Gateway` | `NUCLEO-F103RB` / `STM32F103RB` | `53a61a7b9baa85275f6fd162c5f5f3d2bf5c417d559b53e0ff2a5fd4897a867b` |
| `Reflow_Oven` | `NUCLEO-F103RB` / `STM32F103RB` | `be996b5bba1a7381d2867fedacc7df52fa55819817560a10ae7ac951e8676346` |
| `Robot` | `NUCLEO-F103RB` / `STM32F103RB` | `724ea82d567b9eefb23e6d75cc90ac0ccdbcd0c7aeca0cca964de46ec188f547` |
| `Drone` | `NUCLEO-F103RB` / `STM32F103RB` | `8cd6a8437713e3e4e0c8c2145b7b72a37143cdfec8753a5400a2d9a879b49c21` |
| `Console` | `FRDM-K64F` / `MK64FN1M0VLL12` | `216bbd526c7079bec496e97ab5bb4e6084819703a3de62dc946b124358e25a67` |
| `Heat_Press` | `Arduino-Due` / `SAM3X8E` | `c4ad1641099388ece8398120d533f24fb15b7ed8a364a081e9f29842ccc9b815` |
| `Steering_Control` | `Arduino-Due` / `SAM3X8E` | `917cf289ecb231e9f2d0393494e7b6732625ed4303b2066e24859729a08697cc` |
| `Soldering_Iron` | `NUCLEO-F103RB` / `STM32F103RB` | `44a6f0e31a6187a6e4f53032390157cfbba3a2ff68c4a7ea2fd83baf22e9a519` |

---

## 4. 安装 Node 依赖与离线工程验证

```bash
cd ~/firmagent-p2im
npm ci --no-audit --no-fund
npm run build
```

依次运行 TypeScript 单测（`8/8`）、Python Oracle 与 `L5` 单测（全部通过，当挂载 `P2IM_ROOT`/`P2IM_NOTES` 时额外运行真 ELF/笔记检查），以及防密钥/路径泄漏审计：

```bash
npm test
P2IM_ROOT="$HOME/deps/p2im" \
P2IM_NOTES="$HOME/deps/hoedur-experiments/02-coverage-est-data-set/binary-patching/P2IM_patching_notes.md" \
npm run test:py

npm run verify:privacy
```

---

## 5. 实验复现一：零模型可运行性、纯 P2IM (`B0`) 与 `--mode offline` 全链路

在调用任何收费大模型 API 之前，建议先跑通零模型链路以核验 10/10 固件均可正常完成建模、AFL 搜索、`extract-sources`、`slice-paths` 与 `L1–L4` 证据提取。

### 5.1 单目标完整零模型 `B0`（以 `PLC`、特例 `Reflow_Oven`、`Soldering_Iron` 为例）

```bash
# 示例 A：PLC（300s 纯 P2IM B0 段 + 切片）
WORK_B0="/tmp/fa-p2im-b0"
python3 tools/p2im_oracle.py prepare --target PLC \
  --elf "$HOME/deps/p2im/externals/p2im-real_firmware/binary/PLC" \
  --expect-sha256 783108cf8b9cf7f703a4164dfee7d12d9a9f79d663328a21454a70a7003c2b08 \
  --work-root "$WORK_B0"
python3 tools/p2im_oracle.py smoke --target PLC --work-root "$WORK_B0"
python3 tools/p2im_oracle.py me --target PLC --round 0 --work-root "$WORK_B0"
python3 tools/p2im_oracle.py fuzz --target PLC --segment s1 --seconds 300 --work-root "$WORK_B0"
python3 tools/p2im_oracle.py extract-sources --target PLC --work-root "$WORK_B0"
python3 tools/p2im_oracle.py slice-paths --target PLC --reach-seeds 2 --work-root "$WORK_B0"
```

查看 `Reflow_Oven`（双种子防干跑崩溃）与 `Soldering_Iron`（零改 ELF + `--auto-forkserver-pc 0x08000268`）能否进入 AFL 搜索：

```bash
# 示例 B：Reflow_Oven（inputs/ 下同时生成 seed-random 与 4B seed-short）
python3 tools/p2im_oracle.py prepare --target Reflow_Oven \
  --elf "$HOME/deps/p2im/externals/p2im-real_firmware/binary/Reflow_Oven" \
  --expect-sha256 be996b5bba1a7381d2867fedacc7df52fa55819817560a10ae7ac951e8676346 \
  --work-root /tmp/fa-p2im-rf
python3 tools/p2im_oracle.py me --target Reflow_Oven --round 0 --work-root /tmp/fa-p2im-rf
python3 tools/p2im_oracle.py fuzz --target Reflow_Oven --segment s1 --seconds 60 --work-root /tmp/fa-p2im-rf
# 预期：execs_done > 0 且无 "PROGRAM ABORT"

# 示例 C：Soldering_Iron（未修补原版 ELF，0 个 svc 0x3f）
python3 tools/p2im_oracle.py prepare --target Soldering_Iron \
  --elf "$HOME/deps/hoedur-experiments/targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf" \
  --expect-sha256 44a6f0e31a6187a6e4f53032390157cfbba3a2ff68c4a7ea2fd83baf22e9a519 \
  --auto-forkserver-pc 0x08000268 --work-root /tmp/fa-p2im-si
python3 tools/p2im_oracle.py smoke --target Soldering_Iron --work-root /tmp/fa-p2im-si
# 预期：evidence/smoke.log 出现 "start up afl forkserver!"
python3 tools/p2im_oracle.py me --target Soldering_Iron --round 0 --work-root /tmp/fa-p2im-si
python3 tools/p2im_oracle.py fuzz --target Soldering_Iron --segment s1 --seconds 60 --work-root /tmp/fa-p2im-si
```

### 5.2 TypeScript `--mode offline` 全流程（`model_requests = 0`）

运行完整 `Mcup2imCampaign` 状态机（零模型请求，自动执行 `prepare → model → discover_seg1 → slice → discover_seg2_skipped/offline → triage_and_verify (3x重放+Contrast消融) → score`）：

```bash
node dist/src/cli.js mcu-p2im \
  --config configs/m3/plc.json \
  --out runs/plc-offline \
  --mode offline
```

运行完成后检查：
- `runs/plc-offline/state.json`：`status` 应为 `"completed"`，`totals.model_calls == 0`，且记录 `layers.l1..l4`。
- `runs/plc-offline/score-owned.json` & `runs/plc-offline/l5-candidates.json`：记录重放 3/3 一致性与 Contrast 决定性字节消融结果，以及通过共享 SRAM 关联给出的 `upstream_functions`。

---

## 6. 实验复现二：真实 LLM（DeepSeek）受控闭环与对照实验

### 6.1 凭据注入与配置自检（零密钥落盘）

**严禁将任何 API Key 写入仓库文件、配置 JSON 或提交到 Git。**  
在当前 Bash 会话通过标准环境变量注入 DeepSeek API Key：

```bash
read -rsp "DEEPSEEK_API_KEY: " DEEPSEEK_API_KEY && export DEEPSEEK_API_KEY && echo
```

Pi SDK 默认模型注册表已内置 `deepseek` 提供商的 `deepseek-v4-flash` 与 `deepseek-v4-pro`。若你的账户使用兼容端点上的 `deepseek-chat` 或自定义别名，可将 [`configs/pi-agent-example/models.json`](../configs/pi-agent-example/models.json) 复制到私有目录（如 `~/.pi/agent/models.json`）后指定 `--pi-agent-dir`。

在发起真实调用前，先用只读 `doctor` 验证解析（不发出模型请求、不读取密钥内容）：

```bash
node dist/src/cli.js doctor --provider deepseek --model deepseek-v4-flash
```

### 6.2 在 `PLC` 上复现真实 Agent 闭环与共享 SRAM 根因归因

```bash
node dist/src/cli.js mcu-p2im \
  --config configs/m3/plc.json \
  --out runs/plc-real \
  --mode real \
  --provider deepseek --model deepseek-v4-flash \
  --model-calls 16 --max-total-tokens 150000 --wall-ms 1200000
```

核验关键产出：
1. **共享 SRAM 切片（`/tmp/fa-p2im/plc/analysis/paths.json`）**：检查 `shared_globals` 中 `rx_callback`（`0x20000214`）是否带有 `call_edge: false` 及 `indexed_reach`（指明 `Modbus::process_FC1` / `Modbus::process_FC3` 对 `slave` `0x20000124` 做无界字节下标写并覆盖 `rx_callback`）。
2. **模型提案种子（`/tmp/fa-p2im/plc/proposed-seeds/`）**：模型调用 `seed_propose` 提交的 `modbus_rtu` 帧已由宿主核验长度（`<=256B`）、防泄漏及 CRC16 校验，通过 `--include-proposed` 独立投入第二段 AFL（`outputs-s2`）。
3. **候选上溯归因（`runs/plc-real/l5-candidates.json`）**：对于崩溃在 `HAL_UART_RxCpltCallback`（`0x8003f30`）的确定性崩溃，宿主通过 `sharedViaRank` 将其 `via_shared_global` 保留为 `rx_callback`，`upstream_functions` 列出 `Modbus::process_FC1`、`Modbus::process_FC3` 等上游写穿函数候选。
4. **账本治理（`runs/plc-real/account.json` & `ledger.jsonl`）**：核验所有模型请求状态均为 `settled`，记录 `tokens` 与 `wall_ms`，确保提示词与模型输出零真值泄漏。

### 6.3 10 固件同端到端墙钟对照实验协议（Formal Benchmark）

进行正式对比实验（纯 P2IM `B0` 基线 vs `FirmAgent/Pi mcu-p2im`）时请严格遵循以下实验设计规范：
1. **对齐总端到端墙钟预算**：
   - 将 `B0`（纯 AFL 单段运行总墙钟，例如 `1200s`）与 `mcu-p2im`（`s1` + 切片 + Agent 推理 + `s2` + `triage_and_verify` 的总墙钟，如 `480s×2 + 推理与重放`）严格区分开来；同时分别报告**同墙钟**与**同目标执行次数（`execs_done`）**视角下的指标，**不跨不同固件或不同重托管板卡比较绝对覆盖数或执行次数**。
2. **多次随机种子与分布统计**：
   - 每个对比臂独立运行多次（例如初筛 3 次、正式对照固定更多随机种子如 `1707/2707/3707`，且每次使用全新 `--work-root` 清空状态与语料），同时保留每一次运行原始值、中位数与离散度，不仅凭单次均值下结论。
3. **成本单列**：
   - 从 `runs/<target>/account.json` 与 `ledger.jsonl` 如实导出 `model_requests`、`tokens`、`wall_ms` 与计费口径。

批量运行 10 个目标示例脚本框架：

```bash
for cfg in configs/m3/*.json; do
  slug="$(basename "$cfg" .json)"
  node dist/src/cli.js mcu-p2im \
    --config "$cfg" \
    --out "runs/real-${slug}" \
    --mode real \
    --provider deepseek --model deepseek-v4-flash \
    --model-calls 16 --max-total-tokens 150000 --wall-ms 1200000
done
```

---

## 7. 实验复现三：盲测隔离的宿主离线 `L5` 计分

**在全部 Agent 运行结束后**，由宿主启动独立 Python 进程运行 `score_l5.py` 与 `leak_check.py`：

```bash
NOTES="$HOME/deps/hoedur-experiments/02-coverage-est-data-set/binary-patching/P2IM_patching_notes.md"

python3 scripts/score_l5.py \
  --notes "$NOTES" \
  --candidates runs/plc-real/l5-candidates.json \
  --target PLC \
  --summary-only \
  --out runs/plc-real/l5.json

python3 scripts/leak_check.py \
  --work-dir /tmp/fa-p2im/plc \
  --candidates runs/plc-real/l5-candidates.json \
  --out runs/plc-real/leak-check.json
```

`score_l5.py`（schema `mcu-p2im/l5-0.3`）将每条经 `L3/L4` 实证的候选清晰归入以下三类之一（并输出真值文件 SHA256 与章节诊断，**不回显真值原文**）：
- `known_p2im_bug_direct`：崩溃函数或地址直接命中真值补丁函数/地址；
- `known_p2im_bug_downstream`：崩溃发生在下游受害点（如 `HAL_UART_RxCpltCallback`），但经 `shared_globals`/`indexed_reach` 关联出的 `upstream_functions` 命中已知根因函数（如 `Modbus::process_FC1`）；
- `unmatched_verified_candidate`：经 3 次重放与 Contrast 确认但未命中真值表的候选。

同时检查 `runs/plc-real/leak-check.json` 必须满足 `"leak_in_prompt": false` 且 `missing` 为空。

---

## 8. 产物目录字典与常见故障排查

### 8.1 关键产物路径

| 路径 | 生产者 | 内容 |
|---|---|---|
| `$P2IM_WORK_ROOT/<slug>/meta.json` | `oracle prepare` | 锁定 ELF SHA256、板卡、MCU 与可选 `auto_forkserver_pc` |
| `$P2IM_WORK_ROOT/<slug>/0/peripheral_model.json` | `oracle me` / `me.py` | Round 0 自动提取的外设 SR/CR/DR 接口模型 |
| `$P2IM_WORK_ROOT/<slug>/analysis/{sources,paths}.json` | `oracle extract-sources / slice-paths` | 全轮 DR 读点、调用边、共享 SRAM 写穿链（`indexed_reach`） |
| `$P2IM_WORK_ROOT/<slug>/proposed-seeds/` | `oracle admit-seed` | 宿主校验通过的模型提案种子 |
| `runs/<run>/{state,account,score-owned}.json` | `mcu-runtime.ts` | 阶段状态、模型与 Token 账本、`L1–L4` 统计 |
| `runs/<run>/l5-candidates.json` | `mcu-runtime.ts` | 待离线评分的验证候选及共享全局上溯归因 |
| `runs/<run>/l5.json` | `scripts/score_l5.py` | 宿主离线 `L5` 三分类统计结果 |

### 8.2 常见故障排查表（来自真实环境踩坑实证）

| 报错 / 现象 | 原因 | 解决方法 |
|---|---|---|
| `PROGRAM ABORT : -c options should be shorter than 100 bytes` | `work_root` 路径过长（P2IM AFL 对 `-c` 模型路径有 100 字节硬上限） | 将 `work_root` 设为 `/tmp/fa-p2im` 或 `/home/<user>/m3` 等短路径，勿放仓库深层子目录 |
| `EPERM: fsync`（运行在 `/mnt/c` 或 `/mnt/d` 时） | WSL 9p 文件系统对目录 `fsync` 语义不兼容，且 QEMU I/O 极慢 | 将代码或至少 `work_root` 与 `--out` 放到 Linux 原生 ext4 文件系统 |
| `undefined symbol: g_string_free_and_steal` | `LD_LIBRARY_PATH` 加载了 2017 年随包旧版 `libglib-2.0.so.0` | 始终通过 `p2im_oracle.py` 生成的 shim（内含 `unset LD_LIBRARY_PATH`）启动重编 QEMU |
| `FRDM-K64F` 启动即 `abort` | 重编 QEMU 时误开启了 `CONFIG_KINETIS=y` | 保持 `default-configs/gnuarmeclipse-softmmu.mak` 中 `CONFIG_KINETIS=n`、`CONFIG_STM32=y` |
| `AttributeError: module 'configparser' has no attribute 'SafeConfigParser'` | Python 3.12 移除了旧类 | 使用 `scripts/setup_upstreams.sh` 安装打过 `patches/p2im-python312-scripts.patch` 的脚本 |
| `All test cases time out or crash, giving up!` | `core_pattern` 管道延迟或仅有易崩长种子 | 执行 `echo core \| sudo tee /proc/sys/kernel/core_pattern` 并保留 `cmd_prepare` 自动写入的 4B `seed-short` |
| `me.py` 找不到 `killall` | 宿主机缺少 `psmisc` 包 | `sudo apt-get install -y psmisc` |
| 真实模式下 `DEEPSEEK` 请求提示缺模型或认证失败 | 未设置环境变量或误写别名 | 确认 `export DEEPSEEK_API_KEY="<your-deepseek-api-key>"`，或用内置 `--model deepseek-v4-flash` |
| 仓库防泄漏自检命中 | `runs/`、`node_modules/`、`dist/` 或私钥进入目录 | 运行 `npm run verify:privacy` 清理无关产物后再提交 Git |
