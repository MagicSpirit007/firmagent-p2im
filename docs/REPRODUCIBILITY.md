# 科研理据、技术改造解析与分步复现手册 (`firmagent-p2im`)

本文档不仅提供让第三方研究者零阻力跑通实验的命令清单，还从**研究问题本质、原版阻塞机制、源码级改造设计、改动前后可观测对比（Before vs After）**以及**不依赖黑盒脚本的 Step 1–Step 9 全手工实操步骤**四个层面，完整阐明 `firmagent-p2im` 为什么这样做、改变了什么，以及每一步该如何独立验证。

> **三项不可违背的实验约定**：
> 1. **原字节零修改固件**：全程禁止重编译或二值修补任何被测 ELF（所有目标运行前均以 SHA256 锁定，保留原版内存布局与向量表）。
> 2. **盲测隔离**：真值文件（`P2IM_patching_notes.md` 与论文原文提取文本）严禁进入 Agent 上下文、工具输出或分析切片；仅在全部 Agent 会话结束后，由独立离线进程 `scripts/score_l5.py` 评分。
> 3. **Linux 原生 ext4 短路径工作区**：所有 AFL/QEMU 工作根目录（`P2IM_WORK_ROOT`）与实验输出（`--out`）必须置于 Linux 原生 ext4（如 `/tmp/fa-p2im` 或 `~/m3std`），严禁放在 WSL `/mnt/*`（避免 9p `fsync EPERM`）或深层路径（避免超出 P2IM AFL `-c` 100 字节缓冲区上限）。

---

## 第一部分：科研动机、设计理据与三层改动全解

### 1.1 问题域差异与架构选型：为何不直接在原版 FirmAgent 上硬改，以及基于 Pi 的技术路线

#### 1.1.1 问题域差异：为何不能将 Linux 路由器 FirmAgent 原样迁移至裸机 MCU？

Linux 网络固件（如路由器 `httpd`/`upnpd`）的 Agent 协同模糊测试依赖 POSIX 操作系统抽象；而 P2IM 基准面向无操作系统的 ARM Cortex-M3/M4 单体 ELF，二者在五个基础维度存在本质错配：

| 对比维度 | Linux 网络固件（传统 FirmAgent） | 裸机 MCU 固件（P2IM 基准） | 本研究必须引入的机制 |
|---|---|---|---|
| **执行载体与构建形态** | 多进程、动态库、根文件系统、`qemu-user`/`system` | 单一静态 ELF（Thumb-2 裸机代码，直接映射至 Flash `0x08000000` / `0x00080000` 与 SRAM `0x20000000`） | 按 Board/MCU/Flash/Vector 校验硬件家族；用真实 `arm-none-eabi-objdump` / `nm` 构建反汇编索引，不依赖符号重构 |
| **外部输入注入面** | 网络 Socket、HTTP 请求体、CLI 参数、Env | 无文件描述符；由 P2IM 自动推导外设 MMIO **Data Register (`DR`)** 并将扁平字节流依次喂给 `DR` 读与中断触发 | `extract-sources` 解析 Round `reg_acc*` 寄存器访问日志，结合真实 `reg_size` 步长定位外部输入进入点 |
| **跨上下文数据流形态** | 参数顺调用栈显式传递，静态 Callgraph 即可串联 `source -> sink` | **中断服务例程（ISR）读 UART DR → 写入全局 SRAM 环形缓冲 → 主循环状态机异步轮询消费**；二者之间**不存在直接函数调用边** | `slice-paths` 构造独立于调用图的 **`via_shared_global` 与 `indexed_reach` 共享 SRAM 切片**，并显式标注 `call_edge: false` |
| **漏洞故障可观测形式** | 内核拦截 `SIGSEGV`/ASan 报告，拥有丰富栈回溯 | 无 MMU/OS 保护，常见表现为：1）溢出覆盖相邻全局函数指针（如 `rx_callback`），跳入外设区 `0x40000000..0x5fffffff` 取指；2）在下游受害回调（如 `HAL_UART_RxCpltCallback`）崩溃 | QEMU 侧增加外设取指保护 `PM_EXEC_PERI = 0x72`；验证层叠加 **3 次确定性重放 (`L3`) + Contrast 决定性字节消融 (`L4`) + 共享 SRAM 上溯归因 (`L5`)** |
| **开放式 Agent 风险** | 模型自由跑 Shell 易烧光预算、修改被测文件或通过联网/文件检索泄露 CVE 真值 | 单次 MCU 变异窗口耗时数十到数百秒，开放 Shell 更容易死锁或污染对比基准 | 以 Pi SDK (`0.85.1`) 托管双段固定状态机 + 只读 SHA256 工件切片 + `RunGovernance` 严控账本 + `assertNoLeak` 防泄漏拦截 |

#### 1.1.2 为何不直接在原版 `vul337/FirmAgent` 代码库上修改？我们采用了什么技术路线？

1. **为什么不直接在原版 `vul337/FirmAgent` 仓库上修补扩展？**
   - **代码强耦合与自身断点**：原版 `vul337/FirmAgent`（`ea0dbdd`）重度耦合于 Greenhouse 容器重托管、HTTP URI/参数网络变异器、闭源商业软件 IDA Pro Hex-Rays `ctree` 插件与 POSIX 调用栈污点假设，几乎不存在可直接复用于 ARM Cortex-M 裸机单体 ELF 的模块；同时原公开仓库本身带有多处未闭合断点（如 `Pre_Fuzzing/run.sh` 注释了 LLM API 提取脚本、`Distance.py` 实为固定 4 字节步长近似而非真实基本块控制流图、缺少请求/Token 硬账本与进程组清理治理）。
   - **规避工程包袱与收益归因失真**：若在原仓库上“一边修补原仓断点、一边强塞裸机 P2IM 分支”，既背负与裸机无关的 Linux/IDA 历史包袱，改出的系统也无法算作对原版 FirmAgent 的严格复现；更重要的是，从论文与实验方法学视角看，“补全 + 移植”不仅容易把针对裸机核心难点（ISR 与主循环共享 SRAM 无调用边耦合、无 MMU 外设区取指失控、跨段外设模型与队列延续）的方法创新弱化为工程移植，还会把“框架补全、P2IM 底座修复、共享 SRAM 静态切片、大模型提案”混杂在一起，导致无法干净剥离各组件净收益。

2. **本研究基于 Pi 与 FirmAgent 核心思想的技术路线**：
   - **保留核心思想，重构受控底座与开源裸机后端**：吸收 FirmAgent“程序切片引导大模型协同模糊测试”的思想内核，上层基于 **Pi SDK (`0.85.1`)** 构建受控会话（`src/core/session.ts`）、串行预算硬账本 `RunGovernance`（`src/campaign/governance.ts`）、进程身份核验清理（`src/campaign/owned-process.ts`）与只读 `ToolEnvelope` 工具契约（禁自由 Shell、禁越界路径、内置 `assertNoLeak` 防真值泄漏），以独立的 `Mcup2imCampaign`（`src/campaign/mcu-runtime.ts`）专职服务裸机实验；下层对接原版 P2IM QEMU/AFL（零修改 10 份被测 ELF 字节），在 `tools/p2im_oracle.py` 中使用开源 `arm-none-eabi-objdump` / `nm` 实现跨中断共享 SRAM 切片（`via_shared_global` 与 `indexed_reach`），替代闭源 IDA 依赖。
   - **采用“宿主固定阶段流水线（`pipeline`）+ 中场单会话（`main`）聚焦提案”的精简编排**：
     - 全流程 `prepare → model → discover_seg1 → slice → analyze_and_propose → discover_seg2 → triage_and_verify → score` 由 TypeScript 宿主状态机固定驱动，不采用多子代理层层派工（零子代理调度开销），也不交给单会话自由编排全流程；
     - 前后两段模糊测试（`discover_seg1` / `discover_seg2`）及后置崩溃重放消融（`triage_and_verify`，默认 `replay_model_calls = 0` 由宿主确定性完成 `L3/L4`，仅在显式指定 `--replay-model-calls > 0` 时才开重放会话做消融）全部由宿主直接调用 `p2im_oracle.py` 完成；
     - 默认**仅在中场 `analyze_and_propose` 阶段开启 1 个受控 `main` 会话**，将全部 LLM 调用与 Token 预算集中在“审计共享 SRAM 切片、记录越界假设（`hypothesis_note`）、提交通过长度与 CRC16 校验的协议种子（`seed_propose`）”这一最能发挥大模型语义推理价值的环节，并配套四路归因分离评估（`B0` 裸结果、`B0` + 离线共享 SRAM 切片、无模型 `offline`、完整 `real`）。

---

### 1.2 三层改动：原版阻塞现象 → 根因分析 → 具体改动 → 改动前后对比

#### 层面 A：Ubuntu 24.04 / Python 3.12 / WSL2 宿主复活层

原版 `RiS3-Lab/p2im`（commit `0e64506a`）发布于 Ubuntu 16.04/18.04 + Python 2/3.6 时代，直接在新版 Ubuntu 22.04/24.04 或 WSL2 中会在建模前即崩溃。

| 问题项 | 原版阻塞现象与根因 | 本研究具体改动（位置） | 改动前（Before）→ 改动后（After） |
|---|---|---|---|
| **1. Python 3.12 移除 `SafeConfigParser`** | 运行 `fuzz.py` / `me.py` / `cov.py` 立即抛出 `AttributeError: module 'configparser' has no attribute 'SafeConfigParser'`；若仅改名 `ConfigParser` 而忘记传 `inline_comment_prefixes=('#', ';')`，P2IM 模板里 `fuzz.cfg` 的行内注释会被当成路径/数值的一部分引发语法报错 | [`patches/p2im-python312-scripts.patch`](../patches/p2im-python312-scripts.patch)：在 3 份脚本中改用 `configparser.ConfigParser(inline_comment_prefixes=('#', ';'))`，修复 `me.py` 中 `error_rv.get` 判断，保留 `qemu-stderr.txt` 故障现场 | **Before**: Python 3.12 零步退出<br>**After**: 原生 Python 3.12 稳定执行 `me.py`/`fuzz.py`/`cov.py` 并将 QEMU stderr 完整留证 |
| **2. WSL2 / 容器环境下的 AFL 自检失败** | 缺少 `AFL_SKIP_CPUFREQ`、`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`、`AFL_NO_AFFINITY`、`AFL_SKIP_CRASHES` 时，AFL 在调频缩放与 `/proc/sys/kernel/core_pattern` 管道模式下直接拒跑；Python stderr 缓冲也会掩盖 `me.py` 失败原因 | [`p2im-shim/wsl_compat.py`](../p2im-shim/wsl_compat.py) 与 `p2im_oracle.py` `tool_env()`：统一注入上述环境变量与 `PYTHONUNBUFFERED=1`，并生成 bash `me` 包装脚本规避 `#!` / CRLF 差异 | **Before**: WSL2 默认配置下 AFL 拒跑或无错误回显<br>**After**: 开箱即绕过容器化宿主的无关自检，同时保留 `core_pattern=core` 显式校验 |
| **3. 随包 2017 年 `libglib` 与宿主库符号冲突** | 上游预编译发行包在 `qemu/` 目录自带 2017 年 `librt*.so`、`libutil*.so`（glibc 2.19 `GLIBC_PRIVATE` 不兼容）与 `libglib-2.0.so.0`（2.51）。若将现代重编 QEMU 放进同一目录或设了 `LD_LIBRARY_PATH`，动态链接立即报错 `undefined symbol: g_string_free_and_steal` | `scripts/setup_upstreams.sh` 从源码重编本地版 QEMU 并安装至 `$P2IM_TOOLS_ROOT/qemu/`；[`tools/p2im_oracle.py`](../tools/p2im_oracle.py) `Work.install_shim()` 在工作区生成包装脚本，`unset LD_LIBRARY_PATH` 后 `exec` 真 QEMU | **Before**: 启动 QEMU 即动态链接崩溃或受宿主旧库污染<br>**After**: 与旧版 2017 动态库完全解耦，零符号冲突启动 |
| **4. 全局 `killall` 跨工作区误杀与残留清理** | 原版 `me.py` / `cov.py` 信号处理直接调用全局 `killall qemu-system-gnuarmeclipse`，多窗并行时会误杀同机其他实验；最小化镜像缺 `psmisc` 还会报错 | `patches/p2im-python312-scripts.patch` 移除脚本内无作用域 `killall`，交由 [`tools/p2im_oracle.py`](../tools/p2im_oracle.py) 按独立进程组与 `/proc/<pid>/cmdline` 精确限定本 `work_dir` 的 `sweep_work()` 收尾 | **Before**: 并行实验互相误杀或残留孤儿 QEMU<br>**After**: 严格按 `work_dir` 隔离清场，零跨窗干扰、零孤儿残留 |
| **5. AFL `-c` 100 字节硬上限、`s2` 模型连续性与 WSL 9p `fsync`** | P2IM `afl-fuzz.c` 规定 `MODEL_IF_LEN = 100`；原版 `fuzz.py` 启动前对 `inputs-s2/` 每条种子生成 `0.<seed>.1/peripheral_model.json`（长队列名/SHA256 名达 `118B+` 立即 `PROGRAM ABORT`），且无条件把 `--model-if` 重置回 `0/` 丢弃 `s1` 累积模型 | `generate_configs.py` 与 `p2im_oracle.py` 预检 `0.seed-random.10/peripheral_model.json` `< 100B`；`prepare_segment_inputs()` 将 `inputs-s2/` 种子映射为 `<=5B` 短名（`b00`/`q0000`/`p00`，溯源表写入 `evidence/inputs-s2-map.json`）；`prepare_segment_model_continuity()` 将 `s1` 累积模型拷入 `0.s2/` 并配合 `--skip-seed-prefix q` 跳过冗余冷启动 | **Before**: `s2` 因长种子名超 `100B` 立即 `PROGRAM ABORT` 或丢失 `s1` 外设模型<br>**After**: 100% 满足 `<100B` 约束，`s2` 完整继承 `s1` 队列与累积外设模型 |

---

#### 层面 B：零修改原版 ELF（`SHA256` 锁定）打通 10/10 基准的最小侵入机制

为严格保证**“被测二进制与论文对照组完全同字节”**，禁止通过重编译固件、注入 `svc #0x3f` 或给漏洞打桩来迎合工具链。本工作采用“外围最小侵入 + 显式开关门控”攻克全 10 目标可运行性：

1. **攻克第 10 个固件 `Soldering_Iron.elf`（`0` 个 `svc 0x3f`）—— `P2IM_AUTO_FORKSERVER_PC`**
   - **原版阻塞现象**：`RiS3-Lab/p2im` 的 `externals/p2im-real_firmware/README.md` 注明其当时未清理好 `Soldering_Iron`。公开可获取的未修补原版 `Soldering_Iron.elf`（来自 `hoedur-experiments`，SHA256 `44a6f0e3…`）含 **`0` 条 `svc #0x3f` 指令**，导致 P2IM QEMU 永远等不到 `startForkserver(env, 0)` 调用，`me.py` 与 AFL 无法拉起 forkserver。
   - **改动原理与源码位置**：在 [`patches/p2im-qemu-auto-forkserver.patch`](../patches/p2im-qemu-auto-forkserver.patch) 涉及的 `target-arm/translate.c` 与 `cpu-exec.c` 中加入 `p2im_maybe_auto_forkserver(env, tb->pc, tb->size)`，在每次执行翻译基本块（TB）前判定：**当且仅当**环境变量 `P2IM_AUTO_FORKSERVER_PC` 被显式设定，且当前首次命中覆盖该 Thumb PC 的基本块时，调用一次 `startForkserver(env, 0)`。
   - **不变性与隔离证明**：当 `P2IM_AUTO_FORKSERVER_PC` 未设置（其余 9 个已含 `svc 0x3f` 的固件默认不设置）时，函数在首次判定后即返回，逻辑行为与原版完全等价。
   - **Before vs After**：
     - **Before**: 原版 ELF 无法触发 AFL forkserver，`p2im_runnable = false`（只跑了 9/10）。
     - **After（2026-11-17 本机实证）**：`Soldering_Iron.elf` 原字节保持 `44a6f0e31a6187a6e4f53032390157cfbba3a2ff68c4a7ea2fd83baf22e9a519`，配置 `"auto_forkserver_pc": "0x08000268"` 后 `smoke` 0.016s 出现 `start up afl forkserver!`，`me` Round 0 产出 13 外设 / 33 DR，`60.066s` 短窗平稳完成 `193 execs`、`12 paths`。

2. **外设 MMIO 区取指保护 `PM_EXEC_PERI = 0x72`**
   - **原版阻塞现象**：当固件缺陷（如全局缓冲越界写穿回调函数指针 `rx_callback`）把函数指针改写为外设地址区间 `0x40000000..0x5fffffff` 并执行 `blx r3` 时，QEMU 翻译期取指会走内存读路径并误触 `unassigned_mem_read`，使 P2IM 误以为“主循环访问了未建模外设寄存器（`0x40`）”而陷入无休止的模型重试死循环。
   - **改动原理与源码位置**：在 `cputlb.c`、`memory.c`、`include/peri-mod/peri-mod.h`、`include/afl/afl-qemu-cpu-inl.h` 增加取指态标志 `pm_fetching_code` 与 `get_page_addr_code` 检查：若取指地址落入外设 MMIO 区间，立即输出 `guest_code_fetch addr=... pc=... r0=... r3=...` 现场寄存器并按 `PM_EXEC_PERI = 0x72` cleanly exit；同时 `fuzz.py` / `me.py` / `cov.py` 将 `0x72` 纳入 `no_retry`，`p2im_oracle.py`（`parse_fault` / `replay_once`）将 `0x72` 与 `guest_code_fetch` 解析为确定性 `exec_peri` 崩溃纳入 `L2–L4` 验证。
   - **Before vs After**：
     - **Before**: 指针损坏跳入 MMIO 区时 `me.py` 不断触发伪造 `unmodeled_peri` 重试并丢失故障原因。
     - **After**: `0x40` 伪误报被抑制，真实 `guest_code_fetch` 现场被保存用于后续定性与溯源。

3. **现代主机重编 QEMU 2.3.50 的四项编译与板卡陷阱修复**
   - `configure` + 7 份 QAPI/tracetool `.py`：升级 Python 2 语法（`except E, e`、`has_key`、`StringIO`、`string.maketrans`、`.keys()` 迭代器）至 Python 3.12。
   - `hw/display/gpio-led.c`、`hw/arm/cortexm-helper.c`：将 SDL 图形界面逻辑包裹进 `#if defined(CONFIG_SDL)`，使无桌面 / 无旧版 `libsdl1.2-dev` 服务器可通过 `--disable-sdl` 编译（模糊测试本就使用 `-nographic`）。
   - **板卡注册防重不变量**：`default-configs/gnuarmeclipse-softmmu.mak` 必须保持 `CONFIG_STM32=y` 与 `CONFIG_KINETIS=n` / `CONFIG_SAM=n`，因为 P2IM 将 `FRDM-K64F`、`Arduino-Due` 也直接注册在 `stm32-boards.c` 内；开启 `CONFIG_KINETIS=y` 会导致 `FRDM-K64F` 被重复注册，QEMU 一启动即 `abort`。

4. **`CNC` 板卡实证锁定（`STM32F429I-Discovery`）**
   - **原版阻塞现象**：按 `CNC` ELF 文件头的 MCU 家族直接选 `STM32F4-Discovery / STM32F407VG` 时，`smoke` 在未建模 `mem_r *0x0`/`*0x4` 上以退出码 `-11` 失败，`me.py` Round 0 仅 1.292s 退出（`Stage 1 returned due to unexpected reasons!`），产出 **`0` 外设、`0` DR**。
   - **根因与改动**：P2IM 定制的外设建模钩子仅完整挂载在论文 Table 8 所列出的 `STM32F429I-Discovery / STM32F429ZI` 机器定义上。据此将 [`tools/p2im_oracle.py`](../tools/p2im_oracle.py) `BOARD_FOR_TARGET["CNC"]` 与 [`docs/P2IM_10_UNPATCHED_MANIFEST.json`](P2IM_10_UNPATCHED_MANIFEST.json) 显式锁定为 `STM32F429I-Discovery / STM32F429ZI`。
   - **Before vs After（历史本机实证）**：由 `0 外设 / 0 DR / 无法启动建模` 变为 `12 外设 / 39 DR / 60.017s 内执行 2926 次、探索 153 paths`。

5. **`Reflow_Oven` 双初始种子机制（`seed-random` + `seed-short`）**
   - **原版阻塞现象**：`cmd_prepare` 仅生成确定性 256 字节伪随机种子 `seed-random`；`Reflow_Oven` 吞入 256 字节长输入会在初始化/解析路径直接触发崩溃，`afl-fuzz.c:2811` 在 dry-run 阶段报告 `All test cases time out or crash, giving up!` 并在 0.366s 退出（`execs_done = 0`）。
   - **改动原理**：`tools/p2im_oracle.py` `write_initial_seeds()` 在保留 `seed-random`（不覆盖既有文件）的同时，在 `inputs/` 并存写入 4 字节极短种子 `seed-short`（`b"0\n\x00\x00"`），使 AFL 在开启 `AFL_SKIP_CRASHES=1` 时至少保有一枚干跑通过的队列种子进入变异循环。
   - **Before vs After（历史本机实证）**：
     - **Before（`/home/<user>/m3rf/reflow-oven`）**：`0.366s`，`execs_done = 0`，`PROGRAM ABORT`。
     - **After（`/home/<user>/m3rf60/reflow-oven`）**：`60.604s`，`execs_done = 2582`，`26 paths`，`1 unique crash`，`All set and ready to roll!`。

6. **真实寄存器步长 `reg_size` 与多轮深层 `reg_acc*` 全收集**
   - **原版阻塞/漏报现象**：旧逻辑把 `regs[index]` 地址硬按 4 字节对齐（`base + index * 4`），使 1 字节步长的 K64F UART（`Console` 目标）计算出错误 DR 地址；`extract-sources` 旧实现只读首个 `reg_acc*`，遗漏 `depth:*` 子目录里的深层访问，且未用 `c++filt` 对 QEMU 裸 C++ 修饰符号做解码以对齐 `nm -C`。
   - **改动**：`read_model_summary()` 按 `base + index * reg_size` 计算 DR/CR 寄存器精确地址；`cmd_extract_sources()` 遍历该轮全部 `reg_acc*`（含 `depth:*` 子目录）并统一经 `demangle()`（`/usr/bin/c++filt`）对齐符号。

---

#### 层面 C：受控 Pi Agent 两段闭环、共享 SRAM `indexed_reach` 切片与盲测 `L1–L5`

1. **为什么需要“受控两段状态机”，而不是把整个 Linux 终端交给大模型自由循环？**
   - Open-loop 自由终端让模型自己起停 `afl-fuzz` 与 QEMU，极易出现：孤儿进程占满 CPU、预算失控（超时误判冻结或静默回退模型）、篡改输入语料污染基线对照，或直接在工作区 `grep CVE` 造成数据污染。
   - `src/campaign/mcu-runtime.ts` 与 `src/campaign/governance.ts` 将生命周期固化为可控状态机：
     `prepare` → `model` (Round 0) → `discover_seg1` (`s1`) → `slice` (`extract-sources` + `slice-paths`) → `analyze_and_propose` (Pi `main` 会话读取摘要与切片、调用 `seed_propose` 与 `hypothesis_note`) → `discover_seg2` (`s2` 通过 `--include-proposed` 独立并入已核验种子) → `triage_and_verify` (`L3` 三次重放 + `L4` Contrast 字节消融 + 可选 `gdb-watch`) → `score`（落盘 `score-owned.json` 与 `l5-candidates.json`）。
   - 系统提示词在编译时冻结（`MCUP2IM_PROMPTS`，零动态变量插值以保前缀缓存一致性），`RunGovernance` 按单次请求串行记账并在超支/未知用量时停机（显式允许对超时等暂态错误按 `0 token / retryable` 处理而不静默更换 provider）。

2. **共享 SRAM 数据流与 `indexed_reach` 跨界切片（以 `PLC` 为实证剖析）**
   - **痛点（Before）**：在 `PLC` 中，UART 中断在 `HAL_UART_IRQHandler` / `HAL_UART_RxCpltCallback` 写入输入，主循环状态机 `Modbus::process_FC1` / `process_FC3` 再异步解析 `slave`（`0x20000124`，大小 `0x64`）。更隐蔽的是：当 `process_FC1/FC3` 执行无上界字节下标写 `ldrb.w r3, [r4, #73]` + `add` 基址 + `strb ..., [sum, #9]` 时，可达区间 `0x2000012d..0x2000022c` 直接**跨界覆盖了相邻全局对象 `rx_callback`（`0x20000214`）**，导致最终在下游 `HAL_UART_RxCpltCallback`（`[0x8003f30, 0x8003f3e)`）触发空指针解引用读崩溃。
   - 若仅靠静态 Callgraph 或早期切片：
     1. 裸机 ELF 不一定保留论文手记中的符号别名（如 `au8Buffer` 未必以同名符号存在）；
     2. ARM Thumb 的三字母 `add` 助记符曾被 `objdump` 解析器误判成十六进制机器码丢弃；
     3. 崩溃点 `HAL_UART_RxCpltCallback` 自身也引用了 `rx_callback_obj`，后遍历的普通自引用会把先前关联到的跨界写穿结果冲掉。
   - **改造（After）**：
     - `tools/p2im_oracle.py` 升级至 `DISASM_PARSER_VERSION = 3`（准确保留 `add` 助记符并解析 Thumb literal-pool `ldr rX, [pc, #imm]` / `=0x...`），排除 ARM `$d/$t/$a` mapping symbols；
     - `indexed_member_sites()` 扫描 `[base + index_reg]` 写点及邻近无符号上限比较 `cmp #N`（有 `cmp #63` 约束的 `getRxBuffer` 窗口止步于 `0x2000016c`，不产生误报；无界 `process_FC1/FC3` 按 `[base + member_offset, base + member_offset + 255]` 外推并命中下游对象 `rx_callback`）；
     - `merge_indexed_reach()` 将命中的越界函数挂入下游对象 `rx_callback` 的 `indexed_reach` 列表，**显式置 `call_edge: false`**（从不伪造函数调用边）；
     - TypeScript 侧 `sharedViaRank()` 严格规定优先级 `indexed_reach (3) > adjacent (2) > self-reference (1)`，确保后续普通全局符号不能覆盖跨界写穿的 `via_shared_global` 与 `upstream_functions`（历史 PLC 尝试 3 实测 `L5` 从 `0 downstream / 2 unmatched` 变为 **`2 known_p2im_bug_downstream`** 命中 `Modbus::process_FC1`）。

3. **宿主侧 `admit-seed` 严校验与 `L1–L5` 五层评估体系**
   - 模型调用 `seed_propose` 提交协议帧时，宿主 `cmd_admit_seed()` 执行四关校验：合法偶数十六进制、长度 `1..256` 字节、若 `frame == "modbus_rtu"` 则末 2 字节必须匹配小端 `crc16_modbus(payload[:-2])`、防泄漏正则通过；合格种子写入独立目录 `proposed-seeds/<sha256>.bin`，**原 `inputs/` 目录一字节不动**，保证 `B0` / `s1` 可溯源对照。
   - 代码落盘严格区分五个验证层级（拒绝把“AFL 报的 crash 数”直接当漏洞数）：
     - **`L1`**（`layers.l1`）：AFL 产出的原始 crash 文件总数（`crashes.raw_files`）；
     - **`L2`**（`layers.l2`）：至少复现出一次崩溃的**唯一崩溃指纹数**（按 `fault.kind | fault.address | last_bbl.function` 去重；原始重放文件数另记于 `layers_files`）；
     - **`L3`**（`layers.l3`）：经 `replay --repeat 3` 三次重放中 `outcome`、`fault.address` 与 `last_bbl.start` 全部一致的**唯一确定性崩溃指纹数**（严格满足 `L1 >= L2 >= L3 >= L4`，且 `triage_and_verify` 按 `outputs-s2` 优先轮询交错抽样，杜绝 `s1` 崩溃数较多时饿死 `s2` 新崩溃）；
     - **`L4`**（`layers.l4`）：经 `contrast` 在预算内缩减后，能找到**“删掉该决定性字节或再截断 1 字节后故障立即消失（`outcome != 'crash'`）”**的**唯一因果验证崩溃指纹数**（`contrast_confirmed === true`）；
     - **`L5`**（`scripts/score_l5.py`，`l5-0.4`）：**独立于 Agent 进程之后运行**。按二级标题 `## <Firmware>` 与三级 `### Bug` / `### Known, unpatched Bugs` 子节切分 `P2IM_patching_notes.md` 全部 5 个含真值目标（`CNC` 1、`Gateway` 3、`PLC` 4、`Heat_Press` 1、`Soldering_Iron` 3，共 12 个已知真值缺陷），结合纯 Python ELF32 `.symtab` 过滤 code-cave 借道补丁点并支持 `bbl_range` 区间匹配，输出**按唯一缺陷 ID（`bug_id`）去重的主指标 `unique_bugs`**（`unique_known_bugs_direct`、`unique_known_bugs_downstream`、`unique_known_bugs_total`、`matched_bug_ids`），同时保留候选级统计：
       - `known_p2im_bug_direct`：崩溃函数、基本块区间 `bbl_range` 或地址直接命中真值缺陷；
       - `known_p2im_bug_downstream`：崩溃发生在下游受害点，但其经静态/共享 SRAM 关联出的 `upstream_functions` 命中已知根因函数；
       - `unmatched_verified_candidate`：确定性且因果有效，但未命中 P2IM 已知补丁列表。

---

## 第二部分：全手工分步实操指南（Step 1 – Step 9）

> 下面每一个操作都给出**手工命令与即时验证手段**，方便审稿人或复现者逐层理解、单步调试与拆解验证。如果你已熟知全部步骤、只需快速批量部署环境，**Step 1–Step 5** 与自动化脚本 [`scripts/setup_upstreams.sh`](../scripts/setup_upstreams.sh) 完全等价。

---

### Step 1：宿主操作系统预检、环境变量约定与 `core_pattern` 配置

**目的**：确保运行在具备 ARM 交叉符号/反汇编器、QEMU 编译头文件与 `Node.js >= 22.19.0` 的原生 Linux ext4 环境，并消除 WSL2/桌面系统因 `core_pattern` 管道转储造成的 AFL 误判崩溃。

> **环境澄清（无需 Python `venv`）**：本仓库全部 Python 脚本及补丁后 P2IM 脚本均只依赖 Python 3 标准库（无 `requirements.txt` 或 `pip` 安装包）。请直接使用系统 `python3`（如 `3.12.3`），**不要**额外创建 Python 虚拟环境，以免子进程 PATH 切换导致版本偏差；Node.js 依赖由 `npm ci` 自动装入仓库内 `node_modules/`。
>
> **WSL2 重启提示**：WSL2 宿主机每次重启都会把 `/proc/sys/kernel/core_pattern` 重置为管道模式（如 `|/wsl-capture-crash ...`）。若复现期间重启过 WSL，开跑前务必重新执行下方 `1.3` 并确认输出为 `core`。

在 Ubuntu Bash（WSL2 请先执行 `wsl -d Ubuntu-24.04`）执行：

```bash
# 1.1 安装系统工具链与编译库（注意 psmisc 提供 killall，binutils-arm-none-eabi 提供 objdump/nm/readelf）
sudo apt-get update && sudo apt-get install -y \
  build-essential git pkg-config python3 psmisc \
  binutils-arm-none-eabi \
  libglib2.0-dev libpixman-1-dev libfdt-dev zlib1g-dev libjansson-dev \
  gdb-multiarch

# 1.2 验证必需宿主命令与版本
node -v                          # 期望 >= v22.19.0（见 package.json engines）
python3 --version                # 期望 >= 3.10（实测 3.12.3）
arm-none-eabi-objdump --version | head -n 1
which killall pkg-config

# 1.3 配置 WSL2 / Ubuntu 核心转储行为，避免外部进程拉起延迟导致 AFL dry-run 误判崩溃
echo core | sudo tee /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern   # 期望输出: core
```

接下来锁定工作区路径环境变量。**多实验共存时建议将以下模板写为独立工作区的 `env.sh`（按需 `source env.sh`）**，将所有路径锚定到专属根目录与短路径工作区（`P2IM_WORK_ROOT` 必须位于 Linux 原生 ext4 且使最长模型路径 `< 100` 字节）：

```bash
# 可保存为 ~/re-firmagent-p2im/env.sh 后执行: source ~/re-firmagent-p2im/env.sh
export REPO_ROOT="${REPO_ROOT:-$HOME/re-firmagent-p2im/firmagent-p2im}"
export DEPS_ROOT="${DEPS_ROOT:-$HOME/re-firmagent-p2im/deps}"
export P2IM_ROOT="${P2IM_ROOT:-$DEPS_ROOT/p2im}"
export HOEDUR_EXPERIMENTS_ROOT="${HOEDUR_EXPERIMENTS_ROOT:-$DEPS_ROOT/hoedur-experiments}"
export P2IM_TOOLS_ROOT="${P2IM_TOOLS_ROOT:-$HOME/re-firmagent-p2im/p2im-tools}"
export P2IM_WORK_ROOT="${P2IM_WORK_ROOT:-/tmp/re-fa-p2im}"
export QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$DEPS_ROOT/p2im-qemu-build}"

mkdir -p "$DEPS_ROOT" "$P2IM_TOOLS_ROOT/qemu" "$P2IM_TOOLS_ROOT/scripts" "$P2IM_WORK_ROOT"
```

---

### Step 2：克隆本仓库与上游公开 Commit，核验 10/10 未修补原版 ELF 哈希

**目的**：严格锁定论文级相同字节的 10 个未修补固件与两个上游源码基线，并亲手用 `arm-none-eabi-objdump` 验证“为何 `Soldering_Iron.elf` 需要 `P2IM_AUTO_FORKSERVER_PC`”。

```bash
# 2.1 克隆本开源仓库至 Linux 原生 ext4
git clone https://github.com/MagicSpirit007/firmagent-p2im.git "$REPO_ROOT"

# 2.2 拉取固定版本的 RiS3-Lab/p2im 及其真实固件子模块（用 && 串联避免首步失败后级联报错）
git clone https://github.com/RiS3-Lab/p2im.git "$P2IM_ROOT" && \
git -C "$P2IM_ROOT" checkout --force 0e64506a371b9c66ff67ed64a3fa65fa7e197e21 && \
git -C "$P2IM_ROOT" submodule update --init externals/p2im-real_firmware && \
git -C "$P2IM_ROOT/externals/p2im-real_firmware" rev-parse HEAD
# 期望输出: d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7

# 2.3 稀疏检出公开 hoedur-experiments（仅拉取未修补 Soldering_Iron.elf 与离线真值笔记）
git clone --filter=blob:none --no-checkout \
  https://github.com/fuzzware-fuzzer/hoedur-experiments.git "$HOEDUR_EXPERIMENTS_ROOT" && \
git -C "$HOEDUR_EXPERIMENTS_ROOT" sparse-checkout init --cone && \
git -C "$HOEDUR_EXPERIMENTS_ROOT" sparse-checkout set \
  targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron \
  02-coverage-est-data-set/binary-patching && \
git -C "$HOEDUR_EXPERIMENTS_ROOT" checkout 2babc78b72b1331b3122c11f170e9367132b8aa2
```

<details>
<summary>受限网络 / 无外网代理时的离线传包方案（git bundle + 浅克隆 git archive）</summary>

1. `firmagent-p2im`、`p2im`、`p2im-real_firmware`（完整历史仓库）可在有网机器使用 `git bundle create <name>.bundle --all` 打包后传入目标机 `git clone <name>.bundle ...`。
2. 若有网机器上的 `hoedur-experiments` 为 `--depth 1` 浅克隆，`git bundle` 会因缺少父提交在目标机 `git clone` 失败；本仓库所有脚本仅读取文件而不依赖其 `.git` 元数据，可用 `git archive` 精确导出所需两目录后再在目标机解压：

```bash
# 有网机器导出：
git -C "$SRC_HOEDUR" archive 2babc78b72b1331b3122c11f170e9367132b8aa2 \
  targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron \
  02-coverage-est-data-set/binary-patching \
  -o hoedur-subset.tar

# 目标机解压到 $HOEDUR_EXPERIMENTS_ROOT：
mkdir -p "$HOEDUR_EXPERIMENTS_ROOT" && tar -xf hoedur-subset.tar -C "$HOEDUR_EXPERIMENTS_ROOT"
```

</details>

**手工核验 10 个 ELF SHA256 与 `svc 0x3f` 实证差异**：

```bash
# 查看第 1–9 个固件的 sha256sum（与第 3 节表核对）
sha256sum "$P2IM_ROOT/externals/p2im-real_firmware/binary/"{PLC,CNC,Gateway,Reflow_Oven,Robot,Drone,Console,Heat_Press,Steering_Control}
sha256sum "$HOEDUR_EXPERIMENTS_ROOT/targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf"

# 或调用 oracle 批量校验全部 10 份 ELF 特征并写入临时核对清单
python3 "$REPO_ROOT/tools/p2im_oracle.py" identify-all --out /tmp/manifest-check.json

# 亲手用 binutils 验证 Soldering_Iron 无 svc 0x3f，且入口/目标 PC 存在 0x08000268：
arm-none-eabi-objdump -d "$P2IM_ROOT/externals/p2im-real_firmware/binary/PLC" | grep -E 'svc\s+(63|0x3f)' | head -n 5
# 期望: 能看到 svc 63 / 0x3f 调用点
arm-none-eabi-objdump -d "$HOEDUR_EXPERIMENTS_ROOT/targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf" | grep -cE '\bsvc\s+(63|0x3f)' || true
# 期望输出: 0
arm-none-eabi-objdump -d "$HOEDUR_EXPERIMENTS_ROOT/targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf" | grep -E '^\s*800026[0-9a-f]:' | head -n 5
```

10 个未修补原版固件完整 SHA256 与板卡锁定对照表：

| 目标 | 锁定板卡 / MCU | 完整期望 SHA256 |
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

### Step 3：手工编译 P2IM AFL 2.06b

**目的**：获得与现代 GCC ABI 匹配的 `afl-fuzz`，用于承载 P2IM forkserver 变异循环。

```bash
make -C "$P2IM_ROOT/afl" -j"$(nproc)"
test -x "$P2IM_ROOT/afl/afl-fuzz" && "$P2IM_ROOT/afl/afl-fuzz" -h | head -n 5
```

---

### Step 4：手工审阅 16 文件 QEMU 补丁、核验板卡不变量并编译 `qemu-system-gnuarmeclipse`

**目的**：将 `P2IM_AUTO_FORKSERVER_PC`（零改 ELF 支持 `Soldering_Iron`）、`PM_EXEC_PERI = 0x72`（MMIO 取指保护）与 Python 3.12 / `--disable-sdl` 构建修复合入 `qemu.git` 并编译（详细文件解释见 [`docs/BUILD_QEMU.md`](BUILD_QEMU.md)）。

```bash
# 4.1 审阅补丁修改清单与行变动统计（应精确列出 16 个文件）
git -C "$REPO_ROOT" apply --stat patches/p2im-qemu-auto-forkserver.patch

# 4.2 将补丁应用至 P2IM 内嵌的 qemu.git 源码树（先干跑检查无冲突）
# 注：git apply 对 configure 与 scripts/tracetool.py 打印的 `type 100755, expected 100644`
# 属于上游 Git 树文件模式正常提示，不影响补丁应用与后续可执行权限，可安全忽略。
git -C "$P2IM_ROOT" apply --check --directory=qemu/src/qemu.git \
  "$REPO_ROOT/patches/p2im-qemu-auto-forkserver.patch" && \
git -C "$P2IM_ROOT" apply --directory=qemu/src/qemu.git \
  "$REPO_ROOT/patches/p2im-qemu-auto-forkserver.patch"

# 4.3 必须检查板卡配置不变量（严禁将 CONFIG_KINETIS 设为 y，否则与 stm32-boards.c 双重注册导致启动 abort）
grep -E '^(CONFIG_STM32|CONFIG_KINETIS|CONFIG_SAM)=' \
  "$P2IM_ROOT/qemu/src/qemu.git/default-configs/gnuarmeclipse-softmmu.mak"
# 期望输出包含: CONFIG_STM32=y 且 CONFIG_KINETIS=n、CONFIG_SAM=n

# 4.4–4.5 在独立构建目录执行 configure、精确补齐 LIBS+=-ljansson、make、安装与符号核验
# 注：Ubuntu 24.04 默认启用 ld --as-needed，--extra-ldflags 里的 -ljansson 位于 .o 之前会被丢弃；
# 必须精确检测 `^LIBS` 行并将 -ljansson 追加到 LIBS 末尾。以下使用 && 串联以防中途静默失败。
mkdir -p "$QEMU_BUILD_DIR" && \
(
  cd "$QEMU_BUILD_DIR" && \
  "$P2IM_ROOT/qemu/src/qemu.git/configure" \
    --prefix="$QEMU_BUILD_DIR/install" \
    --target-list=gnuarmeclipse-softmmu \
    --python="$(command -v python3)" \
    --disable-werror --disable-docs --disable-gtk --disable-sdl \
    --disable-vnc --disable-xen --disable-kvm --disable-guest-agent \
    --extra-cflags="$(pkg-config --cflags jansson 2>/dev/null || true)" \
    --extra-ldflags="$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)" && \
  { grep -qE '^LIBS[[:space:]]*\+?=.*-ljansson([[:space:]]|$)' config-host.mak || {
    echo "QEMU_CFLAGS+=$(pkg-config --cflags jansson 2>/dev/null || true)" >> config-host.mak &&
    echo "LIBS+=$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)" >> config-host.mak
  }; } && \
  make -j"$(nproc)"
) && \
install -m 755 "$QEMU_BUILD_DIR/gnuarmeclipse-softmmu/qemu-system-gnuarmeclipse" \
  "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse" && \
nm "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse" | grep ' T p2im_maybe_auto_forkserver'
# 期望输出含: ... T p2im_maybe_auto_forkserver
```

---

### Step 5：手工部署 Python 3.12 运行脚本、`wsl_compat.py` 与生成 10 份 Campaign 配置

**目的**：将原版 `me.py`/`fuzz.py`/`cov.py`/`statFp3.py` 适配为 Python 3.12 可执行版本并注入 `no_retry = {0x72}` 与 WSL2 环境变量，随后生成短路径版 `configs/m3/*.json`。

```bash
# 5.1 复制 4 份上游 P2IM 运行脚本并归一化为 LF
cp "$P2IM_ROOT/model_instantiation/fuzz.py" "$P2IM_TOOLS_ROOT/scripts/fuzz.py"
cp "$P2IM_ROOT/model_instantiation/me.py" "$P2IM_TOOLS_ROOT/scripts/me.py"
cp "$P2IM_ROOT/utilities/coverage/cov.py" "$P2IM_TOOLS_ROOT/scripts/cov.py"
cp "$P2IM_ROOT/utilities/model_stat/statFp3.py" "$P2IM_TOOLS_ROOT/scripts/statFp3.py"

python3 - "$P2IM_TOOLS_ROOT/scripts" <<'PY'
from pathlib import Path
import sys
for name in ("fuzz.py", "me.py", "cov.py", "statFp3.py"):
    p = Path(sys.argv[1]) / name
    p.write_bytes(p.read_bytes().replace(b"\r\n", b"\n"))
PY

# 5.2 应用 Python 3.12 + 0x72 补丁并部署 wsl_compat.py 与 me 包装器
patch -d "$P2IM_TOOLS_ROOT/scripts" -p1 < "$REPO_ROOT/patches/p2im-python312-scripts.patch"
cp "$REPO_ROOT/p2im-shim/wsl_compat.py" "$P2IM_TOOLS_ROOT/scripts/wsl_compat.py"

cat > "$P2IM_TOOLS_ROOT/scripts/me" <<'EOF'
#!/usr/bin/env bash
exec python3 "$(cd "$(dirname "$0")" && pwd)/me.py" "$@"
EOF
chmod +x "$P2IM_TOOLS_ROOT/scripts/"{fuzz.py,me.py,cov.py,statFp3.py,me}

# 5.3 验证语法无误
python3 -m py_compile "$P2IM_TOOLS_ROOT/scripts/"{fuzz.py,me.py,cov.py,wsl_compat.py}

# 5.4 按本机绝对路径生成 configs/m3/*.json（自动校验最长模型路径 < 100 字节）
python3 "$REPO_ROOT/scripts/generate_configs.py" \
  --p2im-root "$P2IM_ROOT" \
  --hoedur-root "$HOEDUR_EXPERIMENTS_ROOT" \
  --work-root "$P2IM_WORK_ROOT" \
  --out-dir "$REPO_ROOT/configs/m3"
```

> **提示**：如果你无需逐行手动审阅 Step 1–Step 5，仓库内的 [`scripts/setup_upstreams.sh`](../scripts/setup_upstreams.sh) 与以上五步命令一一对应、完全等价，可直接运行 `bash scripts/setup_upstreams.sh`。

---

### Step 6：洁净树隐私自检、安装 Node.js 运行时、构建 TypeScript 并运行离线验证套件

**目的**：先在未构建的干净源码树完成发版前目录清洁度门禁（`hits=0`），再安装依赖、锁定 Pi SDK `0.85.1` 及相关契约单测，在不调用外部收费 LLM（`model_requests = 0`）的情况下检验宿主编排层与 `score_l5.py` 的契约正确性。

> **切勿在构建之后删除 `node_modules/` 或 `dist/`！** `npm run verify:privacy` 默认检查仓库中是否存在发布禁止目录（`node_modules/`、`dist/`、`__pycache__/`）。因此必须在 `npm ci` **之前**执行；构建完成后如只需审计源码密钥与敏感字面量，请加 `--ignore-build-artifacts`。

```bash
cd "$REPO_ROOT"

# 6.0 发版前洁净门禁（在 npm ci / build 之前运行；期望 hits=0）
python3 scripts/privacy_audit.py

# 6.1 安装 Node 依赖并构建（国内或无代理环境可改用 --registry=https://registry.npmmirror.com）
npm ci --no-audit --no-fund && npm run build
# 如直连官方源超时：
# npm ci --registry=https://registry.npmmirror.com --no-audit --no-fund && npm run build

# 6.2 TypeScript 契约测试（含预算/thinking/截断诊断/队列继承/B0 归因与防泄漏测试）
npm test

# 6.3 Python Oracle 与 L5 计分器单测（挂载真实 ELF 与 Notes 时全量通过且 0 条跳过、0 条 ResourceWarning）
P2IM_ROOT="$P2IM_ROOT" \
HOEDUR_EXPERIMENTS_ROOT="$HOEDUR_EXPERIMENTS_ROOT" \
P2IM_NOTES="$HOEDUR_EXPERIMENTS_ROOT/02-coverage-est-data-set/binary-patching/P2IM_patching_notes.md" \
npm run test:py

# 6.4 构建后如仅复查源码密钥/敏感字面量（保留 node_modules 与 dist）：
python3 scripts/privacy_audit.py --ignore-build-artifacts
# 期望: hits=0

# 6.5 CLI 只读连通自检（不发模型请求、不读取密钥内容）
node dist/src/cli.js doctor --provider deepseek --model deepseek-v4-flash
```

---

### Step 7：不依赖 TypeScript Agent 外壳，手工解剖 `p2im_oracle.py` 全链路（强烈推荐用于审稿走查）

**目的**：让研究者跳过上层 Agent 黑盒，亲眼验证每一份宿主工件（`meta.json`、QEMU shim、Round 0 `peripheral_model.json`、`sources.json`、带 `indexed_reach` 与 `call_edge: false` 的 `paths.json`、CRC16 种子准入正反例、`L3` 三次重放、`L4` 决定性字节消融），并手工复现 `Soldering_Iron` 与 `Reflow_Oven` 两大边界突破。

#### 7.1 `prepare` + 检验 `unset LD_LIBRARY_PATH` shim 与双初始种子

```bash
WORK_MANUAL="/tmp/fa-manual"
python3 "$REPO_ROOT/tools/p2im_oracle.py" prepare \
  --target PLC \
  --elf "$P2IM_ROOT/externals/p2im-real_firmware/binary/PLC" \
  --expect-sha256 783108cf8b9cf7f703a4164dfee7d12d9a9f79d663328a21454a70a7003c2b08 \
  --work-root "$WORK_MANUAL"

# 验证：1) 原版 ELF SHA256 原字节复制；2) QEMU shim 已包含 unset LD_LIBRARY_PATH；3) 存在双初始种子
sha256sum "$WORK_MANUAL/plc/PLC.elf"
cat "$WORK_MANUAL/bin/qemu-system-gnuarmeclipse"
ls -la "$WORK_MANUAL/plc/inputs/"
# 期望同时看到 256B 的 seed-random 与 4B 的 seed-short
```

#### 7.2 `smoke` + `me --round 0` 外设自动化建模

```bash
python3 "$REPO_ROOT/tools/p2im_oracle.py" smoke --target PLC --work-root "$WORK_MANUAL"
cat "$WORK_MANUAL/plc/evidence/smoke.log" | tail -n 10

python3 "$REPO_ROOT/tools/p2im_oracle.py" me --target PLC --round 0 --work-root "$WORK_MANUAL"
# 查看自动提取的外设数量、DR 寄存器精确步长与地址、以及中断号
python3 - "$WORK_MANUAL/plc/evidence/me-round.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["model"]
print("peripherals:", d["peripheral_count"], "dr_count:", len(d["dr_registers"]))
print("sample_dr:", d["dr_registers"][:5])
PY
```

#### 7.3 第一段纯 AFL 搜索（`s1`）与实时统计

```bash
# 测试短窗可设 60s（正式对比段通常设 300s 或 480s）
python3 "$REPO_ROOT/tools/p2im_oracle.py" fuzz \
  --target PLC --segment s1 --seconds 60 --work-root "$WORK_MANUAL"

python3 "$REPO_ROOT/tools/p2im_oracle.py" status --target PLC --work-root "$WORK_MANUAL"
# 查看 totals.execs_done, crash_files, unique_crashes
```

#### 7.4 `extract-sources` 与共享 SRAM 跨中断切片 `slice-paths`

```bash
python3 "$REPO_ROOT/tools/p2im_oracle.py" extract-sources --target PLC --work-root "$WORK_MANUAL"
python3 "$REPO_ROOT/tools/p2im_oracle.py" slice-paths --target PLC --reach-seeds 2 --work-root "$WORK_MANUAL"

# 解剖 analysis/paths.json 中的 rx_callback（期望看见 call_edge: false 与来自 slave 的 indexed_reach）
python3 - "$WORK_MANUAL/plc/analysis/paths.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print("counts:", p["counts"])
for g in p["shared_globals"]:
    if g["symbol"] in ("rx_callback", "slave", "rx_callback_obj"):
        print(json.dumps({
            "symbol": g["symbol"],
            "address": g["address"],
            "call_edge": g["call_edge"],
            "interrupt_write_side": g["interrupt_write_side"],
            "main_consume_side": g["main_consume_side"],
            "indexed_reach": g.get("indexed_reach", []),
            "adjacent": [a["symbol"] for a in g.get("adjacent", [])],
        }, indent=2))
PY
```

#### 7.5 宿主侧协议种子校验正反例与第二段引导搜索（`s2`）

```bash
# 反例（刻意篡改 CRC16 末字节为 00）：宿主必须以 exit 3 拒绝，check="crc16"
python3 "$REPO_ROOT/tools/p2im_oracle.py" admit-seed \
  --target PLC --hex 01030000000ac500 --frame modbus_rtu \
  --note "bad crc verification" --work-root "$WORK_MANUAL" || true

# 正例（功能码 0x03 Read Holding Registers，小端 CRC16 = 0xc5cd）：宿主校验通过并放入 proposed-seeds/
python3 "$REPO_ROOT/tools/p2im_oracle.py" admit-seed \
  --target PLC --hex 01030000000ac5cd --frame modbus_rtu \
  --note "valid modbus read holding registers" --work-root "$WORK_MANUAL"

# 辅助公式：用自带 crc16_modbus 为任意自定义 Modbus 请求体计算小端 CRC16
python3 -c 'import sys; sys.path.insert(0, "tools"); import p2im_oracle as o; b=bytes.fromhex("010100000010"); c=o.crc16_modbus(b); print((b+bytes((c&0xff, c>>8))).hex())'

# 核验原 inputs/ 与 outputs-s1/ 依然完整只读，而 proposed-seeds/ 独立存放提案种子
ls -la "$WORK_MANUAL/plc/inputs/" "$WORK_MANUAL/plc/proposed-seeds/"

# 开启 --inherit-queue s1 --include-proposed 跑第二段（inputs-s2/ 用短文件名 b00/q0000/p00 汇总 inputs + outputs-s1/queue/* + proposed-*.bin，映射关系写入 evidence/inputs-s2-map.json，累积外设模型延续至 0.s2/，不污染 inputs/ 与 outputs-s1/）
python3 "$REPO_ROOT/tools/p2im_oracle.py" fuzz \
  --target PLC --segment s2 --seconds 60 --inherit-queue s1 --include-proposed --work-root "$WORK_MANUAL"
```

#### 7.6 确定性重放（`L3`）与 Contrast 决定性字节消融（`L4`）+ 可选硬件写断点观察

```bash
python3 "$REPO_ROOT/tools/p2im_oracle.py" crashes --target PLC --work-root "$WORK_MANUAL"

# 从上面 crashes 输出中安全读取第一条 crash id（60s 短窗可能暂无 crash，切勿直接下标 [0] 否则 IndexError）
CRASH_ID="$(python3 -c 'import json; d=json.load(open("/tmp/fa-manual/plc/evidence/crash-index.json")); print(d["crashes"][0]["id"] if d.get("crashes") else "")')"
echo "CRASH_ID=${CRASH_ID:-<none_in_60s>}"
# 若 CRASH_ID 为空（60s 短窗 0 crash），可补跑一段 300s 窗口（--segment s3 --seconds 300 --inherit-queue s2）或直接进入 Step 8（300s×2）

if [ -n "$CRASH_ID" ]; then
  # L3: 连续重放 3 次，期望 deterministic: true
  python3 "$REPO_ROOT/tools/p2im_oracle.py" replay \
    --target PLC --input "$CRASH_ID" --repeat 3 --work-root "$WORK_MANUAL"

  # L4: Contrast 缩小种子并删去单字节验证因果消失（输出 contrast_confirmed: true 与 decisive_byte）
  python3 "$REPO_ROOT/tools/p2im_oracle.py" contrast \
    --target PLC --input "$CRASH_ID" --op trim --max-replays 40 --work-root "$WORK_MANUAL"

  # 可选（若已安装 gdb-multiarch）：在疑似越界对象 rx_callback (0x20000214) 下数据写断点验证写穿现场
  python3 "$REPO_ROOT/tools/p2im_oracle.py" gdb-watch \
    --target PLC --input "$CRASH_ID" --watch 0x20000214 --work-root "$WORK_MANUAL"
fi
```

#### 7.7 两大关键兼容性特例手工对比验证（`Soldering_Iron` 与 `Reflow_Oven`）

```bash
# 特例 1：Soldering_Iron 原字节 ELF（无 svc 0x3f），通过 --auto-forkserver-pc 0x08000268 打通
python3 "$REPO_ROOT/tools/p2im_oracle.py" prepare \
  --target Soldering_Iron \
  --elf "$HOEDUR_EXPERIMENTS_ROOT/targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron/Soldering_Iron.elf" \
  --expect-sha256 44a6f0e31a6187a6e4f53032390157cfbba3a2ff68c4a7ea2fd83baf22e9a519 \
  --auto-forkserver-pc 0x08000268 --work-root /tmp/fa-manual-si
python3 "$REPO_ROOT/tools/p2im_oracle.py" smoke --target Soldering_Iron --work-root /tmp/fa-manual-si
grep -E "forkserver|auto_forkserver" /tmp/fa-manual-si/soldering-iron/evidence/smoke.log || true
# 期望在日志中看到 "start up afl forkserver!"
python3 "$REPO_ROOT/tools/p2im_oracle.py" me --target Soldering_Iron --round 0 --work-root /tmp/fa-manual-si
python3 "$REPO_ROOT/tools/p2im_oracle.py" fuzz --target Soldering_Iron --segment s1 --seconds 60 --work-root /tmp/fa-manual-si

# 特例 2：Reflow_Oven（凭 cmd_prepare 自动写入的 4B seed-short 跨过 dry-run 崩溃障碍）
python3 "$REPO_ROOT/tools/p2im_oracle.py" prepare \
  --target Reflow_Oven \
  --elf "$P2IM_ROOT/externals/p2im-real_firmware/binary/Reflow_Oven" \
  --expect-sha256 be996b5bba1a7381d2867fedacc7df52fa55819817560a10ae7ac951e8676346 \
  --work-root /tmp/fa-manual-rf
python3 "$REPO_ROOT/tools/p2im_oracle.py" me --target Reflow_Oven --round 0 --work-root /tmp/fa-manual-rf
python3 "$REPO_ROOT/tools/p2im_oracle.py" fuzz --target Reflow_Oven --segment s1 --seconds 60 --work-root /tmp/fa-manual-rf
# 验证：execs_done > 0 且无 "PROGRAM ABORT"
```

#### 7.8 一屏只读体检与工作根级残留进程核查

```bash
# 使用只读 verify_step7.py 一屏汇总检查 SHA256、QEMU、smoke、me、segments、paths（call_edge=false）、L3/L4 与工作根进程：
python3 "$REPO_ROOT/scripts/verify_step7.py" \
  --work-root "$WORK_MANUAL" \
  --work-root /tmp/fa-manual-si \
  --work-root /tmp/fa-manual-rf \
  --check-procs

# 若需用 pgrep 检查残留进程，务必按当前工作根路径过滤，避免误杀同机其他无关实验：
pgrep -af "$WORK_MANUAL" || true
```

---

### Step 8：运行受控三臂实验（`B0` 基线、`--mode offline`、`--mode real`）

**目的**：在严格隔离的短路径 `--work-root` 下，使用同口径状态机比较 **`b0`（纯原版 P2IM 单段连续）**、**`offline`（无模型切片骨架）** 与 **`real`（大模型提案闭环）** 的端到端墙钟、`execs_done`、统一 BBL 并集覆盖率与 `L1–L5` 发现效果。

> **工作区防撞（必须独立 `--work-root`）**：切勿让不同臂复用同一个 `work_root`，否则第二轮命中 `ORACLE_REFUSED: segment output directory is not empty`；且 `configs/m3/*.json` 里默认共享 `$P2IM_WORK_ROOT`。请直接向 CLI 传入 `--work-root` 覆盖（例如 `/tmp/fa-b0`、`/tmp/fa-off`、`/tmp/fa-r1`）。
> **同墙钟 / 同执行次数双预算与配对种子**：
> - **同端到端探索墙钟（`--fuzz-budget-s 1200`）**：`b0` 单段跑满 `1200s`；`offline` / `real` 先跑 `seg1`（如 `--segment-seconds 300`），扣除 `slice + analyze_and_propose` 真实耗时后将剩余秒数分配给 `seg2`（若剩余不足 `15s` 则显式记 `SEG2_SKIPPED_WALL_BUDGET` 并将状态标为 `partial`，绝不静默伪装 `completed`）；事后覆盖率重放 `bbl-coverage` 在 `end_to_end_wall_ms` 冻结之后独立统计于 `eval_coverage_wall_ms`，不污染三臂墙钟对比。
> - **同目标执行次数（`--max-execs N`）**：可选传入 `--max-execs N` 让 `b0` 与两段模式按相同总 `execs_done` 上限停机。
> - **配对随机种子与重试累计（`--seed` / `--resume` / `--parent-out`）**：多轮独立试验传入 `--seed 1707`（`2707`、`3707`）使同轮三臂共享完全一致的确定性初始种子；中断恢复传 `--resume <attempt_id>`，跨目录重跑传 `--parent-out <prev_run_dir>` 自动累计前序请求、Token、墙钟与执行次数（`cumulative_cost`）。
> - **默认配置冻结**：`real` 模式默认 `max_tokens = 160000`、`max_output_tokens = 16384`、`wall_ms = 3600000`、`analyze_model_calls = 6`、`--thinking low`、`--replay-model-calls 0`（确定性宿主重放，可传 `--replay-model-calls 2` 做消融）、`--inherit-queue-s2 true`。

#### 8.0 纯原版 P2IM 单段基线臂：`--mode b0`（`model_requests = 0`）

```bash
cd "$REPO_ROOT"
node dist/src/cli.js mcu-p2im \
  --config configs/m3/plc.json \
  --work-root /tmp/fa-b0 \
  --out /tmp/runs/plc-b0 \
  --mode b0 \
  --fuzz-budget-s 1200 --seed 1707 \
  --collect-coverage true

# 产出：score-owned.json（含 stage_wall_ms、total_execs_done、coverage）与
# l5-candidates-bare.json（纯原版 P2IM 裸结果，无共享 SRAM 切片）/ l5-candidates.json（同套离线 SRAM 切片归因）
```

#### 8.1 消融对照臂：`--mode offline`（`model_requests = 0`）

```bash
cd "$REPO_ROOT"
node dist/src/cli.js mcu-p2im \
  --config configs/m3/plc.json \
  --work-root /tmp/fa-off \
  --out /tmp/runs/plc-offline \
  --mode offline \
  --segment-seconds 300 --fuzz-budget-s 1200 --seed 1707 \
  --collect-coverage true

# 核对：status="completed", totals.model_calls=0, 并产出 L1..L4、coverage 与两份 l5-candidates*.json
cat /tmp/runs/plc-offline/score-owned.json
```

#### 8.2 真实大模型闭环臂：`--mode real`（DeepSeek）

> **凭据安全规则**：仅使用运行时交互式环境变量 `DEEPSEEK_API_KEY`（或私有目录 `~/.pi/agent/auth.json`），**严禁把密钥写入仓库配置、日志文件或命令参数**。Pi SDK `0.85.1` 默认注册表内置 `deepseek` 的 `deepseek-v4-flash` / `deepseek-v4-pro`；如需兼容格式自定义端点，可参照 [`configs/pi-agent-example/models.json`](../configs/pi-agent-example/models.json) 放至私有 `--pi-agent-dir`。

```bash
read -rsp "DEEPSEEK_API_KEY: " DEEPSEEK_API_KEY && export DEEPSEEK_API_KEY && echo

node dist/src/cli.js mcu-p2im \
  --config configs/m3/plc.json \
  --work-root /tmp/fa-r1 \
  --out /tmp/runs/plc-real-r1 \
  --mode real \
  --segment-seconds 300 --fuzz-budget-s 1200 --seed 1707 \
  --provider deepseek --model deepseek-v4-flash \
  --thinking low --max-output-tokens 16384 --analyze-model-calls 6 \
  --replay-model-calls 0 \
  --model-calls 16 --max-total-tokens 160000 \
  --collect-coverage true
```

运行结束后的关键核验项：
1. `/tmp/runs/plc-real-r1/state.json`：`status === "completed"`、`work_dir === "/tmp/fa-r1/plc"`、`model_diagnostics.thinking === "low"`、`model_diagnostics.analyze_length_truncations === 0` 且 `warnings` 为空（若因 `stop_reason === "length"` 导致 0 种子，会显式告警 `ANALYZE_TRUNCATED_ZERO_SEEDS`）；
2. `/tmp/runs/plc-real-r1/account.json` 与 `ledger.jsonl`：核验每笔模型请求均为 `settled`、`triage_mode` 为 `host_deterministic`、总 `tokens` 与 `stage_wall_ms`；
3. `/tmp/runs/plc-real-r1/l5-candidates.json`：核验 `admitted_seeds` 记有 `crc_checked` 与字节长度，候选已按崩溃点去重并附带 `bbl_range` 与 `witness_count`；同时 `/tmp/fa-r1/plc/inputs-s2/` 包含短命名继承队列（`q0000*`）与提案种子（`p00*`），完整溯源映射见 `/tmp/fa-r1/plc/evidence/inputs-s2-map.json`。

---

### Step 9：盲测隔离的宿主离线 `L5` 计分与论文级三臂对比评估

#### 9.1 在所有 Agent 会话完全终止后运行离线 `L5` 与防泄漏审计

```bash
NOTES="$HOEDUR_EXPERIMENTS_ROOT/02-coverage-est-data-set/binary-patching/P2IM_patching_notes.md"

# 1) 对单次运行做 L5 评分（同时输出 bare_without_sram_slice 与 with_shared_sram_slice 双口径）
python3 "$REPO_ROOT/scripts/score_l5.py" \
  --notes "$NOTES" \
  --candidates /tmp/runs/plc-real-r1/l5-candidates.json \
  --target PLC \
  --summary-only \
  --out /tmp/runs/plc-real-r1/l5.json

# 2) 防泄漏审计：务必传入与该次运行一致的 --work-dir（或省略 --work-dir 由 --candidates 里的 work_dir 自动定位）
python3 "$REPO_ROOT/scripts/leak_check.py" \
  --work-dir /tmp/fa-r1/plc \
  --candidates /tmp/runs/plc-real-r1/l5-candidates.json \
  --out /tmp/runs/plc-real-r1/leak-check.json

# 3) 如运行未传 --collect-coverage true，也可事后对工作区离线提取统一唯一基本块并集覆盖率（BBL(s1) ∪ BBL(s2) vs BBL(B0)）
python3 "$REPO_ROOT/tools/p2im_oracle.py" bbl-coverage --target PLC --work-root /tmp/fa-r1

# 4) 同口径三臂对比（拆开报告 B0 裸结果 vs B0+静态切片 vs offline vs real，并给出同墙钟与同 execs_done 口径、raw/中位数/离散区间与成对 BBL 差集）
python3 "$REPO_ROOT/scripts/eval_arms.py" compare \
  --arm b0=/tmp/runs/plc-b0 \
  --arm offline=/tmp/runs/plc-offline \
  --arm real=/tmp/runs/plc-real-r1 \
  --notes "$NOTES" \
  --out /tmp/runs/plc-compare.json \
  --markdown /tmp/runs/plc-compare.md

cat /tmp/runs/plc-real-r1/l5.json
cat /tmp/runs/plc-real-r1/leak-check.json
cat /tmp/runs/plc-compare.md
```

期望验收标准：
- `leak-check.json`：`"work_dir": "/tmp/fa-r1/plc"`、`"leak_in_prompt": false`、`"total_hits": 0`、`missing` 为空（`leak_check.py` 会自动同扫同目录 `ledger.jsonl` 与工具定义源码，若显式 `--work-dir` 与 `candidates.work_dir` 不一致则以退出码 `2` 拒绝）；
- `l5.json`（`mcu-p2im/l5-0.4`）：同时输出按唯一缺陷 ID 去重的 `unique_bugs`（`unique_known_bugs_direct`、`unique_known_bugs_downstream`、`unique_known_bugs_total`、`matched_bug_ids`）与候选计数 `counts`、`attribution_split`（`bare_without_sram_slice` vs `with_shared_sram_slice` vs `sram_slice_net_gain`），且 `"raw_text_emitted": false`；
- `plc-compare.json` / `plc-compare.md`：以唯一已知缺陷数（`unique_bugs`）作为 `L5` 主指标，明确区分四条归因口径、同端到端墙钟与执行次数效率视角（若需严格同 `execs_done` 对照则运行期加 `--max-execs N`），以及统一 `unique_bbls_union` 并集覆盖率。

#### 9.2 正式论文级对照实验设计准则（三臂对照 & 统计口径）

若要将本框架用于发表级对比评估，请遵循以下严格准则：
1. **保留三臂完整对照并拆开静态切片归因**：
   - **`B0` 裸基线（`--mode b0` + `l5-candidates-bare.json`）**：纯原版 P2IM 单段 AFL，不计入共享 SRAM 切片归因；
   - **`B0 + 离线共享 SRAM 切片`（`--mode b0` + `l5-candidates.json`）**：将同套静态/共享 SRAM 切片仅作为离线归因工具叠加到 `B0`，用于独立剥离切片模块净收益；
   - **`--mode offline`（两段无 Agent 对照臂）**：保留分段（`s2` 默认继承 `s1` 队列）、切片、`L3/L4` 验证，但 `model_calls = 0`；
   - **`--mode real`（FirmAgent-P2IM 完整臂）**：开启 Pi 受控分析与 `seed_propose` 引导 `s2` 探索（亦可设 `--inherit-queue-s2 false` 消融冷重启）。
2. **统一覆盖率与双时间预算口径分开报告**：
   - 覆盖率采用 `tools/p2im_oracle.py bbl-coverage` 基于 QEMU `-trace` 提取的**唯一基本块并集**（`BBL(s1) ∪ BBL(s2)` vs `BBL(B0)`），禁止将分段 AFL `paths_total` 直接相加；
   - **同端到端墙钟对比**：保证 `B0` 单段总时长等于 `mcu-p2im` 的全流程墙钟（包含切片、LLM 推理往返与重放开销）；
   - **同目标执行次数对比**：另行比较相同 `execs_done` 预算（及 `per 1k execs`）下的 `unique_bbls_union` 与 `L3/L4/L5` 产出。
3. **跨目标禁止直接比大小**：裸机 MCU 分属四套芯片/外设模型（STM32F429、STM32F103、K64F、SAM3X8E），绝不跨不同目标对比 `execs_done` 或覆盖数绝对值；仅在同一固件内部做配对比较（`scripts/eval_arms.py compare` 会自动拒绝跨目标混比）。
4. **多随机种子独立工作根与完整分布汇报**：至少独立运行 3 次（初筛 3 轮，正式评估按试跑方差冻结更多独立种子，每轮重建全新 `--work-root` 清空语料与模型缓存），可向 `scripts/eval_arms.py compare` 重复传入多次 `--arm real=<dir>`，论文表格须同时列出**单次原始值、中位数与离散区间**，并单列 `provider`/`model`/`thinking` 档位、模型请求次数、Token 总量与计费口径（不可仅汇报 3 次均值）。

---

## 第三部分：关键产物 Schema 字典与真实排错指南

### 3.1 工件清单

| 路径 | 生产者 | 核心内容 |
|---|---|---|
| `$P2IM_WORK_ROOT/<slug>/meta.json` | `oracle prepare` | 锁定 ELF SHA256、板卡/MCU、可选 `auto_forkserver_pc` |
| `$P2IM_WORK_ROOT/bin/qemu-system-gnuarmeclipse` | `oracle prepare` | 清空 `LD_LIBRARY_PATH` 后转调重编 QEMU 的宿主 shim |
| `$P2IM_WORK_ROOT/<slug>/inputs/{seed-random,seed-short}` | `oracle prepare` | 256B 确定性种子与 4B `0\n\x00\x00` 避坑短种子 |
| `$P2IM_WORK_ROOT/<slug>/0/peripheral_model.json` | `oracle me` / `me.py` | Round 0 外设寄存器接口模型（SR / CR / DR / 中断） |
| `$P2IM_WORK_ROOT/<slug>/analysis/{sources,paths}.json` | `oracle extract-sources / slice-paths` | 全轮 DR 读点、`via_shared_global` 与 `indexed_reach`（`call_edge: false`） |
| `$P2IM_WORK_ROOT/<slug>/proposed-seeds/` | `oracle admit-seed` | 经过长度、防泄漏与 CRC16 校验的模型提案种子 |
| `<out>/{state,account,score-owned}.json` | `mcu-runtime.ts` | 状态机流转、逐笔模型/Token 账本、`L1–L4` 验证分层 |
| `<out>/l5-candidates.json` & `l5-candidates-bare.json` | `mcu-runtime.ts` | 送往离线评分的确定性崩溃列表（分别含共享 SRAM 上游候选与裸崩溃口径） |
| `<out>/l5.json`, `leak-check.json`, `arm-summary.json` | `score_l5.py` / `leak_check.py` / `eval_arms.py` | 宿主事后离线 `L5` 双归因统计、防泄漏审计与三臂对比汇总 |
| `$P2IM_WORK_ROOT/<slug>/analysis/bbl-coverage.json` | `oracle bbl-coverage` | 基于 QEMU `-trace` 的跨段唯一基本块并集覆盖率（`BBL(s1) ∪ BBL(s2)`） |

### 3.2 真实环境常见故障速查表

| 报错 / 现象 | 原因 | 解决方法 |
|---|---|---|
| `PROGRAM ABORT : -c options should be shorter than 100 bytes` | `work_root` 路径过长（P2IM AFL `-c` 硬限制 `< 100` 字节） | 将 `--work-root` 设为 `/tmp/fa-p2im` 或 `/home/<user>/m3` 等短路径 |
| `EPERM: fsync`（位于 `/mnt/c` 或 `/mnt/d`） | WSL2 9p 文件系统不支持目录 `fsync` 语义，且跨盘 QEMU I/O 慢 | 把仓库、`work_root` 与 `--out` 放在 Linux 原生 ext4 分区 |
| `undefined symbol: g_string_free_and_steal` | 旧版 `LD_LIBRARY_PATH` 加载了 2017 年 `libglib-2.0.so.0` | 必须通过 `p2im_oracle.py` 生成的 shim（含 `unset LD_LIBRARY_PATH`）运行 QEMU |
| `FRDM-K64F` 启动即 `abort` (`already exists`) | QEMU 编译配置误开了 `CONFIG_KINETIS=y` | 保持 `gnuarmeclipse-softmmu.mak` 为 `CONFIG_STM32=y`、`CONFIG_KINETIS=n` |
| `AttributeError: module 'configparser' has no attribute 'SafeConfigParser'` | Python 3.12 删除旧 API | 确认已对 `$P2IM_TOOLS_ROOT/scripts` 应用 `patches/p2im-python312-scripts.patch` |
| `All test cases time out or crash, giving up!` | 宿主 `core_pattern` 为管道模式或缺少 `seed-short` | 执行 `echo core \| sudo tee /proc/sys/kernel/core_pattern` 且保留 `inputs/seed-short` |
| `me.py` 报 `killall: not found` | 系统缺 `psmisc` 包 | `sudo apt-get install -y psmisc` |
| `DEEPSEEK` 请求提示认证失败或未找到模型 | 未注入环境变量或自定义端点别名缺失 | 用 `read -rsp` 导出 `DEEPSEEK_API_KEY`；先用 `node dist/src/cli.js doctor` 验证解析 |
| `npm run verify:privacy` 命中构建目录 | 构建后才运行发版前洁净检查（包含 `node_modules/`、`dist/`） | **不要删除构建产物**；洁净检查在 `npm ci` 前运行，构建后改用 `python3 scripts/privacy_audit.py --ignore-build-artifacts` |
