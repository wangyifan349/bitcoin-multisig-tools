# ₿ Bitcoin Key & Multisig Tools

> 两个**单文件、零依赖运行、中文友好**的比特币命令行工具 🔑🏗️ —— 保护私钥、正确建多签、方便自测。

| 文件 | 用途 |
| ---- | ---- |
| 🔑 `bitcoin_batch_keys.py` | 单签私钥/地址的批量生成、导入、查看（V1） |
| 🏦 `bitcoin_multisig_v2.py` | 多签地址生成与端到端验签（V2，仅比特币主网） |

运行都不需要第三方钱包库。安装了 `coincurve / ecdsa / bech32m / bech32 / base58` 会优先使用；没装则自动回退到文件内置的等价实现，所需用到的只是 Python 3.8+ 标准库。

---

## 🔑 V1 `bitcoin_batch_keys.py` —— 单签批量工具

批量生成比特币 WIF 私钥 + 各类单签地址，适合批量留存、回收地址备用、离线管理。

```bash
python bitcoin_batch_keys.py                 # 直接运行（或双击）进入中文菜单
```

子命令：

```bash
python bitcoin_batch_keys.py gen -c 20 -o keys.txt   # 🔑 批量生成 20 个密钥，私钥写入文件
python bitcoin_batch_keys.py gen -c 3 -d             # 🧾 3 个，明细视图（十六进制私钥 / 公钥 / 锁定脚本）
python bitcoin_batch_keys.py import -i keys.txt      # 📥 导入之前保存的文件（文件以 END 结尾）
python bitcoin_batch_keys.py info bc1q... 1Abc...    # 🔍 查看地址信息
python bitcoin_batch_keys.py selftest                # ✅ 内置自检（13 项）
```

`gen` 常用参数：

- `-c/--count`：数量，默认 10
- `--no-compression`：WIF 不带压缩标志
- `-n/--network {bc,btc,tb}`：网络前缀，默认 `bc`（主网）
- `--kinds`：指定输出脚本类型，逗号分隔
- `-f/--format {block,line,csv,json}`：输出格式，默认 `block`
- `-d`：block 格式下改用明细视图
- `-o`：输出文件；写文件时每行一个 WIF，可用 `import` 读回

支持的地址类型：P2PKH（`1...`）、P2SH-P2WPKH（`3...`）、P2WPKH（`bc1q...`，BIP84）、P2TR（`bc1p...`，BIP86）。

---

## 🏦 V2 `bitcoin_multisig_v2.py` —— 多签工具（主网）

只做两件事：生成多签地址、验证地址的签名逻辑按预期工作。

- ✅ **bc1q（P2WSH）**：`m-of-n` 任意 m 人签即可，比如 3-of-5、2-of-3；
- ✅ **bc1p（Taproot）**：`n-of-n` 全员签名，一个都不能少；`chain` 与 `tree` 两种布局。

运行子命令或菜单：

```bash
python bitcoin_multisig_v2.py build -t p2wsh -m 3      # 生成 3-of-n 方案
python bitcoin_multisig_v2.py build -t both -m 2       # 同时看 bc1q 和 bc1p
python bitcoin_multisig_v2.py keys -c 5                # 随机生成 5 个成员密钥
python bitcoin_multisig_v2.py inspect bc1q...          # 解析地址
python bitcoin_multisig_v2.py selftest -v              # 31 项官方向量自检
```

菜单（回车 = 默认）：

```
1  一键生成多签方案
     → 输入 3v2（5v3 / 只写人数也行），程序自动创建私钥、
       逐项校算「公钥确实由对应私钥推出」、给出 bc1q / bc1p 地址、
       端到端验签报告、描述符，最后才问要不要存文件。
2  用自己的名单生成
     → 粘贴 xpub / 公钥 / 私钥（WIF、hex、十进制、33 字节压缩公钥、"x:"+x-only 公钥）
3  解析地址
4  自检
0  退出
```

`build` 参数摘要：

- `-t {p2wsh,p2tr,both}`：方案类型，默认 `p2wsh`；
- `-m`：m-of-n 需要几个签名（bc1p 永远是全员）；
- `--order {bip67,fingerprint}`：公钥排序，默认 BIP67 字节升序；
- `--layout {chain,tree}`：Taproot 结构；
- `-d/--detail`：显示脚本、控制块、merkle 路径等；
- `--verify`：顺便做一次端到端签名验证；
- `-f {block,json}` / `-o` / `-v`。

输入时会逐项核对：每条「公钥」都重新从所附私钥推全比对，不匹配会标红「异常」。

---

## 🟰 bc1q 和 bc1p 分别是什么？

### 🟨 bc1q（P2WSH，SegWit v0）

- 地址以 `bc1q...` 开头，SegWit v0；见证程序是 20 字节的 witness script 的 hash160。
- 多签脚本是标准的 `OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG`。
- 花费时每把私钥各自签名，见证里放 `签名列表 + 完整脚本`，链上把脚本解锁逻辑亮出来。
- **适合**：m-of-n 场景（2-of-3、3-of-5 等）、需要任意 m 人就能花。
- **优点**：多签门槛灵活；比早期 `3...`（P2SH）多签更省手续费；已被所有 SegWit 钱包/交易所广泛支持。
- **限制**：门槛在地址创建时就定死，后续改门槛等于换地址；一个地址只支持一种门槛。
- 本工具输出的描述符形如 `wsh(sortedmulti(3,02aa...,03bb...,...))`。

### 🟪 bc1p（Taproot，SegWit v1，BIP340/341/342）

- 地址以 `bc1p...` 开头，SegWit v1，Bech32m 编码。
- Taproot 输出同时支持两种路径：**key path**（聚合/调整后的单一 Schnorr 签名）与**脚本路径**（Merkle 树 + 控制块揭示某一片脚本）。
- 本工具的 bc1p 用的是 NUMS 内部公钥（任何人都不知道它的离散对数），所以**key path 天然不能花**，只能走脚本路径 ⇒ 真正强制 `n-of-n` 全员签名。
- 全员签名不是 `OP_CHECKMULTISIG`，而是一条 `CHECKSIG / CHECKSIGVERIFY` 链：`pk1 OP_CHECKSIGVERIFY pk2 OP_CHECKSIGVERIFY ... pkn OP_CHECKSIG`。
- **适合**：n-of-n 冷钱包/公司金库/高安全资产托管。
- **优点**：全员必签，安全模型最严；脚本路径只揭示用到的那一片，隐私更好；未来可以平滑升级到 BIP342 脚本集；Schnorr 签名更短。
- **限制**：必须所有成员都签，少一个就完全不能花；不适合 m-of-n（如 2-of-3）这种要"部分人就行"的场景（那种请用 bc1q）。
- 本工具输出的描述符形如 `tr(<NUMS>,and_v(v:pk(...),...))`。

### 🛠️ 怎么选？

| 需求 | 推荐 |
| ---- | ---- |
| 2-of-3、3-of-5，任意 m 人就行 | 🟨 **bc1q** |
| 全员必须签才算数 | 🟪 **bc1p** |
| 想省手续费、又要多签 | bc1q；bc1p 全签脚本路径单笔花费通常更省 |
| 想看地址长得直观、随便查 | bc1q |
| 想要最严苛的"少一个都花不了" | bc1p |

---

## ✅ 自检与官方向量

两种工具都内置 `selftest`，逐项比对官方测试向量：BIP32（xpub）、BIP340（Schnorr）、BIP341（Taproot tweak/输出公钥）、BIP143（签名哈希）、BIP380（描述符校验和）、BIP173/BIP350（地址编码）。改动共识代码后请运行：

```bash
python bitcoin_multisig_v2.py selftest
python bitcoin_batch_keys.py selftest
```

## ⚠️ 安全提醒

- WIF 私钥 = 签名权。生成的私钥只保留在自己的机器里。
- 多方建多签时，**只交换公钥（或 xpub）**，绝不发送私钥。
- 正式上账前先跑一遍 `--verify`，确认地址逻辑符合预期。

## 📄 License

MIT License, Copyright (c) 2026 Alex Walker. 详见 `LICENSE`。
