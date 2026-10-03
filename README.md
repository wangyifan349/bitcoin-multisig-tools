# ₿ Bitcoin Key & Multisig Tools

> Two **single-file, zero-dependency-friendly, Chinese-friendly** Bitcoin command-line tools 🔑🏗️ — keep your keys safe, build multisig correctly, and self-test easily.

| File | Purpose |
| ---- | ------- |
| 🔑 `bitcoin_batch_keys.py` | Single-signer key/address batch generation, import, and viewer (V1) |
| 🏦 `bitcoin_multisig_v2.py` | Multisig address generation and end-to-end sign/verify suite (V2, Bitcoin mainnet only) |

Both are Python 3.8+ and need only the standard library to run. If `coincurve`, `ecdsa`, `bech32m`, `bech32`, or `base58` are installed they are used first; otherwise each file falls back to its built-in equivalents. Copy one file anywhere and run.

---

## 🔑 V1 — `bitcoin_batch_keys.py` (single-signer)

Batch-generate WIF private keys and derive all single-signer address types. Useful for bulk key storage, backup address collection, and offline management.

```bash
python bitcoin_batch_keys.py                 # Run (or double-click) to enter the Chinese menu
```

Sub-commands:

```bash
python bitcoin_batch_keys.py gen -c 20 -o keys.txt   # 🔑 Batch-generate 20 keys, write WIFs to a file
python bitcoin_batch_keys.py gen -c 3 -d             # 🧾 3 keys, detailed view (hex private key / pubkey / lock script)
python bitcoin_batch_keys.py import -i keys.txt      # 📥 Import a file saved earlier (must end with END)
python bitcoin_batch_keys.py info bc1q... 1Abc...    # 🔍 Inspect addresses
python bitcoin_batch_keys.py selftest                # ✅ Built-in self-test (13 checks)
```

`gen` options:

- `-c/--count`: how many, default 10
- `--no-compression`: WIF without the compression flag
- `-n/--network {bc,btc,tb}`: network prefix, default `bc` (mainnet)
- `--kinds`: comma-separated script types to output
- `-f/--format {block,line,csv,json}`: output format, default `block`
- `-d`: detailed view under `block` format
- `-o`: output file; when writing to a file each line is one WIF, importable via `import`

Supported address types: P2PKH (`1...`), P2SH-P2WPKH (`3...`), P2WPKH (`bc1q...`, BIP84), P2TR (`bc1p...`, BIP86).

---

## 🏦 V2 — `bitcoin_multisig_v2.py` (multisig, mainnet)

Does two things: generate multisig addresses and verify that the signing logic for an address behaves as intended.

- ✅ **bc1q (P2WSH)**: arbitrary `m-of-n` (e.g. 3-of-5, 2-of-3)
- ✅ **bc1p (Taproot)**: `n-of-n`, every member must sign; `chain` and `tree` layouts

Sub-commands:

```bash
python bitcoin_multisig_v2.py build -t p2wsh -m 3      # Generate a 3-of-n plan
python bitcoin_multisig_v2.py build -t both -m 2       # See both bc1q and bc1p
python bitcoin_multisig_v2.py keys -c 5                # Generate 5 random member keys
python bitcoin_multisig_v2.py inspect bc1q...          # Inspect an address
python bitcoin_multisig_v2.py selftest -v              # 31 official-vector checks
```

Menu (press Enter at each prompt for the default):

```
1  One-shot multisig plan
     → type "3v2" ("5v3" or just the member count works too). The program creates
       keys, cross-checks that each public key really derives from its private key,
       prints the bc1q / bc1p addresses and descriptors, an end-to-end verify
       report, and only then asks whether to save.
2  Use your own member list
     → paste xpub / public keys / private keys
       (WIF, hex, decimal, 33-byte compressed pubkey, "x:"+x-only pubkey)
3  Inspect address
4  Self-test
0  Quit
```

`build` options in short:

- `-t {p2wsh,p2tr,both}`: which plan, default `p2wsh`
- `-m`: how many signatures for m-of-n (bc1p is always full)
- `--order {bip67,fingerprint}`: pubkey ordering, default BIP67 byte order
- `--layout {chain,tree}`: Taproot structure
- `-d/--detail`: scripts, control blocks, merkle paths
- `--verify`: also run an end-to-end signature check
- `-f {block,json}` / `-o` / `-v`

When you paste members, each entry is cross-checked: every public key is re-derived from the attached private key and compared; mismatches are flagged as an error.

---

## 🟰 What are bc1q and bc1p?

### 🟨 bc1q (P2WSH, SegWit v0)

- Address starts with `bc1q...`, SegWit v0; the witness program is the hash160 of a 20-byte witness script.
- The multisig script is the standard `OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG`.
- Spending puts `signature list + full script` in the witness, so the unlocking logic is visible on-chain.
- **Good for**: m-of-n (2-of-3, 3-of-5, ...) where any m signers suffice.
- **Pros**: flexible threshold; cheaper than the old `3...` (P2SH) multisig; broadly supported by SegWit wallets and exchanges.
- **Limits**: the threshold is fixed when the address is created; changing it means a new address; one address encodes one threshold.
- Descriptor produced by this tool looks like `wsh(sortedmulti(3,02aa...,03bb...,...))`.

### 🟪 bc1p (Taproot, SegWit v1, BIP340/341/342)

- Address starts with `bc1p...`, SegWit v1, Bech32m-encoded.
- A Taproot output supports two paths: **key path** (a single aggregated/adjusted Schnorr signature) and the **script path** (a Merkle tree + control block revealing one leaf script).
- This tool uses a NUMS internal key (whose discrete log nobody knows), so the **key path cannot be spent** — only the script path is spendable, which means `n-of-n` is genuinely enforced.
- Full-signature spending is not `OP_CHECKMULTISIG` but a `CHECKSIG / CHECKSIGVERIFY` chain: `pk1 OP_CHECKSIGVERIFY pk2 OP_CHECKSIGVERIFY ... pkn OP_CHECKSIG`.
- **Good for**: n-of-n cold wallets / corporate vaults / high-value custody.
- **Pros**: strictest model — every member must sign; the script path reveals only the leaf actually used, better privacy; smooth upgrade path to BIP342 scripts; shorter Schnorr signatures.
- **Limits**: all members must sign; missing even one blocks spending entirely. Not for "any m of n" cases (use bc1q for that).
- Descriptor produced by this tool looks like `tr(<NUMS>,and_v(v:pk(...),...))`.

### 🛠️ Which one should I use?

| Need | Recommendation |
| ---- | -------------- |
| 2-of-3, 3-of-5, any m will do | 🟨 **bc1q** |
| Everyone must sign | 🟪 **bc1p** |
| Lower fee + multisig | bc1q; a full-sign Taproot script-path spend is usually cheaper still |
| Want a familiar, easy-to-inspect address | bc1q |
| Want the strictest "spend only if every key signs" | bc1p |

---

## ✅ Self-tests and official vectors

Both tools ship a `selftest` that cross-checks official test vectors: BIP32 (xpub), BIP340 (Schnorr), BIP341 (Taproot tweak / output key), BIP143 (signature hash), BIP380 (descriptors), BIP173/BIP350 (address encoding). If you touch consensus logic, run:

```bash
python bitcoin_multisig_v2.py selftest
python bitcoin_batch_keys.py selftest
```

## ⚠️ Security notes

- WIF private keys are signing authority. Keep generated keys only on your own machine.
- For a multisig setup, only exchange **public keys** (or xpubs) — never share private keys.
- Run `--verify` on a generated address before funding it.

## 📄 License

MIT License, Copyright (c) 2026 Alex Walker. See `LICENSE`.
