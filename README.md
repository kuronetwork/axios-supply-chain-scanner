# axios-supply-chain-scanner

Quick scan scripts for the **axios npm supply chain attack** (2026-03-31).

Scripts are **detection only** — they scan and report findings but do **NOT** modify, delete, or kill anything on your system.

Affected versions: `axios@1.14.1` and `axios@0.30.4`
Safe versions: `axios@1.14.0` or `axios@0.30.3`

## 攻擊摘要

2026 年 3 月 31 日，攻擊者透過被盜的 npm maintainer 帳號 (`jasonsaayman`) 發布了兩個惡意版本的 axios。axios 原始碼本身未被修改，攻擊者在 `package.json` 中注入了一個惡意依賴 `plain-crypto-js@4.2.1`，該套件會在 `npm install` 時透過 postinstall hook 自動執行跨平台 RAT dropper。

惡意程式執行後會**自我刪除並清除痕跡**（刪除 `setup.js`、替換 `package.json`），使事後檢查 `node_modules` 時不會發現明顯異常。

## 使用方式

### macOS

```bash
chmod +x scan_macos.sh
./scan_macos.sh
```

### Linux

```bash
chmod +x scan_linux.sh
./scan_linux.sh
```

### Windows（以系統管理員身分執行 cmd.exe）

```bat
scan_windows.bat
```

## 掃描項目

| # | Check | macOS | Linux | Windows |
|---|-------|:-----:|:-----:|:-------:|
| 1 | Global npm axios version | ✅ | ✅ | ✅ |
| 2 | Global npm plain-crypto-js | ✅ | ✅ | ✅ |
| 3 | Full scan plain-crypto-js directories | ✅ | ✅ | ✅ |
| 4 | npm cache residue | ✅ | ✅ | ✅ |
| 5 | Platform-specific RAT artifact | ✅ | ✅ | ✅ |
| 6 | RAT staging directory (`$TMPDIR/6202033`) | ✅ | ✅ | ✅ |
| 7 | Hidden payloads in tmp | ✅ | ✅ | — |
| 8 | Persistence / RAT process | ✅ | ✅ | — |
| 9 | C2 domain DNS resolution | ✅ | ✅ | ✅ |
| 10 | Active C2 network connections | — | ✅ | ✅ |
| 11 | Project lockfile scan | ✅ | ✅ | ✅ |

## 結果判讀

- `[OK] Clean` → 該項目安全
- `[!] AFFECTED` → 偵測到受影響的套件版本
- `[!!!] COMPROMISED` → 偵測到 RAT artifact，系統可能已被入侵
- `[?] Suspicious` → 需要人工確認的可疑項目

掃描結束時會列出所有偵測到的項目路徑與相關 IOC 資訊。

## IOC（入侵指標）

### 惡意套件版本

| Package | Malicious Version | Safe Version |
|---------|-------------------|--------------|
| axios | 1.14.1 | 1.14.0 |
| axios | 0.30.4 | 0.30.3 |
| plain-crypto-js | 4.2.1 | — (remove) |

### RAT artifacts（依作業系統）

| OS | Path | Description |
|----|------|-------------|
| macOS | `/Library/Caches/com.apple.act.mond` | RAT binary（偽裝 Apple daemon） |
| macOS | `/private/tmp/.XXXXXX` | Stage-3 hidden payload |
| Windows | `%PROGRAMDATA%\wt.exe` | Renamed PowerShell copy |
| Windows | `%TEMP%\6202033.ps1` | PowerShell payload |
| Windows | `%TEMP%\6202033.vbs` | VBScript launcher |
| Linux | `/tmp/ld.py` | Python RAT script |
| Linux | `/tmp/.<random>` | Stage-3 hidden binary (dot-prefixed) |
| All | `$TMPDIR/6202033` | Staging directory |

### C2 Server

| Indicator | Value |
|-----------|-------|
| Domain | `sfrclak[.]com` |
| IP | `142.11.206.73` |
| Port | `8000` |
| Campaign ID | `6202033` |
| Full URL | `http://sfrclak[.]com:8000/6202033` |

### 已知 SHA256

| File | SHA256 |
|------|--------|
| `/tmp/ld.py` (Linux RAT) | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |

### 相關惡意套件

- `@shadanai/openclaw` (versions 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2)
- `@qqbrowser/openclaw-qbot@0.0.130`

## 影響時間窗口

| 時間 (UTC) | 事件 |
|------------|------|
| 2026-03-30 05:57 | `plain-crypto-js@4.2.0`（乾淨版）發布 |
| 2026-03-30 23:59 | `plain-crypto-js@4.2.1`（惡意版）發布 |
| 2026-03-31 00:21 | `axios@1.14.1`（惡意版）發布 |
| 2026-03-31 01:00 | `axios@0.30.4`（惡意版）發布 |
| 2026-03-31 ~03:29 | npm 下架惡意版本 |

如果你的 `package-lock.json` 或 `yarn.lock` 在惡意版本發布**之前**已經 commit，且期間沒有執行 `npm install` 或 `npm update`，則**不受影響**。

## 參考來源

- [Socket — Supply Chain Attack on Axios](https://socket.dev/blog/axios-npm-package-compromised)
- [StepSecurity — axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Snyk — Axios npm Package Compromised](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [The Hacker News — Axios Supply Chain Attack](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [SafeDep — axios npm Supply Chain Compromise](https://safedep.io/axios-npm-supply-chain-compromise/)
- [SOCRadar — Axios npm Hijack 2026](https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/)

## License

MIT
