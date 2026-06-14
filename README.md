<div align="center">

<img src="art/photo_2026-06-07_16-27-13-removebg-preview.png" alt="Air Dragon" width="340"/>

```
 █████╗ ██╗██████╗
██╔══██╗██║██╔══██╗
███████║██║██████╔╝
██╔══██║██║██╔══██╗
██║  ██║██║██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**Next-generation Wi-Fi auditing toolkit**  
*Built with Rust 2024 · C23 · Async · TUI*

[![CI](https://github.com/YOUR_USERNAME/air/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/air/actions/workflows/ci.yml)
[![Tests](https://github.com/YOUR_USERNAME/air/actions/workflows/tests.yml/badge.svg)](https://github.com/YOUR_USERNAME/air/actions/workflows/tests.yml)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange?logo=rust)](https://www.rust-lang.org)
[![C23](https://img.shields.io/badge/C-23-blue?logo=c)](https://en.wikipedia.org/wiki/C23_(C_standard_revision))
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## What is Air?

**Air** is a modern rewrite of the [Aircrack-ng](https://www.aircrack-ng.org) suite — redesigned from the ground up with:

- **Rust 2024** async runtime (`tokio`) for all orchestration logic
- **C23** for hot-path cryptography (PBKDF2, HMAC-SHA1, RC4, AES-CMAC)
- A beautiful **terminal UI** powered by [ratatui](https://ratatui.rs)
- Clean **design patterns** throughout (Observer, Strategy, Builder, Facade, Template Method)
- Zero legacy C89 cruft — every file is either Rust or C23

> Air is an educational and authorized-testing tool. Use it only on networks you own or have explicit permission to test.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        air (bin)                        │
│          CLI (clap) ──── TUI (ratatui / air-tui)        │
│                         │                               │
│              tokio async engine                         │
│    scan ─── crack ─── deauth ─── inject ─── stats      │
│                         │                               │
│              air-crypto (FFI bridge)                    │
│         safe Rust wrappers → C23 native layer           │
│   PBKDF2 · HMAC-SHA1/MD5 · PRF-512 · RC4 · AES-CMAC   │
└─────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Role |
|---|---|
| `air` | Main binary — CLI, TUI, async engine, scan, crack, deauth |
| `air-crypto` | C23 crypto (PMK, PTK, MIC, WEP) behind safe Rust FFI |
| `air-tui` | Reusable ratatui widgets library (Builder pattern) |

---

## Features

### WPA/WPA2 Cracking
- **PBKDF2-HMAC-SHA1** PMK derivation (C23 hot path, Rayon parallelism)
- **PRF-512** PTK derivation
- **MIC verification** — HMAC-MD5, HMAC-SHA1, AES-CMAC (WPA3)
- **PMKID attack** — no handshake required
- **Wordlist + Bruteforce** modes with live ETA and words/sec counter
- Template Method pattern: `crack_auto()` — same pipeline, swap the source

### WEP Cracking
- **RC4** KSA/PRGA — pure C23, in-place decryption
- **CRC32 ICV** verification per IEEE 802.11
- WEP-40 and WEP-104 key lengths

### Live Terminal UI
- 5-tab layout: `Scan` · `Attack` · `Crack` · `Log` · `Settings`
- Real-time AP table with signal strength color coding
- Live crack progress gauge with speed (w/s) and ETA
- Scrollable log ring buffer
- Brand theme: gold `#C8A23C` on black `#0D0D0D`

### Event Bus (Observer Pattern)
```rust
// All background tasks emit events:
State::emit(AppEvent::CrackProgress(progress));
State::emit(AppEvent::HandshakeCaptured(bssid));

// TUI subscribes and reacts in real time:
let mut rx = State::subscribe();
while let Ok(ev) = rx.recv().await { app.on_event(ev); }
```

### Word Sources (Strategy Pattern)
```rust
WordSource::File(path)          // stream from wordlist
WordSource::Stdin               // pipe from stdin
WordSource::Bruteforce(config)  // odometer generator, O(1) memory
```

---

## Quick Start

### Requirements

- Rust 1.80+ (`rustup update stable`)
- Clang 18+ with C23 support
- Linux with wireless card in monitor mode
- Root or `CAP_NET_RAW` capability

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang-18 libpcap-dev libnl-3-dev libnl-genl-3-dev libssl-dev

# Clone & build
git clone https://github.com/Alinthropisc/air
cd air
cargo build --release

# Or install globally
cargo install --path .
```

### Usage

```bash
# Launch interactive TUI
sudo air

# Scan for access points
sudo air scan -i wlan0

# Capture WPA handshake
sudo air capture -i wlan0 --bssid AA:BB:CC:DD:EE:FF -o capture.pcap

# Crack WPA with wordlist
sudo air crack -f capture.pcap --bssid AA:BB:CC:DD:EE:FF -w rockyou.txt

# Crack WPA with bruteforce (8-char digits)
sudo air bruteforce -f capture.pcap --bssid AA:BB:CC:DD:EE:FF \
  --charset 0123456789 --min 8 --max 8

# PMKID attack (no handshake)
sudo air pmkid -i wlan0 --bssid AA:BB:CC:DD:EE:FF -w wordlist.txt

# Deauthentication
sudo air deauth -i wlan0 --bssid AA:BB:CC:DD:EE:FF --client FF:EE:DD:CC:BB:AA

# Show session statistics
sudo air stats
```

---

## Design Patterns

| Pattern | Where |
|---|---|
| **Observer** | `AppEvent` broadcast bus — `State::emit()` / `State::subscribe()` |
| **Strategy** | `WordSource` enum — File / Stdin / Bruteforce |
| **Builder** | All `air-tui` widgets — `SpeedGauge::new().with_ratio(0.5).with_speed(...)` |
| **Template Method** | `crack_auto()` — fixed pipeline, pluggable word source |
| **Facade** | `State` (global singletons), `Renderer` (terminal lifecycle) |
| **Opaque Handle** | `c_avl_tree_t *` — callers never see struct internals |

---

## Crypto Stack

```
Password + SSID
     │
     ▼ PBKDF2-HMAC-SHA1 (4096 iter)     ← C23  air-crypto/native/mic.c
     │
    PMK (256-bit)
     │
     ▼ PRF-512 (HMAC-SHA1 expansion)    ← C23
     │
    PTK (512-bit)
     │
  ┌──┴───────────────┐
  ▼                  ▼
KCK (128-bit)      KEK (128-bit)
  │
  ▼ MIC verification
  ├─ HMAC-MD5    (WPA)
  ├─ HMAC-SHA1   (WPA)
  └─ AES-CMAC    (WPA3)

WEP:  RC4(IV ‖ Key) → XOR → CRC32 ICV   ← C23  air-crypto/native/wep.c
```

---

## Project Structure

```
air/
├── src/
│   ├── main.rs          — CLI entry point, subcommands
│   ├── engine.rs        — async crack engine, EtaEstimator
│   ├── globals.rs       — State facade, event bus, singletons
│   ├── types.rs         — AppEvent, CrackProgress, LogEntry
│   ├── wordlist.rs      — WordSource, BruteforceGen
│   └── tui/             — 5-tab TUI (ratatui)
│
├── air-crypto/
│   ├── src/
│   │   ├── lib.rs       — safe Rust wrappers
│   │   └── ffi.rs       — unsafe extern "C" declarations
│   ├── native/
│   │   ├── mic.c        — PBKDF2, HMAC-SHA1/MD5, PRF-512 (C23)
│   │   └── wep.c        — RC4, WEP decrypt, CRC32 ICV (C23)
│   └── include/
│       ├── mic.h
│       └── wep.h
│
├── air-tui/
│   └── src/
│       ├── theme.rs     — Theme Value Object (gold/black)
│       ├── logo.rs      — ASCII dragon logo
│       ├── renderer.rs  — Terminal Facade
│       └── widgets/     — SpeedGauge, ApTable, LogPanel, CrackPanel…
│
├── libac/               — C23 utility library (AVL tree, ring buffer)
├── osdep/               — OS abstraction layer
├── crypto/              — Low-level crypto primitives
├── defs.h               — C23 compat shims, contracts (REQUIRE/ENSURE)
└── docs/
    └── PROGRESS.md
```

---

## CI / CD

| Workflow | Jobs |
|---|---|
| `ci.yml` | `rustfmt` check · `clippy -D warnings` · `clang-tidy` · `cargo audit` |
| `tests.yml` | Unit tests · ARM64 cross-check · Coverage (tarpaulin) |

---

## Contributing

1. Fork → branch off `dev`
2. Code must pass `cargo fmt`, `cargo clippy -- -D warnings`, and all tests
3. C code: `clang -std=c23` only; no `malloc` without matching free
4. New crypto: add a known-answer test vector from an RFC or NIST publication
5. Open a PR against `main`

---

## License

MIT © 2024 Air Contributors

---

<div align="center">
<sub>Built with Rust 🦀 + C23 · Inspired by Aircrack-NG · Redesigned for the modern era</sub>
</div>
