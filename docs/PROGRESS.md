# Air — Progress

Living status doc. Updated after each work session.

## Project
Hybrid rewrite of **Airgorah** (Rust GTK GUI) + **Aircrack-NG** (C) into a modern
**Rust 2024 + async (tokio) + C23** stack. TUI-first; GTK deferred. The C23 core is
the performance engine, Rust provides async orchestration on top. We grow the project
in **vertical slices** (one piece taken end to end, then the next).

## Done
- [x] `air-crypto` crate — C23 **PBKDF2-HMAC-SHA1** core: clean-room SHA-1 → HMAC → PBKDF2,
      no OpenSSL/gcrypt, compiled via `clang -std=c23` through the `cc` crate.
- [x] Async Rust front: `calc_pmk`, `calc_pmk_async` (tokio `spawn_blocking`),
      `calc_pmk_batch` (rayon), generic `pbkdf2_sha1`.
- [x] Correctness verified against **IEEE 802.11i** and **RFC 6070** vectors (5 tests pass).
- [x] C layout convention: `include/` (.h) + `native/` (.c) + `src/` (Rust).
- [x] Root build-script blockers fixed: `serde` import, `[build-dependencies]`, `HashMap` import.

## In progress
- Root `air` crate does not fully compile yet (gtk4 not wired in `Cargo.toml`;
  `src/main.rs` has a wrong `pub mod lib;`). Deferred on purpose — we're TUI-first.

## Next
- Extend the C core (goal: "more powerful, more code"): AVX2 SIMD batch (4–8 PMK at once),
  PMKID attack (no handshake needed), full WPA handshake cracker (PTK + MIC).
- pcap / hccapx / PMKID parser to feed candidates into the core.
- `air-tui`: first screen — dragon logo, gold-on-black palette, live cracking progress.

## Needed / open questions
- GTK fate: kept deferred (revisit later).
- Branding: dragon mascot + flame banner in `art/` → CLI ANSI art, TUI splash, GUI icon.
  Palette: black `#0D0D0D` + gold `#C8A23C` + white.

## Session log

### 2026-06-13 — C23 modernisation: IV tracker + PTW attack

**Done:**
- `core.h` — fixed syntax error (stray comment fragment broke compilation).
- `ce-wep/uniqueiv.c` — full C23 rewrite with new `air_uiv_*` API.
  Two-level lazy bitmap (2 MiB worst-case). Cloaking-detection (`air_iv_data_t`)
  keeps 3 B/IV layout. Old C89 API removed; header shims keep callers building.
- `ptw/aircrack-ptw-lib.h` — C23 modernisation:
  - Named constants (`enum : uint32_t`), Strategy pattern (`rc4_test_fn`),
    Opaque Handle pattern (`PTW_attack_ctx` forward-declared).
  - Legacy shims (`PTW_newattackstate` etc.) as `static inline` wrappers.
- `ptw/aircrack-ptw-lib.c` — fixed includes, opaque struct moved here,
  global `opt` replaced with `g_quiet`, new C23 public API added at bottom.

**Rust candidates tagged (`TODO(rust)`):**
- `doRound()` — recursive key search, stack-heavy, not thread-safe.
- Static globals `tried / depth[] / keytable[][]` — no mutex; rayon in Rust.
- AMD64 SSE2 inline-asm RC4 — kept as-is (proven), Rust port via `asm!` later.

**Patterns applied:** Strategy, Opaque Handle/Pimpl, Named Constants, Compat Shims.

---

### 2026-06-13 (session 3) — batch include fix + pmkid/hkdf impl

**Done:**
- `crypto/arcfour.h` — C23 modernisation: `#pragma once`, `AIR_EXPORT`, `[[nodiscard]]`,
  Adapter pattern (gcrypt / OpenSSL <3 / OpenSSL ≥3 / generic), cleaner generic struct.
- `crypto/mac.h` — full C23 rewrite: new `enum : size_t` constants, streaming OMAC1 context API
  (`Create / Update / Finish / Destroy`), one-shot `MAC_OMAC1_AES_128`, `MAC_HMAC_SHA1_AES_PRF`.
- `crypto/pmkid.h` — **NEW**: PMKID attack API (WPA2 without 4-way handshake).
  `air_pmkid_compute`, `air_pmkid_verify` (constant-time), `air_pmkid_from_passphrase`.
- `crypto/hkdf.h` — **NEW**: HKDF RFC 5869 (SHA-256 + SHA-384), WPA3-SAE convenience wrapper
  `air_wpa3_sae_kck_pmk`. Template Method pattern. SAE scalar math tagged `TODO(rust)`.
- `crypto/crypto.h` — C23 update: `#pragma once`, relative includes, `AIR_EXPORT`.
- `crypto/sha1.c`, `sha256.c`, `md5.c` — fixed `aircrack-ng/*` paths → relative,
  `API_EXPORT` → `AIR_EXPORT`, `ustrlen` → `air_ustrlen`.

**Patterns applied:** Adapter (arcfour, mac), Template Method (hkdf), Named Constants (mac, pmkid, hkdf).

**New attack surface:**
- PMKID attack: no client deauth needed, works from a single EAPOL frame.
- HKDF: enables WPA3-SAE audit capability (future).

---

### 2026-06-14 (session 5) — C layer completion pass

**Done:**
- `crypto/mac-omac1-generic.c` — **full CMAC/OMAC1 implementation** (was a stub returning -1):
  - Opaque `Air_OMAC_CTX` struct (Pimpl pattern) with CBC-MAC accumulator
  - Subkey generation (NIST SP 800-38B §6.1): `L = AES(K, 0^128)`, K1/K2 via `block_shift_left1 + XOR Rb`
  - Streaming API: `Create / Update / Finish / Destroy` (correct last-block detection)
  - One-shot vector: `MAC_OMAC1_AES_Vector`, `MAC_OMAC1_AES`, `MAC_OMAC1_AES_128`
  - Uses `Cipher_AES_Encrypt` from generic AES ECB back-end
- `crypto/sha256.c` — added two missing functions:
  - `KDF_PBKDF2_SHA256` — RFC 2898 PBKDF2-HMAC-SHA256 (arbitrary iterations + output length)
  - `SHA256_PRF` — IEEE 802.11r FT key hierarchy (wrapper around `Digest_SHA256_PRF_Bits`)
- `crypto/` backends (sha1-openssl, sha1-gcrypt, sha1-generic, md5-gcrypt, aes-128-cbc-gcrypt,
  mac-omac1-gcrypt, sha256-gcrypt, sha256-openssl, crypto.h) — `NULL` → `nullptr`
- `support/pcap_local.h` + 8 other support headers — removed orphaned `#endif` from old
  include guards after `#pragma once` conversion
- `osdep/*.c` — `NULL` → `nullptr`, `assert()` → `REQUIRE()`, `#include <assert.h>` removed
- `ce-wpa/misc.h` — added missing JtR macros:
  - `MEM_ALIGN_NONE/WORD/SIMD/PAGE/MEM_ALLOC_SIZE/MEM_ALLOC_MAX_WASTE` (`enum : size_t`)
  - `mem_alloc`, `mem_alloc_tiny`, `mem_alloc_copy`, `mem_calloc_align`, `mem_calloc`, `MEM_FREE`
  - `UNUSED_PARAM(x)` — used by `libac/cpu/cpuset_pthread.c`
  - Forward declarations for all `memory.c` slab functions
- `ce-wpa/arch.h` — added JtR compat aliases: `ARCH_WORD_32`, `ARCH_WORD_64`, `ARCH_ALLOWS_UNALIGNED`

**C layer status:** core complete. All crypto algorithms implemented; all `NULL`→`nullptr`,
`assert`→`REQUIRE`, `API_EXPORT`→`AIR_EXPORT` migrations done across crypto/, ce-wpa/, libac/,
support/, osdep/. Remaining `TODO(rust)` stubs: AES key unwrap, HKDF-SHA384, GHASH SIMD.

---

### 2026-06-14 (session 6) — Async Rust upgrade: event bus, Strategy wordlist, live TUI

**Done:**

- `src/types.rs` — `AppEvent` (Observer), `CrackProgress`, `CrackState`, `LogEntry`
- `src/globals.rs` — `tokio::broadcast` event bus, `State::emit/subscribe`, log ring, crack progress
- `src/engine.rs` — `EtaEstimator` (Strategy), `crack_channel` + `crack_pmkid_channel` emit live progress, `crack_auto` (Template Method), `crack_wep` (WEP thin wrapper)
- `src/wordlist.rs` — `WordSource` (Strategy), `BruteforceConfig`, `BruteforceGen` (async odometer), `WordSource::chain`
- `src/tui/mod.rs` — 5 tabs (Scan/Attack/Crack/Log/Settings), ratatui Table for APs, live Gauge progress bar, Log ring viewer, event bus subscription
- `src/main.rs` — new subcommands: `bruteforce`, `crack-wep`, `stats`; live crack progress on stderr

**Patterns:** Observer, Strategy, Template Method, Iterator (async), MVC, Command.

---

### 2026-06-08
- Built the first vertical slice: `air-crypto` C23 core + async Rust front; tests green.
- Split `csrc/` into `include/` + `native/` (no mixing .c and .h).
- Fixed the root crate's build-script blockers.

### 2026-06-13 (session 4) — AES generic back-end + batch crypto/.c cleanup

**Done:**
- `crypto/aes-128-cbc-generic.c` — полная реализация:
  - §1 AES S-box + round constants (FIPS 197)
  - §2 `struct Air_AES_CTX` с key schedule (128/192/256)
  - §3 `Cipher_AES_Encrypt_Init/Encrypt/Deinit` — реальный AES-ECB (не стаб)
  - §4 `air_aes_ctr_xcrypt` — AES-CTR (nonce[12] + counter32, in-place)
  - §5 GHASH — portable GF(2^128) multiply (reduction 0xe1)
  - §6 `air_aes_gcm_encrypt/decrypt` — AES-GCM с constant-time tag verify
  - §7 `air_aes_key_wrap` — RFC 3394 W алгоритм; unwrap — `TODO(rust)` (InvCipher)
- `crypto/*.c` (22 файла) — batch `sed`: все `aircrack-ng/crypto/` → relative, `API_EXPORT` → `AIR_EXPORT`
- `crypto/pmkid.c` — **NEW**: полный PMKID attack (compute + constant-time verify + from_passphrase)
- `crypto/hkdf.c` — **NEW**: HKDF-SHA256 (Extract/Expand/one-shot) + WPA3-SAE wrapper; SHA-384 `TODO(rust)`

**Patterns applied:** Strategy (generic vs OpenSSL vs gcrypt), Template Method (GCM→ECB), Named Constants.

**TODO(rust) tagged:**
- `air_aes_key_unwrap` — требует InvCipher; делегировать `aes` crate
- `air_hkdf_sha384_*` — SHA-384 HMAC отсутствует в C layer
- GHASH SIMD — portable битовая реализация, оптимизация через `ghash` crate

**Следующая сессия:** `libac/` модули, `crypto/sha1-generic.c` C23, Rust FFI bindings для pmkid/hkdf.
