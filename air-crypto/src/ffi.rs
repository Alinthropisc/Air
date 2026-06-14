//! Raw FFI declarations for the C23 crypto core.
//!
//! Sources: `native/pbkdf2_sha1.c` + `native/mic.c`
//! Unsafe by nature — safe wrappers live in `lib.rs`.

use std::os::raw::c_char;

unsafe extern "C" {
    // ── pbkdf2_sha1.c ───────────────────────────────────────────────────

    /// Generic PBKDF2-HMAC-SHA1. Returns 0 on success.
    pub fn air_pbkdf2_sha1(
        passphrase:     *const u8,
        passphrase_len: usize,
        salt:           *const u8,
        salt_len:       usize,
        iterations:     u32,
        out:            *mut u8,
        out_len:        usize,
    ) -> i32;

    /// WPA PMK: PBKDF2-HMAC-SHA1(pass, essid, 4096, 32). Returns 0 on success.
    pub fn air_calc_pmk(passphrase: *const c_char, essid: *const c_char, out: *mut u8) -> i32;

    // ── mic.c ───────────────────────────────────────────────────────────

    /// HMAC-SHA1 (RFC 2104). `out` must be 20 bytes. Returns 0 on success.
    pub fn air_hmac_sha1(
        key:      *const u8,
        key_len:  usize,
        data:     *const u8,
        data_len: usize,
        out:      *mut u8,
    ) -> i32;

    /// HMAC-MD5 (RFC 2104). `out` must be 16 bytes. Returns 0 on success.
    pub fn air_hmac_md5(
        key:      *const u8,
        key_len:  usize,
        data:     *const u8,
        data_len: usize,
        out:      *mut u8,
    ) -> i32;

    /// IEEE 802.11 PRF-512. `out` must be 64 bytes. Returns 0 on success.
    pub fn air_prf512(
        key:       *const u8,
        key_len:   usize,
        label:     *const u8,
        label_len: usize,
        data:      *const u8,
        data_len:  usize,
        out:       *mut u8,
    ) -> i32;

    // ── wep.c ────────────────────────────────────────────────────────────

    /// RC4 XOR in-place. Returns 0 on success.
    pub fn air_rc4_xcrypt(
        key:      *const u8,
        key_len:  usize,
        data:     *mut u8,
        data_len: usize,
    ) -> i32;

    /// WEP decrypt + ICV verify. Returns 0=ok, -1=args, -2=bad ICV.
    pub fn air_wep_decrypt(
        key:        *const u8,
        key_len:    usize,
        iv:         *const u8,  // 3 bytes
        cipher:     *const u8,
        cipher_len: usize,
        plain:      *mut u8,
    ) -> i32;
}
