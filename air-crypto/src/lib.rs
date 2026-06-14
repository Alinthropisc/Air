//! air-crypto — a C23 cryptographic core fronted by an async Rust API.
//!
//! First vertical slice of the Air project: WPA PMK derivation
//! (PBKDF2-HMAC-SHA1). The heavy math lives in `csrc/pbkdf2_sha1.c`
//! (clang `-std=c23`); this module provides safe, ergonomic, and async
//! Rust wrappers on top.

mod ffi;

use std::ffi::CString;

/// WPA Pairwise Master Key length, in bytes.
pub const PMK_LEN: usize = 32;

/// Errors surfaced by the crypto core.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The C core rejected the arguments (non-zero return code).
    #[error("crypto core rejected arguments (code {0})")]
    InvalidArg(i32),
    /// A passphrase or ESSID contained an interior NUL byte.
    #[error("passphrase or essid contains an interior NUL byte")]
    NulByte,
    /// WEP ICV checksum mismatch — wrong key.
    #[error("WEP ICV mismatch — wrong key")]
    IcvMismatch,
}

/// Derive a 32-byte WPA PMK from a passphrase and ESSID
/// (PBKDF2-HMAC-SHA1, 4096 iterations, ESSID as salt).
pub fn calc_pmk(passphrase: &str, essid: &str) -> Result<[u8; PMK_LEN], CryptoError> {
    let pass = CString::new(passphrase).map_err(|_| CryptoError::NulByte)?;
    let ssid = CString::new(essid).map_err(|_| CryptoError::NulByte)?;

    let mut out = [0u8; PMK_LEN];
    // SAFETY: both C strings are NUL-terminated and outlive the call; `out`
    // is exactly PMK_LEN bytes, matching the C contract.
    let rc = unsafe { ffi::air_calc_pmk(pass.as_ptr(), ssid.as_ptr(), out.as_mut_ptr()) };
    if rc != 0 {
        return Err(CryptoError::InvalidArg(rc));
    }
    Ok(out)
}

/// Generic PBKDF2-HMAC-SHA1 producing `out_len` derived bytes.
pub fn pbkdf2_sha1(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; out_len];
    // SAFETY: pointers/lengths come from live slices; `out` has `out_len` bytes.
    let rc = unsafe {
        ffi::air_pbkdf2_sha1(
            passphrase.as_ptr(),
            passphrase.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if rc != 0 {
        return Err(CryptoError::InvalidArg(rc));
    }
    Ok(out)
}

/// Async PMK derivation.
///
/// PMK computation is CPU-bound (4096 HMAC-SHA1 rounds), so it runs on
/// tokio's blocking pool to avoid stalling the async reactor.
pub async fn calc_pmk_async(
    passphrase: String,
    essid: String,
) -> Result<[u8; PMK_LEN], CryptoError> {
    tokio::task::spawn_blocking(move || calc_pmk(&passphrase, &essid))
        .await
        .expect("pmk worker thread panicked")
}

/// Derive PMKs for many candidate passphrases against one ESSID, in
/// parallel (rayon). Results preserve input order.
pub fn calc_pmk_batch(
    essid: &str,
    candidates: &[String],
) -> Vec<Result<[u8; PMK_LEN], CryptoError>> {
    use rayon::prelude::*;
    candidates
        .par_iter()
        .map(|candidate| calc_pmk(candidate, essid))
        .collect()
}

// ── MIC helpers (native/mic.c) ───────────────────────────────────────────────

/// HMAC-SHA1 (RFC 2104) — 20-byte output.
/// Used for WPA2/CCMP MIC verification and as the PRF-512 building block.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20], CryptoError> {
    let mut out = [0u8; 20];
    let rc = unsafe {
        ffi::air_hmac_sha1(
            key.as_ptr(),  key.len(),
            data.as_ptr(), data.len(),
            out.as_mut_ptr(),
        )
    };
    if rc != 0 { return Err(CryptoError::InvalidArg(rc)); }
    Ok(out)
}

/// HMAC-MD5 (RFC 2104) — 16-byte output.
/// Used for WPA1/TKIP MIC verification (key version 1).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16], CryptoError> {
    let mut out = [0u8; 16];
    let rc = unsafe {
        ffi::air_hmac_md5(
            key.as_ptr(),  key.len(),
            data.as_ptr(), data.len(),
            out.as_mut_ptr(),
        )
    };
    if rc != 0 { return Err(CryptoError::InvalidArg(rc)); }
    Ok(out)
}

/// IEEE 802.11 PRF-512 — 64-byte PTK material.
///
/// `label` = `b"Pairwise key expansion"`
/// `data`  = min(BSSID,STA)||max(BSSID,STA)||min(ANonce,SNonce)||max(ANonce,SNonce)
pub fn prf512(key: &[u8], label: &[u8], data: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut out = [0u8; 64];
    let rc = unsafe {
        ffi::air_prf512(
            key.as_ptr(),   key.len(),
            label.as_ptr(), label.len(),
            data.as_ptr(),  data.len(),
            out.as_mut_ptr(),
        )
    };
    if rc != 0 { return Err(CryptoError::InvalidArg(rc)); }
    Ok(out)
}

// ── WEP / RC4 helpers (native/wep.c) ─────────────────────────────────────────

pub const WEP40_KEY_LEN:  usize = 5;
pub const WEP104_KEY_LEN: usize = 13;

/// RC4 XOR in-place — mutates `data`.
pub fn rc4_xcrypt(key: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
    let rc = unsafe {
        ffi::air_rc4_xcrypt(key.as_ptr(), key.len(), data.as_mut_ptr(), data.len())
    };
    if rc != 0 { return Err(CryptoError::InvalidArg(rc)); }
    Ok(())
}

/// Decrypt a WEP payload and verify ICV.
/// Returns `Ok(plaintext_without_icv)` or `Err(CryptoError::IcvMismatch)`.
pub fn wep_decrypt(
    key:    &[u8],
    iv:     &[u8; 3],
    cipher: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if cipher.len() < 4 { return Err(CryptoError::InvalidArg(-1)); }
    let mut plain = vec![0u8; cipher.len()];
    let rc = unsafe {
        ffi::air_wep_decrypt(
            key.as_ptr(),    key.len(),
            iv.as_ptr(),
            cipher.as_ptr(), cipher.len(),
            plain.as_mut_ptr(),
        )
    };
    match rc {
        0  => { plain.truncate(cipher.len() - 4); Ok(plain) }
        -2 => Err(CryptoError::IcvMismatch),
        _  => Err(CryptoError::InvalidArg(rc)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // IEEE 802.11i, Annex H.4 — canonical WPA passphrase test vector.
    #[test]
    fn pmk_vector_password_ieee() {
        let pmk = calc_pmk("password", "IEEE").unwrap();
        assert_eq!(
            hex(&pmk),
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
        );
    }

    // IEEE 802.11i, Annex H.4 — second test vector.
    #[test]
    fn pmk_vector_thisisapassword() {
        let pmk = calc_pmk("ThisIsAPassword", "ThisIsASSID").unwrap();
        assert_eq!(
            hex(&pmk),
            "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"
        );
    }

    // RFC 6070 PBKDF2-HMAC-SHA1 vector: "password"/"salt", 4096 iters, dkLen 20.
    #[test]
    fn pbkdf2_rfc6070_vector() {
        let dk = pbkdf2_sha1(b"password", b"salt", 4096, 20).unwrap();
        assert_eq!(hex(&dk), "4b007901b765489abead49d926f721d065a429c1");
    }

    #[test]
    fn batch_matches_individual() {
        let words = vec!["password".to_string(), "ThisIsAPassword".to_string()];
        let batch = calc_pmk_batch("IEEE", &words);
        assert_eq!(batch[0].as_ref().unwrap(), &calc_pmk("password", "IEEE").unwrap());
    }

    #[tokio::test]
    async fn async_matches_sync() {
        let sync = calc_pmk("password", "IEEE").unwrap();
        let asyncv = calc_pmk_async("password".into(), "IEEE".into()).await.unwrap();
        assert_eq!(sync, asyncv);
    }

    // RC4 encrypt then decrypt must be identity.
    #[test]
    fn rc4_roundtrip() {
        let key = b"secret";
        let original = b"Hello, Air!";
        let mut buf = original.to_vec();
        rc4_xcrypt(key, &mut buf).unwrap();
        assert_ne!(buf, original); // must be ciphertext
        rc4_xcrypt(key, &mut buf).unwrap();
        assert_eq!(buf, original); // back to plaintext
    }

    // Known-answer test: RC4("Key", "Plaintext") = 0xBBF316E8...
    // This vector is from the RC4 Wikipedia article.
    #[test]
    fn rc4_known_answer() {
        let mut data = b"Plaintext".to_vec();
        rc4_xcrypt(b"Key", &mut data).unwrap();
        assert_eq!(hex(&data), "bbf316e8d940af0ad3");
    }

    // WEP decrypt with a known IV+key and a hand-crafted payload.
    // We encrypt a 4-byte payload (0xDEADBEEF) with RC4(iv||key),
    // append its CRC32, then verify wep_decrypt recovers the plaintext.
    #[test]
    fn wep_encrypt_decrypt_roundtrip() {
        let key: &[u8] = b"12345"; // WEP-40
        let iv: [u8; 3] = [0xAB, 0xCD, 0xEF];
        let plaintext: &[u8] = b"AIRTEST!";

        // Build seed = iv || key
        let mut seed = [0u8; 8];
        seed[..3].copy_from_slice(&iv);
        seed[3..].copy_from_slice(key);

        // CRC32 of plaintext (IEEE 802.11 style)
        let crc = {
            let mut c = 0xFFFF_FFFFu32;
            for &b in plaintext {
                c ^= b as u32;
                for _ in 0..8 { c = (c >> 1) ^ (0xEDB88320 & (0u32.wrapping_sub(c & 1))); }
            }
            c ^ 0xFFFF_FFFF
        };
        let icv = crc.to_le_bytes();

        // Plaintext + ICV
        let mut frame = plaintext.to_vec();
        frame.extend_from_slice(&icv);

        // Encrypt with RC4(seed)
        rc4_xcrypt(&seed, &mut frame).unwrap();

        // wep_decrypt should recover original
        let plain = wep_decrypt(key, &iv, &frame).unwrap();
        assert_eq!(&plain, plaintext);
    }
}
