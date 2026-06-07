use std::sync::Arc;
use tokio::sync::Semaphore;
use rayon::prelude::*;

use crate::{AirError, AirResult};
use crate::memory::{AlignedBuffer, BatchPool};



/// SIMD processor capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdSupport {
    None,
    Sse2,
    Avx,
    Avx2,
    Avx512f,
    Neon,    // ARM
    Asimd,   // ARM64
}

impl std::fmt::Display for SimdSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None (scalar)"),
            Self::Sse2 => write!(f, "SSE2"),
            Self::Avx => write!(f, "AVX"),
            Self::Avx2 => write!(f, "AVX2"),
            Self::Avx512f => write!(f, "AVX-512F"),
            Self::Neon => write!(f, "NEON (ARM)"),
            Self::Asimd => write!(f, "ASIMD (ARM64)"),
        }
    }
}

/// Version WPA Keys
#[derive(Debug, Clone, Copy)]
pub enum WpaKeyVersion {
    Wpa1Tkip = 1,   // HMAC-MD5
    Wpa2Ccmp = 2,   // HMAC-SHA1
    Wpa2Aes  = 3,   // AES-128-CMAC
}

/// Вфеф WPA handshake
#[derive(Debug, Clone)]
pub struct WpaHandshake {
    pub bssid: [u8; 6],
    pub stmac: [u8; 6],
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub eapol: Vec<u8>,       // max 256
    pub mic: [u8; 16],
    pub keyver: WpaKeyVersion,
    pub essid: String,
}

/// Result of cracking
#[derive(Debug)]
pub struct CrackResult {
    pub password: String,
    pub pmk: [u8; 32],
    pub tried: u64,
}


/// WPA Crypto Engine
///
/// # example
/// ```rust
/// let engine = WpaEngine::new("MyNetwork")?;
/// let result = engine.crack_from_list(
///     &handshake,
///     vec!["password1", "12345678"]
/// ).await?;
/// ```
pub struct WpaEngine {
    essid:       String,
    simd:        SimdSupport,
    /// ESSID aligned buffer for SIMD
    essid_buf:   AlignedBuffer,
    /// Maximum parallel threads
    max_threads: usize,
}

impl WpaEngine {
    /// Create an engine for a given ESSID
    pub fn new(essid: &str) -> AirResult<Self> {
        if essid.is_empty() || essid.len() > 32 {
            return Err(AirError::InvalidParam(
                format!("[ ETA ]: ESSID length must be 1-32, got {}", essid.len())
            ));
        }
        // Aligned buffer for ESSID (SIMD requires alignment)
        let mut essid_buf = AlignedBuffer::new_simd(64)?;
        let slice = essid_buf.as_slice_mut();
        let bytes = essid.as_bytes();
        slice[..bytes.len()].copy_from_slice(bytes);
        let simd = Self::detect_simd();
        let max_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        tracing::info!("[ ETA ]: WpaEngine initialized: essid='{}' simd={} threads={}",essid, simd, max_threads);

        Ok(Self {
            essid: essid.to_string(),
            simd,
            essid_buf,
            max_threads,
        })
    }

    /// Determine SIMD capabilities
    fn detect_simd() -> SimdSupport {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                return SimdSupport::Avx512f;
            }
            if is_x86_feature_detected!("avx2") {
                return SimdSupport::Avx2;
            }
            if is_x86_feature_detected!("avx") {
                return SimdSupport::Avx;
            }
            if is_x86_feature_detected!("sse2") {
                return SimdSupport::Sse2;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            return SimdSupport::Asimd;
        }
        #[cfg(target_arch = "arm")]
        {
            return SimdSupport::Neon;
        }
        SimdSupport::None
    }

    /// Batch the size depends on SIMD
    fn batch_size(&self) -> usize {
        match self.simd {
            SimdSupport::Avx512f => 16,
            SimdSupport::Avx2=> 8,
            SimdSupport::Avx => 8,
            SimdSupport::Sse2 => 4,
            SimdSupport::Asimd => 4,
            SimdSupport::Neon => 4,
            SimdSupport::None => 1,
        }
    }


    /// Calculate the PMK for one password
    ///
    /// PMK = PBKDF2-SHA1(password, essid, 4096, 32)
    pub fn calc_pmk(&self, password: &str) -> [u8; 32] {
        use std::num::NonZeroU32;
        let mut pmk = [0u8; 32];
        // PBKDF2-HMAC-SHA1
        // In reality, it calls C23 air_engine_calc_pmk_single
        // Here we show the logic
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(),self.essid.as_bytes(),4096,&mut pmk);
        pmk
    }

    /// Cracking from a password list (parallel)
    ///
    /// Uses rayon for parallelism.
    /// Stops when the first match is found.
    pub fn crack_list(&self,handshake: &WpaHandshake,passwords: &[String]) -> AirResult<Option<CrackResult>> {
        use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
        use std::sync::Mutex;
        let tried   = AtomicU64::new(0);
        let found   = AtomicBool::new(false);
        let result  = Mutex::new(None::<CrackResult>);
        passwords.par_chunks(self.batch_size()).for_each(|batch| {
                // If you've already found it, skip it.
                if found.load(Ordering::Relaxed) { 
                    return; 
                }

                for password in batch {
                    if found.load(Ordering::Relaxed) { 
                        break; 
                    }
                    tried.fetch_add(1, Ordering::Relaxed);
                    let pmk = self.calc_pmk(password);
                    let mic = self.calc_mic_from_pmk(&pmk, handshake);

                    if mic[..16] == handshake.mic {
                        found.store(true, Ordering::Relaxed);
                        let mut guard = result.lock().unwrap();
                        *guard = Some(CrackResult {
                            password: password.clone(),
                            pmk,
                            tried: tried.load(Ordering::Relaxed),
                        });
                    }
                }
            });

        Ok(result.into_inner().unwrap())
    }

    /// Async cracking from a password channel
    ///
    /// Reads passwords as they arrive.
    /// No need to load the entire dictionary into memory!
    pub async fn crack_channel(self: Arc<Self>, handshake: Arc<WpaHandshake>,mut rx: tokio::sync::mpsc::Receiver<Vec<String>>) -> AirResult<Option<CrackResult>> {
        while let Some(batch) = rx.recv().await {
            let engine = Arc::clone(&self);
            let hs     = Arc::clone(&handshake);

            let result = tokio::task::spawn_blocking(move || {
                engine.crack_list(&hs, &batch)
            }).await.map_err(|e| AirError::Engine(e.to_string()))??;

            if result.is_some() {
                return Ok(result);
            }
        }
        Ok(None)
    }

  

    fn calc_mic_from_pmk(&self,pmk: &[u8; 32],handshake: &WpaHandshake) -> [u8; 20] {
        // PTK = PRF-512(PMK, "Pairwise key expansion", PKE)
        let ptk = self.calc_ptk(pmk, handshake);

        // MIC depends on keyver
        match handshake.keyver {
            WpaKeyVersion::Wpa1Tkip => {
                // HMAC-MD5(PTK[0..16], EAPOL)
                self.hmac_md5(&ptk[..16], &handshake.eapol)
            }
            WpaKeyVersion::Wpa2Ccmp => {
                // HMAC-SHA1(PTK[0..16], EAPOL)
                self.hmac_sha1(&ptk[..16], &handshake.eapol)
            }
            WpaKeyVersion::Wpa2Aes => {
                // AES-128-CMAC(PTK[0..16], EAPOL)
                self.aes_cmac(&ptk[..16], &handshake.eapol)
            }
        }
    }

    fn calc_ptk(&self,pmk: &[u8; 32],handshake: &WpaHandshake) -> [u8; 64] {
        // PKE = "Pairwise key expansion" || min(BSSID,STMAC)
        //     || max(BSSID,STMAC) || min(ANonce,SNonce)
        //     || max(ANonce,SNonce)
        let mut pke = [0u8; 100];
        pke[..23].copy_from_slice(b"Pairwise key expansion\0");

        // Order MAC addresses
        if handshake.stmac <= handshake.bssid {
            pke[23..29].copy_from_slice(&handshake.stmac);
            pke[29..35].copy_from_slice(&handshake.bssid);
        } else {
            pke[23..29].copy_from_slice(&handshake.bssid);
            pke[29..35].copy_from_slice(&handshake.stmac);
        }

        // Order nonce
        if handshake.snonce <= handshake.anonce {
            pke[35..67].copy_from_slice(&handshake.snonce);
            pke[67..99].copy_from_slice(&handshake.anonce);
        } else {
            pke[35..67].copy_from_slice(&handshake.anonce);
            pke[67..99].copy_from_slice(&handshake.snonce);
        }

        // PRF-512
        self.sha1_prf(pmk, b"Pairwise key expansion", &pke[23..99])
    }

    fn sha1_prf(&self,key: &[u8],label: &[u8],data: &[u8]) -> [u8; 64] {
        // IEEE 802.11 PRF-512
        // R = "" ; i = 0..3: R ||= HMAC-SHA1(key, label||0x00||data||i)
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mut result = [0u8; 64];
        let mut offset = 0usize;

        for i in 0u8..4 {
            let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC-SHA1 init failed");
            mac.update(label);
            mac.update(&[0x00]);
            mac.update(data);
            mac.update(&[i]);
            let hash = mac.finalize().into_bytes();
            let end  = (offset + 20).min(64);
            result[offset..end].copy_from_slice(&hash[..end - offset]);
            offset = end;

            if offset >= 64 { 
                break; 
            }
        }

        result
    }

    fn hmac_md5(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, Mac};
        use md5::Md5;
        let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC-MD5 init failed");
        mac.update(data);
        let mut result = [0u8; 20];
        let hash = mac.finalize().into_bytes();
        result[..16].copy_from_slice(&hash);
        result
    }

    fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC-SHA1 init failed");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn aes_cmac(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        use cmac::{Cmac, Mac};
        use aes::Aes128;
        let mut mac = <Cmac<Aes128>>::new_from_slice(key).expect("AES-CMAC init failed");
        mac.update(data);
        let mut result = [0u8; 20];
        let hash = mac.finalize().into_bytes();
        result[..16].copy_from_slice(&hash);
        result
    }
}
















