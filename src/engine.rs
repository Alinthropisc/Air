use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use rayon::prelude::*;

use crate::{AirError, AirResult};
use crate::memory::AlignedBuffer;
use crate::types::{AppEvent, CrackProgress, CrackState};
use crate::globals::State;

// How often we emit a progress event (candidates between broadcasts)
const PROGRESS_INTERVAL: u64 = 5_000;

// ── EtaEstimator — rolling-window speed + ETA calculator ────────────────────
// Pattern: Strategy — pluggable estimator, swap for more sophisticated later.

struct EtaEstimator {
    window:      std::collections::VecDeque<(std::time::Instant, u64)>,
    window_secs: u64,
}

impl EtaEstimator {
    fn new() -> Self {
        Self { window: std::collections::VecDeque::with_capacity(64), window_secs: 10 }
    }

    fn push(&mut self, tried: u64) {
        let now = std::time::Instant::now();
        self.window.push_back((now, tried));
        while self.window.len() > 1 {
            if now.duration_since(self.window[0].0).as_secs() > self.window_secs {
                self.window.pop_front();
            } else { break; }
        }
    }

    fn speed(&self) -> f64 {
        if self.window.len() < 2 { return 0.0; }
        let (t0, w0) = self.window[0];
        let (t1, w1) = *self.window.back().unwrap();
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt < 0.01 { return 0.0; }
        w1.saturating_sub(w0) as f64 / dt
    }

    fn eta(&self, tried: u64, total: u64) -> Option<u64> {
        if total == 0 { return None; }
        let remaining = total.saturating_sub(tried);
        let speed = self.speed();
        if speed < 1.0 { return None; }
        Some((remaining as f64 / speed) as u64)
    }
}



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

/// WPA 4-way handshake data captured from the air
#[derive(Debug, Clone)]
pub struct WpaHandshake {
    /// AP MAC as colon-separated hex (e.g. "AA:BB:CC:DD:EE:FF")
    pub bssid:  String,
    /// Station MAC as colon-separated hex
    pub stmac:  String,
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub eapol:  Vec<u8>,
    pub mic:    [u8; 16],
    pub keyver: WpaKeyVersion,
    pub essid:  String,
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
    #[allow(dead_code)]
    essid_buf:   AlignedBuffer,
    /// Maximum parallel threads
    #[allow(dead_code)]
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
    /// PMK = PBKDF2-SHA1(password, essid, 4096, 32) — delegates to C23 core.
    pub fn calc_pmk(&self, password: &str) -> [u8; 32] {
        air_crypto::calc_pmk(password, &self.essid).unwrap_or([0u8; 32])
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

    /// Async cracking from a password channel — streams batches, emits live progress.
    ///
    /// Pattern: Observer — emits `AppEvent::CrackProgress` every PROGRESS_INTERVAL words.
    pub async fn crack_channel(
        self: Arc<Self>,
        handshake: Arc<WpaHandshake>,
        mut rx: tokio::sync::mpsc::Receiver<Vec<String>>,
        total_words: u64,
    ) -> AirResult<Option<CrackResult>> {
        let total_tried = Arc::new(AtomicU64::new(0));
        let mut eta = EtaEstimator::new();
        let mut last_emit = 0u64;

        State::reset_crack_progress(&handshake.bssid, &handshake.essid, total_words);

        while let Some(batch) = rx.recv().await {
            let engine = Arc::clone(&self);
            let hs     = Arc::clone(&handshake);
            let ctr    = Arc::clone(&total_tried);

            let result = tokio::task::spawn_blocking(move || {
                let r = engine.crack_list(&hs, &batch);
                ctr.fetch_add(batch.len() as u64, Ordering::Relaxed);
                r
            }).await.map_err(|e| AirError::Engine(e.to_string()))??;

            let tried = total_tried.load(Ordering::Relaxed);
            eta.push(tried);

            // Emit progress periodically
            if tried - last_emit >= PROGRESS_INTERVAL {
                last_emit = tried;
                State::emit(AppEvent::CrackProgress(CrackProgress {
                    bssid:     handshake.bssid.clone(),
                    essid:     handshake.essid.clone(),
                    tried,
                    total:     total_words,
                    speed_wps: eta.speed(),
                    eta_secs:  eta.eta(tried, total_words),
                    state:     CrackState::Running,
                }));
            }

            if let Some(ref r) = result {
                State::emit(AppEvent::CrackFound {
                    bssid: handshake.bssid.clone(),
                    essid: handshake.essid.clone(),
                    password: r.password.clone(),
                });
                return Ok(result);
            }
        }

        let tried = total_tried.load(Ordering::Relaxed);
        State::emit(AppEvent::CrackExhausted { bssid: handshake.bssid.clone(), tried });
        Ok(None)
    }

    /// PMKID attack — no 4-way handshake needed.
    /// PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
    /// Pattern: Observer — emits CrackProgress via event bus.
    #[allow(clippy::too_many_arguments)]
    pub async fn crack_pmkid_channel(
        self: Arc<Self>,
        pmkid:   [u8; 16],
        ap_mac:  [u8; 6],
        sta_mac: [u8; 6],
        essid:   String,
        bssid:   String,
        total_words: u64,
        mut rx:  tokio::sync::mpsc::Receiver<Vec<String>>,
    ) -> AirResult<Option<CrackResult>> {
        let total_tried = Arc::new(AtomicU64::new(0));
        let mut eta      = EtaEstimator::new();
        let mut last_emit = 0u64;

        State::reset_crack_progress(&bssid, &essid, total_words);

        while let Some(batch) = rx.recv().await {
            let engine    = Arc::clone(&self);
            let tried_ctr = Arc::clone(&total_tried);

            let result = tokio::task::spawn_blocking(move || {
                for password in &batch {
                    tried_ctr.fetch_add(1, Ordering::Relaxed);
                    let pmk = engine.calc_pmk(password);
                    let candidate = engine.calc_pmkid(&pmk, &ap_mac, &sta_mac);
                    if candidate == pmkid {
                        return Some(CrackResult {
                            password: password.clone(),
                            pmk,
                            tried: tried_ctr.load(Ordering::Relaxed),
                        });
                    }
                }
                None
            }).await.map_err(|e| AirError::Engine(e.to_string()))?;

            let tried = total_tried.load(Ordering::Relaxed);
            eta.push(tried);

            if tried - last_emit >= PROGRESS_INTERVAL {
                last_emit = tried;
                State::emit(AppEvent::CrackProgress(CrackProgress {
                    bssid:     bssid.clone(),
                    essid:     essid.clone(),
                    tried,
                    total:     total_words,
                    speed_wps: eta.speed(),
                    eta_secs:  eta.eta(tried, total_words),
                    state:     CrackState::Running,
                }));
            }

            if let Some(ref r) = result {
                State::emit(AppEvent::CrackFound {
                    bssid:    bssid.clone(),
                    essid:    essid.clone(),
                    password: r.password.clone(),
                });
                return Ok(result);
            }
        }

        let tried = total_tried.load(Ordering::Relaxed);
        State::emit(AppEvent::CrackExhausted { bssid, tried });
        Ok(None)
    }

    /// High-level entry point: auto-selects wordlist or bruteforce source.
    ///
    /// Pattern: Template Method — same crack pipeline, swappable word source.
    pub async fn crack_auto(
        self: Arc<Self>,
        handshake: Arc<WpaHandshake>,
        source:    crate::wordlist::WordSource,
    ) -> AirResult<Option<CrackResult>> {
        let total = source.count_hint().await;
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<String>>(64);

        let src_task = tokio::spawn(async move {
            let _ = source.stream_into(tx).await;
        });

        let result = Self::crack_channel(self, handshake, rx, total).await;
        let _ = src_task.await;
        result
    }

    /// WEP cracking via external aircrack-ng (thin wrapper).
    /// WEP key recovery is statistically fast; we delegate to the proven C tool.
    pub async fn crack_wep(cap_file: &str, bssid: &str) -> AirResult<Option<String>> {
        let output = tokio::process::Command::new("aircrack-ng")
            .args(["-b", bssid, "-q", cap_file])
            .output()
            .await
            .map_err(|e| AirError::Engine(format!("aircrack-ng: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // aircrack-ng prints "KEY FOUND! [ XX:XX:XX:XX:XX ]"
        if let Some(line) = stdout.lines().find(|l| l.contains("KEY FOUND!")) {
            let key = line
                .split('[').nth(1)
                .and_then(|s| s.split(']').next())
                .map(|s| s.trim().to_string());
            return Ok(key);
        }
        Ok(None)
    }

    /// Compute PMKID per IEEE 802.11-2016 §12.7.1.3
    fn calc_pmkid(&self, pmk: &[u8; 32], ap_mac: &[u8; 6], sta_mac: &[u8; 6]) -> [u8; 16] {
        // HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
        let mut data = [0u8; 8 + 6 + 6];
        data[..8].copy_from_slice(b"PMK Name");
        data[8..14].copy_from_slice(ap_mac);
        data[14..20].copy_from_slice(sta_mac);
        let full = air_crypto::hmac_sha1(pmk, &data).unwrap_or([0u8; 20]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
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

    /// Parse "AA:BB:CC:DD:EE:FF" → [u8; 6]
    fn mac_str_to_bytes(s: &str) -> [u8; 6] {
        let mut out = [0u8; 6];
        for (i, part) in s.split(':').take(6).enumerate() {
            out[i] = u8::from_str_radix(part, 16).unwrap_or(0);
        }
        out
    }

    fn calc_ptk(&self, pmk: &[u8; 32], handshake: &WpaHandshake) -> [u8; 64] {
        let mut pke = [0u8; 100];
        pke[..23].copy_from_slice(b"Pairwise key expansion\0");

        let bssid_b = Self::mac_str_to_bytes(&handshake.bssid);
        let stmac_b = Self::mac_str_to_bytes(&handshake.stmac);

        // Order MAC addresses (smaller first per IEEE 802.11)
        if stmac_b <= bssid_b {
            pke[23..29].copy_from_slice(&stmac_b);
            pke[29..35].copy_from_slice(&bssid_b);
        } else {
            pke[23..29].copy_from_slice(&bssid_b);
            pke[29..35].copy_from_slice(&stmac_b);
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

    fn sha1_prf(&self, key: &[u8], label: &[u8], data: &[u8]) -> [u8; 64] {
        air_crypto::prf512(key, label, data).unwrap_or([0u8; 64])
    }

    fn hmac_md5(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        let hash16 = air_crypto::hmac_md5(key, data).unwrap_or([0u8; 16]);
        let mut out = [0u8; 20];
        out[..16].copy_from_slice(&hash16);
        out
    }

    fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        air_crypto::hmac_sha1(key, data).unwrap_or([0u8; 20])
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
















