

#[derive(Debug, Clone)]
pub struct CpuFeatures {
    pub avx512f: bool,
    pub avx2: bool,
    pub avx: bool,
    pub sse2: bool,
    pub neon: bool,   // ARM
    pub asimd: bool,   // ARM64
}

impl CpuFeatures {
    pub fn detect() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            avx512f: is_x86_feature_detected!("avx512f"),
            #[cfg(target_arch = "x86_64")]
            avx2:    is_x86_feature_detected!("avx2"),
            #[cfg(target_arch = "x86_64")]
            avx:     is_x86_feature_detected!("avx"),
            #[cfg(target_arch = "x86_64")]
            sse2:    is_x86_feature_detected!("sse2"),

            #[cfg(target_arch = "aarch64")]
            asimd: true,
            #[cfg(target_arch = "arm")]
            neon:  std::arch::is_arm_feature_detected!("neon"),

            #[cfg(not(target_arch = "x86_64"))]
            avx512f: false,
            #[cfg(not(target_arch = "x86_64"))]
            avx2: false,
            #[cfg(not(target_arch = "x86_64"))]
            avx: false,
            #[cfg(not(target_arch = "x86_64"))]
            sse2: false,
            #[cfg(not(target_arch = "arm"))]
            neon: false,
            #[cfg(not(target_arch = "aarch64"))]
            asimd: false,
        }
    }

    #[allow(clippy::if_same_then_else)]
    pub fn optimal_batch_size(&self) -> usize {
        if self.avx512f {
            16
        } else if self.avx2 {
            8
        } else if self.avx  {
            8
        } else if self.sse2 {
            4
        } else if self.asimd{
            4
        } else if self.neon {
            4
        } else {
            1
        }
    }

    pub fn best_name(&self) -> &'static str {
        if self.avx512f { 
            "AVX-512F" 
        } else if self.avx2 { 
            "AVX2"
        } else if self.avx { 
            "AVX"
        } else if self.sse2{ 
            "SSE2" 
        } else if self.asimd { 
            "ASIMD" 
        } else if self.neon { 
            "NEON"
        } else { 
            "scalar"
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpuCoreInfo {
    pub physical: usize, 
    pub logical:  usize,
    pub has_htt:  bool,
}

impl CpuCoreInfo {
    pub fn detect() -> Self {
        let logical = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

        Self {
            physical: logical / 2,
            logical,
            has_htt: logical > 1,
        }
    }

    pub fn optimal_crypto_threads(&self) -> usize {
        if self.has_htt {
            self.physical.max(1)
        } else {
            self.logical.max(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_detect() {
        let features = CpuFeatures::detect();
        println!("Best SIMD: {}", features.best_name());
        println!("Batch size: {}", features.optimal_batch_size());
    }

    #[test]
    fn test_core_info() {
        let cores = CpuCoreInfo::detect();
        assert!(cores.logical >= 1);
        assert!(cores.optimal_crypto_threads() >= 1);
    }
}