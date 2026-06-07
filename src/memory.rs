use std::ptr::NonNull;
use std::alloc::{alloc_zeroed, dealloc, Layout};

use crate::AirError;



/// Buffer with the specified alignment
/// Automatically freed on Drop
pub struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}



impl AlignedBuffer {
    /// Create a zero-aligned buffer
    ///
    /// # Example
    /// ```rust
    /// // 32-byte aligned SIMD buffer (AVX2)
    /// let buf = AlignedBuffer::new(1024, 32)?;
    /// ```
    pub fn new(size: usize, align: usize) -> Result<Self, AirError> {
        if size == 0 {
            return Err(AirError::Memory("size cannot be zero".into()));
        }
        let layout = Layout::from_size_align(size, align).map_err(|e| AirError::Memory(e.to_string()))?;
        // SAFETY: layout valid, we are checking ptr
        let ptr = unsafe { 
            alloc_zeroed(layout) 
        };
        let ptr = NonNull::new(ptr).ok_or_else(|| AirError::Memory(format!("Failed to allocate {} bytes aligned to {}", size, align)))?;
        Ok(Self { 
            ptr, 
            layout, 
        })
    }

    /// Typical alignments for SIMD
    pub fn new_simd(size: usize) -> Result<Self, AirError> {
        // AVX2 = 32 bytes, AVX512 = 64 bytes
        // We take 64 - it works for everyone
        Self::new(size, 64)
    }

    /// Raw pointer (only for FFI with C23 core)
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Byte slice
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptrvalid, size from layout
        unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr(),self.layout.size())
        }
    }

    /// Mutable cut
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(),self.layout.size())
        }
    }

    /// Buffer size
    pub fn size(&self) -> usize {
        self.layout.size()
    }

    /// Reset Contents
    pub fn zero(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr(), 0, self.layout.size());
        }
    }
}




/// Automatic release
/// Replacement for cleanup_tiny_memory()
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr and layout valid, highlighted by us

        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
        tracing::trace!("[ ETA ]: AlignedBuffer freed: {} bytes align {}",self.layout.size(),self.layout.align());
    }
}

/// Send + Sync Safe - We have exclusive access
unsafe impl Send for AlignedBuffer {

}

unsafe impl Sync for AlignedBuffer {
    
}


/// Pre-allocated pool for batch operations
///
/// Instead of complex mem_alloc_tiny with linked list -
/// just a Vec with clear boundaries
pub struct BatchPool {
    /// PMK buffers: [batch_size][32]
    pmk: Vec<[u8; 32]>,
    /// PTK buffers: [batch_size][64]
    ptk: Vec<[u8; 64]>,
    /// MIC buffers: [batch_size][20]
    mic: Vec<[u8; 20]>,
    /// size batch
    batch_size: usize,
}

impl BatchPool {
    pub fn new(batch_size: usize) -> Self {
        Self {
            pmk: vec![[0u8; 32]; batch_size],
            ptk: vec![[0u8; 64]; batch_size],
            mic: vec![[0u8; 20]; batch_size],
            batch_size,
        }
    }

    pub fn pmk_mut(&mut self, idx: usize) -> &mut [u8; 32] {
        assert!(idx < self.batch_size, "batch index out of bounds");
        &mut self.pmk[idx]
    }

    pub fn ptk_mut(&mut self, idx: usize) -> &mut [u8; 64] {
        assert!(idx < self.batch_size);
        &mut self.ptk[idx]
    }

    pub fn mic_mut(&mut self, idx: usize) -> &mut [u8; 20] {
        assert!(idx < self.batch_size);
        &mut self.mic[idx]
    }

    /// Resetting everything is faster than recreating it.
    pub fn reset(&mut self) {
        for pmk in &mut self.pmk { 
            pmk.fill(0);
        }

        for ptk in &mut self.ptk { 
            ptk.fill(0);
        }

        for mic in &mut self.mic { 
            mic.fill(0);
        }
    }

    pub fn batch_size(&self) -> usize { self.batch_size }
}


/// Output bytes in hex format
/// Replacement for dump_stuff() / dump_stuff_msg()
pub fn hex_dump(label: &str, data: &[u8]) {
    use std::fmt::Write;
    let mut out = String::with_capacity(data.len() * 3 + label.len() + 4);

    if !label.is_empty() {
        let _ = write!(out, "{}: ", label);
    }

    for (i, byte) in data.iter().enumerate() {
        let _ = write!(out, "{:02x}", byte);
        if (i + 1) % 4 == 0 { out.push(' '); }
    }
    tracing::debug!("{}", out.trim_end());
}

/// Endianity swap For u32 array
/// Replacement alter_endianity()
pub fn swap_endian_u32(data: &mut [u32]) {
    for word in data.iter_mut() {
        *word = word.swap_bytes();
    }
}

/// Endianity swap For u64 array
pub fn swap_endian_u64(data: &mut [u64]) {
    for word in data.iter_mut() {
        *word = word.swap_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aligned_buffer_creates() {
        let buf = AlignedBuffer::new(1024, 32).unwrap();
        assert_eq!(buf.size(), 1024);
        // Let's check that it's reset.
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_aligned_buffer_simd() {
        let buf = AlignedBuffer::new_simd(4096).unwrap();
        // The pointer is aligned to 64
        assert_eq!(buf.as_ptr() as usize % 64, 0);
    }

    #[test]
    fn test_batch_pool() {
        let mut pool = BatchPool::new(8);
        pool.pmk_mut(0).fill(0xAB);
        assert_eq!(pool.pmk_mut(0)[0], 0xAB);
        pool.reset();
        assert_eq!(pool.pmk_mut(0)[0], 0x00);
    }

    #[test]
    fn test_swap_endian() {
        let mut data = vec![0x12345678u32];
        swap_endian_u32(&mut data);
        assert_eq!(data[0], 0x78563412);
    }
}


























