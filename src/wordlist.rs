use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::{AirError, AirResult};




#[derive(Debug, Default, Clone)]
pub struct WordlistStats {
    pub total_words: u64,
    pub tried_words: u64,
    pub current_file: String,
    pub speed_wps: f64,   // words per second
}

impl WordlistStats {
    pub fn progress(&self) -> f64 {
        if self.total_words == 0 { 
            return 0.0; 
        }
        self.tried_words as f64 / self.total_words as f64 * 100.0
    }
}


#[derive(Debug, Clone)]
pub struct WordlistConfig {
    /// Paths to dictionary files
    pub paths: Vec<PathBuf>,
    /// Batch size to send
    pub batch_size: usize,
    /// Minimum WPA password length (8)
    pub min_len: usize,
    /// Maximum WPA password length (63)
    pub max_len: usize,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            batch_size: 1000,
            min_len: 8,
            max_len: 63,
        }
    }
}


/// Async dictionary reader
pub struct WordlistReader {
    config: WordlistConfig,
}

impl WordlistReader {
    pub fn new(config: WordlistConfig) -> AirResult<Self> {
        if config.paths.is_empty() {
            return Err(AirError::InvalidParam("[ ETA ]: No wordlist files specified".into()));
        }

        for path in &config.paths {
            if !path.exists() {
                return Err(AirError::Io(std::io::Error::new(std::io::ErrorKind::NotFound,format!("[ ETA ]: Wordlist not found: {}", path.display()))));
            }
        }
        Ok(Self { config })
    }

    /// Counting words in files (for the progress bar)
    pub async fn count_words(&self) -> u64 {
        let mut total = 0u64;

        for path in &self.config.paths {
            if let Ok(file) = tokio::fs::File::open(path).await {
                let reader = BufReader::new(file);
                let mut lines = reader.lines();

                while lines.next_line().await.ok().flatten().is_some() {
                    total += 1;
                }
            }
        }
        total
    }

    /// Start streaming passwords through a channel
    ///
    /// Returns:
    /// - receiver for receiving password batches
    /// - handle for cancellation
    ///
    /// # Example
    /// ```rust
    /// let (rx, _handle) = reader.stream().await?;
    /// while let Some(batch) = rx.recv().await {
    /// // process the batch
    /// }
    /// ```
    pub async fn stream(self) -> AirResult<(mpsc::Receiver<Vec<String>>,tokio::task::JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel::<Vec<String>>(32);

        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(config.batch_size);

            for path in &config.paths {
                tracing::info!("[ ETA ]: Reading wordlist: {}", path.display());

                let file = match tokio::fs::File::open(path).await {
                    Ok(f)  => f,
                    Err(e) => {
                        tracing::error!("[ ETA ]: Cannot open {}: {}", path.display(), e);
                        continue;
                    }
                };
                let reader = BufReader::new(file);
                let mut lines = reader.lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    let word = line.trim().to_string();

                    // WPA Password: 8-63 characters
                    if word.len() < config.min_len || word.len() > config.max_len {
                        continue;
                    }
                    batch.push(word);

                    if batch.len() >= config.batch_size {
                        let send_batch = std::mem::replace(&mut batch,Vec::with_capacity(config.batch_size));

                        if tx.send(send_batch).await.is_err() {
                            // The recipient is closed - the password was found
                            tracing::info!("[ ETA ]: Wordlist stream stopped (found)");
                            return;
                        }
                    }
                }
            }

            // We send the rest
            if !batch.is_empty() {
                let _ = tx.send(batch).await;
            }
            tracing::info!("[ ETA ]: Wordlist exhausted");
        });
        Ok((rx, handle))
    }

    /// Streaming with mmap (for very large files > 1GB)
    pub async fn stream_mmap(&self) -> AirResult<mpsc::Receiver<Vec<String>>> {
        let (tx, rx) = mpsc::channel::<Vec<String>>(64);

        for path in self.config.paths.clone() {
            let tx       = tx.clone();
            let min_len  = self.config.min_len;
            let max_len  = self.config.max_len;
            let batch_sz = self.config.batch_size;

            tokio::task::spawn_blocking(move || {
                let file = std::fs::File::open(&path)?;
                // mmap - file not loaded into RAM!
                let mmap = unsafe {
                    memmap2::Mmap::map(&file)?
                };
                let mut batch = Vec::with_capacity(batch_sz);

                for line in mmap.split(|&b| b == b'\n') {
                    // Remove \r if present (Windows files)
                    let line = line.strip_suffix(b"\r").unwrap_or(line);

                    if line.len() < min_len || line.len() > max_len {
                        continue;
                    }

                    // Valid UTF-8 only
                    if let Ok(word) = std::str::from_utf8(line) {
                        batch.push(word.to_string());

                        if batch.len() >= batch_sz {
                            let send = std::mem::replace(&mut batch,Vec::with_capacity(batch_sz));

                            if tx.blocking_send(send).is_err() {
                                return Ok::<_, std::io::Error>(());
                            }
                        }
                    }
                }

                if !batch.is_empty() {
                    let _ = tx.blocking_send(batch);
                }
                Ok(())
            });
        }
        Ok(rx)
    }
}


/// Cracking progress tracker
pub struct ProgressTracker {
    stats: Arc<tokio::sync::RwLock<WordlistStats>>,
    start: std::time::Instant,
}

impl ProgressTracker {
    pub fn new(total_words: u64, file_name: &str) -> Self {
        Self {
            stats: Arc::new(tokio::sync::RwLock::new(WordlistStats {
                total_words,
                tried_words: 0,
                current_file: file_name.to_string(),
                speed_wps: 0.0,
            })),
            start: std::time::Instant::now(),
        }
    }

    /// Update the number of verified passwords
    pub async fn update(&self, tried: u64) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let speed   = if elapsed > 0.0 {
            tried as f64 / elapsed
        } else { 
            0.0 
        };
        let mut stats = self.stats.write().await;
        stats.tried_words = tried;
        stats.speed_wps   = speed;
    }

    /// Get current statistics
    pub async fn get(&self) -> WordlistStats {
        self.stats.read().await.clone()
    }

    /// Arc clone for another thread
    pub fn clone_stats(&self) -> Arc<tokio::sync::RwLock<WordlistStats>> {
        Arc::clone(&self.stats)
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_wordlist_stream() {
        // Create a temporary file
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        file.write_all(b"password1\n12345678\nshort\ntoolongpasswordthatexceeds63chars1234567890123456789012345678901\n").await.unwrap();

        let config = WordlistConfig {
            paths: vec![path],
            batch_size: 10,
            min_len: 8,
            max_len: 63,
        };
        let reader = WordlistReader::new(config).unwrap();
        let (mut rx, _handle) = reader.stream().await.unwrap();
        let batch = rx.recv().await.unwrap();
        // "short" missing (< 8), long missing (> 63)
        assert_eq!(batch.len(), 2);
        assert!(batch.contains(&"password1".to_string()));
        assert!(batch.contains(&"12345678".to_string()));
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let tracker = ProgressTracker::new(1000, "test.txt");
        tracker.update(500).await;
        let stats = tracker.get().await;
        assert_eq!(stats.tried_words, 500);
        assert_eq!(stats.total_words, 1000);
        assert!((stats.progress() - 50.0).abs() < 1.0);
    }
}





































































