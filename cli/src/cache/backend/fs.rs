use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::CacheBackend;

/// Filesystem cache backend.
///
/// Stores narinfos and NARs in a local directory, producing a layout directly
/// usable as `--substituters file:///path`.
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn narinfo_path(&self, store_hash: &str) -> PathBuf {
        self.root.join(format!("{store_hash}.narinfo"))
    }

    fn nar_dir(&self) -> PathBuf {
        self.root.join("nar")
    }
}

#[async_trait]
impl CacheBackend for FsBackend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        Ok(self.narinfo_path(store_hash).exists())
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let path = self.narinfo_path(store_hash);
        tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("reading narinfo {}", path.display()))
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .context("creating cache directory")?;

        let path = self.narinfo_path(store_hash);
        tokio::fs::write(&path, content)
            .await
            .with_context(|| format!("writing narinfo {}", path.display()))
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let path = self.root.join(url);
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("reading NAR {}", path.display()))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let nar_dir = self.nar_dir();
        tokio::fs::create_dir_all(&nar_dir)
            .await
            .context("creating nar directory")?;

        let path = nar_dir.join(filename);
        tokio::fs::write(&path, data)
            .await
            .with_context(|| format!("writing NAR {}", path.display()))
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for hash in store_hashes {
            if !self.narinfo_path(hash).exists() {
                missing.push(hash.to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .context("creating cache directory")?;

        let info_path = self.root.join("nix-cache-info");
        if !info_path.exists() {
            let content = format!(
                "StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n"
            );
            tokio::fs::write(&info_path, content)
                .await
                .context("writing nix-cache-info")?;
        }
        Ok(())
    }
}
