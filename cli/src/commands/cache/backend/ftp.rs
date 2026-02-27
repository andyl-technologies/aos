use std::io::Cursor;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;
use suppaftp::FtpStream;

use super::{AuthOptions, CacheBackend};

/// FTP cache backend (plain FTP, no TLS).
///
/// Standard binary cache layout on a remote FTP server.
/// Primarily useful for pulling from FTP mirrors (anonymous read).
/// All operations use the synchronous FTP client behind a Mutex,
/// similar to the SFTP backend pattern.
pub struct FtpBackend {
    host: String,
    port: u16,
    user: String,
    password: String,
    root: String,
    /// Cached connection. Re-created if stale.
    conn: Mutex<Option<FtpStream>>,
}

impl FtpBackend {
    pub fn new(host: &str, port: u16, path: &str, secure: bool, auth: &AuthOptions) -> Result<Self> {
        if secure {
            anyhow::bail!(
                "FTPS (ftps://) requires the 'native-tls' or 'rustls' feature. \
                 Use plain ftp:// or a different backend."
            );
        }

        let user = auth
            .ftp_user
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());
        let password = auth
            .ftp_password
            .clone()
            .unwrap_or_else(|| "aos@".to_string());

        Ok(Self {
            host: host.to_string(),
            port,
            user,
            password,
            root: path.trim_start_matches('/').trim_end_matches('/').to_string(),
            conn: Mutex::new(None),
        })
    }

    /// Get or create an FTP connection.
    fn get_conn(&self) -> Result<std::sync::MutexGuard<'_, Option<FtpStream>>> {
        let mut guard = self.conn.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;

        if guard.is_none() {
            let addr = format!("{}:{}", self.host, self.port);
            let mut ftp = FtpStream::connect(&addr)
                .map_err(|e| anyhow::anyhow!("FTP connect to {addr}: {e}"))?;

            ftp.login(&self.user, &self.password)
                .map_err(|e| anyhow::anyhow!("FTP login as {}: {e}", self.user))?;

            ftp.transfer_type(suppaftp::types::FileType::Binary)
                .map_err(|e| anyhow::anyhow!("FTP binary mode: {e}"))?;

            *guard = Some(ftp);
        }

        Ok(guard)
    }

    fn remote_path(&self, relative: &str) -> String {
        if self.root.is_empty() {
            format!("/{relative}")
        } else {
            format!("/{}/{}", self.root, relative)
        }
    }

    fn ftp_read(&self, path: &str) -> Result<Vec<u8>> {
        let mut guard = self.get_conn()?;
        let ftp = guard.as_mut().unwrap();
        let cursor = ftp
            .retr_as_buffer(path)
            .map_err(|e| anyhow::anyhow!("FTP RETR {path}: {e}"))?;
        Ok(cursor.into_inner())
    }

    fn ftp_write(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut guard = self.get_conn()?;
        let ftp = guard.as_mut().unwrap();
        let mut cursor = Cursor::new(data.to_vec());
        ftp.put_file(path, &mut cursor)
            .map_err(|e| anyhow::anyhow!("FTP STOR {path}: {e}"))?;
        Ok(())
    }

    fn ftp_exists(&self, path: &str) -> Result<bool> {
        let mut guard = self.get_conn()?;
        let ftp = guard.as_mut().unwrap();
        match ftp.size(path) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn ftp_mkdir(&self, path: &str) -> Result<()> {
        let mut guard = self.get_conn()?;
        let ftp = guard.as_mut().unwrap();
        let _ = ftp.mkdir(path); // Ignore error if already exists.
        Ok(())
    }
}

impl Drop for FtpBackend {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.conn.lock() {
            if let Some(ref mut ftp) = *guard {
                let _ = ftp.quit();
            }
        }
    }
}

#[async_trait]
impl CacheBackend for FtpBackend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let path = self.remote_path(&format!("{store_hash}.narinfo"));
        self.ftp_exists(&path)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let path = self.remote_path(&format!("{store_hash}.narinfo"));
        let data = self.ftp_read(&path)?;
        String::from_utf8(data).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        // Ensure directories exist.
        if !self.root.is_empty() {
            self.ftp_mkdir(&format!("/{}", self.root))?;
        }
        let path = self.remote_path(&format!("{store_hash}.narinfo"));
        self.ftp_write(&path, content.as_bytes())
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let path = self.remote_path(url);
        self.ftp_read(&path)
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        // Ensure directories exist.
        if !self.root.is_empty() {
            self.ftp_mkdir(&format!("/{}", self.root))?;
        }
        self.ftp_mkdir(&self.remote_path("nar"))?;
        let path = self.remote_path(&format!("nar/{filename}"));
        self.ftp_write(&path, data)
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for hash in store_hashes {
            let path = self.remote_path(&format!("{hash}.narinfo"));
            if !self.ftp_exists(&path)? {
                missing.push(hash.to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        let info_path = self.remote_path("nix-cache-info");
        if self.ftp_exists(&info_path)? {
            return Ok(());
        }

        // Ensure directories.
        if !self.root.is_empty() {
            self.ftp_mkdir(&format!("/{}", self.root))?;
        }
        self.ftp_mkdir(&self.remote_path("nar"))?;

        let content = format!(
            "StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n"
        );
        self.ftp_write(&info_path, content.as_bytes())
    }
}
