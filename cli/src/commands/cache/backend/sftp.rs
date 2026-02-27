use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ssh2::Session;

use super::{AuthOptions, CacheBackend};

/// SFTP cache backend.
///
/// Same layout as the filesystem backend, over SSH/SFTP.
pub struct SftpBackend {
    session: Mutex<Session>,
    root: String,
}

impl SftpBackend {
    pub fn new(
        host: &str,
        port: u16,
        user: Option<String>,
        path: &str,
        auth: &AuthOptions,
    ) -> Result<Self> {
        let tcp = TcpStream::connect(format!("{host}:{port}"))
            .with_context(|| format!("connecting to {host}:{port}"))?;

        let mut session = Session::new().context("creating SSH session")?;
        session.set_tcp_stream(tcp);
        session.handshake().context("SSH handshake failed")?;

        let username = user
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "root".to_string());

        // Try authentication methods in order.
        let mut authenticated = false;

        // 1. SSH agent
        if std::env::var("SSH_AUTH_SOCK").is_ok() {
            if let Ok(mut agent) = session.agent() {
                if agent.connect().is_ok() && agent.list_identities().is_ok() {
                    let identities: Vec<_> = agent.identities().unwrap_or_default();
                    for identity in &identities {
                        if agent.userauth(&username, identity).is_ok() {
                            authenticated = true;
                            break;
                        }
                    }
                }
            }
        }

        // 2. Explicit key file
        if !authenticated {
            if let Some(ref key_path) = auth.ssh_key {
                if session
                    .userauth_pubkey_file(&username, None, Path::new(key_path), None)
                    .is_ok()
                {
                    authenticated = true;
                }
            }
        }

        // 3. Default key files
        if !authenticated {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            for key_name in &["id_ed25519", "id_rsa"] {
                let key_path = PathBuf::from(&home).join(".ssh").join(key_name);
                if key_path.exists()
                    && session
                        .userauth_pubkey_file(&username, None, &key_path, None)
                        .is_ok()
                {
                    authenticated = true;
                    break;
                }
            }
        }

        // 4. Password
        if !authenticated {
            if let Some(ref password) = auth.ssh_password {
                session
                    .userauth_password(&username, password)
                    .context("SSH password authentication failed")?;
                authenticated = true;
            }
        }

        if !authenticated {
            anyhow::bail!(
                "SSH authentication failed for {username}@{host}:{port}. \
                 Try --ssh-key, --ssh-password, or ensure SSH agent is running."
            );
        }

        Ok(Self {
            session: Mutex::new(session),
            root: path.trim_end_matches('/').to_string(),
        })
    }

    fn narinfo_path(&self, store_hash: &str) -> String {
        format!("{}/{store_hash}.narinfo", self.root)
    }

    fn nar_path(&self, filename: &str) -> String {
        format!("{}/nar/{filename}", self.root)
    }

    fn sftp_read(&self, remote_path: &str) -> Result<Vec<u8>> {
        let session = self.session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        let mut file = sftp
            .open(Path::new(remote_path))
            .with_context(|| format!("opening {remote_path}"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .with_context(|| format!("reading {remote_path}"))?;
        Ok(buf)
    }

    fn sftp_write(&self, remote_path: &str, data: &[u8]) -> Result<()> {
        let session = self.session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;

        // Ensure parent directory exists.
        if let Some(parent) = Path::new(remote_path).parent() {
            let _ = sftp.mkdir(parent, 0o755);
        }

        let mut file = sftp
            .create(Path::new(remote_path))
            .with_context(|| format!("creating {remote_path}"))?;
        use std::io::Write;
        file.write_all(data)
            .with_context(|| format!("writing {remote_path}"))?;
        Ok(())
    }

    fn sftp_exists(&self, remote_path: &str) -> Result<bool> {
        let session = self.session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        match sftp.stat(Path::new(remote_path)) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[async_trait]
impl CacheBackend for SftpBackend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let path = self.narinfo_path(store_hash);
        self.sftp_exists(&path)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let path = self.narinfo_path(store_hash);
        let data = self.sftp_read(&path)?;
        String::from_utf8(data).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let path = self.narinfo_path(store_hash);
        self.sftp_write(&path, content.as_bytes())
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let path = format!("{}/{url}", self.root);
        self.sftp_read(&path)
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let path = self.nar_path(filename);
        self.sftp_write(&path, data)
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for hash in store_hashes {
            let path = self.narinfo_path(hash);
            if !self.sftp_exists(&path)? {
                missing.push(hash.to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        let info_path = format!("{}/nix-cache-info", self.root);
        if !self.sftp_exists(&info_path)? {
            // Create root directory.
            let session = self.session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
            let sftp = session.sftp().context("opening SFTP channel")?;
            let _ = sftp.mkdir(Path::new(&self.root), 0o755);
            let _ = sftp.mkdir(Path::new(&format!("{}/nar", self.root)), 0o755);
            drop(sftp);
            drop(session);

            let content = format!(
                "StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n"
            );
            self.sftp_write(&info_path, content.as_bytes())?;
        }
        Ok(())
    }
}
