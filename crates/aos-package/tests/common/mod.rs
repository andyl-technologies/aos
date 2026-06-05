use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_core::output::Printer;
use aos_package::registry::channel;
use aos_package::registry::objectstore;
use aos_package::types::{RegistryConfig, RegistryState, SigningConfig};
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub struct RegistryFixture {
    tmp: tempfile::TempDir,
    name: String,
    source: PathBuf,
    origin: PathBuf,
    cache: PathBuf,
    registries: PathBuf,
    config_dir: PathBuf,
    signing: SigningFixture,
}

impl RegistryFixture {
    pub fn new(name: &str) -> Result<Self> {
        let tmp = tempfile::TempDir::new().context("creating registry fixture tempdir")?;
        let source = tmp.path().join("source");
        let origin = tmp.path().join("origin.git");
        let cache = tmp.path().join("cache");
        let registries = tmp.path().join("registries");
        let config_dir = tmp.path().join("config");
        fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;
        fs::create_dir_all(&registries)
            .with_context(|| format!("creating {}", registries.display()))?;
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("creating {}", config_dir.display()))?;

        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                source.to_str().expect("fixture path is UTF-8"),
            ],
        )?;
        git(&source, &["config", "user.name", "AOS Registry"])?;
        git(&source, &["config", "user.email", "registry@example.com"])?;
        git(&source, &["config", "commit.gpgsign", "false"])?;

        let signing = SigningFixture::new(tmp.path(), name)?;
        signing.configure_git(&source)?;

        Ok(Self {
            tmp,
            name: name.to_string(),
            source,
            origin,
            cache,
            registries,
            config_dir,
            signing,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source
    }

    pub fn origin_path(&self) -> &Path {
        &self.origin
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    pub fn registries_dir(&self) -> &Path {
        &self.registries
    }

    pub fn printer(&self) -> Printer {
        Printer::new(0, true, false)
    }

    pub fn trusted_key(&self) -> &str {
        &self.signing.trusted_key
    }

    #[allow(dead_code)]
    pub fn write_registry_toml(&self, cache_url: &str) -> Result<()> {
        self.write_registry_toml_with_caches(&[(cache_url, 50)])
    }

    pub fn write_registry_toml_with_caches(&self, caches: &[(&str, u32)]) -> Result<()> {
        let mut content = format!(
            r#"[registry]
name = "{}"
description = "Fixture registry"
"#,
            self.name
        );
        for (url, priority) in caches {
            content.push_str(&format!(
                r#"
[[caches]]
url = "{url}"
priority = {priority}
"#,
            ));
        }
        fs::write(self.source.join("registry.toml"), content).context("writing registry.toml")?;
        Ok(())
    }

    pub fn write_gitattributes(&self) -> Result<()> {
        fs::write(self.source.join(".gitattributes"), "* text eol=lf\n")
            .context("writing .gitattributes")?;
        Ok(())
    }

    pub fn write_keys_toml(&self) -> Result<()> {
        fs::write(
            self.source.join("keys.toml"),
            format!(
                r#"schema = 1

[[keys]]
id = "initial"
key = "{}"
"#,
                self.trusted_key(),
            ),
        )
        .context("writing keys.toml")?;
        Ok(())
    }

    pub fn write_package(&self, name: &str, version: &str) -> Result<String> {
        let hash = format!("{:0<32}", name);
        let dir = self.source.join("packages").join(&name[..1]);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let store_path = format!("/nix/store/{hash}-{name}-{version}");
        fs::write(
            dir.join(format!("{name}.toml")),
            package_toml(name, version, &store_path),
        )
        .with_context(|| format!("writing package {name}"))?;
        Ok(store_path)
    }

    pub fn write_closure(&self, store_path: &str) -> Result<()> {
        let hash = store_path
            .strip_prefix("/nix/store/")
            .and_then(|rest| rest.split_once('-'))
            .map(|(hash, _)| hash)
            .ok_or_else(|| anyhow::anyhow!("invalid store path {store_path}"))?;
        let dir = self.source.join("closures");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::write(dir.join(hash), format!("{hash}\n")).context("writing closure file")?;
        Ok(())
    }

    pub fn commit_all(&self, message: &str) -> Result<String> {
        git(&self.source, &["add", "."])?;
        git(&self.source, &["commit", "-m", message])?;
        git_stdout(&self.source, &["rev-parse", "HEAD"])
    }

    pub fn signed_tag(&self, name: &str, target: &str) -> Result<String> {
        git(
            &self.source,
            &["tag", "-s", name, target, "-m", &format!("release {name}")],
        )?;
        git_stdout(&self.source, &["rev-parse", &format!("{name}^{{tag}}")])
    }

    pub fn signed_channel_tag_bytes(&self, channel: &str, release_tag: &str) -> Result<Vec<u8>> {
        git(
            &self.source,
            &[
                "tag",
                "-f",
                "-s",
                channel,
                release_tag,
                "-m",
                &format!("{channel} -> {release_tag}"),
            ],
        )?;
        git_raw(&self.source, &["cat-file", "tag", channel])
    }

    pub fn set_branch(&self, branch: &str, target: &str) -> Result<()> {
        git(&self.source, &["branch", "-f", branch, target])
    }

    pub fn publish_bare_origin(&self) -> Result<()> {
        if !self.origin.exists() {
            git(
                self.tmp.path(),
                &[
                    "init",
                    "--bare",
                    "--object-format=sha256",
                    self.origin.to_str().expect("fixture path is UTF-8"),
                ],
            )?;
        }
        git(
            &self.source,
            &[
                "push",
                "--mirror",
                self.origin.to_str().expect("fixture path is UTF-8"),
            ],
        )?;
        objectstore::refresh_server_info(&self.origin)?;
        Ok(())
    }

    pub fn write_all_channel_partitions(&self, channel_name: &str, tag_bytes: &[u8]) -> Result<()> {
        for bucket in 0u8..=255 {
            self.write_channel_partition(channel_name, bucket, tag_bytes)?;
        }
        Ok(())
    }

    pub fn write_channel_partition(
        &self,
        channel_name: &str,
        bucket: u8,
        tag_bytes: &[u8],
    ) -> Result<()> {
        let path = self
            .origin
            .join(channel::partition_path(channel_name, bucket));
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("partition path has no parent"))?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        fs::write(&path, tag_bytes).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn registry_config(&self, url: String) -> RegistryConfig {
        RegistryConfig {
            name: self.name.clone(),
            url,
            priority: 500,
            enabled: true,
            commit: None,
            branch: Some("main".into()),
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            signing: None,
        }
    }

    #[allow(dead_code)]
    pub fn signed_registry_config(&self, url: String, channel: &str) -> RegistryConfig {
        RegistryConfig {
            name: self.name.clone(),
            url,
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: Some(channel.into()),
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            signing: Some(SigningConfig {
                required: true,
                public_key: self.trusted_key().to_string(),
            }),
        }
    }

    pub fn write_registry_config_file(&self, config: &RegistryConfig) -> Result<PathBuf> {
        let dir = self.config_dir.join("registries.d");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{}.toml", config.name));
        fs::write(&path, registry_config_toml(config))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    pub fn assert_state_roundtrip(&self, state: &RegistryState) -> Result<RegistryState> {
        let config = self.registry_config("http://fixture.invalid/".into());
        let path = self.write_registry_config_file(&config)?;
        aos_package::registry::state::save_state(&path, state)?;
        let loaded = aos_package::registry::state::load_state(&path)?
            .ok_or_else(|| anyhow::anyhow!("state did not round-trip"))?;
        Ok(loaded)
    }
}

pub struct StaticHttpServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl StaticHttpServer {
    pub async fn spawn(root: PathBuf) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("binding static fixture HTTP server")?;
        let addr = listener.local_addr().context("reading listener address")?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let root = root.clone();
                tokio::spawn(async move {
                    let _ = serve_one(stream, root).await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

impl Drop for StaticHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct SigningFixture {
    trusted_key: String,
    private_key: PathBuf,
    allowed_signers: PathBuf,
}

impl SigningFixture {
    fn new(root: &Path, registry: &str) -> Result<Self> {
        let signing_dir = root.join("signing");
        fs::create_dir_all(&signing_dir)
            .with_context(|| format!("creating {}", signing_dir.display()))?;

        let seed = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let raw_public_key = signing_key.verifying_key().to_bytes();
        let public_blob = ssh_ed25519_public_key_blob(&raw_public_key);
        let public_blob_b64 = base64::engine::general_purpose::STANDARD.encode(public_blob);
        let private_key = signing_dir.join("registry_ed25519");
        let allowed_signers = signing_dir.join("allowed_signers");

        fs::write(
            &private_key,
            openssh_ed25519_private_key(&seed, &raw_public_key, registry),
        )
        .with_context(|| format!("writing {}", private_key.display()))?;
        restrict_private_key_permissions(&private_key)?;
        fs::write(
            &allowed_signers,
            format!("registry ssh-ed25519 {public_blob_b64}\n"),
        )
        .with_context(|| format!("writing {}", allowed_signers.display()))?;

        Ok(Self {
            trusted_key: format!("{registry}:Ed25519:{public_blob_b64}"),
            private_key,
            allowed_signers,
        })
    }

    fn configure_git(&self, repo: &Path) -> Result<()> {
        git(repo, &["config", "gpg.format", "ssh"])?;
        git(
            repo,
            &[
                "config",
                "user.signingkey",
                self.private_key.to_str().expect("fixture path is UTF-8"),
            ],
        )?;
        git(
            repo,
            &[
                "config",
                "gpg.ssh.allowedSignersFile",
                self.allowed_signers
                    .to_str()
                    .expect("fixture path is UTF-8"),
            ],
        )?;
        Ok(())
    }
}

async fn serve_one(mut stream: TcpStream, root: PathBuf) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.context("reading request")?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let Some(line) = request.lines().next() else {
        return Ok(());
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    if method != "GET" && method != "HEAD" {
        write_response(&mut stream, 405, "Method Not Allowed", b"").await?;
        return Ok(());
    }

    let path = safe_path(&root, target)?;
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        write_response(&mut stream, 404, "Not Found", b"").await?;
        return Ok(());
    };
    if metadata.is_dir() {
        write_response(&mut stream, 403, "Forbidden", b"").await?;
        return Ok(());
    }

    let body = if method == "HEAD" {
        Vec::new()
    } else {
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("reading {}", path.display()))?
    };
    let length = if method == "HEAD" {
        metadata.len() as usize
    } else {
        body.len()
    };
    write_response_with_length(&mut stream, 200, "OK", length, &body).await?;
    Ok(())
}

fn safe_path(root: &Path, target: &str) -> Result<PathBuf> {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target);
    let mut out = root.to_path_buf();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." || component.contains('\\') {
            bail!("unsafe request path {target}");
        }
        out.push(component);
    }
    Ok(out)
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()> {
    write_response_with_length(stream, status, reason, body.len(), body).await
}

async fn write_response_with_length(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    length: usize,
    body: &[u8],
) -> Result<()> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .context("writing response headers")?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .context("writing response body")?;
    }
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

fn git_stdout(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output.stdout)
}

fn package_toml(name: &str, version: &str, store_path: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
description = "Fixture package {name}"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "{version}"

[versions.platforms.x86_64-linux]
store_path = "{store_path}"
nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
nar_size = 1
closure_size = 1
source_drv = "{store_path}.drv"
source_nar_hash = "sha256:1111111111111111111111111111111111111111111111111111"
references = []
"#,
    )
}

fn registry_config_toml(config: &RegistryConfig) -> String {
    let mut out = format!(
        r#"[registry]
name = "{}"
url = "{}"
priority = {}
enabled = {}
"#,
        config.name, config.url, config.priority, config.enabled
    );
    if let Some(branch) = &config.branch {
        out.push_str(&format!("branch = \"{branch}\"\n"));
    }
    if let Some(channel) = &config.channel {
        out.push_str(&format!("channel = \"{channel}\"\n"));
    }
    if let Some(signing) = &config.signing {
        out.push_str(&format!(
            r#"
[registry.signing]
required = {}
public_key = "{}"
"#,
            signing.required, signing.public_key
        ));
    }
    out
}

fn ssh_ed25519_public_key_blob(public_key: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    push_ssh_string(&mut blob, b"ssh-ed25519");
    push_ssh_string(&mut blob, public_key);
    blob
}

fn openssh_ed25519_private_key(seed: &[u8; 32], public_key: &[u8; 32], comment: &str) -> String {
    let public_blob = ssh_ed25519_public_key_blob(public_key);
    let mut private_key = Vec::new();
    private_key.extend_from_slice(seed);
    private_key.extend_from_slice(public_key);

    let mut private = Vec::new();
    push_u32(&mut private, 0x1234_5678);
    push_u32(&mut private, 0x1234_5678);
    push_ssh_string(&mut private, b"ssh-ed25519");
    push_ssh_string(&mut private, public_key);
    push_ssh_string(&mut private, &private_key);
    push_ssh_string(&mut private, comment.as_bytes());
    for pad in 1..=(8 - private.len() % 8) {
        if private.len() % 8 == 0 {
            break;
        }
        private.push(pad as u8);
    }

    let mut blob = b"openssh-key-v1\0".to_vec();
    push_ssh_string(&mut blob, b"none");
    push_ssh_string(&mut blob, b"none");
    push_ssh_string(&mut blob, b"");
    push_u32(&mut blob, 1);
    push_ssh_string(&mut blob, &public_blob);
    push_ssh_string(&mut blob, &private);

    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut out = "-----BEGIN OPENSSH PRIVATE KEY-----\n".to_string();
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is UTF-8"));
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
