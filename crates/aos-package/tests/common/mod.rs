#![allow(dead_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use aos_core::output::Printer;
use aos_package::registry::channel;
use aos_package::registry::objectstore;
use aos_package::types::{RegistryConfig, RegistryState, SigningConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

static SSH_KEYGEN: OnceLock<Option<PathBuf>> = OnceLock::new();

pub struct RegistryFixture {
    tmp: tempfile::TempDir,
    name: String,
    source: PathBuf,
    origin: PathBuf,
    cache: PathBuf,
    registries: PathBuf,
    config_dir: PathBuf,
    trusted: PathBuf,
    anchors: PathBuf,
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
        let trusted = tmp.path().join("trusted-keys.d");
        let anchors = tmp.path().join("anchors.d");
        fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;
        fs::create_dir_all(&registries)
            .with_context(|| format!("creating {}", registries.display()))?;
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("creating {}", config_dir.display()))?;
        fs::create_dir_all(&trusted).with_context(|| format!("creating {}", trusted.display()))?;
        fs::create_dir_all(&anchors).with_context(|| format!("creating {}", anchors.display()))?;

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
        // Sign fixture commits with the fixture maintainer key so syncs
        // under the fail-closed default verify end to end.
        git(&source, &["config", "commit.gpgsign", "true"])?;

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
            trusted,
            anchors,
            signing,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source
    }

    pub fn name(&self) -> &str {
        &self.name
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

    /// Trusted-key directories for sync: a writable store first, then a
    /// read-only anchor directory (mirroring /etc/apm/trusted-keys.d).
    pub fn trusted_keys_dirs(&self) -> Vec<PathBuf> {
        vec![self.trusted.clone(), self.anchors.clone()]
    }

    /// The writable trusted-key file where sync pins roster keys.
    pub fn pinned_keys_path(&self) -> PathBuf {
        self.trusted.join(format!("{}.pub", self.name))
    }

    /// Write a read-only anchor file (image-baked trust anchor stand-in).
    pub fn write_anchor_keys(&self, lines: &[&str]) -> Result<()> {
        let path = self.anchors.join(format!("{}.pub", self.name));
        let mut content = lines.join("\n");
        content.push('\n');
        fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn printer(&self) -> Printer {
        Printer::new(0, true, false)
    }

    pub fn trusted_key(&self) -> &str {
        &self.signing.trusted_key
    }

    pub fn private_key_path(&self) -> &Path {
        &self.signing.private_key
    }

    #[allow(dead_code)]
    pub fn write_registry_toml(&self, cache_url: &str) -> Result<()> {
        self.write_registry_toml_with_caches(&[(cache_url, 50)])
    }

    pub fn write_registry_toml_with_caches(&self, caches: &[(&str, u32)]) -> Result<()> {
        let mut caches = caches.to_vec();
        caches.sort_by(|left, right| right.1.cmp(&left.1));
        let mut content = format!(
            r#"[registry]
name = "{}"
description = "Fixture registry"
"#,
            self.name
        );
        if let Some((url, _)) = caches.first() {
            if caches.len() == 1 {
                content.push_str(&format!("\n[caches]\nendpoint = \"{url}\"\n"));
            } else {
                content.push_str("\n[caches]\nkind = \"try\"\nmembers = [\n");
                for (url, _) in &caches {
                    content.push_str(&format!("  {{ endpoint = \"{url}\" }},\n"));
                }
                content.push_str("]\n");
            }
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
        let hash = nixbase32_store_hash(name);
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

    /// Write a `store/<shard>/<hash>` realisation record for the path: a
    /// leaf IA-only record carrying one blessed NAR (RFC-0005). Named
    /// `write_closure` for historical call-site compatibility.
    pub fn write_closure(&self, store_path: &str) -> Result<()> {
        let hash = store_path
            .strip_prefix("/nix/store/")
            .and_then(|rest| rest.split_once('-'))
            .map(|(hash, _)| hash)
            .ok_or_else(|| anyhow::anyhow!("invalid store path {store_path}"))?;
        let dir = self.source.join("store").join(&hash[..2]);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // A valid 52-char nixbase32 SHA-256 plus a size; no dependency edges.
        fs::write(
            dir.join(hash),
            "nar:sha256:1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy:1\n",
        )
        .context("writing store record")?;
        Ok(())
    }

    pub fn commit_all(&self, message: &str) -> Result<String> {
        git(&self.source, &["add", "."])?;
        git(&self.source, &["commit", "-m", message])?;
        git_stdout(&self.source, &["rev-parse", "HEAD"])
    }

    /// Commit all changes signed with a specific private key (instead of
    /// the fixture's default maintainer key).
    pub fn commit_all_with_key(&self, message: &str, key_path: &Path) -> Result<String> {
        git(&self.source, &["add", "."])?;
        let signing_key = format!("user.signingkey={}", key_path.display());
        git(&self.source, &["-c", &signing_key, "commit", "-m", message])?;
        git_stdout(&self.source, &["rev-parse", "HEAD"])
    }

    /// Create a signed tag with a specific private key.
    pub fn signed_tag_with_key(&self, name: &str, target: &str, key_path: &Path) -> Result<String> {
        let signing_key = format!("user.signingkey={}", key_path.display());
        git(
            &self.source,
            &[
                "-c",
                &signing_key,
                "tag",
                "-s",
                name,
                target,
                "-m",
                &format!("release {name}"),
            ],
        )?;
        git_stdout(&self.source, &["rev-parse", &format!("{name}^{{tag}}")])
    }

    /// Generate an additional maintainer keypair, returning its trust-key
    /// line and private key path.
    pub fn make_keypair(&self, seed: [u8; 32], name: &str) -> Result<(String, PathBuf)> {
        let keypair = aos_package::sshkey::Ed25519Keypair::from_seed(seed);
        let dir = self.tmp.path().join("signing");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(name);
        fs::write(&path, keypair.to_openssh_private_key(name))
            .with_context(|| format!("writing {}", path.display()))?;
        restrict_key_permissions(&path)?;
        Ok((keypair.trust_key_line(&self.name), path))
    }

    /// Write a committed `keys.toml` with an arbitrary roster.
    pub fn write_keys_toml_with(&self, active: &[(&str, &str)], revoked: &[&str]) -> Result<()> {
        let mut content = String::from("schema = 1\n");
        for (id, key) in active {
            content.push_str(&format!("\n[[keys]]\nid = \"{id}\"\nkey = \"{key}\"\n"));
        }
        for id in revoked {
            content.push_str(&format!("\n[[revoked]]\nid = \"{id}\"\n"));
        }
        fs::write(self.source.join("keys.toml"), content).context("writing keys.toml")?;
        Ok(())
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

    /// Hard-reset the checked-out branch to `target` (force-push fixture).
    pub fn reset_hard(&self, target: &str) -> Result<()> {
        git(&self.source, &["reset", "--hard", target])
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
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            // Unverified legacy sync: opting out requires an explicit
            // required = false under the fail-closed default.
            signing: Some(SigningConfig {
                required: false,
                public_key: None,
                root_owner_signers: Vec::new(),
            }),
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
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: Some(SigningConfig {
                required: true,
                public_key: Some(self.trusted_key().to_string()),
                root_owner_signers: Vec::new(),
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

fn restrict_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
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
        let keypair = aos_package::sshkey::Ed25519Keypair::from_seed(seed);
        let public_blob_b64 = keypair.public_key_base64();
        let private_key = signing_dir.join("registry_ed25519");
        let allowed_signers = signing_dir.join("allowed_signers");

        fs::write(&private_key, keypair.to_openssh_private_key(registry))
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

/// Build a git command insulated from the host's global and system git
/// configuration.
///
/// Fixture repositories configure everything they need repo-locally
/// (identity, signing keys, allowed signers); a host `~/.gitconfig` that
/// enables e.g. `commit.gpgsign` with a GPG key must not leak into them.
fn git_command(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    add_ssh_program_config(&mut cmd);
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    cmd
}

fn add_ssh_program_config(command: &mut Command) {
    if let Some(path) = ssh_keygen_path() {
        command
            .arg("-c")
            .arg(format!("gpg.ssh.program={}", path.display()));
    }
}

fn ssh_keygen_path() -> Option<&'static Path> {
    SSH_KEYGEN.get_or_init(find_working_ssh_keygen).as_deref()
}

fn find_working_ssh_keygen() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("AOS_GIT_SSH_PROGRAM") {
        candidates.push(PathBuf::from(path));
    }
    for env_var in ["AOS_HOST_PATH", "PATH"] {
        let Some(path) = std::env::var_os(env_var) else {
            continue;
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("ssh-keygen");
            if !candidates.iter().any(|seen| seen == &candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file() && ssh_keygen_can_sign(candidate))
}

fn ssh_keygen_can_sign(candidate: &Path) -> bool {
    let Ok(tmp) = tempfile::TempDir::new() else {
        return false;
    };
    let key = tmp.path().join("key");
    let Ok(keygen) = Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "aos-registry", "-f"])
        .arg(&key)
        .output()
    else {
        return false;
    };
    if !keygen.status.success() {
        return false;
    }

    let payload = tmp.path().join("payload");
    if fs::write(&payload, b"aos-registry").is_err() {
        return false;
    }

    Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(&key)
        .arg("-n")
        .arg("git")
        .arg(&payload)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let output = git_command(dir)
        .args(args)
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
    let output = git_command(dir)
        .args(args)
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
    let output = git_command(dir)
        .args(args)
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

/// Nix's base32 alphabet, which omits `e`, `o`, `t`, and `u`.
const NIX_BASE32_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// Derive a valid 32-character nixbase32 store-path hash from a package name.
///
/// Real Nix store paths are named `<32-char-nixbase32>-<name>-<version>`, and
/// the registry's `store/` validation enforces that the hash is nixbase32. A
/// readable placeholder like `hello` cannot be used verbatim (`e`/`o`/`t`/`u`
/// fall outside the alphabet), so each character is folded into the alphabet
/// — in-alphabet characters are kept for readability — and the result is
/// right-padded to 32 characters. The mapping is deterministic, so a given
/// name always yields the same hash.
fn nixbase32_store_hash(name: &str) -> String {
    let mut hash: String = name
        .chars()
        .map(|ch| {
            if NIX_BASE32_ALPHABET.contains(ch) {
                ch
            } else {
                // Fold any out-of-alphabet character (including `e`/`o`/`t`/`u`)
                // deterministically into the 32-character alphabet.
                NIX_BASE32_ALPHABET
                    .as_bytes()
                    .get((ch as usize) % 32)
                    .copied()
                    .map(char::from)
                    .unwrap_or('0')
            }
        })
        .take(32)
        .collect();
    while hash.len() < 32 {
        hash.push('0');
    }
    hash
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
    if !config.signing_keys.is_empty() {
        out.push_str("\n[registry.signing_keys]\n");
        for (id, source) in &config.signing_keys {
            let value = match (source.path(), source.command()) {
                (Some(path), _) => format!("\"{path}\""),
                (_, Some(command)) => format!("{{ command = \"{command}\" }}"),
                _ => "\"\"".to_string(),
            };
            out.push_str(&format!("\"{id}\" = {value}\n"));
        }
    }
    if let Some(signing) = &config.signing {
        out.push_str(&format!(
            "\n[registry.signing]\nrequired = {}\n",
            signing.required
        ));
        if let Some(public_key) = &signing.public_key {
            out.push_str(&format!("public_key = \"{public_key}\"\n"));
        }
    }
    out
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
