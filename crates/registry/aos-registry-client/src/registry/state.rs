//! Registry state persistence.
//!
//! `apm update` records each registry's last-synced commit and channel rollout
//! state in a `[registry.state]` table. Under the seed/state split this is
//! written to the **writable** config layer (`/var/lib/apm/config` for system
//! scope), never to the read-only `/etc/apm` seed — so for a *seeded* registry
//! the on-disk file is a minimal `[registry.state]`-only overlay whose
//! `url`/signing keep inheriting from the seed (see [`crate::config`]).
//!
//! Because the writable-layer file is apm-owned, [`save_state`] rewrites it by
//! a structured round-trip: parse, replace `registry.state`, re-serialize. The
//! producer-side `[registry.signing_keys]` / `[registry.upload_auth]` helpers
//! ([`upsert_signing_key`], [`save_upload_auth`]) still edit a single section
//! textually, leaving the rest of an operator's `apr` config untouched.
//!
//! A fully populated state section looks like:
//!
//! ```toml
//! [registry.state]
//! last_commit = "abc123def456"
//! selected_channel = "stable"
//! default_channel = "stable"
//! floor = "1.4.2"
//! bucket = 183
//! retained = ["1.0.0", "1.4.0", "1.4.2"]
//! last_update = "2026-02-13T10:30:00Z"
//! ```

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::types::{RegistryFile, RegistryState, RegistryUploadAuthConfig, SigningKeySource};

/// An exclusive transaction lock for one registry's consumer state.
///
/// Package refresh and image discovery acquire this lock before reading any
/// trust state and hold it through verified catalog publication and durable
/// state replacement. Callers that also acquire a cache-local lock must take
/// this registry lock first. A transaction never holds locks for two
/// registries, so independent registries remain concurrent.
#[derive(Debug)]
pub struct RegistryStateLock {
    _file: File,
}

impl RegistryStateLock {
    /// Acquires the transaction lock associated with `state_path`.
    ///
    /// Lock acquisition runs on Tokio's blocking pool because another process
    /// may be completing a registry transaction. The stable lock file remains
    /// beside the state file after use; removing it could split concurrent
    /// callers across different inodes.
    ///
    /// # Errors
    ///
    /// Returns an error if the state directory or lock file cannot be opened,
    /// the blocking task cannot be joined, or the operating system rejects the
    /// exclusive lock.
    pub async fn acquire(state_path: &Path) -> Result<Self> {
        let lock_path = transaction_lock_path(state_path);

        tokio::task::spawn_blocking(move || acquire_lock(&lock_path))
            .await
            .context("joining registry state lock task")?
    }
}

fn transaction_lock_path(state_path: &Path) -> PathBuf {
    let mut file_name = state_path
        .file_name()
        .map_or_else(|| OsString::from("registry-state"), OsString::from);
    file_name.push(".lock");

    state_path.with_file_name(file_name)
}

fn acquire_lock(lock_path: &Path) -> Result<RegistryStateLock> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .with_context(|| format!("locking {}", lock_path.display()))?;

    Ok(RegistryStateLock { _file: file })
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load state from a registry config file's `[registry.state]` section.
///
/// Returns `Ok(None)` if the file has no state section or does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or is not valid
/// registry TOML.
pub fn load_state(path: &Path) -> Result<Option<RegistryState>> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    Ok(rf.registry.state)
}

/// Save or update the `[registry.state]` table in a registry config file.
///
/// The writable-layer file is apm-owned, so it is rewritten by a structured
/// round-trip: the file is parsed, its `registry.state` sub-table is replaced,
/// and the whole value is re-serialized. Unset state fields are omitted (an
/// empty `retained` renders as `[]`).
///
/// When `path` does not exist, its parent is created and a minimal
/// `[registry.state]`-only overlay is written — for a seeded registry the
/// `url`/signing keep inheriting from the lower `/etc` seed layer.
///
/// # Errors
///
/// Returns an error when an existing file cannot be read or parsed, when the
/// parent directory cannot be created, or when the atomic replacement cannot
/// be written and synchronized.
pub fn save_state(path: &Path, state: &RegistryState) -> Result<()> {
    let mut root: toml::Value = if path.exists() {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        toml::Value::Table(toml::map::Map::new())
    };

    let table = root
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: top level is not a TOML table", path.display()))?;
    let registry = table
        .entry("registry".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: [registry] is not a TOML table", path.display()))?;
    registry.insert("state".to_string(), toml::Value::try_from(state)?);

    let rendered = toml::to_string_pretty(&root)?;
    let temporary = prepare_state_replacement(path, rendered.as_bytes())?;
    persist_state_replacement(path, temporary)
}

fn prepare_state_replacement(path: &Path, contents: &[u8]) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary state in {}", parent.display()))?;
    temporary
        .write_all(contents)
        .with_context(|| format!("writing temporary state for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("synchronizing temporary state for {}", path.display()))?;

    Ok(temporary)
}

fn persist_state_replacement(path: &Path, temporary: tempfile::NamedTempFile) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    temporary
        .persist(path)
        .with_context(|| format!("replacing {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("synchronizing {}", parent.display()))?;

    Ok(())
}

/// Record a signing-key source in the `[registry.signing_keys]` section.
///
/// Reads the existing map, inserts or replaces the entry for `id`, and
/// rewrites only that section, preserving every other user-edited field
/// (mirroring [`save_state`]). Path sources render as a bare string; command
/// sources render as an inline `{ command = "..." }` table.
///
/// # Errors
///
/// Returns an error when the config file does not exist, cannot be
/// parsed, or cannot be rewritten.
pub fn upsert_signing_key(path: &Path, id: &str, source: &SigningKeySource) -> Result<()> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut signing_keys = rf.registry.signing_keys;
    signing_keys.insert(id.to_string(), source.clone());

    let mut section = String::from("\n[registry.signing_keys]\n");
    for (entry_id, entry_source) in &signing_keys {
        section.push_str(&format!(
            "\"{}\" = {}\n",
            escape_toml_string(entry_id),
            render_signing_key_source(entry_source),
        ));
    }

    let new_content = if let Some(start) = find_section(&content, "[registry.signing_keys]") {
        let after_header = start + "[registry.signing_keys]".len();
        let end = content[after_header..]
            .find("\n[")
            .map(|pos| after_header + pos)
            .unwrap_or(content.len());
        let before = content[..start].trim_end_matches('\n');
        let after = &content[end..];
        format!("{before}{section}{after}")
    } else {
        let trimmed = content.trim_end_matches('\n');
        format!("{trimmed}{section}")
    };

    std::fs::write(path, &new_content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Save/update the `[registry.upload_auth]` section in a registry config
/// file.
///
/// Renders the given producer upload defaults as a fresh section and
/// replaces the existing one in place (or appends one), preserving every
/// other user-edited field (mirroring [`upsert_signing_key`]). Unset fields
/// are omitted from the rendered section, and a fully default `upload`
/// value removes the section entirely, so unsetting the last stored field
/// leaves no empty section behind.
///
/// # Errors
///
/// Returns an error when the config file does not exist, cannot be read, or
/// cannot be rewritten.
pub fn save_upload_auth(path: &Path, upload: &RegistryUploadAuthConfig) -> Result<()> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let header = "[registry.upload_auth]";
    let section = render_upload_auth_section(upload);
    let new_content = match (find_section(&content, header), section) {
        (Some(start), section) => {
            let after_header = start + header.len();
            let end = content[after_header..]
                .find("\n[")
                .map(|pos| after_header + pos)
                .unwrap_or(content.len());
            let before = content[..start].trim_end_matches('\n');
            let after = &content[end..];
            match section {
                Some(section) => format!("{before}{section}{after}"),
                None => format!("{before}\n{after}"),
            }
        }
        (None, Some(section)) => {
            let trimmed = content.trim_end_matches('\n');
            format!("{trimmed}{section}")
        }
        // Nothing stored and nothing to store — leave the file untouched.
        (None, None) => return Ok(()),
    };

    std::fs::write(path, &new_content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Render a [`RegistryUploadAuthConfig`] as a `[registry.upload_auth]`
/// section, with unset fields omitted.
///
/// Returns `None` for a fully default value, signalling the caller to drop
/// the section instead of writing an empty one.
fn render_upload_auth_section(upload: &RegistryUploadAuthConfig) -> Option<String> {
    if *upload == RegistryUploadAuthConfig::default() {
        return None;
    }

    let mut section = String::from("\n[registry.upload_auth]\n");
    if !upload.upload_urls.is_empty() {
        section.push_str(&format!(
            "upload_urls = {}\n",
            render_string_array(&upload.upload_urls),
        ));
    }
    let scalar_fields = [
        ("token", &upload.token),
        ("view", &upload.view),
        ("http_user", &upload.http_user),
        ("http_password", &upload.http_password),
    ];
    for (name, value) in scalar_fields {
        if let Some(value) = value {
            section.push_str(&format!("{name} = \"{}\"\n", escape_toml_string(value)));
        }
    }
    if !upload.headers.is_empty() {
        section.push_str(&format!(
            "headers = {}\n",
            render_string_array(&upload.headers),
        ));
    }
    let scalar_fields = [
        ("s3_region", &upload.s3_region),
        ("s3_profile", &upload.s3_profile),
        ("s3_endpoint", &upload.s3_endpoint),
        ("ssh_key", &upload.ssh_key),
        ("ssh_password", &upload.ssh_password),
    ];
    for (name, value) in scalar_fields {
        if let Some(value) = value {
            section.push_str(&format!("{name} = \"{}\"\n", escape_toml_string(value)));
        }
    }
    if upload.ssh_ask_pass {
        section.push_str("ssh_ask_pass = true\n");
    }
    Some(section)
}

/// Render a list of strings as a single-line TOML string array.
fn render_string_array(values: &[String]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape_toml_string(value)))
        .collect();
    format!("[{}]", items.join(", "))
}

/// Render a [`SigningKeySource`] as the right-hand side of a TOML key entry.
///
/// A path source becomes a quoted string; a command source becomes an inline
/// `{ command = "..." }` table. A degenerate entry that somehow carries both
/// (or neither) is rendered losslessly so a hand-edited file round-trips.
fn render_signing_key_source(source: &SigningKeySource) -> String {
    match (source.path(), source.command()) {
        (Some(path), None) => format!("\"{}\"", escape_toml_string(path)),
        (None, Some(command)) => {
            format!("{{ command = \"{}\" }}", escape_toml_string(command))
        }
        (Some(path), Some(command)) => format!(
            "{{ path = \"{}\", command = \"{}\" }}",
            escape_toml_string(path),
            escape_toml_string(command),
        ),
        (None, None) => "\"\"".to_string(),
    }
}

/// Escape backslashes and double quotes for a basic TOML string literal.
fn escape_toml_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Find the byte offset of a `[section]` header at the start of a line.
fn find_section(content: &str, header: &str) -> Option<usize> {
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == header {
            // Calculate byte offset: sum of previous lines + newlines.
            let offset: usize = content
                .lines()
                .take(i)
                .map(|l| l.len() + 1) // +1 for newline
                .sum();
            return Some(offset);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::{Barrier, oneshot};
    use tokio::time::{Duration, timeout};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registry_transactions_reload_state_after_waiting_for_the_lock() {
        let tmp = TempDir::new().unwrap();
        let path = Arc::new(tmp.path().join("aos-core.toml"));
        save_state(
            &path,
            &RegistryState {
                last_commit: Some("c0".into()),
                ..RegistryState::default()
            },
        )
        .unwrap();

        let first_holds_lock = Arc::new(Barrier::new(2));
        let release_first = Arc::new(Barrier::new(2));
        let first_path = Arc::clone(&path);
        let first_holds_lock_worker = Arc::clone(&first_holds_lock);
        let release_first_worker = Arc::clone(&release_first);
        let first = tokio::spawn(async move {
            let _transaction = RegistryStateLock::acquire(&first_path).await.unwrap();
            let observed = load_state(&first_path).unwrap().unwrap();
            assert_eq!(observed.last_commit.as_deref(), Some("c0"));
            first_holds_lock_worker.wait().await;
            release_first_worker.wait().await;

            save_state(
                &first_path,
                &RegistryState {
                    last_commit: Some("c1".into()),
                    ..observed
                },
            )
            .unwrap();
        });
        first_holds_lock.wait().await;

        let (second_started_tx, second_started_rx) = oneshot::channel();
        let (second_acquired_tx, mut second_acquired_rx) = oneshot::channel();
        let second_path = Arc::clone(&path);
        let second = tokio::spawn(async move {
            second_started_tx.send(()).unwrap();
            let _transaction = RegistryStateLock::acquire(&second_path).await.unwrap();
            second_acquired_tx.send(()).unwrap();
            let observed = load_state(&second_path).unwrap().unwrap();
            assert_eq!(observed.last_commit.as_deref(), Some("c1"));

            save_state(
                &second_path,
                &RegistryState {
                    last_commit: Some("c2".into()),
                    ..observed
                },
            )
            .unwrap();
        });
        second_started_rx.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), &mut second_acquired_rx)
                .await
                .is_err(),
            "the second registry transaction acquired a held lock"
        );

        release_first.wait().await;
        first.await.unwrap();
        second_acquired_rx.await.unwrap();
        second.await.unwrap();

        let final_state = load_state(&path).unwrap().unwrap();
        assert_eq!(final_state.last_commit.as_deref(), Some("c2"));

        let _replay = RegistryStateLock::acquire(&path).await.unwrap();
        let replay_base = load_state(&path).unwrap().unwrap();
        assert_ne!(
            replay_base.last_commit.as_deref(),
            Some("c0"),
            "a delayed c1 worker must observe c2 and reject its stale base"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn independent_registry_transactions_do_not_block_each_other() {
        let tmp = TempDir::new().unwrap();
        let first_path = tmp.path().join("first.toml");
        let second_path = tmp.path().join("second.toml");
        let _first = RegistryStateLock::acquire(&first_path).await.unwrap();

        timeout(
            Duration::from_secs(1),
            RegistryStateLock::acquire(&second_path),
        )
        .await
        .expect("independent registry lock timed out")
        .unwrap();
    }

    #[test]
    fn interrupted_atomic_replacement_preserves_the_published_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(&path, "published state\n").unwrap();

        let pending = prepare_state_replacement(&path, b"pending state\n").unwrap();
        drop(pending);

        assert_eq!(fs::read_to_string(path).unwrap(), "published state\n");
    }

    #[test]
    fn load_state_from_registry_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"

[registry.state]
last_commit = "abc123def456"
floor = "1.4.2"
bucket = 183
retained = ["1.0.0", "1.4.0", "1.4.2"]
last_update = "2026-02-13T10:30:00Z"
"#,
        )
        .unwrap();

        let state = load_state(&path).unwrap().unwrap();
        assert_eq!(state.last_commit.unwrap(), "abc123def456");
        assert_eq!(state.floor.unwrap(), "1.4.2");
        assert_eq!(state.bucket.unwrap(), 183);
        assert_eq!(state.retained, vec!["1.0.0", "1.4.0", "1.4.2"]);
        assert_eq!(state.last_update.unwrap(), "2026-02-13T10:30:00Z");
    }

    #[test]
    fn load_state_returns_none_when_no_state_section() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
"#,
        )
        .unwrap();

        let state = load_state(&path).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn load_state_returns_none_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let state = load_state(&path).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn save_state_updates_file_preserving_definition() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("deadbeef".into()),
            last_roster_commit: Some("feedface".into()),
            floor: Some("1.4.2".into()),
            bucket: Some(183),
            retained: vec!["1.0.0".into(), "1.4.0".into(), "1.4.2".into()],
            last_update: Some("2026-02-16T12:00:00Z".into()),
            ..RegistryState::default()
        };
        save_state(&path, &state).unwrap();

        // State round-trips through load_state.
        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.as_deref(), Some("deadbeef"));
        assert_eq!(loaded.last_roster_commit.as_deref(), Some("feedface"));
        assert_eq!(loaded.floor.as_deref(), Some("1.4.2"));
        assert_eq!(loaded.bucket, Some(183));
        assert_eq!(loaded.retained, vec!["1.0.0", "1.4.0", "1.4.2"]);

        // The existing definition (url, signing) is preserved.
        let content = fs::read_to_string(&path).unwrap();
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(
            rf.registry.url.as_deref(),
            Some("https://registry.aos.dev/core")
        );
        assert!(rf.registry.signing.is_some());
    }

    #[test]
    fn save_state_replaces_existing_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.state]
last_commit = "old_commit"
last_update = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("new_commit".into()),
            last_roster_commit: Some("new_roster_commit".into()),
            floor: Some("1.4.2".into()),
            bucket: Some(183),
            retained: vec!["1.4.2".into()],
            last_update: Some("2026-02-16T12:00:00Z".into()),
            ..RegistryState::default()
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("old_commit"));

        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.as_deref(), Some("new_commit"));
        assert_eq!(
            loaded.last_roster_commit.as_deref(),
            Some("new_roster_commit")
        );
        assert_eq!(loaded.floor.as_deref(), Some("1.4.2"));
        assert_eq!(loaded.bucket, Some(183));
        assert_eq!(loaded.retained, vec!["1.4.2"]);

        // The definition is preserved across the rewrite.
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(
            rf.registry.url.as_deref(),
            Some("https://registry.aos.dev/core")
        );
    }

    #[test]
    fn save_state_creates_minimal_overlay_when_absent() {
        let tmp = TempDir::new().unwrap();
        // A nested path that does not exist yet — parents are created and a
        // pure `[registry.state]` overlay (no url/name) is written, as for a
        // seeded registry's first sync.
        let path = tmp.path().join("config/registries.d/aos-core.toml");

        let state = RegistryState {
            last_commit: Some("deadbeef".into()),
            floor: Some("1.4.2".into()),
            ..RegistryState::default()
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert!(rf.registry.url.is_none());
        assert!(rf.registry.name.is_none());
        let loaded = rf.registry.state.unwrap();
        assert_eq!(loaded.last_commit.as_deref(), Some("deadbeef"));
        assert_eq!(loaded.floor.as_deref(), Some("1.4.2"));
    }

    #[test]
    fn upsert_signing_key_round_trips_path_and_command_sources() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing_keys]
alice = "/run/secrets/alice"
"#,
        )
        .unwrap();

        // Add a command source alongside the existing path source.
        upsert_signing_key(
            &path,
            "bob",
            &SigningKeySource::Spec(crate::types::SigningKeySpec {
                path: None,
                command: Some("pass show apm/bob".to_string()),
            }),
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"bob\" = { command = \"pass show apm/bob\" }"));
        // The user-edited [registry] header is preserved.
        assert!(content.contains("name = \"aos-core\""));

        // Both forms parse back through the untagged enum.
        let rf: crate::types::RegistryFile = toml::from_str(&content).unwrap();
        let keys = &rf.registry.signing_keys;
        assert_eq!(
            keys.get("alice").and_then(|s| s.path()),
            Some("/run/secrets/alice")
        );
        assert_eq!(keys.get("alice").and_then(|s| s.command()), None);
        assert_eq!(
            keys.get("bob").and_then(|s| s.command()),
            Some("pass show apm/bob")
        );
        assert_eq!(keys.get("bob").and_then(|s| s.path()), None);
    }

    #[test]
    fn save_state_preserves_other_sections() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.toml");
        fs::write(
            &path,
            r#"[registry]
name = "test"
url = "https://example.com"

[registry.state]
last_commit = "old"

[registry.signing]
required = false
public_key = "test:Ed25519:abc"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("new".into()),
            last_update: None,
            ..RegistryState::default()
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(
            rf.registry.state.unwrap().last_commit.as_deref(),
            Some("new")
        );
        // The signing section is preserved across the rewrite.
        let signing = rf.registry.signing.unwrap();
        assert!(!signing.required);
        assert_eq!(signing.public_key.as_deref(), Some("test:Ed25519:abc"));
    }

    #[test]
    fn save_upload_auth_round_trips_and_preserves_other_sections() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing_keys]
alice = "/run/secrets/alice"

[registry.state]
last_commit = "abc123"
"#,
        )
        .unwrap();

        let upload = RegistryUploadAuthConfig {
            upload_urls: vec!["s3://bucket/".to_string(), "file:///mirror".to_string()],
            s3_endpoint: Some("https://s3.example".to_string()),
            ssh_ask_pass: true,
            ..RegistryUploadAuthConfig::default()
        };
        save_upload_auth(&path, &upload).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        // The section lands between the existing user-owned sections,
        // which are preserved byte for byte.
        assert!(content.contains("name = \"aos-core\""), "{content}");
        assert!(
            content.contains("alice = \"/run/secrets/alice\""),
            "{content}"
        );
        assert!(content.contains("last_commit = \"abc123\""), "{content}");

        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(rf.registry.upload_auth.unwrap(), upload);
    }

    #[test]
    fn save_upload_auth_replaces_existing_section_in_place() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.upload_auth]
upload_urls = ["s3://old/"]
token = "old-token"

[registry.state]
last_commit = "abc123"
"#,
        )
        .unwrap();

        let upload = RegistryUploadAuthConfig {
            upload_urls: vec!["s3://new/".to_string()],
            ..RegistryUploadAuthConfig::default()
        };
        save_upload_auth(&path, &upload).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("s3://old/"), "{content}");
        assert!(!content.contains("old-token"), "{content}");
        assert!(content.contains("last_commit = \"abc123\""), "{content}");
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(rf.registry.upload_auth.unwrap(), upload);
    }

    #[test]
    fn save_upload_auth_removes_section_when_fully_default() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.upload_auth]
upload_urls = ["s3://bucket/"]

[registry.state]
last_commit = "abc123"
"#,
        )
        .unwrap();

        save_upload_auth(&path, &RegistryUploadAuthConfig::default()).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("[registry.upload_auth]"), "{content}");
        assert!(content.contains("last_commit = \"abc123\""), "{content}");
        let rf: RegistryFile = toml::from_str(&content).unwrap();
        assert!(rf.registry.upload_auth.is_none());
    }
}
