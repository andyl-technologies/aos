//! In-browser channel verification — the honest badge.
//!
//! RFC-0004's web surface promises a verification badge that runs *real*
//! Ed25519 verification in the visitor's browser, against the registry's
//! committed roster, rendering "verified in your browser: partition →
//! 1.4.2 → commit ab12…". This module is that verifier. It reuses the exact
//! reader the hub indexer and `apm` run — [`aos_registry_surface`] — so
//! there is one parser across server, Worker, and browser, and the badge
//! cannot quietly disagree with what a real client would accept.
//!
//! The flow, all same-origin (zero CORS):
//!
//! ```text
//! HEAD                      -> default branch name
//! info/refs                 -> commit + tag oids
//! channels/<chan>/<bucket>  -> signed partition payload (raw tag)
//! objects/<head-commit>     -> commit object  -> tree oid
//! walk tree                 -> keys.toml blob -> trust roster
//! verify_signed_tag(partition, roster)  (Ed25519, client-side)
//! ```
//!
//! The pure outcome type [`BadgeOutcome`] and the roster extraction
//! [`roster_keys`] are unit-tested natively; the async walk
//! [`verify_channel`] is generic over a [`SurfaceFetch`] so it is exercised
//! against an in-memory surface fixture without a browser.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use aos_registry_surface::object::{self, ObjectKind, Oid};
use aos_registry_surface::refs::{parse_head, parse_info_refs};
use aos_registry_surface::tag::verify_signed_tag;

/// The bucket a channel's partition object is served under.
///
/// Channel partitions live at `channels/<channel>/<bucket>`; the floor
/// surface publishes a single `current` partition per channel.
pub const DEFAULT_PARTITION_BUCKET: &str = "current";

/// Async, same-origin byte reader for the registry surface.
///
/// In the browser this is a `fetch()` GET relative to the document origin;
/// in tests it is an in-memory map. A `None` result means a clean 404 (the
/// path is absent), distinguished from a transport error.
pub trait SurfaceFetch {
    /// Fetch one surface path's bytes, or `None` if it 404s.
    ///
    /// # Errors
    ///
    /// Returns an error on a transport failure (network error, a 5xx, a
    /// body that cannot be read) — never for a clean 404, which is `None`.
    #[allow(async_fn_in_trait)]
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>>;
}

/// The result of running the in-browser verifier for one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadgeOutcome {
    /// The partition verified against the committed roster.
    Verified(VerifiedBadge),
    /// Verification ran but the partition was rejected (bad signature,
    /// untrusted key, name-binding replay, malformed payload).
    Failed {
        /// Human-readable reason, suitable for the badge subtitle.
        reason: String,
    },
}

/// The data a successful verification renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBadge {
    /// The channel that was verified (e.g. `stable`).
    pub channel: String,
    /// The tag-object id the channel partition points at (the release tag),
    /// in full hex.
    pub release_tag_oid: String,
}

impl VerifiedBadge {
    /// The short (12-hex) form of the release-tag oid for compact display.
    pub fn short_release(&self) -> String {
        self.release_tag_oid.chars().take(12).collect::<String>()
    }
}

/// Extract the trusted key set from a committed `keys.toml`.
///
/// Returns each *active* key's `registry:Ed25519:<base64>` line, dropping
/// any active key whose `id` also appears under `[[revoked]]`. This mirrors
/// the roster semantics `aos_package::registry::keys` enforces: the trust
/// anchor is the active set minus revocations. A deliberately tiny scanner
/// (the SPA ships no TOML parser) — it reads `[[keys]]` / `[[revoked]]`
/// tables and their `id` / `key` string values, ignoring everything else.
///
/// The active table is spelled `[[keys]]` to match the on-disk format the
/// server writes and reads: `aos_package::registry::keys::KeysToml` declares
/// its active vector as `#[serde(rename = "keys")]`, so a real committed
/// `keys.toml` lists active keys under `[[keys]]`, never `[[active]]`.
///
/// # Errors
///
/// Returns an error when `keys_toml` is not UTF-8-decodable text the
/// scanner can walk; malformed-but-decodable input yields an empty or
/// partial key set rather than an error, and an empty set is rejected
/// downstream by [`verify_signed_tag`].
pub fn roster_keys(keys_toml: &str) -> Result<Vec<String>> {
    #[derive(Default)]
    struct Entry {
        id: Option<String>,
        key: Option<String>,
    }

    let mut active: Vec<Entry> = Vec::new();
    let mut revoked_ids: Vec<String> = Vec::new();
    // Which table the current line belongs to: 0 = none, 1 = active,
    // 2 = revoked.
    let mut table = 0u8;

    for raw in keys_toml.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[keys]]" {
            table = 1;
            active.push(Entry::default());
            continue;
        }
        if line == "[[revoked]]" {
            table = 2;
            revoked_ids.push(String::new());
            continue;
        }
        if line.starts_with('[') {
            // Any other table (e.g. top-level keys after `[meta]`).
            table = 0;
            continue;
        }
        let Some((field, value)) = line.split_once('=') else {
            continue;
        };
        let field = field.trim();
        let value = unquote(value.trim());
        match (table, field) {
            (1, "key") => {
                if let Some(entry) = active.last_mut() {
                    entry.key = Some(value);
                }
            }
            (1, "id") => {
                if let Some(entry) = active.last_mut() {
                    entry.id = Some(value);
                }
            }
            (2, "id") => {
                if let Some(last) = revoked_ids.last_mut() {
                    *last = value;
                }
            }
            _ => {}
        }
    }

    let revoked_ids: Vec<String> = revoked_ids
        .into_iter()
        .filter(|id| !id.is_empty())
        .collect();
    let keys = active
        .into_iter()
        .filter(|entry| {
            entry
                .id
                .as_ref()
                .map(|id| !revoked_ids.contains(id))
                .unwrap_or(true)
        })
        .filter_map(|entry| entry.key)
        .collect();
    Ok(keys)
}

/// Strip one matched pair of surrounding single or double quotes.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

/// Run the full in-browser verification for one channel against `fetch`.
///
/// Walks `HEAD` → `info/refs` → the channel partition → the head commit's
/// tree → `keys.toml`, then verifies the partition's SSH-Ed25519 signature
/// against the roster and checks the channel name binding — exactly the
/// checks the hub indexer performs, in the same crate. A *transport*
/// failure (the surface is unreachable) is returned as `Err`; a clean
/// *verification* failure (the partition is present but does not verify)
/// is returned as `Ok(BadgeOutcome::Failed)`, because that is a finding to
/// render, not a crash.
///
/// # Errors
///
/// Returns an error when a required surface path is unreachable due to a
/// transport error, when `HEAD`/`info/refs` is absent or unparseable, when
/// the head commit or its tree is missing, or when `keys.toml` is absent
/// (an unsigned-roster registry cannot be verified in the browser).
pub async fn verify_channel<F: SurfaceFetch>(fetch: &F, channel: &str) -> Result<BadgeOutcome> {
    let bucket = DEFAULT_PARTITION_BUCKET;
    let partition_path = format!("channels/{channel}/{bucket}");
    let partition = match fetch.fetch(&partition_path).await? {
        Some(bytes) => bytes,
        None => bail!("channel '{channel}' has no partition at {partition_path}"),
    };

    let roster = load_roster(fetch).await?;
    if roster.is_empty() {
        bail!("registry roster (keys.toml) lists no trusted keys");
    }

    match verify_signed_tag(&partition, channel, &roster) {
        Ok(signed) => Ok(BadgeOutcome::Verified(VerifiedBadge {
            channel: channel.to_string(),
            release_tag_oid: signed.tag.object,
        })),
        Err(err) => Ok(BadgeOutcome::Failed {
            reason: format!("{err:#}"),
        }),
    }
}

/// Fetch and walk the head commit's tree to the committed `keys.toml`,
/// returning its trusted-key set.
async fn load_roster<F: SurfaceFetch>(fetch: &F) -> Result<Vec<String>> {
    let head = fetch.fetch("HEAD").await?.context("surface has no HEAD")?;
    let head = String::from_utf8(head).context("HEAD is not UTF-8")?;
    let branch = parse_head(&head).context("HEAD is not a symbolic ref")?;

    let info_refs = fetch
        .fetch("info/refs")
        .await?
        .context("surface has no info/refs")?;
    let info_refs = String::from_utf8(info_refs).context("info/refs is not UTF-8")?;
    let refs = parse_info_refs(&info_refs)?;
    let commit_oid = *refs
        .branches
        .get(&branch)
        .with_context(|| format!("info/refs has no branch '{branch}'"))?;

    let commit_content = read_object(fetch, commit_oid, ObjectKind::Commit).await?;
    let commit = object::parse_commit(&commit_content)?;
    let tree = read_tree_map(fetch, commit.tree).await?;
    let keys_entry = tree
        .get("keys.toml")
        .context("committed tree has no keys.toml")?;
    let keys_blob = read_object(fetch, keys_entry.oid, ObjectKind::Blob).await?;
    let keys_text = String::from_utf8(keys_blob).context("keys.toml is not UTF-8")?;
    roster_keys(&keys_text)
}

/// Read and hash-verify one loose object, requiring a specific kind.
async fn read_object<F: SurfaceFetch>(fetch: &F, oid: Oid, want: ObjectKind) -> Result<Vec<u8>> {
    let path = oid.loose_path();
    let bytes = fetch
        .fetch(&path)
        .await?
        .with_context(|| format!("loose object {path} is missing from the surface"))?;
    let (kind, content) = object::decode_loose(&bytes, Some(oid))?;
    if kind != want {
        bail!(
            "object {oid} is a {}, expected {}",
            kind.as_str(),
            want.as_str()
        );
    }
    Ok(content)
}

/// Read a tree object and index it by entry name.
async fn read_tree_map<F: SurfaceFetch>(
    fetch: &F,
    oid: Oid,
) -> Result<BTreeMap<String, object::TreeEntry>> {
    let content = read_object(fetch, oid, ObjectKind::Tree).await?;
    object::tree_map(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::object::{encode_loose, encode_tree, hash_object, TreeEntry};
    use aos_registry_surface::sshsig;
    use aos_registry_surface::tag::render_tag_payload;

    const ROSTER: &str = r#"
schema = 1

[[keys]]
id = "root"
key = "PLACEHOLDER"

[[keys]]
id = "ci"
key = "PLACEHOLDER_CI"

[[revoked]]
id = "ci"
reason = "rotated"
"#;

    #[test]
    fn roster_keys_returns_active_minus_revoked() {
        let toml = ROSTER
            .replace("PLACEHOLDER_CI", "aos:Ed25519:CIKEY")
            .replace("PLACEHOLDER", "aos:Ed25519:ROOTKEY");
        let keys = roster_keys(&toml).unwrap();
        // `ci` is revoked, so only the root key remains trusted.
        assert_eq!(keys, vec!["aos:Ed25519:ROOTKEY".to_string()]);
    }

    #[test]
    fn roster_keys_handles_single_quotes_and_no_revocations() {
        let toml = "[[keys]]\nid = 'only'\nkey = 'aos:Ed25519:K'\n";
        assert_eq!(
            roster_keys(toml).unwrap(),
            vec!["aos:Ed25519:K".to_string()]
        );
    }

    /// Cross-format regression: the SPA scanner must accept the *exact*
    /// bytes the server writer (`aos_package::registry::keys::write_keys_toml`
    /// via `toml::to_string_pretty`, and the hub seed at `seed.rs`) produces.
    ///
    /// Both server paths spell the active table `[[keys]]` (the serde
    /// `rename = "keys"` on `KeysToml::active`). This fixture replicates the
    /// hub seed's literal blob format
    /// (`"schema = 1\n\n[[keys]]\nid = \"…\"\nkey = \"…\"\n"`, see
    /// `seed.rs` ~288) plus a `[[revoked]]` table, and asserts the scanner
    /// recovers the same trusted set the server's `KeysToml` deserialization
    /// yields: the active keys minus revocations. Before the `[[active]]` →
    /// `[[keys]]` fix this returned an empty set against every real registry.
    #[test]
    fn roster_keys_matches_server_keys_table_spelling() {
        // The exact wire shape produced by the hub seed writer (seed.rs),
        // extended with a second key and a revocation so the active-minus-
        // revoked semantics are exercised against the real table name.
        let keys_toml = concat!(
            "schema = 1\n",
            "\n",
            "[[keys]]\n",
            "id = \"maintainer\"\n",
            "key = \"aos-core:Ed25519:bWFpbnRhaW5lcg==\"\n",
            "\n",
            "[[keys]]\n",
            "id = \"ci\"\n",
            "key = \"aos-core:Ed25519:Y2k=\"\n",
            "\n",
            "[[revoked]]\n",
            "id = \"ci\"\n",
            "reason = \"rotated out\"\n",
        );

        let keys = roster_keys(keys_toml).unwrap();
        // The revoked `ci` key is dropped; only the active `maintainer`
        // key remains trusted — the same set the server roster computes.
        assert_eq!(keys, vec!["aos-core:Ed25519:bWFpbnRhaW5lcg==".to_string()]);
    }

    /// An in-memory surface: a path → bytes map.
    struct MemSurface(BTreeMap<String, Vec<u8>>);

    impl SurfaceFetch for MemSurface {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(path).cloned())
        }
    }

    /// Build a minimal, internally consistent surface with one signed
    /// `stable` partition, a committed `keys.toml` roster, and the loose
    /// objects the verifier walks (commit + tree + blob).
    fn build_surface(partition_name: &str) -> (MemSurface, ed25519_dalek::SigningKey) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let trusted = sshsig::trusted_key_line("root", &key.verifying_key());

        // keys.toml blob.
        let keys_toml = format!("schema = 1\n\n[[keys]]\nid = \"root\"\nkey = \"{trusted}\"\n");
        let keys_blob = keys_toml.into_bytes();
        let keys_oid = hash_object(ObjectKind::Blob, &keys_blob);

        // Root tree with a single keys.toml entry.
        let tree_entries = vec![TreeEntry {
            mode: "100644".into(),
            name: "keys.toml".into(),
            oid: keys_oid,
        }];
        let tree_content = encode_tree(&tree_entries);
        let tree_oid = hash_object(ObjectKind::Tree, &tree_content);

        // Commit pointing at the tree.
        let commit_content = format!(
            "tree {tree_oid}\nauthor A <a@x> 1770000000 +0000\ncommitter A <a@x> 1770000000 +0000\n\nrelease\n"
        )
        .into_bytes();
        let commit_oid = hash_object(ObjectKind::Commit, &commit_content);

        // Signed channel partition (a raw tag payload pointing at a release
        // tag object).
        let body =
            render_tag_payload(partition_name, &"ab".repeat(32), "tag", "msg", 1770000000).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), &key);
        let partition = format!("{body}{armor}\n").into_bytes();

        let mut map = BTreeMap::new();
        map.insert("HEAD".to_string(), b"ref: refs/heads/main\n".to_vec());
        map.insert(
            "info/refs".to_string(),
            format!("{commit_oid}\trefs/heads/main\n").into_bytes(),
        );
        map.insert("channels/stable/current".to_string(), partition);
        map.insert(
            commit_oid.loose_path(),
            encode_loose(ObjectKind::Commit, &commit_content).unwrap(),
        );
        map.insert(
            tree_oid.loose_path(),
            encode_loose(ObjectKind::Tree, &tree_content).unwrap(),
        );
        map.insert(
            keys_oid.loose_path(),
            encode_loose(ObjectKind::Blob, &keys_blob).unwrap(),
        );
        (MemSurface(map), key)
    }

    #[test]
    fn verify_channel_accepts_a_well_formed_partition() {
        let (surface, _key) = build_surface("stable");
        let outcome = pollster_block(verify_channel(&surface, "stable")).unwrap();
        match outcome {
            BadgeOutcome::Verified(badge) => {
                assert_eq!(badge.channel, "stable");
                assert_eq!(badge.release_tag_oid, "ab".repeat(32));
                assert_eq!(badge.short_release(), "abababababab");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn verify_channel_reports_name_replay_as_failed() {
        // The partition embeds the name "testing" but is served at the
        // "stable" path — a replay the name binding must reject.
        let (surface, _key) = build_surface("testing");
        let outcome = pollster_block(verify_channel(&surface, "stable")).unwrap();
        assert!(matches!(outcome, BadgeOutcome::Failed { .. }));
    }

    #[test]
    fn verify_channel_reports_tampered_partition_as_failed() {
        let (mut surface, _key) = build_surface("stable");
        // Flip a byte inside the signed region of the partition.
        if let Some(partition) = surface.0.get_mut("channels/stable/current") {
            partition[10] ^= 0xff;
        }
        let outcome = pollster_block(verify_channel(&surface, "stable")).unwrap();
        assert!(matches!(outcome, BadgeOutcome::Failed { .. }));
    }

    /// Minimal executor for the non-`Send` futures these tests produce.
    ///
    /// The in-memory `MemSurface` resolves every fetch synchronously, so a
    /// no-op waker that never re-schedules is sufficient — the future is
    /// always immediately `Ready` after one poll round.
    fn pollster_block<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: the vtable's clone/wake/drop are all no-ops over a null
        // data pointer that is never dereferenced, which is the canonical
        // noop-waker construction. The waker is only used to poll a future
        // that completes synchronously, so it is never stored or woken.
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
}
