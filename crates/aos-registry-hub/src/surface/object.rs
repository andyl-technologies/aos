//! Git object primitives for SHA-256 registry surfaces.
//!
//! AOS registries are SHA-256 git repositories served as static files, and
//! the publishing pipeline guarantees every object is present *loose* under
//! the root `objects/` directory (per-release directories are pack-only
//! optimizations). This module reads that guaranteed layout without the git
//! CLI: zlib-compressed loose objects with the standard
//! `<type> <size>\0<content>` header, identified by the SHA-256 of the
//! uncompressed header + content, stored at `objects/<xx>/<62-hex>`.
//!
//! ```text
//! objects/ab/cdef…   = zlib( b"commit 213\0" + content )
//! oid                = sha256( b"commit 213\0" + content )  (64 hex chars)
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// A SHA-256 git object id (64 hex characters).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid([u8; 32]);

impl Oid {
    /// Parse an oid from its 64-character hex form.
    ///
    /// # Errors
    ///
    /// Returns an error if `hex_str` is not exactly 64 hex characters.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim())
            .with_context(|| format!("invalid object id hex '{hex_str}'"))?;
        Self::from_bytes(&bytes)
    }

    /// Construct an oid from its 32 raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("object id must be 32 bytes, got {}", bytes.len()))?;
        Ok(Self(arr))
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The loose-object path relative to the surface root:
    /// `objects/<first two hex chars>/<remaining 62>`.
    pub fn loose_path(&self) -> String {
        let h = self.to_hex();
        format!("objects/{}/{}", &h[..2], &h[2..])
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.to_hex())
    }
}

/// The type tag of a git object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A commit object.
    Commit,
    /// A tree object.
    Tree,
    /// An annotated tag object.
    Tag,
    /// A blob object.
    Blob,
}

impl ObjectKind {
    /// The on-disk header name (`commit`, `tree`, `tag`, `blob`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Tag => "tag",
            Self::Blob => "blob",
        }
    }

    /// Parse a header name into an object kind.
    ///
    /// # Errors
    ///
    /// Returns an error for any name other than the four git object types.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "commit" => Self::Commit,
            "tree" => Self::Tree,
            "tag" => Self::Tag,
            "blob" => Self::Blob,
            other => bail!("unknown git object type '{other}'"),
        })
    }
}

/// Compute the SHA-256 oid of an object from its kind and content.
pub fn hash_object(kind: ObjectKind, content: &[u8]) -> Oid {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(content);
    Oid(hasher.finalize().into())
}

/// Encode an object as a zlib-compressed loose object.
///
/// # Errors
///
/// Returns an error only if the in-memory zlib encoder reports an I/O
/// failure. The encoder writes into a heap `Vec`, so in practice this cannot
/// fail; the `Result` exists so callers never have to `unwrap` an infallible
/// path.
pub fn encode_loose(kind: ObjectKind, content: &[u8]) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(content.len() + 32);
    raw.extend_from_slice(kind.as_str().as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write as _;
    encoder
        .write_all(&raw)
        .context("writing loose object into zlib encoder")?;
    encoder
        .finish()
        .context("finishing zlib encoder for loose object")
}

/// Maximum inflated size of a loose object (64 MiB).
///
/// Registry objects are commits, trees, tags, and small TOML blobs; a
/// loose object inflating past this cap is treated as hostile (a zlib
/// bomb) rather than read into memory.
pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Decode a zlib-compressed loose object into its kind and content.
///
/// The decoded bytes are verified against `expected` when given, so a
/// corrupted or substituted object is rejected at read time. Inflation is
/// bounded by [`MAX_OBJECT_BYTES`] so a hostile surface cannot zlib-bomb
/// the reader.
///
/// # Errors
///
/// Returns an error if the zlib stream is invalid, the inflated size
/// exceeds [`MAX_OBJECT_BYTES`], the header is malformed, the declared
/// length disagrees with the content, or the content hashes to a
/// different oid than `expected`.
pub fn decode_loose(compressed: &[u8], expected: Option<Oid>) -> Result<(ObjectKind, Vec<u8>)> {
    decode_loose_with_limit(compressed, expected, MAX_OBJECT_BYTES)
}

/// [`decode_loose`] with an explicit inflation cap (factored for tests).
fn decode_loose_with_limit(
    compressed: &[u8],
    expected: Option<Oid>,
    limit: u64,
) -> Result<(ObjectKind, Vec<u8>)> {
    // Read at most limit + 1 bytes: landing past the limit proves the
    // stream inflates beyond the cap without materializing the rest.
    let decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut raw = Vec::new();
    decoder
        .take(limit.saturating_add(1))
        .read_to_end(&mut raw)
        .context("inflating loose object")?;
    if raw.len() as u64 > limit {
        bail!("loose object inflates past the {limit}-byte cap");
    }

    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .context("loose object missing header NUL")?;
    let header = std::str::from_utf8(&raw[..nul]).context("loose object header is not UTF-8")?;
    let (kind_str, len_str) = header
        .split_once(' ')
        .context("loose object header missing space")?;
    let kind = ObjectKind::parse(kind_str)?;
    let declared: usize = len_str
        .parse()
        .with_context(|| format!("invalid loose object length '{len_str}'"))?;
    let content = raw[nul + 1..].to_vec();
    if content.len() != declared {
        bail!(
            "loose object length mismatch: header declares {declared}, content is {}",
            content.len(),
        );
    }
    if let Some(expected) = expected {
        let actual = hash_object(kind, &content);
        if actual != expected {
            bail!("loose object hash mismatch: expected {expected}, got {actual}");
        }
    }
    Ok((kind, content))
}

/// Parsed fields of a commit object.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The root tree oid.
    pub tree: Oid,
    /// Parent commit oids, in header order.
    pub parents: Vec<Oid>,
    /// The armored SSH signature from the `gpgsig`/`gpgsig-sha256`
    /// header, when present.
    pub signature: Option<String>,
    /// The commit content with the signature header removed — the exact
    /// bytes the signature covers.
    pub signed_payload: Vec<u8>,
    /// Committer timestamp in Unix seconds, when parseable.
    pub committer_when: Option<i64>,
}

/// Parse a raw commit object's headers and reconstruct its signed payload.
///
/// Git signs commits by inserting the armored signature as a multi-line
/// signature header (continuation lines prefixed with one space) — `gpgsig`
/// in SHA-1 repos, `gpgsig-sha256` in SHA-256 repos; the signed
/// payload is the commit content with that whole header removed.
///
/// # Errors
///
/// Returns an error when the `tree` header is missing or malformed.
pub fn parse_commit(content: &[u8]) -> Result<Commit> {
    let text = std::str::from_utf8(content).context("commit object is not UTF-8")?;
    let mut tree = None;
    let mut parents = Vec::new();
    let mut signature_lines: Vec<&str> = Vec::new();
    let mut committer_when = None;
    let mut payload = String::with_capacity(text.len());

    let mut lines = text.split_inclusive('\n').peekable();
    let mut in_headers = true;
    while let Some(line) = lines.next() {
        if in_headers {
            let trimmed = line.strip_suffix('\n').unwrap_or(line);
            if trimmed.is_empty() {
                in_headers = false;
                payload.push_str(line);
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("tree ") {
                tree = Some(Oid::from_hex(rest)?);
            } else if let Some(rest) = trimmed.strip_prefix("parent ") {
                parents.push(Oid::from_hex(rest)?);
            } else if let Some(rest) = trimmed.strip_prefix("committer ") {
                committer_when = parse_ident_when(rest);
            } else if let Some(rest) = trimmed
                .strip_prefix("gpgsig-sha256 ")
                .or_else(|| trimmed.strip_prefix("gpgsig "))
            {
                // Consume the multi-line header without copying it into the
                // signed payload.
                signature_lines.push(rest);
                while let Some(next) = lines.peek() {
                    if let Some(cont) = next.strip_prefix(' ') {
                        signature_lines.push(cont.strip_suffix('\n').unwrap_or(cont));
                        lines.next();
                    } else {
                        break;
                    }
                }
                continue;
            }
            payload.push_str(line);
        } else {
            payload.push_str(line);
        }
    }

    let signature = if signature_lines.is_empty() {
        None
    } else {
        Some(signature_lines.join("\n"))
    };

    Ok(Commit {
        tree: tree.context("commit object missing tree header")?,
        parents,
        signature,
        signed_payload: payload.into_bytes(),
        committer_when,
    })
}

/// One entry of a tree object.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    /// File mode (`100644` for blobs, `40000` for subtrees).
    pub mode: String,
    /// Entry name within the tree.
    pub name: String,
    /// Target object id.
    pub oid: Oid,
}

impl TreeEntry {
    /// Whether this entry is a subtree.
    pub fn is_tree(&self) -> bool {
        self.mode == "40000"
    }
}

/// Parse a binary tree object into its entries.
///
/// Tree entries are `<mode> <name>\0<32 raw oid bytes>`, concatenated.
///
/// # Errors
///
/// Returns an error on truncated entries or non-UTF-8 names.
pub fn parse_tree(content: &[u8]) -> Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .context("tree entry missing mode terminator")?;
        let mode = std::str::from_utf8(&rest[..space])
            .context("tree entry mode is not UTF-8")?
            .to_string();
        rest = &rest[space + 1..];
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .context("tree entry missing name terminator")?;
        let name = std::str::from_utf8(&rest[..nul])
            .context("tree entry name is not UTF-8")?
            .to_string();
        rest = &rest[nul + 1..];
        if rest.len() < 32 {
            bail!("tree entry for '{name}' has truncated oid");
        }
        let oid = Oid::from_bytes(&rest[..32])?;
        rest = &rest[32..];
        entries.push(TreeEntry { mode, name, oid });
    }
    Ok(entries)
}

/// Encode tree entries into the binary tree object format.
///
/// Entries are emitted in the given order; callers wanting a canonical git
/// tree should pre-sort by name.
pub fn encode_tree(entries: &[TreeEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(entry.mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(entry.name.as_bytes());
        out.push(0);
        out.extend_from_slice(&entry.oid.0);
    }
    out
}

/// Build a name → entry map from tree content.
///
/// # Errors
///
/// Returns an error if the tree fails to parse.
pub fn tree_map(content: &[u8]) -> Result<BTreeMap<String, TreeEntry>> {
    Ok(parse_tree(content)?
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect())
}

/// Extract the Unix timestamp from a `Name <email> <secs> <tz>` ident line.
fn parse_ident_when(ident: &str) -> Option<i64> {
    ident
        .split_whitespace()
        .rev()
        .nth(1)
        .and_then(|s| s.parse::<i64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_roundtrip_preserves_content_and_hash() {
        let content = b"hello registry";
        let compressed = encode_loose(ObjectKind::Blob, content).unwrap();
        let oid = hash_object(ObjectKind::Blob, content);
        let (kind, decoded) = decode_loose(&compressed, Some(oid)).unwrap();
        assert_eq!(kind, ObjectKind::Blob);
        assert_eq!(decoded, content);
    }

    #[test]
    fn decode_enforces_inflation_cap() {
        // Highly compressible content well past a tiny test cap.
        let content = vec![0u8; 4096];
        let compressed = encode_loose(ObjectKind::Blob, &content).unwrap();
        let err = decode_loose_with_limit(&compressed, None, 64).unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {err:#}");
        // The same object decodes fine under a sufficient cap.
        assert!(decode_loose_with_limit(&compressed, None, 8192).is_ok());
    }

    #[test]
    fn decode_rejects_wrong_oid() {
        let compressed = encode_loose(ObjectKind::Blob, b"a").unwrap();
        let wrong = hash_object(ObjectKind::Blob, b"b");
        assert!(decode_loose(&compressed, Some(wrong)).is_err());
    }

    #[test]
    fn tree_roundtrip() {
        let oid = hash_object(ObjectKind::Blob, b"x");
        let entries = vec![
            TreeEntry {
                mode: "100644".into(),
                name: "registry.toml".into(),
                oid,
            },
            TreeEntry {
                mode: "40000".into(),
                name: "packages".into(),
                oid,
            },
        ];
        let encoded = encode_tree(&entries);
        let parsed = parse_tree(&encoded).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "registry.toml");
        assert!(!parsed[0].is_tree());
        assert!(parsed[1].is_tree());
    }

    #[test]
    fn commit_parse_extracts_signature_and_payload() {
        let tree = hash_object(ObjectKind::Tree, b"");
        let unsigned = format!(
            "tree {tree}\nauthor A <a@x> 1770000000 +0000\ncommitter A <a@x> 1770000000 +0000\n\nmsg\n",
        );
        let signed = format!(
            "tree {tree}\nauthor A <a@x> 1770000000 +0000\ncommitter A <a@x> 1770000000 +0000\ngpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n line2\n -----END SSH SIGNATURE-----\n\nmsg\n",
        );
        let commit = parse_commit(signed.as_bytes()).unwrap();
        assert_eq!(commit.tree, tree);
        assert_eq!(commit.committer_when, Some(1770000000));
        assert_eq!(commit.signed_payload, unsigned.as_bytes());
        let sig = commit.signature.unwrap();
        assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(sig.ends_with("-----END SSH SIGNATURE-----"));
    }

    #[test]
    fn commit_without_signature_has_identity_payload() {
        let tree = hash_object(ObjectKind::Tree, b"");
        let text = format!("tree {tree}\ncommitter A <a@x> 1 +0000\n\nm\n");
        let commit = parse_commit(text.as_bytes()).unwrap();
        assert!(commit.signature.is_none());
        assert_eq!(commit.signed_payload, text.as_bytes());
    }
}
