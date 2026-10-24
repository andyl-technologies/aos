//! Portable, exact-revision candidates for registry publication.
//!
//! A mutable stage record selects an immutable revision. Its inventory contains
//! immutable origin objects only; Git tags, channel partitions, and public
//! listings are installed by the later release transaction.
//!
//! ```json
//! {"schema":"aos.registry-stage/v1","id":"candidate","registry":"example/main","revision":1,"release_id":"1.0.0","source_branch":"maintainer/candidate","commit":"0000000000000000000000000000000000000000","inventory_digest":"sha256:...","inventory":[],"store_roots":[]}
//! ```

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub mod wire;

/// Identifies the portable stage revision schema.
pub const STAGE_SCHEMA: &str = "aos.registry-stage/v1";

/// Identifies one immutable object available to a candidate revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageObject {
    /// Canonical origin-relative object key.
    pub path: String,
    /// Exact SHA-256 of the stored bytes, prefixed with `sha256:`.
    pub sha256: String,
    /// Exact number of stored bytes.
    pub byte_size: u64,
    /// Artifact category for administrative inventory displays.
    pub kind: String,
    /// HTTP media type of the stored bytes.
    pub media_type: String,
}

/// Holds exact prepared pointer bytes withheld until candidate publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagePointer {
    /// Mutable origin-relative pointer key.
    pub path: String,
    /// Exact prepared, signed bytes to install.
    #[serde(with = "pointer_bytes")]
    pub bytes: Vec<u8>,
    /// SHA-256 of the pointer observed before staging, when it exists.
    pub expected_sha256: Option<String>,
}

/// Binds one candidate revision to its branch, commit, and immutable bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageRevision {
    /// Exact schema identifier.
    pub schema: String,
    /// Stable candidate identifier within its registry.
    pub id: String,
    /// Canonical registry identity.
    pub registry: String,
    /// Monotonic revision, beginning at one.
    pub revision: u64,
    /// Exact semver reserved for eventual release.
    pub release_id: String,
    /// Ordinary maintainer branch, without the `refs/heads/` prefix.
    pub source_branch: String,
    /// Exact Git commit containing the candidate catalog.
    pub commit: String,
    /// Domain-separated digest of the canonical inventory.
    pub inventory_digest: String,
    /// Strictly path-sorted, unique immutable objects.
    pub inventory: Vec<StageObject>,
    /// Complete signed container graph retained in its OCI repository namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<StageContainerGraph>,
    /// Exact prepared public pointers withheld until explicit publication.
    pub publication: Vec<StagePointer>,
    /// Store outputs retained while this stage remains active.
    pub store_roots: Vec<String>,
}

/// Binds a candidate's complete OCI graph to its canonical repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageContainerGraph {
    /// Distribution repository whose digest namespace receives the objects.
    pub repository: aos_oci_types::RepositoryName,
    /// Signed release declaration committed in the candidate's Git catalog.
    pub release: aos_oci_types::ContainerRelease,
    /// Complete verified graph, sorted and unique by content digest.
    pub descriptors: Vec<aos_oci_types::Descriptor>,
}

impl StageContainerGraph {
    /// Checks descriptor identities and the signed release's required roots.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid releases, unordered or conflicting objects,
    /// absent signed roots, or inventory objects outside the declared graph.
    pub fn validate(&self, inventory: &[StageObject], release_id: &str) -> Result<()> {
        self.release.validate()?;
        if self.release.identity.release != release_id || self.repository.as_str().is_empty() {
            bail!("container stage release or repository identity differs from the candidate");
        }
        aos_oci_types::RepositoryName::parse(self.repository.as_str())?;
        if self.descriptors.len() > aos_oci_types::limits::MAX_REACHABLE_DESCRIPTORS {
            bail!("container stage graph exceeds the descriptor limit");
        }
        let objects = inventory
            .iter()
            .map(|object| (object.path.as_str(), object))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut descriptors = std::collections::BTreeMap::new();
        let mut previous = None;
        for descriptor in &self.descriptors {
            descriptor.validate()?;
            if previous.is_some_and(|digest| digest >= descriptor.digest) {
                bail!("container stage descriptors must be unique and digest sorted");
            }
            previous = Some(descriptor.digest);
            descriptors.insert(descriptor.digest, descriptor);
            let path = format!(
                "{}{}",
                crate::keymap::OCI_BLOB_KEY_PREFIX,
                descriptor.digest.encoded()
            );
            let object = objects.get(path.as_str()).filter(|object| {
                object.sha256 == descriptor.digest.to_string()
                    && object.byte_size == descriptor.size
                    && object.media_type == descriptor.media_type.as_str()
            });
            if object.is_none() {
                bail!(
                    "container stage descriptor lacks its exact immutable inventory object: {path}"
                );
            }
        }
        for root in [
            &self.release.oci.index,
            &self.release.nix.closure,
            &self.release.evidence.sbom,
            &self.release.evidence.source,
            &self.release.evidence.license,
            &self.release.evidence.provenance,
            &self.release.evidence.signature,
        ]
        .into_iter()
        .chain(self.release.oci.platform_manifests.iter())
        {
            let present = descriptors.get(&root.digest).is_some_and(|descriptor| {
                descriptor.size == root.size && descriptor.media_type == root.media_type
            });
            if !present {
                bail!(
                    "container stage graph omits a signed descriptor: {}",
                    root.digest
                );
            }
        }
        for object in inventory
            .iter()
            .filter(|object| object.path.starts_with(crate::keymap::OCI_BLOB_KEY_PREFIX))
        {
            let digest = aos_oci_types::Sha256Digest::parse(&object.sha256)?;
            if !descriptors.contains_key(&digest) {
                bail!("container stage inventory contains an undeclared OCI digest");
            }
        }
        Ok(())
    }
}

/// Describes the publication lifecycle of a candidate's current revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    /// Revision bytes are being authored or transferred.
    Draft,
    /// Every exact inventory object is available in staging storage.
    Ready,
    /// Exact revision is frozen while its prepared public pointers are installed.
    Releasing,
    /// Exact revision has been published as an immutable release.
    Released,
    /// Revision roots have been relinquished and may be collected.
    Discarded,
}

/// Selects the current immutable revision and its publication state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageRecord {
    /// Exact current revision.
    pub revision: StageRevision,
    /// Current lifecycle state.
    pub state: StageState,
    /// Published semver, present only after finalization.
    pub released_version: Option<String>,
}

/// Computes the identity of a canonical immutable inventory.
///
/// # Errors
///
/// Returns an error when JSON encoding fails.
pub fn inventory_digest(inventory: &[StageObject]) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"aos.registry-stage-inventory/v1\0");
    serde_json::to_writer(InventoryDigestWriter(&mut digest), inventory)?;
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

/// Preserves canonical JSON hashing without retaining a second full inventory.
struct InventoryDigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for InventoryDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validates a stage identifier before using it as a storage component.
///
/// # Errors
///
/// Returns an error for empty, oversized, or unsafe identifiers.
pub fn validate_stage_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid registry stage identifier");
    }
    Ok(())
}

impl StageRevision {
    /// Validates the exact portable revision and its inventory identity.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, invalid identities, mutable
    /// object keys, duplicate or unordered paths, or an inventory mismatch.
    pub fn validate(&self) -> Result<()> {
        validate_stage_id(&self.id)?;
        semver::Version::parse(&self.release_id)?;
        if self.schema != STAGE_SCHEMA || self.revision == 0 || self.registry.is_empty() {
            bail!("invalid registry stage identity");
        }
        if !matches!(self.commit.len(), 40 | 64)
            || !self
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("invalid registry stage commit");
        }
        if self.source_branch.is_empty()
            || self.source_branch.starts_with('/')
            || self.source_branch.ends_with('/')
            || self.source_branch.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\\' | ':' | ' ' | '?' | '*' | '[' | '~' | '^')
            })
            || self.source_branch.ends_with('.')
            || self
                .source_branch
                .split('/')
                .any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"))
            || self.source_branch.contains("..")
            || self.source_branch.contains("@{")
        {
            bail!("invalid registry stage source branch");
        }

        let mut previous: Option<&str> = None;
        for object in &self.inventory {
            if previous.is_some_and(|path| path >= object.path.as_str()) {
                bail!("stage inventory must be strictly path sorted");
            }
            previous = Some(&object.path);
            if object.path.starts_with('/')
                || object.path.contains(['\\', '\0', '\n', '\r'])
                || object
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || !is_immutable_stage_path(&object.path)
            {
                bail!(
                    "stage inventory contains a mutable or unsafe object key: {}",
                    object.path
                );
            }
            let hash = object.sha256.strip_prefix("sha256:").unwrap_or("");
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || object.kind.is_empty()
                || object.media_type.is_empty()
                || object.media_type.chars().any(char::is_control)
            {
                bail!("invalid stage object identity: {}", object.path);
            }
        }
        if inventory_digest(&self.inventory)? != self.inventory_digest {
            bail!("registry stage inventory digest does not match");
        }
        let mut previous: Option<&str> = None;
        for pointer in &self.publication {
            if previous.is_some_and(|path| path >= pointer.path.as_str())
                || !crate::keymap::is_mutable_path(&pointer.path)
                || pointer.path.starts_with('/')
                || pointer.path.contains(['\\', '\0', '\n', '\r'])
                || pointer
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                bail!("invalid or unordered prepared stage pointer");
            }
            previous = Some(&pointer.path);
        }
        if self.store_roots.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .store_roots
                .iter()
                .any(|root| !root.starts_with("/nix/store/") || root[11..].contains('/'))
        {
            bail!("stage store roots must be exact, unique, sorted store outputs");
        }
        for root in &self.store_roots {
            crate::store::store_path_hash(root)?;
        }
        if let Some(container) = &self.container {
            container.validate(&self.inventory, &self.release_id)?;
        } else if self
            .inventory
            .iter()
            .any(|object| object.path.starts_with("oci/blobs/"))
        {
            bail!("OCI stage objects require a signed complete container graph");
        }
        Ok(())
    }
}

/// Returns whether an origin key denotes immutable staged bytes.
pub fn is_immutable_stage_path(path: &str) -> bool {
    (crate::keymap::is_machine_path(path) && !crate::keymap::is_mutable_path(path))
        || crate::keymap::is_loose_git_object_path(path)
        || (path.ends_with(".narinfo") && !path.contains('/'))
        || path
            .strip_prefix(crate::keymap::OCI_BLOB_KEY_PREFIX)
            .is_some_and(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

mod pointer_bytes {
    use base64::Engine as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}
