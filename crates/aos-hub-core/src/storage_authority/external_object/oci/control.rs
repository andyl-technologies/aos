//! Fresh, purpose-separated application controls for real OCI originals.
//!
//! Raw manifest, chunk and blob bodies never appear in this wire. A staging
//! admission is transported separately from the public body and authenticates
//! its original upload allowance. Unknown physical effects remain owned by the
//! original, even after a fresh control expires.
//!
//! ```text
//! control = {version, domain, original, actor,
//!            issued_at, expires_at, nonce, operation}
//! operation = stage | install_sources | compose | inspect | status
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::storage_work::{StorageBindingSnapshot, StorageWorkKey};

use super::{digest_string, ExternalOciOriginal, OciActorOriginal, OciObjectOriginal, OciSourceOriginal};

/// Authenticated metadata-only external OCI control endpoint.
pub const EXTERNAL_OCI_PATH: &str = "/_internal/storage/external-oci/v1";
/// Separate original/control signature header, never a public bearer capability.
pub const EXTERNAL_OCI_SIGNATURE_HEADER: &str = "x-aos-external-oci-signature";
/// Maximum bounded signed OCI control, excluding every public object body.
pub const MAX_EXTERNAL_OCI_CONTROL_BYTES: usize = 64 * 1024;
/// Largest ordered source declaration page retained before materialization.
pub const MAX_EXTERNAL_OCI_SOURCE_PAGE: usize = 32;
/// Largest bounded part advance allowed by one fresh OCI control.
pub const MAX_EXTERNAL_OCI_ADVANCE_PARTS: u8 = 8;

const DOMAIN: &str = "aos.external-oci-application.v1";

/// Selects only one OCI operation on an already selected original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OciControl {
    /// Stages exactly one public OCI chunk under its existing quota allowance.
    Stage,
    /// Retains an ordered source page; this grants no provider mutation.
    InstallSources {
        /// Zero-based source index, unchanged when replaying this exact page.
        first: u32,
        /// Exact bounded source descriptors from the completing SQL upload.
        sources: Vec<OciSourceOriginal>,
    },
    /// Advances a bounded number of guard-selected materialization part steps.
    Compose {
        /// Maximum provider part advances, never an arbitrary action list.
        maximum_parts: u8,
    },
    /// Revalidates a positive incarnation by a conditional storage-local read.
    Inspect,
    /// Returns retained originals and progress without effect or lease renewal.
    Status,
    /// Locates the same immutable business selection without creating an owner.
    RecoverOriginal,
}

/// Pairs an immutable OCI original with a fresh exact application permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciRequest {
    /// Closed control version, currently one.
    pub version: u8,
    /// Exact purpose domain included in every request signature.
    pub domain: String,
    /// Actual upload and immutable physical writer original.
    pub original: ExternalOciOriginal,
    /// Exact currently acknowledged snapshot selected for this phase alone.
    pub snapshot_revision: String,
    /// Freshly authenticated same-account/IAM-token OCI grant for this phase.
    pub actor: OciActorOriginal,
    /// Original issue time of this short-lived control.
    pub issued_at: i64,
    /// Exclusive control expiry, clipped to both actor and upload deadlines.
    pub expires_at: i64,
    /// Original random request correlation value, never a provider retry id.
    pub nonce: String,
    /// Closed bounded phase selected by current Native authority.
    pub operation: OciControl,
}

impl ExternalOciRequest {
    /// Constructs a fresh control without changing its retained business original.
    ///
    /// The caller independently checks current SQL ownership, writer authority,
    /// purpose-specific profile acceptance and actor permission before signing.
    ///
    /// # Errors
    /// Refuses malformed originals, phases, correlation or expired permission.
    pub fn new(
        original: ExternalOciOriginal,
        snapshot_revision: String,
        actor: OciActorOriginal,
        issued_at: i64,
        expires_at: i64,
        nonce: String,
        operation: OciControl,
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            domain: DOMAIN.into(),
            original,
            snapshot_revision,
            actor,
            issued_at,
            expires_at,
            nonce,
            operation,
        };
        value.validate(&value.original.deployment_id, issued_at)?;
        Ok(value)
    }

    /// Checks exact original shape, phase and the immutable permission cutoff.
    ///
    /// # Errors
    /// Refuses foreign deployment, malformed or excessive phases, rollback,
    /// changed actor identity or renewed upload deadlines, noncanonical fields or oversized controls.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<()> {
        self.validate_checked(deployment, Some(now))
    }

    /// Checks historical intrinsic shape without accepting current permission.
    ///
    /// This neither authenticates a signature nor grants physical dispatch.
    ///
    /// # Errors
    /// Refuses foreign originals, malformed actor/window/phase or excess bytes.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<()> {
        self.validate_checked(deployment, None)
    }

    fn validate_checked(&self, deployment: &str, now: Option<i64>) -> Result<()> {
        self.original.validate()?;
        self.actor.validate()?;
        ensure!(
            self.version == 1
                && self.domain == DOMAIN
                && self.original.deployment_id == deployment
                && digest_string(&self.nonce)
                && digest_string(&self.snapshot_revision)
                && self.issued_at > 0
                && now.is_none_or(|now| self.issued_at <= now)
                && now.is_none_or(|now| self.expires_at > now)
                && self.expires_at > self.issued_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|age| age <= 30)
                && self.expires_at <= self.actor.expires_at.get()
                && self.actor.account == self.original.actor.account
                && self.actor.token_id == self.original.actor.token_id
                && self.expires_at <= self.original.upload.expires_at.get(),
            "external OCI permission time or identity differs"
        );
        match (&self.operation, &self.original.object) {
            (OciControl::Stage, OciObjectOriginal::Chunk { .. }) => {}
            (OciControl::Compose { maximum_parts }, OciObjectOriginal::Compose { .. }) => {
                ensure!(
                    *maximum_parts > 0 && *maximum_parts <= MAX_EXTERNAL_OCI_ADVANCE_PARTS,
                    "external OCI phase exceeds bounded part advance"
                );
            }
            (
                OciControl::InstallSources { first, sources },
                OciObjectOriginal::Compose {
                    sources: manifest, ..
                },
            ) => {
                ensure!(
                    !sources.is_empty()
                        && sources.len() <= MAX_EXTERNAL_OCI_SOURCE_PAGE
                        && first
                            .checked_add(sources.len() as u32)
                            .is_some_and(|end| end <= manifest.count),
                    "external OCI source page escapes full original"
                );
                let prefix = crate::keymap::r2_key(
                    &self.original.writer.binding_prefix,
                    &self.original.writer.placement_prefix,
                );
                let private = crate::keymap::r2_key(
                    &prefix,
                    &format!("oci/uploads/{}/chunks", self.original.upload.upload_id),
                );
                let mut keys = std::collections::BTreeSet::new();
                for source in sources {
                    source.bytes.validate()?;
                    source
                        .incarnation
                        .validate(self.original.scope.physical_authority_id.as_str())?;
                    ensure!(
                        source
                            .key
                            .strip_prefix(&format!("{private}/"))
                            .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('/'))
                            && source.bytes.size > 0
                            && source.bytes.size <= super::MAX_EXTERNAL_OCI_CHUNK_BYTES
                            && keys.insert(&source.key)
                            && digest_string(&source.receipt_digest)
                            && crate::surface_write::strong_if_match_etag(&source.etag)?
                                == source.etag,
                        "external OCI source page differs from private original"
                    );
                }
            }
            (OciControl::Inspect | OciControl::Status | OciControl::RecoverOriginal, _) => {}
            _ => anyhow::bail!("external OCI control does not match original object kind"),
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_OCI_CONTROL_BYTES,
            "external OCI control oversized"
        );
        Ok(())
    }

    /// Rechecks immutable control and protected binding after asynchronous waits.
    ///
    /// # Errors
    /// Refuses expired controls, changed binding lifetime/revision or a protected
    /// physical prefix different from the independently selected original.
    pub fn validate_snapshot(&self, snapshot: &StorageBindingSnapshot, now: i64) -> Result<()> {
        self.validate(&self.original.deployment_id, now)?;
        snapshot.validate(&self.original.deployment_id, now)?;
        let writer = &self.original.writer;
        ensure!(
            snapshot.binding_id == writer.binding_id.get()
                && snapshot.binding_stable_id == writer.binding_stable_id
                && snapshot.binding_resource_version == writer.binding_resource_version.get()
                && snapshot.object_prefix == writer.binding_prefix
                && snapshot.revision()? == self.snapshot_revision
                && snapshot.binding_spec_revision()? == self.original.binding_spec_revision
                && matches!(snapshot.binding_kind.as_str(), "s3" | "r2")
                && snapshot.access_mode == "private",
            "external OCI protected binding differs from original"
        );
        Ok(())
    }

    /// Signs exact bounded control bytes under the existing application role.
    ///
    /// # Errors
    /// Refuses malformed/stale controls or serialization/signing failures.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment, now)?;
        let bytes = serde_json::to_vec(self)?;
        Ok((bytes.clone(), key.sign_body(&bytes)?))
    }

    /// Authenticates the exact control before parsing its closed OCI permission.
    ///
    /// # Errors
    /// Refuses excess bytes, bad signatures, noncanonical JSON, wrong purpose
    /// or any changed/expired original and phase.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EXTERNAL_OCI_CONTROL_BYTES,
            "external OCI control oversized"
        );
        key.verify_body(signature, bytes)?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "noncanonical external OCI control"
        );
        value.validate(deployment, now)?;
        Ok(value)
    }
}
