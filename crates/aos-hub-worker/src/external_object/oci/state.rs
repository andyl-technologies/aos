//! Compact retained OCI ownership and exact positive-only physical transitions.
//!
//! Full originals, source pages, part receipts and terminal receipts live in
//! existing object KV records. Head retains only the matching ownership pointer.
//! A pending effect never clears because a request expired or a HEAD changed.
//!
//! ```text
//! owner = {original_digest, configuration}
//! session = {original, phase, upload_id, progress, pending, closed}
//! pending = {effect, effect_digest, dispatch_nonce}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::{
    db::OciSha256State,
    storage_authority::external_object::oci::{
        ExternalOciOriginal, OciBytes, OciObjectOriginal, OciProviderIncarnation,
        OciSourceManifest, EXTERNAL_OCI_PART_BYTES,
    },
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Owner {
    pub original_digest: String,
    pub configuration: String,
}

impl Owner {
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        ensure!(
            digest_string(&self.original_digest) && digest_string(&self.configuration),
            "external OCI ownership pointer malformed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Declared,
    Active,
    Closed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub original: ExternalOciOriginal,
    pub configuration: String,
    pub phase: Phase,
    pub provider_upload_id: Option<String>,
    pub source_count: u32,
    pub source_bytes: u64,
    pub source_manifest_sha256: OciSha256State,
    pub next_part: u32,
    pub accepted_bytes: u64,
    pub source_ended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cursor: Option<SourceCursor>,
    pub last_part_bytes: u64,
    pub sha256: OciSha256State,
    pub upload_sha256: OciSha256State,
    pub pending: Option<Pending>,
    pub closed: Option<Closed>,
}

/// Portable contiguous source continuation, committed with each positive part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceCursor {
    pub index: u32,
    pub offset: u64,
    pub sha256: OciSha256State,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub effect: Effect,
    pub effect_digest: String,
    pub dispatch_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Effect {
    Create,
    EmptyPut { bytes: OciBytes },
    Part {
        part_number: u32,
        bytes: OciBytes,
        checksum_md5: String,
        next_sha256: OciSha256State,
        next_upload_sha256: OciSha256State,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_source_cursor: Option<SourceCursor>,
    },
    Complete {
        bytes: OciBytes,
        parts_digest: String,
    },
    Abort,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Positive {
    Created {
        upload_id: String,
    },
    Part {
        etag: String,
    },
    Completed {
        etag: String,
        incarnation: OciProviderIncarnation,
    },
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub original_digest: String,
    pub pending: Pending,
    pub positive: Positive,
}

pub(super) use aos_hub_core::storage_authority::external_object::oci::reply::OciClosedObject as Closed;

impl Session {
    pub(super) fn declare(original: ExternalOciOriginal, configuration: String) -> Result<Self> {
        original.validate()?;
        ensure!(
            digest_string(&configuration),
            "external OCI configuration digest malformed"
        );
        let source_cursor = matches!(original.object, OciObjectOriginal::Compose { .. }).then(|| SourceCursor {
            index: 0, offset: 0, sha256: OciSha256State::initial(), total_bytes: 0,
        });
        let value = Self {
            upload_sha256: match &original.object {
                OciObjectOriginal::Chunk { prior_sha256, .. } => prior_sha256.clone(),
                OciObjectOriginal::Compose { .. } => OciSha256State::initial(),
            },
            original,
            configuration,
            phase: Phase::Declared,
            provider_upload_id: None,
            source_count: 0,
            source_bytes: 0,
            source_manifest_sha256: OciSourceManifest::initial_hash()?,
            next_part: 1,
            accepted_bytes: 0,
            source_ended: false,
            source_cursor,
            last_part_bytes: 0,
            sha256: OciSha256State::initial(),
            pending: None,
            closed: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn owner(&self) -> Result<Owner> {
        Ok(Owner {
            original_digest: self.original.fingerprint()?,
            configuration: self.configuration.clone(),
        })
    }

    pub(super) fn reply(
        &self,
        request: &aos_hub_core::storage_authority::external_object::oci::control::ExternalOciRequest,
    ) -> Result<aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply>
    {
        self.validate()?;
        let recovering = matches!(request.operation,
            aos_hub_core::storage_authority::external_object::oci::control::OciControl::RecoverOriginal);
        ensure!(
            self.original == request.original
                || (recovering && self.original.selection_digest()? == request.original.selection_digest()?),
            "external OCI lookup original changed"
        );
        let reply =
            aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply {
                version: 1,
                request_digest: super::super::protocol::digest(request)?,
                nonce: request.nonce.clone(),
                original_digest: self.original.fingerprint()?,
                retained_original: recovering.then(|| self.original.clone()),
                source_count: self.source_count,
                next_part: self.next_part,
                accepted_bytes: self.accepted_bytes,
                upload_sha256: self.upload_sha256.clone(),
                pending_effect_digest: self
                    .pending
                    .as_ref()
                    .map(|pending| pending.effect_digest.clone()),
                closed: self.closed.clone(),
            };
        reply.validate_for(request)?;
        Ok(reply)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.original.validate()?;
        self.owner()?.validate()?;
        self.sha256.validate()?;
        self.upload_sha256.validate()?;
        self.source_manifest_sha256.validate()?;
        match (&self.original.object, &self.source_cursor) {
            (OciObjectOriginal::Chunk { .. }, None) => {}
            (OciObjectOriginal::Compose { sources, .. }, Some(cursor)) => {
                cursor.sha256.validate()?;
                ensure!(cursor.index <= sources.count && cursor.total_bytes == self.accepted_bytes
                    && cursor.offset == cursor.sha256.total_bytes
                    && (cursor.index != sources.count || cursor.offset == 0),
                    "OCI source continuation differs from positive parts");
            }
            _ => anyhow::bail!("OCI source continuation belongs to another object kind"),
        }

        ensure!(
            self.next_part > 0
                && self.next_part <= 2049
                && self.sha256.total_bytes == self.accepted_bytes
                && self.upload_sha256.total_bytes
                    == self
                        .original_offset()
                        .checked_add(self.accepted_bytes)
                        .ok_or_else(|| anyhow::anyhow!(
                            "external OCI upload byte count overflow"
                        ))?
                && self.accepted_bytes <= self.maximum_bytes()
                && self.last_part_bytes <= EXTERNAL_OCI_PART_BYTES
                && (self.next_part > 1) == (self.last_part_bytes > 0)
                && match self.phase {
                    Phase::Declared =>
                        self.provider_upload_id.is_none()
                            && self.accepted_bytes == 0
                            && self.last_part_bytes == 0
                            && !self.source_ended
                            && self.closed.is_none(),
                    Phase::Active =>
                        self.provider_upload_id
                            .as_ref()
                            .is_some_and(|id| !id.is_empty() && id.len() <= 2048)
                            && self.closed.is_none(),
                    Phase::Closed =>
                        (self.provider_upload_id.is_some() || self.maximum_bytes() == 0)
                            && self.closed.is_some()
                            && self.source_ended
                            && self.pending.is_none(),
                    Phase::Aborted =>
                        self.provider_upload_id.is_some()
                            && self.closed.is_none()
                            && self.pending.is_none(),
                },
            "external OCI session lifecycle inconsistent"
        );
        if let Some(pending) = &self.pending {
            ensure!(
                digest_string(&pending.dispatch_nonce)
                    && pending.effect_digest
                        == digest(&(
                            "aos.external-oci-effect.v1",
                            self.original.fingerprint()?,
                            &pending.effect
                        ))?,
                "external OCI pending original differs"
            );
            self.validate_effect(&pending.effect)?;
        }
        if let Some(closed) = &self.closed {
            closed.bytes.validate()?;
            closed
                .incarnation
                .validate(self.original.scope.physical_authority_id.as_str())?;
            ensure!(
                closed.bytes.size == self.accepted_bytes
                    && closed.bytes.sha256 == self.sha256.final_digest()?.encoded()
                    && digest_string(&closed.receipt_digest)
                    && aos_hub_core::surface_write::strong_if_match_etag(&closed.etag)?
                        == closed.etag,
                "external OCI positive closure differs from counted bytes"
            );
        }
        Ok(())
    }

    pub(super) fn begin(&self, effect: Effect, dispatch_nonce: String) -> Result<Self> {
        self.validate()?;
        ensure!(
            self.pending.is_none(),
            "external OCI physical outcome remains unknown"
        );
        self.validate_effect(&effect)?;
        ensure!(
            digest_string(&dispatch_nonce),
            "external OCI dispatch nonce malformed"
        );
        let mut next = self.clone();
        next.pending = Some(Pending {
            effect_digest: digest(&(
                "aos.external-oci-effect.v1",
                self.original.fingerprint()?,
                &effect,
            ))?,
            effect,
            dispatch_nonce,
        });
        next.validate()?;
        Ok(next)
    }

    pub(super) fn acknowledge(&self, receipt: &Receipt) -> Result<Self> {
        self.validate()?;
        ensure!(
            receipt.original_digest == self.original.fingerprint()?
                && self.pending.as_ref() == Some(&receipt.pending),
            "external OCI receipt differs from retained original/attempt"
        );
        let mut next = self.clone();
        match (&receipt.pending.effect, &receipt.positive) {
            (Effect::Create, Positive::Created { upload_id }) => {
                ensure!(
                    !upload_id.is_empty()
                        && upload_id.len() <= 2048
                        && !upload_id.chars().any(char::is_control),
                    "external OCI provider upload identity malformed"
                );
                next.provider_upload_id = Some(upload_id.clone());
                next.phase = Phase::Active;
            }
            (
                Effect::Part {
                    bytes,
                    next_sha256,
                    next_upload_sha256,
                    next_source_cursor,
                    ..
                },
                Positive::Part { etag },
            ) => {
                ensure!(
                    aos_hub_core::surface_write::strong_if_match_etag(etag)? == *etag,
                    "external OCI part receipt has no strong identity"
                );
                next.accepted_bytes = self
                    .accepted_bytes
                    .checked_add(bytes.size)
                    .ok_or_else(|| anyhow::anyhow!("external OCI byte count overflow"))?;
                next.next_part += 1;
                next.last_part_bytes = bytes.size;
                next.sha256 = next_sha256.clone();
                next.upload_sha256 = next_upload_sha256.clone();
                next.source_cursor = next_source_cursor.clone();
            }
            (Effect::Complete { bytes, .. } | Effect::EmptyPut { bytes },
                Positive::Completed { etag, incarnation }) => {
                incarnation.validate(self.original.scope.physical_authority_id.as_str())?;
                next.closed = Some(Closed {
                    bytes: bytes.clone(),
                    etag: etag.clone(),
                    incarnation: incarnation.clone(),
                    receipt_digest: digest(receipt)?,
                });
                next.phase = Phase::Closed;
                next.source_ended = true;
            }
            (Effect::Abort, Positive::Aborted) => next.phase = Phase::Aborted,
            _ => anyhow::bail!("external OCI acknowledgement is not the exact positive effect"),
        }
        next.pending = None;
        next.validate()?;
        Ok(next)
    }

    /// Retains actual source EOF after every submitted byte has a positive receipt.
    ///
    /// This is called by the byte executor only after its reader returned EOF.
    /// Header lengths, a maximum-size boundary and provider HEAD are insufficient.
    pub(super) fn seal_source(&self, bytes: &OciBytes) -> Result<Self> {
        self.validate()?;
        bytes.validate()?;
        ensure!(
            self.phase == Phase::Active
                && self.pending.is_none()
                && self.next_part > 1
                && self.accepted_bytes == bytes.size
                && self.sha256.final_digest()?.encoded() == bytes.sha256,
            "external OCI EOF differs from positively accepted bytes"
        );
        let expected = match &self.original.object {
            OciObjectOriginal::Chunk { expected, .. } => expected.as_ref(),
            OciObjectOriginal::Compose { expected, .. } => Some(expected),
        };
        ensure!(
            expected.is_none_or(|expected| expected == bytes),
            "external OCI EOF differs from the retained expected identity"
        );
        let mut next = self.clone();
        next.source_ended = true;
        next.validate()?;
        Ok(next)
    }

    fn maximum_bytes(&self) -> u64 {
        match &self.original.object {
            OciObjectOriginal::Chunk { maximum_bytes, .. } => *maximum_bytes,
            OciObjectOriginal::Compose { expected, .. } => expected.size,
        }
    }

    fn original_offset(&self) -> u64 {
        match &self.original.object {
            OciObjectOriginal::Chunk { offset, .. } => *offset,
            OciObjectOriginal::Compose { .. } => 0,
        }
    }

    /// Appends only a previously absent ordered declaration page.
    ///
    /// The storage adapter handles exact page replay before this transition.
    /// A complete manifest must match the original before any source is read.
    pub(super) fn append_sources(
        &self,
        first: u32,
        sources: &[aos_hub_core::storage_authority::external_object::oci::OciSourceOriginal],
    ) -> Result<Self> {
        self.validate()?;
        let OciObjectOriginal::Compose {
            sources: manifest, ..
        } = &self.original.object
        else {
            anyhow::bail!("source declaration requires a composition original");
        };
        ensure!(self.phase == Phase::Declared && self.pending.is_none()
            && first == self.source_count && !sources.is_empty()
            && sources.len() <= aos_hub_core::storage_authority::external_object::oci::control::MAX_EXTERNAL_OCI_SOURCE_PAGE,
            "external OCI source page changed or skipped");
        let mut next = self.clone();
        for source in sources {
            source.bytes.validate()?;
            source
                .incarnation
                .validate(self.original.scope.physical_authority_id.as_str())?;
            next.source_count = next
                .source_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("external OCI source count overflow"))?;
            next.source_bytes = next
                .source_bytes
                .checked_add(source.bytes.size)
                .ok_or_else(|| anyhow::anyhow!("external OCI source byte count overflow"))?;
            OciSourceManifest::append_hash(&mut next.source_manifest_sha256, source)?;
        }
        ensure!(
            next.source_count <= manifest.count && next.source_bytes <= manifest.bytes,
            "external OCI source page exceeds full original"
        );
        if next.source_count == manifest.count {
            ensure!(
                next.source_bytes == manifest.bytes
                    && next.source_manifest_sha256.final_digest()?.encoded() == manifest.sha256,
                "external OCI complete source declaration differs"
            );
        }
        next.validate()?;
        Ok(next)
    }

    fn validate_effect(&self, effect: &Effect) -> Result<()> {
        match effect {
            Effect::Create => ensure!(
                self.phase == Phase::Declared,
                "external OCI Create original already used"
            ),
            Effect::EmptyPut { bytes } => {
                bytes.validate()?;
                ensure!(self.phase == Phase::Declared && self.provider_upload_id.is_none()
                    && bytes.size == 0 && self.accepted_bytes == 0
                    && bytes.sha256 == self.sha256.final_digest()?.encoded(),
                    "empty OCI PUT lacks the exact empty byte identity");
                let OciObjectOriginal::Compose { expected, sources } = &self.original.object else {
                    anyhow::bail!("empty OCI PUT requires the real canonical claim");
                };
                ensure!(expected == bytes && sources.count == 0 && sources.bytes == 0
                    && self.source_count == 0 && self.source_bytes == 0
                    && self.source_manifest_sha256.final_digest()?.encoded() == sources.sha256,
                    "empty OCI PUT differs from the retained complete source declaration");
            }
            Effect::Part {
                part_number,
                bytes,
                checksum_md5,
                next_sha256,
                next_upload_sha256,
                next_source_cursor,
            } => {
                use base64::Engine as _;
                bytes.validate()?;
                next_sha256.validate()?;
                next_upload_sha256.validate()?;
                match (&self.source_cursor, next_source_cursor) {
                    (None, None) => {}
                    (Some(prior), Some(next)) => {
                        next.sha256.validate()?;
                        ensure!(next.total_bytes == next_sha256.total_bytes
                            && next.total_bytes > prior.total_bytes && next.index >= prior.index
                            && next.offset == next.sha256.total_bytes,
                            "OCI materialization changed its positive source continuation");
                    }
                    _ => anyhow::bail!("OCI part changed its source continuation kind"),
                }
                let checksum = base64::engine::general_purpose::STANDARD.decode(checksum_md5)?;
                ensure!(
                    self.phase == Phase::Active
                        && !self.source_ended
                        && (self.next_part == 1 || self.last_part_bytes == EXTERNAL_OCI_PART_BYTES)
                        && *part_number == self.next_part
                        && bytes.size > 0
                        && bytes.size <= EXTERNAL_OCI_PART_BYTES
                        && checksum.len() == 16
                        && base64::engine::general_purpose::STANDARD.encode(checksum)
                            == *checksum_md5
                        && next_upload_sha256.total_bytes
                            == self
                                .original_offset()
                                .checked_add(next_sha256.total_bytes)
                                .ok_or_else(|| anyhow::anyhow!(
                                    "external OCI upload byte count overflow"
                                ))?
                        && self
                            .accepted_bytes
                            .checked_add(bytes.size)
                            .is_some_and(|total| total <= self.maximum_bytes()
                                && total == next_sha256.total_bytes),
                    "external OCI part differs from contiguous bounded original"
                );
                if let OciObjectOriginal::Compose { sources, .. } = &self.original.object {
                    let cursor = next_source_cursor.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("OCI materialization part lacks its source continuation"))?;
                    ensure!(cursor.index <= sources.count
                        && (cursor.index != sources.count || cursor.offset == 0),
                        "OCI part source cursor escapes the declared manifest");
                    ensure!(
                        self.source_count == sources.count
                            && self.source_bytes == sources.bytes
                            && self.source_manifest_sha256.final_digest()?.encoded()
                                == sources.sha256,
                        "external OCI sources are incomplete or unverified"
                    );
                }
            }
            Effect::Complete {
                bytes,
                parts_digest,
            } => {
                bytes.validate()?;
                ensure!(
                    self.phase == Phase::Active
                        && self.source_ended
                        && self.accepted_bytes == bytes.size
                        && self.sha256.final_digest()?.encoded() == bytes.sha256
                        && digest_string(parts_digest)
                        && self.next_part > 1,
                    "external OCI Complete lacks exact retained full-byte proof"
                );
                let expected = match &self.original.object {
                    OciObjectOriginal::Chunk { expected, .. } => expected.as_ref(),
                    OciObjectOriginal::Compose { expected, .. } => Some(expected),
                };
                ensure!(
                    expected.is_none_or(|expected| expected == bytes),
                    "external OCI Complete differs from claimed content identity"
                );
            }
            Effect::Abort => ensure!(
                self.phase == Phase::Active,
                "external OCI Abort lacks a positively known incomplete upload"
            ),
        }
        Ok(())
    }
}
