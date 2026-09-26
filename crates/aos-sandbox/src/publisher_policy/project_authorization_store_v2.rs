//! Protected, nonauthorizing retention of signed project-limit decisions.
//!
//! The publisher owner commits one immutable request row and its current
//! epoch head in a single protected journal transaction. Historical rows
//! replay against their immutable AOSPOLR1 revision and reconstructable
//! AOSPOLH1 pointer; a current read separately rejects a later publisher
//! head. Cold load validates structure only. The current authenticated read
//! separately obtains the fixed issuer credential and reverifies the exact
//! packet; retained rows alone are not authority. No Source seed or Create
//! capability is issued here.
//!
//! ```text
//! project-auth/row/<project:16><request:16> =
//!   AOSPAUR2 | project:16 | request:16 | epoch:u64be |
//!   issuer-generation:u64be | publisher-generation:u64be |
//!   AOSPOLH1-digest:32 | AOSPOLR1-digest:32 | packet-digest:32 |
//!   seven ceilings:u32be each | exact AOSPSC02 packet:224
//! project-auth/current/<project:16> =
//!   AOSPAUH2 | project:16 | epoch:u64be | request:16 | row-digest:32
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId};
#[cfg(any(target_os = "linux", test))]
use thiserror::Error;

use crate::controller_service::journal::production_journal_limits;
use crate::hierarchy::model::TreeLimitsV1;
#[cfg(target_os = "linux")]
use crate::hierarchy::source_seed::verify_controller_source_tree_seed_from_fixed_issuer_v1;
#[cfg(any(target_os = "linux", test))]
use crate::hierarchy::source_seed::{
    ControllerSourceTreeSeedErrorV1, ControllerSourceTreeSeedExpectedV1,
    VerifiedControllerSourceTreeSeedV1,
};
use crate::journal::{CommitResult, Journal, JournalRecord, RecordNamespace};

use super::project_authorization_source_v2::{
    HEAD_DOMAIN, PACKET_BYTES, PACKET_DOMAIN, PinnedPublisherProjectAuthorizationIssuerV2,
    ProjectAuthorizationSourceErrorV2, ProjectAuthorizationSourceExpectedV2,
    ProtectedProjectAuthorizationIssuerV2, REVISION_DOMAIN,
    VerifiedPublisherProjectAuthorizationSourceV2, commitment,
    parse_unverified_project_authorization_claims_v2,
    verify_current_project_authorization_source_v2,
};
use super::{
    PublisherPolicyError, PublisherPolicyStore, decode_policy_revision, encode_policy_head,
    policy_current_key, policy_revision_key,
};

pub(super) const ROW_PREFIX: &[u8] = b"project-auth/row/";
pub(super) const HEAD_PREFIX: &[u8] = b"project-auth/current/";
const ROW_MAGIC: &[u8; 8] = b"AOSPAUR2";
const HEAD_MAGIC: &[u8; 8] = b"AOSPAUH2";
const ROW_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization.row.v2\0";
// The seed binds the exact retained pointer, including its epoch and row digest.
#[cfg(any(target_os = "linux", test))]
const RETAINED_HEAD_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization.retained-current-head.v2\0";
const ROW_BYTES: usize = 188 + PACKET_BYTES;
const HEAD_BYTES: usize = 80;
const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RetainedProjectAuthorizationRowV2 {
    pub(super) project: ProjectId,
    pub(super) request_id: [u8; 16],
    pub(super) epoch: u64,
    issuer_generation: u64,
    publisher_generation: u64,
    publisher_head_digest: ObjectDigest,
    publisher_revision_digest: ObjectDigest,
    packet_digest: ObjectDigest,
    limits: TreeLimitsV1,
    packet: [u8; PACKET_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RetainedProjectAuthorizationHeadV2 {
    pub(super) project: ProjectId,
    epoch: u64,
    request_id: [u8; 16],
    row_digest: ObjectDigest,
}

/// Describes only the durability result, never Source or Create authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectAuthorizationRetentionV2 {
    Committed(CommitResult),
    ExactReplay,
}

/// Reports why a Controller-held initial-tree seed preflight is unavailable.
///
/// Passing this preflight does not spend the seed epoch or authorize Source
/// journal mutation.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Error)]
pub(crate) enum CurrentSourceTreeSeedPreflightErrorV1 {
    /// No authenticated project decision is current for the requested project.
    #[error("no current project authorization is retained")]
    MissingAuthorization,
    /// The retained decision or its fixed issuer is unavailable or stale.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
    /// The seed or its distinct fixed issuer is unavailable or stale.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
}

pub(super) fn row_key(project: ProjectId, request_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ROW_PREFIX.len() + 32);
    key.extend_from_slice(ROW_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(&request_id);
    key
}

pub(super) fn head_key(project: ProjectId) -> Vec<u8> {
    let mut key = Vec::with_capacity(HEAD_PREFIX.len() + 16);
    key.extend_from_slice(HEAD_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key
}

pub(super) fn project_auth_row_digest(bytes: &[u8]) -> ObjectDigest {
    commitment(ROW_DOMAIN, bytes)
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PublisherPolicyError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(PublisherPolicyError::CorruptState)
}

fn encode_row(value: &RetainedProjectAuthorizationRowV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ROW_BYTES);
    bytes.extend_from_slice(ROW_MAGIC);
    bytes.extend_from_slice(value.project.as_bytes());
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.epoch.to_be_bytes());
    bytes.extend_from_slice(&value.issuer_generation.to_be_bytes());
    bytes.extend_from_slice(&value.publisher_generation.to_be_bytes());
    bytes.extend_from_slice(value.publisher_head_digest.as_bytes());
    bytes.extend_from_slice(value.publisher_revision_digest.as_bytes());
    bytes.extend_from_slice(value.packet_digest.as_bytes());
    for limit in [
        value.limits.maximum_project_roots(),
        value.limits.maximum_project_sandboxes(),
        value.limits.maximum_project_live_sandboxes(),
        value.limits.maximum_depth(),
        value.limits.maximum_children_per_parent(),
        value.limits.maximum_descendants(),
        value.limits.maximum_live_descendants(),
    ] {
        bytes.extend_from_slice(&(limit as u32).to_be_bytes());
    }
    bytes.extend_from_slice(&value.packet);
    bytes
}

pub(super) fn decode_row(
    bytes: &[u8],
) -> Result<RetainedProjectAuthorizationRowV2, PublisherPolicyError> {
    if bytes.len() != ROW_BYTES || bytes.get(..8) != Some(ROW_MAGIC) {
        return Err(PublisherPolicyError::CorruptState);
    }
    let limits = TreeLimitsV1::new(
        u32::from_be_bytes(take::<4>(bytes, 160)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 164)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 168)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 172)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 176)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 180)?) as usize,
        u32::from_be_bytes(take::<4>(bytes, 184)?) as usize,
    )
    .map_err(|_| PublisherPolicyError::CorruptState)?;
    let row = RetainedProjectAuthorizationRowV2 {
        project: ProjectId::from_bytes(take::<16>(bytes, 8)?),
        request_id: take::<16>(bytes, 24)?,
        epoch: u64::from_be_bytes(take::<8>(bytes, 40)?),
        issuer_generation: u64::from_be_bytes(take::<8>(bytes, 48)?),
        publisher_generation: u64::from_be_bytes(take::<8>(bytes, 56)?),
        publisher_head_digest: ObjectDigest::from_bytes(take::<32>(bytes, 64)?),
        publisher_revision_digest: ObjectDigest::from_bytes(take::<32>(bytes, 96)?),
        packet_digest: ObjectDigest::from_bytes(take::<32>(bytes, 128)?),
        limits,
        packet: take::<PACKET_BYTES>(bytes, 188)?,
    };
    let claims = parse_unverified_project_authorization_claims_v2(&row.packet)
        .map_err(|_| PublisherPolicyError::CorruptState)?;
    if row.project != claims.project
        || row.request_id != claims.request_id
        || row.epoch != claims.epoch
        || row.issuer_generation != claims.issuer_generation
        || row.publisher_generation != claims.publisher_generation
        || row.publisher_head_digest != claims.publisher_head_digest
        || row.publisher_revision_digest != claims.publisher_revision_digest
        || row.limits != claims.limits
        || row.packet_digest != commitment(PACKET_DOMAIN, &row.packet)
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(row)
}

fn encode_head(value: RetainedProjectAuthorizationHeadV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEAD_BYTES);
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(value.project.as_bytes());
    bytes.extend_from_slice(&value.epoch.to_be_bytes());
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(value.row_digest.as_bytes());
    bytes
}

pub(super) fn decode_head(
    bytes: &[u8],
) -> Result<RetainedProjectAuthorizationHeadV2, PublisherPolicyError> {
    if bytes.len() != HEAD_BYTES || bytes.get(..8) != Some(HEAD_MAGIC) {
        return Err(PublisherPolicyError::CorruptState);
    }
    let head = RetainedProjectAuthorizationHeadV2 {
        project: ProjectId::from_bytes(take::<16>(bytes, 8)?),
        epoch: u64::from_be_bytes(take::<8>(bytes, 24)?),
        request_id: take::<16>(bytes, 32)?,
        row_digest: ObjectDigest::from_bytes(take::<32>(bytes, 48)?),
    };
    if head.project.as_bytes() == &[0; 16]
        || head.request_id == [0; 16]
        || head.epoch == 0
        || head.row_digest.as_bytes() == &[0; 32]
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(head)
}

fn row_from_verified(
    verified: VerifiedPublisherProjectAuthorizationSourceV2,
    packet: &[u8],
) -> Result<RetainedProjectAuthorizationRowV2, ProjectAuthorizationSourceErrorV2> {
    let packet: [u8; PACKET_BYTES] = packet
        .try_into()
        .map_err(|_| ProjectAuthorizationSourceErrorV2::NonCanonical)?;
    Ok(RetainedProjectAuthorizationRowV2 {
        project: verified.project(),
        request_id: verified.request_id(),
        epoch: verified.epoch(),
        issuer_generation: verified.issuer_generation(),
        publisher_generation: verified.publisher_generation(),
        publisher_head_digest: verified.publisher_head_digest(),
        publisher_revision_digest: verified.publisher_revision_digest(),
        packet_digest: verified.packet_digest(),
        limits: verified.limits(),
        packet,
    })
}

pub(super) fn validate_historical_row(
    journal: &Journal,
    row: &RetainedProjectAuthorizationRowV2,
) -> Result<(), PublisherPolicyError> {
    let revision = journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_revision_key(row.project, row.publisher_generation),
        )
        .ok_or(PublisherPolicyError::CorruptState)?;
    let prepared = decode_policy_revision(revision)?;
    if prepared.project() != row.project
        || prepared.generation() != row.publisher_generation
        || commitment(REVISION_DOMAIN, revision) != row.publisher_revision_digest
        || commitment(HEAD_DOMAIN, &encode_policy_head(&prepared)) != row.publisher_head_digest
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(())
}

pub(super) fn validate_rows_and_heads(
    rows: &BTreeMap<ProjectId, BTreeMap<u64, ([u8; 16], ObjectDigest)>>,
    heads: &BTreeMap<ProjectId, RetainedProjectAuthorizationHeadV2>,
) -> Result<(), PublisherPolicyError> {
    if rows.len() != heads.len() {
        return Err(PublisherPolicyError::CorruptState);
    }
    for (project, epochs) in rows {
        let (&epoch, &(request_id, row_digest)) = epochs
            .last_key_value()
            .ok_or(PublisherPolicyError::CorruptState)?;
        let head = heads
            .get(project)
            .ok_or(PublisherPolicyError::CorruptState)?;
        if head.epoch != epoch || head.request_id != request_id || head.row_digest != row_digest {
            return Err(PublisherPolicyError::CorruptState);
        }
    }
    Ok(())
}

impl PublisherPolicyStore<'_> {
    fn require_fixed_controller_writer_v2(&self) -> Result<(), ProjectAuthorizationSourceErrorV2> {
        let uid = self
            .journal
            .protected_owner_uid()
            .map_err(PublisherPolicyError::from)?;
        self.journal
            .require_protected_named_location(
                Path::new(CONTROLLER_ROOT),
                CONTROLLER_JOURNAL,
                uid,
                production_journal_limits(),
            )
            .map_err(PublisherPolicyError::from)?;
        Ok(())
    }

    /// Checks one seed against the authenticated current Controller row.
    ///
    /// The caller must retain this store's Controller writer. Both issuer
    /// credentials come from their fixed privileged names and are rechecked
    /// around the joined read. The result is only a preflight observation: it
    /// neither spends an epoch nor grants Source append authority.
    ///
    /// # Errors
    ///
    /// Rejects missing or stale current rows, unavailable issuer credentials,
    /// a changed publisher pointer or revision, and any seed mismatch.
    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_current_source_tree_seed_from_fixed_issuers_v1(
        &self,
        project: ProjectId,
        packet: &[u8],
    ) -> Result<VerifiedControllerSourceTreeSeedV1, CurrentSourceTreeSeedPreflightErrorV1> {
        self.require_fixed_controller_writer_v2()?;
        let authorization_issuer =
            ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        authorization_issuer.recheck()?;
        let authorization = self
            .current_authenticated_project_authorization_v2(project, authorization_issuer.pin())?
            .ok_or(CurrentSourceTreeSeedPreflightErrorV1::MissingAuthorization)?;
        let head_digest = self.current_project_authorization_head_digest_v2(project)?;
        let verified = verify_seed_for_current_authorization_v1(
            packet,
            authorization,
            head_digest,
            verify_controller_source_tree_seed_from_fixed_issuer_v1,
        )?;
        authorization_issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(verified)
    }

    #[cfg(any(target_os = "linux", test))]
    fn current_project_authorization_head_digest_v2(
        &self,
        project: ProjectId,
    ) -> Result<ObjectDigest, ProjectAuthorizationSourceErrorV2> {
        // The preceding authenticated read validated this pair. The store's
        // Controller writer prevents either record changing before this read.
        let head_bytes = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        Ok(commitment(RETAINED_HEAD_DOMAIN, head_bytes))
    }

    /// Authenticates the current retained decision with the fixed issuer pin.
    ///
    /// Structural journal replay does not establish the AOSPSC02 signature.
    /// A future Source consumer must use this read while retaining the
    /// Controller writer, then keep that writer through its Source append.
    ///
    /// # Errors
    ///
    /// Rejects missing or replaced credential custody, a changed publisher
    /// head, invalid signature, or a retained row inconsistent with its packet.
    pub(crate) fn current_authenticated_project_authorization_from_fixed_issuer_v2(
        &self,
        project: ProjectId,
    ) -> Result<
        Option<VerifiedPublisherProjectAuthorizationSourceV2>,
        ProjectAuthorizationSourceErrorV2,
    > {
        self.require_fixed_controller_writer_v2()?;
        let issuer = ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        issuer.recheck()?;
        let current = self.current_authenticated_project_authorization_v2(project, issuer.pin())?;
        issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(current)
    }

    fn current_authenticated_project_authorization_v2(
        &self,
        project: ProjectId,
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<
        Option<VerifiedPublisherProjectAuthorizationSourceV2>,
        ProjectAuthorizationSourceErrorV2,
    > {
        let Some(row) = self.current_retained_project_authorization_v2(project)? else {
            return Ok(None);
        };
        let floor = row
            .epoch
            .checked_sub(1)
            .ok_or(PublisherPolicyError::CorruptState)?;
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, row.request_id, floor)?;
        let verified =
            verify_current_project_authorization_source_v2(self, &row.packet, issuer, expected)?;
        if verified.project() != row.project
            || verified.request_id() != row.request_id
            || verified.epoch() != row.epoch
            || verified.issuer_generation() != row.issuer_generation
            || verified.publisher_generation() != row.publisher_generation
            || verified.publisher_head_digest() != row.publisher_head_digest
            || verified.publisher_revision_digest() != row.publisher_revision_digest
            || verified.packet_digest() != row.packet_digest
            || verified.limits() != row.limits
        {
            return Err(PublisherPolicyError::CorruptState.into());
        }
        Ok(Some(verified))
    }

    /// Retains a signed decision using the fixed privileged issuer credential.
    ///
    /// The credential is rechecked around the protected journal transaction.
    /// This is an owner-internal retention step, not Source append authority.
    ///
    /// # Errors
    ///
    /// Rejects absent, malformed, or replaced issuer custody and all invalid
    /// packet, current-head, or journal states.
    pub(super) fn retain_project_authorization_from_fixed_issuer_v2(
        &mut self,
        transaction_id: [u8; 16],
        project: ProjectId,
        request_id: [u8; 16],
        packet: &[u8],
    ) -> Result<ProjectAuthorizationRetentionV2, ProjectAuthorizationSourceErrorV2> {
        self.require_fixed_controller_writer_v2()?;
        let issuer = ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        issuer.recheck()?;
        let result = self.retain_project_authorization_source_v2(
            transaction_id,
            project,
            request_id,
            packet,
            issuer.pin(),
        )?;
        issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(result)
    }

    /// Retains a signed administrative decision with an already checked pin.
    ///
    /// Only the fixed-credential entry point may call this in production.
    ///
    /// # Errors
    ///
    /// Rejects changed publisher heads, signer/request/epoch reuse, malformed
    /// rows, or journal errors. An I/O error requires a fresh protected reopen.
    fn retain_project_authorization_source_v2(
        &mut self,
        transaction_id: [u8; 16],
        project: ProjectId,
        request_id: [u8; 16],
        packet: &[u8],
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<ProjectAuthorizationRetentionV2, ProjectAuthorizationSourceErrorV2> {
        self.journal
            .ensure_protected_authority()
            .map_err(PublisherPolicyError::from)?;
        let head = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
            .map(decode_head)
            .transpose()?;
        let previous = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &row_key(project, request_id),
            )
            .map(decode_row)
            .transpose()?;
        let exact_replay = previous.as_ref().is_some_and(|row| {
            row.packet == packet
                && head.is_some_and(|head| {
                    head.request_id == request_id
                        && head.epoch == row.epoch
                        && head.row_digest == commitment(ROW_DOMAIN, &encode_row(row))
                })
        });
        if previous.is_some() && !exact_replay {
            return Err(ProjectAuthorizationSourceErrorV2::Stale);
        }
        let floor = if exact_replay {
            head.ok_or(ProjectAuthorizationSourceErrorV2::Stale)?
                .epoch
                .checked_sub(1)
                .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?
        } else {
            head.map_or(0, |head| head.epoch)
        };
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, request_id, floor)?;
        let verified =
            verify_current_project_authorization_source_v2(self, packet, issuer, expected)?;
        if exact_replay {
            return Ok(ProjectAuthorizationRetentionV2::ExactReplay);
        }

        let row = row_from_verified(verified, packet)?;
        let row_bytes = encode_row(&row);
        let next_head = RetainedProjectAuthorizationHeadV2 {
            project,
            epoch: row.epoch,
            request_id,
            row_digest: commitment(ROW_DOMAIN, &row_bytes),
        };
        let result = self.commit_bounded(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    row_key(project, request_id),
                    row_bytes,
                ),
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    head_key(project),
                    encode_head(next_head),
                ),
            ],
        )?;
        Ok(ProjectAuthorizationRetentionV2::Committed(result))
    }

    /// Reads the retained current decision only while its publisher cut matches.
    ///
    /// This read does not reverify the issuer signature and is not a Source
    /// seed capability. A subsequent policy update leaves historical rows
    /// replayable while making the current decision stale.
    ///
    /// # Errors
    ///
    /// Rejects a malformed retained pair, missing policy, or changed pointer
    /// or revision bytes.
    fn current_retained_project_authorization_v2(
        &self,
        project: ProjectId,
    ) -> Result<Option<RetainedProjectAuthorizationRowV2>, ProjectAuthorizationSourceErrorV2> {
        self.journal
            .ensure_protected_authority()
            .map_err(PublisherPolicyError::from)?;
        let Some(head_bytes) = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
        else {
            return Ok(None);
        };
        let head = decode_head(head_bytes)?;
        let row_bytes = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &row_key(project, head.request_id),
            )
            .ok_or(PublisherPolicyError::CorruptState)?;
        let row = decode_row(row_bytes)?;
        if head.project != project
            || head.epoch != row.epoch
            || head.row_digest != commitment(ROW_DOMAIN, row_bytes)
        {
            return Err(PublisherPolicyError::CorruptState.into());
        }
        let current = self
            .current_policy(project)?
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let current_head = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_current_key(project),
            )
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let current_revision = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, current.generation()),
            )
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        if row.publisher_generation != current.generation()
            || row.publisher_head_digest != commitment(HEAD_DOMAIN, current_head)
            || row.publisher_revision_digest != commitment(REVISION_DOMAIN, current_revision)
        {
            return Err(ProjectAuthorizationSourceErrorV2::Stale);
        }
        Ok(Some(row))
    }
}

#[cfg(any(target_os = "linux", test))]
fn verify_seed_for_current_authorization_v1(
    packet: &[u8],
    authorization: VerifiedPublisherProjectAuthorizationSourceV2,
    authorization_head_digest: ObjectDigest,
    verify_seed: impl FnOnce(
        &[u8],
        ControllerSourceTreeSeedExpectedV1,
    ) -> Result<
        VerifiedControllerSourceTreeSeedV1,
        ControllerSourceTreeSeedErrorV1,
    >,
) -> Result<VerifiedControllerSourceTreeSeedV1, CurrentSourceTreeSeedPreflightErrorV1> {
    let epoch_floor = authorization
        .epoch()
        .checked_sub(1)
        .ok_or(ControllerSourceTreeSeedErrorV1::Stale)?;
    let expected = ControllerSourceTreeSeedExpectedV1::new(
        authorization.project(),
        authorization.publisher_generation(),
        authorization.publisher_head_digest(),
        authorization_head_digest,
        authorization.request_id(),
        epoch_floor,
    )?;
    let verified = verify_seed(packet, expected)?;
    if verified.seed().epoch() != authorization.epoch()
        || verified.seed().limits() != authorization.limits()
    {
        return Err(ControllerSourceTreeSeedErrorV1::Stale.into());
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::JournalTransaction;
    use crate::hierarchy::source_seed::{
        ControllerSourceTreeSeedV1, PinnedControllerSourceTreeSeedIssuerV1,
        encode_controller_source_tree_seed_credential_v1, sign_controller_source_tree_seed_v1,
        verify_controller_source_tree_seed_v1,
    };

    use super::*;
    use crate::publisher_policy::project_authorization_test_fixture::{
        TestDirectory, packet as signed_packet, pin as issuer_pin, policy as policy_at,
    };
    use crate::publisher_policy::{PreparedPublisherPolicyRevisionV1, PublisherPolicyLimits};

    fn policy(project: ProjectId, generation: u64) -> PreparedPublisherPolicyRevisionV1 {
        policy_at(project, generation, 100)
    }

    fn packet(
        store: &PublisherPolicyStore<'_>,
        project: ProjectId,
        request_id: [u8; 16],
        epoch: u64,
        signer: &SigningKey,
    ) -> [u8; PACKET_BYTES] {
        signed_packet(store, project, signer, 7, request_id, epoch)
    }

    fn pin(signer: &SigningKey) -> PinnedPublisherProjectAuthorizationIssuerV2 {
        issuer_pin(signer, 7)
    }

    fn initial_store(journal: &mut Journal, project: ProjectId) -> PublisherPolicyStore<'_> {
        let mut store =
            PublisherPolicyStore::load(journal, PublisherPolicyLimits::default()).unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], None, &policy(project, 1))
            .unwrap();
        store
    }

    #[test]
    fn current_seed_preflight_joins_both_signatures_and_exact_controller_cut() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let authorization_signer = SigningKey::from_bytes(&[2; 32]);
        let seed_signer = SigningKey::from_bytes(&[42; 32]);
        let seed_credential =
            encode_controller_source_tree_seed_credential_v1(11, &seed_signer.verifying_key())
                .unwrap();
        let seed_issuer = PinnedControllerSourceTreeSeedIssuerV1::decode(&seed_credential).unwrap();
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let authorization_packet = packet(&store, project, [4; 16], 9, &authorization_signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &authorization_packet,
                &pin(&authorization_signer),
            )
            .unwrap();
        let authorization = store
            .current_authenticated_project_authorization_v2(project, &pin(&authorization_signer))
            .unwrap()
            .unwrap();
        let head_digest = store
            .current_project_authorization_head_digest_v2(project)
            .unwrap();
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            authorization.limits(),
            authorization.publisher_generation(),
            authorization.publisher_head_digest(),
            head_digest,
            authorization.request_id(),
            authorization.epoch(),
        )
        .unwrap();
        let seed_packet =
            sign_controller_source_tree_seed_v1(seed, seed_issuer.generation(), &seed_signer)
                .unwrap();
        let verify = |packet: &[u8], expected| {
            verify_controller_source_tree_seed_v1(packet, &seed_issuer, expected)
        };
        assert_eq!(
            verify_seed_for_current_authorization_v1(
                &seed_packet,
                authorization,
                head_digest,
                verify,
            )
            .unwrap()
            .seed(),
            seed
        );

        let mismatch = |seed: ControllerSourceTreeSeedV1| {
            let packet =
                sign_controller_source_tree_seed_v1(seed, seed_issuer.generation(), &seed_signer)
                    .unwrap();
            verify_seed_for_current_authorization_v1(
                &packet,
                authorization,
                head_digest,
                |packet, expected| {
                    verify_controller_source_tree_seed_v1(packet, &seed_issuer, expected)
                },
            )
        };
        let changed =
            |limits, publisher_generation, publisher_head, authorization_head, request, epoch| {
                ControllerSourceTreeSeedV1::new(
                    project,
                    limits,
                    publisher_generation,
                    publisher_head,
                    authorization_head,
                    request,
                    epoch,
                )
                .unwrap()
            };
        for altered in [
            changed(
                seed.limits(),
                2,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                ObjectDigest::from_bytes([8; 32]),
                head_digest,
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                ObjectDigest::from_bytes([8; 32]),
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                head_digest,
                [8; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                10,
            ),
            changed(
                TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 2).unwrap(),
                1,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                9,
            ),
        ] {
            assert!(matches!(
                mismatch(altered),
                Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                    ControllerSourceTreeSeedErrorV1::Stale
                ))
            ));
        }

        let rotated_key = SigningKey::from_bytes(&[43; 32]);
        let rotated_credential =
            encode_controller_source_tree_seed_credential_v1(11, &rotated_key.verifying_key())
                .unwrap();
        let rotated_issuer =
            PinnedControllerSourceTreeSeedIssuerV1::decode(&rotated_credential).unwrap();
        assert!(matches!(
            verify_seed_for_current_authorization_v1(
                &seed_packet,
                authorization,
                head_digest,
                |packet, expected| {
                    verify_controller_source_tree_seed_v1(packet, &rotated_issuer, expected)
                },
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                ControllerSourceTreeSeedErrorV1::Signature
            ))
        ));

        store
            .publish_policy_from_trusted_controller([6; 16], Some(1), &policy(project, 2))
            .unwrap();
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(
                project,
                &pin(&authorization_signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn copied_protected_controller_rows_cannot_pass_fixed_current_reads() {
        let source_directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let authorization_signer = SigningKey::from_bytes(&[2; 32]);
        let mut source_journal = source_directory.open();
        let mut source = initial_store(&mut source_journal, project);
        let authorization_packet = packet(&source, project, [4; 16], 9, &authorization_signer);
        source
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &authorization_packet,
                &pin(&authorization_signer),
            )
            .unwrap();
        let copied_records = source
            .journal
            .all_records()
            .map(|(namespace, key, value)| {
                JournalRecord::put(namespace, key.to_vec(), value.to_vec())
            })
            .collect();
        drop(source);
        drop(source_journal);

        let copy_directory = TestDirectory::new();
        let mut copied_journal = copy_directory.open_with_limits(production_journal_limits());
        copied_journal
            .commit(&JournalTransaction::new([99; 16], copied_records).unwrap())
            .unwrap();
        let copy =
            PublisherPolicyStore::load(&mut copied_journal, PublisherPolicyLimits::default())
                .unwrap();
        let authorization = copy
            .current_authenticated_project_authorization_v2(project, &pin(&authorization_signer))
            .unwrap()
            .unwrap();
        let authorization_head = copy
            .current_project_authorization_head_digest_v2(project)
            .unwrap();
        let seed_signer = SigningKey::from_bytes(&[42; 32]);
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            authorization.limits(),
            authorization.publisher_generation(),
            authorization.publisher_head_digest(),
            authorization_head,
            authorization.request_id(),
            authorization.epoch(),
        )
        .unwrap();
        let seed_packet = sign_controller_source_tree_seed_v1(seed, 11, &seed_signer).unwrap();

        assert!(matches!(
            copy.current_authenticated_project_authorization_from_fixed_issuer_v2(project),
            Err(ProjectAuthorizationSourceErrorV2::Publisher(
                PublisherPolicyError::Journal(_)
            ))
        ));
        assert!(matches!(
            copy.preflight_current_source_tree_seed_from_fixed_issuers_v1(project, &seed_packet),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Publisher(PublisherPolicyError::Journal(_))
            ))
        ));
    }

    #[test]
    fn exact_attempt_survives_cold_replay_and_spends_request_and_epoch() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Ok(ProjectAuthorizationRetentionV2::Committed(_))
        ));
        let current = store
            .current_retained_project_authorization_v2(project)
            .unwrap()
            .unwrap();
        assert_eq!(current.packet, first);
        assert_eq!(current.issuer_generation, 7);
        assert_eq!(
            current.limits,
            TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap()
        );
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        let authenticated = store
            .current_authenticated_project_authorization_v2(project, &pin(&signer))
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.request_id(), [4; 16]);
        assert_eq!(authenticated.epoch(), 9);
        assert_eq!(authenticated.limits(), current.limits);
        assert_eq!(
            store
                .retain_project_authorization_source_v2(
                    [6; 16],
                    project,
                    [4; 16],
                    &first,
                    &pin(&signer)
                )
                .unwrap(),
            ProjectAuthorizationRetentionV2::ExactReplay
        );
        let duplicate_epoch = packet(&store, project, [7; 16], 9, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [8; 16],
                project,
                [7; 16],
                &duplicate_epoch,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        let collision = packet(&store, project, [4; 16], 10, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [9; 16],
                project,
                [4; 16],
                &collision,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        let second = packet(&store, project, [7; 16], 10, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [10; 16],
                project,
                [7; 16],
                &second,
                &pin(&signer)
            ),
            Ok(ProjectAuthorizationRetentionV2::Committed(_))
        ));
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [11; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn policy_advance_preserves_history_but_stales_current_authorization() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        store
            .publish_policy_from_trusted_controller([6; 16], Some(1), &policy(project, 2))
            .unwrap();
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert!(matches!(
            store.current_retained_project_authorization_v2(project),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&signer)),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [7; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn incomplete_pair_and_changed_historical_revision_fail_cold_replay() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        let second = packet(&store, project, [7; 16], 10, &signer);
        let verified = verify_current_project_authorization_source_v2(
            &store,
            &second,
            &pin(&signer),
            ProjectAuthorizationSourceExpectedV2::new(project, [7; 16], 9).unwrap(),
        )
        .unwrap();
        let orphan_row = row_from_verified(verified, &second).unwrap();
        drop(store);
        journal
            .commit(
                &JournalTransaction::new(
                    [6; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        row_key(project, [7; 16]),
                        encode_row(&orphan_row),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        let mut reopened = directory.open();
        assert!(matches!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()),
            Err(PublisherPolicyError::CorruptState)
        ));

        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        drop(store);
        let changed = policy_at(project, 1, 101);
        let revision = super::super::encode_policy_revision(&changed).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [8; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        policy_revision_key(project, 1),
                        revision,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        let mut reopened = directory.open();
        assert!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).is_err()
        );
    }

    #[test]
    fn changed_row_packet_or_head_digest_fails_cold_replay() {
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        for corrupt_row in [true, false] {
            let directory = TestDirectory::new();
            let mut journal = directory.open();
            let mut store = initial_store(&mut journal, project);
            let first = packet(&store, project, [4; 16], 9, &signer);
            store
                .retain_project_authorization_source_v2(
                    [5; 16],
                    project,
                    [4; 16],
                    &first,
                    &pin(&signer),
                )
                .unwrap();
            drop(store);

            let key = if corrupt_row {
                row_key(project, [4; 16])
            } else {
                head_key(project)
            };
            let mut bytes = journal
                .get(RecordNamespace::PublisherPolicy, &key)
                .unwrap()
                .to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            journal
                .commit(
                    &JournalTransaction::new(
                        [6; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::PublisherPolicy,
                            key,
                            bytes,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);

            let mut reopened = directory.open();
            assert!(matches!(
                PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()),
                Err(PublisherPolicyError::CorruptState)
            ));
        }
    }

    #[test]
    fn cold_current_read_rejects_rotated_issuer_and_rechecks_packet_signature() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let signed = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &signed,
                &pin(&signer),
            )
            .unwrap();
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        let rotated = SigningKey::from_bytes(&[3; 32]);
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&rotated)),
            Err(ProjectAuthorizationSourceErrorV2::Signature)
        ));
        drop(store);
        drop(reopened);

        let mut journal = directory.open();
        let key = row_key(project, [4; 16]);
        let mut row =
            decode_row(journal.get(RecordNamespace::PublisherPolicy, &key).unwrap()).unwrap();
        row.packet[PACKET_BYTES - 1] ^= 1;
        row.packet_digest = commitment(PACKET_DOMAIN, &row.packet);
        let row_bytes = encode_row(&row);
        let head = RetainedProjectAuthorizationHeadV2 {
            project,
            epoch: row.epoch,
            request_id: row.request_id,
            row_digest: commitment(ROW_DOMAIN, &row_bytes),
        };
        journal
            .commit(
                &JournalTransaction::new(
                    [6; 16],
                    vec![
                        JournalRecord::put(RecordNamespace::PublisherPolicy, key, row_bytes),
                        JournalRecord::put(
                            RecordNamespace::PublisherPolicy,
                            head_key(project),
                            encode_head(head),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let mut reopened = directory.open();
        let store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&signer)),
            Err(ProjectAuthorizationSourceErrorV2::Signature)
        ));
    }
}
