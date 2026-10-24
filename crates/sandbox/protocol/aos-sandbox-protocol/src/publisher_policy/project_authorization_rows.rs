//! Owns historical project-authorization row/head encoding and cross-links.
//!
//! Rows retain signed packet DATA. Fixed issuer credentials and current native
//! authorization remain with the actual upper source owner.

use std::collections::BTreeMap;
use aos_sandbox_model::source_tree_model::TreeLimitsV1;
use crate::source_project_authorization::{PROJECT_AUTHORIZATION_SOURCE_BYTES_V2 as PACKET_BYTES,
    PROJECT_AUTHORIZATION_SOURCE_BYTES_V3, parse_unverified_project_authorization_claims_v2,
    project_authorization_packet_digest};
use crate::publisher_project_authorization::{HEAD_DOMAIN, REVISION_DOMAIN, commitment};
use super::*;

/// Prefixes immutable project-authorization rows.
pub const ROW_PREFIX: &[u8] = b"project-auth/row/";
/// Prefixes current project-authorization heads.
pub const HEAD_PREFIX: &[u8] = b"project-auth/current/";
const ROW_MAGIC: &[u8; 8] = b"AOSPAUR2";
const HEAD_MAGIC: &[u8; 8] = b"AOSPAUH2";
/// Separates V2 authorization row commitments.
pub const ROW_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization.row.v2\0";
// The seed binds the exact retained pointer, including its epoch and row digest.
const ROW_BYTES: usize = 188 + PACKET_BYTES;
const ROW_BYTES_V3: usize = 188 + PROJECT_AUTHORIZATION_SOURCE_BYTES_V3;
/// Separates V3 authorization row commitments.
pub const ROW_DOMAIN_V3: &[u8] = b"aos.sandbox.publisher-project-authorization.row.v3\0";
const HEAD_BYTES: usize = 80;

/// Retains a complete historical authorization row without fixed-issuer authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedProjectAuthorizationRowV2 {
    pub(super) project: ProjectId,
    pub(super) request_id: [u8; 16],
    pub(super) epoch: u64,
    issuer_generation: u64,
    publisher_generation: u64,
    publisher_head_digest: ObjectDigest,
    publisher_revision_digest: ObjectDigest,
    packet_digest: ObjectDigest,
    limits: TreeLimitsV1,
    packet: Vec<u8>,
}

impl RetainedProjectAuthorizationRowV2 {
    /// Reports whether the packet uses the established resource-envelope version.
    pub fn resource_version(&self) -> bool {
        self.packet.len() == PROJECT_AUTHORIZATION_SOURCE_BYTES_V3
    }
}

/// Identifies one historical authorization row and epoch without native currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedProjectAuthorizationHeadV2 {
    resource_version: bool,
    pub(super) project: ProjectId,
    epoch: u64,
    request_id: [u8; 16],
    row_digest: ObjectDigest,
}
/// Encodes the project and immutable request identity in the original authorization-row key.

pub fn row_key(project: ProjectId, request_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ROW_PREFIX.len() + 32);
    key.extend_from_slice(ROW_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key.extend_from_slice(&request_id);
    key
}
/// Encodes the original current project-authorization head key.

pub fn head_key(project: ProjectId) -> Vec<u8> {
    let mut key = Vec::with_capacity(HEAD_PREFIX.len() + 16);
    key.extend_from_slice(HEAD_PREFIX);
    key.extend_from_slice(project.as_bytes());
    key
}
/// Commits the exact retained row under its established V2 or V3 domain.

pub fn project_auth_row_digest(bytes: &[u8]) -> ObjectDigest {
    let domain = if bytes.get(..8) == Some(b"AOSPAUR3".as_slice()) { ROW_DOMAIN_V3 } else { ROW_DOMAIN };
    commitment(domain, bytes)
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PublisherPolicyError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(PublisherPolicyError::CorruptState)
}
/// Encodes the retained authorization packet and its complete historical claims.

pub fn encode_row(value: &RetainedProjectAuthorizationRowV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(188 + value.packet.len());
    bytes.extend_from_slice(if value.resource_version() { b"AOSPAUR3" } else { ROW_MAGIC });
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
/// Decodes the original V2 or V3 authorization row and checks every packet claim.
///
/// # Errors
///
/// Rejects framing, limits or any row/packet/commitment disagreement.

pub fn decode_row(
    bytes: &[u8],
) -> Result<RetainedProjectAuthorizationRowV2, PublisherPolicyError> {
    let resource_version = bytes.len() == ROW_BYTES_V3 && bytes.get(..8) == Some(b"AOSPAUR3".as_slice());
    if !resource_version && (bytes.len() != ROW_BYTES || bytes.get(..8) != Some(ROW_MAGIC)) {
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
        packet: bytes[188..].to_vec(),
    };
    let claims = parse_unverified_project_authorization_claims_v2(&row.packet)
        .map_err(|_| PublisherPolicyError::CorruptState)?;
    if row.project != claims.project()
        || row.request_id != claims.request_id()
        || row.epoch != claims.epoch()
        || row.issuer_generation != claims.issuer_generation()
        || row.publisher_generation != claims.publisher_generation()
        || row.publisher_head_digest != claims.publisher_head_digest()
        || row.publisher_revision_digest != claims.publisher_revision_digest()
        || row.limits != claims.limits()
        || claims.resource_envelope().is_some() != resource_version
        || row.packet_digest != project_authorization_packet_digest(&row.packet)
            .map_err(|_| PublisherPolicyError::CorruptState)?
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(row)
}
/// Encodes the exact retained project-authorization epoch and selected row digest.

pub fn encode_head(value: RetainedProjectAuthorizationHeadV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEAD_BYTES);
    bytes.extend_from_slice(if value.resource_version { b"AOSPAUH3" } else { HEAD_MAGIC });
    bytes.extend_from_slice(value.project.as_bytes());
    bytes.extend_from_slice(&value.epoch.to_be_bytes());
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(value.row_digest.as_bytes());
    bytes
}
/// Decodes the established V2 or V3 project-authorization head.
///
/// # Errors
///
/// Rejects framing or a sentinel project, request, epoch or row digest.

pub fn decode_head(
    bytes: &[u8],
) -> Result<RetainedProjectAuthorizationHeadV2, PublisherPolicyError> {
    let resource_version = bytes.get(..8) == Some(b"AOSPAUH3".as_slice());
    if bytes.len() != HEAD_BYTES || (!resource_version && bytes.get(..8) != Some(HEAD_MAGIC)) {
        return Err(PublisherPolicyError::CorruptState);
    }
    let head = RetainedProjectAuthorizationHeadV2 {
        resource_version,
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
/// Joins one authorization row to its immutable Publisher revision and head commitment.
///
/// # Errors
///
/// Rejects a missing or malformed revision or any project, generation or commitment disagreement.

pub fn validate_historical_row(
    journal: PublisherReadDataV2<'_>,
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
/// Joins each retained authorization chain to its unique final head.
///
/// # Errors
///
/// Rejects unequal project sets or a final epoch, request, version or row digest disagreement.

pub fn validate_rows_and_heads(
    rows: &BTreeMap<ProjectId, BTreeMap<u64, ([u8; 16], ObjectDigest, bool)>>,
    heads: &BTreeMap<ProjectId, RetainedProjectAuthorizationHeadV2>,
) -> Result<(), PublisherPolicyError> {
    if rows.len() != heads.len() {
        return Err(PublisherPolicyError::CorruptState);
    }
    for (project, epochs) in rows {
        let (&epoch, &(request_id, row_digest, resource_version)) = epochs
            .last_key_value()
            .ok_or(PublisherPolicyError::CorruptState)?;
        let head = heads
            .get(project)
            .ok_or(PublisherPolicyError::CorruptState)?;
        if head.epoch != epoch || head.request_id != request_id || head.row_digest != row_digest
            || head.resource_version != resource_version {
            return Err(PublisherPolicyError::CorruptState);
        }
    }
    Ok(())
}

impl RetainedProjectAuthorizationRowV2 {
    /// Returns the retained project DATA.
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the retained request id DATA.
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the retained epoch DATA.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the retained issuer generation DATA.
    pub const fn issuer_generation(&self) -> u64 {
        self.issuer_generation
    }

    /// Returns the retained publisher generation DATA.
    pub const fn publisher_generation(&self) -> u64 {
        self.publisher_generation
    }

    /// Returns the retained publisher head digest DATA.
    pub const fn publisher_head_digest(&self) -> ObjectDigest {
        self.publisher_head_digest
    }

    /// Returns the retained publisher revision digest DATA.
    pub const fn publisher_revision_digest(&self) -> ObjectDigest {
        self.publisher_revision_digest
    }

    /// Returns the retained packet digest DATA.
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the retained limits DATA.
    pub const fn limits(&self) -> TreeLimitsV1 {
        self.limits
    }

    /// Borrows the exact retained signed packet DATA.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Retains supplied historical fields without issuing native authorization.
    pub fn from_historical_fields(
        project: ProjectId,
        request_id: [u8; 16],
        epoch: u64,
        issuer_generation: u64,
        publisher_generation: u64,
        publisher_head_digest: ObjectDigest,
        publisher_revision_digest: ObjectDigest,
        packet_digest: ObjectDigest,
        limits: TreeLimitsV1,
        packet: Vec<u8>,
    ) -> Self {
        Self { project, request_id, epoch, issuer_generation, publisher_generation, publisher_head_digest, publisher_revision_digest, packet_digest, limits, packet }
    }
}

impl RetainedProjectAuthorizationHeadV2 {
    /// Returns the retained resource version DATA.
    pub const fn resource_version(self) -> bool {
        self.resource_version
    }

    /// Returns the retained project DATA.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the retained epoch DATA.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the retained request id DATA.
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the retained row digest DATA.
    pub const fn row_digest(self) -> ObjectDigest {
        self.row_digest
    }

    /// Retains supplied head fields without admitting a native current pointer.
    pub const fn from_historical_fields(
        resource_version: bool,
        project: ProjectId,
        epoch: u64,
        request_id: [u8; 16],
        row_digest: ObjectDigest,
    ) -> Self {
        Self { resource_version, project, epoch, request_id, row_digest }
    }
}

impl RetainedProjectAuthorizationRowV2 {
    /// Transfers the original retained packet without copying its allocation.
    pub fn into_packet(self) -> Vec<u8> {
        self.packet
    }
}
