//! Fixed-width canonical protected-root record format.
//!
//! ```text
//! magic "AOSPRR01" | version:u16be | flags:u16be | root:16 | generation:u64be
//! node:16 | service-principal:16 | project:16 | resource:16
//! domain-kind:u8 | domain-id:16 | isolation-policy:32 | role:u8
//! filesystem-profile:u8 | state:u8 | predecessor-present:u8
//! predecessor:32 | record-digest:32
//! ```

use aos_sandbox_core::{
    CacheDomainId, NodeId, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};

use super::{
    PublicationFilesystemProfileV1, PublicationRootId, PublicationRootRecordV1,
    PublicationRootRoleV1, PublicationRootStateV1,
};

const MAGIC: &[u8; 8] = b"AOSPRR01";
const VERSION: u16 = 1;
const RECORD_BYTES: usize = 217;

/// Reports malformed or noncanonical protected-root bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootRecordCodecError {
    /// Framing, reserved fields, enum tags, or lengths differ from v1.
    #[error("protected publication-root record is malformed")]
    Malformed,
    /// Semantic identities, scope, chain shape, or digest are invalid.
    #[error("protected publication-root record is semantically invalid")]
    InvalidRecord,
    /// Fixed bounded output allocation failed.
    #[error("protected publication-root allocation failed")]
    Allocation,
}

/// Encodes one exact canonical protected-root record.
///
/// # Errors
///
/// Returns [`RootRecordCodecError::InvalidRecord`] unless every field and the
/// derived record digest validate.
pub fn encode_root_record_v1(
    record: &PublicationRootRecordV1,
) -> Result<Vec<u8>, RootRecordCodecError> {
    record
        .clone()
        .validate()
        .map_err(|_| RootRecordCodecError::InvalidRecord)?;
    let predecessor = record
        .predecessor_digest
        .map_or([0; 32], |digest| *digest.as_bytes());
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RECORD_BYTES)
        .map_err(|_| RootRecordCodecError::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(record.root_id.as_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.extend_from_slice(record.service_node.as_bytes());
    bytes.extend_from_slice(record.service_principal.as_bytes());
    bytes.extend_from_slice(record.project.as_bytes());
    bytes.extend_from_slice(record.resource.as_bytes());
    bytes.push(super::model::domain_code(record.domain));
    bytes.extend_from_slice(record.domain.domain_id().as_bytes());
    bytes.extend_from_slice(record.isolation_policy.as_bytes());
    bytes.push(record.role as u8);
    bytes.push(record.filesystem_profile as u8);
    bytes.push(record.state as u8);
    bytes.push(u8::from(record.predecessor_digest.is_some()));
    bytes.extend_from_slice(&predecessor);
    bytes.extend_from_slice(record.record_digest.as_bytes());
    Ok(bytes)
}

/// Decodes and canonically re-encodes one protected-root record.
///
/// # Errors
///
/// Returns [`RootRecordCodecError`] for any framing, semantic, digest, or
/// noncanonical representation violation.
pub fn decode_root_record_v1(
    bytes: &[u8],
) -> Result<PublicationRootRecordV1, RootRecordCodecError> {
    if bytes.len() != RECORD_BYTES
        || &bytes[..8] != MAGIC
        || u16::from_be_bytes(exact(&bytes[8..10])?) != VERSION
        || u16::from_be_bytes(exact(&bytes[10..12])?) != 0
    {
        return Err(RootRecordCodecError::Malformed);
    }
    let domain_kind = match bytes[100] {
        1 => CacheDomainKind::Private,
        2 => CacheDomainKind::Project,
        3 => CacheDomainKind::TrustDomain,
        4 => CacheDomainKind::Public,
        _ => return Err(RootRecordCodecError::Malformed),
    };
    let predecessor = match bytes[152] {
        0 if bytes[153..185] == [0; 32] => None,
        1 => Some(ObjectDigest::from_bytes(exact(&bytes[153..185])?)),
        _ => return Err(RootRecordCodecError::Malformed),
    };
    let record = PublicationRootRecordV1 {
        root_id: PublicationRootId::from_bytes(exact(&bytes[12..28])?)
            .map_err(|_| RootRecordCodecError::InvalidRecord)?,
        generation: u64::from_be_bytes(exact(&bytes[28..36])?),
        service_node: NodeId::from_bytes(exact(&bytes[36..52])?),
        service_principal: PrincipalId::from_bytes(exact(&bytes[52..68])?),
        project: ProjectId::from_bytes(exact(&bytes[68..84])?),
        resource: ResourceId::from_bytes(exact(&bytes[84..100])?),
        domain: CacheDomain::new(
            domain_kind,
            CacheDomainId::from_bytes(exact(&bytes[101..117])?),
        ),
        isolation_policy: ObjectDigest::from_bytes(exact(&bytes[117..149])?),
        role: PublicationRootRoleV1::from_code(bytes[149])?,
        filesystem_profile: PublicationFilesystemProfileV1::from_code(bytes[150])?,
        state: PublicationRootStateV1::from_code(bytes[151])?,
        predecessor_digest: predecessor,
        record_digest: ObjectDigest::from_bytes(exact(&bytes[185..217])?),
    }
    .validate()
    .map_err(|_| RootRecordCodecError::InvalidRecord)?;
    if encode_root_record_v1(&record)? != bytes {
        return Err(RootRecordCodecError::Malformed);
    }
    Ok(record)
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RootRecordCodecError> {
    bytes
        .try_into()
        .map_err(|_| RootRecordCodecError::Malformed)
}
