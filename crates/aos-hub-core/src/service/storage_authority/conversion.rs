//! Typed operator requests and canonical physical-authority decision inputs.
//!
//! Wire revisions are canonical decimal strings. Conversion rejects ambiguous
//! addresses, malformed evidence and unknown lifecycle states. Credentials are
//! references and fingerprints; no provider credential material is accepted.

use super::{RpcError, pb};
use crate::storage_authority::*;

const MAX_PORTABLE_INTEGER: i64 = 9_007_199_254_740_991;

/// Converts structural wire input without changing exact replay after expiry.
///
/// Evidence expiry and current binding predicates are checked by atomic apply.
///
/// # Errors
/// Returns an invalid-argument error for missing or noncanonical typed fields.
pub(super) fn decision(
    request: Option<pb::StorageAuthorityDecision>,
) -> Result<StorageAuthorityDecisionInput, RpcError> {
    use pb::storage_authority_decision::Input;

    let request = request.ok_or_else(|| RpcError::invalid("decision is required"))?;
    let input = request
        .input
        .ok_or_else(|| RpcError::invalid("decision input is required"))?;
    Ok(match input {
        Input::Create(value) => {
            let qualified_managed_prefix = value
                .qualified_managed_prefix
                .ok_or_else(|| RpcError::invalid("qualified managed prefix is required"))?;
            let specification = CreatePhysicalStorageAuthority {
                authority_id: authority_id(&value.authority_id)?,
                guard_namespace_id: value.guard_namespace_id,
                physical_resource_evidence_digest: value.physical_resource_evidence_digest,
                qualification_digest: value.qualification_digest,
                qualified_managed_prefix,
            };
            specification.validate().map_err(invalid)?;
            StorageAuthorityDecisionInput::Create(specification)
        }
        Input::ApproveAlias(value) => {
            key(&value.alias_id, 64)?;
            digest(&value.equivalence_evidence_digest)?;
            let address = value
                .address
                .ok_or_else(|| RpcError::invalid("alias address is required"))?;
            let host = match address.host {
                Some(pb::storage_authority_address::Host::DnsName(host)) => {
                    StorageAuthorityHost::Dns(host)
                }
                Some(pb::storage_authority_address::Host::Ipv4(bytes)) => {
                    StorageAuthorityHost::Ipv4(
                        bytes
                            .try_into()
                            .map_err(|_| RpcError::invalid("IPv4 requires four octets"))?,
                    )
                }
                Some(pb::storage_authority_address::Host::Ipv6(bytes)) => {
                    StorageAuthorityHost::Ipv6(
                        bytes
                            .try_into()
                            .map_err(|_| RpcError::invalid("IPv6 requires sixteen octets"))?,
                    )
                }
                None => return Err(RpcError::invalid("alias host is required")),
            };
            let spec = StorageAuthorityAliasSpec {
                host,
                port: u16::try_from(address.port)
                    .map_err(|_| RpcError::invalid("alias port is invalid"))?,
                bucket: address.bucket,
            };
            spec.validate().map_err(invalid)?;
            StorageAuthorityDecisionInput::ApproveAlias(ApproveStorageAuthorityAlias {
                alias_id: value.alias_id,
                authority_id: authority_id(&value.authority_id)?,
                spec,
                equivalence_evidence_digest: value.equivalence_evidence_digest,
            })
        }
        Input::AssociateBinding(value) => {
            key(&value.association_id, 64)?;
            key(&value.alias_id, 64)?;
            key(&value.binding_stable_id, 64)?;
            prefix(&value.binding_prefix)?;
            StorageAuthorityDecisionInput::AssociateBinding(AssociateStorageAuthorityBinding {
                association_id: value.association_id,
                authority_id: authority_id(&value.authority_id)?,
                alias_id: value.alias_id,
                binding_id: decimal(&value.binding_id, false)?,
                binding_stable_id: value.binding_stable_id,
                binding_resource_version: decimal(&value.binding_resource_version, false)?,
                binding_write_revision: decimal(&value.binding_write_revision, false)?,
                binding_prefix: value.binding_prefix,
            })
        }
        Input::Attest(value) => {
            key(&value.attestation_id, 64)?;
            key(&value.executor_identity, 255)?;
            prefix(&value.managed_prefix)?;
            digest(&value.qualification_digest)?;
            digest(&value.provider_policy_evidence_digest)?;
            if value.valid_until <= 0
                || value.valid_until > MAX_PORTABLE_INTEGER
                || value.credentials.is_empty()
                || value.credentials.len() > 256
            {
                return Err(RpcError::invalid(
                    "attestation requires a portable expiry and 1..256 exact credentials",
                ));
            }
            let credentials = value
                .credentials
                .into_iter()
                .map(|member| {
                    key(&member.association_id, 64)?;
                    key(&member.secret_version_ref, 1024)?;
                    digest(&member.credential_fingerprint)?;
                    if !matches!(
                        member.purpose.as_str(),
                        "read" | "write" | "delete" | "list" | "presign"
                    ) {
                        return Err(RpcError::invalid("credential purpose is invalid"));
                    }
                    Ok(StorageAuthorityCredentialMember {
                        association_id: member.association_id,
                        purpose: member.purpose,
                        generation: decimal(&member.generation, false)?,
                        secret_version_ref: member.secret_version_ref,
                        credential_fingerprint: member.credential_fingerprint,
                    })
                })
                .collect::<Result<Vec<_>, RpcError>>()?;
            if credentials.windows(2).any(|pair| {
                (&pair[0].association_id, &pair[0].purpose)
                    >= (&pair[1].association_id, &pair[1].purpose)
            }) {
                return Err(RpcError::invalid(
                    "credential members must be sorted and unique",
                ));
            }
            StorageAuthorityDecisionInput::Attest(AttestStorageAuthorityExclusivity {
                attestation_id: value.attestation_id,
                authority_id: authority_id(&value.authority_id)?,
                managed_prefix: value.managed_prefix,
                qualification_digest: value.qualification_digest,
                provider_policy_evidence_digest: value.provider_policy_evidence_digest,
                executor_identity: value.executor_identity,
                credentials,
                valid_until: value.valid_until,
            })
        }
        Input::SetAdmission(value) => {
            key(&value.guard_namespace_id, 255)?;
            let expected_generation = decimal(&value.expected_generation, true)?;
            if expected_generation == MAX_PORTABLE_INTEGER {
                return Err(RpcError::invalid("admission generation is exhausted"));
            }
            if let Some(value) = &value.expected_digest {
                digest(value)?;
            }
            if (expected_generation == 0) != value.expected_digest.is_none() {
                return Err(RpcError::invalid(
                    "expected digest must be absent only at generation zero",
                ));
            }
            let state = match pb::StorageAuthorityDesiredState::try_from(value.state) {
                Ok(pb::StorageAuthorityDesiredState::Admitted) => {
                    StorageAuthorityAdmissionState::Admitted
                }
                Ok(pb::StorageAuthorityDesiredState::Blocked) => {
                    StorageAuthorityAdmissionState::Blocked
                }
                Ok(pb::StorageAuthorityDesiredState::Retired) => {
                    StorageAuthorityAdmissionState::Retired
                }
                _ => return Err(RpcError::invalid("desired admission state is required")),
            };
            if state == StorageAuthorityAdmissionState::Admitted {
                key(
                    value.attestation_id.as_deref().ok_or_else(|| {
                        RpcError::invalid("admitted state requires an attestation")
                    })?,
                    64,
                )?;
                if value.association_ids.is_empty() || value.association_ids.len() > 256 {
                    return Err(RpcError::invalid(
                        "admitted state requires 1..256 associations",
                    ));
                }
                for association in &value.association_ids {
                    key(association, 64)?;
                }
                if value
                    .association_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                {
                    return Err(RpcError::invalid(
                        "admitted associations must be sorted and unique",
                    ));
                }
            } else if value.attestation_id.is_some() || !value.association_ids.is_empty() {
                return Err(RpcError::invalid(
                    "blocked or retired state cannot retain admitted members",
                ));
            }
            StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
                authority_id: authority_id(&value.authority_id)?,
                expected_generation,
                expected_digest: value.expected_digest,
                guard_namespace_id: value.guard_namespace_id,
                state,
                attestation_id: value.attestation_id,
                association_ids: value.association_ids,
            })
        }
    })
}

/// Parses the canonical permanent physical identity.
///
/// # Errors
/// Returns an invalid-argument error for nil or noncanonical UUIDs.
pub(super) fn authority_id(value: &str) -> Result<PhysicalStorageAuthorityId, RpcError> {
    PhysicalStorageAuthorityId::parse(value).map_err(invalid)
}

/// Projects the immutable creation facts without executor authorization.
pub(super) fn creation_message(
    value: CreatePhysicalStorageAuthority,
) -> pb::CreatePhysicalStorageAuthorityDecision {
    pb::CreatePhysicalStorageAuthorityDecision {
        authority_id: value.authority_id.as_str().into(),
        guard_namespace_id: value.guard_namespace_id,
        physical_resource_evidence_digest: value.physical_resource_evidence_digest,
        qualification_digest: value.qualification_digest,
        qualified_managed_prefix: Some(value.qualified_managed_prefix),
    }
}

/// Projects one exact desired SQL admission decision.
pub(super) fn admission_message(
    value: SetStorageAuthorityAdmission,
) -> pb::SetStorageAuthorityAdmissionDecision {
    let state = match value.state {
        StorageAuthorityAdmissionState::Admitted => pb::StorageAuthorityDesiredState::Admitted,
        StorageAuthorityAdmissionState::Blocked => pb::StorageAuthorityDesiredState::Blocked,
        StorageAuthorityAdmissionState::Retired => pb::StorageAuthorityDesiredState::Retired,
    };
    pb::SetStorageAuthorityAdmissionDecision {
        authority_id: value.authority_id.as_str().into(),
        expected_generation: value.expected_generation.to_string(),
        expected_digest: value.expected_digest,
        guard_namespace_id: value.guard_namespace_id,
        state: state as i32,
        attestation_id: value.attestation_id,
        association_ids: value.association_ids,
    }
}

fn decimal(value: &str, allow_zero: bool) -> Result<i64, RpcError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| RpcError::invalid("revision must be a canonical decimal"))?;
    if parsed < i64::from(!allow_zero)
        || parsed > MAX_PORTABLE_INTEGER
        || parsed.to_string() != value
    {
        return Err(RpcError::invalid(
            "revision is outside the canonical portable range",
        ));
    }
    Ok(parsed)
}

fn key(value: &str, maximum: usize) -> Result<(), RpcError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RpcError::invalid("authority key is malformed"));
    }
    Ok(())
}

fn digest(value: &str) -> Result<(), RpcError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RpcError::invalid(
            "evidence digest must be canonical SHA-256 hex",
        ));
    }
    Ok(())
}

fn prefix(value: &str) -> Result<(), RpcError> {
    if value.len() > 512
        || value.trim_matches('/') != value
        || value.trim() != value
        || value.contains("//")
        || value.chars().any(|c| c.is_control() || c == '\\')
        || value.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(RpcError::invalid("authority prefix is not canonical"));
    }
    Ok(())
}

fn invalid(error: anyhow::Error) -> RpcError {
    RpcError::invalid(format!("physical authority input: {error:#}"))
}
