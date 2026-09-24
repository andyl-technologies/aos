//! Protected first issuance of a public holder capability.
//!
//! An authenticated public TLS peer establishes holder and certificate-key
//! custody. Trusted controller administration supplies the approved grants;
//! the current protected publisher policy, controller head, project revocation
//! mapping, and time fence independently bound the resulting record. This
//! module registers no route by which a peer can approve its own grants.

#[cfg(test)]
use aos_sandbox_core::DelegationLimits;
use aos_sandbox_core::{
    AuditId, CapabilityDraft, CapabilityId, CapabilityRecord, ChannelBinding, Grant, ObjectDigest,
    PrincipalId, ProjectId, ResourceKind, Revision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::cli_model::authorization_adapter::advance_initial_issuance_time_floor;
use crate::controller::ControllerProtectedClockV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_api_session::load_entitlement_credentials;
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod entitlement;
pub use entitlement::sign_entitlement_document_v1;
use entitlement::{EntitlementEntryV1, VerifiedEntitlementsV1};

#[cfg(test)]
const MAXIMUM_VALIDITY_SECONDS: i64 = 3_600;
const BOOTSTRAP_KEY_DOMAIN: &[u8] = b"aos.sandbox.public-capability-bootstrap-key.v1\0";
const BOOTSTRAP_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.public-capability-bootstrap-request.v1\0";
const BOOTSTRAP_KEY_PREFIX: &[u8] = b"bootstrap/";
const ENTITLEMENT_HEAD_KEY: &[u8] = b"entitlement/current";
const MAXIMUM_BOOTSTRAP_RECORDS: usize = 65_536;

/// An explicit grant approval supplied only by trusted controller administration.
///
/// The public holder cannot create this approval through the capability service.
/// Every grant is still checked against the current protected project policy.
#[cfg(test)]
pub(crate) struct InitialPublicCapabilityApprovalV1 {
    grants: Vec<Grant>,
    delegation: DelegationLimits,
    validity_seconds: u32,
}

#[cfg(test)]
impl InitialPublicCapabilityApprovalV1 {
    /// Records the grant set and validity approved by the trusted controller.
    ///
    /// # Errors
    ///
    /// Rejects an empty grant set or validity outside `1..=3600` seconds.
    pub(crate) fn new(
        grants: Vec<Grant>,
        delegation: DelegationLimits,
        validity_seconds: u32,
    ) -> Result<Self, InitialPublicCapabilityErrorV1> {
        if grants.is_empty() || !(1..=3_600).contains(&validity_seconds) {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        Ok(Self {
            grants,
            delegation,
            validity_seconds,
        })
    }
}

/// Returns the committed resource identity and secret holder handle.
///
/// The handle is intentionally omitted from `Debug`, audit, and public
/// projections. It may only be delivered on the authenticated holder channel.
pub struct IssuedPublicCapabilityV1 {
    id: CapabilityId,
    handle: [u8; 32],
}

impl IssuedPublicCapabilityV1 {
    /// Returns the non-authorizing public resource identity.
    #[must_use]
    pub const fn id(&self) -> CapabilityId {
        self.id
    }

    /// Returns the secret handle for delivery to the authenticated holder.
    #[must_use]
    pub const fn holder_handle(&self) -> &[u8; 32] {
        &self.handle
    }
}

/// Reports a failed first issuance without exposing a handle.
#[derive(Debug, thiserror::Error)]
pub enum InitialPublicCapabilityErrorV1 {
    /// Approval or current protected authority did not cover the requested grant.
    #[error("initial public capability issuance rejected")]
    Rejected,
    /// Protected publisher policy could not be validated.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyError),
    /// Protected capability custody or commit failed.
    #[error(transparent)]
    Authority(#[from] PublisherAuthorityError),
    /// Protected bootstrap transaction or replay failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

struct AuthenticatedHolderV1 {
    principal: PrincipalId,
    project: ProjectId,
    key_binding: ChannelBinding,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRecordV1 {
    version: u16,
    key_digest: [u8; 32],
    request_digest: [u8; 32],
    entitlement_digest: ObjectDigest,
    entitlement_generation: u64,
    capability_id: CapabilityId,
    principal: PrincipalId,
    project: ProjectId,
    channel_binding: [u8; 32],
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntitlementHeadV1 {
    version: u16,
    generation: u64,
    digest: ObjectDigest,
}

fn bootstrap_checked(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    entitlements: &VerifiedEntitlementsV1,
    idempotency_key: &[u8],
    now: i64,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    if !(16..=128).contains(&idempotency_key.len())
        || holder.principal.as_bytes() == &[0; 16]
        || holder.project.as_bytes() == &[0; 16]
        || holder.key_binding.as_bytes() == &[0; 32]
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    journal.ensure_protected_authority()?;
    let entry = entitlements.for_holder(
        holder.principal,
        holder.project,
        holder.key_binding.as_bytes(),
    )?;

    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store
            .current_policy(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store
            .controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store
            .project_revocation_head(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    if now < entry.not_before
        || now < policy.not_before()
        || now >= entry.expires_at
        || now >= policy.expires_at()
        || policy.generation() != entry.policy_generation
        || policy.descriptor().digest() != entry.policy_digest
        || controller.generation != entry.controller_generation
        || controller.principal.as_bytes() == &[0; 16]
        || revocation.scope() != entry.revocation_scope
        || revocation.generation() != entry.revocation_generation
        || !grants_covered(&entry.grants, &policy)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let key_digest = holder_key_digest(
        holder.principal,
        holder.project,
        holder.key_binding.as_bytes(),
    );
    let request_digest: [u8; 32] = Sha256::new()
        .chain_update(BOOTSTRAP_REQUEST_DOMAIN)
        .chain_update(key_digest)
        .chain_update((idempotency_key.len() as u64).to_be_bytes())
        .chain_update(idempotency_key)
        .chain_update(entitlements.digest().as_bytes())
        .finalize()
        .into();
    let key = bootstrap_key(&key_digest);
    let head = validate_bootstrap_namespace(journal)?;
    if head.as_ref().is_some_and(|head| {
        entitlements.generation() < head.generation
            || (entitlements.generation() == head.generation
                && entitlements.digest() != head.digest)
    }) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    if let Some(bytes) = journal.get(RecordNamespace::PublicCapabilityBootstrap, &key) {
        let retained: BootstrapRecordV1 = decode_canonical(bytes)?;
        if retained.request_digest != request_digest
            || retained.entitlement_digest != entitlements.digest()
            || retained.entitlement_generation != entitlements.generation()
            || retained.principal != holder.principal
            || retained.project != holder.project
            || retained.channel_binding != *holder.key_binding.as_bytes()
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let registry =
            PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
        let capability = registry.resolve_current(retained.capability_id)?;
        if !claims_match(
            &capability,
            &holder,
            entry,
            &policy,
            controller.principal,
            &revocation,
            now,
        ) {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let handle =
            registry.holder_handle(retained.capability_id, holder.principal, holder.key_binding)?;
        return Ok(IssuedPublicCapabilityV1 {
            id: retained.capability_id,
            handle,
        });
    }

    let expires_at = now
        .checked_add(i64::from(entry.validity_seconds))
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
    if expires_at > entry.expires_at || expires_at > policy.expires_at() {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let id = CapabilityId::new();
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id,
        issuer: controller.principal,
        audience: controller.principal,
        holder: holder.principal,
        channel_binding: holder.key_binding,
        root_subject: holder.principal,
        project: holder.project,
        sandbox: None,
        incarnation: None,
        grants: entry.grants.clone(),
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: None,
        not_before: now,
        expires_at,
        revocation_scope: revocation.scope(),
        revocation_generation: Revision::new(revocation.generation()),
        delegation: entry.delegation,
        parent_decision: AuditId::from_bytes(*id.as_bytes()),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let (authority_record, handle) =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?
            .prepare_initial_public_install(capability)?;
    let retained = BootstrapRecordV1 {
        version: 1,
        key_digest,
        request_digest,
        entitlement_digest: entitlements.digest(),
        entitlement_generation: entitlements.generation(),
        capability_id: id,
        principal: holder.principal,
        project: holder.project,
        channel_binding: *holder.key_binding.as_bytes(),
    };
    let mut records = vec![
        authority_record,
        JournalRecord::put(
            RecordNamespace::PublicCapabilityBootstrap,
            key,
            serde_json::to_vec(&retained).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?,
        ),
    ];
    if head.is_none_or(|head| entitlements.generation() > head.generation) {
        records.push(JournalRecord::put(
            RecordNamespace::PublicCapabilityBootstrap,
            ENTITLEMENT_HEAD_KEY.to_vec(),
            serde_json::to_vec(&EntitlementHeadV1 {
                version: 1,
                generation: entitlements.generation(),
                digest: entitlements.digest(),
            })
            .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?,
        ));
    }
    journal.commit(&JournalTransaction::new(*id.as_bytes(), records)?)?;
    let committed_handle =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?
            .holder_handle(id, holder.principal, holder.key_binding)?;
    if committed_handle != handle {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(IssuedPublicCapabilityV1 { id, handle })
}

fn grants_covered(
    grants: &[Grant],
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
) -> bool {
    grants.iter().all(|grant| {
        if grant.id().as_bytes() == &[0; 16] {
            return false;
        }
        let candidates = if grant.delegable() {
            policy.policy().delegable_grants()
        } else {
            policy.policy().effective_grants()
        };
        candidates.iter().any(|candidate| {
            candidate.resource_kind() == grant.resource_kind()
                && grant.operations().is_subset_of(candidate.operations())
                && candidate.selector().contains(grant.selector())
                && (grant.resource_kind() != ResourceKind::CachePublish
                    || matches!(
                        grant.selector(),
                        aos_sandbox_core::Selector::Resource { .. }
                    ))
        })
    })
}

fn claims_match(
    capability: &CapabilityRecord,
    holder: &AuthenticatedHolderV1,
    entry: &EntitlementEntryV1,
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: PrincipalId,
    revocation: &crate::publisher_policy::PublisherProjectRevocationHeadV1,
    now: i64,
) -> bool {
    let claims = capability.claims();
    claims.issuer == controller
        && claims.audience == controller
        && claims.holder == holder.principal
        && claims.channel_binding == holder.key_binding
        && claims.root_subject == holder.principal
        && claims.project == holder.project
        && claims.sandbox.is_none()
        && claims.incarnation.is_none()
        && claims.assignment_epoch.is_none()
        && claims.grants == entry.grants
        && claims.delegation == entry.delegation
        && claims.policy_digest == policy.descriptor().digest()
        && claims.revocation_scope == revocation.scope()
        && claims.revocation_generation.get() == revocation.generation()
        && claims.not_before >= entry.not_before
        && claims.not_before <= now
        && now < claims.expires_at
        && claims.expires_at <= entry.expires_at
}

fn bootstrap_key(digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(BOOTSTRAP_KEY_PREFIX.len() + digest.len());
    key.extend_from_slice(BOOTSTRAP_KEY_PREFIX);
    key.extend_from_slice(digest);
    key
}

fn holder_key_digest(principal: PrincipalId, project: ProjectId, binding: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(BOOTSTRAP_KEY_DOMAIN)
        .chain_update(principal.as_bytes())
        .chain_update(project.as_bytes())
        .chain_update(binding)
        .finalize()
        .into()
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, InitialPublicCapabilityErrorV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T =
        serde_json::from_slice(bytes).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    if serde_json::to_vec(&value).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)? != bytes {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(value)
}

fn validate_bootstrap_namespace(
    journal: &Journal,
) -> Result<Option<EntitlementHeadV1>, InitialPublicCapabilityErrorV1> {
    let mut head = None;
    let mut count = 0_usize;
    let mut greatest_record_generation = 0_u64;
    for (key, bytes) in journal.records(RecordNamespace::PublicCapabilityBootstrap) {
        count = count
            .checked_add(1)
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        if count > MAXIMUM_BOOTSTRAP_RECORDS || bytes.len() > 2_048 {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        if key == ENTITLEMENT_HEAD_KEY {
            let value: EntitlementHeadV1 = decode_canonical(bytes)?;
            if value.version != 1 || value.generation == 0 || value.digest.as_bytes() == &[0; 32] {
                return Err(InitialPublicCapabilityErrorV1::Rejected);
            }
            head = Some(value);
        } else if let Some(digest) = key.strip_prefix(BOOTSTRAP_KEY_PREFIX) {
            let value: BootstrapRecordV1 = decode_canonical(bytes)?;
            if digest.len() != 32
                || digest != value.key_digest
                || value.version != 1
                || value.request_digest == [0; 32]
                || value.entitlement_digest.as_bytes() == &[0; 32]
                || value.entitlement_generation == 0
                || value.capability_id.as_bytes() == &[0; 16]
                || value.principal.as_bytes() == &[0; 16]
                || value.project.as_bytes() == &[0; 16]
                || value.channel_binding == [0; 32]
                || value.key_digest
                    != holder_key_digest(value.principal, value.project, &value.channel_binding)
            {
                return Err(InitialPublicCapabilityErrorV1::Rejected);
            }
            greatest_record_generation =
                greatest_record_generation.max(value.entitlement_generation);
        } else {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
    }
    if count != 0 && head.is_none_or(|head| head.generation < greatest_record_generation) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(head)
}

/// Issues or replays the first capability under fixed signed deployment authority.
///
/// The request supplies only an idempotency key. The credential reader chooses
/// both the entitlement and verifier by fixed names under systemd custody.
///
/// # Errors
///
/// Rejects stale TLS evidence, absent or changed signed entitlement, invalid
/// current protected policy, or an ambiguous protected commit.
pub(crate) fn bootstrap(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    idempotency_key: &[u8],
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let holder = AuthenticatedHolderV1 {
        principal: peer.principal(),
        project: peer.project(),
        key_binding: peer.key_binding(),
    };
    let credentials =
        load_entitlement_credentials().map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let entitlements = VerifiedEntitlementsV1::decode(&credentials[0], &credentials[1])?;
    let mut clock = ControllerProtectedClockV1::open_fixed()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let observed = clock
        .sample()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    advance_initial_issuance_time_floor(journal, observed)
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;

    let issued = bootstrap_checked(
        journal,
        holder,
        &entitlements,
        idempotency_key,
        observed.wall_seconds(),
    )?;
    let current =
        load_entitlement_credentials().map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let current = VerifiedEntitlementsV1::decode(&current[0], &current[1])?;
    if current.digest() != entitlements.digest() {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    Ok(issued)
}

#[cfg(test)]
fn issue_checked(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    approval: InitialPublicCapabilityApprovalV1,
    now: i64,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    if holder.principal.as_bytes() == &[0; 16]
        || holder.project.as_bytes() == &[0; 16]
        || holder.key_binding.as_bytes() == &[0; 32]
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    // A single exclusive journal owner keeps all current-head checks and the
    // capability commit in one authority cut.
    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store
            .current_policy(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store
            .controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store
            .project_revocation_head(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    let expires_at = now
        .checked_add(i64::from(approval.validity_seconds))
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
    if now < policy.not_before()
        || expires_at > policy.expires_at()
        || expires_at <= now
        || expires_at - now > MAXIMUM_VALIDITY_SECONDS
        || controller.principal.as_bytes() == &[0; 16]
        || controller.generation == 0
        || revocation.generation() == 0
        || !grants_covered(&approval.grants, &policy)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let id = CapabilityId::new();
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id,
        issuer: controller.principal,
        audience: controller.principal,
        holder: holder.principal,
        channel_binding: holder.key_binding,
        root_subject: holder.principal,
        project: holder.project,
        sandbox: None,
        incarnation: None,
        grants: approval.grants,
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: None,
        not_before: now,
        expires_at,
        revocation_scope: revocation.scope(),
        revocation_generation: Revision::new(revocation.generation()),
        delegation: approval.delegation,
        parent_decision: AuditId::from_bytes(*id.as_bytes()),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let mut registry =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
    registry.install_from_trusted_controller(*id.as_bytes(), capability)?;
    let handle = registry.holder_handle(id, holder.principal, holder.key_binding)?;
    Ok(IssuedPublicCapabilityV1 { id, handle })
}

#[cfg(test)]
mod tests;
