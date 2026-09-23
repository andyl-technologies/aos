//! Current protected policy join for publisher self-read authorization.
//!
//! This borrow holds the controller's protected policy writer while a read is
//! authorized. A durable publisher read grant is necessary but insufficient:
//! a policy replacement or expiry must also deny the next open.

use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{ChannelBinding, NodeId};

use super::*;
use crate::publisher_admission::ReadAuthorityGrantV1;
use crate::publisher_sessions::AuthenticatedPublisherRecord;

/// Retains a current protected `CacheRead` grant and its authenticated issuer.
#[must_use = "current read policy must be joined to an exact publisher read"]
pub struct CurrentPublisherReadAuthorityV1<'journal> {
    _policy: PublisherPolicyStore<'journal>,
    grant: ReadAuthorityGrantV1,
    instance: PublisherInstanceId,
    channel_binding: ChannelBinding,
    node: NodeId,
    boot: [u8; 16],
    clock_provenance: [u8; 16],
    not_before: i64,
    expires_at: i64,
}

impl CurrentPublisherReadAuthorityV1<'_> {
    /// Rechecks the exact live publisher and current policy clock before an open.
    ///
    /// # Errors
    ///
    /// Returns an error for a replaced execution, changed channel or boot,
    /// clock provenance mismatch, or an expired policy interval.
    pub fn recheck(
        &self,
        record: &AuthenticatedPublisherRecord<'_>,
        now: RawPairedClockSample,
    ) -> Result<(), PublisherControlError> {
        record.recheck()?;
        let scope = record.scope();
        if record.instance() != self.instance
            || record.channel_binding() != self.channel_binding
            || scope.node != self.node
            || scope.principal != self.grant.holder
            || scope.project != self.grant.project
            || scope.cache_resource != self.grant.resource
            || now.host_boot_id() != self.boot
            || now.provenance().as_bytes() != self.clock_provenance
            || now.wall_seconds() < self.not_before
            || now.wall_seconds() >= self.expires_at
        {
            return Err(PublisherControlError::PolicyDenied);
        }
        Ok(())
    }

    /// Returns the exact policy-derived grant expected in durable read custody.
    #[must_use]
    pub(crate) const fn grant(&self) -> &ReadAuthorityGrantV1 {
        &self.grant
    }
}

/// Borrows current protected policy for one authenticated publisher self-read.
///
/// Publication permission does not imply this read permission. The policy
/// must separately allow `ContentRead` on `CacheRead` for the configured
/// resource, and the live publisher session supplies the holder identity.
/// The retained store borrow prevents a safe concurrent policy mutation until
/// the open result has been dispatched or deliberately discarded.
///
/// # Errors
///
/// Returns an error for stale session or clock evidence, missing or expired
/// policy, a mismatched cache binding, or absent read permission.
pub fn current_publisher_self_read_authority_v1<'journal, T>(
    journal: &'journal mut Journal,
    record: &AuthenticatedPublisherRecord<'_>,
    config: PublisherControlPolicy,
    clock: &mut T,
) -> Result<CurrentPublisherReadAuthorityV1<'journal>, PublisherControlError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config)?;
    record.recheck()?;
    let boot = KernelBootId::current()?.into_bytes();
    let before = clock().map_err(|_| PublisherControlError::Clock)?;
    validate_clock(before, boot, config.clock_provenance)?;

    let scope = *record.scope();
    let policy = PublisherPolicyStore::load(journal, config.policy_limits)?;
    let revision = policy
        .current_policy(scope.project)?
        .ok_or(PublisherControlError::PolicyDenied)?;
    let resource = policy
        .resource_binding(scope.cache_resource)?
        .ok_or(PublisherControlError::PolicyDenied)?;
    policy
        .controller_head()?
        .ok_or(PublisherControlError::PolicyDenied)?;
    let selector = Selector::Resource {
        resource: scope.cache_resource,
    };
    if resource.project() != scope.project
        || resource.cache_domain().kind() != CacheDomainKind::Project
        || resource.cache_domain() != revision.policy().cache_domain()
        || before.wall_seconds() < revision.not_before()
        || before.wall_seconds() >= revision.expires_at()
        || !revision.policy().effective_grants().iter().any(|grant| {
            grant.resource_kind() == ResourceKind::CacheRead
                && grant.operations().contains(Operation::ContentRead)
                && grant.selector() == &selector
        })
    {
        return Err(PublisherControlError::PolicyDenied);
    }
    let grant = ReadAuthorityGrantV1::active(
        scope.principal,
        scope.project,
        scope.cache_resource,
        resource.cache_domain(),
        revision.descriptor().digest(),
        1,
    )
    .map_err(|_| PublisherControlError::PolicyDenied)?;

    let after = clock().map_err(|_| PublisherControlError::Clock)?;
    validate_clock(after, boot, config.clock_provenance)?;
    validate_elapsed(
        before,
        after,
        revision.expires_at(),
        u64::from(config.maximum_challenge_seconds),
    )?;
    record.recheck()?;
    Ok(CurrentPublisherReadAuthorityV1 {
        _policy: policy,
        grant,
        instance: record.instance(),
        channel_binding: record.channel_binding(),
        node: scope.node,
        boot,
        clock_provenance: config.clock_provenance,
        not_before: revision.not_before(),
        expires_at: revision.expires_at(),
    })
}
