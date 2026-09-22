//! Strict audit provenance layered over checked public watch events.

use aos_proto::aos::sandbox::v1::{AuditAction, AuditCategory, AuditDecision, Event, EventKind};

use super::event::{CheckedWatchEventV1, InvalidWatchEvent};
use super::model::{OpaqueResponseBytesV1, OpaqueResponseKindV1, QueryBindingV1};
use super::portable::CheckedPolicyDescriptorV1;
use super::resource::{PublicResourceTypeV1, checked_results};

/// Maximum bytes in an actor or authenticated-transport identity.
pub const MAXIMUM_AUDIT_IDENTITY_BYTES: usize = 4 * 1024;

/// Reports an invalid audit-enriched watch event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidAuditWatchEvent {
    /// The base event, cursor, extension, or nested resource is invalid.
    #[error("audit watch event is not a valid public watch event")]
    InvalidEvent,
    /// Audit provenance is missing, oversized, or structurally inconsistent.
    #[error("audit watch event provenance is invalid")]
    InvalidProvenance,
}

impl From<InvalidWatchEvent> for InvalidAuditWatchEvent {
    fn from(_: InvalidWatchEvent) -> Self {
        Self::InvalidEvent
    }
}

/// Stores a watch event with complete checked audit provenance.
#[derive(Clone, PartialEq)]
pub struct CheckedAuditWatchEventV1 {
    event: CheckedWatchEventV1,
    resource_version: OpaqueResponseBytesV1,
    actor: Vec<u8>,
    authenticated_transport_identity: Vec<u8>,
    decision: AuditDecision,
    category: AuditCategory,
    action: AuditAction,
    policy_revision: CheckedPolicyDescriptorV1,
    node_epoch: u64,
    causal_predecessor: Option<[u8; 16]>,
}

impl CheckedAuditWatchEventV1 {
    /// Checks base watch semantics and complete audit provenance.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuditWatchEvent`] for malformed event state, identity,
    /// resource version, decision, policy revision, epoch, or predecessor.
    pub fn from_response(
        binding: QueryBindingV1,
        wire: Event,
    ) -> Result<Self, InvalidAuditWatchEvent> {
        let event = CheckedWatchEventV1::from_response(binding, wire)?;
        let wire = event.full_proto();
        if event.kind() != EventKind::EVENT_KIND_AUDIT
            || wire.operation_id.len() != 16
            || wire.operation_id.as_slice() == [0; 16]
        {
            return Err(InvalidAuditWatchEvent::InvalidProvenance);
        }
        let resource = wire
            .resource
            .as_option()
            .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?;
        if resource.resource_version != wire.resource_version {
            return Err(InvalidAuditWatchEvent::InvalidProvenance);
        }
        let resource_version = OpaqueResponseBytesV1::from_response(
            wire.resource_version.clone(),
            OpaqueResponseKindV1::ResourceVersion,
        )
        .map_err(|_| InvalidAuditWatchEvent::InvalidProvenance)?;
        if wire.actor.is_empty()
            || wire.actor.len() > MAXIMUM_AUDIT_IDENTITY_BYTES
            || wire.authenticated_transport_identity.is_empty()
            || wire.authenticated_transport_identity.len() > MAXIMUM_AUDIT_IDENTITY_BYTES
            || wire.node_epoch == 0
        {
            return Err(InvalidAuditWatchEvent::InvalidProvenance);
        }
        let decision = wire
            .decision
            .as_known()
            .filter(|value| *value != AuditDecision::AUDIT_DECISION_UNSPECIFIED)
            .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?;
        let category = wire
            .audit_category
            .as_known()
            .filter(|value| *value != AuditCategory::AUDIT_CATEGORY_UNSPECIFIED)
            .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?;
        let action = wire
            .audit_action
            .as_known()
            .filter(|value| *value != AuditAction::AUDIT_ACTION_UNSPECIFIED)
            .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?;
        if !action_matches_category(action, category) || !decision_matches_action(decision, action)
        {
            return Err(InvalidAuditWatchEvent::InvalidProvenance);
        }
        let resource_type = checked_results(std::slice::from_ref(resource))
            .map_err(|_| InvalidAuditWatchEvent::InvalidProvenance)?
            .into_iter()
            .next()
            .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?
            .resource_type();
        if !action_matches_resource(action, resource_type) {
            return Err(InvalidAuditWatchEvent::InvalidProvenance);
        }
        let policy_revision = CheckedPolicyDescriptorV1::try_from(
            wire.policy_revision
                .as_option()
                .ok_or(InvalidAuditWatchEvent::InvalidProvenance)?
                .clone(),
        )
        .map_err(|_| InvalidAuditWatchEvent::InvalidProvenance)?;
        let causal_predecessor = if wire.causal_predecessor.is_empty() {
            None
        } else {
            let predecessor: [u8; 16] = wire
                .causal_predecessor
                .as_slice()
                .try_into()
                .map_err(|_| InvalidAuditWatchEvent::InvalidProvenance)?;
            if predecessor == [0; 16] || predecessor == event.event_id() {
                return Err(InvalidAuditWatchEvent::InvalidProvenance);
            }
            Some(predecessor)
        };

        Ok(Self {
            actor: wire.actor.clone(),
            authenticated_transport_identity: wire.authenticated_transport_identity.clone(),
            node_epoch: wire.node_epoch,
            event,
            resource_version,
            decision,
            category,
            action,
            policy_revision,
            causal_predecessor,
        })
    }

    /// Returns the checked base watch event.
    #[must_use]
    pub const fn event(&self) -> &CheckedWatchEventV1 {
        &self.event
    }

    /// Returns the complete audit event after strict provenance validation.
    ///
    /// Callers must keep this projection on the separately authorized audit
    /// surface. Ordinary public event rendering uses the redacted base event.
    #[must_use]
    pub const fn as_proto(&self) -> &Event {
        self.event.full_proto()
    }

    /// Returns the event resource version.
    #[must_use]
    pub const fn resource_version(&self) -> &OpaqueResponseBytesV1 {
        &self.resource_version
    }

    /// Returns the authenticated actor identity bytes.
    #[must_use]
    pub fn actor(&self) -> &[u8] {
        &self.actor
    }

    /// Returns the authenticated transport identity bytes.
    #[must_use]
    pub fn authenticated_transport_identity(&self) -> &[u8] {
        &self.authenticated_transport_identity
    }

    /// Returns the closed audit decision.
    #[must_use]
    pub const fn decision(&self) -> AuditDecision {
        self.decision
    }

    /// Returns the closed audit category.
    #[must_use]
    pub const fn category(&self) -> AuditCategory {
        self.category
    }

    /// Returns the closed audit action.
    #[must_use]
    pub const fn action(&self) -> AuditAction {
        self.action
    }

    /// Returns the checked policy revision descriptor.
    #[must_use]
    pub const fn policy_revision(&self) -> &CheckedPolicyDescriptorV1 {
        &self.policy_revision
    }

    /// Returns the node epoch that produced the event.
    #[must_use]
    pub const fn node_epoch(&self) -> u64 {
        self.node_epoch
    }

    /// Returns the causal predecessor when this event is not a chain root.
    #[must_use]
    pub const fn causal_predecessor(&self) -> Option<[u8; 16]> {
        self.causal_predecessor
    }
}

impl std::fmt::Debug for CheckedAuditWatchEventV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedAuditWatchEventV1")
            .field("sequence", &self.event.sequence())
            .field("decision", &self.decision)
            .field("category", &self.category)
            .field("action", &self.action)
            .field("node_epoch", &self.node_epoch)
            .finish_non_exhaustive()
    }
}

fn action_matches_category(action: AuditAction, category: AuditCategory) -> bool {
    use AuditAction as A;
    use AuditCategory as C;

    match category {
        C::AUDIT_CATEGORY_CAPABILITY => matches!(
            action,
            A::AUDIT_ACTION_CAPABILITY_ISSUE
                | A::AUDIT_ACTION_CAPABILITY_ATTENUATE
                | A::AUDIT_ACTION_CAPABILITY_USE
                | A::AUDIT_ACTION_CAPABILITY_EXPIRE
                | A::AUDIT_ACTION_CAPABILITY_REVOKE
        ),
        C::AUDIT_CATEGORY_OWNERSHIP => matches!(
            action,
            A::AUDIT_ACTION_OWNERSHIP_LEASE_ISSUE
                | A::AUDIT_ACTION_OWNERSHIP_LEASE_RENEW
                | A::AUDIT_ACTION_OWNERSHIP_LEASE_EXPIRE
                | A::AUDIT_ACTION_BROKER_PLAN_ACCEPT
                | A::AUDIT_ACTION_GUARDIAN_CONTAIN
        ),
        C::AUDIT_CATEGORY_LIFECYCLE => matches!(
            action,
            A::AUDIT_ACTION_SANDBOX_CREATE
                | A::AUDIT_ACTION_SANDBOX_PLACE
                | A::AUDIT_ACTION_SANDBOX_START
                | A::AUDIT_ACTION_SANDBOX_STOP
                | A::AUDIT_ACTION_SANDBOX_SUSPEND
                | A::AUDIT_ACTION_SANDBOX_RESUME
                | A::AUDIT_ACTION_SANDBOX_FORK
                | A::AUDIT_ACTION_SANDBOX_RESTORE
                | A::AUDIT_ACTION_SANDBOX_DELETE
        ),
        C::AUDIT_CATEGORY_EXECUTION => matches!(
            action,
            A::AUDIT_ACTION_EXECUTION_ADMIT
                | A::AUDIT_ACTION_EXECUTION_ATTACH
                | A::AUDIT_ACTION_EXECUTION_EXIT
                | A::AUDIT_ACTION_EXECUTION_CANCEL
                | A::AUDIT_ACTION_EXECUTION_DATA_CHANNEL_PRINCIPAL
        ),
        C::AUDIT_CATEGORY_FILESYSTEM_VIEW => matches!(
            action,
            A::AUDIT_ACTION_VIEW_PUBLISH
                | A::AUDIT_ACTION_VIEW_REPLACE
                | A::AUDIT_ACTION_VIEW_DETACH
                | A::AUDIT_ACTION_VIEW_REVOKE
        ),
        C::AUDIT_CATEGORY_SNAPSHOT => matches!(
            action,
            A::AUDIT_ACTION_SNAPSHOT_BARRIER | A::AUDIT_ACTION_SNAPSHOT_EXTERNAL_DEPENDENCY
        ),
        C::AUDIT_CATEGORY_CACHE => matches!(
            action,
            A::AUDIT_ACTION_CACHE_ADMIT
                | A::AUDIT_ACTION_CACHE_CROSS_DOMAIN_DENY
                | A::AUDIT_ACTION_CACHE_PIN
                | A::AUDIT_ACTION_CACHE_EVICT
        ),
        C::AUDIT_CATEGORY_BACKEND_POLICY => matches!(
            action,
            A::AUDIT_ACTION_BACKEND_CAPABILITY_DRIFT | A::AUDIT_ACTION_POLICY_DRIFT
        ),
        C::AUDIT_CATEGORY_BROKER => action == A::AUDIT_ACTION_BROKER_REQUEST,
        C::AUDIT_CATEGORY_UNSPECIFIED => false,
    }
}

fn decision_matches_action(decision: AuditDecision, action: AuditAction) -> bool {
    use AuditAction as A;
    use AuditDecision as D;

    match action {
        A::AUDIT_ACTION_CACHE_CROSS_DOMAIN_DENY => decision == D::AUDIT_DECISION_DENIED,
        A::AUDIT_ACTION_GUARDIAN_CONTAIN => decision == D::AUDIT_DECISION_CONTAINED,
        A::AUDIT_ACTION_CAPABILITY_EXPIRE | A::AUDIT_ACTION_OWNERSHIP_LEASE_EXPIRE => {
            decision == D::AUDIT_DECISION_EXPIRED
        }
        A::AUDIT_ACTION_CAPABILITY_REVOKE | A::AUDIT_ACTION_VIEW_REVOKE => {
            decision == D::AUDIT_DECISION_REVOKED
        }
        A::AUDIT_ACTION_UNSPECIFIED => false,
        _ => matches!(
            decision,
            D::AUDIT_DECISION_ALLOWED
                | D::AUDIT_DECISION_DENIED
                | D::AUDIT_DECISION_COMPLETED
                | D::AUDIT_DECISION_FAILED
        ),
    }
}

fn action_matches_resource(action: AuditAction, resource: PublicResourceTypeV1) -> bool {
    use AuditAction as A;
    use PublicResourceTypeV1 as R;

    match action {
        A::AUDIT_ACTION_CAPABILITY_ISSUE
        | A::AUDIT_ACTION_CAPABILITY_ATTENUATE
        | A::AUDIT_ACTION_CAPABILITY_USE
        | A::AUDIT_ACTION_CAPABILITY_EXPIRE
        | A::AUDIT_ACTION_CAPABILITY_REVOKE => resource == R::Capability,
        A::AUDIT_ACTION_OWNERSHIP_LEASE_ISSUE
        | A::AUDIT_ACTION_OWNERSHIP_LEASE_RENEW
        | A::AUDIT_ACTION_OWNERSHIP_LEASE_EXPIRE
        | A::AUDIT_ACTION_BROKER_PLAN_ACCEPT
        | A::AUDIT_ACTION_GUARDIAN_CONTAIN
        | A::AUDIT_ACTION_SANDBOX_CREATE
        | A::AUDIT_ACTION_SANDBOX_PLACE
        | A::AUDIT_ACTION_SANDBOX_START
        | A::AUDIT_ACTION_SANDBOX_STOP
        | A::AUDIT_ACTION_SANDBOX_SUSPEND
        | A::AUDIT_ACTION_SANDBOX_RESUME
        | A::AUDIT_ACTION_SANDBOX_FORK
        | A::AUDIT_ACTION_SANDBOX_RESTORE
        | A::AUDIT_ACTION_SANDBOX_DELETE
        | A::AUDIT_ACTION_CACHE_ADMIT
        | A::AUDIT_ACTION_CACHE_CROSS_DOMAIN_DENY
        | A::AUDIT_ACTION_CACHE_PIN
        | A::AUDIT_ACTION_CACHE_EVICT
        | A::AUDIT_ACTION_POLICY_DRIFT => resource == R::Sandbox,
        A::AUDIT_ACTION_EXECUTION_ADMIT
        | A::AUDIT_ACTION_EXECUTION_ATTACH
        | A::AUDIT_ACTION_EXECUTION_EXIT
        | A::AUDIT_ACTION_EXECUTION_CANCEL
        | A::AUDIT_ACTION_EXECUTION_DATA_CHANNEL_PRINCIPAL => resource == R::Execution,
        A::AUDIT_ACTION_VIEW_PUBLISH
        | A::AUDIT_ACTION_VIEW_REPLACE
        | A::AUDIT_ACTION_VIEW_REVOKE => resource == R::FilesystemView,
        A::AUDIT_ACTION_VIEW_DETACH => resource == R::Attachment,
        A::AUDIT_ACTION_SNAPSHOT_BARRIER | A::AUDIT_ACTION_SNAPSHOT_EXTERNAL_DEPENDENCY => {
            resource == R::Snapshot
        }
        A::AUDIT_ACTION_BACKEND_CAPABILITY_DRIFT => {
            matches!(resource, R::Sandbox | R::Operation)
        }
        A::AUDIT_ACTION_BROKER_REQUEST => matches!(
            resource,
            R::Sandbox
                | R::Execution
                | R::FilesystemView
                | R::Attachment
                | R::Snapshot
                | R::Operation
        ),
        A::AUDIT_ACTION_UNSPECIFIED => false,
    }
}
