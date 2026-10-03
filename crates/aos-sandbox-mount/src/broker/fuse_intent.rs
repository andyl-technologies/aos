//! Authenticated purpose-57 reservation under the actual Mount writer.
//!
//! ```text
//! AuthorityPublication[aos.mount.fuse.origin.v1\0 || attachment || gen]
//!     = location-MAC({version:1, reservation, original request/session,
//!                     shared base fence, exact phase fence/effect, slot})
//! ```
//!
//! The reservation, original request join and pending effect commit atomically.
//! The shared native base fence is never replaced by the purpose-57 plan.
//! The returned borrow retains the real broker and original Host scope, but is
//! preparation custody only. Session security must keep its actual original
//! RequestPrepared writer alongside it; Root, connected worker, INIT/idmap and
//! current content permission are independent prerequisites, not row facts.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker::BrokerEffectStatusV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::mount_fuse_reserve_intent::{
    ValidatedFuseReserveIntentRequestV1, decode_fuse_reserve_intent_request_v1,
};
use serde::{Deserialize, Serialize};

use super::*;
use crate::state::fuse_worker_reservation_v1::FuseWorkerReservationStateV1;

mod worker_preparation;

pub use worker_preparation::{PreparedMountFuseWorkerHandoffV1, PreparedMountFuseWorkerObjectsV1};

const ORIGIN_PREFIX: &[u8] = b"aos.mount.fuse.origin.v1\0";
const PHASE_FENCE_PREFIX: &[u8] = b"aos.mount.fuse.phase-fence.v1\0";
const MAXIMUM_ORIGIN_BYTES: usize = 8192;
const STATE_DIRECTORY: &str = "/var/lib/aos/sandbox-mount";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    version: u16,
    reservation: FuseWorkerReservationV1,
    session: [u8; 32],
    signed_request: [u8; 32],
    semantics: [u8; 32],
    base_fence_digest: [u8; 32],
    phase_fence_digest: [u8; 32],
    effect_digest: [u8; 32],
    destination_record_digest: [u8; 32],
    destination_device: u64,
    destination_inode: u64,
}

/// Retains actual Mount reservation and original Host custody before launch.
///
/// No public constructor, received-FD adoption or scalar currentness callback
/// exists. This is not a connected worker/channel lease or Root read grant.
/// Failed or dropped preparation retains durable rows for reconciliation; it
/// never frees a generation because a request or public caller expired.
#[must_use = "retain actual Mount custody through preparation/reconciliation"]
pub struct HeldMountFuseIntentPreparationV1<'owner, W: MountWorker> {
    broker: &'owner mut MountBroker<W>,
    request: AuthenticatedBrokerMethodRequestV1,
    decoded: ValidatedFuseReserveIntentRequestV1,
    scope: ObservedMountScope,
    slot: DestinationSlotBindingV1,
    origin: Origin,
    origin_key: Vec<u8>,
    phase_key: Vec<u8>,
    sequence: u64,
    failed: bool,
}

impl<W: MountWorker> MountBroker<W> {
    /// Commits exact signed intent and a physically checked first reservation.
    ///
    /// The call consumes an independently retained Host scope and borrows the
    /// real fixed Mount writer. Its caller must retain the genuine session
    /// RequestPrepared cut throughout; a clone of `original` alone is not that
    /// cut. The returned value deliberately grants only preparation custody.
    ///
    /// # Errors
    ///
    /// Rejects nonfixed custody, another method/direction, missing or invalid
    /// signatures, changed assignment/base lease, wrong accepted Policy, stale
    /// Host scope, unavailable/aliased physical slot, replay or capacity failure.
    #[doc(hidden)]
    pub fn prepare_authenticated_fuse_intent<'owner>(
        &'owner mut self,
        original: &AuthenticatedBrokerMethodRequestV1,
        scope: ObservedMountScope,
    ) -> Result<HeldMountFuseIntentPreparationV1<'owner, W>> {
        self.ensure_authority_healthy()?;
        self.journal
            .validate_held_root_owned_at(STATE_DIRECTORY, "mount.journal")?;
        if original.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || original.method() != BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
        {
            return Err(MountError::Fence("not an original received FUSE intent"));
        }
        let fresh = crate::service::trusted_paired_clock_sample()?;
        if fresh.host_boot_id() != self.kernel_boot_id {
            return Err(MountError::Fence("FUSE kernel boot changed"));
        }
        let decoded = decode_fuse_reserve_intent_request_v1(
            original.exact_body(),
            original.peer(),
            original.peer_policy(),
            fresh.boottime_nanoseconds(),
        )?;
        if original.request_id() != *decoded.header().request_id()
            || original.deadline_boottime_nanoseconds() != decoded.header().deadline_boottime_nanoseconds()
            || original.semantic_commitment() != *aos_sandbox_protocol::semantics::mount_fuse_reserve_intent::canonical_mount_fuse_reserve_intent_semantics_v1(&decoded)
                .map_err(|_| MountError::Fence("FUSE semantic commitment failed"))?.commitment().digest().as_bytes()
        {
            return Err(MountError::Fence("original FUSE request join changed"));
        }
        let base = self
            .journal
            .get(RecordNamespace::DesiredState, decoded.fence().sandbox_id())
            .ok_or(MountError::Fence(
                "FUSE needs the existing Mount base fence",
            ))?
            .to_vec();
        let admission = self
            .authority
            .admit_fuse_reserve_intent(
                original
                    .authorization()
                    .ok_or(MountError::Fence("FUSE has no original authorization"))?,
                &decoded,
                original.exact_body(),
                &fresh,
                Some(&base),
            )
            .map_err(|_| MountError::Fence("FUSE signed current admission failed"))?;
        let idempotency = fuse_intent_idempotency_record(
            &self.journal,
            original.request_id(),
            original.exact_body(),
        )?;
        scope.recheck().map_err(host_scope_error)?;
        require_scope(&decoded, &scope)?;

        let slots = self
            .destination_slots
            .as_ref()
            .ok_or(MountError::Fence("FUSE has no slot owner"))?;
        let slot = select_slot(slots, &decoded)?;
        let physical = slots.resolve(&slot)?;
        let destination_record_digest = *physical.resource().record_digest().as_bytes();
        let destination = physical.identity();
        let namespace = scope.user_namespace().identity();
        let expiry = resource_expiry(
            &decoded,
            &fresh,
            admission
                .effect
                .local_lease_record()
                .fail_stop_boottime_nanoseconds(),
        )?;
        let fence = decoded.fence();
        let (view, revision) = decoded.intent().source_view();
        let reservation = FuseWorkerReservationV1 {
            attachment_id: *decoded.intent().id().as_bytes(),
            connection_generation: 1,
            kernel_boot_id: self.kernel_boot_id,
            worker_instance_id: broker_instance_id()?,
            assignment: AssignmentBindingV1 {
                sandbox_id: *fence.sandbox_id(),
                incarnation_id: *fence.incarnation_id(),
                assignment_epoch: fence.assignment_epoch(),
                desired_generation: fence.desired_generation(),
                assignment_digest: *fence.assignment_digest(),
                namespace_generation: decoded.namespace_target_generation(),
            },
            attachment_generation: decoded.intent().desired_generation().get(),
            destination_slot_id: *decoded.intent().destination_slot().as_bytes(),
            source_view_id: *view.as_bytes(),
            source_view_revision: revision.get(),
            view_revision: ObjectDescriptorV1::from_runtime(decoded.intent().view())?,
            user_namespace_device: namespace.device,
            user_namespace_inode: namespace.inode,
            user_namespace_generation: decoded.namespace_target_generation(),
            presentation_plan_digest: *admission.effect.plan_digest().as_bytes(),
            policy_digest: *decoded.accepted_policy().digest().as_bytes(),
            lease_identity: *decoded.intent().lease().id().as_bytes(),
            lease_expires_boottime_ns: expiry,
            state: FuseWorkerReservationStateV1::Reserved,
        };
        let resources = MountResourceTableV1::recover(
            &self.journal,
            MountResourceLimitsV1::default(),
            self.kernel_boot_id,
        )?;
        let reservations =
            FuseWorkerReservationTableV1::recover(&self.journal, self.kernel_boot_id)?;
        ensure_fuse_slots_exclude_native(&resources, &reservations)?;
        if !native_slot_is_unused_for_fuse(&resources, &reservation) {
            return Err(MountError::Fence("FUSE slot is claimed by native Mount"));
        }
        let reservation_record = reservations.prepare_reservation(&reservation)?;
        let origin_key = key(ORIGIN_PREFIX, &reservation);
        let phase_key = key(PHASE_FENCE_PREFIX, &reservation);
        if self
            .journal
            .get(RecordNamespace::AuthorityPublication, &origin_key)
            .is_some()
            || self
                .journal
                .get(RecordNamespace::AuthorityPublication, &phase_key)
                .is_some()
            || self
                .journal
                .get(RecordNamespace::Effect, &original.request_id())
                .is_some()
        {
            return Err(MountError::Fence(
                "FUSE preparation needs explicit reconciliation",
            ));
        }
        let phase_fence = self
            .authority
            .seal_fence(fence.sandbox_id(), &admission.fence)
            .map_err(|_| MountError::Fence("FUSE phase fence sealing failed"))?;
        // This is an effect-local archive, not a relocated shared fence. Its
        // outer MAC binds the actual publication key before any later use.
        let phase_fence = self
            .authority
            .seal_fuse_origin(&phase_key, &phase_fence)
            .map_err(|_| MountError::Fence("FUSE phase archive sealing failed"))?;
        let effect = self
            .authority
            .seal_effect(&original.request_id(), &admission.effect)
            .map_err(|_| MountError::Fence("FUSE effect sealing failed"))?;
        let origin = Origin {
            version: 1,
            reservation,
            session: original.session_binding(),
            signed_request: original.signed_request_digest(),
            semantics: original.semantic_commitment(),
            base_fence_digest: digest(&base),
            phase_fence_digest: digest(&phase_fence),
            effect_digest: digest(&effect),
            destination_record_digest,
            destination_device: destination.device,
            destination_inode: destination.inode,
        };
        let origin_value = self
            .authority
            .seal_fuse_origin(&origin_key, &encode_origin(&origin)?)
            .map_err(|_| MountError::Fence("FUSE origin sealing failed"))?;
        let transaction = JournalTransaction::new(
            fuse_reservation_transaction_id(&origin.reservation),
            vec![
                idempotency,
                reservation_record,
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    origin_key.clone(),
                    origin_value,
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    phase_key.clone(),
                    phase_fence,
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    original.request_id().to_vec(),
                    effect,
                ),
            ],
        )?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        scope.recheck().map_err(host_scope_error)?;
        slots.resolve(&slot)?;
        self.authority
            .validate_effect_clock(
                &admission.effect,
                &crate::service::trusted_paired_clock_sample()?,
            )
            .map_err(|_| MountError::Fence("FUSE admission expired before commit"))?;
        self.journal.commit(&transaction)?;
        self.resources = resources;
        self.fuse_reservations =
            FuseWorkerReservationTableV1::recover(&self.journal, self.kernel_boot_id)?;
        let sequence = self.journal.snapshot_sequence();
        let mut held = HeldMountFuseIntentPreparationV1 {
            broker: self,
            request: original.clone(),
            decoded,
            scope,
            slot,
            origin,
            origin_key,
            phase_key,
            sequence,
            failed: false,
        };
        held.recheck()?;
        Ok(held)
    }
}

impl<W: MountWorker> HeldMountFuseIntentPreparationV1<'_, W> {
    /// Returns the owner-minted locator as comparison data, never launch authority.
    #[must_use]
    pub const fn worker_locator(&self) -> [u8; 16] {
        self.origin.reservation.worker_instance_id
    }

    /// Returns the exact signed presentation plan commitment for comparison.
    #[must_use]
    pub const fn presentation_plan_digest(&self) -> [u8; 32] {
        self.origin.reservation.presentation_plan_digest
    }

    /// Returns the authenticated origin commitment, not a serialized live guard.
    ///
    /// # Errors
    ///
    /// Rejects an unrepresentable origin record.
    pub fn reservation_digest(&self) -> Result<[u8; 32]> {
        Ok(digest(&encode_origin(&self.origin)?))
    }

    /// Rechecks original fixed writer, authenticated rows, physical slot and Host.
    ///
    /// # Errors
    ///
    /// Rejects any changed head/name/row/peer, expired preparation or physical
    /// substitution. A failure poisons this borrow and preserves durable custody.
    pub fn recheck(&mut self) -> Result<()> {
        let result = self.recheck_current();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn recheck_current(&self) -> Result<()> {
        self.broker.ensure_authority_healthy()?;
        if self.failed || self.broker.journal.snapshot_sequence() != self.sequence {
            return Err(MountError::Fence("FUSE preparation writer changed"));
        }
        self.broker
            .journal
            .validate_held_root_owned_at(STATE_DIRECTORY, "mount.journal")?;
        let request_id = self.request.request_id();
        let idempotency = IdempotencyKey::new(request_id.to_vec())?;
        if self
            .broker
            .journal
            .check_idempotency(&idempotency, digest(self.request.exact_body()))
            != IdempotencyOutcome::Replay(OperationId::from_bytes(request_id))
        {
            return Err(MountError::Fence("FUSE original request index changed"));
        }
        self.scope.recheck().map_err(host_scope_error)?;
        require_scope(&self.decoded, &self.scope)?;
        let value = self
            .broker
            .journal
            .get(RecordNamespace::AuthorityPublication, &self.origin_key)
            .ok_or(MountError::Fence("FUSE origin disappeared"))?;
        let payload = self
            .broker
            .authority
            .open_fuse_origin(&self.origin_key, value)
            .map_err(|_| MountError::Fence("FUSE origin authentication failed"))?;
        if decode_origin(payload)? != self.origin {
            return Err(MountError::Fence("FUSE origin changed"));
        }
        for (namespace, key, expected) in [
            (
                RecordNamespace::DesiredState,
                self.decoded.fence().sandbox_id().as_slice(),
                self.origin.base_fence_digest,
            ),
            (
                RecordNamespace::AuthorityPublication,
                self.phase_key.as_slice(),
                self.origin.phase_fence_digest,
            ),
            (
                RecordNamespace::Effect,
                request_id.as_slice(),
                self.origin.effect_digest,
            ),
        ] {
            if self.broker.journal.get(namespace, key).map(digest) != Some(expected) {
                return Err(MountError::Fence("FUSE authorization row changed"));
            }
        }
        let effect_bytes = self
            .broker
            .journal
            .get(RecordNamespace::Effect, &self.request.request_id())
            .ok_or(MountError::Fence("FUSE effect disappeared"))?;
        let effect = self
            .broker
            .authority
            .open_effect(&self.request.request_id(), effect_bytes)
            .map_err(|_| MountError::Fence("FUSE effect authentication failed"))?;
        if effect.status() != BrokerEffectStatusV1::Pending {
            return Err(MountError::Fence("FUSE preparation is not pending"));
        }
        self.broker
            .authority
            .validate_effect_clock(&effect, &crate::service::trusted_paired_clock_sample()?)
            .map_err(|_| MountError::Fence("FUSE preparation expired"))?;
        let recovered = FuseWorkerReservationTableV1::recover(
            &self.broker.journal,
            self.broker.kernel_boot_id,
        )?;
        if !recovered.rows().any(|row| row == &self.origin.reservation) {
            return Err(MountError::Fence("FUSE reservation changed"));
        }
        let slots = self
            .broker
            .destination_slots
            .as_ref()
            .ok_or(MountError::Fence("FUSE slot owner disappeared"))?;
        let physical = slots.resolve(&self.slot)?;
        if physical.resource().record_digest().as_bytes() != &self.origin.destination_record_digest
            || physical.identity().device != self.origin.destination_device
            || physical.identity().inode != self.origin.destination_inode
        {
            return Err(MountError::Fence("FUSE destination slot changed"));
        }
        self.scope.recheck().map_err(host_scope_error)?;
        self.broker
            .journal
            .validate_held_root_owned_at(STATE_DIRECTORY, "mount.journal")?;
        Ok(())
    }
}

fn host_scope_error(error: crate::host_scope::HostScopeError) -> MountError {
    // Match native catalog scope rechecks: physical failures remain backend
    // failures with private diagnostic detail, while metadata mismatches fence.
    MountError::Worker(error.to_string())
}

fn require_scope(
    request: &ValidatedFuseReserveIntentRequestV1,
    scope: &ObservedMountScope,
) -> Result<()> {
    let metadata = scope.metadata();
    if metadata.fence() != request.fence()
        || metadata.runtime_handle() != request.runtime_handle()
        || metadata.payload_scope_handle() != request.payload_scope_handle()
        || request.header().deadline_boottime_nanoseconds()
            > scope.valid_until_boottime_nanoseconds()
    {
        return Err(MountError::Fence("FUSE original Host scope differs"));
    }
    Ok(())
}

fn select_slot(
    slots: &DestinationSlotStoreV1,
    request: &ValidatedFuseReserveIntentRequestV1,
) -> Result<DestinationSlotBindingV1> {
    let fence = request.fence();
    let mut matches = slots.resources().filter(|slot| {
        let binding = slot.binding();
        binding.sandbox_id() == fence.sandbox_id()
            && binding.incarnation_id() == fence.incarnation_id()
            && binding.assignment_epoch() == fence.assignment_epoch()
            && binding.desired_generation() == fence.desired_generation()
            && binding.assignment_digest() == fence.assignment_digest()
            && binding.namespace_generation() == request.namespace_target_generation()
            && binding.slot_id() == request.intent().destination_slot()
    });
    let slot = matches
        .next()
        .ok_or(MountError::Fence("FUSE physical slot is absent"))?;
    if matches.next().is_some() {
        return Err(MountError::Fence("FUSE slot binding is ambiguous"));
    }
    slots.resolve(slot.binding())?;
    Ok(slot.binding().clone())
}

// Native and FUSE effects share one request-ID namespace. A pending FUSE
// flight cannot be replayed without its original live owners, and an existing
// native index remains occupied even when its effect is absent or reconciled.
pub(super) fn fuse_intent_idempotency_record(
    journal: &Journal,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<JournalRecord> {
    let key = IdempotencyKey::new(request_id.to_vec())?;
    let request_digest = digest(body);
    if journal.check_idempotency(&key, request_digest) != IdempotencyOutcome::Vacant {
        return Err(MountError::Fence(
            "FUSE request ID needs original-flight reconciliation",
        ));
    }
    Ok(JournalRecord::idempotency(
        &key,
        request_digest,
        OperationId::from_bytes(request_id),
    ))
}

fn resource_expiry(
    request: &ValidatedFuseReserveIntentRequestV1,
    clock: &RawPairedClockSample,
    ownership_limit: u64,
) -> Result<u64> {
    let lease = request.intent().lease();
    let duration = lease
        .expires_seconds()
        .checked_sub(clock.wall_seconds())
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| u64::try_from(n).ok())
        .and_then(|n| n.checked_mul(1_000_000_000));
    let deadline = duration
        .and_then(|n| clock.boottime_nanoseconds().checked_add(n))
        .ok_or(MountError::Fence(
            "FUSE accepted lease cannot be mapped to BOOTTIME",
        ))?
        .min(ownership_limit);
    if lease.issued_seconds() > clock.wall_seconds() || deadline <= clock.boottime_nanoseconds() {
        return Err(MountError::Fence("FUSE accepted resource lease is expired"));
    }
    // This lifetime uses accepted attachment+ownership only: never the short
    // request/effect deadline, plan expiry or initiating public capability.
    Ok(deadline)
}

fn key(prefix: &[u8], row: &FuseWorkerReservationV1) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(&row.attachment_id);
    key.extend_from_slice(&row.connection_generation.to_be_bytes());
    key
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn encode_origin(origin: &Origin) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(origin).map_err(|e| MountError::State(e.to_string()))?;
    if bytes.len() > MAXIMUM_ORIGIN_BYTES {
        return Err(MountError::Fence("FUSE origin exceeds capacity"));
    }
    Ok(bytes)
}

fn decode_origin(bytes: &[u8]) -> Result<Origin> {
    if bytes.len() > MAXIMUM_ORIGIN_BYTES {
        return Err(MountError::Fence("FUSE origin exceeds capacity"));
    }
    let origin: Origin =
        serde_json::from_slice(bytes).map_err(|e| MountError::State(e.to_string()))?;
    if origin.version != 1 || encode_origin(&origin)? != bytes {
        return Err(MountError::Fence("FUSE origin is noncanonical"));
    }
    Ok(origin)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, Descriptor, RequestHeader, ReserveFuseWorkerIntentRequestV1,
    };
    use aos_sandbox_core::model::{
        AttachmentConsistency, AttachmentIntent, AttachmentLease, AttachmentPresentation,
        ViewMutation,
    };
    use aos_sandbox_core::{
        AttachmentId, DesiredGeneration, IncarnationId, LeaseId, MediaType, NamespaceGeneration,
        PortableMediaType, RawClockProvenance, Revision, SandboxId, ViewId,
    };

    use super::*;

    #[test]
    fn host_scope_failures_keep_native_backend_class_and_diagnostic_detail() {
        use crate::host_scope::HostScopeError;

        let failures = [
            HostScopeError::HostIdentity,
            HostScopeError::PayloadIdentity,
            HostScopeError::Deadline,
            HostScopeError::Descriptor,
            HostScopeError::Io(rustix::io::Errno::BADF),
            HostScopeError::Transport(aos_sandbox_linux::seqpacket::SeqpacketError::Closed),
            HostScopeError::Kernel(aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "cgroup",
            }),
            HostScopeError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::DeadlineExpired,
            ),
        ];

        for error in failures {
            let detail = error.to_string();
            let mapped = host_scope_error(error);

            assert!(matches!(mapped, MountError::Worker(ref message) if message == &detail));
        }
    }

    fn request() -> ValidatedFuseReserveIntentRequestV1 {
        let intent = AttachmentIntent::new_with_presentation(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(2),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(1),
            None,
            aos_sandbox_core::ObjectDescriptor::new(
                MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
                ObjectDigest::from_bytes([7; 32]),
                1,
            ),
            AttachmentSlotId::from_bytes([8; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            aos_sandbox_core::model::MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([9; 16]), 10, 20).unwrap(),
            AttachmentPresentation::Fuse,
        )
        .unwrap();
        let wire = ReserveFuseWorkerIntentRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 3,
                protocol_minor: 0,
                request_id: vec![11; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![3; 16],
                incarnation_id: vec![4; 16],
                assignment_epoch: 6,
                desired_generation: 7,
                assignment_digest: vec![10; 32],
                ..Default::default()
            })
            .into(),
            attachment_intent_v2: aos_sandbox_core::encode_attachment_intent_v2(&intent),
            desired_record_digest: vec![12; 32],
            namespace_target_generation: 5,
            namespace_allocation_digest: vec![13; 32],
            runtime_handle: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
                &[4; 16], 6, &[10; 32],
            )
            .to_vec(),
            payload_scope_handle: vec![14; 32],
            intent_binding_version: 2,
            accepted_policy: Some(Descriptor {
                media_type: PortableMediaType::Policy.as_str().to_owned(),
                sha256: vec![15; 32],
                encoded_size: 100,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        decode_fuse_reserve_intent_request_v1(
            &wire.encode_to_vec(),
            aos_sandbox_protocol::PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            aos_sandbox_protocol::PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            50,
        )
        .unwrap()
    }

    #[test]
    fn resource_expiry_uses_accepted_attachment_and_ownership_not_dispatch() {
        let request = request();
        let clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            15,
            50,
        )
        .unwrap();
        assert_eq!(
            resource_expiry(&request, &clock, 8_000_000_000).unwrap(),
            4_000_000_050
        );
        assert_eq!(
            resource_expiry(&request, &clock, 3_000_000_000).unwrap(),
            3_000_000_000
        );
        assert!(resource_expiry(&request, &clock, 50).is_err());
        let expired = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            20,
            50,
        )
        .unwrap();
        assert!(resource_expiry(&request, &expired, u64::MAX).is_err());
    }

    #[test]
    fn origin_shape_is_bounded_versioned_and_not_a_live_guard() {
        let request = request();
        let origin = Origin {
            version: 1,
            reservation: FuseWorkerReservationV1 {
                attachment_id: [1; 16],
                connection_generation: 1,
                kernel_boot_id: [2; 16],
                worker_instance_id: [3; 16],
                assignment: AssignmentBindingV1 {
                    sandbox_id: [3; 16],
                    incarnation_id: [4; 16],
                    assignment_epoch: 6,
                    desired_generation: 7,
                    assignment_digest: [10; 32],
                    namespace_generation: 5,
                },
                attachment_generation: 2,
                destination_slot_id: [8; 16],
                source_view_id: [6; 16],
                source_view_revision: 1,
                view_revision: ObjectDescriptorV1::from_runtime(request.intent().view()).unwrap(),
                user_namespace_device: 1,
                user_namespace_inode: 2,
                user_namespace_generation: 5,
                presentation_plan_digest: [16; 32],
                policy_digest: [15; 32],
                lease_identity: [9; 16],
                lease_expires_boottime_ns: 3_000_000_000,
                state: FuseWorkerReservationStateV1::Reserved,
            },
            session: [17; 32],
            signed_request: [18; 32],
            semantics: [19; 32],
            base_fence_digest: [20; 32],
            phase_fence_digest: [21; 32],
            effect_digest: [22; 32],
            destination_record_digest: [23; 32],
            destination_device: 24,
            destination_inode: 25,
        };
        let bytes = encode_origin(&origin).unwrap();
        assert_eq!(decode_origin(&bytes).unwrap(), origin);
        for length in 0..bytes.len() {
            assert!(decode_origin(&bytes[..length]).is_err());
        }
        let mut spaced = bytes.clone();
        spaced.push(b' ');
        assert!(decode_origin(&spaced).is_err());
        let mut unknown = origin.clone();
        unknown.version = 2;
        assert!(decode_origin(&encode_origin(&unknown).unwrap()).is_err());
        assert!(decode_origin(&vec![b' '; MAXIMUM_ORIGIN_BYTES + 1]).is_err());
    }
}
