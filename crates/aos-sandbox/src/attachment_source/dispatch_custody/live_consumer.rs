//! Closed Controller source for a named LocalLive consumer and Host query.
//!
//! The 672-byte `AOSLCS01` source is derived only from a current protected
//! Controller dispatch token. Its digest can be named by a future separately
//! signed Storage/Host plan, but neither these bytes nor a matching method-34
//! query convey a cgroup descriptor, Storage partition, or kernel grant.
//!
//! ```text
//! AOSLCS01 | version:u16be=1 | reserved:6 | controller-sequence:u64be |
//! host-boot-id:16 |
//! consumer:(sandbox:16, incarnation:16, epoch:u64be, generation:u64be,
//!           assignment-digest:32, runtime-handle:32, scope-handle:32) |
//! source:(sandbox:16, incarnation:16, epoch:u64be, generation:u64be,
//!         assignment-digest:32) |
//! export:16 | export-generation:u64be |
//! attachment:16 | attachment-generation:u64be | desired-record-digest:32 |
//! view:16 | view-revision:u64be | current-view-record-digest:32 |
//! view-descriptor-digest:32 | acquire-operation:16 | acquisition-id:32 |
//! acquire-record-digest:32 | acquire-request-digest:32 |
//! source-plan-digest:32 | exact-dispatch-packet-digest:32 |
//! exclusive-boottime-deadline:u64be | attachment-lease-id:16 |
//! attachment-lease-issued:i64be | attachment-lease-expires:i64be |
//! destination-slot:16 | namespace-generation:u64be
//! ```

use aos_sandbox_core::model::{AttachmentConsistency, ViewConsistency, ViewSource};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::host_consumer_cgroup::ValidatedConsumerCgroupRequestV1;
use sha2::Sha256;

use super::*;
use crate::filesystem_view_state::{self, FilesystemViewRevisionPresenceV1};

const MAGIC: &[u8; 8] = b"AOSLCS01";
const VERSION: u16 = 1;
const SOURCE_BYTES: usize = 672;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-local-live-consumer-source.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Assignment {
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    epoch: u64,
    generation: u64,
    digest: [u8; 32],
}

/// Retains a closed, signable Controller statement about one Acquire cut.
///
/// The source is copied data. Its sequence and digest are not a replacement for
/// the held Controller writer or for independent Storage/Host readback. No
/// production signer, verifier, or method-34 dispatch consumes this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedControllerLiveConsumerSourceV1 {
    controller_sequence: u64,
    host_boot_id: [u8; 16],
    consumer: Assignment,
    consumer_runtime_handle: [u8; 32],
    consumer_scope_handle: [u8; 32],
    source: Assignment,
    export: [u8; 16],
    export_generation: u64,
    attachment: [u8; 16],
    attachment_generation: u64,
    desired_digest: [u8; 32],
    view: [u8; 16],
    view_revision: u64,
    view_record_digest: [u8; 32],
    view_descriptor_digest: [u8; 32],
    acquire_operation: [u8; 16],
    acquisition_id: [u8; 32],
    acquire_record_digest: [u8; 32],
    acquire_request_digest: [u8; 32],
    source_plan_digest: [u8; 32],
    dispatch_packet_digest: [u8; 32],
    deadline_boottime_nanoseconds: u64,
    attachment_lease_id: [u8; 16],
    attachment_lease_issued_seconds: i64,
    attachment_lease_expires_seconds: i64,
    destination_slot: [u8; 16],
    namespace_generation: u64,
}

impl ClosedControllerLiveConsumerSourceV1 {
    /// Returns the exact source bytes for a future separately reviewed signer.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SOURCE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.controller_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.host_boot_id);
        append_assignment(&mut bytes, self.consumer);
        bytes.extend_from_slice(&self.consumer_runtime_handle);
        bytes.extend_from_slice(&self.consumer_scope_handle);
        append_assignment(&mut bytes, self.source);
        bytes.extend_from_slice(&self.export);
        bytes.extend_from_slice(&self.export_generation.to_be_bytes());
        bytes.extend_from_slice(&self.attachment);
        bytes.extend_from_slice(&self.attachment_generation.to_be_bytes());
        bytes.extend_from_slice(&self.desired_digest);
        bytes.extend_from_slice(&self.view);
        bytes.extend_from_slice(&self.view_revision.to_be_bytes());
        bytes.extend_from_slice(&self.view_record_digest);
        bytes.extend_from_slice(&self.view_descriptor_digest);
        bytes.extend_from_slice(&self.acquire_operation);
        bytes.extend_from_slice(&self.acquisition_id);
        bytes.extend_from_slice(&self.acquire_record_digest);
        bytes.extend_from_slice(&self.acquire_request_digest);
        bytes.extend_from_slice(&self.source_plan_digest);
        bytes.extend_from_slice(&self.dispatch_packet_digest);
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&self.attachment_lease_id);
        bytes.extend_from_slice(&self.attachment_lease_issued_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.attachment_lease_expires_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.destination_slot);
        bytes.extend_from_slice(&self.namespace_generation.to_be_bytes());
        bytes
    }

    /// Returns the domain-separated commitment to the exact source bytes.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(DIGEST_DOMAIN)
                .chain_update(self.canonical_bytes())
                .finalize()
                .into(),
        )
    }

    /// Compares a validated Storage-audience Host query to this consumer.
    ///
    /// Equality is necessary but does not authenticate Storage, retain its
    /// broker journal, or authorize the resulting cgroup descriptors.
    #[must_use]
    pub fn matches_host_query(&self, query: &ValidatedConsumerCgroupRequestV1) -> bool {
        let fence = query.fence();
        fence.sandbox_id() == &self.consumer.sandbox
            && fence.incarnation_id() == &self.consumer.incarnation
            && fence.assignment_epoch() == self.consumer.epoch
            && fence.desired_generation() == self.consumer.generation
            && fence.assignment_digest() == &self.consumer.digest
            && query.runtime_handle() == &self.consumer_runtime_handle
            && query.payload_scope_handle() == &self.consumer_scope_handle
            && query.header().deadline_boottime_nanoseconds() <= self.deadline_boottime_nanoseconds
    }
}

impl DurableCurrentAttachmentSourceDispatchV1 {
    /// Projects one current LocalLive consumer under the held Controller cut.
    ///
    /// A source can be prepared only for an exact open Acquire of the current
    /// desired attachment and current View revision. The source owner is the
    /// separately observed Host assignment, not a caller-selected sandbox.
    /// The export ID is a logical selector; Storage must independently map it
    /// to its current physical partition before any effect.
    ///
    /// # Errors
    ///
    /// Rejects stale desired/View/Host/attempt custody, a non-live source,
    /// expired lease or observation, or a changed Controller head.
    pub fn closed_local_live_consumer_source<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<ClosedControllerLiveConsumerSourceV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        journal.ensure_protected_authority()?;
        self.recheck(journal, clock)?;
        let sequence = journal.snapshot_sequence();
        let intent = self.desired.intent();
        let attempt = &self.source.record;
        if self.source.kind() != AttachmentSourceAttemptKindV1::Acquire
            || self.desired.presence() != attachment_state::AttachmentDesiredPresenceV1::Present
            || intent.consistency() != AttachmentConsistency::LocalLive
            || attempt.attachment_id != *intent.id().as_bytes()
            || attempt.desired_generation != intent.desired_generation().get()
            || attempt.desired_digest != *self.desired.record_digest().as_bytes()
        {
            return Err(AttachmentSourceError::Conflict);
        }

        let sample = clock()?;
        let boot_id = KernelBootId::current()
            .map_err(|_| AttachmentSourceError::Changed)?
            .into_bytes();
        let lease = intent.lease();
        if sample.host_boot_id() != boot_id
            || sample.wall_seconds() < lease.issued_seconds()
            || sample.wall_seconds() >= lease.expires_seconds()
        {
            return Err(AttachmentSourceError::Changed);
        }
        let (view_id, revision) = intent.source_view();
        let view = filesystem_view_state::get_current(journal, view_id)?
            .filter(|view| {
                view.presence() == FilesystemViewRevisionPresenceV1::Available
                    && view.revision() == revision
                    && view.descriptor() == intent.view()
                    && view.view().consistency() == ViewConsistency::LocalLive
            })
            .ok_or(AttachmentSourceError::Changed)?;
        let ViewSource::LiveExport {
            owner_sandbox,
            export,
            source_generation,
        } = view.source_handle()
        else {
            return Err(AttachmentSourceError::Conflict);
        };
        let source_scope = self
            .source_scope
            .as_ref()
            .ok_or(AttachmentSourceError::Conflict)?;
        let consumer_scope = self.target.runtime_generation().scope();
        let consumer_manifest = consumer_scope.binding().manifest().manifest();
        let source_manifest = source_scope.binding().manifest().manifest();
        let (consumer_sandbox, consumer_incarnation) = intent.consumer();
        if consumer_manifest.sandbox() != consumer_sandbox
            || consumer_manifest.incarnation() != consumer_incarnation
            || source_manifest.sandbox() != *owner_sandbox
            || intent.source_incarnation() != Some(source_manifest.incarnation())
            || source_manifest.node() != consumer_manifest.node()
        {
            return Err(AttachmentSourceError::Conflict);
        }
        source_scope.verify_local_live_source(
            journal,
            view.source_handle(),
            source_manifest.incarnation(),
            consumer_manifest.node(),
            clock,
        )?;

        let source = ClosedControllerLiveConsumerSourceV1 {
            controller_sequence: sequence,
            host_boot_id: boot_id,
            consumer: assignment(
                consumer_manifest,
                consumer_scope.binding().assignment_digest(),
            ),
            consumer_runtime_handle: *consumer_scope.observed().runtime_handle(),
            consumer_scope_handle: *consumer_scope.observed().payload_scope_handle(),
            source: assignment(source_manifest, source_scope.binding().assignment_digest()),
            export: *export.as_bytes(),
            export_generation: source_generation.get(),
            attachment: *intent.id().as_bytes(),
            attachment_generation: intent.desired_generation().get(),
            desired_digest: *self.desired.record_digest().as_bytes(),
            view: *view_id.as_bytes(),
            view_revision: revision.get(),
            view_record_digest: *view.record_digest().as_bytes(),
            view_descriptor_digest: *intent.view().digest().as_bytes(),
            acquire_operation: attempt.operation_id,
            acquisition_id: attempt.acquisition_id,
            acquire_record_digest: attempt.digest,
            acquire_request_digest: attempt.request_digest,
            source_plan_digest: attempt.plan_digest,
            dispatch_packet_digest: Sha256::digest(self.dispatch.packet()).into(),
            deadline_boottime_nanoseconds: consumer_scope
                .deadline_boottime_nanoseconds()
                .min(source_scope.deadline_boottime_nanoseconds()),
            attachment_lease_id: *lease.id().as_bytes(),
            attachment_lease_issued_seconds: lease.issued_seconds(),
            attachment_lease_expires_seconds: lease.expires_seconds(),
            destination_slot: *intent.destination_slot().as_bytes(),
            namespace_generation: intent.expected_namespace_generation().get(),
        };
        if source.canonical_bytes().len() != SOURCE_BYTES {
            return Err(AttachmentSourceError::Protocol);
        }
        self.recheck(journal, clock)?;
        if journal.snapshot_sequence() != sequence {
            return Err(AttachmentSourceError::Changed);
        }
        Ok(source)
    }
}

fn assignment(
    manifest: &aos_sandbox_core::model::AssignmentManifestV1,
    digest: ObjectDigest,
) -> Assignment {
    Assignment {
        sandbox: *manifest.sandbox().as_bytes(),
        incarnation: *manifest.incarnation().as_bytes(),
        epoch: manifest.epoch().get(),
        generation: manifest.desired_generation().get(),
        digest: *digest.as_bytes(),
    }
}

fn append_assignment(bytes: &mut Vec<u8>, assignment: Assignment) {
    bytes.extend_from_slice(&assignment.sandbox);
    bytes.extend_from_slice(&assignment.incarnation);
    bytes.extend_from_slice(&assignment.epoch.to_be_bytes());
    bytes.extend_from_slice(&assignment.generation.to_be_bytes());
    bytes.extend_from_slice(&assignment.digest);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, ObserveConsumerCgroupRequestV1, RequestHeader,
    };
    use aos_sandbox_protocol::host_consumer_cgroup::decode_consumer_cgroup_request_v1;
    use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

    fn fixture() -> ClosedControllerLiveConsumerSourceV1 {
        ClosedControllerLiveConsumerSourceV1 {
            controller_sequence: 17,
            host_boot_id: [32; 16],
            consumer: Assignment {
                sandbox: [1; 16],
                incarnation: [2; 16],
                epoch: 3,
                generation: 4,
                digest: [5; 32],
            },
            consumer_runtime_handle: runtime_handle_v1(&[2; 16], 3, &[5; 32]),
            consumer_scope_handle: [7; 32],
            source: Assignment {
                sandbox: [8; 16],
                incarnation: [9; 16],
                epoch: 10,
                generation: 11,
                digest: [12; 32],
            },
            export: [13; 16],
            export_generation: 14,
            attachment: [15; 16],
            attachment_generation: 16,
            desired_digest: [17; 32],
            view: [18; 16],
            view_revision: 19,
            view_record_digest: [20; 32],
            view_descriptor_digest: [21; 32],
            acquire_operation: [22; 16],
            acquisition_id: [23; 32],
            acquire_record_digest: [24; 32],
            acquire_request_digest: [25; 32],
            source_plan_digest: [26; 32],
            dispatch_packet_digest: [27; 32],
            deadline_boottime_nanoseconds: 28,
            attachment_lease_id: [29; 16],
            attachment_lease_issued_seconds: 12,
            attachment_lease_expires_seconds: 32,
            destination_slot: [30; 16],
            namespace_generation: 31,
        }
    }

    #[test]
    fn canonical_source_binds_both_assignments_and_exact_attempt() {
        let source = fixture();
        let bytes = source.canonical_bytes();
        assert_eq!(bytes.len(), SOURCE_BYTES);
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[10..16], [0; 6]);

        let original = source.digest();
        for changed in [
            {
                let mut value = source.clone();
                value.controller_sequence += 1;
                value
            },
            {
                let mut value = source.clone();
                value.consumer.digest[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.source.digest[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.export_generation += 1;
                value
            },
            {
                let mut value = source.clone();
                value.desired_digest[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.view_record_digest[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.acquisition_id[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.dispatch_packet_digest[0] ^= 1;
                value
            },
            {
                let mut value = source.clone();
                value.attachment_lease_expires_seconds += 1;
                value
            },
        ] {
            assert_ne!(changed.digest(), original);
        }
    }

    fn host_query(
        source: &ClosedControllerLiveConsumerSourceV1,
        deadline: u64,
        scope: [u8; 32],
    ) -> ValidatedConsumerCgroupRequestV1 {
        let request = ObserveConsumerCgroupRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![31; 16],
                audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                deadline_boottime_nanoseconds: deadline,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: source.consumer.sandbox.to_vec(),
                incarnation_id: source.consumer.incarnation.to_vec(),
                assignment_epoch: source.consumer.epoch,
                desired_generation: source.consumer.generation,
                assignment_digest: source.consumer.digest.to_vec(),
                ..Default::default()
            })
            .into(),
            runtime_handle: source.consumer_runtime_handle.to_vec(),
            payload_scope_handle: scope.to_vec(),
            ..Default::default()
        };
        decode_consumer_cgroup_request_v1(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(47),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_STORAGE_BROKER,
            },
            20,
        )
        .expect("valid Storage-audience query")
    }

    #[test]
    fn method_34_comparison_rejects_stale_scope_or_extended_deadline() {
        let source = fixture();
        assert!(source.matches_host_query(&host_query(&source, 28, [7; 32])));
        assert!(!source.matches_host_query(&host_query(&source, 29, [7; 32])));
        assert!(!source.matches_host_query(&host_query(&source, 28, [8; 32])));

        let mut replaced = source.clone();
        replaced.consumer.generation += 1;
        assert!(!replaced.matches_host_query(&host_query(&source, 28, [7; 32])));
    }
}
