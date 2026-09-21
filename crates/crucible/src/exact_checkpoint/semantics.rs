//! One-shot access to repository-authenticated lifecycle objects.

use std::io::{self, Read};

use super::{
    ExactCheckpointClosureRecord, ExactCheckpointExecutionSourceError,
    ExactCheckpointRepositoryBinding,
};
use crate::ContentHash;

/// The semantic role of one authenticated closure object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactCheckpointSemanticObjectRole<'a> {
    /// Compact modeled schedule.
    Schedule,
    /// Canonical scheduler continuation.
    Scheduler,
    /// Ordered scheduler event-log segment.
    EventLogSegment {
        /// Position in the ordered event log.
        index: usize,
        /// Authenticated content identity.
        identity: ContentHash,
    },
    /// Sorted signal-plan artifact.
    SignalArtifact {
        /// Position in the sorted signal-artifact catalog.
        index: usize,
        /// Authenticated content identity.
        identity: ContentHash,
    },
    /// Trigger runtime continuation.
    TriggerState,
    /// Assertion runtime continuation.
    AssertionState,
    /// VM lifecycle continuation.
    LifecycleState,
    /// Fault runtime continuation.
    FaultCheckpoint,
    /// QEMU and Apache snapshot plus authenticated target metadata.
    TargetSnapshot {
        /// Live node name.
        node: &'a str,
        /// Configuration identity.
        configuration: ContentHash,
        /// Immutable guest backing identity.
        immutable_backing: ContentHash,
        /// Node instruction counter.
        counter: u64,
        /// Scheduler virtual-time tick.
        scheduler_time: u64,
    },
    /// Authenticated generation counter for one node.
    NodeGeneration(&'a str, u64),
    /// Authenticated service-state tag for one node.
    NodeServiceState(&'a str, u8),
    /// Host-I/O continuation for one failed node.
    FailedHostIo {
        /// Failed node name.
        node: &'a str,
        /// Failed execution binding.
        execution_binding: ContentHash,
        /// Fingerprint coordinate.
        fingerprint_at: u64,
        /// Fingerprint identity.
        fingerprint: ContentHash,
    },
}

pub(super) fn visit_authenticated_semantic_objects(
    repository: &ExactCheckpointRepositoryBinding,
    closure: &ExactCheckpointClosureRecord,
    targets: &[Option<super::ExactCheckpointTargetRecord>],
    byte_limit: u64,
    mut boundary: impl FnMut() -> io::Result<()>,
    mut open: impl FnMut(ContentHash) -> io::Result<Box<dyn Read + Send>>,
    mut visit: impl FnMut(ExactCheckpointSemanticObjectRole<'_>, &[u8]) -> io::Result<()>,
) -> Result<(), ExactCheckpointExecutionSourceError> {
    let objects = read_unique_semantic_objects(
        repository,
        closure,
        targets,
        byte_limit,
        &mut boundary,
        &mut open,
    )?;
    {
        let mut deliver = |role, identity| {
            let object = objects
                .binary_search_by_key(&identity, |object| object.identity)
                .ok()
                .and_then(|index| objects.get(index))
                .ok_or_else(|| io::Error::other("semantic object was not authenticated"))?;
            visit(role, &object.bytes)?;
            boundary()
        };

        deliver(
            ExactCheckpointSemanticObjectRole::Schedule,
            closure.schedule,
        )?;
        deliver(
            ExactCheckpointSemanticObjectRole::Scheduler,
            closure.scheduler,
        )?;
        for (index, identity) in closure.event_log_segments.iter().copied().enumerate() {
            deliver(
                ExactCheckpointSemanticObjectRole::EventLogSegment { index, identity },
                identity,
            )?;
        }
        for (index, identity) in closure.signal_artifacts.iter().copied().enumerate() {
            deliver(
                ExactCheckpointSemanticObjectRole::SignalArtifact { index, identity },
                identity,
            )?;
        }
        deliver(
            ExactCheckpointSemanticObjectRole::TriggerState,
            closure.trigger_state,
        )?;
        deliver(
            ExactCheckpointSemanticObjectRole::AssertionState,
            closure.assertion_state,
        )?;
        deliver(
            ExactCheckpointSemanticObjectRole::LifecycleState,
            closure.lifecycle_state,
        )?;
        deliver(
            ExactCheckpointSemanticObjectRole::FaultCheckpoint,
            closure.fault_checkpoint,
        )?;
        for target in targets.iter().flatten() {
            deliver(
                ExactCheckpointSemanticObjectRole::TargetSnapshot {
                    node: &target.node,
                    configuration: closure.configuration,
                    immutable_backing: target.immutable_backing,
                    counter: target.counter,
                    scheduler_time: target.scheduler_time,
                },
                target.snapshot,
            )?;
        }
        for failed in &closure.failed_host_io {
            deliver(
                ExactCheckpointSemanticObjectRole::FailedHostIo {
                    node: &failed.node,
                    execution_binding: failed.execution_binding,
                    fingerprint_at: failed.fingerprint_at,
                    fingerprint: failed.fingerprint,
                },
                failed.checkpoint,
            )?;
        }
    }

    for (node, generation) in &closure.node_generations {
        visit(
            ExactCheckpointSemanticObjectRole::NodeGeneration(node, *generation),
            &[],
        )?;
        boundary()?;
    }
    for (node, service_state) in &closure.node_service_states {
        visit(
            ExactCheckpointSemanticObjectRole::NodeServiceState(node, *service_state),
            &[],
        )?;
        boundary()?;
    }

    Ok(())
}

struct AuthenticatedSemanticObject {
    identity: ContentHash,
    bytes: Vec<u8>,
}

fn read_unique_semantic_objects(
    repository: &ExactCheckpointRepositoryBinding,
    closure: &ExactCheckpointClosureRecord,
    targets: &[Option<super::ExactCheckpointTargetRecord>],
    byte_limit: u64,
    boundary: &mut impl FnMut() -> io::Result<()>,
    open: &mut impl FnMut(ContentHash) -> io::Result<Box<dyn Read + Send>>,
) -> Result<Vec<AuthenticatedSemanticObject>, ExactCheckpointExecutionSourceError> {
    let semantic_object_count = closure_object_reference_count(closure, targets)?;
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(semantic_object_count)
        .map_err(|_| io::Error::other("allocate semantic identity accounting"))?;
    identities.extend([
        closure.schedule,
        closure.scheduler,
        closure.trigger_state,
        closure.assertion_state,
        closure.lifecycle_state,
        closure.fault_checkpoint,
    ]);
    identities.extend(closure.event_log_segments.iter().copied());
    identities.extend(closure.signal_artifacts.iter().copied());
    identities.extend(targets.iter().flatten().map(|target| target.snapshot));
    identities.extend(
        closure
            .failed_host_io
            .iter()
            .map(|failed| failed.checkpoint),
    );
    identities.sort_unstable();
    identities.dedup();

    let mut consumed = 0_u64;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(identities.len())
        .map_err(|_| io::Error::other("allocate semantic object catalog"))?;
    for identity in identities {
        let length = repository
            .objects
            .binary_search_by_key(&identity, |object| object.identity)
            .ok()
            .and_then(|index| repository.objects.get(index))
            .ok_or_else(|| io::Error::other("semantic object is absent from repository inventory"))?
            .length;
        consumed = consumed
            .checked_add(length)
            .filter(|total| *total <= byte_limit)
            .ok_or_else(|| io::Error::other("semantic object aggregate exceeds its byte limit"))?;
        let bytes = read_authenticated_object(repository, identity, boundary, open)?;
        objects.push(AuthenticatedSemanticObject { identity, bytes });
    }

    Ok(objects)
}

fn closure_object_reference_count(
    closure: &ExactCheckpointClosureRecord,
    targets: &[Option<super::ExactCheckpointTargetRecord>],
) -> Result<usize, ExactCheckpointExecutionSourceError> {
    6_usize
        .checked_add(closure.event_log_segments.len())
        .and_then(|count| count.checked_add(closure.signal_artifacts.len()))
        .and_then(|count| count.checked_add(targets.len()))
        .and_then(|count| count.checked_add(closure.failed_host_io.len()))
        .ok_or_else(|| io::Error::other("semantic object reference count overflow").into())
}

fn read_authenticated_object(
    repository: &ExactCheckpointRepositoryBinding,
    identity: ContentHash,
    boundary: &mut impl FnMut() -> io::Result<()>,
    open: &mut impl FnMut(ContentHash) -> io::Result<Box<dyn Read + Send>>,
) -> io::Result<Vec<u8>> {
    let expected = repository
        .objects
        .binary_search_by_key(&identity, |object| object.identity)
        .ok()
        .and_then(|index| repository.objects.get(index))
        .ok_or_else(|| io::Error::other("semantic object is absent from repository inventory"))?
        .length;
    let length = usize::try_from(expected)
        .map_err(|_| io::Error::other("semantic object length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("allocate semantic object buffer"))?;
    bytes.resize(length, 0);

    boundary()?;
    let mut reader = open(identity)?;
    let mut offset = 0_usize;
    while offset < bytes.len() {
        boundary()?;
        let count = reader.read(&mut bytes[offset..])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short semantic checkpoint object",
            ));
        }
        offset += count;
    }
    boundary()?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 || ContentHash::from_bytes(&bytes) != identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "semantic checkpoint object identity mismatch",
        ));
    }

    Ok(bytes)
}
