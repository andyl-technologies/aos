//! Retains actual current Host17 writer partials beneath one eligible boundary.
//!
//! The enclosing Capture row preadmits snapshot constructors independently of
//! this owner's raw census. This owner never selects a cut or ordinal, changes
//! Runtime custody, or derives current state from a historical snapshot.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{NodeRuntime, OriginalRestoredCoordinatorBoundary17, WorldActivation};
use std::mem::size_of;

/// Borrows ancestry already authenticated by one actual signed Source ticket.
///
/// The defining ticket getter issues this view. It is not a native permission;
/// cloning its bodies is separately admitted by the actual writer row.
pub(crate) struct RestoredHostCaptureAncestryBorrowed17<'a> {
    pub(crate) parent_archive_index: &'a ContentRef,
    pub(crate) first_host: &'a ContentRef,
    pub(crate) first_semantic: [(&'a Id, &'a ContentRef); 3],
}

#[derive(Serialize)]
struct AncestryProjection<'a> {
    parent_archive_index: &'a ContentRef,
    first_host: &'a ContentRef,
    first_semantic: [SemanticProjection<'a>; 3],
}

#[derive(Serialize)]
struct SemanticProjection<'a> {
    node: &'a Id,
    object: &'a ContentRef,
}

impl RestoredHostCaptureAncestryBorrowed17<'_> {
    fn projection_data(&self) -> AncestryProjection<'_> {
        AncestryProjection {
            parent_archive_index: self.parent_archive_index,
            first_host: self.first_host,
            first_semantic: self
                .first_semantic
                .map(|(node, object)| SemanticProjection { node, object }),
        }
    }

    fn clone_data(&self) -> RestoredHostAncestry17 {
        RestoredHostAncestry17 {
            parent_archive_index: self.parent_archive_index.clone(),
            first_host: self.first_host.clone(),
            first_semantic: self.first_semantic.map(|(node, object)| {
                RestoredHostSemanticAncestor {
                    node: node.clone(),
                    object: object.clone(),
                }
            }),
        }
    }
}

/// Owns the actual complete current record and encoded object after writer success.
///
/// This value carries facts only. The real all-owner administrative ticket,
/// native Capture, Source seal and signed archive publication remain separate.
pub(crate) struct HostSchedulingRestoredContinuation17 {
    record: HostSchedulingRestoredContinuationRecord17,
    encoded: InputPayload,
}

impl HostSchedulingRestoredContinuation17 {
    pub(crate) fn record_data(&self) -> &HostSchedulingRestoredContinuationRecord17 {
        &self.record
    }

    pub(crate) fn encoded_data(&self) -> &InputPayload {
        &self.encoded
    }

    pub(crate) fn into_parts_data(
        self,
    ) -> (HostSchedulingRestoredContinuationRecord17, InputPayload) {
        (self.record, self.encoded)
    }

    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        checked_sum(&[
            size_of::<Self>(),
            self.record.retained_requested_storage_data()?,
            self.encoded.bytes.capacity(),
            self.encoded.reference.owned_storage()?,
        ])
    }
}

/// Retains the one actual writer occurrence, including every constructed partial.
///
/// A failed occurrence is spent. The caller keeps this owner and the returned
/// original error; no snapshot, DOM or encoded buffer is replaced on retry.
pub(crate) struct HostSchedulingRestoredCaptureAttempt17 {
    source: Option<HostSchedulingSelection>,
    runtime: Option<OriginalLineageRuntimeRecord>,
    scheduling: Option<SchedulingSnapshot>,
    objects: Vec<InputPayload>,
    ancestry: Option<RestoredHostAncestry17>,
    record: Option<HostSchedulingRestoredContinuationRecord17>,
    dom: Option<Value>,
    encoded_bytes: Vec<u8>,
    encoded_reference: Option<ContentRef>,
    started: bool,
    completed: bool,
}

impl HostSchedulingRestoredCaptureAttempt17 {
    /// Retains this attempt before constructing current common-state owners.
    ///
    /// The maximum is the independent enclosing row's admitted constructor and
    /// owner ceiling. It does not enlarge any Runtime policy, native budget or
    /// lifetime counter. All partial results precede later fallible work.
    ///
    /// # Errors
    /// Refuses occupied destinations, foreign or stale eligibility, missing
    /// genuine archive ancestry, unsupported scope, finite credit excess or any
    /// changed current source, body, cut, ordinal or policy.
    pub(crate) fn capture_into(
        observation: &HostSchedulingObservation<'_>,
        world: &WorldActivation,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        limits: HostSchedulingContinuationLimits,
        maximum_requested_bytes: usize,
        pending: &mut Option<Self>,
        output: &mut Option<HostSchedulingRestoredContinuation17>,
    ) -> Result<(), RuntimeError> {
        if pending.is_some() || output.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        boundary.authenticate_runtime_data(observation.runtime, world, observation.source)?;
        validation::validate_limits(limits)?;
        if maximum_requested_bytes < size_of::<Self>() {
            return Err(RuntimeError::ResourceLimit);
        }
        *pending = Some(Self {
            source: None,
            runtime: None,
            scheduling: None,
            objects: Vec::new(),
            ancestry: None,
            record: None,
            dom: None,
            encoded_bytes: Vec::new(),
            encoded_reference: None,
            started: false,
            completed: false,
        });
        pending
            .as_mut()
            .ok_or(RuntimeError::OutstandingObligations)?
            .capture(
                observation,
                world,
                boundary,
                limits,
                maximum_requested_bytes,
                output,
            )
    }

    fn capture(
        &mut self,
        observation: &HostSchedulingObservation<'_>,
        world: &WorldActivation,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        limits: HostSchedulingContinuationLimits,
        maximum: usize,
        output: &mut Option<HostSchedulingRestoredContinuation17>,
    ) -> Result<(), RuntimeError> {
        if self.started || self.completed || output.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        let runtime = observation.runtime;
        let source = observation.source;
        let cut = boundary.cut_data();
        let ordinal = boundary.ordinal_data();
        let quarter = limits.maximum_record_bytes / 4;
        if quarter == 0 {
            return Err(RuntimeError::ResourceLimit);
        }
        let archive = source
            .archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        archive.authenticate_birth()?;
        archive.with_restored_capture_ancestry17_data(
            limits.maximum_record_bytes,
            self.retained_requested_storage_data()?,
            |ancestry| {
                self.admit_prospective(&ancestry.projection_data(), maximum)?;
                self.ancestry = Some(ancestry.clone_data());
                Ok(())
            },
        )?;
        self.admit_prospective(source.selection(), maximum)?;
        self.source = Some(source.selection().clone());

        // Price both complete future typed snapshots before either copy. These
        // source-defined serializers borrow the actual Runtime and Scheduler;
        // current encoding size is never used as a heap-layout multiplier.
        let runtime_construction =
            runtime.host_restored17_runtime_snapshot_construction_data(cut, ordinal, maximum)?;
        let scheduling_construction =
            runtime.host_restored17_scheduler_snapshot_construction_data(cut, ordinal, maximum)?;
        self.admit_additional(
            checked_sum(&[runtime_construction, scheduling_construction])?,
            maximum,
        )?;
        runtime.host_scheduler_preflight(quarter)?;
        self.runtime = Some(runtime.original_lineage_runtime_snapshot(
            cut,
            ordinal,
            limits.lineage,
            quarter,
        )?);
        self.scheduling = Some(runtime.host_scheduler_snapshot(cut, ordinal)?);
        let saved_runtime = self.runtime.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
        let scheduling = self
            .scheduling
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        runtime.authenticate_restored17_host_role_data(source, saved_runtime, scheduling)?;
        self.admit_current(maximum)?;

        let mut remaining = limits.lineage;
        let count = runtime.original_lineage_capture_objects().count();
        let slots = count
            .checked_mul(size_of::<InputPayload>())
            .ok_or(RuntimeError::ResourceLimit)?;
        self.admit_additional(slots, maximum)?;
        self.objects
            .try_reserve_exact(count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for object in runtime.original_lineage_capture_objects() {
            remaining.maximum_objects = remaining
                .maximum_objects
                .checked_sub(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            remaining.maximum_bytes = remaining
                .maximum_bytes
                .checked_sub(object.bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            object
                .reference
                .verify(&object.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            self.admit_prospective(object, maximum)?;
            self.objects.push(object.clone());
        }
        // Every original occurrence was independently charged before copying.
        // Deduplication only chooses the portable full-reference representation.
        self.objects
            .sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        if self
            .objects
            .windows(2)
            .any(|pair| pair[0].reference == pair[1].reference && pair[0].bytes != pair[1].bytes)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.objects
            .dedup_by(|left, right| left.reference == right.reference);
        self.record = Some(HostSchedulingRestoredContinuationRecord17 {
            schema_version: 17,
            source: self.source.take().ok_or(RuntimeError::InvalidReceipt)?,
            runtime: self.runtime.take().ok_or(RuntimeError::InvalidReceipt)?,
            scheduling: self.scheduling.take().ok_or(RuntimeError::InvalidReceipt)?,
            objects: std::mem::take(&mut self.objects),
            ancestry: self.ancestry.take().ok_or(RuntimeError::InvalidReceipt)?,
            admission_policy: runtime.host_restored17_runtime_limits_data().into(),
        });
        let record = self.record.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
        record.validate_data(limits)?;
        let serialization =
            NodeRuntime::original_runtime_constructor_serialization_storage_data(record, maximum)?;
        self.admit_additional(serialization, maximum)?;
        self.dom = Some(serde_json::to_value(record).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.encoded_bytes =
            canonical::canonical_json(self.dom.as_ref().ok_or(RuntimeError::InvalidReceipt)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        // The already admitted canonical constructor covers both returned byte
        // backing and the hash's fixed workspace while the DOM remains retained.
        self.encoded_reference = Some(
            canonical::content_ref(&self.encoded_bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        self.admit_current(maximum)?;
        boundary.authenticate_runtime_data(runtime, world, source)?;
        archive.authenticate_birth()?;
        let record = self.record.take().ok_or(RuntimeError::InvalidReceipt)?;
        let reference = self
            .encoded_reference
            .take()
            .ok_or(RuntimeError::InvalidReceipt)?;
        let encoded = InputPayload {
            reference,
            bytes: std::mem::take(&mut self.encoded_bytes),
        };
        *output = Some(HostSchedulingRestoredContinuation17 { record, encoded });
        self.completed = true;
        Ok(())
    }

    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut bytes = size_of::<Self>();
        for next in [
            self.source.owned_storage()?,
            self.runtime.owned_storage()?,
            self.scheduling.owned_storage()?,
            self.objects.owned_storage()?,
            self.encoded_bytes.capacity(),
            self.encoded_reference.owned_storage()?,
        ] {
            bytes = bytes.checked_add(next).ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(ancestry) = &self.ancestry {
            bytes = bytes
                .checked_add(ancestry_owned(ancestry)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(record) = &self.record {
            bytes = bytes
                .checked_add(record.retained_requested_storage_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(dom) = &self.dom {
            bytes = bytes
                .checked_add(dom.owned_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(bytes)
    }

    fn admit_current(&self, maximum: usize) -> Result<(), RuntimeError> {
        self.admit_additional(0, maximum)
    }

    fn admit_additional(&self, additional: usize, maximum: usize) -> Result<(), RuntimeError> {
        self.retained_requested_storage_data()?
            .checked_add(additional)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn admit_prospective(
        &self,
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let future = NodeRuntime::capture_future_decode_storage(value, maximum)?;
        self.admit_additional(future, maximum)
    }
}

fn ancestry_owned(value: &RestoredHostAncestry17) -> Result<usize, RuntimeError> {
    let mut bytes = checked_sum(&[
        value.parent_archive_index.owned_storage()?,
        value.first_host.owned_storage()?,
    ])?;
    for semantic in &value.first_semantic {
        bytes = checked_sum(&[
            bytes,
            semantic.node.owned_storage()?,
            semantic.object.owned_storage()?,
        ])?;
    }
    Ok(bytes)
}

fn checked_sum(values: &[usize]) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or(RuntimeError::ResourceLimit)
    })
}
