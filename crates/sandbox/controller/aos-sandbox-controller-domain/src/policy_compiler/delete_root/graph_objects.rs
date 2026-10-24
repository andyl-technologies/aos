//! Joins actual pre-Planned graph DATA with Root's own retained immutable files.
//!
//! The same R admits every reached native/model phase before growth. Exact file
//! names, device/inode and verity come only from this Root reader's own canonical
//! full manifest. No forwarded graph, descriptor, filename or hash creates an
//! original; the enclosing Delete conjunction still owns acceptance and effects.

use super::*;
use aos_sandbox_broker::physical_cache_observation::current_view::{
    CacheObjectViewOriginalV1, CacheObjectViewClosedV1,
    RootCacheMetadataReadOriginalV2, RootCacheMetadataReadClosedV2,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector, RawPairedClockSample};
use aos_sandbox_model::format::{
    CanonicalCborError, DecodeLimits, ObjectDescriptorVerifier, ObjectDescriptorVerificationError,
    decode_snapshot, decode_view, snapshot_decode_receiving_bytes_v2, view_decode_receiving_bytes_v2,
};
use aos_sandbox_model::registry::{PortableMediaType, RegistryError};
use aos_sandbox_ledger_replay::delete_graph::{
    DeleteDependencyGraphBaseDataV2, DeleteDependencyGraphDataV2, DeleteGraphDataErrorV2,
    DeleteGraphMetadataDataV2, DeleteGraphMetadataRequestDataV2,
    finish_delete_dependency_graph_metadata_data_v2,
};
use aos_sandbox_protocol::cache_state::physical_manifest::view_data;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;
use std::error::Error;
use std::mem::size_of;

/// Selects one closed reached graph phase on the same Root financial original.
#[derive(Clone, Copy)]
pub(crate) enum GraphAdmissionPhaseV2 { Fixed, Objects, Models }

impl GraphAdmissionPhaseV2 {
    pub(crate) fn index_v2(self) -> usize {
        match self { Self::Fixed => 0, Self::Objects => 1, Self::Models => 2 }
    }
}

#[derive(Clone, Copy)]
enum First { Geometry(usize), Permit(usize), Arm, BeforeClock, Before, Body, NativeAfter,
    Physical, After, AfterClock, Reentry }

#[derive(Debug, thiserror::Error)]
enum GraphErrorV2 {
    #[error(transparent)] Journal(#[from] JournalError),
    #[error(transparent)] Graph(#[from] DeleteGraphDataErrorV2),
    #[error(transparent)] Registry(#[from] RegistryError),
    #[error("a bounded Root graph allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("Root graph catalog native stage refused")]
    Catalog,
    #[error("Root graph native object {0} refused")]
    Reader(usize),
    #[error("Root graph object model {0} refused")]
    Model(usize),
    #[error("Root graph frontier clock refused")]
    Clock,
    #[error("Root graph original relation differs")]
    Relation,
}

enum Model { Snapshot(aos_sandbox_model::model::Snapshot), View(aos_sandbox_model::model::View) }

struct ObjectOriginal {
    request: DeleteGraphMetadataRequestDataV2,
    native: RootCacheMetadataReadOriginalV2,
    bytes: Option<Vec<u8>>,
    integrity: Option<Result<(), ObjectDescriptorVerificationError>>,
    model: Option<Result<Model, CanonicalCborError>>,
}

impl ObjectOriginal {
    fn metadata_v2(&self) -> Option<DeleteGraphMetadataDataV2<'_>> {
        if !matches!(self.integrity, Some(Ok(()))) || self.native.failure().is_some() { return None; }
        match (&self.request, self.model.as_ref()?.as_ref().ok()?) {
            (DeleteGraphMetadataRequestDataV2::Snapshot(saved), Model::Snapshot(model))
                if model.source_assignment().sandbox() == saved.sandbox() =>
                Some(DeleteGraphMetadataDataV2::Snapshot { saved, model }),
            (DeleteGraphMetadataRequestDataV2::View { view, descriptor }, Model::View(model)) =>
                Some(DeleteGraphMetadataDataV2::View { id: *view, descriptor, model }),
            _ => None,
        }
    }
}

pub(crate) struct RootDeleteGraphObjectsOriginalV2 {
    phase: Option<GraphAdmissionPhaseV2>,
    geometry: [Option<Result<ResourceVector, JournalError>>; 3],
    permits: [Option<Result<(), ResourceReservationErrorV1>>; 3],
    base: Option<DeleteDependencyGraphBaseDataV2>,
    requests: Option<Result<Vec<DeleteGraphMetadataRequestDataV2>, DeleteGraphDataErrorV2>>,
    view: CacheObjectViewOriginalV1,
    view_prepared: Option<Result<(), CacheObjectViewClosedV1>>,
    view_read: Option<Result<(), CacheObjectViewClosedV1>>,
    view_after: Option<Result<(), CacheObjectViewClosedV1>>,
    physical: Option<Result<(), JournalError>>,
    objects: Vec<ObjectOriginal>,
    graph: Option<Result<DeleteDependencyGraphDataV2, DeleteGraphDataErrorV2>>,
    frontier: Option<RootContinuationClockGateV1>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    body: Option<Result<(), GraphErrorV2>>,
    entered: bool,
    complete: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteGraphObjectsOriginalV2 {
    fn default() -> Self {
        Self { phase: None, geometry: std::array::from_fn(|_| None),
            permits: std::array::from_fn(|_| None), base: None, requests: None,
            view: CacheObjectViewOriginalV1::root_current_v1(), view_prepared: None,
            view_read: None, view_after: None, physical: None, objects: Vec::new(), graph: None,
            frontier: None, posts: Default::default(), arm: None, before: None, after: None,
            before_original: Default::default(), before_clock: None, before_binding: None,
            after_original: Default::default(), after_clock: None, after_binding: None,
            body: None, entered: false, complete: false, first: None, closed: None }
    }
}

impl RootDeleteGraphObjectsOriginalV2 {
    pub(crate) fn admission_phase_v2(&self) -> Result<GraphAdmissionPhaseV2, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.entered || self.first.is_some() || self.permits[phase.index_v2()].is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let index = self.admission_phase_v2()?.index_v2();
        if !self.entered || self.first.is_some() || self.permits[index].is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.geometry[index].as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // Includes successful earlier planes; their actual files/models remain
    // co-resident here. No dynamic plane is refunded merely on method return.
    pub(crate) fn retained_receiving_demand_v2(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        self.geometry.iter().zip(&self.permits).try_fold(ResourceVector::ZERO, |sum, (shape, permit)| {
            match permit {
                Some(Ok(())) => sum.checked_add(*shape.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?).map_err(ResourceReservationErrorV1::from),
                _ => Ok(sum),
            }
        })
    }

    pub(crate) fn verified_graph_v2(&self) -> Result<&DeleteDependencyGraphDataV2, RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.graph.as_ref().and_then(|value| value.as_ref().ok()).ok_or(RootDeleteErrorV1::Original)
    }

    fn admit_v2(&mut self, phase: GraphAdmissionPhaseV2, shape: Result<ResourceVector, JournalError>,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1, source: &RootDeleteSourceCurrentOriginalV1,
        cache: &RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), GraphErrorV2> {
        let index = phase.index_v2();
        self.phase = Some(phase);
        if self.geometry[index].is_some() || self.permits[index].is_some() {
            return Err(GraphErrorV2::Relation);
        }
        self.geometry[index] = Some(shape);
        if !matches!(self.geometry[index], Some(Ok(_))) {
            self.first.get_or_insert(First::Geometry(index));
            return Err(GraphErrorV2::Relation);
        }
        self.permits[index] = Some(flight.admit_delete_graph_objects_v2(challenge, controller, source, cache, self));
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Permit(index));
            return Err(GraphErrorV2::Relation);
        }
        Ok(())
    }

    pub(crate) fn observe_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, controller: &RootDeleteControllerCurrentOriginalV1,
        source: &mut RootDeleteSourceCurrentOriginalV1, cache: &RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        let fixed = self.fixed_demand_v2(source);
        if self.admit_v2(GraphAdmissionPhaseV2::Fixed, fixed, flight, challenge, controller, source, cache).is_err() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.frontier = Some(RootContinuationClockGateV1::new(
            challenge.continuation_horizon_v2().map_err(|_| RootDeleteErrorV1::Original)?));
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(First::Arm); }
        else {
            self.before_clock = Some(self.before_original.observe_once(None));
            self.before_binding = Some(positive(&self.before_clock)
                .and_then(|clock| challenge.require_current_clock_v1(*clock)));
            self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
            if !matches!(self.before_binding, Some(Ok(()))) { self.first = Some(First::BeforeClock); }
            if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(First::Before); }
            if self.first.is_none() {
                self.body = Some(self.observe_inner_v2(flight, challenge, controller, source, cache));
                if !matches!(self.body, Some(Ok(()))) { self.first.get_or_insert(First::Body); }
            }
        }
        // All reached physical/name/mount and Root/C/paired-clock afters are
        // independently prepaid. Failed growth/model/native IO cannot skip them.
        if self.view_prepared.is_some() {
            self.view_after = Some(self.view.finish_native_once());
            if !matches!(self.view_after, Some(Ok(()))) { self.first.get_or_insert(First::NativeAfter); }
        }
        if self.first.is_none() {
            self.physical = Some((|| {
                let expected = cache.physical_v2().map_err(|_| JournalError::ProtectedBoundary)?;
                let actual = self.view.completed_comparison_data_v2(
                    aos_sandbox_model::ObjectDigest::from_bytes(expected.limits))
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                if actual != expected { return Err(JournalError::ProtectedBoundary); }
                Ok(())
            })());
            if !matches!(self.physical, Some(Ok(()))) { self.first = Some(First::Physical); }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        self.after_clock = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            positive(&self.before_clock)?.validate_later_sample(*positive(&self.after_clock)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(*positive(&self.after_clock)?)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) { self.first.get_or_insert(First::AfterClock); }
        if self.first.is_some() || self.failure().is_some() { return Err(RootDeleteErrorV1::Opening); }
        self.complete = true;
        Ok(())
    }

    fn observe_inner_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, controller: &RootDeleteControllerCurrentOriginalV1,
        source: &mut RootDeleteSourceCurrentOriginalV1, cache: &RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), GraphErrorV2> {
        self.base = Some(source.take_verified_graph_base_v2().map_err(|_| GraphErrorV2::Relation)?);
        self.requests = Some(self.base.as_ref().ok_or(GraphErrorV2::Relation)?.metadata_requests_data_v2());
        if !matches!(self.requests, Some(Ok(_))) { return Err(GraphErrorV2::Relation); }
        let uid = flight.delete_cut_startup_v1().map_err(|_| GraphErrorV2::Relation)?
            .native_startup_original_v1().fields().profile.identities[0];
        self.check_frontier_v2()?;
        self.view_prepared = Some(self.view.prepare_once(uid));
        if !matches!(self.view_prepared, Some(Ok(()))) { return Err(GraphErrorV2::Catalog); }
        let objects = self.objects_demand_v2();
        self.admit_v2(GraphAdmissionPhaseV2::Objects, objects, flight, challenge, controller, source, cache)?;
        self.check_frontier_v2()?;
        self.view_read = Some(self.view.read_delete_metadata_catalog_once_v2(
            cache.graph_physical_limits_v2().map_err(|_| GraphErrorV2::Relation)?));
        if !matches!(self.view_read, Some(Ok(()))) { return Err(GraphErrorV2::Catalog); }
        let count = self.requests.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(GraphErrorV2::Relation)?.len();
        self.objects.try_reserve_exact(count)?;
        loop {
            let request = self.requests.as_mut().and_then(|value| value.as_mut().ok()).and_then(Vec::pop);
            let Some(request) = request else { break; };
            let index = self.objects.len();
            self.objects.push(ObjectOriginal { request, native: Default::default(), bytes: None,
                integrity: None, model: None });
            self.check_frontier_v2()?;
            let object = &mut self.objects[index];
            let expected = if object.request.snapshot_saved_v2().is_some() { PortableMediaType::Snapshot } else { PortableMediaType::View };
            if PortableMediaType::parse(object.request.descriptor_v2().media_type().as_str())? != expected {
                return Err(GraphErrorV2::Relation);
            }
            if object.native.open_once_v2(&self.view, object.request.descriptor_v2()).is_err() {
                return Err(GraphErrorV2::Reader(index));
            }
            self.check_frontier_v2()?;
            let object = &mut self.objects[index];
            let maximum = usize::try_from(object.request.descriptor_v2().encoded_size())
                .map_err(|_| GraphErrorV2::Relation)?;
            if object.native.read_once_v2(maximum).is_err() { return Err(GraphErrorV2::Reader(index)); }
            object.bytes = object.native.take_completed_bytes_v2();
            let bytes = object.bytes.as_deref().ok_or(GraphErrorV2::Relation)?;
            object.integrity = Some((|| {
                let mut verifier = ObjectDescriptorVerifier::new(object.request.descriptor_v2().clone());
                verifier.update(bytes)?;
                verifier.finish()
            })());
            if !matches!(object.integrity, Some(Ok(()))) { return Err(GraphErrorV2::Model(index)); }
            self.check_frontier_v2()?;
            let object = &mut self.objects[index];
            let bytes = object.bytes.as_deref().ok_or(GraphErrorV2::Relation)?;
            object.model = Some(if object.request.snapshot_saved_v2().is_some() {
                decode_snapshot(bytes, DecodeLimits::default()).map(Model::Snapshot)
            } else { decode_view(bytes, DecodeLimits::default()).map(Model::View) });
            if object.metadata_v2().is_none() { return Err(GraphErrorV2::Model(index)); }
        }
        let models = self.models_demand_v2(controller);
        self.admit_v2(GraphAdmissionPhaseV2::Models, models, flight, challenge, controller, source, cache)?;
        self.check_frontier_v2()?;
        let mut metadata = Vec::new();
        metadata.try_reserve_exact(self.objects.len())?;
        for object in &self.objects { metadata.push(object.metadata_v2().ok_or(GraphErrorV2::Relation)?); }
        let base = self.base.take().ok_or(GraphErrorV2::Relation)?;
        self.graph = Some(finish_delete_dependency_graph_metadata_data_v2(base,
            controller.graph_controller_rows_v2().map_err(|_| GraphErrorV2::Relation)?, &metadata));
        if !matches!(self.graph, Some(Ok(_))) { return Err(GraphErrorV2::Relation); }
        Ok(())
    }

    fn check_frontier_v2(&mut self) -> Result<(), GraphErrorV2> {
        self.frontier.as_mut().ok_or(GraphErrorV2::Relation)?.check_next_once_v1()
            .map(|_| ()).map_err(|_| GraphErrorV2::Clock)
    }

    fn fixed_demand_v2(&self, source: &RootDeleteSourceCurrentOriginalV1)
        -> Result<ResourceVector, JournalError> {
        let bytes = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let requests = u64::try_from(source.verified_graph_request_receiving_bytes_v2()?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        RootDeleteChunkPostsV1::fixed_demand_v1().map_err(|_| JournalError::JournalTooLarge)?
            .checked_add(CacheObjectViewOriginalV1::fixed_receiving_demand_v1().ok_or(JournalError::JournalTooLarge)?)
            .and_then(|shape| shape.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, requests)))
            .map_err(JournalError::ReceivingAccounting)?
            .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
            .and_then(|shape| shape.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)))
            .map_err(JournalError::ReceivingAccounting)
    }

    fn objects_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        let length = self.view.prepared_length_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let mut shape = view_data::dynamic_receiving_demand_v1(length).ok_or(JournalError::JournalTooLarge)?;
        // The catalog reuses the one parser map peak; this extra FD is the
        // genuine retained duplicate used by all strict object opens.
        shape = shape.checked_add(ResourceVector::ZERO.with(D::OpenFiles, 1))
            .map_err(JournalError::ReceivingAccounting)?;
        let requests = self.requests.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        for request in requests {
            let descriptor = request.descriptor_v2();
            let maximum = usize::try_from(descriptor.encoded_size()).map_err(|_| JournalError::JournalTooLarge)?;
            if maximum > DecodeLimits::default().maximum_bytes { return Err(JournalError::ProtectedBoundary); }
            let model = if request.snapshot_saved_v2().is_some() {
                snapshot_decode_receiving_bytes_v2(maximum, DecodeLimits::default())
            } else { view_decode_receiving_bytes_v2(maximum, DecodeLimits::default()) }
                .and_then(|bytes| bytes.checked_add(3 * size_of::<ObjectOriginal>()))
                .and_then(|bytes| bytes.checked_add(descriptor.media_type().as_str().len().checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            shape = shape.checked_add(RootCacheMetadataReadOriginalV2::receiving_demand_v2(descriptor)
                .ok_or(JournalError::JournalTooLarge)?)
                .and_then(|shape| shape.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, model)))
                .map_err(JournalError::ReceivingAccounting)?;
        }
        Ok(shape)
    }

    fn models_demand_v2(&self, controller: &RootDeleteControllerCurrentOriginalV1)
        -> Result<ResourceVector, JournalError>
    {
        let mut views = 0usize;
        for object in &self.objects {
            if matches!(object.metadata_v2(), Some(DeleteGraphMetadataDataV2::View { .. })) {
                views = views.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
            }
        }
        let links = self.objects.iter().try_fold(0usize, |sum, object| {
            let links = match object.metadata_v2().ok_or(JournalError::ProtectedBoundary)? {
                DeleteGraphMetadataDataV2::View { .. } => 1,
                DeleteGraphMetadataDataV2::Snapshot { model, .. } => model.attachments().len()
                    .checked_add(model.external_dependencies().len())
                    .and_then(|count| count.checked_mul(views))
                    .and_then(|count| count.checked_add(model.ancestry().len()))
                    .ok_or(JournalError::JournalTooLarge)?,
            };
            sum.checked_add(links).ok_or(JournalError::JournalTooLarge)
        })?;
        let rows = controller.graph_controller_rows_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let bytes = self.base.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .finishing_receiving_bytes_v2(rows, links)
            .and_then(|bytes| bytes.checked_add(self.objects.len().checked_mul(3 * size_of::<DeleteGraphMetadataDataV2<'_>>())?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(crate) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Permit(_)))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(crate) fn property_failure_view_v2(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        match self.first? {
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry(index) => cause(&self.geometry[index]),
            First::Permit(index) => cause(&self.permits[index]),
            First::Arm => cause(&self.arm),
            First::BeforeClock => self.before_original.failure().or_else(|| cause(&self.before_binding)),
            First::Before => cause(&self.before),
            First::Body => match self.body.as_ref()?.as_ref().err()? {
                GraphErrorV2::Catalog => self.view.failure().or_else(|| cause(&self.view_prepared)).or_else(|| cause(&self.view_read)),
                GraphErrorV2::Reader(index) => self.objects.get(*index)?.native.failure(),
                GraphErrorV2::Model(index) => self.objects.get(*index).and_then(|object|
                    cause(&object.integrity).or_else(|| cause(&object.model)))
                    .or_else(|| cause(&self.body)),
                GraphErrorV2::Clock => self.frontier.as_ref().and_then(|gate| gate.failure()),
                GraphErrorV2::Relation => cause(&self.requests).or_else(|| cause(&self.graph))
                    .or_else(|| cause(&self.body)),
                cause => Some(cause),
            },
            First::NativeAfter => self.view.failure().or_else(|| cause(&self.view_after)),
            First::Physical => cause(&self.physical),
            First::After => cause(&self.after),
            First::AfterClock => self.after_original.failure().or_else(|| cause(&self.after_binding)),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
