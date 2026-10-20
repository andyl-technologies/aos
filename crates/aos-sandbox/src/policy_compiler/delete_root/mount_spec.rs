//! Reads Mount cleanup's exact immutable Spec through Root's existing Cache engine.
//!
//! Assignment238 precedes three independent frontiers: native capture255,
//! complete catalog/object256 and canonical model257. The fresh view retains
//! its actual object pin and owes native, Root/C and paired-clock afters on
//! every reached failure. A descriptor or decoded Spec supplies no Mount grant.

use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::journal::JournalError;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::physical_cache_observation::current_view::{
    CacheObjectViewClosedV1, CacheObjectViewOriginalV1, RootCacheMetadataReadClosedV2,
    RootCacheMetadataReadOriginalV2,
};
use aos_sandbox_core::format::{
    CanonicalCborError, ObjectDescriptorVerificationError, ObjectDescriptorVerifier,
    decode_sandbox_spec, sandbox_spec_decoding_memory_bound_v4,
};
use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    ObjectDescriptor, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_protocol::cache_state::physical_manifest::view_data;

type Cause = Box<dyn StdError>;
const CLOCKS: usize = 5;

/// Names actual immutable-object work on the same retained Root Delete flight.
#[derive(Clone, Copy)]
pub(crate) enum RootDeleteMountSpecPhaseV4 {
    Fixed,
    Object,
    Model,
}

impl RootDeleteMountSpecPhaseV4 {
    pub(crate) const fn index_v4(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
enum First {
    Geometry(usize),
    Funding(usize),
    Arm,
    Before,
    Clock(usize),
    Prepare,
    Catalog,
    Open,
    Read,
    Integrity,
    Model,
    NativeAfter,
    Physical,
    After,
    Primary,
    Reentry,
}

pub(crate) struct RootDeleteMountSpecOriginalV4 {
    phase: Option<RootDeleteMountSpecPhaseV4>,
    demands: [Option<Result<ResourceVector, Cause>>; 3],
    permits: [Option<Result<(), ResourceReservationErrorV1>>; 3],
    view: CacheObjectViewOriginalV1,
    prepared: Option<Result<(), CacheObjectViewClosedV1>>,
    catalog: Option<Result<(), CacheObjectViewClosedV1>>,
    native_after: Option<Result<(), CacheObjectViewClosedV1>>,
    reader: RootCacheMetadataReadOriginalV2,
    opened: Option<Result<(), RootCacheMetadataReadClosedV2>>,
    read: Option<Result<(), RootCacheMetadataReadClosedV2>>,
    descriptor: Option<ObjectDescriptor>,
    bytes: Option<Vec<u8>>,
    integrity: Option<Result<(), ObjectDescriptorVerificationError>>,
    model: Option<Result<SandboxSpec, CanonicalCborError>>,
    physical: Option<Result<(), JournalError>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; CLOCKS],
    samples: [Option<
        Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
    >; CLOCKS],
    times: [Option<Result<(), Cause>>; CLOCKS],
    latest: Option<RawPairedClockSample>,
    primary: Option<Result<(), Cause>>,
    first: Option<First>,
    entered: bool,
    native_entered: bool,
    complete: bool,
}

impl Default for RootDeleteMountSpecOriginalV4 {
    fn default() -> Self {
        Self {
            phase: None,
            demands: std::array::from_fn(|_| None),
            permits: std::array::from_fn(|_| None),
            view: CacheObjectViewOriginalV1::root_current_v1(),
            prepared: None,
            catalog: None,
            native_after: None,
            reader: Default::default(),
            opened: None,
            read: None,
            descriptor: None,
            bytes: None,
            integrity: None,
            model: None,
            physical: None,
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            clocks: std::array::from_fn(|_| Default::default()),
            samples: std::array::from_fn(|_| None),
            times: std::array::from_fn(|_| None),
            latest: None,
            primary: None,
            first: None,
            entered: false,
            native_entered: false,
            complete: false,
        }
    }
}

pub(super) struct MountSpecInputsV4<'held> {
    pub(super) challenge: &'held RootDeleteChallengeOriginalsV1,
    pub(super) current: RootDeleteResourceContinuationV4<'held>,
    pub(super) assignment: &'held RootDeleteCleanupInputsOriginalV2,
    pub(super) policy: &'held RootDeleteResourcePolicyOriginalV2,
    pub(super) cache: &'held RootDeleteCacheCurrentOriginalV2,
}

impl RootDeleteMountSpecOriginalV4 {
    pub(crate) fn admission_phase_v4(
        &self,
    ) -> Result<RootDeleteMountSpecPhaseV4, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = phase.index_v4();
        if !self.entered
            || self.first.is_some()
            || self.permits[index].is_some()
            || !matches!(self.demands[index], Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v4(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.demands[self.admission_phase_v4()?.index_v4()]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: MountSpecInputsV4<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.primary = Some(self.observe_inner_v4(flight, &inputs));
        if self.primary.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Primary);
        }
        // A failed prepare may already hold native pins. Its after is owed
        // independently of later catalog, allocation, file or model refusal.
        if self.prepared.is_some() {
            self.native_after = Some(self.view.finish_native_once());
            if !matches!(self.native_after, Some(Ok(()))) {
                self.first.get_or_insert(First::NativeAfter);
            }
        }
        if self.first.is_none() {
            self.physical = Some((|| {
                let expected = inputs
                    .cache
                    .physical_v2()
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                let actual = self
                    .view
                    .completed_comparison_data_v2(aos_sandbox_core::ObjectDigest::from_bytes(
                        expected.limits,
                    ))
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                if actual != expected {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                Ok(())
            })());
            if !matches!(self.physical, Some(Ok(()))) {
                self.first = Some(First::Physical);
            }
        }
        if self.native_entered {
            self.after = Some(self.posts.observe_after_once_v1(flight, inputs.challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
            self.sample_once_v4(4, &inputs);
        }
        self.complete = self.first.is_none()
            && matches!(self.primary, Some(Ok(())))
            && matches!(self.model, Some(Ok(_)))
            && self.failure().is_none();
        self.require_completed_v4()
    }

    fn observe_inner_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: &MountSpecInputsV4<'_>,
    ) -> Result<(), Cause> {
        inputs.current.require_completed_v3()?;
        inputs.assignment.require_completed_v2()?;
        self.admit_v4(
            flight,
            inputs,
            RootDeleteMountSpecPhaseV4::Fixed,
            Self::fixed_demand_v4(),
        )?;
        self.native_entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(inputs.challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(First::Arm);
        }
        self.sample_once_v4(0, inputs);
        self.before = Some(self.posts.observe_before_once_v1(flight, inputs.challenge));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        self.require_primary_v4()?;
        let uid = flight
            .delete_cut_startup_v1()?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities[0];
        self.prepared = Some(self.view.prepare_once(uid));
        if !matches!(self.prepared, Some(Ok(()))) {
            self.first = Some(First::Prepare);
            return Err(JournalError::ProtectedBoundary.into());
        }
        let descriptor = inputs.assignment.manifest_v2()?.manifest().sandbox_spec();
        let demand = self.object_demand_v4(descriptor);
        self.admit_v4(flight, inputs, RootDeleteMountSpecPhaseV4::Object, demand)?;
        self.sample_once_v4(1, inputs);
        self.require_primary_v4()?;
        self.descriptor = Some(descriptor.clone());
        self.catalog = Some(
            self.view
                .read_delete_metadata_catalog_once_v2(inputs.cache.graph_physical_limits_v2()?),
        );
        if !matches!(self.catalog, Some(Ok(()))) {
            self.first = Some(First::Catalog);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.opened = Some(self.reader.open_once_v2(&self.view, descriptor));
        if !matches!(self.opened, Some(Ok(()))) {
            self.first = Some(First::Open);
            return Err(JournalError::ProtectedBoundary.into());
        }
        let maximum = usize::try_from(descriptor.encoded_size())?;
        self.read = Some(self.reader.read_once_v2(maximum));
        if !matches!(self.read, Some(Ok(()))) {
            self.first = Some(First::Read);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.bytes = self.reader.take_completed_bytes_v2();
        let demand = self.model_demand_v4();
        self.admit_v4(flight, inputs, RootDeleteMountSpecPhaseV4::Model, demand)?;
        self.sample_once_v4(2, inputs);
        self.require_primary_v4()?;
        let bytes = self
            .bytes
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.integrity = Some((|| {
            let mut verifier = ObjectDescriptorVerifier::new(descriptor.clone());
            verifier.update(bytes)?;
            verifier.finish()
        })());
        if !matches!(self.integrity, Some(Ok(()))) {
            self.first = Some(First::Integrity);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.model = Some(decode_sandbox_spec(
            bytes,
            aos_sandbox_protocol::mount_destination_slot::sandbox_spec_decode_limits(),
        ));
        if !matches!(self.model, Some(Ok(_))) {
            self.first = Some(First::Model);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.sample_once_v4(3, inputs);
        self.require_primary_v4()
    }

    fn fixed_demand_v4() -> Result<ResourceVector, Cause> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(CLOCKS)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(CLOCKS))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(CacheObjectViewOriginalV1::fixed_receiving_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(RootDeleteChunkPostsV1::fixed_demand_v1()?)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, names)
                    .with(
                        D::OpenFiles,
                        (CLOCKS * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                            as u64,
                    ),
            )?)
    }

    fn object_demand_v4(&self, descriptor: &ObjectDescriptor) -> Result<ResourceVector, Cause> {
        let extent = usize::try_from(descriptor.encoded_size())?;
        if extent
            > aos_sandbox_protocol::mount_destination_slot::MAXIMUM_DESTINATION_SLOT_SPEC_BYTES
        {
            return Err(JournalError::JournalTooLarge.into());
        }
        let bytes = descriptor
            .media_type()
            .as_str()
            .len()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(
            view_data::dynamic_receiving_demand_v1(self.view.prepared_length_v1()?)
                .ok_or(JournalError::JournalTooLarge)?
                .checked_add(
                    RootCacheMetadataReadOriginalV2::receiving_demand_v2(descriptor)
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, bytes)
                        .with(D::OpenFiles, 1),
                )?,
        )
    }

    fn model_demand_v4(&self) -> Result<ResourceVector, Cause> {
        let bytes = self
            .bytes
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let memory = sandbox_spec_decoding_memory_bound_v4(
            bytes.len(),
            aos_sandbox_protocol::mount_destination_slot::sandbox_spec_decode_limits(),
        )
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<ObjectDescriptorVerifier>().checked_mul(3)?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                self.descriptor
                    .as_ref()?
                    .media_type()
                    .as_str()
                    .len()
                    .checked_mul(3)?,
            )
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
    }

    fn admit_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: &MountSpecInputsV4<'_>,
        phase: RootDeleteMountSpecPhaseV4,
        demand: Result<ResourceVector, Cause>,
    ) -> Result<(), Cause> {
        let index = phase.index_v4();
        self.phase = Some(phase);
        if self.demands[index].is_some() || self.permits[index].is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.demands[index] = Some(demand);
        if !matches!(self.demands[index], Some(Ok(_))) {
            self.first = Some(First::Geometry(index));
            return Err(JournalError::JournalTooLarge.into());
        }
        self.permits[index] =
            Some(flight.admit_delete_mount_spec_once_v4(inputs.current, inputs.assignment, self));
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first = Some(First::Funding(index));
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn sample_once_v4(&mut self, index: usize, inputs: &MountSpecInputsV4<'_>) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.times[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            if let Some(previous) = self.latest {
                previous.validate_later_sample(sample)?;
            } else {
                inputs
                    .current
                    .completed_clock_v3()?
                    .validate_later_sample(sample)?;
            }
            inputs.challenge.require_current_clock_v1(sample)?;
            let signed = inputs.policy.verified_sources_v2()?;
            if sample.wall_seconds() >= signed.0.head().expires_at()
                || sample.wall_seconds() >= signed.1.expires_at()
                || sample.wall_seconds()
                    >= inputs.assignment.lease_v2()?.authority_expires_seconds()
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            self.latest = Some(sample);
            Ok(())
        })());
        if !matches!(self.times[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Clock(index));
        }
    }

    fn require_primary_v4(&self) -> Result<(), Cause> {
        if self.first.is_some() {
            Err(JournalError::ProtectedBoundary.into())
        } else {
            Ok(())
        }
    }

    pub(crate) fn require_completed_v4(&self) -> Result<(), RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok(())
    }

    pub(super) fn completed_spec_v4(
        &self,
        descriptor: &ObjectDescriptor,
    ) -> Result<(&[u8], &SandboxSpec), RootDeleteErrorV1> {
        self.require_completed_v4()?;
        if self.descriptor.as_ref() != Some(descriptor) {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok((
            self.bytes.as_deref().ok_or(RootDeleteErrorV1::Original)?,
            positive(&self.model).map_err(|_| RootDeleteErrorV1::Original)?,
        ))
    }

    pub(super) fn completed_clock_v4(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v4()?;
        self.latest.ok_or(RootDeleteErrorV1::Original)
    }

    pub(crate) fn funding_failed_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding(_)))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(crate) fn property_failure_view_v4(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            First::Geometry(index) => boxed(&self.demands[index]),
            First::Funding(index) => cause(&self.permits[index]),
            First::Arm => cause(&self.arm),
            First::Before => cause(&self.before),
            First::Clock(index) => self.clocks[index]
                .failure()
                .or_else(|| boxed(&self.times[index])),
            First::Prepare | First::Catalog | First::NativeAfter => self
                .view
                .failure()
                .or_else(|| cause(&self.prepared))
                .or_else(|| cause(&self.catalog))
                .or_else(|| cause(&self.native_after)),
            First::Open | First::Read => self
                .reader
                .failure()
                .or_else(|| cause(&self.opened))
                .or_else(|| cause(&self.read)),
            First::Integrity => cause(&self.integrity),
            First::Model => cause(&self.model),
            First::Physical => cause(&self.physical),
            First::After => cause(&self.after),
            First::Primary => boxed(&self.primary),
            First::Reentry => None,
        }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn boxed<T>(slot: &Option<Result<T, Cause>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
