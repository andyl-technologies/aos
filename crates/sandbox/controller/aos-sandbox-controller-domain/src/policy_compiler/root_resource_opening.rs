//! Shares Root resource opening native clocks, nonce and receiving exactly once.
//!
//! Decoded deadlines remain comparison DATA until the actual Controller cold
//! reader binds the actual protected accepted origin and fixed Root association. The
//! private opening cannot be constructed from a successful reply or raw fields.

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{
    NormalRootStartupErrorV1, RootApplyStageReceivingV1, RootHostLaunchStageReceivingV1,
    RootMaintenanceStorageStageReceivingV2, RootStartAssignmentInputsStageReceivingV2,
};
use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
use crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1, fresh_root_nonce};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::{
    ApplyRootDataErrorV1, StorageApplyQueryDataV1,
};
use std::error::Error;
use std::mem::size_of;

const ROOT_RESOURCE_MAXIMUM_FLIGHT_NS: u64 = 65_000_000_000;

use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::StartAssignmentInputsQueryDataV2;

#[derive(Clone, Copy)]
enum OpeningPurposeV2 {
    StopCleanup,
    ExecutionNoApply,
    MaintenanceStorage,
    Apply,
    Host,
    StartInputs,
}

pub(in crate::policy_compiler) enum OpeningReceivingV2<'held, 'flight, 'startup> {
    StopCleanup(&'held mut crate::normal_root::RootStopCleanupStageReceivingV1<'flight, 'startup>),
    ExecutionNoApply(
        &'held mut crate::normal_root::RootExecutionNoApplyStageReceivingV2<'flight, 'startup>,
    ),
    MaintenanceStorage(&'held mut RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
    Apply(&'held mut RootApplyStageReceivingV1<'flight, 'startup>),
    Host(&'held mut RootHostLaunchStageReceivingV1<'flight, 'startup>),
    StartInputs(&'held mut RootStartAssignmentInputsStageReceivingV2<'flight, 'startup>),
}

impl OpeningReceivingV2<'_, '_, '_> {
    fn purpose(&self) -> OpeningPurposeV2 {
        match self {
            Self::StopCleanup(_) => OpeningPurposeV2::StopCleanup,
            Self::ExecutionNoApply(_) => OpeningPurposeV2::ExecutionNoApply,
            Self::Apply(_) => OpeningPurposeV2::Apply,
            Self::Host(_) => OpeningPurposeV2::Host,
            Self::MaintenanceStorage(_) => OpeningPurposeV2::MaintenanceStorage,
            Self::StartInputs(_) => OpeningPurposeV2::StartInputs,
        }
    }

    fn admit_query(&mut self, demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        match self {
            Self::StopCleanup(stage) => stage.require_stop_cleanup_transport_prepaid_v1(demand),
            Self::ExecutionNoApply(stage) => stage.require_execution_transport_prepaid_v2(demand),
            Self::Apply(stage) => {
                stage.admit_apply_query_once_v1(RootContinuationDemandV1::from_demand_v1(demand))
            }
            Self::Host(stage) => {
                stage.admit_host_query_once_v1(RootContinuationDemandV1::from_demand_v1(demand))
            }
            Self::MaintenanceStorage(stage) => stage
                .admit_maintenance_query_once_v2(RootContinuationDemandV1::from_demand_v1(demand)),
            Self::StartInputs(stage) => stage.admit_start_assignment_inputs_query_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand),
            ),
        }
    }

    fn admit_subject(&mut self, demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        match self {
            Self::StopCleanup(stage) => stage.require_stop_cleanup_transport_prepaid_v1(demand),
            Self::ExecutionNoApply(stage) => stage.require_execution_transport_prepaid_v2(demand),
            Self::Apply(stage) => {
                stage.admit_apply_subject_once_v1(RootContinuationDemandV1::from_demand_v1(demand))
            }
            Self::Host(stage) => {
                stage.admit_host_subject_once_v1(RootContinuationDemandV1::from_demand_v1(demand))
            }
            Self::MaintenanceStorage(stage) => stage.admit_maintenance_subject_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand),
            ),
            Self::StartInputs(stage) => stage.admit_start_assignment_inputs_subject_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand),
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::policy_compiler) enum OpeningQueryV2 {
    StopCleanup(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupQueryDataV1),
    ExecutionAcquisition(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ExecutionNoApplyAcquisitionQueryDataV2),
    ExecutionNoApply(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyQueryDataV2),
    MaintenanceStorage(aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageQueryDataV2),
    Apply(StorageApplyQueryDataV1),
    Host(aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostLaunchQueryDataV1),
    StartInputs(StartAssignmentInputsQueryDataV2),
}

impl OpeningQueryV2 {
    fn extent(self) -> u64 {
        match self {
            Self::StopCleanup(value) => value.subject_bytes,
            Self::ExecutionAcquisition(value) => value.subject_bytes,
            Self::ExecutionNoApply(value) => value.subject_bytes,
            Self::Apply(value) => value.subject_bytes,
            Self::Host(value) => value.subject_bytes,
            Self::MaintenanceStorage(value) => value.subject_bytes,
            Self::StartInputs(value) => value.subject_bytes,
        }
    }

    fn clock_fields(self) -> ([u8; 16], u64, u64) {
        match self {
            Self::StopCleanup(value) => (value.original_boot, value.original_boottime_ns, value.original_cutoff_ns),
            Self::ExecutionAcquisition(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
            Self::ExecutionNoApply(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
            Self::Apply(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
            Self::Host(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
            Self::MaintenanceStorage(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
            Self::StartInputs(value) => (
                value.original_boot,
                value.original_boottime_ns,
                value.original_cutoff_ns,
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum OpeningQueryErrorV2 {
    #[error(transparent)]
    StopCleanup(HistoryErrorV1),
    #[error(transparent)]
    ExecutionNoApply(HistoryErrorV1),
    #[error(transparent)]
    Apply(ApplyRootDataErrorV1),
    #[error(transparent)]
    Host(HistoryErrorV1),
    #[error(transparent)]
    MaintenanceStorage(HistoryErrorV1),
    #[error(transparent)]
    StartInputs(HistoryErrorV1),
}

#[derive(Default)]
pub(in crate::policy_compiler) struct RootResourceOpeningOriginalV2 {
    purpose: Option<OpeningPurposeV2>,
    query_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    query: Option<Result<OpeningQueryV2, OpeningQueryErrorV2>>,
    clock: Option<Box<RetainedKernelPairedClockAttemptV1>>,
    observed: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    nonce: Option<std::io::Result<[u8; 16]>>,
    relation: Option<Result<u64, JournalError>>,
    subject_geometry: Option<Result<ResourceVector, JournalError>>,
    subject_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    tightened: Option<Result<(u64, i64), JournalError>>,
    execution_lease_entered: bool,
    acquisition_wall_entered: bool,
    closed: bool,
}

impl RootResourceOpeningOriginalV2 {
    // This real stage funds the whole fixed server constructor, sampler and
    // remainder IO before either the lazy state or native clock is created.
    pub(in crate::policy_compiler) fn admit_query_once_v1(
        &mut self,
        mut stage: OpeningReceivingV2<'_, '_, '_>,
        server_bytes: usize,
    ) -> Result<(), JournalError> {
        if self.query_funding.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        let bytes = server_bytes
            .checked_add(size_of::<Self>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| {
                bytes
                    .checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        // The selected listener already debited the complete fixed112 wire
        // prefix. This stage adds only the newly reached owner/sampler peak.
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::NetworkBytes, 0)
            .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .checked_add(crate::policy_compiler::provisioning_current::RootContinuationClockGateV1::receiving_demand_v1()?)
            .map_err(JournalError::ReceivingAccounting)?;
        let demand = if matches!(stage.purpose(), OpeningPurposeV2::StartInputs) {
            demand.checked_add(crate::policy_compiler::start_assignment_inputs_root::
                opening_additional_demand_v2()?).map_err(JournalError::ReceivingAccounting)?
        } else {
            demand
        };
        self.purpose = Some(stage.purpose());
        self.query_funding = Some(stage.admit_query(demand));
        if !matches!(self.query_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(in crate::policy_compiler) fn observe_query_once_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), JournalError> {
        if self.query.is_some() || !matches!(self.query_funding, Some(Ok(()))) {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.query = Some(match self.purpose.ok_or(JournalError::ProtectedBoundary)? {
            OpeningPurposeV2::StopCleanup => aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupQueryDataV1::decode_v1(bytes)
                .map(OpeningQueryV2::StopCleanup).map_err(OpeningQueryErrorV2::StopCleanup),
            OpeningPurposeV2::ExecutionNoApply if bytes.starts_with(b"AOSANQ02") => aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ExecutionNoApplyAcquisitionQueryDataV2::decode_v2(bytes)
                .map(OpeningQueryV2::ExecutionAcquisition).map_err(OpeningQueryErrorV2::ExecutionNoApply),
            OpeningPurposeV2::ExecutionNoApply => aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyQueryDataV2::decode_v2(bytes)
                .map(OpeningQueryV2::ExecutionNoApply).map_err(OpeningQueryErrorV2::ExecutionNoApply),
            OpeningPurposeV2::MaintenanceStorage => aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageQueryDataV2::decode_v2(bytes)
                .map(OpeningQueryV2::MaintenanceStorage).map_err(OpeningQueryErrorV2::MaintenanceStorage),
            OpeningPurposeV2::Apply => StorageApplyQueryDataV1::decode_v1(bytes)
                .map(OpeningQueryV2::Apply).map_err(OpeningQueryErrorV2::Apply),
            OpeningPurposeV2::Host => aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostLaunchQueryDataV1::decode_v1(bytes)
                .map(OpeningQueryV2::Host).map_err(OpeningQueryErrorV2::Host),
            OpeningPurposeV2::StartInputs => StartAssignmentInputsQueryDataV2::decode_v2(bytes)
                .map(OpeningQueryV2::StartInputs).map_err(OpeningQueryErrorV2::StartInputs),
        });
        let query = self.query_v1()?;
        self.clock = Some(Box::new(RetainedKernelPairedClockAttemptV1::default()));
        self.observed = Some(
            self.clock
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_once(None),
        );
        self.nonce = Some(fresh_root_nonce());
        self.relation = Some((|| {
            let cutoff = query_sample_cutoff_v2(query, self.root_sample_v1()?)?;
            if self.root_nonce_v1()? == [0; 16] {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(cutoff)
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    pub(in crate::policy_compiler) fn admit_subject_once_v1(
        &mut self,
        mut stage: OpeningReceivingV2<'_, '_, '_>,
        subject_owner_bytes: usize,
    ) -> Result<(), JournalError> {
        if self.subject_geometry.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.subject_geometry = Some((|| {
            let width = usize::try_from(self.query_v1()?.extent())
                .map_err(|_| JournalError::JournalTooLarge)?;
            let bytes = width
                .checked_add(
                    subject_owner_bytes
                        .checked_mul(3)
                        .ok_or(JournalError::JournalTooLarge)?,
                )
                .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            let chunk = match self.purpose.ok_or(JournalError::ProtectedBoundary)? {
                OpeningPurposeV2::StopCleanup => RootSubjectChunkReceivingV1::stop_cleanup_receiving_demand_v1()?,
                OpeningPurposeV2::ExecutionNoApply => {
                    RootSubjectChunkReceivingV1::execution_no_apply_receiving_demand_v2()?
                }
                OpeningPurposeV2::Apply => {
                    RootSubjectChunkReceivingV1::apply_receiving_demand_v1()?
                }
                OpeningPurposeV2::Host => RootSubjectChunkReceivingV1::host_receiving_demand_v2()?,
                OpeningPurposeV2::MaintenanceStorage => {
                    RootSubjectChunkReceivingV1::maintenance_storage_receiving_demand_v2()?
                }
                OpeningPurposeV2::StartInputs => {
                    RootSubjectChunkReceivingV1::start_assignment_inputs_receiving_demand_v2()?
                }
            };
            chunk
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
                    D::NetworkBytes,
                    u64::try_from(width).map_err(|_| JournalError::JournalTooLarge)?,
                ))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let required = *self
            .subject_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.subject_funding = Some(stage.admit_subject(required));
        self.require_paid_chunk_peak_v1()
    }

    // Only actual already-verified inputs can tighten the retained opening.
    // There is no public cutoff setter or later relative flight constructor.
    pub(in crate::policy_compiler) fn tighten_inputs_once_v1(
        &mut self,
        inputs: &crate::policy_compiler::provisioning_current::apply_inputs::RootApplyInputsOriginalV1,
        policy: &crate::policy_compiler::continuation_policy::RootApplyPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some((|| {
            let sample = self.root_sample_v1()?;
            let signed = policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            let expiry = inputs
                .lease_v1()?
                .authority_expires_seconds()
                .min(signed.0.head().expires_at())
                .min(signed.1.expires_at());
            let deadline = sample
                .conservative_expiry_deadline_data_v1(expiry)
                .ok_or(JournalError::ProtectedBoundary)?;
            let cutoff = self
                .base_cutoff_v1()?
                .min(inputs.preparation_cutoff_v1()?)
                .min(deadline);
            if cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    // Only the genuine current accepted Start and same Root policy interval
    // can narrow this purpose. No caller supplies a replacement wall or cutoff.
    pub(in crate::policy_compiler) fn tighten_start_inputs_once_v2(
        &mut self,
        source: &crate::policy_compiler::public_start_source::CurrentAcceptedStartProjectSourceV2,
        policy: &crate::policy_compiler::continuation_policy::RootStartAssignmentInputsPolicyOriginalV2,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some() || !matches!(self.purpose, Some(OpeningPurposeV2::StartInputs))
        {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some((|| {
            let sample = self.root_sample_v1()?;
            let signed = policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            let origin = source.native_origin_data_v2();
            let expiry = origin
                .accepted_v1()
                .original_wall_expiry_v1()
                .ok_or(JournalError::ProtectedBoundary)?
                .min(signed.0.head().expires_at())
                .min(signed.1.expires_at())
                .min(source.publisher_v2().expires);
            let deadline = sample
                .conservative_expiry_deadline_data_v1(expiry)
                .ok_or(JournalError::ProtectedBoundary)?;
            let cutoff = self.base_cutoff_v1()?.min(origin.cutoff_v1()).min(deadline);
            if cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    pub(in crate::policy_compiler) fn tighten_host_inputs_once_v2(
        &mut self,
        source: &crate::policy_compiler::public_start_source::CurrentAcceptedStartProjectSourceV2,
        policy: &crate::policy_compiler::continuation_policy::RootHostLaunchPolicyOriginalV1,
        lease: &aos_sandbox_ownership_protocol::SignedOwnershipLease,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some() || !matches!(self.purpose, Some(OpeningPurposeV2::Host)) {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some((|| {
            let OpeningQueryV2::Host(query) = self.query_v1()? else {
                return Err(JournalError::ProtectedBoundary);
            };
            let origin = source.native_origin_data_v2();
            let first = origin.first_native_clock_v1();
            if query.original_boot != first.host_boot_id()
                || query.original_boottime_ns != first.boottime_nanoseconds()
                || query.original_cutoff_ns != origin.cutoff_v1()
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let sample = self.root_sample_v1()?;
            let signed = policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            let accepted = origin.accepted_v1();
            let expiry = accepted
                .original_wall_expiry_v1()
                .ok_or(JournalError::ProtectedBoundary)?
                .min(lease.authority_expires_seconds())
                .min(source.publisher_v2().expires)
                .min(signed.0.head().expires_at())
                .min(signed.1.expires_at());
            let wall_deadline = sample
                .conservative_expiry_deadline_data_v1(expiry)
                .ok_or(JournalError::ProtectedBoundary)?;
            let lease_deadline = sample
                .conservative_lease_expiry_deadline_data_v2(
                    lease.authority_expires_seconds(),
                    lease.maximum_clock_skew_seconds(),
                )
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let accepted_deadline = accepted
                .cutoff_for_sample_data_v1(sample)
                .ok_or(JournalError::ProtectedBoundary)?;
            let cutoff = self
                .base_cutoff_v1()?
                .min(origin.cutoff_v1())
                .min(accepted_deadline)
                .min(wall_deadline)
                .min(lease_deadline);
            if cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    // The actual Maintenance wrapper already joined the same current assignment
    // and verified live lease. Only those authenticated expiries may narrow the
    // opening; the signed query's original mechanical cutoff remains unchanged.
    pub(in crate::policy_compiler) fn tighten_maintenance_inputs_once_v2(
        &mut self,
        policy: &crate::policy_compiler::continuation_policy::RootMaintenanceStoragePolicyOriginalV2,
        lease: &aos_sandbox_ownership_protocol::SignedOwnershipLease,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some()
            || !matches!(self.purpose, Some(OpeningPurposeV2::MaintenanceStorage))
        {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some((|| {
            let sample = self.root_sample_v1()?;
            let signed = policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            let expiry = lease
                .authority_expires_seconds()
                .min(signed.0.head().expires_at())
                .min(signed.1.expires_at());
            let policy_deadline = sample
                .conservative_expiry_deadline_data_v1(expiry)
                .ok_or(JournalError::ProtectedBoundary)?;
            let lease_deadline = sample
                .conservative_lease_expiry_deadline_data_v2(
                    lease.authority_expires_seconds(),
                    lease.maximum_clock_skew_seconds(),
                )
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let cutoff = self
                .base_cutoff_v1()?
                .min(policy_deadline)
                .min(lease_deadline);
            if cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    pub(crate) fn tighten_execution_acquisition_policy_once_v2(
        &mut self,
        policy: &crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some()
            || !matches!(self.query_v1()?, OpeningQueryV2::ExecutionAcquisition(_))
        {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some(self.execution_policy_cutoff_v2(policy, None));
        self.current_cutoff_v1().map(|_| ())
    }

    pub(crate) fn tighten_stop_cleanup_inputs_once_v1(&mut self,
        original: &crate::policy_compiler::stop_cleanup_root::RootStopCleanupNativeOriginalV1,
    ) -> Result<(), JournalError> {
        if self.tightened.is_some() || !matches!(self.query_v1()?, OpeningQueryV2::StopCleanup(_)) {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightened = Some((|| {
            let expiry = original.policy_expiry_v1()?;
            let sample = self.root_sample_v1()?;
            let cutoff = original.cutoff_v1()?;
            if cutoff > self.current_cutoff_v1()?
                || cutoff > sample.conservative_expiry_deadline_data_v1(expiry)
                    .ok_or(JournalError::ProtectedBoundary)?
                || cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    pub(crate) fn narrow_execution_acquisition_wall_once_v2(
        &mut self,
        expiry: i64,
    ) -> Result<(), JournalError> {
        if self.acquisition_wall_entered
            || self.execution_lease_entered
            || !matches!(self.query_v1()?, OpeningQueryV2::ExecutionAcquisition(_))
        {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.acquisition_wall_entered = true;
        let (cutoff, previous_expiry) = self
            .tightened
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.tightened = Some((|| {
            let expiry = expiry.min(previous_expiry);
            let sample = self.root_sample_v1()?;
            let cutoff = cutoff.min(
                sample
                    .conservative_expiry_deadline_data_v1(expiry)
                    .ok_or(JournalError::ProtectedBoundary)?,
            );
            if cutoff <= sample.boottime_nanoseconds() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok((cutoff, expiry))
        })());
        self.current_cutoff_v1().map(|_| ())
    }

    pub(crate) fn tighten_execution_inputs_once_v2(
        &mut self,
        policy: &crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
        lease: aos_sandbox_protocol::host_execution_no_apply::current_lease::CurrentHostNoApplyLeaseDataV2,
    ) -> Result<(), JournalError> {
        let acquired = matches!(self.query_v1()?, OpeningQueryV2::ExecutionAcquisition(_));
        if self.execution_lease_entered
            || (!acquired && self.tightened.is_some())
            || !matches!(self.purpose, Some(OpeningPurposeV2::ExecutionNoApply))
            || (acquired && !matches!(self.tightened, Some(Ok(_))))
        {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.execution_lease_entered = true;
        // The acquisition programme already narrowed this same original by
        // native policy. A later genuine lease can only narrow it further.
        self.tightened =
            Some(self.execution_policy_cutoff_v2(policy, Some(lease.fields().native_cutoff)));
        self.current_cutoff_v1().map(|_| ())
    }

    fn execution_policy_cutoff_v2(
        &self,
        policy: &crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
        lease_cutoff: Option<u64>,
    ) -> Result<(u64, i64), JournalError> {
        let sample = self.root_sample_v1()?;
        let verified = policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let expiry = verified.0.head().expires_at().min(verified.1.expires_at());
        let expiry = match self.tightened.as_ref() {
            Some(Ok((_, previous))) => expiry.min(*previous),
            Some(Err(_)) => return Err(JournalError::ProtectedBoundary),
            None => expiry,
        };
        let policy_deadline = sample
            .conservative_expiry_deadline_data_v1(expiry)
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut cutoff = self.current_cutoff_v1()?.min(policy_deadline);
        if let Some(lease_cutoff) = lease_cutoff {
            cutoff = cutoff.min(lease_cutoff);
        }
        if cutoff <= sample.boottime_nanoseconds() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((cutoff, expiry))
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        if self.closed || !matches!(self.subject_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.current_cutoff_v1().map(|_| ())
    }

    fn base_cutoff_v1(&self) -> Result<u64, JournalError> {
        if self.closed {
            return Err(JournalError::ProtectedBoundary);
        }
        self.relation
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, JournalError> {
        match self.tightened.as_ref() {
            Some(value) => value
                .as_ref()
                .map(|(cutoff, _)| *cutoff)
                .map_err(|_| JournalError::ProtectedBoundary),
            None => self.base_cutoff_v1(),
        }
    }

    pub(crate) fn require_current_clock_v1(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.horizon_v1()?.require_sample_v1(sample)
    }

    pub(in crate::policy_compiler) fn horizon_v1(
        &self,
    ) -> Result<RootContinuationHorizonDataV1, JournalError> {
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            self.root_sample_v1()?,
            self.current_cutoff_v1()?,
        )?;
        match self.tightened.as_ref() {
            Some(Ok((_, expiry))) => Ok(horizon.with_wall_expiry_data_v1(*expiry)),
            Some(Err(_)) => Err(JournalError::ProtectedBoundary),
            None => Ok(horizon),
        }
    }

    pub(in crate::policy_compiler) fn query_v1(&self) -> Result<OpeningQueryV2, JournalError> {
        self.query
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler) fn root_sample_v1(
        &self,
    ) -> Result<RawPairedClockSample, JournalError> {
        self.observed
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler) fn root_nonce_v1(&self) -> Result<[u8; 16], JournalError> {
        self.nonce
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler) fn funding_failed_v1(&self) -> bool {
        matches!(self.query_funding, Some(Err(_))) || matches!(self.subject_funding, Some(Err(_)))
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.query_funding)
            .or_else(|| match self.query.as_ref()?.as_ref().err()? {
                OpeningQueryErrorV2::StopCleanup(cause) => Some(cause as &(dyn Error + 'static)),
                OpeningQueryErrorV2::ExecutionNoApply(cause) => {
                    Some(cause as &(dyn Error + 'static))
                }
                OpeningQueryErrorV2::Apply(cause) => Some(cause as &(dyn Error + 'static)),
                OpeningQueryErrorV2::Host(cause) => Some(cause as &(dyn Error + 'static)),
                OpeningQueryErrorV2::MaintenanceStorage(cause) => {
                    Some(cause as &(dyn Error + 'static))
                }
                OpeningQueryErrorV2::StartInputs(cause) => Some(cause as &(dyn Error + 'static)),
            })
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| cause(&self.observed))
            .or_else(|| cause(&self.nonce))
            .or_else(|| cause(&self.relation))
            .or_else(|| cause(&self.subject_geometry))
            .or_else(|| cause(&self.subject_funding))
            .or_else(|| cause(&self.tightened))
            .or_else(|| self.closed.then_some(&CLOSED as _))
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

// Pure comparison shared by the actual native opening and negative fixtures.
// It cannot construct a paid opening or authenticate supplied clock fields.
pub(in crate::policy_compiler) fn query_sample_cutoff_v2(
    query: OpeningQueryV2,
    sample: RawPairedClockSample,
) -> Result<u64, JournalError> {
    let (boot, original, cutoff) = query.clock_fields();
    if sample.host_boot_id() != boot || sample.boottime_nanoseconds() < original {
        return Err(JournalError::ProtectedBoundary);
    }
    if matches!(
        query,
        OpeningQueryV2::ExecutionNoApply(_) | OpeningQueryV2::ExecutionAcquisition(_) | OpeningQueryV2::StopCleanup(_)
    ) {
        if cutoff <= sample.boottime_nanoseconds() {
            return Err(JournalError::ProtectedBoundary);
        }
        return Ok(cutoff);
    }
    let cutoff = sample
        .boottime_nanoseconds()
        .checked_add(ROOT_RESOURCE_MAXIMUM_FLIGHT_NS)
        .ok_or(JournalError::JournalTooLarge)?
        .min(cutoff);
    if cutoff <= sample.boottime_nanoseconds() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(cutoff)
}

// This shared comparison consumes only the actual native reader's C rows.
// Each real closed stage supplies its own enrolled node and original partition;
// no decoded account can establish a recipient generation or grant by itself.
pub(in crate::policy_compiler) fn require_controller_baseline_account_data_v3(
    state: &aos_sandbox_ledger_replay::cache_current::State,
    encoded: &[u8],
    node: [u8; 16],
    partition: (ResourceVector, ResourceVector, ResourceVector),
) -> Result<(), Box<dyn Error>> {
    use aos_sandbox_protocol::domain_ledger::resource_bank::{
        AccountHead, AccountKind, is_head_entry,
    };
    let account = AccountHead::decode(encoded)?;
    let enrollment = account.native_fields().enrollment;
    let incarnation = aos_sandbox_protocol::domain_ledger::resource_bank::recipient_incarnation(
        state, enrollment,
    )?
    .ok_or(JournalError::ProtectedBoundary)?;
    if aos_sandbox_protocol::domain_ledger::resource_bank::validate(state)? != Some(enrollment)
        || account.native_fields().kind != AccountKind::Controller
        || enrollment.native_fields().node != node
        || account.recorded_baseline() != partition.0
        || incarnation.generation() != 0
        || incarnation.normal_precharge_v1() != partition.1
        || incarnation.recovery_reserve_v1() != partition.2
        || incarnation.charged_baseline_v1()? != partition.1
        || !state.iter().any(|((namespace, key), bytes)| {
            is_head_entry(*namespace, key) && bytes.as_slice() == encoded
        })
    {
        return Err(JournalError::ProtectedBoundary.into());
    }
    Ok(())
}
