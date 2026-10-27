//! Owns the funded candidate's native reads and independently owed Output posts.
//!
//! The same fixed lifecycle original pays every source model before growth.
//! Output observations complete before an action post is armed, and dedicated
//! after destinations remain callable after a primary failure poisons admission.

use super::*;
use crate::execution_output::{
    CandidateProbeTimeOriginalV1, CandidateProbeTimeV1, CandidateProbeV1,
};
use crate::execution_output_credential::StorageOutputOwedAfterV1;
use crate::execution_output_credential::logical_receiving::LogicalOutputFundingErrorV1;
use crate::resolver::protected_catalog::{
    ProtectedStorageResolverPolicyDirectoryV1, ResolverPolicyReadOriginalV1,
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

type Loan<'cut, 'original> = aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>;

#[derive(Debug, thiserror::Error)]
enum CandidateClockErrorV1 {
    #[error("the actual candidate kernel clock is stale")]
    Stale,
    #[error(transparent)]
    Kernel(aos_linux_descriptors::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for CandidateClockErrorV1 {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

type Clock =
    aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<CandidateClockErrorV1>;

#[derive(Clone, Copy)]
enum First {
    Before,
    Arm,
    AfterArm(usize),
    After(usize),
    Post,
    Closed,
}

pub(crate) struct CandidateNativeOriginalV1 {
    clocks: [[Clock; 2]; 4],
    samples: [[Option<Result<RawPairedClockSample, CandidateClockErrorV1>>; 2]; 4],
    resolver: [ResolverPolicyReadOriginalV1; 4],
    time: CandidateProbeTimeOriginalV1,
    before: Option<Result<(), crate::service::StorageServiceError>>,
    arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    after: [StorageOutputOwedAfterV1; 6],
    prepared: [Option<Result<(), crate::service::StorageServiceError>>; 6],
    finished: [Option<Result<(), crate::service::StorageServiceError>>; 6],
    post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    first: Option<First>,
}

impl CandidateNativeOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            clocks: std::array::from_fn(|_| std::array::from_fn(|_| Clock::default())),
            samples: std::array::from_fn(|_| [None, None]),
            resolver: std::array::from_fn(|_| ResolverPolicyReadOriginalV1::new()),
            time: CandidateProbeTimeOriginalV1::new(),
            before: None,
            arm: None,
            after: std::array::from_fn(|_| StorageOutputOwedAfterV1::new()),
            prepared: std::array::from_fn(|_| None),
            finished: std::array::from_fn(|_| None),
            post: None,
            first: None,
        }
    }

    pub(crate) fn receiving_demand_v1(
        state: ResourceVector,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<ResourceVector, LogicalOutputFundingErrorV1> {
        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let artifacts = request
            .authorization()
            .ok_or(LogicalOutputFundingErrorV1::Closed)?;
        let authorization = crate::authorization::receiving_authorization_memory_v1(artifacts)?;
        let artifact_bytes = [
            artifacts.broker_plan().len(),
            artifacts.broker_plan_signature().len(),
            artifacts.ownership_lease().len(),
            artifacts.ownership_lease_signature().len(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, width| sum.checked_add(width))
        .ok_or_else(overflow)?;
        let request_bytes = request
            .canonical_packet()
            .len()
            .checked_add(request.exact_body().len())
            .and_then(|bytes| bytes.checked_add(request.exact_body().len()))
            .and_then(|bytes| bytes.checked_add(artifact_bytes))
            .ok_or_else(overflow)?;
        // The requirement, its cloned plan and completed preflight coexist.
        // Their names use the existing resolver255/dataset1024 codec limits.
        // Dataset formatting may reallocate before its final fixed hex suffix.
        let dataset_name =
            crate::catalog_transition::execution_capture::MAX_CAPTURE_DATASET_NAME_BYTES;
        let plan = std::mem::size_of::<
            crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1,
        >()
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1,
            >())
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1,
            >())
        })
        .and_then(|bytes| bytes.checked_add(dataset_name.checked_mul(5)?))
        .and_then(|bytes| bytes.checked_add(255usize.checked_mul(4)?))
        // Two fixed six-argument commands: source String arrays and their
        // cloned Vec rows overlap during .to_vec(), including string data.
        .and_then(|bytes| {
            bytes.checked_add(
                12usize
                    .checked_mul(std::mem::size_of::<String>())?
                    .checked_mul(2)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add((255usize.checked_mul(2)?.checked_add(128)?).checked_mul(2)?)
        })
        .ok_or_else(overflow)?;
        let fixed = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<OriginalCaptureCandidateV1>().checked_mul(2)?)
            })
            .and_then(|bytes| bytes.checked_add(request_bytes))
            .and_then(|bytes| bytes.checked_add(plan))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<StorageExecutionCaptureCandidateV1>())
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ValidatedStorageCaptureCandidateV1>().checked_mul(4)?,
                )
            })
            // Canonical candidate stack, generated field backing, canonical
            // response, retained response copy and decoder's candidate backing.
            .and_then(|bytes| bytes.checked_add(STORAGE_CAPTURE_CANDIDATE_BYTES_V1.checked_mul(5)?))
            // The generated canonical response adds its one bytes-field tag
            // and length prefix; the other fields above remain typed inline.
            .and_then(|bytes| bytes.checked_add(4usize.checked_mul(15)?))
            .and_then(|bytes| {
                bytes.checked_add(Clock::dominant_requested_bytes_v1()?.checked_mul(8)?)
            })
            .ok_or_else(overflow)?;
        let files = Clock::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(8)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(overflow)?;
        let mut demand = ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(fixed).map_err(|_| overflow())?,
            )
            .with(D::OpenFiles, files);
        demand = demand.checked_add(
            CandidateProbeTimeOriginalV1::receiving_demand_v1().ok_or_else(overflow)?,
        )?;
        // Four separately retained authority/catalog/policy cuts. Each source
        // decoder and its selected policy is paid once per actual bookend.
        for index in 0..4 {
            // These captures repeat the same actual State and two fixed file
            // namespaces. Native FDs/byte planes remain separately retained.
            let namespace = |shape: ResourceVector| {
                if index == 0 {
                    shape
                } else {
                    shape.with(D::MetadataEntries, 0)
                }
            };
            demand = demand
                .checked_add(state.with(D::MetadataEntries, 0))?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, authorization))?
                .checked_add(namespace(
                    ResolverPolicyReadOriginalV1::receiving_demand_v3().ok_or_else(overflow)?,
                ))?
                .checked_add(namespace(
                    OriginalCapturePolicyReadV1::receiving_demand_v3().ok_or_else(overflow)?,
                ))?;
        }
        Ok(demand)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before => self.before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Arm => self.arm.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AfterArm(index) | First::After(index) => self.after[index].failure(),
            First::Post => self.post.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Closed => Some(&CaptureCandidateClosedV1),
        }
    }

    pub(super) fn probe_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.time.failure()
    }

    pub(super) fn original_output_before_failed(&self) -> bool {
        matches!(self.first, Some(First::Before))
    }

    pub(super) fn field_failure(
        &self,
        index: usize,
        field: BookendCauseV1,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match field {
            BookendCauseV1::Clock | BookendCauseV1::LateClock => {
                let clock = usize::from(field == BookendCauseV1::LateClock);
                self.clocks[index][clock].failure().or_else(|| {
                    self.samples[index][clock]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
            }
            BookendCauseV1::Resolver => self.resolver[index].failure(),
            BookendCauseV1::Credential => self.after[Self::credential_after(index)].failure(),
            _ => None,
        }
    }

    pub(super) fn post_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure().or_else(|| {
            self.after
                .iter()
                .find_map(StorageOutputOwedAfterV1::failure)
        })
    }

    pub(super) fn prepare_delivery_after_v1(
        &mut self,
        output: &StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> bool {
        if self.first.is_some() || !matches!(self.post, Some(Ok(()))) {
            return false;
        }
        if self.prepared[5].is_some() {
            if !matches!(self.finished[5], Some(Ok(()))) || self.after[5].failure().is_some() {
                self.first.get_or_insert(First::Closed);
                return false;
            }
            self.after[5] = StorageOutputOwedAfterV1::new();
            self.prepared[5] = None;
            self.finished[5] = None;
        }
        if !self.prepare_after(5, output, lifecycle, session, socket) {
            return false;
        }
        // The preceding complete source/model/native post was positive. Its
        // exact local files may now be disposed before the already prepaid
        // independent after sample, while the same long-lived owners stay held.
        self.clocks[3] = std::array::from_fn(|_| Clock::default());
        self.samples[3] = [None, None];
        self.resolver[3] = ResolverPolicyReadOriginalV1::new();
        true
    }

    pub(super) fn delivery_is_armed_v1(&self) -> bool {
        matches!(self.prepared[5], Some(Ok(()))) && self.finished[5].is_none()
    }

    fn credential_after(index: usize) -> usize {
        if index < 2 { index } else { index + 1 }
    }

    pub(super) fn prepare_after(
        &mut self,
        index: usize,
        output: &StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> bool {
        if self.prepared[index].is_some() {
            self.first.get_or_insert(First::Closed);
            return false;
        }
        self.prepared[index] = Some(output.prepare_owed_after_receiving_v1(
            lifecycle,
            session,
            socket,
            &mut self.after[index],
        ));
        if !matches!(self.prepared[index], Some(Ok(()))) {
            self.first.get_or_insert(First::AfterArm(index));
            return false;
        }
        true
    }

    fn finish_after(
        &mut self,
        index: usize,
        output: &StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>,
    ) -> Result<(), crate::service::StorageServiceError> {
        if !matches!(self.prepared[index], Some(Ok(()))) || self.finished[index].is_some() {
            self.first.get_or_insert(First::Closed);
            return Err(crate::service::StorageServiceError::Runtime(
                StorageRuntimeError::Receiving,
            ));
        }
        self.finished[index] =
            Some(output.finish_owed_after_receiving_v1(lifecycle, &mut self.after[index]));
        if !matches!(self.finished[index], Some(Ok(()))) {
            self.first.get_or_insert(First::After(index));
            return Err(crate::service::StorageServiceError::Runtime(
                StorageRuntimeError::Receiving,
            ));
        }
        Ok(())
    }
}

pub(super) enum CandidateIntervalV1<'loan, 'cut, 'original> {
    Ordinary(&'loan StorageExecutionOutputCustodyV1),
    Lifecycle {
        output: &'loan mut StorageExecutionOutputCustodyV1,
        lifecycle: &'loan mut Loan<'cut, 'original>,
        session: &'loan aos_sandbox_controller_domain::Journal,
        socket: &'loan aos_sandbox_linux::seqpacket::SeqpacketSocket,
        native: &'loan mut CandidateNativeOriginalV1,
        delivery_after: bool,
    },
}

impl CandidateIntervalV1<'_, '_, '_> {
    pub(super) fn output(&self) -> &StorageExecutionOutputCustodyV1 {
        match self {
            Self::Ordinary(output) => output,
            Self::Lifecycle { output, .. } => output,
        }
    }

    pub(super) fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary(_))
    }

    pub(super) fn begin(&mut self, index: usize) -> bool {
        match self {
            Self::Ordinary(_) => true,
            Self::Lifecycle {
                output,
                lifecycle,
                session,
                socket,
                native,
                ..
            } => {
                if native.first.is_some() {
                    return false;
                }
                // Repeated signing/sending samples may replace only their
                // fully positive native/model posts, never a failed original.
                if native.arm.is_some() {
                    if !matches!(native.post, Some(Ok(())))
                        || native.after.iter().any(|after| after.failure().is_some())
                        || native.prepared.iter().zip(&native.finished).any(
                            |(prepared, finished)| {
                                matches!(prepared, Some(Ok(())))
                                    && !matches!(finished, Some(Ok(())))
                            },
                        )
                    {
                        native.first.get_or_insert(First::Closed);
                        return false;
                    }
                    native.arm = None;
                    native.post = None;
                    native.before = None;
                    if index >= 2 {
                        native.clocks[index] = std::array::from_fn(|_| Clock::default());
                        native.samples[index] = [None, None];
                        native.resolver[index] = ResolverPolicyReadOriginalV1::new();
                        let after = CandidateNativeOriginalV1::credential_after(index);
                        native.after[after] = StorageOutputOwedAfterV1::new();
                        native.prepared[after] = None;
                        native.finished[after] = None;
                    }
                }
                native.before =
                    Some(output.recheck_session_receiving_v1(lifecycle, session, socket));
                if !matches!(native.before, Some(Ok(()))) {
                    native.first = Some(First::Before);
                    return false;
                }
                native.arm = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
                if !matches!(native.arm, Some(Ok(()))) {
                    native.first = Some(First::Arm);
                    return false;
                }
                native.prepare_after(
                    CandidateNativeOriginalV1::credential_after(index),
                    output,
                    lifecycle,
                    session,
                    socket,
                )
            }
        }
    }

    pub(super) fn prepare_after(&mut self, index: usize) -> bool {
        match self {
            Self::Ordinary(_) => true,
            Self::Lifecycle {
                output,
                lifecycle,
                session,
                socket,
                native,
                ..
            } => native.prepare_after(index, output, lifecycle, session, socket),
        }
    }

    pub(super) fn clock(
        &mut self,
        index: usize,
        late: bool,
    ) -> Result<RawPairedClockSample, StorageRuntimeError> {
        match self {
            Self::Ordinary(_) => trusted_paired_clock_sample(),
            Self::Lifecycle { native, .. } => {
                let clock = usize::from(late);
                if native.samples[index][clock].is_some() {
                    return Err(StorageRuntimeError::Recovery);
                }
                native.samples[index][clock] = Some(native.clocks[index][clock].observe_once(None));
                match native.samples[index][clock].as_ref() {
                    Some(Ok(sample)) => Ok(*sample),
                    _ => Err(StorageRuntimeError::Recovery),
                }
            }
        }
    }

    pub(super) fn resolver(
        &mut self,
        index: usize,
        directory: &ProtectedStorageResolverPolicyDirectoryV1,
        assignment: aos_sandbox_model::BrokerAssignment,
    ) -> Result<SelectedStorageResolverPolicyV1, StorageResolverPolicyError> {
        match self {
            Self::Ordinary(_) => directory
                .load()
                .and_then(|catalog| catalog.select(assignment)),
            Self::Lifecycle { native, .. } => directory
                .load_retaining_v1(&mut native.resolver[index])
                .and_then(|catalog| catalog.select(assignment)),
        }
    }

    pub(super) fn custody(
        &mut self,
        root: &std::path::Path,
        index: usize,
    ) -> Result<(), crate::service::StorageServiceError> {
        match self {
            Self::Ordinary(output) => output.recheck(root),
            Self::Lifecycle {
                output,
                lifecycle,
                native,
                delivery_after,
                ..
            } => native.finish_after(
                if *delivery_after {
                    5
                } else {
                    CandidateNativeOriginalV1::credential_after(index)
                },
                output,
                lifecycle,
            ),
        }
    }

    pub(super) fn probe(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        request: &AuthenticatedBrokerMethodRequestV1,
        cut: &AuthenticatedCaptureCandidateCutV1,
        resolver: &SelectedStorageResolverPolicyV1,
        allocation: CaptureAllocationV1,
    ) -> Result<[u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1], CaptureCandidateErrorV1> {
        match self {
            Self::Ordinary(output) => output.ledger().observe_authenticated_capture_candidate(
                cut,
                resolver.policy(),
                allocation,
                &runtime.pin_contract,
            ),
            Self::Lifecycle {
                output,
                lifecycle,
                session,
                socket,
                native,
                ..
            } => {
                let mut stage =
                    crate::process::receiving_stage::StoragePhysicalWorkerStageV1::candidate_v1(
                        lifecycle, session, socket, request,
                    );
                output
                    .ledger()
                    .observe_authenticated_capture_candidate_with_v1(
                        cut,
                        resolver.policy(),
                        allocation,
                        &mut CandidateProbeV1::Receiving {
                            helper: &mut runtime.helper,
                            stage: &mut stage,
                            cutoff: request.deadline_boottime_nanoseconds(),
                        },
                        &mut CandidateProbeTimeV1::Receiving(&mut native.time),
                    )
            }
        }
    }

    pub(super) fn finish(&mut self) {
        if let Self::Lifecycle {
            output,
            lifecycle,
            session,
            socket,
            native,
            ..
        } = self
        {
            // The action post and every prepared Output after are independently
            // owed. No healthy entry/payment is required from this path.
            if matches!(native.arm, Some(Ok(()))) && native.post.is_none() {
                native.post = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
                if !matches!(native.post, Some(Ok(()))) {
                    native.first.get_or_insert(First::Post);
                }
            }
            for index in 0..6 {
                if matches!(native.prepared[index], Some(Ok(())))
                    && native.finished[index].is_none()
                {
                    let _ = native.finish_after(index, output, lifecycle);
                }
            }
        }
    }
}
