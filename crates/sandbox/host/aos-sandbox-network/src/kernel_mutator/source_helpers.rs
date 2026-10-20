//! Executes the sole mutation recipe through actual prepaid Source helpers.
//!
//! The closed worker actor supplies its already-authenticated mutation and
//! unchanged original D. Every helper keeps the real native prefix, paired
//! Source observations and independent clock posts until result/ACK custody.

mod receiving;
pub(crate) use receiving::{MutationProgrammeDataV2, mutation_programme_data_v2};

use super::*;
use crate::kernel_reader::{NetworkArtifactCurrentOriginalV4, NetworkArtifactRoleV4};
use crate::namespace_pin::NetworkNamespacePublicationOriginalV2;
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_broker::receiving::{
    NetworkChildOperationBindingDataV2, NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::process::FixedProcessCaptureCutV3;

/// Counts the exact five-artifact checks in the three actual Prepare effects.
pub(crate) fn preparation_artifact_count_data_v2() -> Option<usize> {
    let full_checks = [2usize, 2, 2]
        .into_iter()
        .try_fold(0usize, |sum, checks| sum.checked_add(checks))?;
    full_checks.checked_mul(
        [
            NetworkArtifactRoleV4::Ip,
            NetworkArtifactRoleV4::Nft,
            NetworkArtifactRoleV4::LeaseLoader,
            NetworkArtifactRoleV4::LeaseObject,
            NetworkArtifactRoleV4::Enforcement,
        ]
        .len(),
    )
}

/// Retains one reached artifact conjunction and its positive physical disposal.
pub(crate) struct NetworkSourceArtifactOriginalV2 {
    native: NetworkArtifactCurrentOriginalV4,
    result: Option<Result<(), NetworkKernelReaderError>>,
    disposal: Option<Result<(), NetworkKernelReaderError>>,
}

impl NetworkSourceArtifactOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            native: NetworkArtifactCurrentOriginalV4::new(),
            result: None,
            disposal: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native
            .failure()
            .or_else(|| {
                self.result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.disposal
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

#[derive(Clone, Copy)]
enum InnerFailure {
    Helper(usize),
    Artifact(usize),
    Publication,
}

/// Counts the literal helper calls of the sole typed Prepare recipe.
///
/// The two fixed role rosters name the actual common effect recipe. Variable
/// calls arise only from its authenticated address and route loops; unsupported
/// host-network plans refuse. No maximum or default substitutes for this plan.
pub(crate) fn preparation_helper_count_data_v2(plan: &NetworkKernelExpectationV1) -> Option<usize> {
    use NetworkStatusHelperRoleV4 as Role;
    let base = match plan.kind() {
        NetworkKind::Isolated => return Some([Role::NftBatch, Role::Ip].len()),
        NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => [
            Role::NftBatch,
            Role::IpWithHostNamespace,
            Role::Ip,
            Role::NftBatch,
            Role::Ip,
            Role::LeaseLoader,
            Role::Ip,
        ]
        .len(),
        NetworkKind::Host => return None,
    };
    let ipv6 = plan
        .address_pairs()
        .iter()
        .filter(|pair| matches!(pair.sandbox, ObservedIpAddressV1::Ipv6(_)))
        .count();
    base.checked_add(plan.address_pairs().len().checked_mul(2)?)?
        .checked_add(ipv6.checked_mul(2)?)?
        .checked_add(plan.routes().len())
}

#[derive(Clone, Copy)]
enum First {
    ClockBefore,
    Cut,
    WaitBefore,
    SourceBefore,
    InputOpen,
    InputWrite,
    InputRewind,
    Helper,
    Output,
    Semantic,
    Disposal,
    ClockAfter,
    WaitAfter,
    SourceAfter,
}

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("the Network effect clock differs from its original BOOT or deadline")]
    Stale,
    #[error(transparent)]
    Native(aos_sandbox_linux::Error),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(cause: aos_sandbox_linux::Error) -> Self {
        Self::Native(cause)
    }
}

type ClockAttempt = RetainedKernelPairedClockAttemptV1<ClockError>;

struct ClockOriginal {
    native: ClockAttempt,
    result: Option<Result<RawPairedClockSample, ClockError>>,
}

impl ClockOriginal {
    fn new() -> Self {
        Self {
            native: ClockAttempt::default(),
            result: None,
        }
    }

    fn capture(&mut self, boot_id: [u8; 16]) -> Result<RawPairedClockSample, ClockError> {
        self.result = Some(self.native.observe_once(None).and_then(|sample| {
            if sample.host_boot_id() == boot_id {
                Ok(sample)
            } else {
                Err(ClockError::Stale)
            }
        }));
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ClockError::Stale)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure().or_else(|| {
            self.result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
        })
    }
}

/// Keeps every reached input/helper/Source/D result on its prepaid attempt.
pub(crate) struct NetworkSourceHelperOriginalV2 {
    clock_before: ClockOriginal,
    current_before: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    cut: Option<Result<FixedProcessCaptureCutV3, aos_sandbox_linux::Error>>,
    wait_before: Option<Result<rustix::event::Timespec, NetworkKernelMutationError>>,
    source_before: NetworkChildSourceProbeOriginalV2,
    source_before_result:
        Option<Result<(), aos_sandbox_broker::receiving::NetworkChildOriginClosedV2>>,
    input_open: Option<Result<File, rustix::io::Errno>>,
    input: Option<File>,
    input_write: Option<std::io::Result<()>>,
    input_rewind: Option<std::io::Result<()>>,
    helper: NetworkStatusHelperOriginalV4,
    helper_result: Option<Result<(), NetworkKernelMutationError>>,
    stdout: Option<Vec<u8>>,
    semantic: Option<Result<bool, NetworkKernelMutationError>>,
    disposal: Option<Result<(), NetworkKernelMutationError>>,
    clock_after: ClockOriginal,
    current_after: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    wait_after: Option<Result<rustix::event::Timespec, NetworkKernelMutationError>>,
    source_after: NetworkChildSourceProbeOriginalV2,
    source_after_result:
        Option<Result<(), aos_sandbox_broker::receiving::NetworkChildOriginClosedV2>>,
    first: Option<First>,
    closed: NetworkKernelMutationError,
}

impl NetworkSourceHelperOriginalV2 {
    pub(crate) fn new(nofile: u64, table: usize) -> Option<Self> {
        Some(Self {
            clock_before: ClockOriginal::new(),
            current_before: None,
            cut: None,
            wait_before: None,
            source_before: NetworkChildSourceProbeOriginalV2::new(),
            source_before_result: None,
            input_open: None,
            input: None,
            input_write: None,
            input_rewind: None,
            helper: NetworkStatusHelperOriginalV4::new_for_programme_data_v2(nofile, table)?,
            helper_result: None,
            stdout: None,
            semantic: None,
            disposal: None,
            clock_after: ClockOriginal::new(),
            current_after: None,
            wait_after: None,
            source_after: NetworkChildSourceProbeOriginalV2::new(),
            source_after_result: None,
            first: None,
            closed: NetworkKernelMutationError::Helper,
        })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            First::ClockBefore => self.clock_before.failure().or_else(|| {
                self.current_before
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            }),
            First::SourceBefore => self.source_before.failure(),
            First::Cut => self
                .cut
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::WaitBefore => self
                .wait_before
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::InputOpen => self
                .input_open
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::InputWrite => self
                .input_write
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::InputRewind => self
                .input_rewind
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Helper => self.helper.failure(),
            First::Disposal => self
                .disposal
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::ClockAfter => self.clock_after.failure().or_else(|| {
                self.current_after
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            }),
            First::SourceAfter => self.source_after.failure(),
            First::WaitAfter => self
                .wait_after
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Output => None,
            First::Semantic => self
                .semantic
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
        };
        cause.or(Some(&self.closed))
    }
}

/// Borrows the actual admitted operation, Source and finite retained destinations.
///
/// Construction remains private to the closed worker factory. This value
/// contains no bank, refill, caller fee, decoded authority or operation adopter.
pub(super) struct SourceHelpers<'held, 'native> {
    source: &'held mut NetworkChildSourceLoanV2<'native>,
    binding: NetworkChildOperationBindingDataV2,
    mutator: &'held FixedNetworkKernelMutator,
    authority: &'held crate::authorization::NetworkAuthorityV1,
    authorization: SourceAuthorization<'held>,
    attempts: &'held mut [NetworkSourceHelperOriginalV2],
    artifacts: &'held mut [NetworkSourceArtifactOriginalV2],
    publication: &'held mut NetworkNamespacePublicationOriginalV2,
    next: usize,
    next_artifact: usize,
    first: Option<InnerFailure>,
    inventory_pending: Option<usize>,
    outer_closed: bool,
}


trait DestroyCurrent {
    fn request_effect(&self) -> ([u8; 16], ObjectDigest);
    fn effect(&self) -> &aos_sandbox_broker::BrokerEffectIntentV1;
    fn local_lease(&self) -> &aos_sandbox_model::LocalLeaseRecord;
    fn require_current(
        &mut self,
        authority: &crate::authorization::NetworkAuthorityV1,
        sample: RawPairedClockSample,
    ) -> Result<(), crate::worker_protocol::NetworkWorkerProtocolError>;
}

struct PendingDestroyCurrent<'held, 'execution> {
    step: &'held mut NetworkLifecycleAuthorizedStepV1<'execution>,
    trusted_current_fence: &'held [u8],
}

impl DestroyCurrent for PendingDestroyCurrent<'_, '_> {
    fn request_effect(&self) -> ([u8; 16], ObjectDigest) {
        self.step.original_request_effect_data_v2()
    }

    fn effect(&self) -> &aos_sandbox_broker::BrokerEffectIntentV1 {
        self.step.original_effect_v2()
    }

    fn local_lease(&self) -> &aos_sandbox_model::LocalLeaseRecord {
        self.step.original_local_lease_v2()
    }

    fn require_current(
        &mut self,
        authority: &crate::authorization::NetworkAuthorityV1,
        sample: RawPairedClockSample,
    ) -> Result<(), crate::worker_protocol::NetworkWorkerProtocolError> {
        // This is the separately retained, genuine coordinator Source handoff,
        // never the dispatch's claimed_current_fence. The existing step engine
        // opens and compares it and permanently poisons a refused pending step.
        self.step.require_current_before_helper_v2(
            authority,
            &mut || Ok(self.trusted_current_fence.to_vec()),
            &mut || Ok(sample),
        )
    }
}

enum SourceAuthorization<'held> {
    Prepare(&'held NetworkMutationAuthorizationV1),
    Destroy(&'held mut dyn DestroyCurrent),
}

impl<'held> SourceAuthorization<'held> {
    fn preparation_original(&self) -> Option<&'held NetworkMutationAuthorizationV1> {
        match self {
            Self::Prepare(original) => Some(*original),
            Self::Destroy(_) => None,
        }
    }

    fn original_effect_v2(&self) -> &aos_sandbox_broker::BrokerEffectIntentV1 {
        match self {
            Self::Prepare(original) => original.original_effect_v2(),
            Self::Destroy(original) => original.effect(),
        }
    }

    fn original_local_lease_v2(&self) -> &aos_sandbox_model::LocalLeaseRecord {
        match self {
            Self::Prepare(original) => original.original_local_lease_v2(),
            Self::Destroy(original) => original.local_lease(),
        }
    }

    fn require_current_before_helper_v2<F>(
        &mut self,
        authority: &crate::authorization::NetworkAuthorityV1,
        clock: &mut F,
    ) -> Result<(), crate::worker_protocol::NetworkWorkerProtocolError>
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::NetworkAdmissionError>,
    {
        match self {
            Self::Prepare(original) => original.require_current_before_helper_v2(authority, clock),
            Self::Destroy(original) => original.require_current(
                authority,
                clock()
                    .map_err(|_| crate::worker_protocol::NetworkWorkerProtocolError::Authority)?,
            ),
        }
    }
}

impl<'held, 'native> SourceHelpers<'held, 'native> {
    pub(super) fn for_preparation(
        source: &'held mut NetworkChildSourceLoanV2<'native>,
        mutator: &'held FixedNetworkKernelMutator,
        authority: &'held crate::authorization::NetworkAuthorityV1,
        authorization: &'held NetworkMutationAuthorizationV1,
        kernel: &'held aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1,
        attempts: &'held mut [NetworkSourceHelperOriginalV2],
        artifacts: &'held mut [NetworkSourceArtifactOriginalV2],
        publication: &'held mut NetworkNamespacePublicationOriginalV2,
    ) -> Option<Self> {
        let binding = source.operation_binding_data_v2()?;
        if binding.purpose != 1
            || binding.request_id != authorization.request_id()
            || binding.effect_digest != *authorization.effect_digest().as_bytes()
            || !kernel.completed_v1()
            || attempts.is_empty()
            || artifacts.len() != preparation_artifact_count_data_v2()?
        {
            return None;
        }
        Some(Self {
            source,
            binding,
            mutator,
            authority,
            authorization: SourceAuthorization::Prepare(authorization),
            attempts,
            artifacts,
            publication,
            next: 0,
            next_artifact: 0,
            first: None,
            inventory_pending: None,
            outer_closed: false,
        })
    }


    fn for_destroy(
        source: &'held mut NetworkChildSourceLoanV2<'native>,
        mutator: &'held FixedNetworkKernelMutator,
        authority: &'held crate::authorization::NetworkAuthorityV1,
        authorization: &'held mut dyn DestroyCurrent,
        kernel: &'held aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1,
        attempts: &'held mut [NetworkSourceHelperOriginalV2],
        artifacts: &'held mut [NetworkSourceArtifactOriginalV2],
        publication: &'held mut NetworkNamespacePublicationOriginalV2,
        next: usize,
        next_artifact: usize,
    ) -> Option<Self> {
        let binding = source.operation_binding_data_v2()?;
        let (request, effect) = authorization.request_effect();
        if binding.purpose != 1
            || binding.request_id != request
            || binding.effect_digest != *effect.as_bytes()
            || authorization.effect().verb() != aos_sandbox_model::BrokerVerb::NetworkDestroy
            || !kernel.completed_v1()
            || next > attempts.len()
            || next_artifact > artifacts.len()
        {
            return None;
        }
        Some(Self {
            source,
            binding,
            mutator,
            authority,
            authorization: SourceAuthorization::Destroy(authorization),
            attempts,
            artifacts,
            publication,
            next,
            next_artifact,
            first: None,
            inventory_pending: None,
            outer_closed: false,
        })
    }

    fn role(
        &self,
        artifact: &PinnedArtifact,
        inherited: usize,
        stdin: bool,
    ) -> Result<NetworkStatusHelperRoleV4, NetworkKernelMutationError> {
        use NetworkStatusHelperRoleV4 as Role;
        if std::ptr::eq(artifact, &self.mutator.ip) && !stdin {
            return match inherited {
                0 => Ok(Role::Ip),
                1 => Ok(Role::IpWithHostNamespace),
                _ => Err(NetworkKernelMutationError::Helper),
            };
        }
        if std::ptr::eq(artifact, &self.mutator.nft) && inherited == 0 {
            return match (stdin, self.authorization.preparation_original().is_some()) {
                (true, true) => Ok(Role::NftBatch),
                (false, false) => Ok(Role::NftDestroy),
                _ => Err(NetworkKernelMutationError::Artifact),
            };
        }
        if std::ptr::eq(artifact, &self.mutator.lease_gate_loader) && !stdin && inherited <= 1 {
            return Ok(Role::LeaseLoader);
        }
        Err(NetworkKernelMutationError::Artifact)
    }

    fn execute(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
        role: NetworkStatusHelperRoleV4,
        nft: Option<&[u8]>,
        output: bool,
    ) -> Result<Option<Vec<u8>>, NetworkKernelMutationError> {
        if self.outer_closed
            || self.first.is_some()
            || self.inventory_pending.is_some()
            || self.next >= self.attempts.len()
        {
            return Err(NetworkKernelMutationError::Helper);
        }
        let index = self.next;
        self.next += 1;
        let original = &mut self.attempts[index];
        let binding = self.binding;
        let effect = self.authorization.original_effect_v2();
        let deadline = effect.effect_deadline_boottime_nanoseconds().min(
            self.authorization
                .original_local_lease_v2()
                .fail_stop_boottime_nanoseconds(),
        );
        let wall = effect
            .plan_expires_seconds()
            .min(effect.authority_expires_seconds());
        original.cut = Some(FixedProcessCaptureCutV3::new(deadline, wall));
        if !matches!(original.cut, Some(Ok(_))) {
            original.first = Some(First::Cut);
        }
        let before = original.clock_before.capture(binding.boot);
        original.current_before = Some(self.authorization.require_current_before_helper_v2(
            self.authority,
            &mut || {
                before
                    .as_ref()
                    .copied()
                    .map_err(|_| crate::NetworkAdmissionError::FenceRejected)
            },
        ));
        if !matches!(original.current_before, Some(Ok(()))) {
            original.first.get_or_insert(First::ClockBefore);
        }
        if original.first.is_none() {
            original.wait_before = Some(remaining(&original.clock_before, deadline, wall));
            if let Some(Ok(timeout)) = original.wait_before.as_ref() {
                original.source_before_result = Some(
                    self.source
                        .require_live_before_once_v2(&mut original.source_before, Some(timeout)),
                );
                if !matches!(original.source_before_result, Some(Ok(()))) {
                    original.first = Some(First::SourceBefore);
                }
            } else {
                original.first = Some(First::WaitBefore);
            }
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if original.first.is_none() {
                if let Some(bytes) = nft {
                    original.input_open = Some(
                        rustix::fs::memfd_create(
                            "aos-network-nft-batch",
                            rustix::fs::MemfdFlags::CLOEXEC,
                        )
                        .map(File::from),
                    );
                    if matches!(original.input_open, Some(Ok(_))) {
                        if let Some(Ok(file)) = original.input_open.take() {
                            original.input = Some(file);
                        }
                    }
                    if let Some(file) = original.input.as_mut() {
                        original.input_write = Some(file.write_all(bytes));
                        if !matches!(original.input_write, Some(Ok(()))) {
                            original.first = Some(First::InputWrite);
                        }
                        original.input_rewind = Some(file.rewind());
                        if !matches!(original.input_rewind, Some(Ok(_))) {
                            original.first.get_or_insert(First::InputRewind);
                        }
                    } else {
                        original.first = Some(First::InputOpen);
                    }
                }
            }
            if original.first.is_none() {
                let input = original.input.as_ref().map(|file| file.as_fd()).or(stdin);
                if let Some(Ok(cut)) = original.cut.as_ref() {
                    original.helper_result = Some(
                        original
                            .helper
                            .run_once_v4(artifact, arguments, input, inherited, role, *cut),
                    );
                }
                if !matches!(original.helper_result, Some(Ok(()))) {
                    original.first = Some(First::Helper);
                } else if output {
                    original.stdout = original.helper.completed_stdout_v4().map(<[u8]>::to_vec);
                    if original.stdout.is_none() {
                        original.first = Some(First::Output);
                    }
                }
            }
        }));
        if body.is_err() {
            original.first.get_or_insert(First::Helper);
        }

        // Both actual posts run even after input, helper, status or unwind.
        let after = original.clock_after.capture(binding.boot);
        original.current_after = Some(self.authorization.require_current_before_helper_v2(
            self.authority,
            &mut || {
                after
                    .as_ref()
                    .copied()
                    .map_err(|_| crate::NetworkAdmissionError::FenceRejected)
            },
        ));
        if !matches!(original.current_after, Some(Ok(()))) {
            original.first.get_or_insert(First::ClockAfter);
        }
        if self.source.operation_binding_data_v2().is_some() {
            original.wait_after = Some(remaining(&original.clock_after, deadline, wall));
            if !matches!(original.wait_after, Some(Ok(_))) {
                original.first.get_or_insert(First::WaitAfter);
            }
            let timeout = match original.wait_after.as_ref() {
                Some(Ok(timeout)) => *timeout,
                _ => rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            original.source_after_result = Some(
                self.source
                    .require_live_before_once_v2(&mut original.source_after, Some(&timeout)),
            );
        } else {
            original.source_after_result = Some(
                self.source
                    .observe_owed_native_after_once_v2(&mut original.source_after),
            );
        }
        if !matches!(original.source_after_result, Some(Ok(()))) {
            original.first.get_or_insert(First::SourceAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if original.first.is_none() && !output {
            original.disposal = Some(original.helper.dispose_positive_once_v4());
            if !matches!(original.disposal, Some(Ok(()))) {
                original.first = Some(First::Disposal);
            }
        }
        if original.first.is_some() {
            self.first = Some(InnerFailure::Helper(index));
            Err(NetworkKernelMutationError::Helper)
        } else {
            if output {
                self.inventory_pending = Some(index);
            }
            Ok(original.stdout.take())
        }
    }
}

/// Retains one actual effect frontier and both independently owed Source/D posts.
pub(crate) struct NetworkSourceEffectFrontierOriginalV2 {
    entered: bool,
    before: ClockOriginal,
    before_current: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    source_before: NetworkChildSourceProbeOriginalV2,
    source_before_result:
        Option<Result<(), aos_sandbox_broker::receiving::NetworkChildOriginClosedV2>>,
    body: Option<Result<(), NetworkKernelMutationError>>,
    after: ClockOriginal,
    after_current: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    source_after: NetworkChildSourceProbeOriginalV2,
    source_after_result:
        Option<Result<(), aos_sandbox_broker::receiving::NetworkChildOriginClosedV2>>,
    wait_before: Option<Result<rustix::event::Timespec, NetworkKernelMutationError>>,
    wait_after: Option<Result<rustix::event::Timespec, NetworkKernelMutationError>>,
    first: Option<First>,
    closed: NetworkKernelMutationError,
}

impl NetworkSourceEffectFrontierOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            before: ClockOriginal::new(),
            before_current: None,
            source_before: NetworkChildSourceProbeOriginalV2::new(),
            source_before_result: None,
            body: None,
            after: ClockOriginal::new(),
            after_current: None,
            source_after: NetworkChildSourceProbeOriginalV2::new(),
            source_after_result: None,
            wait_before: None,
            wait_after: None,
            first: None,
            closed: NetworkKernelMutationError::Helper,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            First::ClockBefore => self.before.failure().or_else(|| {
                self.before_current
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            }),
            First::SourceBefore => self.source_before.failure(),
            First::WaitBefore => self
                .wait_before
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Helper => self
                .body
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::ClockAfter => self.after.failure().or_else(|| {
                self.after_current
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            }),
            First::SourceAfter => self.source_after.failure(),
            First::WaitAfter => self
                .wait_after
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            _ => None,
        };
        cause.or(Some(&self.closed))
    }
}

impl SourceHelpers<'_, '_> {
    fn outer_once<T>(
        &mut self,
        original: &mut NetworkSourceEffectFrontierOriginalV2,
        body: impl FnOnce(&mut Self, RawPairedClockSample) -> Result<T, NetworkKernelMutationError>,
    ) -> Result<T, NetworkKernelMutationError> {
        if original.entered || self.outer_closed || self.first.is_some() {
            self.outer_closed = true;
            original.first.get_or_insert(First::Helper);
            return Err(NetworkKernelMutationError::Helper);
        }
        original.entered = true;
        let effect = self.authorization.original_effect_v2();
        let deadline = effect.effect_deadline_boottime_nanoseconds().min(
            self.authorization
                .original_local_lease_v2()
                .fail_stop_boottime_nanoseconds(),
        );
        let wall = effect
            .plan_expires_seconds()
            .min(effect.authority_expires_seconds());
        let before = original.before.capture(self.binding.boot);
        original.before_current = Some(self.authorization.require_current_before_helper_v2(
            self.authority,
            &mut || {
                before
                    .as_ref()
                    .copied()
                    .map_err(|_| crate::NetworkAdmissionError::FenceRejected)
            },
        ));
        if !matches!(original.before_current, Some(Ok(()))) {
            original.first = Some(First::ClockBefore);
        }
        if original.first.is_none() {
            original.wait_before = Some(remaining(&original.before, deadline, wall));
            if let Some(Ok(wait)) = original.wait_before.as_ref() {
                original.source_before_result = Some(
                    self.source
                        .require_live_before_once_v2(&mut original.source_before, Some(wait)),
                );
                if !matches!(original.source_before_result, Some(Ok(()))) {
                    original.first = Some(First::SourceBefore);
                }
            } else {
                original.first = Some(First::WaitBefore);
            }
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if original.first.is_none() {
                let sample = original
                    .before
                    .result
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .copied();
                match sample.map(|sample| body(self, sample)) {
                    Some(Ok(value)) => {
                        original.body = Some(Ok(()));
                        Some(value)
                    }
                    Some(Err(cause)) => {
                        original.body = Some(Err(cause));
                        original.first = Some(First::Helper);
                        None
                    }
                    None => {
                        original.first = Some(First::ClockBefore);
                        None
                    }
                }
            } else {
                None
            }
        }));
        if body.is_err() {
            original.first.get_or_insert(First::Helper);
        }

        let after = original.after.capture(self.binding.boot);
        original.after_current = Some(self.authorization.require_current_before_helper_v2(
            self.authority,
            &mut || {
                after
                    .as_ref()
                    .copied()
                    .map_err(|_| crate::NetworkAdmissionError::FenceRejected)
            },
        ));
        if !matches!(original.after_current, Some(Ok(()))) {
            original.first.get_or_insert(First::ClockAfter);
        }
        if self.source.operation_binding_data_v2().is_some() {
            original.wait_after = Some(remaining(&original.after, deadline, wall));
            if !matches!(original.wait_after, Some(Ok(_))) {
                original.first.get_or_insert(First::WaitAfter);
            }
            let wait = match original.wait_after.as_ref() {
                Some(Ok(wait)) => *wait,
                _ => rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            original.source_after_result = Some(
                self.source
                    .require_live_before_once_v2(&mut original.source_after, Some(&wait)),
            );
        } else {
            original.source_after_result = Some(
                self.source
                    .observe_owed_native_after_once_v2(&mut original.source_after),
            );
        }
        if !matches!(original.source_after_result, Some(Ok(()))) {
            original.first.get_or_insert(First::SourceAfter);
        }
        let returned = match body {
            Ok(returned) => returned,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        if original.first.is_some() {
            self.outer_closed = true;
            Err(NetworkKernelMutationError::Helper)
        } else {
            returned.ok_or(NetworkKernelMutationError::Helper)
        }
    }
}

/// Retains the sole four-step Prepare effect recipe beside every actual helper.
pub(crate) struct NetworkPrepareEffectsOriginalV2 {
    frontiers: [NetworkSourceEffectFrontierOriginalV2; 4],
    first: Option<usize>,
    helper_failure: Option<InnerFailure>,
    entered: bool,
    activation: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    reentry: Option<NetworkKernelMutationError>,
}

impl NetworkPrepareEffectsOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            frontiers: std::array::from_fn(|_| NetworkSourceEffectFrontierOriginalV2::new()),
            first: None,
            helper_failure: None,
            entered: false,
            activation: None,
            reentry: None,
        }
    }

    /// Runs default drop, fresh activation, realization and publication once.
    ///
    /// This accepts the same authenticated mutation authorization as the sole
    /// existing recipe. Source and Root D checks precede and follow each outer
    /// frontier, while each native helper has its own separately retained pair.
    pub(super) fn execute_once(
        &mut self,
        helpers: &mut SourceHelpers<'_, '_>,
        target: &NamespaceFd,
        host: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        if self.entered {
            self.reentry
                .get_or_insert(NetworkKernelMutationError::Helper);
            return Err(NetworkKernelMutationError::Helper);
        }
        self.entered = true;
        let mutator = helpers.mutator;
        let authorization = helpers.authorization.preparation_original()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        let prepared = match helpers.outer_once(&mut self.frontiers[0], |helpers, _sample| {
            effect_recipe::Recipe::retained(mutator, helpers)
                .install_default_drop(authorization, target)
        }) {
            Ok(prepared) => prepared,
            Err(cause) => {
                self.first = Some(0);
                self.helper_failure = helpers.first;
                return Err(cause);
            }
        };
        let activation =
            match helpers.outer_once(
                &mut self.frontiers[1],
                |helpers, sample| match authorization
                    .authorize_activation(helpers.authority, &mut || Ok(sample))
                {
                    Ok(token) => {
                        self.activation = Some(Ok(()));
                        Ok(token)
                    }
                    Err(cause) => {
                        self.activation = Some(Err(cause));
                        Err(NetworkKernelMutationError::Helper)
                    }
                },
            ) {
                Ok(activation) => activation,
                Err(cause) => {
                    self.first = Some(1);
                    self.helper_failure = helpers.first;
                    return Err(cause);
                }
            };
        if let Err(cause) = helpers.outer_once(&mut self.frontiers[2], |helpers, _sample| {
            effect_recipe::Recipe::retained(mutator, helpers).realize_prepared(
                prepared,
                &activation,
                target,
                host,
                worker,
            )
        }) {
            self.first = Some(2);
            self.helper_failure = helpers.first;
            return Err(cause);
        }
        if let Err(cause) = helpers.outer_once(&mut self.frontiers[3], |helpers, _sample| {
            effect_recipe::Recipe::retained(mutator, helpers)
                .publish_prepared_namespace(authorization, target)
        }) {
            self.first = Some(3);
            self.helper_failure = helpers.first;
            return Err(cause);
        }
        if helpers.next != helpers.attempts.len()
            || helpers.inventory_pending.is_some()
            || helpers.next_artifact != helpers.artifacts.len()
        {
            self.reentry = Some(NetworkKernelMutationError::UnsupportedPlan);
            helpers.outer_closed = true;
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        }
        Ok(())
    }

    /// Enters the sole Prepare recipe through genuine Source and Root borrows.
    ///
    /// The private parent producer has prepaid this finite child programme
    /// before native issue. Its child retains the actual same-kernel notes
    /// proof and the fixed destinations through result/ACK custody. This
    /// method constructs neither a bank nor permission from a quoted vector.
    pub(crate) fn execute_with_source_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        mutator: &FixedNetworkKernelMutator,
        authority: &crate::authorization::NetworkAuthorityV1,
        authorization: &NetworkMutationAuthorizationV1,
        kernel: &aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1,
        attempts: &mut [NetworkSourceHelperOriginalV2],
        artifacts: &mut [NetworkSourceArtifactOriginalV2],
        publication: &mut NetworkNamespacePublicationOriginalV2,
        target: &NamespaceFd,
        host: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let Some(mut helpers) = SourceHelpers::for_preparation(
            source,
            mutator,
            authority,
            authorization,
            kernel,
            attempts,
            artifacts,
            publication,
        ) else {
            self.reentry
                .get_or_insert(NetworkKernelMutationError::UnsupportedPlan);
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        };
        self.execute_once(&mut helpers, target, host, worker)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.first == Some(1) {
            if let Some(Err(cause)) = self.activation.as_ref() {
                return Some(cause);
            }
        }
        self.first
            .and_then(|index| self.frontiers.get(index))
            .and_then(NetworkSourceEffectFrontierOriginalV2::failure)
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    /// Borrows the actual failed helper selected by the enclosing effect.
    ///
    /// The owning actor retains the same finite helper array beside this
    /// effect original. A helper's native or semantic refusal precedes the
    /// outer marker and any independently owed after failure.
    pub(crate) fn failure_with_helpers_v2<'held>(
        &'held self,
        helpers: &'held [NetworkSourceHelperOriginalV2],
        artifacts: &'held [NetworkSourceArtifactOriginalV2],
        publication: &'held NetworkNamespacePublicationOriginalV2,
    ) -> Option<&'held (dyn std::error::Error + 'static)> {
        let native = match self.helper_failure {
            Some(InnerFailure::Helper(index)) => helpers
                .get(index)
                .and_then(NetworkSourceHelperOriginalV2::failure),
            Some(InnerFailure::Artifact(index)) => artifacts
                .get(index)
                .and_then(NetworkSourceArtifactOriginalV2::failure),
            Some(InnerFailure::Publication) => publication.failure(),
            None => None,
        };
        native.or_else(|| self.failure())
    }
}

impl effect_recipe::HelperPort for SourceHelpers<'_, '_> {
    fn current_artifact(
        &mut self,
        artifact: &PinnedArtifact,
        current_executable: bool,
    ) -> Result<(), NetworkKernelMutationError> {
        if self.outer_closed || self.first.is_some() || self.next_artifact >= self.artifacts.len() {
            return Err(NetworkKernelMutationError::Artifact);
        }
        let role = if std::ptr::eq(artifact, &self.mutator.ip) {
            NetworkArtifactRoleV4::Ip
        } else if std::ptr::eq(artifact, &self.mutator.nft) {
            NetworkArtifactRoleV4::Nft
        } else if std::ptr::eq(artifact, &self.mutator.lease_gate_loader) {
            NetworkArtifactRoleV4::LeaseLoader
        } else if std::ptr::eq(artifact, &self.mutator.lease_gate_object) {
            NetworkArtifactRoleV4::LeaseObject
        } else if std::ptr::eq(artifact, &self.mutator.enforcement_artifact) {
            NetworkArtifactRoleV4::Enforcement
        } else {
            return Err(NetworkKernelMutationError::Artifact);
        };
        if current_executable != matches!(role, NetworkArtifactRoleV4::Enforcement) {
            return Err(NetworkKernelMutationError::Artifact);
        }
        let index = self.next_artifact;
        self.next_artifact += 1;
        let original = &mut self.artifacts[index];
        original.result = Some(original.native.validate_once_v4(
            artifact,
            role,
            current_executable,
        ));
        if matches!(original.result, Some(Ok(()))) {
            original.disposal = Some(original.native.dispose_positive_temporary_once_v4());
        }
        if matches!(original.result, Some(Ok(()))) && matches!(original.disposal, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(InnerFailure::Artifact(index));
            Err(NetworkKernelMutationError::Artifact)
        }
    }

    fn publish_namespace(
        &mut self,
        handle: [u8; 32],
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        if self.outer_closed || self.first.is_some()
            || self.authorization.preparation_original().is_none() {
            return Err(NetworkKernelMutationError::NamespacePin(
                crate::NetworkNamespacePinMutationError::Identity,
            ));
        }
        match self.publication.publish_once_v2(handle, namespace) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first.get_or_insert(InnerFailure::Publication);
                Err(cause.into())
            }
        }
    }

    fn complete_link_inventory(
        &mut self,
        result: Result<bool, NetworkKernelMutationError>,
    ) -> Result<bool, NetworkKernelMutationError> {
        let Some(index) = self.inventory_pending.take() else {
            self.outer_closed = true;
            return Err(NetworkKernelMutationError::Helper);
        };
        let original = &mut self.attempts[index];
        original.semantic = Some(result);
        let value = match original.semantic.as_ref() {
            Some(Ok(value)) => *value,
            _ => {
                original.first.get_or_insert(First::Semantic);
                self.first.get_or_insert(InnerFailure::Helper(index));
                return Err(NetworkKernelMutationError::Helper);
            }
        };
        // The exact stdout and native child stay in the original until the
        // shared decoder has parked its actual semantic result. A refusal
        // therefore retains the helper, its bytes and every reached post.
        original.disposal = Some(original.helper.dispose_positive_once_v4());
        if !matches!(original.disposal, Some(Ok(()))) {
            original.first.get_or_insert(First::Disposal);
            self.first.get_or_insert(InnerFailure::Helper(index));
            return Err(NetworkKernelMutationError::Helper);
        }
        Ok(value)
    }

    fn status(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<(), NetworkKernelMutationError> {
        let role = self.role(artifact, inherited.len(), stdin.is_some())?;
        self.execute(artifact, arguments, stdin, inherited, role, None, false)
            .map(|_| ())
    }

    fn link_inventory(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
    ) -> Result<Vec<u8>, NetworkKernelMutationError> {
        if !std::ptr::eq(artifact, &self.mutator.ip) {
            return Err(NetworkKernelMutationError::Artifact);
        }
        self.execute(
            artifact,
            arguments,
            None,
            &[],
            NetworkStatusHelperRoleV4::IpLinks,
            None,
            true,
        )?
        .ok_or(NetworkKernelMutationError::Helper)
    }

    fn nft_batch(
        &mut self,
        artifact: &PinnedArtifact,
        bytes: &[u8],
    ) -> Result<(), NetworkKernelMutationError> {
        if !std::ptr::eq(artifact, &self.mutator.nft)
            || self.authorization.preparation_original().is_none() {
            return Err(NetworkKernelMutationError::Artifact);
        }
        self.execute(
            artifact,
            &["--json".into(), "--file".into(), "-".into()],
            None,
            &[],
            NetworkStatusHelperRoleV4::NftBatch,
            Some(bytes),
            false,
        )
        .map(|_| ())
    }
}

/// Bounds the actual three-step Destroy helper recipe, including absent links.
pub(crate) fn destroy_helper_count_data_v2(plan: &NetworkKernelExpectationV1) -> Option<usize> {
    match plan.kind() {
        NetworkKind::Isolated => Some(1),
        NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
            // Lower: two inventory/set pairs. Remove: exact nft destroy,
            // loader removal, host inventory and conditional host deletion.
            Some(4usize.checked_add(4)?)
        }
        NetworkKind::Host => None,
    }
}

/// Counts before/after checks plus the real final absent-step artifact check.
pub(crate) fn destroy_artifact_count_data_v2() -> Option<usize> {
    5usize.checked_mul(2usize.checked_add(2)?.checked_add(3)?)
}

/// Retains the genuine pending signed9 steps over the same mutation recipe.
///
/// The actor alone authorizes and completes each original lifecycle step. This
/// owner holds its finite helpers, actual cloned plan and independent Source /
/// original-D posts without casting Destroy into Prepare authorization.
pub(crate) struct NetworkDestroyEffectsOriginalV2 {
    frontiers: [NetworkSourceEffectFrontierOriginalV2; 3],
    pin_frontier: NetworkSourceEffectFrontierOriginalV2,
    pin_cut: ClockOriginal,
    pin_gate: Option<Result<(), crate::worker_protocol::NetworkWorkerProtocolError>>,
    pin: crate::namespace_pin::NetworkNamespaceRemovalOriginalV2,
    pin_prepared: Option<Result<(), crate::namespace_pin::NetworkNamespacePinMutationError>>,
    pin_removed: Option<Result<(), crate::namespace_pin::NetworkNamespacePinMutationError>>,
    plans: [Option<crate::NetworkKernelPlanV1>; 3],
    publication: NetworkNamespacePublicationOriginalV2,
    next: usize,
    next_artifact: usize,
    cursor: usize,
    first: Option<usize>,
    helper_failure: Option<InnerFailure>,
    closed: Option<NetworkKernelMutationError>,
}

impl NetworkDestroyEffectsOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            frontiers: std::array::from_fn(|_| NetworkSourceEffectFrontierOriginalV2::new()),
            pin_frontier: NetworkSourceEffectFrontierOriginalV2::new(),
            pin_cut: ClockOriginal::new(),
            pin_gate: None,
            pin: crate::namespace_pin::NetworkNamespaceRemovalOriginalV2::new(),
            pin_prepared: None,
            pin_removed: None,
            plans: std::array::from_fn(|_| None),
            publication: NetworkNamespacePublicationOriginalV2::new(),
            next: 0,
            next_artifact: 0,
            cursor: 0,
            first: None,
            helper_failure: None,
            closed: None,
        }
    }

    /// Executes only the actual next pending Destroy token once.
    ///
    /// The fence slice is the parent's separately retained coordinator result
    /// delivered on the same native Source record. Every frontier delegates
    /// the existing pending-step currentness engine, including its poison on
    /// failure. The caller must complete_success only after this method passes.
    pub(crate) fn execute_step_with_source_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        mutator: &FixedNetworkKernelMutator,
        authority: &crate::authorization::NetworkAuthorityV1,
        step: &mut NetworkLifecycleAuthorizedStepV1<'_>,
        trusted_current_fence: &[u8],
        kernel: &aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1,
        attempts: &mut [NetworkSourceHelperOriginalV2],
        artifacts: &mut [NetworkSourceArtifactOriginalV2],
        target: &NamespaceFd,
        host: &NamespaceFd,
        bootstrap: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let sequence = [
            NetworkLifecycleExecutionStepV1::LowerLinks,
            NetworkLifecycleExecutionStepV1::RemoveOwnedNetworkObjects,
            NetworkLifecycleExecutionStepV1::VerifyKernelOwnedObjectsAbsent,
        ];
        if self.first.is_some()
            || self.closed.is_some()
            || sequence.get(self.cursor).copied() != Some(step.step())
            || step.action() != crate::NetworkNamespaceLifecycleActionV1::Destroy
            || trusted_current_fence.is_empty()
            || attempts.len()
                != destroy_helper_count_data_v2(step.kernel_plan().observation_expectation())
                    .ok_or(NetworkKernelMutationError::UnsupportedPlan)?
            || artifacts.len()
                != destroy_artifact_count_data_v2()
                    .ok_or(NetworkKernelMutationError::UnsupportedPlan)?
        {
            self.closed
                .get_or_insert(NetworkKernelMutationError::UnsupportedPlan);
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        }
        let index = self.cursor;
        self.cursor += 1;
        // This actual plan clone is prepaid and retained; it prevents a shared
        // immutable step borrow from masking the same step's mutable poison.
        self.plans[index] = Some(step.kernel_plan().clone());
        let plan = self.plans[index]
            .as_ref()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        let input = effect_recipe::LifecycleRecipeInputs {
            plan,
            target: step.target_namespace(),
            step: step.step(),
            desired: step.desired_state(),
            action: step.action(),
        };
        let mut current = PendingDestroyCurrent {
            step,
            trusted_current_fence,
        };
        let Some(mut helpers) = SourceHelpers::for_destroy(
            source,
            mutator,
            authority,
            &mut current,
            kernel,
            attempts,
            artifacts,
            &mut self.publication,
            self.next,
            self.next_artifact,
        ) else {
            self.closed
                .get_or_insert(NetworkKernelMutationError::UnsupportedPlan);
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        };
        let returned = helpers.outer_once(&mut self.frontiers[index], |helpers, _| {
            effect_recipe::Recipe::retained(mutator, helpers)
                .execute_lifecycle_inputs(input, target, host, bootstrap, worker)?;
            if index == 2 {
                // Read and retain the canonical exact pin under the final
                // signed-step Source bracket. The target OFD stays held for O.
                self.pin_prepared = Some(self.pin.prepare_once_v2(
                    *plan.network_handle(), target.identity(), false));
                if !matches!(self.pin_prepared, Some(Ok(()))) {
                    return Err(NetworkKernelMutationError::Helper);
                }
            }
            Ok(())
        });
        let returned = returned.and_then(|()| {
            if index != 2 { return Ok(()); }
            helpers.outer_once(&mut self.pin_frontier, |helpers, _| {
                // Source challenge/readback can consume time. Reuse the same
                // pending signed9 engine with a fresh retained Root pair AFTER
                // that challenge, immediately before the first mutation.
                let sample = self.pin_cut.capture(helpers.binding.boot);
                self.pin_gate = Some(helpers.authorization.require_current_before_helper_v2(
                    helpers.authority, &mut || sample.as_ref().copied()
                        .map_err(|_| crate::NetworkAdmissionError::FenceRejected)));
                if !matches!(self.pin_gate, Some(Ok(()))) {
                    return Err(NetworkKernelMutationError::Helper);
                }
                self.pin_removed = Some(self.pin.remove_once_v2());
                if !matches!(self.pin_removed, Some(Ok(()))) {
                    return Err(NetworkKernelMutationError::Helper);
                }
                Ok(())
            })
        });
        self.next = helpers.next;
        self.next_artifact = helpers.next_artifact;
        if returned.is_err() || helpers.inventory_pending.is_some() {
            self.first = Some(index);
            self.helper_failure = helpers.first;
            return Err(NetworkKernelMutationError::Helper);
        }
        Ok(())
    }

    pub(crate) fn completed_data_v2(&self) -> bool {
        self.cursor == 3
            && self.first.is_none()
            && self.closed.is_none()
            && matches!(self.pin_removed, Some(Ok(())))
            && self.pin.require_removed_v2().is_ok()
            && Some(self.next_artifact) == destroy_artifact_count_data_v2()
    }

    pub(crate) fn failure_with_helpers_v2<'held>(
        &'held self,
        helpers: &'held [NetworkSourceHelperOriginalV2],
        artifacts: &'held [NetworkSourceArtifactOriginalV2],
    ) -> Option<&'held (dyn std::error::Error + 'static)> {
        let native = match self.helper_failure {
            Some(InnerFailure::Helper(index)) => helpers
                .get(index)
                .and_then(NetworkSourceHelperOriginalV2::failure),
            Some(InnerFailure::Artifact(index)) => artifacts
                .get(index)
                .and_then(NetworkSourceArtifactOriginalV2::failure),
            Some(InnerFailure::Publication) => self.publication.failure(),
            None => None,
        };
        native
            .or_else(|| self.pin.failure())
            .or_else(|| self.pin_cut.failure())
            .or_else(|| self.pin_gate.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.pin_frontier.failure())
            .or_else(|| {
                self.first
                    .and_then(|index| self.frontiers.get(index))
                    .and_then(NetworkSourceEffectFrontierOriginalV2::failure)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn remaining(
    clock: &ClockOriginal,
    deadline: u64,
    expiry: i64,
) -> Result<rustix::event::Timespec, NetworkKernelMutationError> {
    let sample = clock
        .result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(NetworkKernelMutationError::Helper)?;
    let wall = clock
        .native
        .realtime_observation_data_v1()
        .ok_or(NetworkKernelMutationError::Helper)?;
    let boot = deadline
        .checked_sub(sample.boottime_nanoseconds())
        .filter(|remaining| *remaining != 0)
        .ok_or(NetworkKernelMutationError::Helper)?;
    let wall = expiry
        .checked_sub(wall.tv_sec)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|nanos| nanos.checked_sub(u64::try_from(wall.tv_nsec).ok()?))
        .filter(|remaining| *remaining != 0)
        .ok_or(NetworkKernelMutationError::Helper)?;
    let nanos = boot.min(wall);
    Ok(rustix::event::Timespec {
        tv_sec: i64::try_from(nanos / 1_000_000_000)
            .map_err(|_| NetworkKernelMutationError::Helper)?,
        tv_nsec: (nanos % 1_000_000_000) as i64,
    })
}
