//! Runs closed read recipes on the actual prepaid O Source and native helpers.

use super::*;
use crate::kernel_mutator::{NetworkKernelMutationError, NetworkStatusHelperOriginalV4};
use crate::observation_worker_runtime::read_admission_v2::{
    NetworkObserverReadCurrentOriginalV2, NetworkObserverReadLoanV2, ObserverReadClosedV2,
};
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_broker::receiving::{NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::process::FixedProcessCaptureCutV3;

#[derive(Debug, thiserror::Error)]
pub(super) enum ClockError {
    #[error("the original O read clock is stale")]
    Stale,
    #[error(transparent)]
    Kernel(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(cause)
    }
}

pub(crate) struct ReadFrontierOriginalV2 {
    before: RetainedKernelPairedClockAttemptV1<ClockError>,
    current_before: NetworkObserverReadCurrentOriginalV2,
    affinity: Option<Result<(), ObserverReadClosedV2>>,
    sample: Option<RawPairedClockSample>,
    after_sample: Option<RawPairedClockSample>,
    wait: Option<Result<rustix::event::Timespec, NetworkKernelReaderError>>,
    source: NetworkChildSourceProbeOriginalV2,
    source_result: Option<Result<(), aos_sandbox_broker::receiving::NetworkChildOriginClosedV2>>,
    after: RetainedKernelPairedClockAttemptV1<ClockError>,
    current_after: NetworkObserverReadCurrentOriginalV2,
    first: Option<u8>,
}

impl ReadFrontierOriginalV2 {
    /// Prices this same clock/public/Source engine for one actor frontier.
    /// The enclosing actor separately quotes its transport and native record.
    pub(crate) fn receiving_obligations_data_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let current = NetworkObserverReadCurrentOriginalV2::receiving_obligations_data_v2()?;
        let mut demand = current.checked_add(current).ok()?;
        demand = demand.checked_add(
            NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(1)?
        ).ok()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(
            RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?
                .checked_mul(2)?
        )?;
        let files = RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(2)?;
        let names = RetainedKernelPairedClockAttemptV1::<ClockError>::receiving_metadata_cells_v1()?
            .checked_mul(2)?;
        demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?)).ok()
    }

    /// Borrows deny-only transport ceilings after this actual frontier passed.
    /// The baseline is the retained after sample, never a fresh TTL or signer.
    pub(crate) fn native_cutoff_data_v2(
        &self,
        read: &NetworkObserverReadLoanV2<'_, '_>,
    ) -> Option<aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4> {
        if self.first.is_some() || !matches!(self.source_result, Some(Ok(()))) {
            return None;
        }
        let sample = self.after_sample?;
        let effect = read.original_effect_v2();
        Some(aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4::new(
            sample.boottime_nanoseconds(), sample.wall_seconds(),
            effect.effect_deadline_boottime_nanoseconds().min(
                read.original_local_lease_v2().fail_stop_boottime_nanoseconds()),
            Some(effect.plan_expires_seconds().min(effect.authority_expires_seconds())),
        ))
    }

    pub(crate) fn new() -> Self {
        Self {
            before: Default::default(),
            current_before: NetworkObserverReadCurrentOriginalV2::new(),
            affinity: None,
            sample: None,
            after_sample: None,
            wait: None,
            source: NetworkChildSourceProbeOriginalV2::new(),
            source_result: None,
            after: Default::default(),
            current_after: NetworkObserverReadCurrentOriginalV2::new(),
            first: None,
        }
    }

    pub(crate) fn observe(
        &mut self,
        read: &NetworkObserverReadLoanV2<'_, '_>,
        source: &mut NetworkChildSourceLoanV2<'_>,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.affinity.is_some() {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        self.affinity = Some(read.require_same_native_source_v2(source));
        if !matches!(self.affinity, Some(Ok(()))) {
            self.first = Some(0);
        }
        self.sample = self.before.observe_once(None).ok();
        if let Some(sample) = self.sample {
            if read
                .require_current_before_read_v2(sample, &mut self.current_before)
                .is_err()
            {
                self.first.get_or_insert(2);
            }
        } else {
            self.first.get_or_insert(1);
            let _ = read.observe_owed_public_after_once_v2(&mut self.current_before);
        }
        let effect = read.original_effect_v2();
        self.wait = Some(
            self.sample
                .and_then(|sample| {
                    let remaining = effect
                        .effect_deadline_boottime_nanoseconds()
                        .checked_sub(sample.boottime_nanoseconds())?;
                    if remaining == 0 {
                        return None;
                    }
                    Some(rustix::event::Timespec {
                        tv_sec: i64::try_from(remaining / 1_000_000_000).ok()?,
                        tv_nsec: i64::try_from(remaining % 1_000_000_000).ok()?,
                    })
                })
                .ok_or(NetworkKernelReaderError::HelperFailed),
        );
        if !matches!(self.wait, Some(Ok(_))) {
            self.first.get_or_insert(3);
        }
        if matches!(self.affinity, Some(Ok(()))) && source.operation_binding_data_v2().is_some() {
            let zero = rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let wait = self
                .wait
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .unwrap_or(&zero);
            self.source_result =
                Some(source.require_live_before_once_v2(&mut self.source, Some(wait)));
        } else {
            self.source_result = Some(source.observe_owed_native_after_once_v2(&mut self.source));
        }
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first.get_or_insert(4);
        }
        match self.after.observe_once(None) {
            Ok(sample) => {
                self.after_sample = Some(sample);
                if read
                    .require_current_before_read_v2(sample, &mut self.current_after)
                    .is_err()
                {
                    self.first.get_or_insert(6);
                }
            }
            Err(_) => {
                self.first.get_or_insert(5);
                let _ = read.observe_owed_public_after_once_v2(&mut self.current_after);
            }
        }
        if self.first.is_some() {
            Err(NetworkKernelReaderError::HelperFailed)
        } else {
            Ok(())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            0 => failure(&self.affinity),
            1 => self.before.failure(),
            2 => self.current_before.failure(),
            3 => failure(&self.wait),
            4 => self.source.failure(),
            5 => self.after.failure(),
            _ => self.current_after.failure(),
        }
    }
}

pub(super) struct ReadHelperOriginalV2 {
    before: ReadFrontierOriginalV2,
    arguments: Option<Result<Vec<OsString>, NetworkKernelReaderError>>,
    cut: Option<Result<FixedProcessCaptureCutV3, aos_linux_descriptors::Error>>,
    attestation_before: NetworkArtifactCurrentOriginalV4,
    attestation_after: NetworkArtifactCurrentOriginalV4,
    attestation_result: [Option<Result<(), NetworkKernelReaderError>>; 2],
    attestation_before_retirement: Option<Result<(), NetworkKernelReaderError>>,
    helper: NetworkStatusHelperOriginalV4,
    helper_result: Option<Result<(), NetworkKernelMutationError>>,
    after: ReadFrontierOriginalV2,
    disposal: Option<Result<(), NetworkKernelMutationError>>,
    first: Option<u8>,
}

impl ReadHelperOriginalV2 {
    fn new(nofile: u64, table: usize) -> Option<Self> {
        Some(Self {
            before: ReadFrontierOriginalV2::new(),
            arguments: None,
            cut: None,
            attestation_before: NetworkArtifactCurrentOriginalV4::new(),
            attestation_after: NetworkArtifactCurrentOriginalV4::new(),
            attestation_result: [None, None],
            attestation_before_retirement: None,
            helper: NetworkStatusHelperOriginalV4::new_for_programme_data_v2(nofile, table)?,
            helper_result: None,
            after: ReadFrontierOriginalV2::new(),
            disposal: None,
            first: None,
        })
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            0 => self.before.failure(),
            1 => failure(&self.arguments),
            2 => failure(&self.cut),
            3 => self
                .attestation_before
                .failure()
                .or_else(|| failure(&self.attestation_before_retirement))
                .or_else(|| failure(&self.attestation_result[0])),
            4 => self.helper.failure(),
            5 => self
                .attestation_after
                .failure()
                .or_else(|| failure(&self.attestation_result[1])),
            6 => self.after.failure(),
            7 => failure(&self.disposal),
            _ => None,
        }
    }
}

/// Owns the finite actual O programme through result/ACK/native handback.
/// Failed entered native helpers must remain here while the worker reports its
/// negative result; the existing native helper owner enforces its disposal law.
pub(crate) struct NetworkObservationReadProgrammeOriginalV2 {
    pub(super) quote: ObservationProgrammeDataV2,
    helpers: Vec<ReadHelperOriginalV2>,
    boundaries: Vec<ReadFrontierOriginalV2>,
    next_helper: usize,
    next_boundary: usize,
    group_start: usize,
    first: Option<(bool, usize)>,
    closed: NetworkKernelReaderError,
    borrowed: bool,
    borrow_failed: bool,
}

impl NetworkObservationReadProgrammeOriginalV2 {
    /// Allocates only the already-paid original roster; this grants no IO.
    pub(crate) fn new(quote: ObservationProgrammeDataV2) -> Option<Self> {
        let helpers = (0..quote.helpers)
            .map(|_| ReadHelperOriginalV2::new(quote.native_limits[1], quote.maximum_table))
            .collect::<Option<Vec<_>>>()?;
        let boundaries = (0..quote.boundaries)
            .map(|_| ReadFrontierOriginalV2::new())
            .collect();
        Some(Self {
            quote,
            helpers,
            boundaries,
            next_helper: 0,
            next_boundary: 0,
            group_start: 0,
            first: None,
            closed: NetworkKernelReaderError::HelperFailed,
            borrowed: false,
            borrow_failed: false,
        })
    }

    /// Joins the actual read, same native Source and original pinned O5 roster.
    pub(crate) fn borrow_port_v2<'scope, 'held, 'native>(
        &'scope mut self,
        read: &'scope NetworkObserverReadLoanV2<'held, 'native>,
        source: &'scope mut NetworkChildSourceLoanV2<'native>,
        readers: &'scope NetworkObservationReadersOriginalV2,
    ) -> Result<ObservationHelperPortV2<'scope, 'held, 'native>, NetworkKernelReaderError> {
        if self.borrowed || self.first.is_some() {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        self.borrowed = true;
        // Fail closed before any reached validation; success clears only this
        // provisional refusal, never an earlier helper/native cause.
        self.borrow_failed = true;
        read.require_same_native_source_v2(source)
            .map_err(|_| NetworkKernelReaderError::HelperFailed)?;
        let binding = source
            .operation_binding_data_v2()
            .ok_or(NetworkKernelReaderError::HelperFailed)?;
        if binding.purpose != 2
            || binding.native_limits != self.quote.native_limits
            || read.original_kernel_plan_v2().digest() != self.quote.plan_digest
            || read.original_effect_v2().verb() != self.quote.verb
        {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        let pinned = readers
            .readers
            .as_ref()
            .ok_or(NetworkKernelReaderError::HelperFailed)?
            .artifacts();
        self.borrow_failed = false;
        Ok(ObservationHelperPortV2::Source(
            NetworkObservationSourcePortV2 {
                original: self,
                read,
                source,
                pinned,
            },
        ))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.borrow_failed {
            return Some(&self.closed);
        }
        let (boundary, index) = self.first?;
        let cause = if boundary {
            self.boundaries
                .get(index)
                .and_then(ReadFrontierOriginalV2::failure)
        } else {
            self.helpers
                .get(index)
                .and_then(ReadHelperOriginalV2::failure)
        };
        cause.or(Some(&self.closed))
    }
}

pub(crate) struct NetworkObservationSourcePortV2<'scope, 'held, 'native> {
    original: &'scope mut NetworkObservationReadProgrammeOriginalV2,
    read: &'scope NetworkObserverReadLoanV2<'held, 'native>,
    source: &'scope mut NetworkChildSourceLoanV2<'native>,
    pinned: [&'scope PinnedArtifact; 5],
}

impl NetworkObservationSourcePortV2<'_, '_, '_> {
    pub(super) fn nft_layout_data_v2(
        &self,
        absent: bool,
    ) -> Result<ObservationJsonLayoutDataV2, NetworkKernelReaderError> {
        if absent != (self.original.quote.verb == aos_sandbox_model::BrokerVerb::NetworkDestroy) {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        Ok(self.original.quote.nft_layout)
    }

    pub(super) fn run(
        &mut self,
        artifact: &PinnedArtifact,
        attestation: Option<(&PinnedArtifact, ObservationAttestationV2)>,
        recipe: ObservationRecipeV2<'_>,
    ) -> Result<Vec<u8>, NetworkKernelReaderError> {
        if self.original.first.is_some() {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        let expected = self
            .read
            .original_kernel_plan_v2()
            .observation_expectation();
        let absent = self.original.quote.verb == aos_sandbox_model::BrokerVerb::NetworkDestroy;
        let recipe_matches = match &recipe {
            ObservationRecipeV2::NftPolicy => !absent,
            ObservationRecipeV2::NftTables => absent,
            ObservationRecipeV2::BpfGraph {
                handle,
                absent: requested_absence,
            } => handle == expected.network_handle() && *requested_absence == absent,
            ObservationRecipeV2::Links(Some(name))
            | ObservationRecipeV2::Addresses(Some(name))
            | ObservationRecipeV2::Neighbors(Some(name)) => {
                expected.veth().is_some_and(|veth| veth.host_name == *name)
            }
            _ => true,
        };
        if !recipe_matches {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        let role_index = match recipe.artifact_role() {
            NetworkArtifactRoleV4::Ip => 0,
            NetworkArtifactRoleV4::Nft => 1,
            NetworkArtifactRoleV4::BpfObserver => 3,
            _ => return Err(NetworkKernelReaderError::HelperFailed),
        };
        if !std::ptr::eq(artifact, self.pinned[role_index]) {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        if !matches!(
            (role_index, attestation.as_ref().map(|(_, role)| role)),
            (0, None)
                | (1, Some(ObservationAttestationV2::Enforcement))
                | (3, Some(ObservationAttestationV2::LeaseObject))
        ) {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        if let Some((pinned, role)) = attestation {
            let index = match role {
                ObservationAttestationV2::Enforcement => 2,
                ObservationAttestationV2::LeaseObject => 4,
            };
            if !std::ptr::eq(pinned, self.pinned[index]) {
                return Err(NetworkKernelReaderError::HelperFailed);
            }
        }
        let index = self.original.next_helper;
        let original = self
            .original
            .helpers
            .get_mut(index)
            .ok_or(NetworkKernelReaderError::HelperFailed)?;
        self.original.next_helper += 1;
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if original.before.observe(self.read, self.source).is_err() {
                original.first = Some(0);
            }
            original.arguments = Some(recipe.arguments());
            if !matches!(original.arguments, Some(Ok(_))) {
                original.first.get_or_insert(1);
            }
            let effect = self.read.original_effect_v2();
            original.cut = Some(FixedProcessCaptureCutV3::new(
                effect.effect_deadline_boottime_nanoseconds().min(
                    self.read
                        .original_local_lease_v2()
                        .fail_stop_boottime_nanoseconds(),
                ),
                effect
                    .plan_expires_seconds()
                    .min(effect.authority_expires_seconds()),
            ));
            if !matches!(original.cut, Some(Ok(_))) {
                original.first.get_or_insert(2);
            }
            if original.first.is_none() {
                if let Some((artifact, role)) = attestation {
                    original.attestation_result[0] = Some(
                        original
                            .attestation_before
                            .validate_once_v4(artifact, role.role(), false),
                    );
                    if !matches!(original.attestation_result[0], Some(Ok(()))) {
                        original.first = Some(3);
                    }
                }
            }
            if original.first.is_none() && matches!(original.attestation_result[0], Some(Ok(()))) {
                // The O5 pin and its observations stay owned. Only the completed
                // validation's temporary walk closes before the helper can fork.
                original.attestation_before_retirement = Some(
                    original
                        .attestation_before
                        .dispose_positive_temporary_once_v4(),
                );
                if !matches!(original.attestation_before_retirement, Some(Ok(()))) {
                    original.first = Some(3);
                }
            }
            if original.first.is_none() {
                if let (Some(Ok(arguments)), Some(Ok(cut))) =
                    (original.arguments.as_ref(), original.cut.as_ref())
                {
                    original.helper_result = Some(original.helper.run_once_v4(
                        artifact,
                        arguments,
                        None,
                        &[],
                        recipe.role(),
                        *cut,
                    ));
                }
                if !matches!(original.helper_result, Some(Ok(()))) {
                    original.first = Some(4);
                }
            }
        }));
        if body.is_err() {
            original.first.get_or_insert(8);
        }
        // Attestation and Source posts remain owed after the actual helper or
        // a previous input/currentness failure. No post erases the first cause.
        let attestation_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some((artifact, role)) = attestation {
                original.attestation_result[1] = Some(original.attestation_after.validate_once_v4(
                    artifact,
                    role.role(),
                    false,
                ));
                if !matches!(original.attestation_result[1], Some(Ok(()))) {
                    original.first.get_or_insert(5);
                }
            }
        }));
        if attestation_post.is_err() {
            original.first.get_or_insert(5);
        }
        let source_post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if original.after.observe(self.read, self.source).is_err() {
                original.first.get_or_insert(6);
            }
        }));
        if source_post.is_err() {
            original.first.get_or_insert(6);
        }
        if body.is_err() || attestation_post.is_err() || source_post.is_err() {
            self.original.first.get_or_insert((false, index));
        }
        // Every owed port has now run. Resume the first actual panic; an
        // earlier typed native cause remains selected on its original owner.
        for unwind in [body, attestation_post, source_post] {
            if let Err(payload) = unwind {
                std::panic::resume_unwind(payload);
            }
        }
        if original.first.is_some() {
            self.original.first.get_or_insert((false, index));
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        // The existing decoder owns this exact bounded copy while this native
        // helper remains resident until its actual semantic Result is parked.
        original
            .helper
            .completed_stdout_v4()
            .map(<[u8]>::to_vec)
            .ok_or(NetworkKernelReaderError::HelperFailed)
    }

    pub(super) fn finish_group(&mut self) -> Result<(), NetworkKernelReaderError> {
        let begin = self.original.group_start;
        let end = self.original.next_helper;
        self.original.group_start = end;
        for index in begin..end {
            let original = &mut self.original.helpers[index];
            if original.helper.completed_stdout_v4().is_some() {
                original.disposal = Some(original.helper.dispose_positive_once_v4());
                if !matches!(original.disposal, Some(Ok(()))) {
                    original.first.get_or_insert(7);
                    self.original.first.get_or_insert((false, index));
                }
            }
            if matches!(original.attestation_result[0], Some(Ok(())))
                && original.attestation_before_retirement.is_none()
            {
                original.attestation_before_retirement = Some(
                    original
                        .attestation_before
                        .dispose_positive_temporary_once_v4(),
                );
                if !matches!(original.attestation_before_retirement, Some(Ok(()))) {
                    original.first.get_or_insert(3);
                    self.original.first.get_or_insert((false, index));
                }
            }
            if matches!(original.attestation_result[1], Some(Ok(()))) {
                original.attestation_result[1] = Some(
                    original
                        .attestation_after
                        .dispose_positive_temporary_once_v4(),
                );
                if !matches!(original.attestation_result[1], Some(Ok(()))) {
                    original.first.get_or_insert(5);
                    self.original.first.get_or_insert((false, index));
                }
            }
        }
        if self.original.first.is_some() {
            Err(NetworkKernelReaderError::HelperFailed)
        } else {
            Ok(())
        }
    }

    pub(super) fn require_boundary_once(&mut self) -> Result<(), NetworkKernelReaderError> {
        let index = self.original.next_boundary;
        let original = self
            .original
            .boundaries
            .get_mut(index)
            .ok_or(NetworkKernelReaderError::HelperFailed)?;
        self.original.next_boundary += 1;
        let result = original.observe(self.read, self.source);
        if result.is_err() {
            self.original.first.get_or_insert((true, index));
        }
        if self.original.first.is_some() {
            Err(NetworkKernelReaderError::HelperFailed)
        } else {
            result
        }
    }
}

fn failure<T, E: std::error::Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}
