//! Opens the five actual O argv roles through the existing retained walker.

use super::*;
use crate::namespace_observer::NetworkKernelObservationReaders;
use crate::nftables_reader::FixedNftablesObservationReader;
use crate::observation_worker_runtime::NetworkObservationWorkerConfiguration;
use crate::rtnetlink_reader::FixedRtnetlinkObservationReader;
use aos_sandbox_broker::receiving::{NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2};

pub(super) const ROLES: [NetworkArtifactRoleV4; 5] = [
    NetworkArtifactRoleV4::Ip,
    NetworkArtifactRoleV4::Nft,
    NetworkArtifactRoleV4::Enforcement,
    NetworkArtifactRoleV4::BpfObserver,
    NetworkArtifactRoleV4::LeaseObject,
];

pub(super) struct ObservationReaderSetV2 {
    pub(super) rtnetlink: FixedRtnetlinkObservationReader,
    pub(super) nftables: FixedNftablesObservationReader,
    pub(super) bpf: FixedBpfObservationReader,
}

impl ObservationReaderSetV2 {
    pub(super) fn artifacts(&self) -> [&PinnedArtifact; 5] {
        let (nft, enforcement) = self.nftables.original_artifacts_v2();
        let (bpf, object) = self.bpf.original_artifacts_v2();
        [
            self.rtnetlink.original_ip_v2(),
            nft,
            enforcement,
            bpf,
            object,
        ]
    }

    pub(super) fn view(
        &self,
        plan: &crate::NetworkKernelPlanV1,
    ) -> NetworkKernelObservationReaders<'_> {
        let bpf = match plan.observation_expectation().kind() {
            aos_sandbox_core::model::NetworkKind::Isolated => None,
            _ => Some(&self.bpf),
        };
        NetworkKernelObservationReaders::new(&self.rtnetlink, &self.nftables, bpf)
    }
}

/// Retains the real five original files, ancestry and all reached opening causes.
pub(crate) struct NetworkObservationReadersOriginalV2 {
    entered: bool,
    before: NetworkChildSourceProbeOriginalV2,
    after: NetworkChildSourceProbeOriginalV2,
    kernel: aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1,
    kernel_result: Option<Result<(), aos_sandbox_linux::Error>>,
    originals: [NetworkArtifactOpeningOriginalV4; 5],
    opened: [Option<Result<(), NetworkKernelReaderError>>; 5],
    artifacts: [Option<PinnedArtifact>; 5],
    pub(super) readers: Option<ObservationReaderSetV2>,
    first: Option<usize>,
    closed: NetworkKernelReaderError,
}

impl NetworkObservationReadersOriginalV2 {
    pub(crate) fn for_plan_data_v2(
        &self,
        plan: &crate::NetworkKernelPlanV1,
    ) -> Option<NetworkKernelObservationReaders<'_>> {
        if self.first.is_some() {
            return None;
        }
        Some(self.readers.as_ref()?.view(plan))
    }

    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            before: NetworkChildSourceProbeOriginalV2::new(),
            after: NetworkChildSourceProbeOriginalV2::new(),
            kernel: aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1::new(),
            kernel_result: None,
            originals: std::array::from_fn(|_| NetworkArtifactOpeningOriginalV4::new()),
            opened: std::array::from_fn(|_| None),
            artifacts: std::array::from_fn(|_| None),
            readers: None,
            first: None,
            closed: NetworkKernelReaderError::HelperFailed,
        }
    }

    /// Executes only immutable bootstrap reads, before operation D arrives.
    /// Actual child bootstrap/F and the two Source-query slots are already paid.
    pub(crate) fn open_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        configuration: NetworkObservationWorkerConfiguration,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.entered || self.first.is_some() {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        self.entered = true;
        if !source
            .operation_binding_data_v2()
            .is_some_and(|binding| binding.purpose == 2)
        {
            self.first = Some(7);
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        if source
            .require_live_before_once_v2(&mut self.before, None)
            .is_err()
        {
            self.first = Some(5);
        }
        if self.first.is_none() {
            self.kernel_result = Some(self.kernel.capture_once_v1());
            if !matches!(self.kernel_result, Some(Ok(()))) {
                self.first = Some(8);
            }
        }
        let paths = [
            configuration.ip,
            configuration.nft,
            configuration.enforcement_loader,
            configuration.bpf_observer,
            configuration.lease_gate_object,
        ];
        if self.first.is_none() {
            for (index, (path, role)) in paths.into_iter().zip(ROLES).enumerate() {
                self.opened[index] = Some(self.originals[index].open_once_v4(path, role));
                if !matches!(self.opened[index], Some(Ok(()))) {
                    self.first = Some(index);
                    break;
                }
                self.opened[index] =
                    Some(self.originals[index].dispose_positive_temporary_once_v4());
                if !matches!(self.opened[index], Some(Ok(()))) {
                    self.first = Some(index);
                    break;
                }
                self.artifacts[index] = self.originals[index].take_completed_once_v4();
                if self.artifacts[index].is_none() {
                    self.first = Some(index);
                    break;
                }
            }
        }
        if source.operation_binding_data_v2().is_some() {
            if source
                .require_live_before_once_v2(&mut self.after, None)
                .is_err()
            {
                self.first.get_or_insert(6);
            }
        } else {
            let _ = source.observe_owed_native_after_once_v2(&mut self.after);
            self.first.get_or_insert(6);
        }
        if self.first.is_some() {
            return Err(NetworkKernelReaderError::HelperFailed);
        }
        let artifacts = std::mem::replace(&mut self.artifacts, std::array::from_fn(|_| None));
        match artifacts {
            [
                Some(ip),
                Some(nft),
                Some(enforcement),
                Some(bpf),
                Some(object),
            ] => {
                self.readers = Some(ObservationReaderSetV2 {
                    rtnetlink: FixedRtnetlinkObservationReader::from_original_v2(ip),
                    nftables: FixedNftablesObservationReader::from_original_v2(nft, enforcement),
                    bpf: FixedBpfObservationReader::from_original_v2(bpf, object),
                });
                Ok(())
            }
            partial => {
                self.artifacts = partial;
                self.first = Some(7);
                Err(NetworkKernelReaderError::HelperFailed)
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = match self.first? {
            index @ 0..=4 => self.originals[index].failure().or_else(|| {
                self.opened[index]
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            }),
            5 => self.before.failure(),
            6 => self.after.failure(),
            8 => self.kernel.failure(),
            _ => None,
        };
        cause.or(Some(&self.closed))
    }
}
