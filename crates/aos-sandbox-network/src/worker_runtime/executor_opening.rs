//! Preserves executor construction through the shared two-cgroup recipe.
//!
//! A real fixed Network startup funds this destination before native work. The
//! constructor receives already-held host and cgroup inputs, never descriptor
//! numbers or replacement authority. Failed inputs and probes stay resident.

use super::*;
use crate::namespace_store::acquisition_clock::NetworkStartupAcquisitionClockV4;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4, FixedServiceReceivingCaptureV1,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::CgroupChildOriginalV2;
use aos_sandbox_linux::pidfd::CurrentNetworkNamespaceOriginalV4;

pub(super) const NETWORK_RECEIVING_AGGREGATE_CGROUP: &str =
    crate::worker_process::cgroup_recipe::WorkerCgroupPlacementV4::Receiving.parent();

use aos_sandbox_linux::seqpacket::descriptor_subject::NetworkWorkerConnectionKindV4;

#[derive(Clone, Copy)]
enum OpeningPurposeV4 {
    Preparation,
    Observation,
}

impl OpeningPurposeV4 {
    fn socket(self) -> &'static Path {
        match self {
            Self::Preparation => NetworkWorkerConnectionKindV4::Preparation.path_v4(),
            Self::Observation => NetworkWorkerConnectionKindV4::Observation.path_v4(),
        }
    }
    fn unsafe_path_reason(self) -> &'static str {
        match self {
            Self::Preparation => "unsafe Network worker socket path",
            Self::Observation => "unsafe Network observation-worker socket path",
        }
    }
}

/// Carries only the same positively completed constructor's owning inputs.
/// No bare descriptors or selected path can construct this private completion.
pub(crate) struct CompletedObservationOpeningV4 {
    manager: RetainedCgroupAnchor,
    parent: RetainedCgroupAnchor,
    host: NamespaceFd,
    path: PathBuf,
    fixed: bool,
}

impl CompletedObservationOpeningV4 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PathBuf,
        RetainedCgroupAnchor,
        RetainedCgroupAnchor,
        NamespaceFd,
        bool,
    ) {
        (self.path, self.manager, self.parent, self.host, self.fixed)
    }
}

/// Retains a refused fixed executor construction and its exact native cause.
#[derive(thiserror::Error)]
#[error("Network preparation executor construction is incomplete or refused")]
pub struct NetworkPrepareExecutorOpeningRefusalV4 {
    extra_inputs: Option<(CgroupV2Root, NamespaceFd)>,
}

impl std::fmt::Debug for NetworkPrepareExecutorOpeningRefusalV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkPrepareExecutorOpeningRefusalV4")
            .field("extra_inputs_retained", &self.extra_inputs.is_some())
            .finish()
    }
}

fn refusal() -> NetworkPrepareExecutorOpeningRefusalV4 {
    NetworkPrepareExecutorOpeningRefusalV4 { extra_inputs: None }
}

trait OpeningNative {
    fn validate_host(&mut self, host: &NamespaceFd) -> Result<(), NetworkWorkerRuntimeError>;
    fn resolve(
        &mut self,
        root: &CgroupV2Root,
        path: &Path,
        index: usize,
    ) -> Result<(), NetworkWorkerRuntimeError>;
}

struct LocalOpening {
    resolved: [Option<RetainedCgroupAnchor>; 2],
}

impl OpeningNative for LocalOpening {
    fn validate_host(&mut self, host: &NamespaceFd) -> Result<(), NetworkWorkerRuntimeError> {
        Ok(host.validate_current_network()?)
    }

    fn resolve(
        &mut self,
        root: &CgroupV2Root,
        path: &Path,
        index: usize,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        self.resolved[index] = Some(root.resolve(path)?);
        Ok(())
    }
}

fn prepare_engine(
    path: &Path,
    root: &CgroupV2Root,
    host: &NamespaceFd,
    native: &mut impl OpeningNative,
    purpose: OpeningPurposeV4,
    worker_parent: &Path,
) -> Result<(), NetworkWorkerRuntimeError> {
    if !normalized_absolute_path(path) {
        return Err(NetworkWorkerRuntimeError::Protocol(
            purpose.unsafe_path_reason(),
        ));
    }
    native.validate_host(host)?;
    native.resolve(root, Path::new(SYSTEMD_MANAGER_CGROUP), 0)?;
    native.resolve(root, worker_parent, 1)
}

pub(crate) fn prepare_observation_local(
    path: PathBuf,
    root: CgroupV2Root,
    host: NamespaceFd,
) -> Result<crate::SystemdNetworkObservationExecutor, crate::NetworkObservationWorkerError> {
    let mut native = LocalOpening {
        resolved: [None, None],
    };
    prepare_engine(
        &path,
        &root,
        &host,
        &mut native,
        OpeningPurposeV4::Observation,
        Path::new(CONTROL_SLICE_CGROUP),
    )
    .map_err(|error| match error {
        NetworkWorkerRuntimeError::Linux(error) => {
            crate::NetworkObservationWorkerError::Linux(error)
        }
        NetworkWorkerRuntimeError::Protocol(reason) => {
            crate::NetworkObservationWorkerError::Protocol(reason)
        }
        error => crate::NetworkObservationWorkerError::Runtime(error),
    })?;
    let Some(manager) = native.resolved[0].take() else {
        std::process::abort()
    };
    let Some(parent) = native.resolved[1].take() else {
        std::process::abort()
    };
    Ok(
        crate::SystemdNetworkObservationExecutor::from_completed_opening_v4(
            CompletedObservationOpeningV4 {
                manager,
                parent,
                host,
                path,
                fixed: false,
            },
        ),
    )
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Funding,
    Native,
    Recipe,
    ClockBefore,
    ClockAfter,
    Closed,
}

/// Owns the real fixed Network executor constructor and all failed prefixes.
///
/// Construction grants no dispatch or request permission. The same actual
/// startup original and independently owed outer native after remain required.
#[must_use = "retain the constructor through the enclosing startup posts"]
pub struct NetworkPrepareExecutorOpeningOriginalV4 {
    purpose: OpeningPurposeV4,
    root: Option<CgroupV2Root>,
    host: Option<NamespaceFd>,
    children: [CgroupChildOriginalV2; 2],
    resolved: [Option<RetainedCgroupAnchor>; 2],
    host_validation: CurrentNetworkNamespaceOriginalV4,
    clock: NetworkStartupAcquisitionClockV4,
    clock_before:
        Option<Result<(), crate::namespace_store::acquisition_clock::NetworkStartupClockRefusalV4>>,
    clock_after:
        Option<Result<(), crate::namespace_store::acquisition_clock::NetworkStartupClockRefusalV4>>,
    shape: Option<Result<ResourceVector, AccountingError>>,
    entry: Option<Result<(), FixedServiceOperationClosedV4>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    returned: Option<Result<(), NetworkWorkerRuntimeError>>,
    first: Option<First>,
    taken: bool,
    closed: Option<NetworkPrepareExecutorOpeningRefusalV4>,
}

impl NetworkPrepareExecutorOpeningOriginalV4 {
    /// Creates inert destinations without allocating or observing native state.
    #[must_use]
    pub fn new() -> Self {
        Self::new_for_v4(OpeningPurposeV4::Preparation)
    }

    fn new_for_v4(purpose: OpeningPurposeV4) -> Self {
        Self {
            purpose,
            root: None,
            host: None,
            children: std::array::from_fn(|_| CgroupChildOriginalV2::new()),
            resolved: [None, None],
            host_validation: CurrentNetworkNamespaceOriginalV4::new(),
            clock: NetworkStartupAcquisitionClockV4::new(),
            clock_before: None,
            clock_after: None,
            shape: None,
            entry: None,
            funding: None,
            returned: None,
            first: None,
            taken: false,
            closed: None,
        }
    }

    /// Returns complete constructor storage and real cgroup name/FD liabilities.
    ///
    /// Already-held root and host inputs are supplied by the genuine startup;
    /// their original acquisition is separately owed and never inferred here.
    #[must_use]
    pub fn receiving_demand_v4() -> Option<ResourceVector> {
        Self::receiving_demand_for_v4(OpeningPurposeV4::Preparation)
    }

    fn receiving_demand_for_v4(purpose: OpeningPurposeV4) -> Option<ResourceVector> {
        let owner_bytes = match purpose {
            OpeningPurposeV4::Preparation => std::mem::size_of::<Self>(),
            OpeningPurposeV4::Observation => {
                std::mem::size_of::<NetworkObservationExecutorOpeningOriginalV4>()
            }
        };
        let mut bytes = owner_bytes
            .checked_mul(2)?
            .checked_add(purpose.socket().as_os_str().len())?;
        let (native_memory, mut files, mut names) =
            CurrentNetworkNamespaceOriginalV4::receiving_obligations_v4()?;
        bytes = bytes.checked_add(native_memory)?;
        for path in [SYSTEMD_MANAGER_CGROUP, NETWORK_RECEIVING_AGGREGATE_CGROUP] {
            let (memory, native, entries) =
                CgroupChildOriginalV2::receiving_obligations_v2(path.len())?;
            bytes = bytes.checked_add(memory)?;
            files = files.checked_add(native)?;
            names = names.checked_add(entries)?
                .checked_add(Path::new(path).components().count().checked_sub(1)?)?;
        }
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?)
            .checked_add(NetworkStartupAcquisitionClockV4::receiving_demand_v4()?)
            .ok()
    }

    /// Enters the fixed constructor under the actual same Network startup F.
    ///
    /// The caller funds this owner's compiled header before construction, and
    /// includes this complete contribution in its cumulative startup invoice.
    /// Inputs are parked before either intrinsic guard can fail.
    ///
    /// # Errors
    /// Retains the actual startup, accounting, namespace or cgroup refusal.
    /// Refuses repeated entry without replacing an earlier native prefix.
    pub fn prepare_once_v4(
        &mut self,
        root: CgroupV2Root,
        host: NamespaceFd,
        startup: &mut FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    ) -> Result<(), NetworkPrepareExecutorOpeningRefusalV4> {
        if self.root.is_some() || self.returned.is_some() || self.taken {
            self.first.get_or_insert(First::Closed);
            self.closed.get_or_insert_with(refusal);
            return Err(NetworkPrepareExecutorOpeningRefusalV4 {
                extra_inputs: Some((root, host)),
            });
        }
        self.root = Some(root);
        self.host = Some(host);
        self.entry = Some(startup.require_network_startup_current_v4());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(refusal());
        }
        self.shape = Some(Self::receiving_demand_for_v4(self.purpose).ok_or(
            AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            },
        ));
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(First::Funding);
            return Err(refusal());
        };
        self.funding = Some(startup.require_additional_startup_representation_v4(*shape));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(refusal());
        }

        self.clock_before = Some(self.clock.begin_once_v4().map(|_| ()));
        if matches!(self.clock_before, Some(Ok(()))) {
            self.returned = Some(self.prepare_native());
            if !matches!(self.returned, Some(Ok(()))) {
                self.first.get_or_insert(First::Recipe);
            }
        } else {
            self.first.get_or_insert(First::ClockBefore);
        }
        // This original was prepaid independently of the native body outcome.
        self.clock_after = Some(self.clock.finish_once_v4());
        if !matches!(self.clock_after, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockAfter);
        }
        if self.first.is_some() {
            Err(refusal())
        } else {
            Ok(())
        }
    }

    fn prepare_native(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        // Move input fields out only into this same owner-backed local interval;
        // restore them before any Result escapes, including every failure.
        let Some(root) = self.root.take() else {
            std::process::abort()
        };
        let Some(host) = self.host.take() else {
            std::process::abort()
        };
        let purpose = self.purpose;
        // Only this genuine fixed-startup branch selects the compiled aggregate.
        // The parent worker later rejoins this exact native anchor to Common's
        // independently held same-F aggregate before socket activation.
        let result = prepare_engine(
            purpose.socket(), &root, &host, self, purpose,
            Path::new(NETWORK_RECEIVING_AGGREGATE_CGROUP),
        );
        self.root = Some(root);
        self.host = Some(host);
        result
    }

    /// Moves the same complete executor once while constructor probes stay held.
    #[must_use]
    pub fn take_completed_once_v4(&mut self) -> Option<SystemdNetworkPrepareExecutor> {
        if !matches!(self.purpose, OpeningPurposeV4::Preparation)
            || self.taken
            || self.first.is_some()
            || !matches!(self.returned, Some(Ok(())))
        {
            return None;
        }
        let manager = self.resolved[0].take()?;
        let worker = self.resolved[1].take()?;
        let host = self.host.take()?;
        self.taken = true;
        Some(SystemdNetworkPrepareExecutor {
            socket_path: NetworkWorkerConnectionKindV4::Preparation.path_v4().to_owned(),
            systemd_manager_cgroup: manager,
            worker_parent_cgroup: worker,
            host_namespace: host,
            fail_stopped: false,
            origin: ExecutorOriginV4::FixedService,
        })
    }

    /// Identifies only a failed actual same-F entry or startup debit as source-owned.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        match self.first {
            Some(First::Entry) => matches!(self.entry, Some(Err(_))),
            Some(First::Funding) => matches!(self.funding, Some(Err(_))),
            _ => false,
        }
    }

    /// Borrows the original first cause without another observation or clone.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self
                .shape
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.funding
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::ClockBefore | First::ClockAfter => self.clock.failure(),
            First::Native => self
                .host_validation
                .failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    self.children
                        .iter()
                        .find_map(|child| child.failure())
                        .map(|cause| cause as _)
                }),
            First::Recipe => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

impl OpeningNative for NetworkPrepareExecutorOpeningOriginalV4 {
    fn validate_host(&mut self, host: &NamespaceFd) -> Result<(), NetworkWorkerRuntimeError> {
        if self.host_validation.validate_once_v4(host).is_ok() {
            Ok(())
        } else {
            self.first = Some(First::Native);
            Err(NetworkWorkerRuntimeError::Protocol(
                "original host namespace refusal retained",
            ))
        }
    }

    fn resolve(
        &mut self,
        root: &CgroupV2Root,
        path: &Path,
        index: usize,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        self.children[index].resolve_once(root, path).map_err(|_| {
            self.first = Some(First::Native);
            NetworkWorkerRuntimeError::Protocol("original executor cgroup refusal retained")
        })?;
        self.resolved[index] = self.children[index].take_completed_once();
        if self.resolved[index].is_some() {
            Ok(())
        } else {
            Err(NetworkWorkerRuntimeError::Protocol(
                "executor cgroup result is absent",
            ))
        }
    }
}

/// Retains the fixed fresh observation constructor on the same startup engine.
///
/// This opaque owner uses the same real two-cgroup/host-namespace/clock recipe
/// as preparation. It never takes a supplied socket path or inherited-tail DTO.
#[must_use = "retain the original through the enclosing startup after"]
pub struct NetworkObservationExecutorOpeningOriginalV4 {
    original: NetworkPrepareExecutorOpeningOriginalV4,
}

impl NetworkObservationExecutorOpeningOriginalV4 {
    /// Creates inert native destinations without IO or resource adoption.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: NetworkPrepareExecutorOpeningOriginalV4::new_for_v4(
                OpeningPurposeV4::Observation,
            ),
        }
    }

    /// Prices the actual shared constructor and fixed observation path.
    #[must_use]
    pub fn receiving_demand_v4() -> Option<ResourceVector> {
        NetworkPrepareExecutorOpeningOriginalV4::receiving_demand_for_v4(
            OpeningPurposeV4::Observation,
        )
    }

    /// Enters the same real Network startup once, parking input originals first.
    ///
    /// # Errors
    /// Retains the exact intrinsic F, namespace, cgroup or acquisition cause.
    /// Reentry returns an owning refusal retaining newly supplied input owners.
    pub fn prepare_once_v4(
        &mut self,
        root: CgroupV2Root,
        host: NamespaceFd,
        startup: &mut FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    ) -> Result<(), NetworkPrepareExecutorOpeningRefusalV4> {
        self.original.prepare_once_v4(root, host, startup)
    }

    /// Moves only the same positively completed observation executor once.
    #[must_use]
    pub fn take_completed_once_v4(&mut self) -> Option<crate::SystemdNetworkObservationExecutor> {
        let original = &mut self.original;
        if original.taken || original.first.is_some() || !matches!(original.returned, Some(Ok(())))
        {
            return None;
        }
        let manager = original.resolved[0].take()?;
        let parent = original.resolved[1].take()?;
        let host = original.host.take()?;
        original.taken = true;
        Some(
            crate::SystemdNetworkObservationExecutor::from_completed_opening_v4(
                CompletedObservationOpeningV4 {
                    manager,
                    parent,
                    host,
                    path: NetworkWorkerConnectionKindV4::Observation.path_v4().to_owned(),
                    fixed: true,
                },
            ),
        )
    }

    /// Identifies only a failed actual startup debit as belonging to Common.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        self.original.original_failure_selected_v4()
    }

    /// Borrows the same constructor's chronological typed native or F cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}
