//! Shares fixed helper submission, status and independent artifact posts.
//!
//! Ordinary callers keep their immediate native boundary. The selected child
//! retains real argv/spawn/stream/status prefixes on the already-paid child
//! original. This destination creates no worker, containment or execution grant.

use super::*;
use crate::kernel_reader::{NetworkArtifactCurrentOriginalV4, NetworkArtifactRoleV4};
use aos_sandbox_linux::process::{
    FixedProcessCaptureCutV3, FixedProcessRunOriginalV3, NetworkWorkerForkObservationV4,
    run_fixed_descriptor_process_observing_network_fork_retaining_v4,
};
use aos_sandbox_linux::process::{FixedProcessOutput, FixedProcessRunRefusalV3};
use std::os::fd::OwnedFd;

use crate::kernel_reader::helper_recipe::{
    FixedHelperNativeV4 as StatusNativeV4, run_fixed_helper_recipe_v4 as run_status_recipe_v4,
};

fn require_arguments(arguments: &[OsString]) -> Result<(), NetworkKernelMutationError> {
    let bytes = arguments
        .iter()
        .try_fold(0usize, |total, argument| total.checked_add(argument.len()))
        .ok_or(NetworkKernelMutationError::Helper)?;
    if arguments.len() > MAXIMUM_ARGUMENTS || bytes > MAXIMUM_ARGUMENT_BYTES {
        return Err(NetworkKernelMutationError::Helper);
    }
    Ok(())
}

fn successful_status(outcome: &FixedProcessOutcome) -> Result<(), NetworkKernelMutationError> {
    match outcome {
        FixedProcessOutcome::Completed(output)
            if output.exit_code == Some(0) && output.signal.is_none() =>
        {
            Ok(())
        }
        FixedProcessOutcome::Completed(_)
        | FixedProcessOutcome::TimedOut
        | FixedProcessOutcome::OutputLimitExceeded => Err(NetworkKernelMutationError::Helper),
    }
}

pub(super) fn run_status_local_v4(
    artifact: &PinnedArtifact,
    arguments: &[OsString],
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
) -> Result<(), NetworkKernelMutationError> {
    require_arguments(arguments)?;
    let mut native = LocalStatusV4 {
        artifact,
        arguments,
        stdin,
        inherited,
        outcome: None,
    };
    run_status_recipe_v4(&mut native)
}

struct LocalStatusV4<'held, 'fd> {
    artifact: &'held PinnedArtifact,
    arguments: &'held [OsString],
    stdin: Option<BorrowedFd<'fd>>,
    inherited: &'held [BorrowedFd<'fd>],
    outcome: Option<FixedProcessOutcome>,
}

impl StatusNativeV4 for LocalStatusV4<'_, '_> {
    type Error = NetworkKernelMutationError;

    fn before(&mut self) -> Result<(), NetworkKernelMutationError> {
        Ok(self.artifact.validate_current()?)
    }

    fn run(&mut self) -> Result<(), NetworkKernelMutationError> {
        self.outcome = Some(run_fixed_process_with_descriptors(
            FixedProcessDescriptorRequest {
                process: FixedProcessRequest {
                    executable: self.artifact.path(),
                    arguments: self.arguments,
                    timeout: HELPER_TIMEOUT,
                    maximum_stdout_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
                    maximum_stderr_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
                },
                stdin: self.stdin,
                inherited: self.inherited,
            },
        )?);
        Ok(())
    }

    fn status(&mut self) -> Result<(), NetworkKernelMutationError> {
        successful_status(
            self.outcome
                .as_ref()
                .ok_or(NetworkKernelMutationError::Helper)?,
        )
    }

    fn after(&mut self) -> Result<(), NetworkKernelMutationError> {
        Ok(self.artifact.validate_current()?)
    }

    fn independent_after(&self) -> bool {
        false
    }
}

/// Names the existing closed mutation and observation helper descriptor recipes.
#[derive(Clone, Copy)]
pub(crate) enum NetworkStatusHelperRoleV4 {
    Ip,
    IpWithHostNamespace,
    NftBatch,
    NftDestroy,
    LeaseLoader,
    IpLinks,
    IpAddresses,
    IpNeighbors,
    IpRoutes,
    IpRules,
    NftPolicy,
    BpfGraph,
}

impl NetworkStatusHelperRoleV4 {
    pub(crate) fn artifact(self) -> NetworkArtifactRoleV4 {
        match self {
            Self::Ip
            | Self::IpWithHostNamespace
            | Self::IpLinks
            | Self::IpAddresses
            | Self::IpNeighbors
            | Self::IpRoutes
            | Self::IpRules => NetworkArtifactRoleV4::Ip,
            Self::NftBatch | Self::NftDestroy | Self::NftPolicy => NetworkArtifactRoleV4::Nft,
            Self::LeaseLoader => NetworkArtifactRoleV4::LeaseLoader,
            Self::BpfGraph => NetworkArtifactRoleV4::BpfObserver,
        }
    }

    pub(crate) fn maximum_stdout_bytes_v4(self) -> usize {
        match self {
            Self::Ip | Self::IpWithHostNamespace | Self::NftBatch | Self::NftDestroy | Self::LeaseLoader => {
                MAXIMUM_HELPER_OUTPUT_BYTES
            }
            Self::IpLinks => crate::rtnetlink_reader::MAXIMUM_LINK_BYTES,
            Self::IpAddresses => crate::rtnetlink_reader::MAXIMUM_ADDRESS_BYTES,
            Self::IpNeighbors => crate::rtnetlink_reader::MAXIMUM_NEIGHBOR_BYTES,
            Self::IpRoutes => crate::rtnetlink_reader::MAXIMUM_ROUTE_BYTES,
            Self::IpRules => crate::rtnetlink_reader::MAXIMUM_RULE_BYTES,
            Self::NftPolicy => crate::nftables_reader::MAXIMUM_NFTABLES_OBSERVATION_BYTES,
            Self::BpfGraph => crate::kernel_reader::MAXIMUM_BPF_OBSERVATION_BYTES,
        }
    }

    fn require_descriptors(
        self,
        stdin: bool,
        inherited: usize,
    ) -> Result<(), NetworkKernelMutationError> {
        let matched = match self {
            Self::Ip
            | Self::NftDestroy
            | Self::IpLinks
            | Self::IpAddresses
            | Self::IpNeighbors
            | Self::IpRoutes
            | Self::IpRules
            | Self::NftPolicy
            | Self::BpfGraph => !stdin && inherited == 0,
            Self::IpWithHostNamespace => !stdin && inherited == 1,
            Self::NftBatch => stdin && inherited == 0,
            Self::LeaseLoader => !stdin && inherited <= 1,
        };
        if matched {
            Ok(())
        } else {
            Err(NetworkKernelMutationError::Helper)
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Before,
    BeforeDisposal,
    Process,
    Status,
    After,
    OutputDisposition,
    Disposition,
    AfterDisposal,
    Body,
    Closed,
}

/// Retains one helper's actual native prefix and whole typed failed outcome.
///
/// The enclosing child keeps its input artifact/stdin/namespace owners and
/// finances this complete attempt before entry. Failure cannot be discarded
/// through Rust return/unwind before its diagnostic/cleanup disposition.
pub(crate) struct NetworkStatusHelperOriginalV4 {
    before: NetworkArtifactCurrentOriginalV4,
    before_disposal: Option<Result<(), NetworkKernelReaderError>>,
    process: FixedProcessRunOriginalV3,
    fork: NetworkWorkerForkObservationV4,
    status: Option<Result<(), NetworkKernelMutationError>>,
    after: NetworkArtifactCurrentOriginalV4,
    output: Option<Result<FixedProcessOutput, FixedProcessRunRefusalV3>>,
    disposition: Option<Result<(), FixedProcessRunRefusalV3>>,
    after_disposal: Option<Result<(), NetworkKernelReaderError>>,
    returned: Option<Result<(), NetworkKernelMutationError>>,
    closed: Option<NetworkKernelMutationError>,
    first: Option<First>,
    entered: bool,
    disposed: bool,
}

impl NetworkStatusHelperOriginalV4 {
    pub(crate) fn maximum_clone_arguments_data_v2() -> Option<usize> {
        MAXIMUM_ARGUMENTS.checked_add(1)
    }

    pub(crate) fn new() -> Self {
        Self::with_fork(NetworkWorkerForkObservationV4::new())
    }

    pub(crate) fn new_for_programme_data_v2(native_nofile: u64, maximum_table: usize) -> Option<Self> {
        Some(Self::with_fork(NetworkWorkerForkObservationV4::new_for_programme_data_v2(
            native_nofile, maximum_table)?))
    }

    fn with_fork(fork: NetworkWorkerForkObservationV4) -> Self {
        Self {
            before: NetworkArtifactCurrentOriginalV4::new(),
            before_disposal: None,
            process: FixedProcessRunOriginalV3::new(),
            fork,
            status: None,
            after: NetworkArtifactCurrentOriginalV4::new(),
            output: None,
            disposition: None,
            after_disposal: None,
            returned: None,
            closed: None,
            first: None,
            entered: false,
            disposed: false,
        }
    }

    /// Bounds a positive helper retained until its group's semantic Result.
    ///
    /// Current-before and spawn setup have already retired positively. The
    /// original process keeps its PIDFD and both output readers; the exact
    /// artifact-current after walk remains on this same helper until disposal.
    /// Neither the result nor positive native disposal refunds any debt.
    pub(crate) fn positive_pending_semantic_files_data_v2(
        role: NetworkStatusHelperRoleV4,
    ) -> Option<usize> {
        let (_, after_files, _) =
            NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(role.artifact(), false)?;
        FixedProcessRunOriginalV3::completed_pending_disposal_files_data_v3()
            .checked_add(after_files)
    }

    /// Bounds this actual helper's owned representation, before any IO.
    ///
    /// Native fork/table FD peak, containment and libc internals belong to the enclosing
    /// compiled child source. This Memory-only term supplies no capacity/grant.
    pub(crate) fn receiving_bytes_v4(role: NetworkStatusHelperRoleV4) -> Option<usize> {
        Self::receiving_bytes_with_fork(role, NetworkWorkerForkObservationV4::requested_bytes_v4()?)
    }

    pub(crate) fn receiving_programme_bytes_data_v2(role: NetworkStatusHelperRoleV4,
        native_nofile: u64, maximum_table: usize) -> Option<usize>
    {
        Self::receiving_bytes_with_fork(role,
            NetworkWorkerForkObservationV4::requested_programme_bytes_data_v2(native_nofile, maximum_table)?)
    }

    fn receiving_bytes_with_fork(role: NetworkStatusHelperRoleV4, fork_bytes: usize) -> Option<usize> {
        let (current_bytes, _, _) =
            NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(role.artifact(), false)?;
        let current_inline =
            std::mem::size_of::<NetworkArtifactCurrentOriginalV4>().checked_mul(2)?;
        let process_inline = std::mem::size_of::<FixedProcessRunOriginalV3>().checked_mul(2)?;
        let process_bytes = FixedProcessRunOriginalV3::representation_from_lengths_v3(
            4096,
            MAXIMUM_ARGUMENTS,
            MAXIMUM_ARGUMENT_BYTES.checked_add(MAXIMUM_ARGUMENTS)?,
            role.maximum_stdout_bytes_v4(),
            MAXIMUM_HELPER_OUTPUT_BYTES,
        )?;
        // The same actual stdin and at most one inherited namespace recipe is
        // promoted by the runner; one borrowed table and owning Vec coexist.
        let descriptors = std::mem::size_of::<OwnedFd>()
            .checked_add(std::mem::size_of::<BorrowedFd<'static>>())?
            .checked_mul(2)?;
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(current_bytes.checked_sub(current_inline)?.checked_mul(2)?)?
            .checked_add(process_bytes.checked_sub(process_inline)?)?
            .checked_add(descriptors)?
            .checked_add(
                fork_bytes
                    .checked_sub(2 * std::mem::size_of::<NetworkWorkerForkObservationV4>())?,
            )
    }

    /// Enters the same status recipe with the original nonrenewed absolute cut.
    ///
    /// # Errors
    /// Retains wrong-role/argv refusals, full process outcome/native prefix and
    /// every independent after. The first actual cause remains selected.
    pub(crate) fn run_once_v4(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
        role: NetworkStatusHelperRoleV4,
        cut: FixedProcessCaptureCutV3,
    ) -> Result<(), NetworkKernelMutationError> {
        if self.entered || self.closed.is_some() || self.disposed {
            self.closed
                .get_or_insert(NetworkKernelMutationError::Helper);
            self.first.get_or_insert(First::Closed);
            return Err(NetworkKernelMutationError::Helper);
        }
        self.entered = true;
        let returned = (|| {
            require_arguments(arguments)?;
            role.require_descriptors(stdin.is_some(), inherited.len())?;
            let mut native = RetainedStatusV4 {
                owner: self,
                artifact,
                arguments,
                stdin,
                inherited,
                role,
                cut,
            };
            run_status_recipe_v4(&mut native)
        })();
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Body);
            Err(NetworkKernelMutationError::Helper)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before => self.before.failure(),
            First::BeforeDisposal => self
                .before_disposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Process => self.process.failure().map(|cause| {
                self.fork
                    .failure_for_returned_v4(cause)
                    .unwrap_or(cause as _)
            }),
            First::Status => self.status.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::After => self.after.failure(),
            First::OutputDisposition => {
                self.output.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            First::AfterDisposal => self
                .after_disposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Disposition => self
                .disposition
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Body => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    /// Borrows the actual completed/failed process status and output buffers.
    pub(crate) fn native_outcome_v4(&self) -> Option<&FixedProcessOutcome> {
        self.process.outcome()
    }

    /// Borrows the actual successful stdout before any native output disposal.
    ///
    /// The enclosing reader retains its semantic parse/model Result before
    /// requesting disposal. Negative native/status/posts never expose a
    /// successful snapshot through this borrower.
    pub(crate) fn completed_stdout_v4(&self) -> Option<&[u8]> {
        if self.first.is_some() || self.disposed || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        match self.process.outcome()? {
            FixedProcessOutcome::Completed(output)
                if output.exit_code == Some(0) && output.signal.is_none() =>
            {
                Some(&output.stdout)
            }
            _ => None,
        }
    }

    /// Physically closes only a fully completed positive helper interval.
    ///
    /// Every negative process status/output or owed-post failure stays resident.
    /// No resource debt, Native source bound or operation counter is refunded.
    ///
    /// # Errors
    /// Refuses any prior failure, incomplete process/streams or repeated entry.
    pub(crate) fn dispose_positive_once_v4(&mut self) -> Result<(), NetworkKernelMutationError> {
        if self.disposed
            || self.closed.is_some()
            || self.first.is_some()
            || !matches!(self.returned, Some(Ok(())))
        {
            return Err(NetworkKernelMutationError::Helper);
        }
        // Status-only commands consume no successful output after this point.
        // Move the actual bytes before releasing the exact completed runner.
        self.output = Some(self.process.take_completed_output_v3());
        if !matches!(self.output, Some(Ok(_))) {
            self.first.get_or_insert(First::OutputDisposition);
            return Err(NetworkKernelMutationError::Helper);
        }
        self.disposition = Some(self.process.dispose_after_completed_posts_v3());
        if !matches!(self.disposition, Some(Ok(()))) {
            self.first.get_or_insert(First::Disposition);
            return Err(NetworkKernelMutationError::Helper);
        }
        self.after_disposal = Some(self.after.dispose_positive_temporary_once_v4());
        if !matches!(self.after_disposal, Some(Ok(()))) {
            self.first.get_or_insert(First::AfterDisposal);
            return Err(NetworkKernelMutationError::Helper);
        }
        drop(self.output.take());
        self.disposed = true;
        Ok(())
    }
}

impl Drop for NetworkStatusHelperOriginalV4 {
    fn drop(&mut self) {
        // A child-scope failure handback must happen while all original fields
        // are still owned. Parent death/empty proof supplies the later closure.
        if self.entered && !self.disposed {
            std::process::abort();
        }
    }
}

struct RetainedStatusV4<'held, 'fd> {
    owner: &'held mut NetworkStatusHelperOriginalV4,
    artifact: &'held PinnedArtifact,
    arguments: &'held [OsString],
    stdin: Option<BorrowedFd<'fd>>,
    inherited: &'held [BorrowedFd<'fd>],
    role: NetworkStatusHelperRoleV4,
    cut: FixedProcessCaptureCutV3,
}

impl StatusNativeV4 for RetainedStatusV4<'_, '_> {
    type Error = NetworkKernelMutationError;

    fn before(&mut self) -> Result<(), NetworkKernelMutationError> {
        if self
            .owner
            .before
            .validate_once_v4(self.artifact, self.role.artifact(), false)
            .is_err()
        {
            self.owner.first.get_or_insert(First::Before);
            return Err(NetworkKernelMutationError::Helper);
        }
        // The full before conjunction is complete, and no later post reads
        // its temporary path descriptors. Keep actual artifact input pins.
        self.owner.before_disposal = Some(self.owner.before.dispose_positive_temporary_once_v4());
        if !matches!(self.owner.before_disposal, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::BeforeDisposal);
            return Err(NetworkKernelMutationError::Helper);
        }
        Ok(())
    }

    fn run(&mut self) -> Result<(), NetworkKernelMutationError> {
        let request = FixedProcessDescriptorRequest {
            process: FixedProcessRequest {
                executable: self.artifact.path(),
                arguments: self.arguments,
                timeout: HELPER_TIMEOUT,
                maximum_stdout_bytes: self.role.maximum_stdout_bytes_v4(),
                maximum_stderr_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
            },
            stdin: self.stdin,
            inherited: self.inherited,
        };
        if run_fixed_descriptor_process_observing_network_fork_retaining_v4(
            request,
            &mut self.owner.fork,
            &mut self.owner.process,
            self.cut,
        )
        .is_err()
        {
            self.owner.first.get_or_insert(First::Process);
            return Err(NetworkKernelMutationError::Helper);
        }
        Ok(())
    }

    fn status(&mut self) -> Result<(), NetworkKernelMutationError> {
        self.owner.status = Some(match self.owner.process.outcome() {
            Some(outcome) => successful_status(outcome),
            None => Err(NetworkKernelMutationError::Helper),
        });
        if matches!(self.owner.status, Some(Ok(()))) {
            Ok(())
        } else {
            self.owner.first.get_or_insert(First::Status);
            Err(NetworkKernelMutationError::Helper)
        }
    }

    fn after(&mut self) -> Result<(), NetworkKernelMutationError> {
        if self
            .owner
            .after
            .validate_once_v4(self.artifact, self.role.artifact(), false)
            .is_err()
        {
            self.owner.first.get_or_insert(First::After);
            return Err(NetworkKernelMutationError::Helper);
        }
        Ok(())
    }

    fn independent_after(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailedStatus {
        retained: bool,
        native_failure: bool,
        calls: Vec<&'static str>,
    }

    impl StatusNativeV4 for FailedStatus {
        type Error = NetworkKernelMutationError;

        fn before(&mut self) -> Result<(), NetworkKernelMutationError> {
            self.calls.push("before");
            Ok(())
        }
        fn run(&mut self) -> Result<(), NetworkKernelMutationError> {
            self.calls.push("run");
            if self.native_failure {
                Err(NetworkKernelMutationError::UnsupportedPlan)
            } else {
                Ok(())
            }
        }
        fn status(&mut self) -> Result<(), NetworkKernelMutationError> {
            self.calls.push("status");
            Err(NetworkKernelMutationError::Helper)
        }
        fn after(&mut self) -> Result<(), NetworkKernelMutationError> {
            self.calls.push("after");
            Err(NetworkKernelMutationError::Artifact)
        }
        fn independent_after(&self) -> bool {
            self.retained
        }
    }

    #[test]
    fn ip_host_namespace_role_matches_only_the_actual_veth_descriptor_recipe() {
        assert!(
            NetworkStatusHelperRoleV4::Ip
                .require_descriptors(false, 0)
                .is_ok()
        );
        assert!(
            NetworkStatusHelperRoleV4::Ip
                .require_descriptors(false, 1)
                .is_err()
        );

        assert!(
            NetworkStatusHelperRoleV4::IpWithHostNamespace
                .require_descriptors(false, 1)
                .is_ok()
        );
        for (stdin, inherited) in [(false, 0), (false, 2), (true, 1)] {
            assert!(
                NetworkStatusHelperRoleV4::IpWithHostNamespace
                    .require_descriptors(stdin, inherited)
                    .is_err()
            );
        }
    }

    #[test]
    fn selected_process_failure_still_enters_owed_after_without_replacing_primary() {
        let mut native = FailedStatus {
            retained: true,
            native_failure: true,
            calls: Vec::new(),
        };
        assert!(matches!(
            run_status_recipe_v4(&mut native),
            Err(NetworkKernelMutationError::UnsupportedPlan)
        ));
        assert_eq!(native.calls, ["before", "run", "after"]);
    }

    #[test]
    fn selected_negative_status_precedes_later_post_failure() {
        let mut native = FailedStatus {
            retained: true,
            native_failure: false,
            calls: Vec::new(),
        };
        assert!(matches!(
            run_status_recipe_v4(&mut native),
            Err(NetworkKernelMutationError::Helper)
        ));
        assert_eq!(native.calls, ["before", "run", "status", "after"]);
    }

    #[test]
    fn ordinary_helper_preserves_its_original_native_short_circuit_order() {
        let mut native = FailedStatus {
            retained: false,
            native_failure: true,
            calls: Vec::new(),
        };
        assert!(matches!(
            run_status_recipe_v4(&mut native),
            Err(NetworkKernelMutationError::UnsupportedPlan)
        ));
        assert_eq!(native.calls, ["before", "run"]);
        let mut native = FailedStatus {
            retained: false,
            native_failure: false,
            calls: Vec::new(),
        };
        assert!(matches!(
            run_status_recipe_v4(&mut native),
            Err(NetworkKernelMutationError::Artifact)
        ));
        assert_eq!(native.calls, ["before", "run", "after"]);
    }
}
