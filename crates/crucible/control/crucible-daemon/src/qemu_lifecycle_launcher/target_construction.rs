//! Keeps selected Target construction rows inside their original World payment.
//!
//! Source metadata preparation allocates these rows once. A Target transaction
//! moves the same storage into its Main-held pending owner, never creates a new
//! node directory after target effects, and returns it only after exact native
//! loans and the containing cleanup receipt have physically completed.

use super::*;
use crucible_engine::NodeId;
#[cfg(target_os = "linux")]
use crucible_qemu_host::{LinuxQemuForkTargetPermit, QemuForkTargetConstructionLoan};

/// Keeps the actual initiating refusal without detaching its cleanup owner.
///
/// Native role occupancy is delivered separately in `QemuForkTargetPreparation`.
/// Every failure represented here precedes that delivery; no arm substitutes a
/// failed diagnostic for an issued role's exact retained cleanup loan.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum TargetPreparationFailure {
    /// The actual retained Source rejected its ownership/continuation check.
    #[error("authenticate Target Source: {0}")]
    Source(#[source] crucible_engine::SchedulerError),
    /// Existing launcher/generation state refused before native admission.
    #[error("prepare Target lifecycle: {0}")]
    Lifecycle(#[from] LifecycleApiError),
    /// The actual Source host refused before issuing a Target outcome.
    #[error("prepare native Target: {0}")]
    Native(#[source] QemuVmRealizationError),
}

/// Owns the one reusable, selected-node Target construction directory.
///
/// Identities and capacity are not authority. Permits come only from the actual
/// retained Source, and cleanup loans come only from its matching real factory.
#[must_use = "return the same selected Target storage after exact cleanup"]
pub struct TargetConstructionStorage {
    source_return_prepared: bool,
    source: crate::qemu_resource_guard::QemuGenerationStorageSelection,
    members: Vec<TargetConstructionMember>,
    generations: crate::QemuAttemptGenerationStorage,
    #[cfg(target_os = "linux")]
    native_hosts: crate::qemu_resource_guard::LinuxTargetWorldStorage,
    #[cfg(target_os = "linux")]
    native_identity:
        Option<crucible_host_resources::host_services::process_birth::NativeWorldIdentity>,
}

struct TargetConstructionMember {
    node: NodeId,
    #[cfg(target_os = "linux")]
    permit: Option<LinuxQemuForkTargetPermit>,
    #[cfg(target_os = "linux")]
    cleanup: Option<QemuForkTargetConstructionLoan>,
    #[cfg(target_os = "linux")]
    first_admission:
        Option<crucible_host_resources::host_services::process_birth::NativePoolRefusal>,
    #[cfg(target_os = "linux")]
    first_cleanup: Option<crucible_qemu_host::QemuForkTargetConstructionError>,
    #[cfg(target_os = "linux")]
    first_reconciliation: Option<
        crate::qemu_hot_fork_reconciliation::QemuHotForkAttemptReconciliationError<
            crate::LinuxQemuHotForkReconciliationError,
        >,
    >,
    termination_requested: bool,
    entered: bool,
    #[cfg(target_os = "linux")]
    requested: Option<crucible_campaign::AttemptResourceLimits>,
}

/// Describes admission while the selected row retains every actual outcome.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetMemberAdmission {
    Ready,
    Retained,
}

struct MemberHistory<'a>(&'a TargetConstructionStorage);

impl std::fmt::Debug for MemberHistory<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rows = formatter.debug_list();
        self.0.visit_history(|_, history| {
            rows.entry(&history);
        });
        rows.finish()
    }
}

impl TargetConstructionStorage {
    /// Visits each original row that retains independent native failures.
    pub(crate) fn visit_history(
        &self,
        mut apply: impl FnMut(&'static str, crate::LifecycleHistoryRef<'_>),
    ) {
        for row in &self.members {
            #[cfg(target_os = "linux")]
            if row.first_admission.is_some()
                || row.first_cleanup.is_some()
                || row.first_reconciliation.is_some()
            {
                apply(
                    "Target member",
                    crate::LifecycleHistoryRef::TargetMember {
                        node: &row.node,
                        admission: row.first_admission.as_ref(),
                        cleanup: row.first_cleanup.as_ref(),
                        reconciliation: row.first_reconciliation.as_ref(),
                    },
                );
            }
        }
    }

    /// Borrows every selected member's independent retained causes.
    pub(crate) fn history(&self) -> impl std::fmt::Debug + '_ {
        MemberHistory(self)
    }

    /// Returns the immutable count validated before any selected allocation.
    pub(crate) fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Copies only the original registry's nonissuing identity.
    pub(crate) fn source_selection(
        &self,
    ) -> crate::qemu_resource_guard::QemuGenerationStorageSelection {
        self.source.clone()
    }

    /// Checks only the prepaid selection, before any Source operation.
    pub(crate) fn contains_member(&self, node: &NodeId) -> bool {
        self.members
            .binary_search_by(|row| row.node.cmp(node))
            .is_ok()
    }

    /// Borrows unchanged per-member return history from its prepaid row.
    #[cfg(target_os = "linux")]
    pub(crate) fn first_cleanup_failure(
        &self,
    ) -> Option<&crucible_qemu_host::QemuForkTargetConstructionError> {
        self.members
            .iter()
            .find_map(|row| row.first_cleanup.as_ref())
    }

    /// Borrows the original concrete child's first rollback report.
    #[cfg(target_os = "linux")]
    pub(crate) fn first_reconciliation_failure(
        &self,
    ) -> Option<
        &crate::QemuHotForkAttemptReconciliationError<crate::LinuxQemuHotForkReconciliationError>,
    > {
        self.members
            .iter()
            .find_map(|row| row.first_reconciliation.as_ref())
    }

    /// Advances one retained child once through its actual saved Target Cleanup.
    ///
    /// There is no polling loop, new deadline or replacement child owner. The
    /// child's monotonic Complete phase is observed independently of the post
    /// refusal, so a successful close is not repeated merely to report history.
    #[cfg(target_os = "linux")]
    pub(crate) fn rollback_child<G: crate::QemuAttemptResourceGuard>(
        &mut self,
        node: &NodeId,
        child: &mut crate::QemuHotForkAttemptReconciliation<
            crate::LinuxQemuHotForkReconciliationBackend<G>,
        >,
    ) -> bool {
        self.settle_child(node, child, crate::AttemptExecutionDisposition::Canceled)
    }

    /// Settles the same retained child under its durable semantic disposition.
    ///
    /// This uses the original Target Cleanup. It never admits a replacement
    /// operation or treats the independent postcheck as physical return.
    #[cfg(target_os = "linux")]
    pub(crate) fn settle_child<G: crate::QemuAttemptResourceGuard>(
        &mut self,
        node: &NodeId,
        child: &mut crate::QemuHotForkAttemptReconciliation<
            crate::LinuxQemuHotForkReconciliationBackend<G>,
        >,
        disposition: crate::AttemptExecutionDisposition,
    ) -> bool {
        use crate::qemu_hot_fork_reconciliation::QemuHotForkReconciliationPhase as Phase;
        let Ok(index) = self.members.binary_search_by(|row| row.node.cmp(node)) else {
            return false;
        };
        let row = &mut self.members[index];
        let Some(loan) = row.cleanup.as_ref() else {
            return false;
        };
        if child.phase() == Phase::Reconciled {
            return true;
        }
        let cleanup = match loan.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                row.first_cleanup.get_or_insert(first);
                return false;
            }
        };
        let work = if child.phase() == Phase::Reconciled {
            Ok(())
        } else if child.phase() == Phase::AwaitingPublication {
            child
                .reconcile_execution_disposition(disposition)
                .map(|_| ())
        } else if !row.termination_requested {
            child
                .request_termination()
                .map(|()| row.termination_requested = true)
        } else {
            child.reconcile_step().map(|_| ())
        };
        let complete = child.phase() == Phase::Reconciled;
        let post = cleanup.wait_slice();
        if let Err(first) = work {
            row.first_reconciliation.get_or_insert(first);
        }
        if let Err(first) = post {
            row.first_cleanup.get_or_insert(
                crucible_qemu_host::QemuForkTargetConstructionError::Original(first.into()),
            );
        }
        complete
    }

    /// Executes one exact member step under its same retained Target Cleanup.
    ///
    /// No roster or Source lock remains held while `step` runs. The independent
    /// post is always observed after actual work, and each row retains its own
    /// first boundary refusal without treating that report as physical return.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_member_cleanup(
        &mut self,
        node: &NodeId,
        step: impl FnOnce() -> bool,
    ) -> bool {
        let Ok(index) = self.members.binary_search_by(|row| row.node.cmp(node)) else {
            return false;
        };
        let row = &mut self.members[index];
        let Some(loan) = row.cleanup.as_ref() else {
            return false;
        };
        let cleanup = match loan.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                row.first_cleanup.get_or_insert(first);
                return false;
            }
        };
        let work = step();
        let post = cleanup.wait_slice();
        if let Err(first) = post {
            row.first_cleanup.get_or_insert(
                crucible_qemu_host::QemuForkTargetConstructionError::Original(first.into()),
            );
        }
        // The actual work result is independent of its observed post refusal.
        // The first raw post stays in the same paid member while exact native
        // role/window receipts still determine eventual physical return.
        work
    }

    /// Advances every issued loan once, retaining each node's own first cause.
    ///
    /// A returned bit comes only from that private issuer-created loan's exact
    /// role journal. Later peers are still attempted after an earlier refusal;
    /// no clock, operation, roster or new native claim is admitted here.
    #[cfg(target_os = "linux")]
    pub(crate) fn retry_native_loans(&mut self) -> bool {
        for row in &mut self.members {
            // An unused permit is the same genuine prebirth role. Dropping it
            // admits no physical work; its retained loan still authenticates
            // whether the exact role returned, including a failed Drop fast cut.
            drop(row.permit.take());
            let Some(loan) = row.cleanup.as_mut() else {
                continue;
            };
            if loan.is_physically_returned() {
                continue;
            }
            if let Err(first) = loan.try_finish() {
                // Retry never issues a World/window/account claim: physical
                // owners remain in the same canonical roster or actual G.
                // Preserve each row's first diagnostic; it is not return proof.
                row.first_cleanup.get_or_insert(first);
            }
        }
        self.can_restore_to_source()
    }

    /// Copies routing coordinates already corroborated by this actual Source.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_identity(
        &self,
    ) -> Option<crucible_host_resources::host_services::process_birth::NativeWorldIdentity> {
        self.native_identity
    }

    /// Measures copied identities and the exact finite member payload.
    ///
    /// The actual Source World must include this request before allocation.
    /// This pure query creates no entitlement, permit or replacement deadline.
    pub(crate) fn control_bytes<'a>(
        nodes: impl Clone + Iterator<Item = &'a NodeId>,
    ) -> Result<u64, LifecycleApiError> {
        let generations = crate::QemuAttemptGenerationStorage::control_bytes(nodes.clone())?;
        let (count, _, bytes) = Self::layout(nodes)?;
        #[cfg(target_os = "linux")]
        let native = crate::LinuxQemuAttemptHostResourceOwner::world_control_bytes(count).map_err(
            |first| launcher_message(format!("measure selected Target native arrays: {first}")),
        )?;
        #[cfg(not(target_os = "linux"))]
        let native = {
            let _ = count;
            0
        };
        bytes
            .checked_add(generations)
            .and_then(|bytes| bytes.checked_add(native))
            .ok_or_else(|| launcher_message("Target selected control extent overflows"))
    }

    /// Creates only selected storage under the Source's retained World payment.
    ///
    /// No native Target is reserved or born. Validation and all requested
    /// capacities precede construction, and no owned guard is accepted here.
    pub(crate) fn prepare<'a>(
        nodes: impl Clone + Iterator<Item = &'a NodeId>,
        source: &crate::QemuAttemptGenerationStorage,
    ) -> Result<Self, LifecycleApiError> {
        let (count, mut names, _) = Self::layout(nodes.clone())?;
        if !source.matches_nodes(nodes.clone())? {
            return Err(launcher_message(
                "Target selection differs from its paid Source",
            ));
        }
        let nodes_for_generations = nodes.clone();
        let mut members: Vec<TargetConstructionMember> = Vec::new();
        members.try_reserve_exact(count).map_err(|source| {
            launcher_message(format!("reserve selected Target rows: {source}"))
        })?;
        for node in nodes {
            if members.len() >= count || members.last().is_some_and(|row| row.node >= *node) {
                return Err(launcher_message(
                    "Target selection changed during preparation",
                ));
            }
            names = names.checked_sub(node.name.len()).ok_or_else(|| {
                launcher_message("Target identity extent changed during preparation")
            })?;
            let mut name = String::new();
            name.try_reserve_exact(node.name.len()).map_err(|source| {
                launcher_message(format!("reserve selected Target identity: {source}"))
            })?;
            name.push_str(&node.name);
            members.push(TargetConstructionMember {
                node: NodeId { name },
                #[cfg(target_os = "linux")]
                permit: None,
                #[cfg(target_os = "linux")]
                cleanup: None,
                #[cfg(target_os = "linux")]
                first_admission: None,
                #[cfg(target_os = "linux")]
                first_cleanup: None,
                #[cfg(target_os = "linux")]
                first_reconciliation: None,
                termination_requested: false,
                entered: false,
                #[cfg(target_os = "linux")]
                requested: None,
            });
        }
        if members.len() != count || names != 0 {
            return Err(launcher_message(
                "Target selection extent changed during preparation",
            ));
        }
        Ok(Self {
            source_return_prepared: false,
            source: source.selection(),
            members,
            generations: crate::QemuAttemptGenerationStorage::prepare(nodes_for_generations)?,
            #[cfg(target_os = "linux")]
            native_identity: None,
            #[cfg(target_os = "linux")]
            native_hosts: crate::qemu_resource_guard::LinuxTargetWorldStorage::prepare(count)
                .map_err(|first| {
                    launcher_message(format!("prepare selected Target native array: {first}"))
                })?,
        })
    }

    /// Corroborates copied coordinates from the actual retained Source guard.
    ///
    /// This records routing geometry only. Native birth independently consumes
    /// the same selected node's genuine permit at its matching real factory.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_native_identity(
        &mut self,
        identity: crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
    ) -> bool {
        match self.native_identity {
            Some(saved) => saved == identity,
            None => {
                self.native_identity = Some(identity);
                true
            }
        }
    }

    /// Lends existing registry storage before a Target guard moves into it.
    pub(crate) fn generation_storage(&mut self) -> crate::QemuAttemptGenerationStorage {
        self.source_return_prepared = false;
        self.generations.lend_existing()
    }

    /// Observes only the completed outside-lock metadata return preparation.
    ///
    /// No subsequent work method can preserve this bit. It supplies no native
    /// authority; Source still matches its exact registry and vacant storage.
    pub(crate) fn source_return_is_prepared(&self) -> bool {
        self.source_return_prepared
    }

    /// Stores the genuine logical outcome before returning any status.
    ///
    /// Selection and duplicate-entry checks precede the producer. Once that
    /// producer returns an occupied role, this path only moves its permit,
    /// cleanup loan and actual first refusal into their already-paid row.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_member(
        &mut self,
        node: &NodeId,
        prepare: impl FnOnce() -> Result<
            crucible_qemu_host::QemuForkTargetPreparation,
            TargetPreparationFailure,
        >,
    ) -> Result<TargetMemberAdmission, TargetPreparationFailure> {
        if self.members.iter().any(|row| row.first_admission.is_some()) {
            return Err(launcher_message(
                "Target admission remains retained after an earlier member refusal",
            )
            .into());
        }
        let index = self
            .members
            .binary_search_by(|row| row.node.cmp(node))
            .map_err(|_| launcher_message("Target admission has no paid selected row"))?;
        let row = &mut self.members[index];
        if row.entered {
            return Err(launcher_message("Target selected row was already entered").into());
        }
        self.source_return_prepared = false;
        let prepared = prepare()?;

        row.entered = true;
        let status = match prepared {
            crucible_qemu_host::QemuForkTargetPreparation::Ready { permit, cleanup } => {
                row.permit = Some(permit);
                row.cleanup = Some(cleanup);
                TargetMemberAdmission::Ready
            }
            crucible_qemu_host::QemuForkTargetPreparation::Retained { cleanup, first } => {
                row.cleanup = Some(cleanup);
                row.first_admission = Some(first);
                TargetMemberAdmission::Retained
            }
        };
        Ok(status)
    }

    /// Borrows the actual first landing refusal without changing its custody.
    #[cfg(target_os = "linux")]
    pub(crate) fn first_admission_failure(
        &self,
    ) -> Option<&crucible_host_resources::host_services::process_birth::NativePoolRefusal> {
        self.members
            .iter()
            .find_map(|row| row.first_admission.as_ref())
    }

    /// Moves actual history only after every issued member's exact return.
    ///
    /// Admission stops at the first retained member. Later members cannot be
    /// entered while that refusal is present, so this is one actual leaf,
    /// independent of the number of selected nodes.
    #[cfg(target_os = "linux")]
    pub(crate) fn take_returned_admission_failure(
        &mut self,
    ) -> Result<
        Option<crucible_host_resources::host_services::process_birth::NativePoolRefusal>,
        LifecycleApiError,
    > {
        if !self.can_restore_to_source() {
            return Err(launcher_message(
                "Target admission history still retains its exact role",
            ));
        }
        Ok(self
            .members
            .iter_mut()
            .find_map(|row| row.first_admission.take()))
    }

    /// Creates only genuine selected members in this same prepaid host vector.
    ///
    /// All geometry is checked before the first physical factory call. Each
    /// returned host moves immediately into the Main-held vector; a later
    /// member or refinement failure cannot drop earlier born owners. The
    /// matching factory still verifies every real move-only permit itself.
    #[cfg(target_os = "linux")]
    pub(crate) fn begin_native_world(
        &mut self,
        factory: &mut crucible_qemu_host::LinuxQemuAttemptHostFactory,
        aggregate: crucible_campaign::AttemptResourceLimits,
    ) -> Result<crate::LinuxQemuAttemptHostResourceOwner, QemuVmRealizationError> {
        self.source_return_prepared = false;
        let unavailable = || QemuVmRealizationError::ExecutorUnavailable {
            operation: "begin actual selected Target World",
            message: String::from("selected Target geometry or retained admission is unavailable"),
        };
        let identity = self.native_identity.ok_or_else(unavailable)?;
        let mut selected = 0_usize;
        let mut cpus = 0_u32;
        let mut resident = 0_u64;
        let mut writable = 0_u64;
        for row in &mut self.members {
            if !row.entered {
                continue;
            }
            if row.first_admission.is_some() || row.cleanup.is_none() {
                return Err(unavailable());
            }
            let (member_cpus, member_resident, member_writable) = row
                .permit
                .as_ref()
                .ok_or_else(unavailable)?
                .resource_ceiling()?;
            let requested = crucible_campaign::AttemptResourceLimits::new(
                member_cpus,
                member_resident,
                member_writable,
                aggregate.maximum_execution_quanta(),
            )
            .map_err(|_| unavailable())?;
            cpus = cpus.checked_add(member_cpus).ok_or_else(unavailable)?;
            resident = resident
                .checked_add(member_resident)
                .ok_or_else(unavailable)?;
            writable = writable
                .checked_add(member_writable)
                .ok_or_else(unavailable)?;
            selected = selected.checked_add(1).ok_or_else(unavailable)?;
            row.requested = Some(requested);
        }
        if cpus > aggregate.maximum_vcpus()
            || resident > aggregate.maximum_resident_bytes()
            || writable > aggregate.maximum_disk_bytes()
            || !self.native_hosts.begin_pass(selected, aggregate)
        {
            return Err(unavailable());
        }
        for row in &mut self.members {
            if !row.entered {
                continue;
            }
            let requested = row.requested.ok_or_else(unavailable)?;
            if !self.native_hosts.has_prepared_cell() {
                return Err(unavailable());
            }
            let key = crate::qemu_resource_guard::world_node_key(identity.owner, &row.node);
            let permit = row.permit.take().ok_or_else(unavailable)?;
            let host = factory.begin_fork_target(
                permit,
                requested.maximum_vcpus(),
                requested.maximum_resident_bytes(),
                requested.maximum_disk_bytes(),
            )?;
            self.native_hosts.record_member(key, requested, host);
            self.native_hosts.refine_recorded_limits(requested)?;
        }
        Ok(self.native_hosts.take_host(identity, aggregate))
    }

    /// Keeps the actual aggregate host here until composition accepts it.
    ///
    /// A cancellation or composition refusal leaves the same host in this
    /// Main-held storage. The callback may take it only into the actual guard;
    /// the factory performs no further fallible operation after that transfer.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_native_world(
        &mut self,
        factory: &mut crucible_qemu_host::LinuxQemuAttemptHostFactory,
        resources: crucible_campaign::AttemptResourceLimits,
        install: &mut dyn FnMut(
            &mut Option<crate::LinuxQemuAttemptHostResourceOwner>,
        ) -> Result<(), QemuVmRealizationError>,
    ) -> Result<(), QemuVmRealizationError> {
        if self.native_hosts.installed.is_some() {
            return Err(QemuVmRealizationError::CleanupRetained {
                operation: "repeat installed Target World composition",
            });
        }
        let host = self.begin_native_world(factory, resources)?;
        self.native_hosts.installed = Some(host);
        install(&mut self.native_hosts.installed)
    }

    /// Retries only physical hosts already returned into this Pending storage.
    ///
    /// A partial native pass is wrapped using its saved actual aggregate basis
    /// and SAME vector allocation. The ordinary Linux World owner then drives
    /// its retained Target Cleanups. No permit, process or guard is issued here.
    #[cfg(target_os = "linux")]
    pub(crate) fn retry_native_bodies(&mut self) -> Result<(), QemuVmRealizationError> {
        use crate::qemu_resource_guard::QemuAttemptHostResourceOwner;
        if self.native_hosts.needs_host_cleanup() {
            let identity = self
                .native_identity
                .ok_or(QemuVmRealizationError::CleanupRetained {
                    operation: "retain partial Target World identity",
                })?;
            let aggregate =
                self.native_hosts
                    .aggregate
                    .ok_or(QemuVmRealizationError::CleanupRetained {
                        operation: "retain partial Target World geometry",
                    })?;
            self.native_hosts.installed = Some(self.native_hosts.take_host(identity, aggregate));
        }
        match self.native_hosts.installed.as_mut() {
            Some(host) => host.finish(),
            None => Ok(()),
        }
    }

    /// Recovers partial host capacity only after each exact role return.
    ///
    /// A moved aggregate G must first return its own vector through the guard
    /// recovery method. Absence of an installed host cannot stand in for that
    /// transfer: the original selected capacity must actually be present.
    #[cfg(target_os = "linux")]
    pub(crate) fn recover_retained_native_storage(&mut self) -> bool {
        if !self.can_restore_to_source() {
            return false;
        }
        if let Some(mut host) = self.native_hosts.installed.take() {
            let Some(identity) = self.native_identity else {
                self.native_hosts.installed = Some(host);
                return false;
            };
            if !self.native_hosts.recover_from_host(identity, &mut host) {
                self.native_hosts.installed = Some(host);
                return false;
            }
            // The genuine role receipts preceded the vector move and actual
            // returned host metadata destruction. No physical owner is dropped.
            drop(host);
        }
        self.native_hosts.reconcile_empty_return()
    }

    /// Moves only this selected member's genuine launch permit.
    ///
    /// Its cleanup loan and actual admission history remain in the same Main
    /// pending body before any downstream Target factory effect is attempted.
    #[cfg(target_os = "linux")]
    pub(crate) fn take_member_permit(
        &mut self,
        node: &NodeId,
    ) -> Result<LinuxQemuForkTargetPermit, LifecycleApiError> {
        let index = self
            .members
            .binary_search_by(|row| row.node.cmp(node))
            .map_err(|_| launcher_message("Target permit has no paid selected row"))?;
        let row = &mut self.members[index];
        if !row.entered || row.cleanup.is_none() || row.first_admission.is_some() {
            return Err(launcher_message("Target member landing is not admitted"));
        }
        row.permit
            .take()
            .ok_or_else(|| launcher_message("Target member permit was already consumed"))
    }

    /// Restores local rows only after exact native returns and body destruction.
    ///
    /// Arc uniqueness is checked only after the real loan receipts. It is a
    /// safe metadata access condition, never a substitute for physical return.
    pub(crate) fn prepare_reuse(&mut self) -> bool {
        if !self.can_restore_to_source()
            || {
                #[cfg(target_os = "linux")]
                {
                    !self.native_hosts.can_reuse()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            }
            || self.members.iter().any(|row| {
                #[cfg(target_os = "linux")]
                {
                    row.first_admission.is_some()
                        || row.first_cleanup.is_some()
                        || row.first_reconciliation.is_some()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = row;
                    false
                }
            })
            || !self.generations.reset_after_target_return()
        {
            return false;
        }
        for row in &mut self.members {
            #[cfg(target_os = "linux")]
            {
                row.permit = None;
                row.cleanup = None;
            }
            row.termination_requested = false;
            row.entered = false;
        }
        self.source_return_prepared = true;
        true
    }

    /// Disposes observed terminal row history while its actual role stays paid.
    ///
    /// The protected terminal consumer calls this outside the Source mutex.
    /// Exact loan return, recovered native backing and unique empty generation
    /// metadata are required first. Reset grants no native or Source work.
    #[cfg(target_os = "linux")]
    pub(crate) fn dispose_returned_history_and_reset(&mut self) -> bool {
        if !self.can_restore_to_source()
            || !self.native_hosts.can_reuse()
            || !self.generations.can_reset_after_target_return()
        {
            return false;
        }
        for row in &mut self.members {
            drop(row.first_admission.take());
            drop(row.first_cleanup.take());
            drop(row.first_reconciliation.take());
        }
        self.prepare_reuse()
    }

    /// Recovers existing host capacity only after exact native role receipts.
    #[cfg(target_os = "linux")]
    pub(crate) fn recover_native_hosts(
        &mut self,
        host: &mut crate::LinuxQemuAttemptHostResourceOwner,
    ) -> bool {
        if !self.can_restore_to_source() {
            return false;
        }
        let Some(identity) = self.native_identity else {
            return false;
        };
        self.native_hosts.recover_from_host(identity, host)
    }

    pub(crate) fn belongs_to<G: crate::QemuAttemptResourceGuard>(
        &self,
        owner: &crate::QemuAttemptGenerationResourceOwner<G>,
    ) -> bool {
        owner.matches_storage_selection(&self.source)
    }

    /// Checks storage reuse without attesting a native or World return.
    ///
    /// Fresh selected rows were never issued. An entered row instead requires
    /// its exact loan's return; process absence cannot replace that witness.
    pub(crate) fn can_restore_to_source(&self) -> bool {
        self.members.iter().all(|row| {
            #[cfg(target_os = "linux")]
            if row.permit.is_some()
                || row
                    .cleanup
                    .as_ref()
                    .is_some_and(|loan| !loan.is_physically_returned())
                || (row.entered && row.cleanup.is_none())
            {
                return false;
            }
            !row.entered || cfg!(target_os = "linux")
        })
    }

    fn layout<'a>(
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<(usize, usize, u64), LifecycleApiError> {
        let mut count = 0_usize;
        let mut names = 0_usize;
        let mut previous = None;
        for node in nodes {
            if previous.is_some_and(|previous: &NodeId| previous >= node) {
                return Err(launcher_message(
                    "Target nodes are duplicated or out of order",
                ));
            }
            count = count
                .checked_add(1)
                .filter(|count| *count <= crate::MAX_QEMU_ATTEMPT_GENERATION_NODES)
                .ok_or_else(|| launcher_message("Target selected-node bound is exhausted"))?;
            names = names
                .checked_add(node.name.len())
                .ok_or_else(|| launcher_message("Target identity extent overflows"))?;
            previous = Some(node);
        }
        if count == 0 {
            return Err(launcher_message("Target node selection is empty"));
        }
        let rows = std::alloc::Layout::array::<TargetConstructionMember>(count)
            .map_err(|_| launcher_message("Target row extent overflows"))?;
        let bytes = rows
            .size()
            .checked_add(names)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| launcher_message("Target selected extent overflows"))?;
        Ok((count, names, bytes))
    }
}

#[cfg(test)]
mod tests;
