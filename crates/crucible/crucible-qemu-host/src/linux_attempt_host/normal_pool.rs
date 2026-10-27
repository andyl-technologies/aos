//! Retains genuine normal World/node rosters in the pinned host factory.
//!
//! One Main pool funds every simultaneous World, template and replay. Fixed
//! registry arrays are paid before construction. Published nodes own separate
//! width-one rosters; the scheduler worker count never selects their credit.
//! Retired members return only after physical vector and final Weak/control
//! closure. A failed or abandoned factory keeps the same containing owners.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativePoolPurpose, AuthenticatedNativeWorldClaim,
    AuthenticatedNativeWorldCleanupLoan, NativeNodeReservation, NativePoolRefusal,
    NativeWorldIdentity, NativeWorldReturn, ServiceBirthError,
};
use crucible_host_resources::host_supervision::HostOperationGuard;
use crucible_host_resources::ram_policy::HostResourceVector;

mod node_construction;
use node_construction::NormalNode;

mod world_preparation;
pub use world_preparation::{LinuxQemuNativeWorldPreparation, LinuxQemuNativeWorldPreparationOrigin};

/// Receives genuine World custody separately from checked preparation.
///
/// The receiver is paid before admission. A negative admission postcut can
/// transfer existing holders, but cannot invoke preparation or create an owner.
pub trait LinuxQemuNativeWorldConstructor {
    /// Consumes the caller's no-assignment proof at checked logical World birth.
    ///
    /// All ledger validation has succeeded and publication follows infallibly.
    /// This move enters no new operation and cannot refuse or allocate.
    fn entered_world(&mut self);

    /// Retains both exact holders without allocation or Original admission.
    ///
    /// # Errors
    /// Reports a fixed custody refusal after retaining the SAME holders.
    fn retain_world(
        &mut self,
        loan: AuthenticatedNativeWorldCleanupLoan,
        controls: crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), &'static str>;

    /// Performs selected preparation only after positive original admission.
    ///
    /// # Errors
    /// Preserves the actual selected preparation refusal in its existing owner.
    fn prepare_world(&mut self) -> Result<(), QemuVmRealizationError>;
}

fn complete_world_admission<E>(
    first: Option<E>,
    retained: Result<(), &'static str>,
    report: impl FnOnce(E, Option<&'static str>) -> QemuVmRealizationError,
    prepare: impl FnOnce() -> Result<(), QemuVmRealizationError>,
) -> Result<(), QemuVmRealizationError> {
    if let Some(first) = first {
        return Err(report(first, retained.err()));
    }
    retained.map_err(|operation| QemuVmRealizationError::CleanupRetained { operation })?;
    prepare()
}

/// Names actual retained custody even when its admission postcut refused.
///
/// A retained World must deliver its existing cleanup holders before reporting
/// the refusal. This outcome permits no preparation; `complete_world_admission`
/// checks the saved refusal after that custody transfer.
struct RetainedWorldAdmission {
    index: usize,
    refusal: Option<NativePoolRefusal>,
}

pub(super) struct NormalNativePool {
    purpose: Option<AuthenticatedNativePoolPurpose>,
    worlds: Vec<Option<AuthenticatedNativeWorldClaim>>,
    nodes: Vec<Option<NormalNode>>,
}

pub(super) struct NormalNodeBirth {
    pub(super) index: usize,
    pub(super) key: [u8; 32],
    pub(super) resources: HostResourceVector,
}

/// Owns the actual host resources of one selected normal node.
///
/// The key selects this already admitted member; it grants no new resources.
/// Its real process, storage and original remain in `owner` until cleanup.
#[must_use = "retain each node owner until physical Source/Target retirement"]
pub struct LinuxQemuNativeNodeHost {
    /// Selected node coordinate under its exact World claim.
    pub key: [u8; 32],
    /// Genuine paired process/storage owner born from the consumed node credit.
    pub owner: LinuxQemuAttemptHostOwner,
}

impl std::fmt::Debug for NormalNativePool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NormalNativePool")
            .field("capacity", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl NormalNativePool {
    pub(super) fn control_extent(capacity: usize) -> Option<u64> {
        let worlds =
            std::alloc::Layout::array::<Option<AuthenticatedNativeWorldClaim>>(capacity).ok()?;
        let nodes = std::alloc::Layout::array::<Option<NormalNode>>(capacity).ok()?;
        // The returned host vector may coexist with the caller's final guard
        // payload while it is consumed. The daemon prices its own vector too.
        let returned = std::alloc::Layout::array::<LinuxQemuNativeNodeHost>(capacity).ok()?;
        let (operation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .ok()?;
        let preparation_peak = operation
            .pad_to_align()
            .size()
            .checked_mul(capacity.checked_mul(2)?.checked_add(1)?)?;
        std::mem::size_of::<Self>()
            .checked_add(worlds.size())?
            .checked_add(nodes.size())?
            .checked_add(returned.size())?
            .checked_add(preparation_peak)?
            .try_into()
            .ok()
    }

    pub(super) fn new(
        purpose: AuthenticatedNativePoolPurpose,
    ) -> Result<Self, OriginalActorAccountError> {
        let capacity = purpose.node_capacity();
        let controls =
            Self::control_extent(capacity).ok_or(OriginalActorAccountError::Unavailable)?;
        purpose.verify_consumer_controls(controls)?;

        let mut worlds = Vec::new();
        worlds
            .try_reserve_exact(capacity)
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        worlds.resize_with(capacity, || None);
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        nodes.resize_with(capacity, || None);
        Ok(Self {
            purpose: Some(purpose),
            worlds,
            nodes,
        })
    }

    fn preparation_origin(
        &self,
    ) -> Result<LinuxQemuNativeWorldPreparationOrigin, OriginalActorAccountError> {
        let purpose = self
            .purpose
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(LinuxQemuNativeWorldPreparationOrigin::from_purpose(purpose))
    }

    fn claim_world(
        &mut self,
        identity: NativeWorldIdentity,
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
        populate: impl FnOnce(
            &mut dyn FnMut(NativeNodeReservation) -> Result<(), ServiceBirthError>,
        ) -> Result<(), ServiceBirthError>,
    ) -> Result<RetainedWorldAdmission, OriginalActorAccountError> {
        let index = self
            .worlds
            .iter()
            .position(Option::is_none)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let purpose = self
            .purpose
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        match purpose.claim_world_from(
            identity,
            consumer_control_bytes,
            original,
            entered,
            populate,
        ) {
            Ok(world) => {
                self.worlds[index] = Some(world);
                Ok(RetainedWorldAdmission {
                    index,
                    refusal: None,
                })
            }
            Err(mut first) => {
                let Some(world) = first.take_retained_world() else {
                    return Err(first.into());
                };
                // A negative descriptor/postcut can follow actual publication.
                // Keep that SAME claim canonical before propagating its report.
                self.worlds[index] = Some(world);
                Ok(RetainedWorldAdmission {
                    index,
                    refusal: Some(first),
                })
            }
        }
    }

    pub(super) fn prepare_next(
        &mut self,
        world: usize,
        original: &Arc<HostOperationGuard>,
    ) -> Result<Option<NormalNodeBirth>, OriginalActorAccountError> {
        if self
            .nodes
            .iter()
            .flatten()
            .any(|node| node.world == world && node.is_constructing())
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let claim = self
            .worlds
            .get(world)
            .and_then(Option::as_ref)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let Some(request) = claim.next_node()? else {
            return Ok(None);
        };
        let controls = OriginalNativeAccountRoster::shared_allocation_extent()?;
        let index = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(OriginalActorAccountError::Unavailable)?;

        // The permanently prepaid array owns every raw/conversion holder
        // before issuance, postchecks, roster publication or physical setup.
        self.nodes[index] = Some(NormalNode::constructing(world));
        let node = self.nodes[index]
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        node.prepare(claim, request.node, original, controls)?;
        Ok(Some(NormalNodeBirth {
            index,
            key: request.node,
            resources: request.resources,
        }))
    }

    pub(super) fn binding(
        &self,
        index: usize,
    ) -> Result<&OriginalNativeAccountFactoryBinding, OriginalActorAccountError> {
        self.nodes
            .get(index)
            .and_then(Option::as_ref)
            .and_then(NormalNode::binding)
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(super) fn binding_for_target(
        &self,
        target: &original_roster::ForkTargetReservation,
    ) -> Option<&OriginalNativeAccountFactoryBinding> {
        self.nodes
            .iter()
            .flatten()
            .filter_map(NormalNode::binding)
            .find(|binding| target.belongs_to_factory(binding))
    }

    pub(super) fn verify_quiescent(&self) -> Result<(), OriginalAccountRetirementError> {
        for node in self.nodes.iter().flatten() {
            node.verify_quiescent()?;
        }
        Ok(())
    }

    pub(super) fn sweep_retired(&mut self) -> Result<(), OriginalAccountRetirementError> {
        for entry in &mut self.nodes {
            let Some(node) = entry.as_mut() else {
                continue;
            };
            if node.verify_quiescent().is_err() {
                continue;
            }
            // Constructing closes its actual retained funding. A Published
            // row removes its real Weak alias before exclusive roster close;
            // any other alias still prevents Arc free.
            let closed = node.try_close();
            let returned = node.can_remove();
            if returned {
                *entry = None;
            }
            match closed {
                Ok(()) => {}
                // Existing competing aliases remain pending without starving
                // independent rows. A typed phase/post refusal remains visible.
                Err(OriginalAccountRetirementError::Unavailable) if !returned => {}
                Err(error) => return Err(error),
            }
        }
        for (index, world) in self.worlds.iter_mut().enumerate() {
            if self.nodes.iter().flatten().any(|node| node.world == index) {
                continue;
            }
            if let Some(claim) = world.as_mut() {
                let result = claim.try_finish_after_members_returned();
                let returned = claim.is_physically_returned();
                if returned {
                    *world = None;
                }
                if result? == NativeWorldReturn::PendingBody {
                    continue;
                }
            }
            *world = None;
        }
        Ok(())
    }

    pub(super) fn is_physically_retired(&self) -> bool {
        // Returned credit alone does not destroy its containing facade or
        // retained aliases. Every owning entry must be removed before closure.
        self.nodes.iter().all(Option::is_none) && self.worlds.iter().all(Option::is_none)
    }

    pub(super) fn finish(&mut self) -> Result<(), OriginalAccountRetirementError> {
        self.verify_quiescent()?;
        self.sweep_retired()?;
        if self.nodes.iter().any(Option::is_some) || self.worlds.iter().any(Option::is_some) {
            return Err(OriginalAccountRetirementError::Unavailable);
        }
        Ok(())
    }
}

impl Drop for NormalNativePool {
    fn drop(&mut self) {
        // Facade destruction cannot stand in for a physical node/Weak close.
        std::mem::forget(std::mem::take(&mut self.nodes));
        std::mem::forget(std::mem::take(&mut self.worlds));
        std::mem::forget(self.purpose.take());
    }
}

impl LinuxQemuAttemptHostFactory {
    /// Reports the existing Source host-control body and descriptor bound.
    ///
    /// This is request geometry only. The actual selected node must reserve
    /// these controls under its real Main before Source birth. Extra retained
    /// contract-directory aliases are priced separately by their real caller.
    ///
    /// # Errors
    /// Refuses an unrepresentable actual constructor/control extent.
    pub fn normal_source_control_geometry() -> Result<(u64, u64), QemuVmRealizationError> {
        let (_, bytes, descriptors) =
            original_roster::process_purpose::source_admission::source_host_peak().map_err(
                |source| QemuVmRealizationError::ModelCopy {
                    source: Box::new(source),
                },
            )?;
        Ok((bytes, descriptors))
    }

    /// Bounds the selected node's two separate Main-table landings.
    ///
    /// The Source base is its actual existing constructor query. Its explicit
    /// contract-alias request comes from the containing consumer's real overlap
    /// calculation. Target file staging is bounded by BOTH its genuine issued
    /// child-table ceiling and the existing child-file protocol bound. Fixed
    /// ownership categories below deliberately sum their possible overlaps;
    /// this is an admission bound, not a runtime descriptor census.
    ///
    /// # Errors
    /// Refuses absent two-incarnation geometry or arithmetic overflow.
    pub fn normal_node_host_descriptor_peaks(
        native_family_descriptors: u64,
        contract_alias_descriptors: u64,
    ) -> Result<(u64, u64), QemuVmRealizationError> {
        let local = native_family_descriptors
            .checked_div(2)
            .filter(|local| *local != 0)
            .ok_or_else(|| missing_authority("price native family descriptor geometry"))?;
        let (_, source) = Self::normal_source_control_geometry()?;
        let source = source
            .checked_add(contract_alias_descriptors)
            .ok_or_else(|| missing_authority("price retained contract descriptor aliases"))?;
        // LinuxQemuCgroup owns parent+control(5); the pooled watcher owns its
        // control(5)+cancellation duplicate. The child contract owns <=3,
        // cancellation hook1, memory controller1, and a transient control FD1.
        let kernel_controls = 6_u64 + 6 + 3 + 1 + 1 + 1;
        // Actual hot-fork owning pairs: QMP/console/diagnostics(2 each), plugin
        // control+wake(4), RAM control+source+service wake+plan+spill(7), private-ring
        // mapping+export(2), saved cancellation+pidfd(2), entropy read(1),
        // and workspace backing+corroboration overlap(2).
        let transport_controls = 2_u64 + 2 + 2 + 4 + 7 + 2 + 2 + 1 + 2;
        let child_files = local.min(crate::qmp::QMP_HOT_FORK_CHILD_FILES_MAX as u64);
        let target = kernel_controls
            .checked_add(transport_controls)
            .and_then(|fixed| fixed.checked_add(child_files))
            .ok_or_else(|| missing_authority("price Target descriptor overlap"))?;
        Ok((source, target))
    }

    /// Prices shared factory and dispatcher descriptor ownership.
    ///
    /// Two actual namespace roots coexist with epoll/wake/dispatcher namespace
    /// descriptors and one census/constructor transient. Per-node controls and
    /// every contract clone remain separately assigned to their node windows.
    #[must_use]
    pub const fn normal_shared_descriptor_peak() -> u64 {
        2 + 3 + 1
    }

    /// Prices the actual fixed normal pool consumer storage before its birth.
    ///
    /// This pure geometry includes all node/World cells, their returned host
    /// payload and one serialized in-flight World Preparation alongside live
    /// Worlds. It grants no native or Source authority.
    #[must_use]
    pub fn normal_pool_control_extent(capacity: usize) -> Option<u64> {
        NormalNativePool::control_extent(capacity)
    }

    /// Moves the genuine once-issued Main pool into this pinned factory.
    ///
    /// # Errors
    /// Rejects poisoned/occupied factories and retains refused original custody.
    pub fn bind_normal_pool(
        &mut self,
        purpose: AuthenticatedNativePoolPurpose,
    ) -> Result<(), OriginalActorAccountError> {
        if self.poisoned
            || self.process.is_poisoned()
            || self.original_accounts.is_some()
            || self.normal_pool.is_some()
        {
            std::mem::forget(purpose);
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.normal_pool = Some(NormalNativePool::new(purpose)?);
        Ok(())
    }

    /// Admits real permanent semantic-worker bodies under the same Main bank.
    ///
    /// # Errors
    /// Refuses stale/occupied/exhausted normal pool control accounting. A
    /// component factory with no normal pool returns no production payer.
    pub fn reserve_main_worker_controls(
        &self,
        bytes: u64,
    ) -> Result<Option<AuthenticatedNativePoolPurpose>, QemuVmRealizationError> {
        self.normal_pool
            .as_ref()
            .map(|pool| {
                pool.purpose
                    .as_ref()
                    .ok_or_else(|| missing_authority("retain Main worker control payer"))?
                    .reserve_worker_controls(bytes)
                    .map_err(|source| original_roster::original_error(source.into()))
            })
            .transpose()
    }

    /// Checks the selected open body lease against this factory's no-birth journal.
    ///
    /// # Errors
    /// Preserves foreign, attempted or uncertain custody without releasing it.
    pub fn verify_unborn_native_world(
        &self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
        controls: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), QemuVmRealizationError> {
        controls
            .verify_unborn_world(loan)
            .map_err(|source| original_roster::original_error(source.into()))?;
        let pool = self
            .normal_pool
            .as_ref()
            .ok_or_else(|| missing_authority("retain unborn native World"))?;
        let index = pool
            .worlds
            .iter()
            .position(|world| {
                world
                    .as_ref()
                    .is_some_and(|world| world.matches_cleanup_loan(loan))
            })
            .ok_or_else(|| missing_authority("match unborn native World"))?;
        if pool.nodes.iter().flatten().any(|node| node.world == index) {
            return Err(missing_authority("unborn World has a canonical node owner"));
        }
        Ok(())
    }

    /// Returns only an exact World whose member constructors were never entered.
    ///
    /// The caller first destroys its actual pending body and closes its moved
    /// body lease. This checks both canonical node storage and monotonic ledger
    /// birth history; it never treats a callback location as physical proof.
    ///
    /// # Errors
    /// Retains stale, attempted, aliased or incompletely returned assignments.
    pub fn abort_unborn_native_world(
        &mut self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        let pool = self
            .normal_pool
            .as_mut()
            .ok_or_else(|| missing_authority("retain unborn native World"))?;
        if pool
            .purpose
            .as_ref()
            .ok_or_else(|| missing_authority("retain unborn World pool identity"))?
            .observe_world_returned(loan)
            .map_err(|source| original_roster::original_error(source.into()))?
        {
            // A preexisting exact loan can outlive the canonical facade after
            // a completed return's post-refusal. This observation grants no
            // never-born assertion or new work, and clears no factory intent.
            return Ok(());
        }
        let index = pool
            .worlds
            .iter()
            .position(|world| {
                world
                    .as_ref()
                    .is_some_and(|world| world.matches_cleanup_loan(loan))
            })
            .ok_or_else(|| missing_authority("match unborn native World"))?;
        loan.verify_never_born()
            .map_err(|source| original_roster::original_error(source.into()))?;
        if pool.nodes.iter().flatten().any(|node| node.world == index) {
            return Err(missing_authority("unborn World has a canonical node owner"));
        }
        pool.worlds[index]
            .as_mut()
            .ok_or_else(|| missing_authority("retain unborn World return"))?
            .finish_after_members_returned()
            .map_err(|source| original_roster::original_error(source.into()))?;
        pool.worlds[index] = None;
        // begin_native_world checked a healthy factory before occupying this
        // World; no member constructor could have changed its kernel state.
        if !self.process.is_poisoned() {
            self.poisoned = false;
        }
        Ok(())
    }

    /// Retries only the exact pending World under its same saved Cleanup.
    ///
    /// This loan is acquired before physical birth. Per-node partial owners
    /// remain in canonical construction/roster cells under their same Cleanup.
    /// No sibling World or global factory retirement is attempted here.
    ///
    /// # Errors
    /// Retains actual partial owners and the independent World observation.
    pub fn retry_native_world_construction(
        &mut self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        let pool = self
            .normal_pool
            .as_mut()
            .ok_or_else(|| missing_authority("retain pending native World"))?;
        let world = pool
            .worlds
            .iter()
            .position(|world| {
                world
                    .as_ref()
                    .is_some_and(|world| world.matches_cleanup_loan(loan))
            })
            .ok_or_else(|| missing_authority("match pending native World"))?;
        let cleanup = loan
            .retained_cleanup()
            .map_err(|source| original_roster::original_error(source.into()))?;
        let result = (|| {
            for entry in pool
                .nodes
                .iter_mut()
                .filter(|entry| entry.as_ref().is_some_and(|node| node.world == world))
            {
                let node = entry
                    .as_mut()
                    .ok_or_else(|| missing_authority("retain pending native node"))?;
                cleanup
                    .wait_slice()
                    .map_err(|source| original_roster::original_error(source.into()))?;
                let result = node.retry_cleanup();
                // Exact native return is already recorded inside the same
                // construction owner, independently of a late post refusal.
                if node.can_remove() {
                    *entry = None;
                }
                result?;
            }
            Ok(())
        })();
        original_roster::after_cleanup(result, &cleanup)
    }

    /// Borrows the bound pool origin without entering an operation or World.
    ///
    /// # Errors
    /// Refuses poisoned or absent actual factory/pool custody.
    pub fn native_world_preparation_origin(
        &self,
    ) -> Result<LinuxQemuNativeWorldPreparationOrigin, QemuVmRealizationError> {
        if self.poisoned || self.process.is_poisoned() {
            return Err(missing_authority("borrow normal World Preparation origin"));
        }
        self.normal_pool
            .as_ref()
            .ok_or_else(|| missing_authority("retain normal World Preparation pool"))?
            .preparation_origin()
            .map_err(original_roster::original_error)
    }

    /// Creates the genuine separate host owners of a selected normal World.
    ///
    /// All rows enter one aggregate admission before the first node cgroup or
    /// quota is born. Partial owners stay in their original node rosters.
    ///
    /// # Errors
    /// Retains born World/node state, actual first cause and original failure;
    /// rejects an unavailable pool or any incomplete physical setup.
    pub fn begin_native_world(
        &mut self,
        preparation: &mut LinuxQemuNativeWorldPreparation,
        identity: NativeWorldIdentity,
        consumer_control_bytes: u64,
        exact_checkpoint_root: Option<crucible_engine::ContentHash>,
        before_effects: &mut dyn LinuxQemuNativeWorldConstructor,
        populate: impl FnOnce(
            &mut dyn FnMut(NativeNodeReservation) -> Result<(), ServiceBirthError>,
        ) -> Result<(), ServiceBirthError>,
    ) -> Result<Vec<LinuxQemuNativeNodeHost>, QemuVmRealizationError> {
        if self.poisoned || self.process.is_poisoned() {
            return Err(missing_authority("begin normal node World"));
        }
        let purpose = self
            .normal_pool
            .as_ref()
            .and_then(|pool| pool.purpose.as_ref())
            .ok_or_else(|| missing_authority("retain normal World Preparation pool"))?;
        let original = preparation.begin_attempt(purpose, identity)?;
        // Taking the pool permits disjoint pinned process/storage mutation. A
        // panic leaves this factory poisoned and the pool's actual Drop retains
        // all originals. There is no temporary ordinary fallback.
        self.poisoned = true;
        let mut pool = self
            .normal_pool
            .take()
            .ok_or_else(|| missing_authority("retain normal node pool"))?;
        let mut proven_unassigned = false;
        let result = (|| {
            pool.sweep_retired()
                .map_err(|source| original_roster::original_error(source.into()))?;
            if pool.worlds.iter().all(Option::is_some) {
                // No new assignment callback has run. Retained bodies still
                // consume real capacity without poisoning the containing Main.
                proven_unassigned = true;
                return Err(missing_authority("normal World capacity is occupied"));
            }
            let RetainedWorldAdmission {
                index: world,
                refusal: mut admission_failure,
            } = match pool.claim_world(
                identity,
                consumer_control_bytes,
                &original,
                || preparation.commit_world(|| before_effects.entered_world()),
                populate,
            ) {
                Ok(retained) => retained,
                Err(source) => {
                    proven_unassigned = matches!(
                        &source,
                        OriginalActorAccountError::NativePool(refusal)
                            if refusal.world_assignment_was_refused()
                    );
                    return Err(original_roster::original_error(source));
                }
            };
            let claim = pool.worlds[world]
                .as_mut()
                .ok_or_else(|| missing_authority("retain logical World before effects"))?;
            let custody = claim.take_initial_custody();
            let (loan, controls) = match custody {
                Ok(custody) => custody,
                Err(delivery) => {
                    return Err(match admission_failure {
                        Some(mut first) => {
                            first.retain_world_delivery_error(delivery);
                            original_roster::original_error(first.into())
                        }
                        None => original_roster::original_error(delivery.into()),
                    });
                }
            };
            // The receiver is already Main-paid. This event may only transfer
            // custody; a refused Original never starts selected preparation.
            let retained = before_effects.retain_world(loan, controls);
            complete_world_admission(
                admission_failure.take(),
                retained,
                |mut first, receiver| {
                    if let Some(receiver) = receiver {
                        first.retain_world_receiver_refusal(receiver);
                    }
                    original_roster::original_error(first.into())
                },
                || {
                    original
                        .wait_slice()
                        .map_err(|first| original_roster::original_error(first.into()))?;
                    before_effects.prepare_world()
                },
            )?;
            let mut owners = Vec::new();
            let capacity = pool.worlds[world]
                .as_ref()
                .ok_or_else(|| missing_authority("retain selected normal World"))?
                .unissued_node_count()
                .map_err(|source| original_roster::original_error(source.into()))?;
            owners
                .try_reserve_exact(capacity)
                .map_err(|_| missing_authority("allocate prepaid native node host vector"))?;
            let setup = (|| {
                while let Some(node) = pool
                    .prepare_next(world, &original)
                    .map_err(original_roster::original_error)?
                {
                    let binding = pool
                        .binding(node.index)
                        .map_err(original_roster::original_error)?;
                    let owner = self.begin_original_with_binding(
                        binding,
                        u32::try_from(node.resources.cpu_slots)
                            .map_err(|_| missing_authority("admit native node CPU geometry"))?,
                        node.resources.resident_peak_bytes,
                        node.resources.backing_peak_bytes,
                        exact_checkpoint_root,
                    )?;
                    owners.push(LinuxQemuNativeNodeHost {
                        key: node.key,
                        owner,
                    });
                }
                original
                    .complete()
                    .map_err(|source| original_roster::original_error(source.into()))?;
                Ok(())
            })();
            if let Err(first) = setup {
                for node in &mut owners {
                    node.owner.quarantine();
                }
                return Err(first);
            }
            Ok(owners)
        })();
        self.normal_pool = Some(pool);
        if (result.is_ok() || proven_unassigned) && !self.process.is_poisoned() {
            self.poisoned = false;
        }
        result
    }
}

#[cfg(test)]
mod construction_tests;
