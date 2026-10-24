//! Binds existing Source owners, saved Cleanup and physical last-use order.

use super::{Companion, Contract};

pub(super) const REQUIRED: &[(&str, usize)] = &[
    (
        r#"pub(crate) fn retry_retirement(
    &self,
    owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
) -> bool {
    if self.is_physically_returned() {
        return true;
    }
    // The Source selects its existing Cleanup. A refused caller post stays
    // raw in this record and cannot erase factual return or renew work.
    let _observed = self.return_native(owner);
    self.is_physically_returned()
}"#,
        1,
    ),
    (
        r#"pub(super) fn return_native(
    &self,
    owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
) -> Result<QmpParentParkResult, ManagedParentParkError> {
    self.step(owner, true, |source| {
        let mut receipt = source.return_parent_park_retained(&self.body.node)?;
        // These facts come only from the actual same-connection closed
        // request and the Node's independent membership return operation.
        if receipt.closed_request.is_some() && receipt.host_memberships_returned {
            self.body.physically_returned.store(true, Ordering::Release);
        }
        if let Some(first) = receipt.host_return_after.take() {
            let _ = self.body.host_return_after.set(first);
        }
        if let Some(post) = receipt.cleanup_after.take() {
            let _ = self.body.cleanup_after.set(post);
        }
        Ok(receipt)
    })
}"#,
        1,
    ),
    (
        r#"pub(super) fn matches_source(
    &self,
    _owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    source: &ProductionVmHotForkSourceWorld,
) -> bool {
    match &self.body.source {
        ParkSourceSelection::Main(selection) => source
            .prepared_source_selector()
            .as_ref()
            .is_some_and(|actual| actual.same_role(selection)),
        #[cfg(test)]
        ParkSourceSelection::Component(actual) => {
            crate::vm_lifecycle::unissued_component_source(source)
                && Weak::ptr_eq(actual, &Arc::downgrade(_owner))
        }
    }
}"#,
        1,
    ),
    (
        r#"pub(crate) fn matches_selection(&self, selection: &crate::PreparedSourceSelector) -> bool {
    match &self.body.source {
        ParkSourceSelection::Main(actual) => actual.same_role(selection),
        #[cfg(test)]
        ParkSourceSelection::Component(_) => false,
    }
}"#,
        1,
    ),
    (
        r#"self.body.physically_returned.store(true, Ordering::Release);"#,
        1,
    ),
    (
        r#"HostOperationSupervisor::new("#,
        0,
    ),
    (
        r#"begin_original_cleanup_control("#,
        0,
    ),
    (
        r#"Arc::new("#,
        0,
    ),
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/managed_qemu_hot_fork_source_world_pool/parent_park/retirement",
    required: REQUIRED,
    expressions: &[
    ],
    identifiers: &[
        (
            r#"retry_retirement"#,
            1,
        ),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/parent_park.rs",
            required: &[
                (
                    r#"enum ParkSourceSelection {
    Main(crate::PreparedSourceSelector),
    #[cfg(test)]
    Component(Weak<Mutex<ProductionVmHotForkSourceWorld>>),
}"#,
                    1,
                ),
                (
                    r#"struct ManagedParentParkState {
    source: ParkSourceSelection,
    caller: OriginalPackagedParkCaller,
    node: crucible_engine::NodeId,
    provider: u64,
    lease: u64,
    template: HotCheckpointPoolKey,
    state: AtomicU8,
    first: OnceLock<Refusal>,
    original_after: OnceLock<HostSupervisionError>,
    host_return_after: OnceLock<HostSupervisionError>,
    cleanup_after: OnceLock<HostSupervisionError>,
    physically_returned: AtomicBool,
}"#,
                    1,
                ),
                (
                    r#"fn step(
    &self,
    source_owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    cleanup: bool,
    invoke: impl FnOnce(&mut ProductionVmHotForkSourceWorld) -> Result<QmpParentParkResult, Refusal>,
) -> Result<QmpParentParkResult, ManagedParentParkError> {
    if !cleanup && let Err(first) = self.body.caller.verify_original() {
        return Err(self.refuse(first.into()));
    }
    let mut source = match source_owner.try_lock() {
        Ok(source) => source,
        Err(TryLockError::WouldBlock) => {
            return Err(self.refuse(Refusal::Unavailable("managed source busy")));
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(self.refuse(Refusal::Unavailable("managed source poisoned")));
        }
    };
    if !self.matches_source(source_owner, &source) {
        return Err(self.refuse(Refusal::Unavailable("managed Source selection changed")));
    }
    let result = invoke(&mut source);
    // The initiating command outcome remains first even on a late original
    // refusal. The same caller's raw post is independently retained.
    let post = self.body.caller.verify_original();
    if let Some(raw) = self.body.caller.original_after() {
        let _ = self.body.original_after.set(raw);
    }
    match (result, post) {
        (Err(first), _) => Err(self.refuse(first)),
        (Ok(_), Err(first)) => Err(self.refuse(first.into())),
        (Ok(receipt), Ok(())) => Ok(receipt),
    }
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/vm_lifecycle/parent_park_drain.rs",
            required: &[
                (
                    r#"pub fn return_parent_park_retained(
    &mut self,
    node: &NodeId,
) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
    self.parent_park_drain_step(node, ProductionVmParentParkDrainRequest::Return)
}"#,
                    1,
                ),
                (
                    r#"fn parent_park_drain_step(
    &mut self,
    node: &NodeId,
    request: ProductionVmParentParkDrainRequest<'_>,
) -> Result<QmpParentParkResult, ProductionVmParentParkDrainRefusal> {
    let prepared = self
        .prepared
        .iter()
        .find(|prepared| prepared.node() == node)
        .ok_or(ProductionVmParentParkDrainRefusal::Unavailable(
            "node is not prepared",
        ))?;
    let lifecycle = self.lifecycle.as_deref_mut().ok_or(
        ProductionVmParentParkDrainRefusal::Unavailable("source lifecycle absent"),
    )?;
    let mut source = lifecycle
        .inner
        .backend_mut()
        .prepared_parent_park_source(prepared)
        .map_err(ProductionVmParentParkDrainRefusal::Source)?;
    lifecycle
        .node_launcher
        .parent_park_drain(&mut source, request)
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/qemu_lifecycle_launcher/parent_park_drain.rs",
            required: &[
                (
                    r#"Request::Return => {
    // Cancellation forbids new work, not physical cleanup by the
    // original paid owner. Retain its one finite phase lazily.
    let phase = self
        .parent_park_phase
        .as_mut()
        .ok_or(Refusal::Unavailable("launcher phase absent"))?;
    if source.node() != &phase.body.node {
        return Err(Refusal::Retained);
    }
    if let Some(receipt) = phase.body.receipt.filter(|receipt| {
        receipt.closed_request.is_some() && receipt.host_memberships_returned
    }) {
        return phase.record(Ok(receipt));
    }
    // Healthy progress borrows the same two entered operations.
    // Cleanup's finite clock starts only after an actual refusal.
    if phase.body.cleanup.is_none() {
        loop {
            let observed = phase.paired(|actor, family| {
                Ok(source.return_parent_park_under_originals(actor, family)?)
            });
            if let Ok(receipt) = observed.outcome.as_ref() {
                phase.body.receipt = Some(*receipt);
            }
            let receipt = match phase.retain_pair(observed) {
                Ok(receipt) => receipt,
                Err(first) => {
                    phase.body.first.get_or_insert(first);
                    break;
                }
            };
            if receipt.host_return_after.is_some() {
                let _ = phase.record(Ok(receipt));
                break;
            }
            if receipt.closed_request.is_some() && receipt.host_memberships_returned {
                let receipt = phase.record(Ok(receipt))?;
                let phase = self.parent_park_phase.take().ok_or(Refusal::Retained)?;
                self.parent_park_disposition =
                    Some(OriginalParkDrainDisposition { phase });
                return Ok(receipt);
            }
            let waited = phase.paired(|actor, family| {
                Ok(actor.wait_for_quiescence_change_with(family)?)
            });
            if let Err(first) = phase.retain_pair(waited) {
                phase.body.first.get_or_insert(first);
                break;
            }
        }
        // A physical return decoded before a failed post remains
        // consumed; it needs no second transport or Cleanup entry.
        if let Some(receipt) = phase.body.receipt.filter(|receipt| {
            receipt.closed_request.is_some() && receipt.host_memberships_returned
        }) {
            return phase.record(Ok(receipt));
        }
    }
    if phase.body.cleanup.is_none() {
        match self.owner.retain_parent_park_cleanup() {
            Ok(cleanup) => phase.body.cleanup = Some(cleanup),
            Err(first) => return phase.record(Err(first.into())),
        }
    }
    // Keep the non-Clone phase in the body throughout disposition.
    let cleanup = phase.body.cleanup.as_ref().ok_or(Refusal::Retained)?;
    let outcome = (|| {
        loop {
            let receipt = source.return_parent_park_under_cleanup(&cleanup)?;
            // Keep actual physical evidence before inspecting any
            // semantic status or independent original postcut.
            phase.body.receipt = Some(receipt);
            if receipt.closed_request.is_some() && receipt.host_memberships_returned {
                return Ok(receipt);
            }
            if let Some(first) = receipt.host_return_after {
                return Err(PhaseCause::Original(first));
            }
            if let Some(first) = receipt.cleanup_after {
                return Err(PhaseCause::Original(first));
            }
            cleanup.wait_for_change()?;
        }
    })();
    let receipt = phase.record(outcome)?;
    if receipt.closed_request.is_none() {
        return Err(Refusal::Retained);
    }
    let phase = self.parent_park_phase.take().ok_or(Refusal::Retained)?;
    self.parent_park_disposition = Some(OriginalParkDrainDisposition { phase });
    Ok(receipt)
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/parent_park_cleanup.rs",
            required: &[
                (
                    r#"pub(in crate::linux_attempt_host) fn retain_parent_park_cleanup(
    &self,
) -> Result<OriginalParentParkCleanup, OriginalActorAccountError> {
    Ok(OriginalParentParkCleanup {
        guard: self.cleanup()?,
        roster: RosterWeak::clone(&self.roster),
        index: self.index,
        generation: self.generation,
    })
}"#,
                    1,
                ),
                (
                    r#"pub(crate) fn verify_node(
    &self,
    binding: &OriginalNativeNodeBinding,
) -> Result<(), OriginalActorAccountError> {
    if !RosterWeak::ptr_eq(&self.roster, &binding.roster)
        || self.index != binding.index
        || self.generation != binding.generation
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    Ok(())
}"#,
                    1,
                ),
            ],
        },
        super::super::host_physical_custody::SOURCE_CLEANUP,
        super::super::host_physical_custody::SOURCE_ORIGINAL,
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/node/parent_park_drain.rs",
            required: &[
                (
                    r#"cleanup
    .verify_node(native_binding)
    .map_err(|_| crate::QmpError::InvalidBound {
        operation: "parent Park Cleanup belongs to another original account",
    })?;
// Read the retained selector by identity. Cancellation may prohibit new
// work, but cannot substitute another request or prevent owned cleanup.
let binding = self.host_io_runtime.retained_parent_park_action().ok_or(
    crate::QmpError::InvalidBound {
        operation: "parent Park retained selector absent",
    },
)?;
let receipt = self
    .channels
    .qmp_machine_control
    .parent_park_return(binding, cleanup.guard())?;
self.settle_parent_park_receipt(receipt)"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/qmp/parent_park_drain.rs",
            required: &[
                (
                    r#"pub(crate) fn parent_park_return_under_cleanup(
    &mut self,
    binding: ActionBinding,
    cleanup: &HostOperationGuard,
) -> Result<QmpParentParkResult, QmpError> {
    let request = ParentParkRequest::Return { binding };
    request.validate()?;
    self.ensure_usable()?;
    cleanup
        .verify_operation_class(HostOperationClass::Cleanup)
        .map_err(|error| QmpError::OperationalSupervision {
            operation: "parent Park retained Cleanup",
            source: error,
        })?;
    if !self
        .parent_park_session
        .as_ref()
        .is_some_and(|session| session.state.binding == binding)
    {
        return Err(QmpError::InvalidBound {
            operation: "parent Park return requires same connection selector",
        });
    }
    let deadline = super::QmpOperationDeadline {
        supervision: None,
        timeout: self.io_timeout_policy.command_timeout,
        shared: None,
        checkpoint_original: None,
        checkpoint_loan: None,
        borrowed: Some(cleanup),
        paired: None,
        _lifetime: std::marker::PhantomData,
    };
    let mut result = self.exchange_parent_park(&request, &deadline)?;
    // Physical evidence is stored before observing the independent post.
    result.cleanup_after = cleanup.wait_slice().err();
    Ok(result)
}"#,
                    1,
                ),
            ],
        },
    ],
};
