//! Reviews two actual pre-VM continuation owners without issuing authority.
//!
//! Full same-file companions preserve the real effect while narrow local facts
//! make omitted obligations observable to the unchanged generic controls.

use super::{Companion, Contract, source};

#[path = "pre_vm/child.rs"]
mod child;

const LAUNCHER: Companion = Companion {
    path: source::CONTRACT.companions[4].path,
    required: source::CONTRACT.companions[4].required,
};

// The existing Source family shares these same physical producers rather than
// copying its child, Original, RAM and kernel-join contracts.
pub(super) const CHILD_OWNER: Companion = child::OWNER;
pub(super) const CHILD_ORIGINAL: Companion = child::ORIGINAL;
pub(super) const CHILD_LADDER: Companion = child::LADDER;
pub(super) const CHILD_WAIT: Companion = child::WAIT;
pub(super) const ACTUAL_CHILD: Companion = child::ACTUAL_CHILD;
pub(super) const SHUTDOWN_TARGET: Companion = child::SHUTDOWN_TARGET;
pub(super) const PROCESS_CONTROL: Companion = child::PROCESS_CONTROL;
pub(super) const OWNED_WAIT: Companion = child::OWNED_WAIT;
pub(super) const RAM_BODY: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/host_policy.rs",
    required: &[super::super::ram_source_cleanup::CONTRACT.required[0]],
};
pub(super) const RAM_STOP: Companion = Companion {
    path: super::super::ram_source_cleanup::CONTRACT.companions[0].path,
    required: super::super::ram_source_cleanup::CONTRACT.companions[0].required,
};
pub(super) const RAM_HISTORY: Companion = Companion {
    path: super::super::ram_source_cleanup::CONTRACT.companions[1].path,
    required: super::super::ram_source_cleanup::CONTRACT.companions[1].required,
};
pub(super) const RAM_ORIGINAL: Companion = Companion {
    path: super::super::ram_source_cleanup::CONTRACT.companions[2].path,
    required: super::super::ram_source_cleanup::CONTRACT.companions[2].required,
};
pub(super) const RAM_JOIN: Companion = Companion {
    path: super::super::ram_source_cleanup::CONTRACT.companions[3].path,
    required: super::super::ram_source_cleanup::CONTRACT.companions[3].required,
};

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_lifecycle_launcher/retained_node",
        required: &[
            (
                "pub(super) enum RetainedLaunch { Node(RetainedNodeLaunch), Preparation(RetainedFreshPreparation), }",
                1,
            ),
            (
                "lease: Option<QemuAttemptGenerationLease>, directory: Option<QemuPreparedRunDirectory>,",
                1,
            ),
            (
                "contract: Option<QemuChildProcessContract>, body: FreshPreparationBody,",
                1,
            ),
            (
                "receiver: Option<crucible_qemu_host::QemuIssuedHelperReceiver>, helper_returned: bool, native: NativeLaunchProgress, directory_closing: bool,",
                1,
            ),
            ("Self::Preparation(preparation) => preparation.finish(),", 1),
            ("HostOperationSupervisor::new(", 0),
            ("HostOperationClass::Cleanup", 0),
            ("Instant::now(", 0),
            ("Box::new(", 0),
            ("Arc::new(", 0),
        ],
        expressions: &[
            ("receiver.retry_retained_helper()", 1),
            ("receiver.retry_physical_cleanup()", 1),
        ],
        identifiers: &[("retry_retained_helper", 1), ("retry_physical_cleanup", 1)],
        companions: &[
            source::PRE_VM_CUSTODY,
            source::PRE_VM_BIRTH,
            LAUNCHER,
            source::PRE_VM_ALLOCATION,
            child::CALLER,
            child::HELPER,
            source::PRE_VM_LENDER,
            source::PRE_VM_ABORT,
            super::super::host_physical_custody::SOURCE_CLEANUP,
            super::super::host_physical_custody::SOURCE_ORIGINAL,
            child::OWNER,
            child::ORIGINAL,
            child::LADDER,
            child::WAIT,
            child::ACTUAL_CHILD,
            child::SHUTDOWN_TARGET,
            child::PROCESS_CONTROL,
            child::OWNED_WAIT,
            source::PRE_VM_NATIVE_RETURN,
            source::PRE_VM_EXACT_ARTIFACTS,
            source::PRE_VM_EXACT_HANDOFF,
            source::PRE_VM_EXACT_ADMISSION,
            source::PRE_VM_EXACT_MATERIALIZATION,
            source::PRE_VM_EXACT_LAUNCH,
            source::PRE_VM_NATIVE_OWNER,
            source::PRE_VM_ISSUED_RETURN,
            source::PRE_VM_NATIVE_ISSUER,
            source::PRE_VM_NATIVE_NODE,
            source::PRE_VM_NATIVE_CONTAIN,
            source::PRE_VM_NATIVE_CONTROLS,
            source::PRE_VM_MONOTONE_FINISH,
            RAM_BODY,
            RAM_STOP,
            RAM_HISTORY,
            RAM_ORIGINAL,
            RAM_JOIN,
        ],
    },
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_resource_guard/generation_resource/tests",
        required: &[
            (
                "struct RegistryGuard { cancellation: ExecutionCancellation, }",
                1,
            ),
            ("let registry = Arc::clone(&pending.generations);", 1),
            (
                "let locked = registry.lock().expect(\"hold actual registry\");",
                1,
            ),
            ("assert!(!locked.abandoned);", 1),
            ("assert_eq!(locked.nodes[0].active[0], Some(1));", 1),
            ("assert!(!first.finished);", 1),
            ("HostOperationSupervisor::new(", 0),
            ("HostOperationClass::Cleanup", 0),
            ("Instant::now(", 0),
            ("loop {", 0),
        ],
        expressions: &[("retry.abort_without_process()", 1)],
        identifiers: &[
            (
                "contention_retains_the_same_no_process_lease_for_exact_retry",
                1,
            ),
            ("retry", 2),
        ],
        companions: &[REGISTRY_BODY, REGISTRY_OWNER],
    },
];

const REGISTRY_BODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/generation_resource/tests.rs",
    required: &[(
        r#"use super::*;
struct RegistryGuard { cancellation: ExecutionCancellation, }
impl crate::QemuAttemptOperationalBoundary for RegistryGuard {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        crucible_campaign::AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("component resource limits")
    }
    fn cancellation(&self) -> &ExecutionCancellation { &self.cancellation }
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("registry controls cannot execute a guest")
    }
    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("registry controls cannot execute a guest")
    }
}
impl QemuAttemptResourceGuard for RegistryGuard {
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> { Ok(()) }
    fn quarantine(&mut self) { panic!("an owned no-process lease must not be abandoned") }
}
fn owner() -> QemuAttemptGenerationResourceOwner<RegistryGuard> {
    let node = NodeId { name: String::from("vm-a"), };
    let storage = QemuAttemptGenerationStorage::prepare(std::iter::once(&node))
        .expect("actual selected registry");
    QemuAttemptGenerationResourceOwner::new(
        RegistryGuard { cancellation: ExecutionCancellation::default(), }, storage,
    )
}
fn generation(value: u64) -> ProductionVmNodeGeneration {
    ProductionVmNodeGeneration::new(NodeId { name: String::from("vm-a"), }, value,)
        .expect("positive generation")
}
#[test]
fn contention_retains_the_same_no_process_lease_for_exact_retry() {
    let mut owner = owner();
    let mut pending = owner.register_generation(generation(1)).expect("register actual lease");
    let identity = pending.identity().clone();
    let registry = Arc::clone(&pending.generations);
    let locked = registry.lock().expect("hold actual registry");
    assert!(pending.abort_without_process().is_err());
    assert!(!pending.finished);
    assert_eq!(pending.identity(), &identity);
    assert!(!locked.abandoned);
    assert_eq!(locked.nodes[0].active[0], Some(1));
    drop(locked);
    pending.abort_without_process().expect("same lease return after contention");
    assert!(pending.abort_without_process().is_err(), "no second return");
    let mut retry = owner.register_generation(identity).expect("exact generation reusable");
    retry.abort_without_process().expect("return exact retry");
    owner.finish().expect("no abandoned local generation");
}
#[test]
fn nonlatest_no_process_refusal_preserves_both_issued_leases() {
    let mut owner = owner();
    let mut first = owner.register_generation(generation(1)).expect("first actual lease");
    let mut next = owner.register_generation(generation(2)).expect("second actual lease");
    assert!(first.abort_without_process().is_err());
    assert!(!first.finished);
    assert!(!next.finished);
    assert!(!owner.generations.lock().expect("registry observation").abandoned);
    next.abort_without_process().expect("restore actual previous fence");
    first.abort_without_process().expect("return same first lease");
    owner.finish().expect("both exact leases physically absent");
}"#,
        1,
    )],
};

const REGISTRY_OWNER: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/generation_resource.rs",
    required: &[
        (
            r#"pub fn register_generation(
    &mut self,
    identity: ProductionVmNodeGeneration,
) -> Result<QemuAttemptGenerationLease, LifecycleApiError> {
    if self.retirement != GenerationResourceRetirement::Active {
        return Err(generation_error("QEMU attempt generation owner is already terminal",));
    }
    let mut state = self.generations.lock()
        .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
    if state.abandoned {
        return Err(generation_error("a QEMU attempt generation lease was abandoned",));
    }
    let index = state.nodes.binary_search_by(|row| row.node.cmp(identity.node()))
        .map_err(|_| {
            generation_error(format!(
                "QEMU node `{}` was not selected before Source construction", identity.node().name,
            ))
        })?;
    let row = &mut state.nodes[index];
    let free = row.active.iter().position(Option::is_none).ok_or_else(|| {
        generation_error(format!(
            "QEMU node `{}` already retains the active and staged generation leases", row.node.name,
        ))
    })?;
    if row.latest.is_some_and(|latest| identity.generation() <= latest) {
        return Err(generation_error(format!(
            "QEMU node `{}` generation {} does not advance beyond {:?}",
            row.node.name, identity.generation(), row.latest,
        )));
    }
    let previous_generation = row.latest;
    row.active[free] = Some(identity.generation());
    row.latest = Some(identity.generation());
    drop(state);
    Ok(QemuAttemptGenerationLease {
        identity, generations: Arc::clone(&self.generations), previous_generation, finished: false,
    })
}"#,
            1,
        ),
        source::PRE_VM_ABORT.required[0],
    ],
};

#[cfg(test)]
#[path = "pre_vm/tests.rs"]
mod tests;
