//! Binds the held-binding mutex regression to actual component credit custody.
//!
//! One refused call, then the same unlocked roster observation, is distinct
//! from rerunning a test. This component owns no configured native process or
//! Main World; the exact full test and real lower cleanup cuts are required.

use super::{Companion, Contract};

const HELD_TEST: &str = r#"fn contended_cleanup_retains_the_same_binding_and_paired_credit()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;
        let held = binding
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let credit = state.slots[0]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let address = std::ptr::from_ref(credit);

        // This is the actual binding's mutex, held in this same thread. A
        // blocking entry cannot reach the original-bound retirement checks.
        let error = roster
            .retry_unsettled()
            .expect_err("contended cleanup must refuse");
        let QemuVmRealizationError::ModelCopy { source } = error else {
            panic!("preserve the original typed roster refusal");
        };
        assert!(matches!(
            source.downcast_ref::<OriginalActorAccountError>(),
            Some(OriginalActorAccountError::Unavailable)
        ));
        assert!(std::ptr::eq(
            &**roster
                .held
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?,
            &*held
        ));
        assert_eq!(
            std::ptr::from_ref(
                state.slots[0]
                    .credit
                    .as_ref()
                    .ok_or(OriginalActorAccountError::Unavailable)?
            ),
            address
        );
        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());
        drop(source);
        drop(state);

        roster.retry_unsettled()?;
        roster.verify_quiescent()?;
        assert!(
            roster.try_close().is_err(),
            "the real binding still blocks release"
        );
        drop(held);
        drop(binding);
        roster.try_close()?;
        assert!(roster.is_physically_returned());
        drop(OriginalNativeAccountCredit::reserve_mechanism_pair(
            &resident, &metadata,
        )?);
        roster.try_close()?;
        Ok(())
    }"#;

const RETIRED_BODY: &str = r#"fn retire_with_post_free(
        &mut self,
        post_free: impl FnOnce(),
    ) -> Result<(), OriginalActorAccountError> {
        if let Some(held) = self.held.as_mut() {
            if self.retiring_credits.iter().any(Option::is_some) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            held.retire_body(
                |state| {
                    for slot in &state.slots {
                        verify_closed_slot(slot)?;
                        if let Some(credit) = &slot.credit {
                            credit.require_return_phase()?;
                        }
                    }
                    Ok(())
                },
                |state| {
                    for (slot, retained) in state.slots.iter_mut().zip(&mut self.retiring_credits) {
                        *retained = slot.credit.take();
                    }
                },
            )?;
            // The same pairs are now outside the allocation they financed.
            drop(self.held.take());
            post_free();
        }

        for retained in &mut self.retiring_credits {
            if let Some(credit) = retained {
                let result = credit.retire_after_control_free();
                if credit.is_physically_returned() {
                    *retained = None;
                }
                result?;
            }
            *retained = None;
        }
        Ok(())
    }"#;

pub(in super::super::super) const RECONCILE_BODY: &str = r#"pub fn retry_unsettled(&mut self) -> Result<(), QemuVmRealizationError> {
    let launch_return = self.retry_failed_launch_bodies();
    let held = self
        .held
        .as_ref()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
    // Contention must not wait beyond the caller's saved Cleanup.
    // Refusal leaves the same roster and every physical owner untouched.
    let width = held
        .try_lock()
        .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?
        .width;
    for index in 0..width {
        let generation = {
            let state = held
                .try_lock()
                .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
            let slot = &state.slots[index];
            slot.active.filter(|_| slot.unsettled.is_some() && !slot.fork_target.is_owned())
        };
        if let Some(generation) = generation {
            NativeAccountAttempt {
                roster: held.downgrade(), index, generation,
            }.cleanup().map_err(original_error)?;
        }
    }
    let mut state = held
        .try_lock()
        .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
    for slot in &mut state.slots {
        fork_target::retry_unsettled_target(slot)?;
        if slot.fork_target.is_owned() || slot.unsettled.is_none() {
            continue;
        }
        let cleanup = slot.cleanup.as_ref().map(Arc::clone)
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
        slot.unsettled
            .as_mut()
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
            .finish(&cleanup)?;
        close_slot(slot).map_err(original_error)?;
        slot.unsettled = None;
    }
    launch_return.map_err(original_error)
}"#;

pub(in super::super::super) const FAILED_BODIES: &str = r#"pub(super) fn retry_failed_launch_bodies(&self) -> Result<(), OriginalActorAccountError> {
    let Some(held) = self.held.as_ref() else { return Ok(()); };
    let count = held.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?.slots.len();
    let mut returned = true;
    for index in 0..count {
        let retained = {
            let state = held.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?;
            state.slots.get(index).and_then(|slot| slot.source_controller.as_ref()).cloned()
        };
        if let Some(retained) = retained {
            returned &= retained.retry_physical_cleanup();
        }
    }
    if returned { Ok(()) } else { Err(OriginalActorAccountError::Unavailable) }
}"#;

// Keep all consumers on the same Source assignment, Original and return facts.
pub(in super::super) const SOURCE_CLEANUP: Companion = Companion {
    path: CONTRACT.companions[0].path,
    required: &[
        CONTRACT.companions[0].required[1],
        CONTRACT.companions[0].required[2],
        CONTRACT.companions[0].required[3],
        CONTRACT.companions[0].required[4],
        CONTRACT.companions[0].required[5],
    ],
};

pub(in super::super) const SOURCE_ORIGINAL: Companion = Companion {
    path: CONTRACT.companions[3].path,
    required: CONTRACT.companions[3].required,
};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/linux_attempt_host/original_roster/retirement",
    required: &[
        (
            r#"pub(in crate::linux_attempt_host) fn verify_quiescent(
    &self,
) -> Result<(), OriginalActorAccountError> {
    if let Some(held) = self.held.as_ref() {
        let state = held
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        for slot in &state.slots {
            verify_closed_slot(slot)?;
            if let Some(credit) = slot.credit.as_ref() {
                credit.verify_quiescent_custody()?;
            }
        }
    }
    for credit in self.retiring_credits.iter().flatten() {
        credit.verify_quiescent_custody()?;
    }
    Ok(())
}"#,
            1,
        ),
        (
            r#"pub fn try_close(&mut self) -> Result<(), OriginalActorAccountError> {
    self.retry_failed_launch_bodies()?;
    self.retire_with_post_free(|| {})
}"#,
            1,
        ),
        (FAILED_BODIES, 1),
        (RETIRED_BODY, 1),
        (
            r#"fn verify_closed_slot(slot: &NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.fork_target.is_owned()
        || slot.active.is_some()
        || slot.node_bindings_live != 0
        || slot
            .digest_purposes
            .iter()
            .any(device_digest::DigestPurposeState::is_live)
        || slot.launch_in_flight
        || slot.launch_abandoned
        || slot.launch_refusal.is_some()
        || slot.control.is_some()
        || slot.cleanup.is_some()
        || slot.unsettled.is_some()
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    Ok(())
}"#,
            1,
        ),
    ],
    expressions: &[
        (HELD_TEST, 1),
        ("self.retry_failed_launch_bodies()?", 1),
        ("retained.retry_physical_cleanup()", 1),
    ],
    identifiers: &[("retry_failed_launch_bodies", 2)],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
            required: &[
                (RECONCILE_BODY, 1),
                (
                    r#"fn assign_source_cleanup(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.source_cleanup_assigned { return Ok(()); }
    if slot.source_controller.is_none() {
        return Err(OriginalActorAccountError::Unavailable);
    }
    let extent = cleanup_control_extent()?;
    let next = slot.cleanup_controls_bytes.checked_add(extent)
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let pending = match slot.installed_process.as_ref() {
        Some(purpose) if purpose.pending_cleanup_is(extent) => extent,
        Some(_) => return Err(OriginalActorAccountError::Unavailable),
        None => 0,
    };
    slot.require_metadata_assignment_replacing_pending(extent, pending)?;
    if let Some(purpose) = slot.installed_process.as_mut()
        && !purpose.consume_cleanup(extent)
    { return Err(OriginalActorAccountError::Unavailable); }
    slot.cleanup_controls_bytes = next;
    slot.source_cleanup_assigned = true;
    Ok(())
}"#,
                    1,
                ),
                (
                    r#"fn cleanup_entry(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    let roster = self.roster.upgrade().ok_or(OriginalActorAccountError::Unavailable)?;
    let controller = {
        let mut state = roster.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state.slots.get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        assign_source_cleanup(slot)?;
        slot.source_controller.as_ref().cloned()
            .ok_or(OriginalActorAccountError::Unavailable)?
    };
    let original = controller.retained_cleanup()?;
    let mut state = roster.try_lock().map_err(|_| OriginalActorAccountError::Unavailable)?;
    let slot = state.slots.get_mut(self.index).filter(|slot| {
        slot.active == Some(self.generation)
            && slot.source_controller.as_ref().is_some_and(|saved| saved.same_owner(&controller))
    }).ok_or(OriginalActorAccountError::Unavailable)?;
    if slot.cleanup.is_none() { slot.cleanup = Some(Arc::clone(&original)); }
    if !slot.cleanup.as_ref().is_some_and(|saved| Arc::ptr_eq(saved, &original)) {
        return Err(OriginalActorAccountError::Unavailable);
    }
    Ok(original)
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    let original = self.cleanup_entry()?;
    original.wait_slice()?;
    Ok(original)
}"#,
                    1,
                ),
                (
                    r#"fn close_control(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.source_controller.as_ref().is_some_and(|controller| !controller.physical_owners_returned()) {
        return Err(OriginalActorAccountError::Unavailable);
    }"#,
                    1,
                ),
                (
                    r#"cleanup.complete()?;
slot.cleanup = None;
slot.source_controller = None;
slot.source_cleanup_assigned = false;"#,
                    1,
                ),
                (
                    r#"fn finish(&mut self, cleanup: &HostOperationGuard) -> Result<(), QemuVmRealizationError> {
    cleanup
        .wait_slice()
        .map_err(|source| original_error(source.into()))?;
    if let Some(process) = self.process.as_mut() {
        process.finish_under_original(cleanup)?;
    }
    self.process = None;
    if let Some(group) = self.unconfigured.as_mut() {
        group.remove_under_original(cleanup)?;
    }
    self.unconfigured = None;
    if let Some(state) = self.native_resources.as_ref() {
        NativeResourceState::drain(state);
    }
    self.native_resources = None;
    cleanup
        .wait_slice()
        .map_err(|source| original_error(source.into()))?;
    let result = if let Some(storage) = self.storage.as_mut() {
        storage.cleanup_under_original(cleanup)
    } else {
        Ok(())
    };
    if result.is_ok() {
        // Physical release is recorded before the separate original
        // postcut. Refusal leaves the actual owner in this same slot.
        self.storage = None;
    }
    after_cleanup(result, cleanup)
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn after_cleanup<T>(
    result: Result<T, QemuVmRealizationError>,
    cleanup: &HostOperationGuard,
) -> Result<T, QemuVmRealizationError> {
    after_boundary(result, cleanup.wait_slice().map(|_| ()).map_err(Into::into))
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/native_account.rs",
            required: &[
                (
                    r#"pub(super) fn reserve_mechanism_pair(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
) -> Result<HostServiceLeasePair, HostServiceError> {
    // These test counters establish retention and refund behavior only;
    // they cannot issue a configured native process purpose.
    let first = resident.reserve_resources(69, 1056, 1536 << 20)?;
    let second = metadata.reserve_resources(0, 0, 512 << 20)?;
    Ok(HostServiceLeasePair::new(first, second))
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn mechanism_credit(
    preparation: Arc<HostOperationGuard>,
) -> Result<(Self, HostServiceAllocator, HostServiceAllocator), HostServiceError> {
    let resident = HostServiceAllocator::new(69, 1056, 1536 << 20)?;
    let metadata = HostServiceAllocator::new(1, 1, 512 << 20)?;
    let pair = Self::reserve_mechanism_pair(&resident, &metadata)?;
    Ok((
        Self {
            original: Some(RetainedNativeCredit {
                _pair: Some(pair),
                normal: None,
                preparation,
            }),
            full_resident_bytes: 1536 << 20,
            full_backing_bytes: 4 << 30,
            total_metadata_bytes: 512 << 20,
            cpu_ceiling: 1,
            task_ceiling: 69,
            descriptor_ceiling: 1056,
            normal_controls_bytes: 0,
            #[cfg(feature = "private-measurement-domain")]
            actor_family: None,
        },
        resident,
        metadata,
    ))
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn retire_after_control_free(&mut self) -> Result<(), OriginalActorAccountError> {
    let Some(retained) = self.original.as_ref() else {
        return Ok(());
    };
    if let Some(normal) = retained.normal.as_ref() {
        let cleanup = normal.retained_world_cleanup()?;
        let normal = self
            .original
            .as_mut()
            .and_then(|retained| retained.normal.as_mut())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let result = normal.retire_after_control_free(&cleanup);
        if normal.is_physically_returned() {
            drop(self.original.take());
        }
        return result.map_err(Into::into);
    }
    // Existing private/component pairs have no World claim. They retain
    // their original Preparation policy; this path issues no Main Cleanup.
    self.require_original()?;
    drop(self.original.take());
    Ok(())
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn require_return_phase(&self) -> Result<(), OriginalActorAccountError> {
    match self.original.as_ref() {
        Some(retained) => match retained.normal.as_ref() {
            Some(normal) => {
                let cleanup = normal.retained_world_cleanup()?;
                normal.verify_world_cleanup(&cleanup)?;
                Ok(())
            }
            None => self.require_original(),
        },
        None => Ok(()),
    }
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn is_physically_returned(&self) -> bool {
    self.original.is_none()
}"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: super::super::TARGET_CLEANUP_REQUIRED,
        },
        Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_node.rs",
            required: &[
                (
                    r#"pub(super) fn retained_cleanup(
    &self,
) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    self.cleanup.get_or_init(|| self.origin.begin_original_cleanup_control().map(Arc::new))
        .as_ref().map(Arc::clone).map_err(|first| (*first).into())
}"#,
                    1,
                ),
                (
                    r#"pub(super) fn cleanup_matches(&self, original: &Arc<HostOperationGuard>) -> bool {
    self.cleanup.get().and_then(|saved| saved.as_ref().ok())
        .is_some_and(|saved| Arc::ptr_eq(saved, original))
}"#,
                    1,
                ),
            ],
        },
        super::roster_storage::STORAGE,
        super::roster_storage::FUNDING,
    ],
};

#[test]
fn held_roster_regression_requires_contention_identity_and_physical_credit_return()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    let source = std::fs::read_to_string(
        crate::workspace::package_path(&root.join("crates"), CONTRACT.package)
            .join(format!("{}.rs", CONTRACT.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = super::super::read_companions(&CONTRACT)?;
    let details =
        super::super::lifecycle_retirement::contract_diagnostics(&CONTRACT, &code, &companions);
    assert!(
        details.is_empty(),
        "whole held-roster test is not bound: {details:#?}"
    );
    let masked = super::super::mask_contract(&CONTRACT, &code, &companions);
    assert_ne!(masked, code);
    assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());

    let rejects = |candidate: &str, evidence: &[String]| {
        assert_eq!(
            super::super::mask_contract(&CONTRACT, candidate, evidence),
            candidate
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", candidate).is_empty());
    };
    rejects(&code, &[]);

    let mutate_body = |body: &str, needle: &str, replacement: &str| {
        let changed = super::super::replace_one_obligation(
            body,
            &super::super::source_pattern(needle),
            replacement,
        );
        assert_ne!(
            changed, body,
            "mutation must reach the actual held stage: {needle}"
        );
        super::super::replace_one_obligation(&code, &super::super::source_pattern(body), &changed)
    };
    for (needle, replacement) in [
        (
            "let error = roster.retry_unsettled()",
            "drop(state); let error = roster.retry_unsettled()",
        ),
        ("assert!(std::ptr::eq(", "unproved_identity(std::ptr::eq("),
        (
            "assert_eq!(std::ptr::from_ref(",
            "unproved_address(std::ptr::from_ref(",
        ),
        (
            "assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());",
            "unproved_credit_retention();",
        ),
        ("drop(binding);", "retain(binding);"),
        (
            "roster.retry_unsettled()?;",
            "loop { roster.retry_unsettled()?; }",
        ),
    ] {
        rejects(&mutate_body(HELD_TEST, needle, replacement), &companions);
    }
    for (needle, replacement) in [
        ("held.retire_body(", "held.unproved_retirement("),
        (
            "*retained = slot.credit.take();",
            "drop(slot.credit.take());",
        ),
        ("if credit.is_physically_returned()", "if true"),
    ] {
        rejects(&mutate_body(RETIRED_BODY, needle, replacement), &companions);
    }
    let mut changed = companions.clone();
    let helper = crate::scrub_comments_and_strings(&changed[0]);
    let blocking = RECONCILE_BODY.replace(".try_lock()", ".lock()");
    assert_ne!(blocking, RECONCILE_BODY);
    changed[0] = super::super::replace_one_obligation(
        &helper,
        &super::super::source_pattern(RECONCILE_BODY),
        &blocking,
    );
    assert_ne!(changed[0], helper);
    rejects(&code, &changed);
    for (needle, replacement) in [
        ("returned &= retained.retry_physical_cleanup();", "returned = true;"),
        (".try_lock()", ".lock()"),
        ("slot.source_controller.as_ref()", "slot.foreign_controller.as_ref()"),
    ] {
        rejects(&mutate_body(FAILED_BODIES, needle, replacement), &companions);
    }
    for (index, needle, replacement) in [
        (4, "if Arc::strong_count(&self.shared) != 1", "if false"),
        (4, "gate.seal();", "drop(gate);"),
        (4, "let gate = self.funding.as_ref().map(NativeRosterAllocationFunding::try_open).transpose().ok()?;", "let gate = ();"),
        (4, "shared: Weak<Mutex<NativeRoster>>, funding: Option<NativeRosterAllocationFunding>,", "funding: Option<NativeRosterAllocationFunding>, shared: Weak<Mutex<NativeRoster>>,"),
        (5, "let metadata = self.owner.owner.reserve_metadata(extent)", "let metadata = unrelated.reserve_metadata(extent)"),
        (5, ".checked_add(allocation_bytes)", ".checked_add(16)"),
    ] {
        let mut changed = companions.clone();
        let original = crate::scrub_comments_and_strings(&changed[index]);
        changed[index] = super::super::replace_one_obligation(
            &original, &super::super::source_pattern(needle), replacement,
        );
        assert_ne!(changed[index], original, "mutation missed actual roster funding: {needle}");
        rejects(&code, &changed);
    }
    Ok(())
}
