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
    assert!(Arc::ptr_eq(
        roster
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?,
        &held
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
        let state = Arc::get_mut(held)
            .ok_or(OriginalActorAccountError::Unavailable)?
            .get_mut()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        for slot in &state.slots {
            verify_closed_slot(slot)?;
            if let Some(credit) = &slot.credit {
                credit.require_return_phase()?;
            }
        }

        for (slot, retained) in state.slots.iter_mut().zip(&mut self.retiring_credits) {
            *retained = slot.credit.take();
        }
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

const RECONCILE_BODY: &str = r#"pub fn retry_unsettled(&mut self) -> Result<(), QemuVmRealizationError> {
    let held = self
        .held
        .as_ref()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
    // Contention must not wait beyond the caller's saved Cleanup.
    // Refusal leaves the same roster and every physical owner untouched.
    let mut state = held
        .try_lock()
        .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
    for slot in &mut state.slots {
        fork_target::retry_unsettled_target(slot)?;
        if slot.fork_target.is_owned() || slot.unsettled.is_none() {
            continue;
        }
        let cleanup = retain_cleanup(slot).map_err(original_error)?;
        slot.unsettled
            .as_mut()
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
            .finish(&cleanup)?;
        close_slot(slot).map_err(original_error)?;
        slot.unsettled = None;
    }
    Ok(())
}"#;

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
    self.retire_with_post_free(|| {})
}"#,
            1,
        ),
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
    expressions: &[(HELD_TEST, 1)],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
            required: &[
                (RECONCILE_BODY, 1),
                (
                    r#"fn retain_cleanup(
    slot: &mut NativeSlot,
) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    if slot.cleanup.is_none() {
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // The guard Arc is within the already admitted TOTAL metadata. The
        // finite supervisor BTree was charged once as initial actor structure.
        let extent = cleanup_control_extent()?;
        if let Some(purpose) = slot.installed_process.as_mut()
            && !purpose.consume_cleanup(extent)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        slot.require_metadata_assignment(extent)?;
        // Returned guard aliases may outlive a closed generation. Keep each
        // assigned body charged until whole-roster retirement, rather than
        // treating completion or dropping this slot's alias as physical free.
        slot.cleanup_controls_bytes = slot
            .cleanup_controls_bytes
            .checked_add(extent)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.cleanup = Some(Arc::new(credit.begin_cleanup()?));
    }
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.wait_slice()?;
    Ok(Arc::clone(cleanup))
}"#,
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
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/native_account.rs",
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
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: super::super::TARGET_CLEANUP_REQUIRED,
        },
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
        ("assert!(Arc::ptr_eq(", "unproved_identity(Arc::ptr_eq("),
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
        ("Arc::get_mut(held)", "Arc::make_mut(held)"),
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
    Ok(())
}
