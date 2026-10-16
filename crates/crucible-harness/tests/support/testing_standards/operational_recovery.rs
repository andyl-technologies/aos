//! Binds single-attempt recovery names to retained-custody controls.
//!
//! Exact identifier counts admit the reviewed observations only. Removing a
//! custody assertion or adding another attempt leaves the retry token visible.
//! These local controls establish no live native Source or lifecycle authority.

use super::{compact_code, identifier_count, mask_identifier, source_pattern};

struct Contract {
    package: &'static str,
    target: &'static str,
    required: &'static [&'static str],
    identifiers: &'static [(&'static str, usize)],
}

const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-cas",
        target: "src/ram/tests/packed_volume/archive_sender",
        required: &[
            r#"let visits = sender.state_for_test().1;"#,
            r#"let RamStoreError::Store(StoreError::RamValidation { source: first }) = error else"#,
            r#"first.storage_failure(), RamStoreError::Limit("transfer requests")"#,
            r#"let retry = sender.respond(want, &mut || { panic!("a failed sender cannot poll or read again") }).err().unwrap();"#,
            r#"assert_eq!(first, retry);"#,
            r#"assert_eq!(sender.state_for_test().1, visits);"#,
            r#"PreparedRamFailure::<std::convert::Infallible>::allocation_bytes().unwrap()"#,
            r#"drop((first, retry)); assert_eq!(fixture.quota.0.usage().unwrap(), baseline);"#,
        ],
        identifiers: &[("retry", 5)],
    },
    Contract {
        package: "crucible-cas",
        target: "src/ram/tests/packed_volume/pending_publication",
        required: &[
            r#"Arc::get_mut(envelope).unwrap().body_mut()[36] ^= 1;"#,
            r#"matches!(error, RamStoreError::Store(StoreError::Corrupt { id: found }) if found == id)"#,
            r#"assert_eq!(pending.len(), 1);"#,
            r#"assert_eq!(pending.sorted_positions, positions);"#,
            r#"assert_eq!(pending.encoded_bytes, encoded);"#,
            r#"assert_eq!(fixture.quota.0.usage().unwrap(), held);"#,
            r#"assert_eq!(work.pending.as_ref().unwrap().len(), 1);"#,
        ],
        identifiers: &[(
            "pending_duplicate_still_compares_exact_envelope_and_preserves_retry_state",
            1,
        )],
    },
    Contract {
        package: "crucible-qemu",
        target: "src/node/exact_snapshot/capture_original/tests",
        required: &[
            r#"assert_eq!(owner.enter(&replacement).unwrap_err(), first);"#,
            r#"assert_eq!(body.native_transfer.as_ref().unwrap().cancellation.as_raw_fd(), alias);"#,
            r#"supervisor.cancel().unwrap(); let retry = owner.prepare_receiving(&registration(&account, Arc::new(UnavailableRegistrar))).unwrap_err();"#,
            r#"assert_eq!(retry.source, refusal.source); assert!(retry.original_after.is_some());"#,
            r#"assert_eq!(body.first_refusal, Some(refusal)); assert_eq!(body.basis.unwrap(), basis);"#,
            r#"assert_eq!(owner.receiver_custody, ReceiverCustody::Receiving);"#,
            r#"assert!(account.reserve_resources(0, 1, 1).is_err());"#,
            r#"assert_eq!(retry.source, first.source); assert!(retry.original_after.is_some());"#,
            r#"assert_eq!(owner.body.as_ref().unwrap().first_refusal, Some(first));"#,
            r#"assert_eq!(retry, first);"#,
            r#"assert!(owner.body.as_ref().unwrap().native_transfer.is_none());"#,
            r#"assert!(owner.body.as_ref().unwrap().basis.is_none());"#,
            r#"assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);"#,
        ],
        identifiers: &[
            ("retry", 8),
            (
                "receiving_retry_cannot_replace_basis_or_alias_after_refusal",
                1,
            ),
        ],
    },
    Contract {
        package: "crucible-qemu",
        target: "src/qmp/checkpoint_begin/tests",
        required: &[
            r#"client.bind_checkpoint_original(original).unwrap();"#,
            r#"Err(QmpError::MalformedTypedResponse { .. })"#,
            r#"assert!(client.poisoned);"#,
            r#"let before = client.stream.get_ref().output.len(); assert!(client.begin_checkpoint_receiving(arm).is_err()); assert_eq!(client.stream.get_ref().output.len(), before);"#,
        ],
        identifiers: &[(
            "begin_refuses_a_mismatched_or_absent_connection_receipt_and_poisoning_blocks_retry",
            1,
        )],
    },
    Contract {
        package: "crucible-qemu",
        target: "src/qmp/checkpoint_original_wait/tests",
        required: &[
            r#"let id = original.guard.status().unwrap().operation_id;"#,
            r#"budgets.classes[HostOperationClass::Quiescence as usize].total_timeout = Some(Duration::from_nanos(1));"#,
            r#"assert!(matches!(first.source, QmpError::CheckpointOriginal { .. })); assert!(first.original_after.is_some()); assert!(client.poisoned);"#,
            r#"assert!(matches!(retry.source, QmpError::ConnectionPoisoned));"#,
            r#"assert_eq!(retry.original_after, first.original_after);"#,
            r#"assert_eq!(client.stream.get_ref().written.len(), before);"#,
            r#"assert_eq!(original.guard.status().unwrap().operation_id, id);"#,
            r#"assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);"#,
        ],
        identifiers: &[
            (
                "amended_original_expiration_prevents_retry_without_new_start_or_write",
                1,
            ),
            ("retry", 3),
        ],
    },
    Contract {
        package: "crucible-qemu",
        target: "src/spawn/source_supervision/parent_park_return/tests",
        required: &[
            r#"action.retain_park_return(verified, 0).unwrap(); action.park_members_returned_mask = 1; action.retain_park_return(verified, 1).unwrap();"#,
            r#"assert_eq!(action.park_members_returned_mask, 1);"#,
            r#"assert_eq!(action.observation.borrowed_mask, 3);"#,
            r#"assert_eq!(action.verified_park_return, Some(verified));"#,
            r#"assert_eq!(verified.journal.first, -5);"#,
            r#"assert_eq!(verified.journal.original_statuses, [-125, -110]);"#,
            r#"verified.completed_requests = 2; assert!(action.retain_park_return(verified, 0).is_err());"#,
            r#"verified.journal.post = -4; assert!(action.retain_park_return(verified, 0).is_err());"#,
            r#"assert_eq!(action.verified_park_return, Some(evidence()));"#,
        ],
        identifiers: &[
            ("retry_keeps_same_evidence_and_actual_host_unlink_state", 1),
            (
                "new_closure_requires_advancement_but_retry_cannot_change_it",
                1,
            ),
        ],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/scheduling/checkpoint/tests",
        required: &[
            r#".completion_errno.store(libc::ECANCELED, Ordering::SeqCst);"#,
            r#"queue.finish_receipt(9, || panic!("uncertain completion must not retry")).is_err()"#,
            r#"queue.release_checkpoint(1, || panic!("uncertain receipt must remain held")).is_err()"#,
            r#"assert!(Arc::ptr_eq(&operation.upgrade().unwrap(), &queue.receipt.as_ref().unwrap().operation));"#,
            r#"assert!(queue.capture.disposition_uncertain);"#,
            r#"assert!(queue.capture.completed_receipt.is_none());"#,
            r#"assert!(queue.capture.require_open().is_err());"#,
            r#"assert_eq!(counts.completed.load(Ordering::SeqCst), 1);"#,
            r#"assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);"#,
        ],
        identifiers: &[(
            "negative_completion_after_its_effect_retains_the_receipt_without_retry",
            1,
        )],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/callback_child/publication/tests",
        required: &[
            r#"cuts.begin_status = -libc::EKEYEXPIRED; cuts.return_status = -libc::EBUSY;"#,
            r#"assert_eq!(first, Err(super::super::status_error(-libc::EKEYEXPIRED)));"#,
            r#"assert_eq!(owner.loan, token()); assert_eq!(owner.serial, 9);"#,
            r#"assert_eq!(retry, Err(super::super::status_error(-libc::EBUSY)));"#,
            r#"assert_eq!(cuts.begins, 1); assert_eq!(cuts.currents, 0);"#,
            r#"cuts.return_status = 0; cuts.consume = true;"#,
            r#"assert!(owner.identity_return().is_ok()); assert!(!owner.retained());"#,
        ],
        identifiers: &[("retry", 2)],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/callback_child/tests",
        required: &[
            r#"CUTS.with_borrow_mut(|cuts| cuts.create_status = -libc::ENOMEM);"#,
            r#"assert_eq!(first, Err(status_error(-libc::ENOMEM)));"#,
            r#"assert_eq!(owner.projection, token()); assert!(owner.retains_storage());"#,
            r#"assert_eq!(retry, Err(status_error(-libc::EALREADY)));"#,
            r#"assert_eq!(cuts.creates, 1); assert_eq!(cuts.initializes, 0);"#,
        ],
        identifiers: &[
            (
                "born_negative_child_allocation_retains_projection_and_closes_retry",
                1,
            ),
            ("retry", 2),
        ],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/fingerprint_worker/tests",
        required: &[
            r#"unsafe { worker.hold_workspace_for_fork() }.unwrap();"#,
            r#"assert!(enqueue(worker.control.as_ref().unwrap(), 64).is_ok());"#,
            r#"assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());"#,
            r#"assert_eq!(worker.fork_workspace.get_mut().as_ref().unwrap().descriptor_number(), retained);"#,
            r#"assert!(worker.control.as_ref().unwrap().workspace().is_none());"#,
            r#"assert_eq!(worker.control.as_ref().unwrap().lock().pending.as_ref().unwrap().capture_request, 64);"#,
        ],
        identifiers: &[(
            "already_held_workspace_cannot_bless_a_retry_with_retained_capture",
            1,
        )],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/park_return/tests",
        required: &[
            r#"let progress = writer.write(&slot, &bytes); slot.retain_action_frontier(2).unwrap(); let retry = writer.write(&slot, &bytes);"#,
            r#"assert_eq!(progress.first_status, -libc::EIO);"#,
            r#"assert_eq!(progress.publication_uncertain, 1);"#,
            r#"assert_eq!(retry.first_status, -libc::EALREADY);"#,
            r#"assert_eq!(retry.write_attempted, 0);"#,
            r#"assert_eq!(slot.observe_parent_park_return().unwrap(), None);"#,
            r#"assert_eq!(writer.journal.lock().unwrap().bytes, bytes);"#,
        ],
        identifiers: &[("retry", 3)],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/workspace_mapping/tests",
        required: &[
            r#"creation_status: -libc::ENOKEY, empty_outputs: true,"#,
            r#"Err(DeviceDigestWorkspaceError::Admission { status }) if status == -libc::ENOKEY"#,
            r#"assert!(owner.returned); assert!(owner.attempted);"#,
            r#"assert_eq!(owner.creation_status, Some(-libc::ENOKEY));"#,
            r#"assert_eq!(owner.return_status, None);"#,
            r#"assert!(owner.create_using(7, runtime(), api()).is_err());"#,
            r#"assert!(owner.identity_return().is_ok());"#,
            r#"NATIVE.with(|fixture| assert_eq!(fixture.borrow().calls, ["create"]));"#,
        ],
        identifiers: &[(
            "empty_negative_creation_settles_only_local_custody_without_retry",
            1,
        )],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/startup_source/control_purpose/tests",
        required: &[
            r#"CUTS.with_borrow_mut(|cuts| cuts.null_success = true);"#,
            r#"let expected = Err(StartupSourceError::Ownership { reason: "native fixed control reservation returned no retained holder", });"#,
            r#"assert_eq!(reserve_model(owner), expected); assert_eq!(owner.check_installer_control_purpose(), expected); assert_eq!(reserve_model(owner), expected);"#,
            r#"CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));"#,
        ],
        identifiers: &[(
            "null_success_cannot_admit_birth_or_retry_the_same_attempt",
            1,
        )],
    },
];

pub(super) fn mask(package: &str, target: &str, code: &str) -> String {
    let Some(contract) = CONTRACTS
        .iter()
        .find(|contract| contract.package == package && contract.target == target)
    else {
        return code.to_owned();
    };
    mask_contract(contract, code)
}

fn mask_contract(contract: &Contract, code: &str) -> String {
    let compact = compact_code(code);
    if !contract
        .required
        .iter()
        .all(|part| compact.contains(&source_pattern(part)))
        || !contract
            .identifiers
            .iter()
            .all(|(name, count)| identifier_count(code, name) == *count)
    {
        return code.to_owned();
    }

    let mut masked = code.to_owned();
    for (name, _) in contract.identifiers {
        masked = mask_identifier(&masked, name);
    }
    masked
}

// Keep surrounding lexical boundaries when removing a multiline obligation.
// Compacting the whole source could merge `let` and a surviving local name.
fn remove_obligation(code: &str, obligation: &str) -> String {
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let compact = compact_code(code);
    let occurrences = compact
        .match_indices(obligation)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    let mut changed = code.to_owned();
    for offset in occurrences.into_iter().rev() {
        let start = offsets[offset];
        let end = offsets[offset + obligation.len() - 1] + 1;
        changed.replace_range(start..end, " removed_custody_obligation() ");
    }
    changed
}

#[test]
fn recovery_names_require_custody_and_reject_additional_attempts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::super::workspace_root();
    let has_retry = |code: &str| {
        super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    };
    for contract in CONTRACTS {
        let source = std::fs::read_to_string(
            root.join("crates")
                .join(contract.package)
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = super::super::scrub_comments_and_strings(&source);
        let compact = compact_code(&code);
        assert!(
            has_retry(&code),
            "control has no retry token: {}",
            contract.target
        );
        assert!(
            !has_retry(&mask_contract(contract, &code)),
            "reviewed recovery control drifted: {}",
            contract.target
        );

        for requirement in contract.required {
            let obligation = source_pattern(requirement);
            assert!(compact.contains(&obligation));
            let changed = remove_obligation(&code, &obligation);
            assert!(
                has_retry(&mask_contract(contract, &changed)),
                "removed custody assertion was admitted: {} {requirement}",
                contract.target
            );
        }
        for (name, count) in contract.identifiers {
            assert_eq!(identifier_count(&code, name), *count);
            let extra = format!("{code}\nfn conceal_failure() {{ let {name} = (); }}");
            assert!(
                has_retry(&mask_contract(contract, &extra)),
                "additional reviewed identifier was admitted: {} {name}",
                contract.target
            );
            let called = format!("{code}\nfn conceal_failure() {{ {name}(); }}");
            assert!(
                has_retry(&mask_contract(contract, &called)),
                "invocation of a reviewed name was admitted: {} {name}",
                contract.target
            );
        }
        for addition in [
            "fn conceal_failure() { retry(); }",
            "fn conceal_failure() { retry!(); }",
            "fn conceal_failure() { retry_failed_test(); }",
            "fn conceal_failure() { loop { retry_failed_test(); } }",
        ] {
            let changed = format!("{code}\n{addition}");
            assert!(
                has_retry(&mask_contract(contract, &changed)),
                "test rerun was admitted: {} {addition}",
                contract.target
            );
        }
    }
    Ok(())
}
