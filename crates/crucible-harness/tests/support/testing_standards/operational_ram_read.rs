//! Contracts original-work SQLite reads and sticky failure observations.
//!
//! Exact call expressions and counts bind the native snapshot and same failed
//! Work. Changed originals, extra calls, test reruns and unrelated waits remain
//! visible to the existing flaky-input scanner.

use super::{Companion, Contract};

const ORIGINAL_BUSY: &str = r#"fn retry<T>(
    connection: &Connection,
    transactional: bool,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    mut statement: impl FnMut(&mut dyn FnMut() -> Result<(), StoreError>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    loop {
        healthy(quarantined)?;
        boundary()?;
        match statement(boundary) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let busy = match &error {
                    StoreError::StreamIo { source, .. } => source
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<rusqlite::Error>())
                        .is_some_and(|error| {
                            matches!(error,
                            rusqlite::Error::SqliteFailure(code, _) if code.extended_code == 5)
                        }),
                    _ => false,
                };
                // Exact base BUSY is retryable only while the admitted
                // transaction remains active. LOCKED and extended BUSY codes
                // keep their original cause; auto-aborted work is never replayed.
                if !busy || (transactional && connection.is_autocommit()) {
                    return Err(error);
                }
                boundary()?;
                std::thread::yield_now();
            }
        }
    }
}"#;

const MANAGED_LOCK: &str = r#"    pub(in crate::content_store::sqlite) fn try_lock_for(
        &self,
        operation: &'static str,
    ) -> Result<Option<SqliteConnectionGuard<'_>>, StoreError> {
        self.heap.verify_live()?;
        let owner = self
            .connection
            .as_ref()
            .ok_or_else(|| refusal("SQLite connection handle has closed"))?;
        match owner.connection.try_lock() {
            Ok(guard) => {
                self.heap.verify_live()?;
                if guard.is_none() {
                    return Err(refusal("SQLite native connection has closed").into());
                }
                Ok(Some(SqliteConnectionGuard { guard }))
            }
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Poisoned(_)) => Err(StoreError::Poisoned { operation }),
        }
    }"#;

const SNAPSHOT_COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible-cas/src/content_store/sqlite/batch/busy.rs",
        required: &[ORIGINAL_BUSY],
        counts: &[("fn retry<T>(", 1)],
    },
    Companion {
        path: "crates/crucible-cas/src/content_store/sqlite/process_heap/connection.rs",
        required: &[MANAGED_LOCK],
        counts: &[("fn try_lock_for(", 1)],
    },
    Companion {
        path: "crates/crucible-cas/src/content_store/checked_reader.rs",
        required: &[
            r#"original.verify_live().map_err(|error| batch::admission_under(original, error))?;
            boundary()?;
            original.verify_live().map_err(|error| batch::admission_under(original, error))"#,
        ],
        counts: &[("fn check(", 1)],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch/busy/snapshot",
        required: &[
            "original.verify_live()",
            "checked(original, quarantined, boundary)?;",
            "connection.busy_timeout(Duration::ZERO)",
            "let credit = match prepared { Some(credit) => credit, None => Self::prepare(original)?, };",
            "scope.owns_transaction = begun.is_ok();",
            r#"connection.execute_batch("ROLLBACK")"#,
            ".busy_timeout(Duration::from_millis(self.saved_timeout)).err()",
            "if rollback.is_some() || restoration.is_some() { quarantined.store(true, Ordering::Release); }",
            "Ok(value) if rollback.is_none() && restoration.is_none() => Ok((value, credit))",
            "other.err(), rollback, restoration, outcome, credit, None",
        ],
        expressions: &[("retry(connection, false, quarantined, &mut check, |_|", 1)],
        companions: SNAPSHOT_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/bounded_read",
        required: &[
            "super::super::batch::with_id_text(id, |encoded|",
            ".query_row(METADATA, [encoded], |row|",
            "AdmissionEdge::OriginalOnly => original.verify_live()",
            "admit(length)?; if length > maximum",
            "let mut consume = Some(consume);",
            ".prepare(BODY)",
            ".query(rusqlite::params![encoded, length, maximum])",
            "if bytes.len() as u64 != length",
            "let consume = consume.take().ok_or(StoreError::Unsupported",
            "consume(bytes)",
        ],
        expressions: &[("busy::retry(connection, true, quarantined, check, |_|", 2)],
        companions: SNAPSHOT_COMPANIONS,
    },
    // Each repeated read is a single adversarial observation of the SAME
    // already-failed Work. No fixture invocation is repeated to hide failure.
    Contract {
        package: "crucible-cas",
        target: "src/ram/tests/bounded_read",
        required: &[
            r#"let operation = original.child().unwrap();"#,
            r#"let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();"#,
            r#"let first = work.account.read_failure().unwrap();"#,
            r#"assert_eq!((work.visits, work.io_bytes), counts);"#,
            r#"assert_eq!((work.visits, work.io_bytes), before);"#,
            r#"assert_eq!(provider.calls.load(Ordering::SeqCst), 1);"#,
            r#"assert_eq!(provider.calls.load(Ordering::SeqCst), 0);"#,
            r#"assert_eq!(quota.0.usage().unwrap(), credits);"#,
            r#"assert_eq!(quota.0.usage().unwrap(), used,"#,
            r#"assert_eq!(polls, cut,"#,
            r#"assert_eq!(source, &failure);"#,
            r#"namespace.verify_live().unwrap();"#,
            r#"assert_eq!((work.visits, work.io_bytes, quota.0.usage().unwrap()), before);"#,
        ],
        expressions: &[
            (
                r#"fn transfer_task_preserves_first_validation_cleanup_and_sticky_same_work_retry()"#,
                1,
            ),
            (
                r#"fn failed_provider_cannot_erase_first_validation_or_retry_effects()"#,
                1,
            ),
            (
                r#"fn pending_validation_and_complete_provider_failure_keep_original_retry_custody()"#,
                1,
            ),
            (
                r#"fn entry_and_after_success_original_refusals_remain_sticky_before_retry_effects()"#,
                1,
            ),
            (
                r#"let retry = crate::ram::bounded_read::read_canonical_tree(&provider, malformed.regions[0], &response, &mut work,).err().unwrap();"#,
                1,
            ),
            (
                r#"let retry = crate::ram::bounded_read::read_canonical(&provider, root.object_id(), &response, &mut work,).err().unwrap();"#,
                1,
            ),
            (
                r#"let retry = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work).err().unwrap();"#,
                4,
            ),
            (r#"original_error(&retry)"#, 1),
            (
                r#"drop((retry, first, scope, response, malformed, operation));"#,
                1,
            ),
            (
                r#"RamStoreError::Store(StoreError::RamValidation { source: retry }),"#,
                2,
            ),
            (r#") = (retained, retry) else"#, 1),
            (r#") = (first, retry) else"#, 1),
            (r#"assert_eq!(retained, retry);"#, 1),
            (r#"assert_eq!(first, retry)"#, 3),
            (
                r#"let RamStoreError::Store(StoreError::RamReadValidation { source: retry }) = retry else"#,
                1,
            ),
            (r#"assert_eq!(alias, retry);"#, 1),
            (r#"drop(retry);"#, 1),
            (r#"let RamStoreError::Store(retry) = retry else"#, 1),
            (r#"match (&first, &retry)"#, 1),
            (r#"StoreError::RamValidation { source: retry },"#, 1),
            (r#"StoreError::RamReadBoundary { source: retry },"#, 1),
            (r#"drop((first, retry, error, operation));"#, 1),
            (
                r#"let RamStoreError::Store(StoreError::RamValidation { source: retry }) = retry else"#,
                1,
            ),
            (r#"assert_eq!(first, &retry);"#, 1),
            (r#"drop((error, retry, provider));"#, 1),
        ],
        companions: &[Companion {
            path: "crates/crucible-cas/src/ram/bounded_read.rs",
            required: &[
                "if let Some(first) = work.account.read_failure() { return Err(first.into()); }",
                "if let Err(error) = work.original().verify_live()",
                "(ReadPhase::Failed, Err(error)) => Err(self.work.account.reconcile_failed_read(error))",
                "let previous = std::mem::replace(&mut self.state.phase, ReadPhase::Consumed);",
            ],
            counts: &[(
                "let previous = std::mem::replace(&mut self.state.phase, ReadPhase::Consumed);",
                1,
            )],
        }],
    },
    // Single adversarial observations of the same already-failed sender/Work.
    // Original cause, counters, native outcome and loans remain unchanged.
    Contract {
        package: "crucible-cas",
        target: "src/ram/tests/wire_state",
        required: &[
            r#"let operation = original.child().unwrap();"#,
            r#"let mut sender = sender(&store, &root, &operation);"#,
            r#"Some(RamStoreError::Canceled)"#,
            r#"RamStoreError::Store(StoreError::RamBoundary { .. })"#,
            r#"(sender.state_for_test().0, sender.state_for_test().1, sender.state_for_test().2), (0, 0, 0)"#,
            r#"assert_eq!(polls, 1);"#,
            r#"let mut account = super::super::store_boundary::WorkAccount::new(&operation).unwrap();"#,
            r#"let first = account.checked(&mut || { polls += 1; Err(RamStoreError::Canceled) }, |_, boundary| boundary(),).unwrap_err();"#,
            r#"drop(account);"#,
            r#"original.verify_live().unwrap();"#,
            r#"for refused_poll in [2, 9]"#,
            r#"let response = operation.child().unwrap();"#,
            r#"let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();"#,
            r#"assert_eq!(polls.get(), refused_poll);"#,
            r#"assert!(charged_at_refusal.get() >= baseline + 18 * (8 << 20));"#,
            r#"assert_eq!(quota.0.usage().unwrap().1, baseline,"#,
            r#"assert!(quota.0.usage().unwrap().1 >= baseline + 18 * (8 << 20));"#,
            r#"scope.outcome(), crate::content_store::SqliteCommitOutcome::NotCommitted"#,
            r#"assert!(scope.rollback_failure().is_none());"#,
            r#"assert!(scope.restoration_failure().is_none());"#,
            r#"assert!(scope.blob_close_failure().is_none());"#,
            r#"assert!(scope.metadata_completion_failure().is_none());"#,
            r#"assert!(scope.metadata_finalization_failure().is_none());"#,
            r#"drop(work);"#,
        ],
        expressions: &[
            (
                r#"fn sender_retry_retains_the_actual_callback_cause_without_polling_or_reading()"#,
                1,
            ),
            (
                r#"let retry = sender.respond(want(&root), &mut || { panic!("failed operation cannot poll again") }).err().unwrap();"#,
                1,
            ),
            (
                r#"let RamStoreError::Store(StoreError::RamReadBoundary { source: retry }) = retry else"#,
                1,
            ),
            (r#"assert_eq!(first, retry);"#, 2),
            (r#"drop((sender, retry, first, operation));"#, 1),
            (
                r#"let retry = account.checked::<()>(&mut || panic!("sticky operation must not poll again"), |_, _| panic!("sticky operation must not enter another provider"),).unwrap_err();"#,
                1,
            ),
            (r#"let RamStoreError::Boundary(retry) = retry else"#, 1),
            (r#"drop((retry, first, operation));"#, 1),
            (
                r#"let retry = super::super::bounded_read::read_canonical(store.backend.as_ref(), root.object_id(), &response, &mut work,).unwrap_err();"#,
                1,
            ),
            (
                r#"let RamStoreError::Store(StoreError::RamReadBoundary { source: retry_cause }) = &retry else"#,
                1,
            ),
            (r#"assert_eq!(source, retry_cause);"#, 1),
            (r#"drop((retry, error, response, operation));"#, 1),
        ],
        companions: &[
            Companion {
                path: "crates/crucible-cas/src/ram/send.rs",
                required: &[
                    r#"if let Some(error) = self.state.as_ref().and_then(|state| state.read_failure()) { return Err(error.into()); }"#,
                    r#"if let Err(error) = self.check_state() { return Err(self.seal_transport_error(error)); }"#,
                    r#"work: Some(Work::from_retained(self.store.limits, &self.original, boundary, state, self.visits, self.io_bytes,))"#,
                    r#"Err(error) if work.account.read_failure().is_none() => { Err(work.account.fail_read(error).into()) }"#,
                    r#"*self.visits = work.visits; *self.io_bytes = work.io_bytes; *self.state = Some(work.account.into_retained());"#,
                ],
                counts: &[(r#"Work::from_retained("#, 1)],
            },
            Companion {
                path: "crates/crucible-cas/src/ram/store_boundary.rs",
                required: &[
                    r#"if let Some(first) = &self.state.first_failure { return Err(match first { FirstReadCause::Boundary(failure) => RamStoreError::Boundary(failure.clone()), first => first.error().into(), }); }"#,
                    r#"(Some(first), Err(storage @ StoreError::RamBoundary { .. })) => { Err(self.retain_boundary(first, storage)) }"#,
                    r#"self.state.first_failure = Some(FirstReadCause::Boundary(cause.clone()));"#,
                ],
                counts: &[(r#"fn retain_boundary("#, 1)],
            },
            Companion {
                path: "crates/crucible-cas/src/ram/bounded_read.rs",
                required: &[
                    r#"if let Some(first) = work.account.read_failure() { return Err(first.into()); }"#,
                    r#"if let Err(error) = work.original().verify_live()"#,
                    r#"return Err(work.account.fail_read(error).into());"#,
                ],
                counts: &[(r#"pub(super) fn read_canonical("#, 1)],
            },
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::super::{mask_with_companions, pattern, read_companions};
    use super::*;

    fn findings(contract: &Contract, source: &str, companions: &[String]) -> Vec<String> {
        let code = super::super::super::super::scrub_comments_and_strings(source);
        let masked = mask_with_companions(contract, &code, companions);
        super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &masked)
    }

    #[test]
    fn original_sql_reads_and_sticky_observations_reject_drift_and_extra_attempts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let companions = read_companions(contract)?;
            let code = super::super::super::super::scrub_comments_and_strings(&source);
            let compact = pattern(&code);
            for obligation in contract.required {
                assert!(
                    compact.contains(&pattern(obligation)),
                    "{}: {obligation}",
                    contract.target
                );
            }
            for (expression, count) in contract.expressions {
                assert_eq!(
                    compact.matches(&pattern(expression)).count(),
                    *count,
                    "{}: {expression}",
                    contract.target
                );
            }
            let observed = findings(contract, &source, &companions);
            assert!(observed.is_empty(), "{}: {observed:?}", contract.target);
            assert!(!findings(contract, &source, &[]).is_empty());

            for obligation in contract.required {
                let obligation = pattern(obligation);
                let changed = compact.replace(&obligation, "removed_original_obligation()");
                assert!(!findings(contract, &changed, &companions).is_empty());
            }
            for (expression, _) in contract.expressions {
                let expression = pattern(expression);
                let extra = format!("{compact}\n{expression}");
                assert!(!findings(contract, &extra, &companions).is_empty());
                let changed = compact.replacen(&expression, "changed_retry_call()", 1);
                assert!(!findings(contract, &changed, &companions).is_empty());
            }
            for extra in [
                "retry_failed_test();",
                "loop { retry_failed_test(); }",
                "std::thread::sleep(unbounded);",
            ] {
                assert!(!findings(contract, &format!("{source}\n{extra}"), &companions).is_empty());
            }
            for (index, binding) in contract.companions.iter().enumerate() {
                for obligation in binding.required {
                    let mut changed = companions.clone();
                    let code = pattern(&changed[index]);
                    let obligation = pattern(obligation);
                    assert!(code.contains(&obligation));
                    changed[index] = code.replace(&obligation, "changed_original_helper()");
                    assert!(!findings(contract, &source, &changed).is_empty());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn sqlite_read_contracts_reject_foreign_accounts_late_checks_and_changed_busy_roles()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::super::workspace_root();
        for contract in &CONTRACTS[..2] {
            let source = std::fs::read_to_string(
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let companions = read_companions(contract)?;
            let changed = source.replace("original", "foreign_account");
            assert!(!findings(contract, &changed, &companions).is_empty());

            let changed = source
                .replace("quarantined, check, |_|", "quarantined, foreign_check, |_|")
                .replace(
                    "quarantined, &mut check, |_|",
                    "quarantined, &mut foreign_check, |_|",
                );
            assert!(!findings(contract, &changed, &companions).is_empty());
            let changed = if contract.target.ends_with("snapshot") {
                source.replace(
                    "connection, false, quarantined",
                    "connection, true, quarantined",
                )
            } else {
                source.replace(
                    "connection, true, quarantined",
                    "connection, false, quarantined",
                )
            };
            assert!(!findings(contract, &changed, &companions).is_empty());

            let mut late = companions.clone();
            late[0] = late[0]
                .replace(
                    "boundary()?;\n        match statement(boundary)",
                    "match statement(boundary)",
                )
                .replace(
                    "Ok(value) => return Ok(value),",
                    "Ok(value) => { boundary()?; return Ok(value); },",
                );
            assert_ne!(late[0], companions[0]);
            assert!(!findings(contract, &source, &late).is_empty());
        }
        Ok(())
    }
}
