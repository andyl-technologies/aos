//! Binds component Source observations to prepaid custody and actual return.
//!
//! The finite waits observe the same worker or deliberately expire one Cleanup.
//! These controls supply no Main/Source issuer or native profile authority.

use super::{Companion, Contract};

const RECEIPTS: &str = r#"fn immutable_stop_receipts_keep_original_credit_through_actual_header_free() {
        let bytes = StopJournal::peak_bytes().unwrap();
        let account = HostServiceAllocator::new(1, 1, bytes).unwrap();
        let loan = account.reserve_resources(0, 0, bytes).unwrap();
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<StopJournalAllocation>())
            .unwrap();
        let (journal, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
                StopJournal::new(loan)
            });
        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);

        // This component records an actual expired Cleanup. It supplies no
        // Main purpose, worker birth, native join or physical-return receipt.
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Cleanup).unwrap();
        let (revision, mut budgets) = supervisor.budgets().unwrap();
        budgets.classes[HostOperationClass::Cleanup as usize] =
            HostOperationBudget::finite(Duration::from_nanos(1));
        supervisor.update_budgets(revision, budgets).unwrap();
        thread::sleep(Duration::from_millis(1));
        let mut record = StopState::new().history;
        record.observations[0].0 = Some(original.wait_slice().unwrap_err());
        let ((first, alias), counts) = TestAllocationObserver::count(|| {
            let first = journal.snapshot(&record);
            let alias = first.clone();
            (first, alias)
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(std::ptr::eq(&*first, &*alias));

        record.observations[0].1 = Some(original.wait_slice().unwrap_err());
        let ((later, repeated), counts) = TestAllocationObserver::count(|| {
            (journal.snapshot(&record), journal.snapshot(&record))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(std::ptr::eq(&*later, &*repeated));
        assert!(first.observations[0].1.is_none());
        assert!(later.observations[0].1.is_some());
        drop(journal);
        drop(first);
        drop(later);
        drop(repeated);
        assert!(matches!(
            account.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));

        // Both observer channels inspect this same component account.
        let (_, observations) = TestAllocationObserver::observe_controls(
            [&account, &account],
            None,
            [identity, None, None],
            || drop(alias),
        );
        let observed = observations[0].unwrap();
        assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
        let _whole = account.reserve_resources(0, 0, bytes).unwrap();
    }"#;

const CANCELLATION: &str = r#"fn cancellation_observers_keep_prepaid_cause_through_actual_header_free() {
        use std::error::Error;

        let bytes = StopJournal::peak_bytes().unwrap();
        let account = HostServiceAllocator::new(1, 1, bytes).unwrap();
        let loan = account.reserve_resources(0, 0, bytes).unwrap();
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<CancellationCause>())
            .unwrap();
        let (journal, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
                StopJournal::new(loan)
            });
        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);

        let first = std::io::Error::from_raw_os_error(libc::EPIPE);
        let ((cause, alias, receipt), counts) = TestAllocationObserver::count(|| {
            let cause = journal.cancellation_failure(first);
            let alias = cause.clone();
            let mut record = StopState::new().history;
            record.cancellation = Some(cause.clone());
            (cause, alias, journal.snapshot(&record))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(cause, alias);
        assert_eq!(receipt.cancellation.as_ref(), Some(&cause));
        let original = cause
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(original.raw_os_error(), Some(libc::EPIPE));
        let original_identity = std::ptr::from_ref(original);

        // A repeated observation retains the first actual returned error. It
        // creates neither another error body nor another service reservation.
        let (repeated, counts) = TestAllocationObserver::count(|| {
            journal.cancellation_failure(std::io::Error::from_raw_os_error(libc::EINVAL))
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(repeated, cause);
        assert_eq!(
            std::ptr::from_ref(
                repeated
                    .source()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
            ),
            original_identity,
        );

        drop(receipt);
        drop(journal);
        drop(cause);
        drop(repeated);
        assert!(matches!(
            account.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));

        let (_, observations) = TestAllocationObserver::observe_controls(
            [&account, &account],
            None,
            [identity, None, None],
            || drop(alias),
        );
        let observed = observations[0].unwrap();
        assert_eq!(observed.before.original_bytes, [Some(bytes); 2]);
        assert_eq!(observed.after.original_bytes, [Some(bytes); 2]);
        let _whole = account.reserve_resources(0, 0, bytes).unwrap();
    }"#;

const DETACHED: &str = r#"fn detached_close(panic_after_close: bool) {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let gate = Arc::new(ExitGate {
        entered: Barrier::new(2),
        released: Barrier::new(2),
    });
    let backing = Arc::new(GatedBacking {
        backing: ImmutableBacking::new(2).unwrap(),
        gate: Arc::clone(&gate),
        panic_after_close,
    });
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor,
        account.clone(),
        None,
    )
    .unwrap();

    // This is the actual startup inventory Arc; the checked header offset
    // locates its allocation without reading control storage or creating aliases.
    let offset = crate::ram_source::worker_outcome::WorkerOutcome::allocation_header_offset();
    let target = source
        .failure
        .allocation_address()
        .unwrap()
        .checked_sub(offset)
        .and_then(NonZeroUsize::new)
        .unwrap();
    let target = AllocationIdentity::from_address(target);
    let mut worker = source.worker.take().unwrap();

    // Retain only the real join handle, without cloning any loan. Source Drop
    // does not join; the watch owns the same original account until actual join,
    // including a panicking worker, before any registry teardown can begin.
    let ((gated_probe, joined), report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            drop(source);
            gate.entered.wait();
            let gated_probe = account.reserve_resources(0, 0, 1);
            gate.released.wait();

            for _ in 0..5_000 {
                if worker.native.poll().unwrap()
                    == crate::ram_source::NativeJoinObservation::Returned
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(worker.native.last_status(), Some(0));

            let snapshot = worker.outcome.snapshot();
            assert!(snapshot.delivered && !snapshot.uncertain);
            let joined = snapshot.panic.map_or(Ok(()), Err);
            let panicked = joined.is_err();
            // Both actual outcome aliases close before the observed control
            // allocation can free and return its original loan.
            drop(joined);
            drop(worker);
            (gated_probe, panicked)
        })
        .unwrap();

    assert!(matches!(
        gated_probe,
        Err(HostServiceError::CapacityExhausted)
    ));
    assert_eq!(joined, panic_after_close);
    verify_original_refusal(report);
    verify_closed(&account);
}"#;

const UNREAPED: &str = r#"fn unreaped_receiver_retains_the_actual_source_and_unqueried_native_owner() {
    use std::io::Write;
    use crucible_qemu_protocol::ram_page::{
        RamPageRequest, RamPageResponse, RamPageStatus, read_ram_page_response,
    };

    let _serial = TEST_LOCK.lock().unwrap();
    let backing = Arc::new(ImmutableBacking::new(2).unwrap());
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let (socket, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    receiver
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor,
        account.clone(),
        None,
    )
    .unwrap();
    let native_identity = source.worker.as_ref().unwrap().native.thread_id();
    let outcome = source.failure.clone();

    let (_, counts) = TestAllocationObserver::count(|| source.retain_for_unreaped_receiver());

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let retained = outcome
        .retained_live_receiver()
        .unwrap_or_else(|| panic!("unreaped receiver must retain its actual Source facade"));
    let native = &retained.worker.as_ref().unwrap().native;
    assert_eq!(native.thread_id(), native_identity);
    assert_eq!(native.last_status(), None);
    assert_eq!(retained.binding, binding);
    assert!(!retained.cancellation.load(Ordering::Acquire));

    // The receiver still gets an authentic page from the same live worker.
    receiver
        .write_all(
            &RamPageRequest {
                binding,
                sequence: 1,
                region_ordinal: 0,
                page_index: 0,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    let bytes = read_ram_page_response(&mut receiver).unwrap();
    let response = RamPageResponse::decode(&bytes).unwrap();
    assert_eq!(response.binding, binding);
    assert_eq!(response.status, RamPageStatus::Page);
    assert_eq!(response.page.len(), 4096);
    assert!(!response.proof.is_empty());
    drop(receiver);

    for _ in 0..5_000 {
        if outcome.snapshot().delivered {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(outcome.snapshot().delivered);
    let retained = outcome.retained_live_receiver().unwrap();
    assert_eq!(
        retained.worker.as_ref().unwrap().native.thread_id(),
        native_identity
    );
    assert_eq!(retained.worker.as_ref().unwrap().native.last_status(), None);
    assert!(!retained.cancellation.load(Ordering::Acquire));
    drop(outcome);

    // Rust delivery and closing the diagnostic observer do not consume the
    // retained native join authority or refund the actual original account.
    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));
}"#;

const JOURNAL: &str = r#"impl StopJournal {
    pub(super) const fn empty() -> Self {
        Self { shared: None }
    }

    pub(super) fn new(lease: HostServiceLease) -> Self {
        let cancellation = SharedOperationalCause::new(CancellationCause {
            first: OnceLock::new(),
            _lease: lease.clone(),
        });
        Self {
            shared: Some(Arc::new(StopJournalAllocation {
                records: std::array::from_fn(|_| OnceLock::new()),
                cancellation,
                _lease: lease,
            })),
        }
    }

    pub(super) fn peak_bytes() -> Option<u64> {
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<StopJournalAllocation>())
            .ok()?;
        u64::try_from(layout.pad_to_align().size())
            .ok()?
            .checked_add(std::mem::size_of::<StopJournalAllocation>() as u64)?
            .checked_add(std::mem::size_of::<QemuRamSourceStopRecord>() as u64)?
            .checked_add(std::mem::size_of::<QemuRamSourceStopHistory>() as u64)?
            .checked_add(std::mem::size_of::<Self>() as u64)?
            .checked_add(
                u64::try_from(
                    SharedOperationalCause::<CancellationCause>::allocation_bytes().ok()?,
                )
                .ok()?,
            )?
            .checked_add(std::mem::size_of::<CancellationCause>() as u64)?
            .checked_add(std::mem::size_of::<SharedOperationalCause<CancellationCause>>() as u64)
    }

    /// Publishes the original syscall failure from its prepaid shared body.
    pub(super) fn cancellation_failure(&self, first: std::io::Error) -> BackendOperationalCause {
        let Some(journal) = self.shared.as_ref() else {
            unreachable!("only a funded Source can publish cancellation failure");
        };
        journal
            .cancellation
            .source_ref()
            .first
            .get_or_init(|| first);
        journal.cancellation.backend_cause()
    }

    pub(super) fn snapshot(&self, record: &QemuRamSourceStopRecord) -> QemuRamSourceStopHistory {
        let Some(journal) = self.shared.as_ref() else {
            unreachable!("only a funded Source can publish stop observations");
        };
        for (index, slot) in journal.records.iter().enumerate() {
            if slot.get_or_init(|| record.clone()) == record {
                return QemuRamSourceStopHistory {
                    journal: self.clone(),
                    index,
                };
            }
        }
        unreachable!("the prepaid stop journal covers every monotonic observation")
    }
}

impl Drop for StopJournal {
    fn drop(&mut self) {
        if let Some(journal) = self.shared.take() {
            // No Weak alias escapes. The actual header closes before the moved
            // records, their payload aliases and this same original loan.
            drop(Arc::into_inner(journal));
        }
    }
}"#;

const FUNDING: &str = r#"pub(super) fn startup_metadata_bytes() -> Result<u64, QemuRamSourceError> {
        // These concrete startup controls share the same original worker loan.
        // The lease's value is already inside the final worker-error body.
        let lease_control = HostServiceLease::metadata_bytes()
            .checked_sub(std::mem::size_of::<HostServiceLease>() as u64)
            .ok_or(QemuRamSourceError::Ownership)?;
        Self::allocation_bytes()?
            .checked_mul(2)
            .ok_or(QemuRamSourceError::Ownership)?
            .checked_add(lease_control)
            .and_then(|bytes| bytes.checked_add(shared_allocation_bytes::<AtomicBool>().ok()?))
            .and_then(|bytes| {
                bytes.checked_add(
                    super::worker_outcome::WorkerOutcome::allocation_peak_bytes().ok()?,
                )
            })
            .and_then(|bytes| bytes.checked_add(super::stop::StopState::journal_peak_bytes()?))
            .ok_or(QemuRamSourceError::Ownership)
    }"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-host",
        target: "src/ram_source/stop/history",
        required: &[RECEIPTS, CANCELLATION, JOURNAL],
        expressions: &[("thread::sleep(Duration::from_millis(1));", 1)],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/ram_source/worker_failure.rs",
            required: &[FUNDING],
            counts: &[("fn startup_metadata_bytes()", 1)],
        }],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/ram_source/worker_failure/tests/worker_scope",
        required: &[DETACHED, UNREAPED],
        expressions: &[
            (
                r#"for _ in 0..5_000 {
                if worker.native.poll().unwrap()
                    == crate::ram_source::NativeJoinObservation::Returned
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }"#,
                1,
            ),
            (
                r#"for _ in 0..5_000 {
        if outcome.snapshot().delivered {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }"#,
                1,
            ),
        ],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/ram_source/worker_failure.rs",
            required: &[FUNDING],
            counts: &[("fn startup_metadata_bytes()", 1)],
        }],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_wait(source: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", source)
            .iter()
            .any(|finding| finding.contains("thread::sleep"))
    }

    #[test]
    fn source_component_waits_require_actual_owners_and_finite_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::workspace_root();
        for contract in CONTRACTS {
            let path = crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target));
            let source = std::fs::read_to_string(path)?;
            let code = crate::scrub_comments_and_strings(&source);
            let companions = read_companions(contract)?;
            assert!(has_wait(&code));
            assert!(!has_wait(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            assert!(
                crate::flaky_escape_failures(contract.package, contract.target, &source).is_empty()
            );

            for (expression, _) in contract.expressions {
                let extra = format!("{code}\nfn extra_wait() {{ {expression} }}");
                assert!(has_wait(&mask_with_companions(
                    contract,
                    &extra,
                    &companions
                )));
            }
            for (index, companion) in contract.companions.iter().enumerate() {
                for required in companion.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] =
                        changed[index].replacen(required, "removed_original_funding();", 1);
                    assert!(has_wait(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn source_component_waits_reject_invented_receipts_and_foreign_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::workspace_root();
        for (index, body, before, after) in [
            (
                0,
                RECEIPTS,
                "HostOperationBudget::finite(Duration::from_nanos(1))",
                "HostOperationBudget::finite(Duration::from_secs(1))",
            ),
            (
                0,
                CANCELLATION,
                "let alias = cause.clone();",
                "let alias = foreign.clone();",
            ),
            (
                0,
                CANCELLATION,
                "drop(journal);",
                "std::mem::forget(journal);",
            ),
            (
                0,
                CANCELLATION,
                "observed.after.original_bytes",
                "observed.before.original_bytes",
            ),
            (1, DETACHED, "drop(source);", "drop(foreign_source);"),
            (
                1,
                DETACHED,
                "worker.native.last_status(), Some(0)",
                "worker.native.last_status(), None",
            ),
            (1, DETACHED, "drop(joined);", "std::mem::forget(joined);"),
            (
                1,
                DETACHED,
                "verify_original_refusal(report);",
                "verify_original_refusal(foreign_report);",
            ),
            (
                1,
                UNREAPED,
                "source.retain_for_unreaped_receiver()",
                "drop(source)",
            ),
            (
                1,
                UNREAPED,
                "native.thread_id(), native_identity",
                "native.thread_id(), foreign_identity",
            ),
            (
                1,
                UNREAPED,
                "native.last_status(), None",
                "native.last_status(), Some(0)",
            ),
            (1, UNREAPED, "if outcome.snapshot().delivered", "if true"),
            (1, DETACHED, "for _ in 0..5_000", "loop"),
            (1, UNREAPED, "for _ in 0..5_000", "loop"),
        ] {
            let contract = &CONTRACTS[index];
            let path = crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target));
            let source = std::fs::read_to_string(path)?;
            let companions = read_companions(contract)?;
            assert!(
                source.contains(body),
                "missing real body: {}",
                contract.target
            );
            assert!(body.contains(before), "unreached actual mutation: {before}");
            let changed = source.replacen(body, &body.replacen(before, after, 1), 1);
            let code = crate::scrub_comments_and_strings(&changed);
            assert!(
                has_wait(&mask_with_companions(contract, &code, &companions)),
                "changed actual Source custody was classified: {before}"
            );
        }
        Ok(())
    }
}
