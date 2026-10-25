//! Binds component quantum retry observations to retained requests and causes.
//!
//! Repeated observations retain one pending request. Scripted finish refusal
//! exercises the actual driver but grants no native Source or return receipt.

use super::{Companion, Contract};

const FINISH_REFUSAL: &str = r#"fn issued_quantum_finish_refusal_preserves_post_and_cannot_retry()
-> Result<(), Box<dyn std::error::Error>> {
    for retryable in [false, true] {
        let mut target = ScriptedTarget::completed();
        let mut runtime = SupervisedRuntime::new()?;
        target.refuse_finish = Some((runtime.supervisor.clone(), retryable));

        let result = run(&mut target, &mut runtime);

        let QemuAsyncDriverError::ChannelOriginalPost {
            source,
            original_after,
        } = result.expect_err("actual finish and Original refuse")
        else {
            panic!("finish first cause and independent Original must survive");
        };
        assert_eq!(source.operation, "actual finish refusal");
        assert_eq!(source.message(), "first channel cause");
        assert_eq!(source.is_retryable(), retryable);
        assert!(matches!(
            original_after,
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            }
        ));
        assert_eq!(target.started, vec![12]);
        assert_eq!(target.finished, 1);
        assert_eq!(target.shutdowns, 0);
        assert_eq!(runtime.scripted.awaits, 1);
        assert_eq!(runtime.scripted.yields, 1);
    }
    Ok(())
}"#;

const FINISH_FIXTURE: &str = r#"fn finish_quantum(
        &mut self,
        _pending: &mut Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.finished += 1;
        if let Some((supervisor, retryable)) = &self.refuse_finish {
            supervisor.cancel().unwrap();
            return Err(if *retryable {
                QemuNodeChannelError::retryable("actual finish refusal", "first channel cause")
            } else {
                QemuNodeChannelError::new("actual finish refusal", "first channel cause")
            });
        }
        if self.pending_finishes > 0 {
            self.pending_finishes -= 1;
            return Err(QemuNodeChannelError::retryable(
                "finish quantum",
                "plugin report is still in flight",
            ));
        }
        Ok(self.completion.clone())
    }"#;

const CHANNEL_RETURN: &str = r#"fn observe_channel_return<T>(
    result: Result<T, QemuNodeChannelError>,
    original: Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
) -> Result<T, QemuAsyncDriverError> {
    let post = original.and_then(|operation| operation.wait_slice().err());

    match (result, post) {
        (Ok(value), None) => Ok(value),
        (Ok(_), Some(source)) => Err(supervision_error(source)),
        (Err(source), None) => Err(QemuAsyncDriverError::Channel(source)),
        (Err(source), Some(original_after)) => Err(QemuAsyncDriverError::ChannelOriginalPost {
            source,
            original_after,
        }),
    }
}"#;

const HELD_WRITER: &str = r#"fn held_writer_refuses_channel_observers_without_allocating_or_mutating() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);

    for reader in 0..5 {
        // Each mapped channel call uses a fresh temporary adapter. Reusing one
        // would also exercise the separately allocated multi-event log spill.
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let before = slot.snapshot();
        let reservation = slot.reserve_scheduler_advance().unwrap();
        let occupied = reservation.generation() - 1;

        let (error, counts) = TestAllocationObserver::count(|| match reader {
            0 => QemuShmemHotPathChannel::current_icount(&mut hot_path).unwrap_err(),
            1 => QemuShmemHotPathChannel::logical_time_calibration(&mut hot_path).unwrap_err(),
            2 => QemuShmemHotPathChannel::virtual_timer_fire_witness(&mut hot_path).unwrap_err(),
            3 => QemuShmemHotPathChannel::idle_state(&mut hot_path).unwrap_err(),
            4 => QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path).unwrap_err(),
            _ => unreachable!(),
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(error.is_retryable());
        assert!(error.message().is_empty());
        assert_eq!(
            error.quantum_node_slot_source(),
            Some(&NodeSlotError::AdvancePublicationOccupied {
                expected: occupied,
                observed: occupied
            })
        );
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<NodeSlotError>());
        assert_eq!(source, error.quantum_node_slot_source());
        assert_eq!(
            hot_path.operation_log(),
            &[QemuQuantumOperation::ReadNodeReport]
        );
        assert_eq!(inbound_ring.read_index(), 0);
        assert_eq!(outbound_ring.read_index(), 0);

        drop(reservation);
        let after = slot.snapshot();
        assert_eq!(after.advance_publication_sequence, occupied + 1);
        assert_eq!(after.max_advance_icount, before.max_advance_icount);
        assert_eq!(after.wake_signal, before.wake_signal);
    }
}"#;

const PENDING_REFUSAL: &str = r#"fn completion_refusal_retains_same_pending_without_republication_or_allocation() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let mut pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        horizon(10),
        crate::QemuQuantumStopCondition::Ceiling,
    )
    .unwrap();
    let before = slot.snapshot();
    let reservation = slot.reserve_scheduler_advance().unwrap();
    let operation_count = hot_path.operation_log().len();

    let (error, counts) = TestAllocationObserver::count(|| {
        QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap_err()
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(error.is_retryable());
    assert_eq!(
        error.quantum_node_slot_source(),
        Some(&NodeSlotError::AdvancePublicationOccupied {
            expected: 3,
            observed: 3
        })
    );
    assert_eq!(
        &hot_path.operation_log()[operation_count..],
        &[QemuQuantumOperation::ObservePluginReport]
    );
    assert_eq!(inbound_ring.read_index(), 0);
    assert_eq!(outbound_ring.read_index(), 0);

    drop(reservation);
    assert_eq!(slot.snapshot().wake_signal, before.wake_signal);
    slot.publish_reached_icount(10).unwrap();
    let report = QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap();
    assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(slot.snapshot().wake_signal, before.wake_signal);
}"#;

const PENDING_REPORT: &str = r#"fn unpublished_report_poll_preserves_coordinates_without_allocation_or_republication() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut pending = {
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        QemuShmemHotPathChannel::start_quantum(
            &mut hot_path,
            horizon(10),
            crate::QemuQuantumStopCondition::Ceiling,
        )
        .unwrap()
    };
    let published = slot.snapshot();
    let expected = crate::QemuPendingQuantumReport {
        current_icount: 0,
        ceiling: 10,
    };
    let old_message = QemuQuantumError::PluginReportNotPublished {
        current_icount: 0,
        ceiling: 10,
    }
    .to_string();

    for _ in 0..3 {
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let (channel, counts) = TestAllocationObserver::count(|| {
            QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap_err()
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(channel.is_retryable());
        assert_eq!(channel.pending_quantum_report(), Some(&expected));
        assert_eq!(
            channel.to_string(),
            format!("qemu_quantum_shmem_hot_path failed: {old_message}")
        );
        assert_eq!(
            std::error::Error::source(&channel)
                .and_then(|source| source.downcast_ref::<crate::QemuPendingQuantumReport>()),
            Some(&expected)
        );
        assert_eq!(slot.snapshot(), published);
        assert_eq!(
            hot_path.operation_log(),
            &[QemuQuantumOperation::ObservePluginReport]
        );

        let (node, counts) = TestAllocationObserver::count(|| {
            crate::QemuNodeError::from_channel(crate::QemuNodeChannelPlane::ShmemHotPath, channel)
        });
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(
            std::error::Error::source(&node)
                .and_then(|source| source.downcast_ref::<crate::QemuPendingQuantumReport>()),
            Some(&expected)
        );
        let scheduler = crucible_engine::BackendError::from(node);
        assert!(matches!(
            scheduler,
            crucible_engine::BackendError::RetainedOperationalFailure { .. }
        ));
        let mut cause: &(dyn std::error::Error + 'static) = &scheduler;
        let retained = loop {
            if let Some(report) = cause.downcast_ref::<crate::QemuPendingQuantumReport>() {
                break Some(report);
            }
            match cause.source() {
                Some(source) => cause = source,
                None => break None,
            }
        };
        assert_eq!(retained, Some(&expected));
    }

    slot.publish_reached_icount(10).unwrap();
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let report = QemuShmemHotPathChannel::poll_quantum(&mut hot_path, &mut pending).unwrap();
    assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
    let completed = slot.snapshot();
    assert_eq!(completed.wake_signal, published.wake_signal);
    assert_eq!(
        completed.advance_publication_sequence,
        published.advance_publication_sequence
    );
}"#;

const TERMINAL_SLOT: &str = r#"fn actual_terminal_slot_failure_keeps_diagnostic_and_cannot_request_retry() {
    let slot = NodeSlot::default();
    let source = slot.publish_reached_icount(1).unwrap_err();
    let expected = format!(
        "qemu_quantum_shmem_hot_path failed: QEMU quantum node-slot operation actual plugin report failed: {source}"
    );

    let (error, counts) = TestAllocationObserver::count(|| {
        QemuNodeChannelError::from(QemuQuantumError::NodeSlot {
            operation: "actual plugin report",
            source: source.clone(),
        })
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(!error.is_retryable());
    assert_eq!(error.quantum_node_slot_source(), Some(&source));
    assert_eq!(error.to_string(), expected);

    let (node, counts) = TestAllocationObserver::count(|| {
        crate::QemuNodeError::from_channel(crate::QemuNodeChannelPlane::ShmemHotPath, error)
    });
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(
        std::error::Error::source(&node).and_then(|source| source.downcast_ref::<NodeSlotError>()),
        Some(&source)
    );
}"#;

const SLOT_CAUSE: &str = r#"pub(crate) fn quantum_node_slot(
        operation: &'static str,
        source: crucible_qemu_shmem::NodeSlotError,
    ) -> Self {
        Self {
            operation: "qemu_quantum_shmem_hot_path",
            retryable: matches!(
                source,
                crucible_qemu_shmem::NodeSlotError::NodeReportChanged { .. }
                    | crucible_qemu_shmem::NodeSlotError::AdvancePublicationOccupied { .. }
            ),
            detail: ChannelFailureDetail::QuantumNodeSlot { operation, source },
        }
    }"#;

const REPORT_CAUSE: &str = r#"pub(crate) fn quantum_report_pending(current_icount: u64, ceiling: u64) -> Self {
        Self {
            operation: "qemu_quantum_shmem_hot_path",
            retryable: true,
            detail: ChannelFailureDetail::QuantumReportPending(QemuPendingQuantumReport {
                current_icount,
                ceiling,
            }),
        }
    }"#;

const RETRY_OBSERVATION: &str = r#"pub const fn is_retryable(&self) -> bool {
        self.retryable
    }"#;

const CHANNEL_CONVERSION: &str = r#"impl From<QemuQuantumError> for QemuNodeChannelError {
    fn from(error: QemuQuantumError) -> Self {
        match error {
            QemuQuantumError::OperationalSupervision { operation, source } => {
                Self::operational_supervision(operation, source)
            }
            QemuQuantumError::NodeSlot { operation, source } => {
                Self::quantum_node_slot(operation, source)
            }
            QemuQuantumError::PluginReportNotPublished {
                current_icount,
                ceiling,
            } => Self::quantum_report_pending(current_icount, ceiling),
            error => Self::new("qemu_quantum_shmem_hot_path", error.to_string()),
        }
    }
}"#;

const FINISH_DECISION: &str = r#"match observe_channel_return(target.finish_quantum(&mut pending), active_operation) {
            Ok(completion) => {
                observe_health_return(target.operational_health(), active_operation)?;
                check_original(active_operation)?;
                break Some(completion);
            }
            Err(QemuAsyncDriverError::Channel(error)) => {
                observe_health_return(target.operational_health(), active_operation)?;
                if error.is_retryable() {
                    continue;
                }
                return Err(QemuAsyncDriverError::Channel(error));
            }
            Err(error) => return Err(error),
        }"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-host",
        target: "src/async_driver_test/supervision",
        required: &[FINISH_REFUSAL],
        expressions: &[(FINISH_REFUSAL, 1)],
        companions: &[
            Companion {
                path: "crates/crucible/crucible-qemu-host/src/async_driver/driver.rs",
                required: &[CHANNEL_RETURN, FINISH_DECISION],
                counts: &[(CHANNEL_RETURN, 1), (FINISH_DECISION, 1)],
            },
            Companion {
                path: "crates/crucible/crucible-qemu-host/src/async_driver_test.rs",
                required: &[FINISH_FIXTURE],
                counts: &[(FINISH_FIXTURE, 1)],
            },
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/quantum/tests/bounded_observations",
        required: &[HELD_WRITER, PENDING_REFUSAL, PENDING_REPORT, TERMINAL_SLOT],
        expressions: &[
            (HELD_WRITER, 1),
            (PENDING_REFUSAL, 1),
            (PENDING_REPORT, 1),
            (TERMINAL_SLOT, 1),
        ],
        companions: &[
            Companion {
                path: "crates/crucible/crucible-qemu-host/src/node/error.rs",
                required: &[SLOT_CAUSE, REPORT_CAUSE, RETRY_OBSERVATION],
                counts: &[(SLOT_CAUSE, 1), (REPORT_CAUSE, 1), (RETRY_OBSERVATION, 1)],
            },
            Companion {
                path: "crates/crucible/crucible-qemu-host/src/quantum/channel.rs",
                required: &[CHANNEL_CONVERSION],
                counts: &[(CHANNEL_CONVERSION, 1)],
            },
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source(contract: &Contract) -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn quantum_observer_classification_requires_the_actual_owner_and_preserves_added_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        for contract in CONTRACTS {
            let code = source(contract)?;
            let companions = read_companions(contract)?;

            assert!(has_retry(&code));
            assert!(!has_retry(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            let extra = format!("{code}\nfn unrelated_retry() {{ loop {{ retry(); }} }}");
            assert!(has_retry(&mask_with_companions(
                contract,
                &extra,
                &companions
            )));

            for (index, binding) in contract.companions.iter().enumerate() {
                for required in binding.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] = changed[index].replacen(required, "foreign();", 1);
                    assert!(has_retry(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn quantum_observer_classification_rejects_changed_effects_and_refusal_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        for (index, before, after) in [
            (
                0,
                "runtime.supervisor.clone()",
                "HostOperationSupervisor::default()",
            ),
            (
                0,
                "assert_eq!(target.finished,1);",
                "assert_eq!(target.finished,2);",
            ),
            (
                0,
                "assert_eq!(runtime.scripted.awaits,1);",
                "assert_eq!(runtime.scripted.awaits,2);",
            ),
            (
                1,
                "assert!(error.is_retryable());",
                "assert!(!error.is_retryable());",
            ),
            (
                1,
                "assert!(channel.is_retryable());",
                "assert!(!channel.is_retryable());",
            ),
            (
                1,
                "assert!(!error.is_retryable());",
                "assert!(error.is_retryable());",
            ),
            (
                1,
                "assert_eq!(slot.snapshot(),published);",
                "slot.publish_reached_icount(1).unwrap();",
            ),
            (
                1,
                "assert_eq!(counts.allocations,0);",
                "assert_eq!(counts.allocations,1);",
            ),
        ] {
            let contract = &CONTRACTS[index];
            let code = super::super::compact_code(&source(contract)?);
            let companions = read_companions(contract)?;

            assert!(
                code.contains(before),
                "missing actual refusal cut: {before}"
            );
            // Change the reviewed owner, rather than an earlier test that
            // happens to contain the same assertion or supervisor expression.
            let owner = contract
                .required
                .iter()
                .find_map(|required| {
                    let required =
                        super::super::compact_code(&crate::scrub_comments_and_strings(required));
                    required.contains(before).then_some(required)
                })
                .unwrap_or_else(|| panic!("missing reviewed owner for cut: {before}"));
            let changed = code.replacen(&owner, &owner.replacen(before, after, 1), 1);
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &companions)),
                "changed refusal was classified: {before}"
            );
        }
        Ok(())
    }
}
