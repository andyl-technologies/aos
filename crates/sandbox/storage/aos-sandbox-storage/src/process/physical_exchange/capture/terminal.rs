//! Joins the actual resident worker EOF report to durable full676 completion.
//!
//! Parsed worker fields stay inside this private native interval. The same
//! READY subject, aggregate membership, original Source944 clock law, fresh
//! protected catalog and physical row precede the sole Output commit/readback.
//! The final worker ACK and quiescence remain separate from a Host transport ACK.

use super::*;
use crate::execution_output::{CaptureCompletePersistenceOriginalV2, ExecutionOutputLedgerErrorV1};
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::storage_capture_result::{
    CaptureCompleteRecordDataV2, CaptureCompleteStreamDataV2,
};

type Clock = crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<8>;

#[derive(Clone, Copy)]
enum Failure {
    Payment,
    Before,
    Receive,
    Subject,
    Membership,
    Decode,
    After,
    Catalog,
    Row,
    Record,
    CommitBefore,
    Commit,
    CommitAfter,
    AckBefore,
    Ack,
    AckAfter,
    WaitBefore,
    Wait,
    WaitAfter,
    Quiescence,
}

pub(super) struct CaptureNativeTerminalOriginalV3 {
    entered: bool,
    payment: Option<Result<(), StorageReceivingClosedV1>>,
    clocks: Option<Clock>,
    clock_status: [Option<Result<(), ()>>; 8],
    received: Option<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_status: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    decoded: Option<
        Result<crate::execution_capture_zfs_worker::UnboundCaptureWorkerResultV1, ZfsWorkerError>,
    >,
    catalog:
        Option<Result<crate::state::VerifiedStorageResolverJournalV1, crate::StorageStateError>>,
    row: Option<
        Result<crate::execution_output::ProtectedRetainedOutputV1, ExecutionOutputLedgerErrorV1>,
    >,
    record: Option<Result<CaptureCompleteRecordDataV2, ZfsWorkerError>>,
    persistence: CaptureCompletePersistenceOriginalV2,
    committed: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    ack: Option<Result<[u8; capture_worker::wire::FINAL_ACK_BYTES_V3], ZfsWorkerError>>,
    sent: Option<ZfsWorkerSendAttemptV1>,
    waited: Option<Result<(), aos_sandbox_linux::seqpacket::bounded::BoundedRecordError>>,
    quiescence: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<Failure>,
}

impl CaptureNativeTerminalOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            payment: None,
            clocks: None,
            clock_status: std::array::from_fn(|_| None),
            received: None,
            subject: None,
            membership: ExactCgroupMembershipReadbackV1::new(),
            membership_status: None,
            decoded: None,
            catalog: None,
            row: None,
            record: None,
            persistence: CaptureCompletePersistenceOriginalV2::default(),
            committed: None,
            ack: None,
            sent: None,
            waited: None,
            quiescence: None,
            first: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(
            value: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            Failure::Payment => error(&self.payment),
            Failure::Before => self.clocks.as_ref()?.failure_at_v3(0),
            Failure::After => self.clocks.as_ref()?.failure_at_v3(1),
            Failure::CommitBefore => self.clocks.as_ref()?.failure_at_v3(2),
            Failure::CommitAfter => self.clocks.as_ref()?.failure_at_v3(3),
            Failure::AckBefore => self.clocks.as_ref()?.failure_at_v3(4),
            Failure::AckAfter => self.clocks.as_ref()?.failure_at_v3(5),
            Failure::Receive => error(&self.received),
            Failure::Subject => error(&self.subject),
            Failure::Membership => self.membership.failure().map(|cause| cause as _),
            Failure::Decode => error(&self.decoded),
            Failure::Catalog => error(&self.catalog),
            Failure::Row => error(&self.row),
            Failure::Record => error(&self.record).or_else(|| error(&self.ack)),
            Failure::Commit => self
                .persistence
                .failure()
                .or_else(|| error(&self.committed)),
            Failure::Ack => self.sent.as_ref()?.failure(),
            Failure::Wait => error(&self.waited),
            Failure::Quiescence => error(&self.quiescence),
            Failure::WaitBefore => self.clocks.as_ref()?.failure_at_v3(6),
            Failure::WaitAfter => self.clocks.as_ref()?.failure_at_v3(7),
        }
    }

    fn clock(
        &mut self,
        index: usize,
        lifetime: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> bool {
        let Some(clocks) = self.clocks.as_mut() else {
            return false;
        };
        self.clock_status[index] = Some(clocks.observe_verified_once_v3(index, lifetime));
        matches!(self.clock_status[index], Some(Ok(())))
    }

    // An uncertain append/readback may already have published Complete. Such
    // an original must use authenticated recovery, never an incomplete receipt.
    pub(super) fn complete_publication_entered_v4(&self) -> bool {
        self.committed.is_some()
    }

    pub(super) fn completed_v3(&self) -> Option<CaptureCompleteRecordDataV2> {
        if self.first.is_some()
            || !matches!(self.waited, Some(Ok(())))
            || !matches!(self.quiescence, Some(Ok(())))
        {
            return None;
        }
        self.persistence.completed_data_v2()
    }

    // This consumes neither the resident original nor its final disposal token.
    // Host ACK/posts and actual F death/population/post disposal still follow.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_once_v3(
        &mut self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        native: &NativeCaptureCreateOriginalV3,
        request: &[u8],
        mounted: &capture_worker::wire::CaptureMountedReportDataV3,
        physical_row: ObjectDigest,
        ready: &ReceivedRecord,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        store: &crate::StorageTransactionStore,
        state: &aos_sandbox_controller_domain::Journal,
        output: &mut StorageExecutionOutputCustodyV1,
        settlement: ObjectDigest,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered || settlement.as_bytes() == &[0; 32] {
            return Err(ZfsWorkerError::Authority);
        }
        self.entered = true;
        let lifetime = native.admission_v3().lifetime_v3();
        self.first = Some(Failure::Payment);
        let clock_bytes = Clock::receiving_bytes_v3()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ZfsWorkerError::Authority)?;
        let clock_files = Clock::maximum_retained_files_v3()
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(ZfsWorkerError::Authority)?;
        let clock_shape = aos_sandbox_model::ResourceVector::ZERO
            .with(
                aos_sandbox_model::ResourceDimension::MemoryBytes,
                clock_bytes,
            )
            .with(aos_sandbox_model::ResourceDimension::OpenFiles, clock_files);
        let demand = store
            .receiving_inventory_geometry_v1()
            .and_then(|geometry| geometry.retained_model_demand_v1())
            .map_err(|_| ZfsWorkerError::Authority)?
            .checked_add(
                output
                    .capture_complete_receiving_demand_v3()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            )
            .and_then(|demand| demand.checked_add(clock_shape))
            .map_err(|_| ZfsWorkerError::Authority)?;
        self.payment = Some(worker.reserve_capture_terminal_models_v3(
            state,
            output.ledger().held_journal_for_receiving_v1(),
            lifetime,
            demand,
        ));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        self.clocks = Some(Clock::from_verified_v3(lifetime));
        // The real enclosing held interval has already armed the sole Output
        // post before any Host input. It always finishes after this body and
        // Host ACK; this private engine is never a standalone consumer.
        self.body(
            worker,
            native,
            request,
            mounted,
            physical_row,
            ready,
            anchor,
            store,
            output,
            settlement,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn body(
        &mut self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        native: &NativeCaptureCreateOriginalV3,
        request: &[u8],
        mounted: &capture_worker::wire::CaptureMountedReportDataV3,
        physical_row: ObjectDigest,
        ready: &ReceivedRecord,
        anchor: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        store: &crate::StorageTransactionStore,
        output: &mut StorageExecutionOutputCustodyV1,
        settlement: ObjectDigest,
    ) -> Result<(), ZfsWorkerError> {
        let lifetime = native.admission_v3().lifetime_v3();
        let cutoff = lifetime.ongoing_deadline_v3();
        self.first = Some(Failure::Before);
        if !self.clock(0, lifetime) {
            return Err(worker_entry::retained());
        }
        let observed = (|| {
            self.first = Some(Failure::Receive);
            self.received = Some(receive_zfs_worker_record_v1(
                worker.socket_mut_v2(),
                ZfsWorkerRecordKindV1::MutationResult,
                cutoff,
            ));
            let Some(Ok(record)) = self.received.as_ref() else {
                return Err(worker_entry::retained());
            };
            self.first = Some(Failure::Subject);
            self.subject = Some(verify_same_live_subject(ready.subject(), record.subject()));
            if !matches!(self.subject, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            self.first = Some(Failure::Membership);
            self.membership_status = Some(
                self.membership
                    .capture_once(anchor, record.subject().pidfd()),
            );
            if !matches!(self.membership_status, Some(Ok(()))) {
                return Err(worker_entry::retained());
            }
            self.first = Some(Failure::Decode);
            self.decoded = Some(capture_worker::wire::decode_completed_v3(
                record.payload(),
                request,
                native,
                mounted,
            ));
            if !matches!(self.decoded, Some(Ok(_))) {
                return Err(worker_entry::retained());
            }
            self.first = None;
            Ok(())
        })();
        let after = self.clock(1, lifetime);
        if observed.is_err() {
            return observed;
        }
        if !after {
            self.first = Some(Failure::After);
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Catalog);
        self.catalog = Some(store.verified_resolver_journal());
        let Some(Ok(catalog)) = self.catalog.as_ref() else {
            return Err(worker_entry::retained());
        };
        let resolution = native
            .catalog_resolution_v3()
            .ok_or(ZfsWorkerError::Authority)?;
        let dataset = resolution
            .requirement_v3()
            .verify_present(catalog.physical())
            .map_err(|_| ZfsWorkerError::Authority)?;
        if dataset.binding() != mounted.dataset_binding {
            return Err(ZfsWorkerError::Authority);
        }
        let Some(Ok(result)) = self.decoded.as_ref() else {
            return Err(worker_entry::retained());
        };
        let source = native.admission_v3().source_v3();
        let original = source.original_source_v1();
        self.first = Some(Failure::Row);
        self.row = Some(output.ledger().read_protected_retained_output(
            *original.settlement().execution().as_bytes(),
            *original.settlement().create_operation().as_bytes(),
            original.output_record_digest(),
        ));
        let Some(Ok(row)) = self.row.as_ref() else {
            return Err(worker_entry::retained());
        };
        fn stream(
            value: &crate::execution_capture_writer::UnboundCapturedStreamV1,
        ) -> CaptureCompleteStreamDataV2 {
            CaptureCompleteStreamDataV2 {
                maximum_bytes: value.maximum_bytes,
                captured_bytes: value.captured_bytes,
                truncated: value.truncated,
                content_digest: value.content_digest,
            }
        }
        self.first = Some(Failure::Record);
        self.record = Some({
            let record = CaptureCompleteRecordDataV2 {
                source_digest: source.source_digest_v2(),
                attempt: result.attempt,
                durable_attempt_digest: native.durable_attempt_digest_v3(),
                execution: row.execution(),
                create_operation: row.create_operation(),
                output_record_digest: row.record_digest(),
                claim_digest: row.claim_digest(),
                assignment_digest: row.assignment_digest(),
                dataset_binding: result.dataset_binding,
                mount_id: result.mount_id,
                catalog_generation: dataset.catalog_v3().generation(),
                catalog_digest: dataset.catalog_v3().digest(),
                physical_row_digest: physical_row,
                before_observation_digest: result.before_observation_digest,
                mounted_observation_digest: result.mounted_observation_digest,
                after_observation_digest: result.after_observation_digest,
                worker_request_digest: ObjectDigest::from_bytes(
                    request[request.len() - 32..]
                        .try_into()
                        .map_err(|_| ZfsWorkerError::Authority)?,
                ),
                worker_result_digest: result.result_digest,
                host_settlement_digest: settlement,
                stdout: stream(&result.written.stdout),
                stderr: stream(&result.written.stderr),
            };
            record
                .verify_original_ongoing_v2(
                    source,
                    result.attempt,
                    native.durable_attempt_digest_v3(),
                )
                .and_then(|()| record.encode().map(|_| ()))
                .map(|()| record)
                .map_err(|_| ZfsWorkerError::Authority)
        });
        let Some(record) = self
            .record
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return Err(worker_entry::retained());
        };
        self.first = Some(Failure::Record);
        let Some(Ok(received)) = self.received.as_ref() else {
            return Err(worker_entry::retained());
        };
        self.ack = Some(capture_worker::wire::final_ack_data_v3(
            record.worker_request_digest,
            source.source_digest_v2(),
            received.payload(),
        ));
        self.first = Some(Failure::AckBefore);
        if !self.clock(4, lifetime) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Ack);
        let Some(Ok(ack)) = self.ack.as_ref() else {
            return Err(worker_entry::retained());
        };
        self.sent = Some(send_zfs_worker_record_v1(
            worker.socket_mut_v2(),
            ack,
            ZfsWorkerSendKindV1::CaptureReportAcknowledgment,
            cutoff,
        ));
        let sent = self.sent.as_ref().is_some_and(|sent| sent.is_sent());
        let after = self.clock(5, lifetime);
        if !sent {
            return Err(worker_entry::retained());
        }
        if !after {
            self.first = Some(Failure::AckAfter);
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::WaitBefore);
        if !self.clock(6, lifetime) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Wait);
        self.waited = Some(
            aos_sandbox_linux::seqpacket::bounded::wait_capture_worker_exit_v3(
                ready.subject().pidfd(),
                cutoff,
            ),
        );
        let waited = matches!(self.waited, Some(Ok(())));
        let after = self.clock(7, lifetime);
        if !waited {
            return Err(worker_entry::retained());
        }
        if !after {
            self.first = Some(Failure::WaitAfter);
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Quiescence);
        self.quiescence = Some(worker.observe_capture_precommit_quiescence_v3());
        if !matches!(self.quiescence, Some(Ok(()))) {
            return Err(worker_entry::retained());
        }
        // The private106 ACK acknowledges the exact report only. Actual
        // pidfd death and empty/retired population now precede publication;
        // cold61 never reads a promise of future physical quiescence.
        self.first = Some(Failure::CommitBefore);
        if !self.clock(2, lifetime) {
            return Err(worker_entry::retained());
        }
        self.first = Some(Failure::Commit);
        self.committed =
            Some(output.commit_native_capture_complete_v3(&mut self.persistence, &record));
        let committed = matches!(self.committed, Some(Ok(())));
        let after = self.clock(3, lifetime);
        if !committed {
            return Err(worker_entry::retained());
        }
        if !after {
            self.first = Some(Failure::CommitAfter);
            return Err(worker_entry::retained());
        }
        self.first = None;
        Ok(())
    }
}
