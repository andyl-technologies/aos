//! Captures the genuine fresh Source22 coordinates before the sole Root stream.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::{
    execution_no_apply::acquisition::encode_acquisition_raw_pair_data_v2,
    finality_recover::OBSERVATION_ADMISSION_KEY_BYTES_V1,
};

pub(super) struct Opening {
    admission_key: [u8; OBSERVATION_ADMISSION_KEY_BYTES_V1],
    admission: [u8; 32],
    recover_original: [u8; 48],
    recover_cutoff: [u8; 8],
    recover_wall_expiry: [u8; 8],
    cleanup: [u8; 16],
    controller_first: [u8; 48],
    cleanup_cutoff: [u8; 8],
    source_parent: [u8; 32],
    pub(super) host: HostReference,
    query: [u8; QUERY_BYTES_V1],
}

impl Opening {
    fn subject(&self) -> StopCleanupSubjectDataV1<'_> {
        StopCleanupSubjectDataV1 {
            admission_key: &self.admission_key,
            admission: &self.admission,
            recover_original: &self.recover_original,
            recover_cutoff: &self.recover_cutoff,
            recover_wall_expiry: &self.recover_wall_expiry,
            cleanup: &self.cleanup,
            controller_first: &self.controller_first,
            cleanup_cutoff: &self.cleanup_cutoff,
            source_parent: &self.source_parent,
            host_query: &self.host.0,
            host_session: &self.host.1,
            host_request: &self.host.2,
            host_outcome: &self.host.3,
            host_body: &self.host.4,
        }
    }
}

impl RootStopCleanupClientOriginalV1 {
    /// Opens one actual Root connection from the current paid fresh Stop22 owner.
    ///
    /// # Errors
    /// Retains Source, capacity, peer, framing and temporal refusals, draining
    /// every already entered Root after independently of the primary result.
    pub fn begin_once_v1(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        if self.entry.is_some() {
            return Err(self.refuse_reentry());
        }
        let profile = source.root_profile_arc_v1();
        self.entry = Some((|| {
            source.require_current_v1(controller)?;
            self.complete = Self::demand(&profile)?;
            let whole = self
                .complete
                .checked_add(resource_stream::peer_traffic_v1(BOOKENDS)?)?;
            let debit = source.admit_root_transport_complete_v1(controller, whole);
            if debit.is_err() && source.failure_v1().is_some() {
                self.funding_original = true;
            }
            debit?;
            self.observations = BOOKENDS;
            let origin = source.original_clock_data_v1(controller)?;
            let cutoff = source.original_cutoff_v1(controller)?;
            let subject = source.subject_data_v1(controller)?;
            let source_parent = source.source_parent_data_v1(controller)?;
            let host = source.completed_host_inventory_reference_data_v1(controller, 0)?;
            let reference = source.recovery_admission_data_v1(controller)?;
            let affinity = source.capture_inventory_financial_original_v1(controller)?;
            let opening = Opening {
                admission_key: reference.key,
                admission: reference.commitment,
                recover_original: encode_acquisition_raw_pair_data_v2(reference.original),
                recover_cutoff: reference.cutoff.to_be_bytes(),
                recover_wall_expiry: reference.wall_expiry.to_be_bytes(),
                cleanup: *subject.cleanup_request_v1(),
                controller_first: encode_acquisition_raw_pair_data_v2(origin),
                cleanup_cutoff: cutoff.to_be_bytes(),
                source_parent,
                host,
                query: [0; QUERY_BYTES_V1],
            };
            self.native = Some(Box::new(Native {
                profile: Arc::clone(&profile),
                affinity,
                controller: controller.execution_observation_identity_v4(),
                origin,
                source_cutoff: cutoff,
                cutoff,
                expiry: reference.wall_expiry,
                source_parent,
                source_subject: subject,
                opening,
                query_digest: [0; 32],
                decision_digest: [0; 32],
                observed: false,
                connection: Default::default(),
                connect: None,
                reporting: None,
                query_sender: Default::default(),
                query_sent: None,
                sender: std::array::from_fn(|_| Default::default()),
                sent: std::array::from_fn(|_| None),
                scratch: [0; 4096],
                data_failure: None,
                replies: std::array::from_fn(|_| Reply {
                    received: Default::default(),
                    preparation: None,
                    extension: None,
                    chunk: None,
                }),
                eof: Default::default(),
                eof_byte: [0],
                ended: None,
                confirmation: None,
                comparison: None,
                bookends: std::array::from_fn(|_| RootClientBookendV1::new()),
                signing: None,
                final_host: None,
            }));
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first.get_or_insert(First::Entry);
            return Err(RootStopCleanupClientClosedV1);
        }
        self.pending = Some(1);
        let mut guard = OwedAfter {
            owner: self,
            profile,
        };
        let result = guard.owner.open_body(source, controller);
        guard.owner.record_body(0, result);
        guard.finish();
        drop(guard);
        if self.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.phase = 1;
        Ok(())
    }

    fn open_body(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), Cause> {
        self.require_source(source, controller)?;
        self.charge(
            source,
            controller,
            QUERY_BYTES_V1
                .checked_add(SUBJECT_BYTES_V1)
                .and_then(|n| n.checked_add(REPLY_HEADER_BYTES_V1))
                .ok_or(HistoryErrorV1::Extent)?,
            QUERY_BYTES_V1
                .checked_add(SUBJECT_BYTES_V1)
                .ok_or(HistoryErrorV1::Extent)?,
        )?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let subject = native.opening.subject();
        let query = StopCleanupQueryDataV1 {
            controller_nonce: native.opening.cleanup,
            original_boot: native.origin.host_boot_id(),
            original_boottime_ns: native.origin.boottime_nanoseconds(),
            original_cutoff_ns: native.source_cutoff,
            subject_bytes: u64::try_from(subject.encoded_bytes_v1()?)?,
            subject_digest: subject.digest_v1()?,
        };
        subject.require_query_v1(query)?;
        native.opening.query = query.encode_v1()?;
        native.query_digest = query.digest_v1()?;
        native.connect = Some(native.connection.connect_once());
        positive(&native.connect)?;
        let profile = Arc::clone(&native.profile);
        self.observe_bookend(0, &profile, false)?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        native.reporting = Some(native.connection.stream_mut()?.enable_subject_reporting());
        positive(&native.reporting)?;
        native.query_sent = Some(native.query_sender.run_once(
            native.connection.stream_mut()?,
            &mut native.opening.query,
            native.cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        positive(&native.query_sent)?;
        resource_stream::send_subject_v1(
            RootSubjectDataV1::StopCleanup(native.opening.subject()),
            &mut native.connection,
            &mut native.sender[0],
            &mut native.sent[0],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootStopCleanupClientClosedV1)?;
        self.receive(source, controller, 0, Some(RootReplyPurposeV1::StopCleanup))?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let reply = StopCleanupReplyDataV1::decode_v1(native.replies[0].received.bytes())?;
        if reply.query_digest != native.query_digest {
            return Err(HistoryErrorV1::Correlation.into());
        }
        let (root_sample, expiry, cutoff) = match reply.decision_v1()? {
            StopCleanupDecisionDataV1::Effect(effect) => {
                let subject = HostStopCleanupSubjectDataV1::decode_v1(effect.subject)?;
                if subject != native.source_subject {
                    return Err(HistoryErrorV1::Correlation.into());
                }
                native.decision_digest = subject.digest_data_v1();
                (effect.root_sample, effect.policy_expiry, effect.cutoff)
            }
            StopCleanupDecisionDataV1::Observed(observed) => {
                native.observed = true;
                native.decision_digest = observed.decision_digest_v1()?;
                (
                    observed.root_sample,
                    observed.policy_expiry,
                    observed.cutoff,
                )
            }
        };
        let root_sample = aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::
            decode_acquisition_raw_pair_data_v2(root_sample)?;
        native.origin.validate_later_sample(root_sample)?;
        let cutoff = u64::from_be_bytes(cutoff.try_into()?);
        if cutoff > native.cutoff || cutoff <= root_sample.boottime_nanoseconds() {
            return Err(HistoryErrorV1::Correlation.into());
        }
        native.cutoff = cutoff;
        native.expiry = native.expiry.min(i64::from_be_bytes(expiry.try_into()?));
        Ok(())
    }
}
