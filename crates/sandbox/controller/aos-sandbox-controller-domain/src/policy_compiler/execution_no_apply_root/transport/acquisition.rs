//! Drives the finite acquisition prefix on the same held Execution Root R.
//!
//! A signed acquisition precedes new Host42/43. The genuine issuer independently
//! reads current kind3 authority and full history, retains its own owed originals,
//! and keeps the main policy interval open. The later preliminary subject is
//! authenticated independently by the common actual43/floor/ACK programme.

use super::*;
use crate::policy_compiler::execution_no_apply_root::{
    RootExecutionNoApplyAcquisitionOriginalV2, RootNoApplyAcquisitionSelectionDataV2,
};
use crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2;
use aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::*;
use aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2;
use aos_sandbox_protocol::host_execution_no_apply::{
    BeforeArgumentNoApplySourceDataV2, ClosedBeforeArgumentNoApplyRecordV2,
    recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2,
};

pub(super) struct AcquisitionTransportV2 {
    pub(super) original: RootExecutionNoApplyAcquisitionOriginalV2,
    pub(super) buffer: RetainedSubjectStreamReadV1,
    pub(super) chunk: RootSubjectChunkReceivingV1,
    reply: Option<Vec<u8>>,
    pub(super) sender: SliceDeadlineStreamIoV1,
}

impl AcquisitionTransportV2 {
    pub(super) fn new() -> Self {
        Self {
            original: RootExecutionNoApplyAcquisitionOriginalV2::new(),
            buffer: RetainedSubjectStreamReadV1::new(),
            chunk: Default::default(),
            reply: None,
            sender: Default::default(),
        }
    }

    pub(super) fn require_preliminary(
        &self,
        lease: CurrentHostNoApplyLeaseDataV2,
        cut: aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2,
    ) -> Result<(), JournalError> {
        let acquired = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(
            self.original.acquisition_bytes_v2()?,
        )
        .map_err(|_| JournalError::ProtectedBoundary)?
        .fields_v2();
        let fields = lease.fields();
        if fields.scope != HostNoApplyLeaseScopeV2::RecoveryCleanup
            || fields.accepted_source != acquired.accepted_source
            || fields.marker
                != HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(acquired.marker)
            || fields.terminal_archive_head != acquired.terminal_archive
            || fields.signed_terminal_outcome != acquired.signed_terminal
            || fields.native_boot != acquired.host_boot
            || fields.current_session != acquired.host_session
            || fields.native_cutoff > acquired.cutoff
            || cut != acquired.controller_cut
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl Native {
    pub(super) fn begin_policy(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        current_policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.phase = Phase::Policy;
        self.policy_begin = Some(
            root.flight
                .begin_execution_no_apply_policy_once_v2(&mut self.policy),
        );
        positive(&self.policy_begin)?;
        self.policy_verify = Some(
            root.flight
                .verify_execution_no_apply_policy_sources_once_v2(
                    &mut self.policy,
                    current_policy,
                    self.opening.sample()?,
                ),
        );
        positive(&self.policy_verify)?;
        Ok(())
    }

    pub(super) fn receive_acquisition_and_preliminary(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        current_policy: &RootCurrentPolicyInputDataV1<'_>,
        query: ExecutionNoApplyAcquisitionQueryDataV2,
    ) -> Result<(), Cause> {
        self.phase = Phase::Acquisition;
        self.acquisition
            .buffer
            .prepare_exact_once(ACQUISITION_SUBJECT_BYTES_V2)?;
        self.acquisition.chunk.receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.acquisition.buffer,
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let subject =
            ExecutionNoApplyAcquisitionSubjectDataV2::decode_v2(self.acquisition.buffer.bytes())?;
        let first = decode_acquisition_raw_pair_data_v2(subject.controller_first)?;
        let cutoff = u64::from_be_bytes(subject.cleanup_cutoff.try_into()?);
        if query.subject_digest != subject.digest_v2()?
            || query.original_boot != first.host_boot_id()
            || query.original_boottime_ns != first.boottime_nanoseconds()
            || query.original_cutoff_ns != cutoff
            || query.controller_nonce != subject.controller_nonce[..16]
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let selection = RootNoApplyAcquisitionSelectionDataV2 {
            admission: RootRecoveryAdmissionReferenceDataV2 {
                key: subject.admission_key.try_into()?,
                commitment: subject.admission.try_into()?,
                original: decode_acquisition_raw_pair_data_v2(subject.recover_original)?,
                cutoff: u64::from_be_bytes(subject.recover_cutoff.try_into()?),
                wall_expiry: i64::from_be_bytes(subject.recover_wall_expiry.try_into()?),
            },
            controller_nonce: subject.controller_nonce.try_into()?,
            controller_first: first,
            cleanup_cutoff: cutoff,
            host_session: subject.host_session.try_into()?,
            historical_availability: HostExecutionAvailabilityObservationV2::decode_canonical(
                subject.historical_availability,
            )?,
            accepted_source: BeforeArgumentNoApplySourceDataV2::decode_canonical(
                subject.accepted_source,
            )?,
            marker: ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(subject.marker)?,
            terminal_archive: subject.terminal_archive.try_into()?,
            signed_terminal: subject.signed_terminal.try_into()?,
        };
        self.begin_policy(root, current_policy)?;
        self.opening.tighten_acquisition_policy(&self.policy)?;
        self.clock = Some(Box::new(RootContinuationClockGateV1::new(
            self.opening.horizon()?,
        )));
        self.phase = Phase::Acquisition;
        root.flight.observe_execution_no_apply_acquisition_once_v2(
            &mut self.acquisition.original,
            positive(&self.stream)?,
            &self.policy,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            selection,
        )?;
        // The genuine issuer matched the protected admission row. Its wall
        // expiry now narrows the same original gate and every later trust,
        // floor-crossing/signing and ACK horizon; it never renews authority.
        self.opening
            .narrow_acquisition_wall(self.acquisition.original.acquisition_wall_expiry_v2()?)?;
        self.clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .narrow_horizon_data_v1(self.opening.horizon()?)?;
        self.phase = Phase::AcquisitionReply;
        let digest = query.digest_v2()?;
        let frame = ExecutionNoApplyAcquisitionReplyDataV2 {
            query_digest: &digest,
            acquisition: self.acquisition.original.acquisition_bytes_v2()?,
        };
        self.acquisition.reply = Some(vec![0; frame.encoded_bytes_v2()?]);
        frame.encode_range_v2(
            0,
            self.acquisition
                .reply
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        self.acquisition.sender.run_once(
            &mut root.original,
            self.acquisition
                .reply
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        )?;

        // The same peer now obtains the signed acquisition, posts new42 and
        // sends its actual preliminary lease. No nonce43 existed before this.
        self.phase = Phase::Preliminary;
        self.buffers[0].prepare_exact_once(28)?;
        self.chunks[0].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[0],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let bytes = ExecutionNoApplySubjectDataV2::declared_bytes_v2(self.buffers[0].bytes())?;
        self.buffers[0].extend_completed_exact_once(bytes)?;
        self.chunks[0].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[0],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        Ok(())
    }
}
