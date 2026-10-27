//! Forecasts the actual fixed admission, Authorize and first Observe appends.
//!
//! These byte requirements are DATA from the SAME held journals. A genuine
//! Host purpose20 original must admit them before the original Guest59 send.
//! No Journal, grant, currentness, writer or resource account is constructed.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_journal::geometry::RecordShape;
use crate::journal::JournalAppendReceivingDemandErrorV1;
use super::DormantRuntimeExecutionOwnerV1;

impl DormantRuntimeExecutionOwnerV1 {
    /// Prices the canonical provisional output transaction on this same writer.
    ///
    /// The first transaction has four fixed records; later/replay paths need
    /// fewer. Shapes come from the actual format, marker, claim and correlation
    /// codecs. This opens no writer and supplies no receiving permission.
    ///
    /// # Errors
    /// Preserves the actual retained extent, native limits and accounting cause.
    pub fn host_output_reservation_append_demand_v2(&self)
        -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        self.execution_journal.append_receiving_demand_v1(
            super::super::store::host_output_reservation_record_shapes_v2().into_iter())
    }

    /// Prices semantic materialization from the four actual retained prefixes.
    ///
    /// This reuses the common held-prefix representation engine with an empty
    /// append sequence. It opens no replacement writer and grants no claim.
    ///
    /// # Errors
    /// Preserves actual metadata, native-limit and aggregate-accounting failures.
    pub fn execution_claim_receiving_demand_v2(&self)
        -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    {
        let mut complete = ResourceVector::ZERO;
        for journal in [&self.peer_journal, &self.execution_journal, &self.agent_journal, &self.lifecycle_journal] {
            let demand = journal.append_sequence_receiving_demand_v1(
                std::iter::empty::<Result<std::iter::Empty<RecordShape>, crate::JournalError>>(),
            )?;
            complete = complete.checked_add(demand)?;
        }
        Ok(complete)
    }

    /// Prices the exact early no-Apply append on this same execution writer.
    ///
    /// This is receiving DATA only. The Host purpose owner must actually admit
    /// it before parsing/body growth or native effect; it supplies no Ready.
    ///
    /// # Errors
    /// Preserves native extent/limit and accounting failures.
    pub fn before_argument_no_apply_append_demand_v2(
        &self,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        self.execution_journal.append_receiving_demand_v1(std::iter::once(RecordShape {
            key_bytes: 17,
            value_bytes: Some(aos_sandbox_protocol::host_execution_no_apply::
                BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2),
        }))
    }

    /// Borrows the exact first failed append retained by the actual native owner.
    #[must_use]
    pub fn accepted_execution_native_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        [&self.peer_journal, &self.execution_journal, &self.agent_journal, &self.lifecycle_journal]
            .into_iter().find_map(crate::Journal::retained_native_append_failure_v1)
    }


    /// Prices the two fixed post-Accept effects against their actual prefix.
    ///
    /// Every large value is clipped by the SAME native per-record hard cap,
    /// not a configured maximum-transaction allocation. Small control/receipt
    /// values use that same cap conservatively until their shared typed codec
    /// sizes are available. The observer needs separate actual Host/Agent/State
    /// and Storage native receiving demand before any of those allocations.
    ///
    /// # Errors
    /// Preserves actual metadata, hard native limit and accounting failures.
    pub fn accepted_execution_append_demand_v2(
        &self,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let limits = self.execution_journal.configured_limits_data_v1();
        let value = limits.maximum_record_bytes.checked_sub(7)
            .and_then(|n| n.checked_sub(limits.maximum_key_bytes))
            .ok_or(crate::JournalError::LimitExceeded("Host execution append shape"))?;
        let shape = RecordShape { key_bytes: limits.maximum_key_bytes, value_bytes: Some(value) };
        // Admission5; Authorize Pending2/Issued1/route1/signed-outcome1/Complete1;
        // first Observe Pending2/Issued1/route1/signed-outcome1/terminalComplete3.
        // Replays allocate less; failures stop before a later sequence member.
        let execution = self.execution_journal.append_sequence_receiving_demand_v1(
            [5, 2, 1, 1, 1, 1, 2, 1, 1, 1, 3].into_iter()
                .map(|count| Ok(std::iter::repeat_n(shape, count))),
        )?;
        let limits = self.lifecycle_journal.configured_limits_data_v1();
        // Each actual Guest result advances the same96-byte lifecycle head,
        // preserving the current issue row (exact200 bytes) or deleting it.
        let lifecycle = self.lifecycle_journal.append_sequence_receiving_demand_v1(
            [0, 1].into_iter().map(|_| Ok([
                RecordShape { key_bytes: limits.maximum_key_bytes, value_bytes: Some(super::LIFECYCLE_HEAD_BYTES) },
                RecordShape { key_bytes: limits.maximum_key_bytes, value_bytes: Some(super::LIFECYCLE_ISSUE_BYTES) },
            ].into_iter())),
        )?;
        Ok(execution.checked_add(lifecycle)?)
    }
}

impl DormantRuntimeExecutionOwnerV1 {
    /// Prices four fixed rooted/native name observations as passive DATA.
    #[must_use]
    pub fn execution_currentness_demand_v2() -> Option<ResourceVector> {
        let mut complete = ResourceVector::ZERO;
        for name in [super::PEER_JOURNAL_NAME, super::EXECUTION_JOURNAL_NAME,
            super::AGENT_JOURNAL_NAME, super::LIFECYCLE_JOURNAL_NAME] {
            complete = complete.checked_add(crate::journal::ProtectedJournalCurrentnessOriginalsV1
                ::fixed_demand_v1(std::path::Path::new(super::HOST_STATE_ROOT), name).ok()?).ok()?;
        }
        Some(complete)
    }

    /// Prices the four actual names-only independently owed posts.
    ///
    /// These use the held directory and do not repeat rooted traversal. This
    /// passive geometry grants no entry, currentness or receiving capacity.
    #[must_use]
    pub fn execution_currentness_post_demand_v2() -> Option<ResourceVector> {
        let mut complete = ResourceVector::ZERO;
        for name in [super::PEER_JOURNAL_NAME, super::EXECUTION_JOURNAL_NAME,
            super::AGENT_JOURNAL_NAME, super::LIFECYCLE_JOURNAL_NAME] {
            complete = complete.checked_add(crate::journal::ProtectedJournalCurrentnessOriginalsV1
                ::named_demand_v1(name).ok()?).ok()?;
        }
        Some(complete)
    }

    /// Prices the actual common fixed HostState protected ancestry once.
    #[must_use]
    pub fn execution_shared_directory_demand_v6() -> Option<ResourceVector> {
        crate::journal::ProtectedJournalCurrentnessOriginalsV1::directory_demand_v6(
            std::path::Path::new(super::HOST_STATE_ROOT)).ok()
    }

    /// Captures the actual common fixed HostState ancestry for this interval.
    ///
    /// # Errors
    /// Retains every reached ancestor and native failure without creating a claim.
    pub fn observe_execution_directory_v6(&self,
        original: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), crate::JournalError> {
        original.capture_directory_once_v6(std::path::Path::new(super::HOST_STATE_ROOT), 0)
    }

    /// Prices the four exact name/binding samples sharing one separate ancestry.
    #[must_use]
    pub fn execution_shared_names_demand_v6() -> Option<ResourceVector> {
        let mut complete = ResourceVector::ZERO;
        for name in [super::PEER_JOURNAL_NAME, super::EXECUTION_JOURNAL_NAME,
            super::AGENT_JOURNAL_NAME, super::LIFECYCLE_JOURNAL_NAME] {
            complete = complete.checked_add(crate::journal::ProtectedJournalCurrentnessOriginalsV1
                ::named_demand_v1(name).ok()?).ok()?;
        }
        Some(complete)
    }

    /// Observes all four writers against one actual retained protected ancestry.
    ///
    /// # Errors
    /// Keeps each independent writer's native binding/name cause. A failed
    /// shared sample remains owned by the caller and cannot grant currentness.
    pub fn observe_execution_names_with_directory_v6(&self,
        shared: &crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        originals: &mut [crate::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
        results: &mut [Option<Result<(), crate::JournalError>>; 4],
    ) -> Result<(), crate::JournalError> {
        self.observe_execution_names_recipe_v6(originals, results, false, Some(shared))
    }

    /// Runs independently owed fixed writer-name observations on the same owner.
    ///
    /// All four destinations are entered even after an earlier failure. This
    /// is a native observation, never a healthy role/effect grant.
    ///
    /// # Errors
    /// Preserves each native cause in its actual destination and returns a
    /// refusal unless every fixed rooted/name observation completed positively.
    pub fn observe_execution_names_v2(
        &self,
        originals: &mut [crate::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
        results: &mut [Option<Result<(), crate::JournalError>>; 4],
    ) -> Result<(), crate::JournalError> {
        self.observe_execution_names_engine_v2(originals, results, false)
    }

    /// Observes independently owed names even after a failed native append.
    ///
    /// # Errors
    /// Preserves each actual native observation error. This path checks names
    /// only and cannot issue a healthy claim or authorize a replacement effect.
    pub fn observe_execution_names_post_v2(
        &self,
        originals: &mut [crate::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
        results: &mut [Option<Result<(), crate::JournalError>>; 4],
    ) -> Result<(), crate::JournalError> {
        self.observe_execution_names_engine_v2(originals, results, true)
    }

    fn observe_execution_names_engine_v2(
        &self,
        originals: &mut [crate::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
        results: &mut [Option<Result<(), crate::JournalError>>; 4],
        owed: bool,
    ) -> Result<(), crate::JournalError> {
        self.observe_execution_names_recipe_v6(originals, results, owed, None)
    }

    fn observe_execution_names_recipe_v6(&self,
        originals: &mut [crate::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
        results: &mut [Option<Result<(), crate::JournalError>>; 4],
        owed: bool, shared: Option<&crate::journal::ProtectedJournalCurrentnessOriginalsV1>,
    ) -> Result<(), crate::JournalError> {
        let journals = [&self.peer_journal, &self.execution_journal,
            &self.agent_journal, &self.lifecycle_journal];
        let names = [super::PEER_JOURNAL_NAME, super::EXECUTION_JOURNAL_NAME,
            super::AGENT_JOURNAL_NAME, super::LIFECYCLE_JOURNAL_NAME];
        for index in 0..4 {
            if results[index].is_some() { return Err(crate::JournalError::ProtectedBoundary); }
            results[index] = Some(if owed {
                journals[index].observe_held_names_post_retaining_v1(&mut originals[index])
            } else if let Some(shared) = shared {
                journals[index].validate_held_owned_at_with_directory_retaining_v6(
                    std::path::Path::new(super::HOST_STATE_ROOT), names[index], 0,
                    &mut originals[index], shared)
            } else {
                journals[index].validate_held_owned_at_for_uid_retaining(
                    super::HOST_STATE_ROOT, names[index], 0, &mut originals[index])
            });
        }
        if results.iter().all(|result| matches!(result, Some(Ok(())))) { Ok(()) }
        else { Err(crate::JournalError::ProtectedBoundary) }
    }
}
