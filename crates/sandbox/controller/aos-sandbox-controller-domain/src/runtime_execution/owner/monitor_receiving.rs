//! Forecasts one ordinary Observe child on the already-held execution journals.
//!
//! This passive supplier uses the same claim replay, canonical record encoders
//! and append engine as prepare/issue/Agent custody/complete. It does not claim
//! a runtime, choose a sequence, prepare an effect or authorize a monitor.

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_model::runtime_backend::durable_execution_effect_encoded_width_v5;
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_protocol::domain_ledger::capacity::RESERVATION_KEY_BYTES_V1;
use crate::journal::{JournalAppendReceivingDemandErrorV1, JournalError};
use super::DormantRuntimeExecutionOwnerV1;
use super::super::{outcome_record, route_record, store};

impl DormantRuntimeExecutionOwnerV1 {
    /// Borrows the actual retained append failure for the entered monitor frontier.
    ///
    /// The caller must select this only for the same returned operation whose
    /// previously healthy append owner gained a failure. It grants no recovery,
    /// health or native entry and performs no IO.
    #[must_use]
    pub fn execution_monitor_append_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.execution_journal.retained_native_append_failure_v1()
            .or_else(|| self.lifecycle_journal.retained_native_append_failure_v1())
    }

    /// Forecasts the same held-owner Query3 replay and bounded historical results.
    ///
    /// The caller pays before either claim, durable-effect decoding or signed
    /// result growth. Native/name/clock/Session prefixes are separately priced.
    /// No append, next sequence or semantic/native authority is supplied.
    ///
    /// # Errors
    /// Preserves real held journal metadata failures and checked overflow.
    pub fn execution_monitor_query_receiving_demand_v3(&self, specification_bytes: usize)
        -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let overflow = || JournalAppendReceivingDemandErrorV1::Accounting(
            AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
        let complete = durable_execution_effect_encoded_width_v5(specification_bytes,
            Some(aos_sandbox_protocol::execution_evidence::execution_completion_evidence_bytes_v5()))
            .ok_or_else(overflow)?;
        let packet = aos_sandbox_guest_protocol::signed_outcome_packet::observe_signed_outcome_packet_bytes_v5()
            .ok_or_else(overflow)?;
        // Current child, optional C1 and authenticated original outcomes coexist
        // with both claim/revalidation views. Keep the whole result invoice.
        let model = complete.checked_mul(12)
            .and_then(|bytes| bytes.checked_add(packet.checked_mul(8)?))
            .ok_or_else(overflow)?;
        let claim = self.initial_claim_receiving_demand_v2()?;
        claim.checked_add(claim)?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(model).map_err(|_| overflow())?)).map_err(Into::into)
    }

    /// Prices one historical execution query against its actual stored admission.
    ///
    /// The containing canonical admission width bounds its embedded encoded
    /// specification. The same Query model/claim supplier then prices the
    /// actual effect and original signed packet roster; no raw record escapes.
    ///
    /// # Errors
    /// Rejects a missing materialized record or the ordinary checked receiving
    /// geometry errors. This passive read performs no native IO or decoding.
    pub fn execution_historical_query_receiving_demand_v5(&self,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let width = self.execution_journal.records(super::RecordNamespace::HostExecution)
            .find_map(|(key, value)| (key.len() == 17 && key[0] == store::admission_key_prefix_v5()
                && key[1..] == execution.as_bytes()[..]).then_some(value.len()))
            .ok_or(JournalAppendReceivingDemandErrorV1::Journal(
                JournalError::MalformedRecord("historical execution admission is absent")))?;
        self.execution_monitor_query_receiving_demand_v3(width)
    }

    /// Forecasts one finite monitor claim and its complete actual append roster.
    ///
    /// This must be admitted before semantic claim/model or request growth.
    /// Native observations, the Agent exchange, retained interval carriers and
    /// independently owed Host posts remain separately paid. All widths are
    /// representation DATA; no returned amount grants execution permission.
    ///
    /// # Errors
    /// Preserves held-writer/native geometry failures and checked overflow.
    pub fn execution_monitor_receiving_demand_v5(
        &self, specification_bytes: usize,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let overflow = || JournalAppendReceivingDemandErrorV1::Accounting(
            AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
        let incomplete = durable_execution_effect_encoded_width_v5(specification_bytes, None)
            .ok_or_else(overflow)?;
        let complete = durable_execution_effect_encoded_width_v5(specification_bytes,
            Some(aos_sandbox_protocol::execution_evidence::execution_completion_evidence_bytes_v5()))
            .ok_or_else(overflow)?;
        let request = aos_sandbox_guest_protocol::protocol::observe_request_frame_bytes_v5();
        let reply = aos_sandbox_guest_protocol::signed_outcome_packet::observe_signed_outcome_packet_bytes_v5()
            .ok_or_else(overflow)?;
        let route = route_record::encoded_width_v5(request).ok_or_else(overflow)?;
        let outcome = outcome_record::encoded_width_v5(reply).ok_or_else(overflow)?;
        let effect = |bytes| RecordShape {
            key_bytes: store::EFFECT_KEY_BYTES_V5, value_bytes: Some(bytes),
        };
        let pending = [effect(incomplete), RecordShape {
            key_bytes: store::SEQUENCE_KEY_BYTES_V5,
            value_bytes: Some(store::SEQUENCE_VALUE_BYTES_V5),
        }];
        let issued = [effect(incomplete)];
        let routed = [effect(route)];
        let received = [effect(outcome)];
        // Only a genuine terminal completion emits the marker and reservation
        // deletion. Forecast both branches before its signed outcome exists.
        let terminal = [effect(complete), effect(store::TERMINAL_VALUE_BYTES_V5),
            RecordShape { key_bytes: RESERVATION_KEY_BYTES_V1, value_bytes: None }];
        let schedule: [&[RecordShape]; 5] = [&pending, &issued, &routed, &received, &terminal];
        let appends = self.execution_journal.append_sequence_receiving_demand_v1(
            schedule.into_iter().map(|records| Ok::<_, JournalError>(records.iter().copied())))?;
        let lifecycle = [RecordShape {
            key_bytes: super::LIFECYCLE_HEAD_KEY.len(),
            value_bytes: Some(super::LIFECYCLE_HEAD_BYTES),
        }, RecordShape {
            key_bytes: super::LIFECYCLE_ISSUE_KEY.len(),
            value_bytes: Some(super::LIFECYCLE_ISSUE_BYTES),
        }];
        let lifecycle = self.lifecycle_journal.append_receiving_demand_v1(lifecycle.into_iter())?;
        // Candidate/admission clones, pending and issued predecessors, parked
        // signed completion and transaction/cold-readback views coexist. The
        // common append supplier prices its native/archive copies separately.
        let model = incomplete.checked_mul(16)
            .and_then(|bytes| bytes.checked_add(complete.checked_mul(16)?))
            .and_then(|bytes| bytes.checked_add(route.checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(outcome.checked_mul(4)?))
            .ok_or_else(overflow)?;
        // Sequence selection, live issue, and final post-gated commit each
        // replay this same claim engine; all three invoices stay summed.
        let claim = self.initial_claim_receiving_demand_v2()?;
        claim.checked_add(claim)?.checked_add(claim)?
            .checked_add(appends)?.checked_add(lifecycle)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(model).map_err(|_| overflow())?)).map_err(Into::into)
    }
}
