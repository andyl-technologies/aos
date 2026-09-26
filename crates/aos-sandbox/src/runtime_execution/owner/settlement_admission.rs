//! Live Host admission of the protected preliminary settlement witness.
//!
//! The owner retains HostState and Effect writer claims through both appends.
//! An unwitnessed AOSCHL01 is only a crash coordinate; a later request must
//! still be the same live signed method-42 packet before it can complete the
//! immediate AOSCHA01 append. This is not a Controller floor or recovery grant.

use aos_sandbox_protocol::host_execution_no_apply::{
    HostNoApplyControllerCoordinateV2, HostNoApplySettlementPhaseV2,
    decode_host_no_apply_settlement_request_v2,
};

use super::super::no_apply_settlement::HostSettlementStageV1;
use super::super::store::HostSettlementAdmissionWitnessV1;
use super::*;
use crate::journal::host_currentness_fence::cut_v1;

#[derive(Clone, Copy)]
struct AdmissionClockV1 {
    host_boot_id: [u8; 16],
    boottime_nanoseconds: u64,
}

impl DormantRuntimeExecutionClaimV1<'_> {
    /// Appends or exactly verifies the witness for one live signed method-42 stage.
    ///
    /// The owner reads kernel BOOTTIME and boot identity while both protected
    /// writers remain held. A missing witness after a failed append is not an
    /// idempotent success; exact live replay may complete the
    /// immediate second append only if no Effect frame intervened. This method
    /// never grants historical recovery or a Controller settlement transition.
    ///
    /// # Errors
    ///
    /// Rejects a foreign or expired signed request, changed HostState/Effect
    /// custody, nonconsecutive stage, or uncertain witness durability.
    pub fn ensure_host_settlement_admission_witness_v1(
        &mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        canonical_preliminary: &[u8],
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let admitted_clock = read_kernel_admission_clock()?;
        if authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            || authenticated.authorization().is_some()
            || !live_admission_clock(
                admitted_clock,
                self.host_verifier.boot_id(),
                authenticated.deadline_boottime_nanoseconds(),
            )
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }

        let request = decode_host_no_apply_settlement_request_v2(
            authenticated.exact_body(),
            authenticated.peer(),
            authenticated.peer_policy(),
            admitted_clock.boottime_nanoseconds,
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let preliminary = HostSettlementRecordV1::decode_canonical(canonical_preliminary)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if request.phase() != HostNoApplySettlementPhaseV2::Preliminary
            || request.coordinate() != HostNoApplyControllerCoordinateV2::Preliminary
            || request.header().request_id() != &authenticated.request_id()
            || request.challenge() != authenticated.request_id()
            || request.header().deadline_boottime_nanoseconds()
                != authenticated.deadline_boottime_nanoseconds()
            || preliminary.stage != HostSettlementStageV1::Preliminary
            || preliminary.session_binding != authenticated.session_binding()
            || self
                .execution
                .load_host_settlement_history_v1(preliminary.execution)?
                != [Some(preliminary), None, None]
            || self.peer_fence.is_some()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }

        let original = request.original();
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(original.canonical_attempt())
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let marker = self
            .query_host_no_apply_v1(
                &source,
                original.original_session_binding(),
                original.original_signed_request_digest(),
            )?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        if !preliminary.matches_preliminary_source(
            marker,
            preliminary.handoff_digest,
            request.archive_head(),
            request.signed_terminal_outcome(),
            authenticated.session_binding(),
            authenticated.request_id(),
        ) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }

        let hoststate_cut = cut_v1(
            self.peer_authority.records()?,
            self.execution_store_binding,
            self.protected_sequence,
            false,
        )?;
        self.validate_current()?;
        let existing = self
            .execution
            .load_host_settlement_admission_witness_v1(preliminary.execution)?;
        let effect_sequence = self.execution.protected_host_settlement_cut_v1()?.0;
        let commit_sequence = match existing {
            Some(witness) => witness.commit_sequence,
            None => effect_sequence
                .checked_add(2)
                .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
        };
        let witness = HostSettlementAdmissionWitnessV1 {
            execution: preliminary.execution,
            store_binding: self.execution_store_binding,
            preliminary_digest: preliminary.digest(),
            signed_request_digest: ObjectDigest::from_bytes(authenticated.signed_request_digest()),
            settlement_session_binding: authenticated.session_binding(),
            source_digest: source.record_digest(),
            handoff_digest: preliminary.handoff_digest,
            host_boot_id: admitted_clock.host_boot_id,
            admitted_boottime_nanoseconds: admitted_clock.boottime_nanoseconds,
            original_deadline_boottime_nanoseconds: authenticated.deadline_boottime_nanoseconds(),
            commit_sequence,
            hoststate_cut,
        };
        match existing {
            Some(retained) if exact_live_witness_replay(retained, witness, effect_sequence) => {}
            Some(_) => return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness),
            None => {
                self.execution
                    .append_host_settlement_admission_witness_v1(witness)?;
            }
        }
        self.validate_current()
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if self
            .execution
            .load_host_settlement_admission_witness_v1(preliminary.execution)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
            != Some(existing.unwrap_or(witness))
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }
        Ok(())
    }
}

fn live_admission_clock(
    sample: AdmissionClockV1,
    host_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
) -> bool {
    sample.host_boot_id == host_boot_id
        && sample.boottime_nanoseconds > 0
        && sample.boottime_nanoseconds < deadline_boottime_nanoseconds
}

#[cfg(target_os = "linux")]
fn read_kernel_admission_clock() -> Result<AdmissionClockV1, DormantRuntimeExecutionOwnerErrorV1> {
    use aos_sandbox_linux::boot::KernelBootId;
    use rustix::time::{ClockId, clock_gettime};

    let boot_before = KernelBootId::current()
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?
        .into_bytes();
    let now = clock_gettime(ClockId::Boottime);
    let boot_after = KernelBootId::current()
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?
        .into_bytes();
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
    if boot_before != boot_after {
        return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
    }
    Ok(AdmissionClockV1 {
        host_boot_id: boot_after,
        boottime_nanoseconds,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_kernel_admission_clock() -> Result<AdmissionClockV1, DormantRuntimeExecutionOwnerErrorV1> {
    Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
}

fn exact_live_witness_replay(
    retained: HostSettlementAdmissionWitnessV1,
    observed: HostSettlementAdmissionWitnessV1,
    effect_sequence: u64,
) -> bool {
    retained.commit_sequence.checked_add(1) == Some(effect_sequence)
        && retained.admitted_boottime_nanoseconds <= observed.admitted_boottime_nanoseconds
        && retained
            == HostSettlementAdmissionWitnessV1 {
                admitted_boottime_nanoseconds: retained.admitted_boottime_nanoseconds,
                ..observed
            }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::ExecutionId;

    use super::*;

    fn sample(boot: [u8; 16], boottime: u64) -> AdmissionClockV1 {
        AdmissionClockV1 {
            host_boot_id: boot,
            boottime_nanoseconds: boottime,
        }
    }

    #[test]
    fn admission_clock_rejects_reboot_and_expired_second_sample() {
        assert!(live_admission_clock(sample([2; 16], 49), [2; 16], 50));
        assert!(!live_admission_clock(sample([3; 16], 49), [2; 16], 50));
        assert!(!live_admission_clock(sample([2; 16], 50), [2; 16], 50));
        assert!(!live_admission_clock(sample([2; 16], 51), [2; 16], 50));
        assert!(!live_admission_clock(sample([2; 16], 0), [2; 16], 50));
    }

    #[test]
    fn live_replay_requires_original_packet_session_deadline_and_hoststate_cut() {
        let retained = HostSettlementAdmissionWitnessV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            store_binding: ObjectDigest::from_bytes([2; 32]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            signed_request_digest: ObjectDigest::from_bytes([4; 32]),
            settlement_session_binding: [5; 32],
            source_digest: ObjectDigest::from_bytes([6; 32]),
            handoff_digest: ObjectDigest::from_bytes([7; 32]),
            host_boot_id: [8; 16],
            admitted_boottime_nanoseconds: 9,
            original_deadline_boottime_nanoseconds: 20,
            commit_sequence: 11,
            hoststate_cut: ObjectDigest::from_bytes([12; 32]),
        };
        let later = HostSettlementAdmissionWitnessV1 {
            admitted_boottime_nanoseconds: 10,
            ..retained
        };
        assert!(exact_live_witness_replay(retained, later, 12));
        assert!(!exact_live_witness_replay(retained, later, 13));
        for foreign in [
            HostSettlementAdmissionWitnessV1 {
                signed_request_digest: ObjectDigest::from_bytes([13; 32]),
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                settlement_session_binding: [14; 32],
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                original_deadline_boottime_nanoseconds: 21,
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                hoststate_cut: ObjectDigest::from_bytes([15; 32]),
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                preliminary_digest: ObjectDigest::from_bytes([16; 32]),
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                host_boot_id: [17; 16],
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                commit_sequence: 18,
                ..later
            },
            HostSettlementAdmissionWitnessV1 {
                admitted_boottime_nanoseconds: 8,
                ..later
            },
        ] {
            assert!(!exact_live_witness_replay(retained, foreign, 12));
        }
    }
}
