//! Commits exact prepare/CAS on the continuously held Controller/Root interval.
//!
//! Only the live actual Root response borrower enters this programme. It keeps
//! the same C18/Source and Controller writer through one-row prepare, real Host
//! Seal and three-row CAS. Root DATA alone cannot construct the append loan.

mod native;
pub(crate) use native::ControllerExecutionNoApplyAppendLoanV2;
pub(super) use native::require_current_map as require_controller_cut_current_v2;

use super::*;
use crate::journal::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::normal_root::{
    RootExecutionNoApplyClientClosedV2 as RootClosed,
    RootExecutionNoApplyClientFloorBorrowV2 as RootBorrow,
};
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::{
    RootExecutionNoApplyControllerCutDataV2 as Cut, RootExecutionNoApplyFloorRecordDataV2 as Floor,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    closed_controller::{
        ClosedCreateFailurePrepareDataV2 as Prepare, ControllerCreateFailureAckDataV2 as Ack,
        ControllerCreateFailureAckPhaseV2 as AckPhase,
    },
    held_settlement_transport::HostNoApplyHeldCommandV2,
    root_attestation::{
        MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2,
        RootExecutionNoApplyAttestationDataV2 as Attestation,
        RootNoApplyAttestationDataErrorV2 as AttestationError,
    },
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum First {
    RootBefore,
    Body,
    RootAfter,
}

pub(super) struct ControllerSettlementOriginalV2 {
    packet: Vec<u8>,
    decoded: Option<Result<(Floor, Prepare, [u8; 32]), AttestationError>>,
    binding: Option<Result<(), JournalError>>,
    stages: [native::AppendOriginalV2; 3],
    recovery_metadata: Option<Result<(), JournalError>>,
    recovery_operation: Option<OperationId>,
    recovery_model: Option<Result<JournalTransaction, aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::MetadataCompleteDataErrorV1>>,
    recovery_funding: Option<Result<(), ResourceReservationErrorV1>>,
    root_before: [Option<Result<(), RootClosed>>; 2],
    root_after: [Option<Result<(), RootClosed>>; 2],
    body: [Option<Result<(), JournalError>>; 2],
    first: [Option<First>; 2],
    prepared: bool,
    settled: bool,
    ack: Option<Ack>,
}

impl ControllerSettlementOriginalV2 {
    fn new() -> Self {
        Self {
            packet: Vec::new(),
            decoded: None,
            binding: None,
            stages: std::array::from_fn(|_| native::AppendOriginalV2::new()),
            recovery_metadata: None,
            recovery_operation: None,
            recovery_model: None,
            recovery_funding: None,
            root_before: std::array::from_fn(|_| None),
            root_after: std::array::from_fn(|_| None),
            body: std::array::from_fn(|_| None),
            first: [None; 2],
            prepared: false,
            settled: false,
            ack: None,
        }
    }

    fn fixed_demand(
        controller: &Journal,
        plan: &aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2,
    ) -> Result<ResourceVector, JournalError> {
        let rows = plan
            .records_data_v2()
            .iter()
            .try_fold(0_usize, |sum, record| {
                sum.checked_add(record.key().len())?
                    .checked_add(record.value()?.len())
            })
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| n.checked_add(rows.checked_mul(8)?))
            .and_then(|n| n.checked_add(MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2.checked_mul(6)?))
            .and_then(|n| n.checked_add(8192_usize.checked_mul(8)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let one = native::AppendOriginalV2::fixed_demand(controller,
            size_of::<ControllerExecutionNoApplyAppendLoanV2<'_, '_, '_>>())?;
        Ok(one
            .checked_add(one)?
            .checked_add(one)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    fn data(&self) -> Result<(Floor, Prepare, [u8; 32]), JournalError> {
        self.decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn complete(&self, index: usize) -> Result<(), JournalError> {
        if self.first[index].is_some()
            || !matches!(self.body[index], Some(Ok(())))
            || !matches!(self.root_before[index], Some(Ok(())))
            || !matches!(self.root_after[index], Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stages[index].complete()
    }

    fn root_selected(&self) -> bool {
        self.first
            .iter()
            .find_map(|first| *first)
            .is_some_and(|first| matches!(first, First::RootBefore | First::RootAfter))
    }

    pub(super) fn ack_data_v2(&self) -> Option<Ack> {
        self.complete(1).ok()?;
        self.ack
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        for index in 0..2 {
            if let Some(first) = self.first[index] {
                return match first {
                    First::RootBefore => error(&self.root_before[index]),
                    First::RootAfter => error(&self.root_after[index]),
                    First::Body => error(&self.decoded)
                        .or_else(|| error(&self.binding))
                        .or_else(|| self.stages[index].failure())
                        .or_else(|| error(&self.body[index])),
                };
            }
        }
        error(&self.recovery_funding).or_else(|| error(&self.recovery_model))
            .or_else(|| self.stages[2].failure()).or_else(|| error(&self.recovery_metadata))
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    fn acknowledgement_phase_v2(&self) -> Result<AckPhase, ResourceReservationErrorV1> {
        use aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryPhaseV2 as Phase;
        let Some(cleanup) = self.native()?.cleanup.as_deref() else { return Ok(AckPhase::Active) };
        let acquisition = cleanup.acquisition_fields.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(match acquisition.phase {
            Phase::BeforeFloor => AckPhase::RecoveryBeforeFloor,
            Phase::FloorAnchored => AckPhase::RecoveryFloorAnchored,
            Phase::Prepared => AckPhase::RecoveryPrepared,
            Phase::Settled => AckPhase::RecoverySettled,
        })
    }

    fn settlement(&self) -> Result<&ControllerSettlementOriginalV2, ResourceReservationErrorV1> {
        self.native()?
            .settlement
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn settlement_command_v2(
        &self,
    ) -> Result<HostNoApplyHeldCommandV2, ResourceReservationErrorV1> {
        let original = self.settlement()?;
        let comparison = *self
            .native
            .lease
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        match self.native.active {
            3 if original.prepared => {
                original
                    .complete(0)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                native::require_current_map(
                    self.controller,
                    original.stages[0]
                        .after_cut()
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                )
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                Ok(HostNoApplyHeldCommandV2::FloorSeal {
                    comparison,
                    canonical_root_attestation: original.packet.clone(),
                    controller_prepare: original
                        .data()
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?
                        .1,
                })
            }
            4 if original.settled => Ok(HostNoApplyHeldCommandV2::Acknowledge {
                comparison,
                ack: self.controller_acknowledgement_data_v2()?,
            }),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    fn prepare_settlement_original(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.native.settlement_geometry.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (plan, _) = self
            .native()?
            .controller
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .completed(self.controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.native.settlement_geometry = Some(ControllerSettlementOriginalV2::fixed_demand(
            self.controller,
            plan,
        ));
        let demand = self
            .native
            .settlement_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.complete_transport_base_v2(demand)?;
        self.native.settlement_funding = Some(self.require_transport_complete_v2(complete));
        if !matches!(self.native.settlement_funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.base = self.base.checked_add(demand)?;
        self.native.settlement = Some(Box::new(ControllerSettlementOriginalV2::new()));
        Ok(())
    }

    /// Commits actual812 only while the original live Root connection stays borrowed.
    ///
    /// # Errors
    /// Retains Source, Root bookend, exact C preimage, native append/readback and
    /// independently owed posts. A successful Root packet alone cannot finish.
    pub fn prepare_controller_once_v2(
        &mut self,
        root: &mut RootBorrow<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native()?;
        if self.native.active != 3 || self.native.settlement.is_some() {
            self.reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prepare_settlement_original()?;
        let before = root.begin_controller_prepare_once_v2(self);
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.root_before[0] = Some(before);
        if before.is_err() {
            original.first[0] = Some(First::RootBefore);
        }
        if before.is_ok() {
            let body = self.prepare_controller_body(root);
            let original = self
                .native
                .settlement
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            original.body[0] = Some(body);
            if matches!(original.body[0], Some(Err(_))) {
                original.first[0].get_or_insert(First::Body);
            }
        }
        let after = root.finish_controller_prepare_owed_once_v2();
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.root_after[0] = Some(after);
        if after.is_err() {
            original.first[0].get_or_insert(First::RootAfter);
        }
        original
            .complete(0)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        root.require_controller_prepare_complete_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        original.prepared = true;
        self.native.entropy[3] = Some(self.native.nonce[3].observe_once());
        self.no_apply_request_id_data_v2().map(|_| ())
    }

    fn prepare_controller_body(&mut self, root: &RootBorrow<'_>) -> Result<(), JournalError> {
        let bytes = root
            .canonical_attestation_data_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        original.packet.extend_from_slice(bytes);
        original.decoded = Some(Attestation::decode_canonical(&original.packet).map(|data| {
            (
                data.floor_data_v2(),
                data.prepare_data_v2(),
                data.root_read_nonce_v2(),
            )
        }));
        let (floor, prepare, nonce) = original.data()?;
        let fields = floor.fields();
        let cut = self
            .native
            .controller
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?
            .completed(self.controller)?;
        let expected_cut = cut.1;
        let (predecessor, successor) = cut.0.row_digests_data_v2();
        let binding = (|| {
            if fields.controller_cut != cut.1
                || fields.predecessor_rows != predecessor
                || fields.successor_rows != successor
                || fields.terminal_wall_seconds != cut.0.wall_seconds_data_v2()
                || fields.host_lease
                    != *self
                        .native
                        .lease
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?
                || Some(fields.signed_current_outcome) != self.native.signed_current_outcome
                || Some(nonce) != self.native.read_nonce
                || prepare
                    != Prepare::from_root_floor_data_v2(floor)
                        .map_err(|_| JournalError::ProtectedBoundary)?
                || prepare.operation != self.source.operation_v1()
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })();
        self.native
            .settlement
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .binding = Some(binding);
        positive(
            &self
                .native
                .settlement
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .binding,
        )?;
        let transaction = JournalTransaction::new(
            transaction_id(prepare, false),
            vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                prepare.operation.into_bytes().to_vec(),
                prepare.encode_canonical(),
            )],
        )?;
        self.run_controller_append(0, transaction, expected_cut)
    }

    /// Requires the genuine prepared owner and unchanged current C before CAS.
    ///
    /// # Errors
    /// Refuses copied/foreign Root packets, unfinished Host Seal or changed C.
    #[doc(hidden)]
    pub fn require_prepared_root_floor_current_v2(
        &self,
        packet: &[u8],
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self.settlement()?;
        if !original.prepared || original.packet != packet || self.native.active != 4 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original
            .complete(0)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cut = original.stages[0]
            .after_cut()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        native::require_current_map(self.controller, cut)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let (_, prepare, _) = original
            .data()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.controller.get(
            RecordNamespace::ControllerCreateFailurePrepare,
            prepare.operation.as_bytes(),
        ) != Some(prepare.encode_canonical().as_slice())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Commits the sole exact three-row CAS after genuine Host Seal and Root before.
    ///
    /// # Errors
    /// Retains changed C/Root/Host association, native append/readback or owed
    /// posts. No terminal ACK DATA appears before actual C and Root completion.
    pub fn commit_controller_cas_once_v2(
        &mut self,
        root: &mut RootBorrow<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let phase = self.acknowledgement_phase_v2()?;
        self.require_prepared_root_floor_current_v2(
            root.canonical_attestation_data_v2()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
        )?;
        if self.settlement()?.root_before[1].is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let before = root.begin_controller_cas_once_v2(self);
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.root_before[1] = Some(before);
        if before.is_err() {
            original.first[1] = Some(First::RootBefore);
        }
        if before.is_ok() {
            let body = self.commit_controller_cas_body();
            let original = self
                .native
                .settlement
                .as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            original.body[1] = Some(body);
            if matches!(original.body[1], Some(Err(_))) {
                original.first[1].get_or_insert(First::Body);
            }
        }
        let after = root.finish_controller_cas_owed_once_v2();
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.root_after[1] = Some(after);
        if after.is_err() {
            original.first[1].get_or_insert(First::RootAfter);
        }
        original
            .complete(1)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        root.require_controller_cas_complete_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let (floor, prepare, _) = original
            .data()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cut = original.stages[1]
            .after_cut()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if floor.fields().controller_cut.next().checked_add(phase.controller_advance_data_v2()) != Some(cut.next()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.ack = Some(Ack {
            operation: prepare.operation,
            root_floor: prepare.root_floor,
            root_sequence: prepare.root_sequence,
            controller_prepare: prepare.digest(),
            settled_cas: prepare.settled_cas_digest(),
            phase,
            controller_cut: cut,
        });
        original.settled = true;
        self.native.entropy[4] = Some(self.native.nonce[4].observe_once());
        self.no_apply_request_id_data_v2().map(|_| ())
    }

    fn commit_controller_cas_body(&mut self) -> Result<(), JournalError> {
        let original = self
            .native
            .settlement
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (_, prepare, _) = original.data()?;
        let expected = original.stages[0].after_cut()?;
        if self.acknowledgement_phase_v2().map_err(|_| JournalError::ProtectedBoundary)?
            == AckPhase::RecoverySettled {
            return self.run_controller_terminal_replay_once_v2(expected, prepare);
        }
        let plan = self
            .native
            .controller
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?
            .captured_plan_v2()?;
        let records = plan.records_data_v2().to_vec();
        let transaction = JournalTransaction::new(transaction_id(prepare, true), records)?;
        self.run_controller_append(1, transaction, expected)
    }

    /// Borrows ACK only from the actual completed native CAS and both Root posts.
    ///
    /// # Errors
    /// Refuses absent native terminal completion, failed posts or stale global C.
    pub fn controller_acknowledgement_data_v2(&self) -> Result<Ack, ResourceReservationErrorV1> {
        let original = self.settlement()?;
        original
            .complete(1)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let ack = original.ack.ok_or(ResourceReservationErrorV1::Conflict)?;
        native::require_current_map(self.controller, ack.controller_cut)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(ack)
    }

    /// Selects the actual Root cause only when it preceded the native C primary.
    #[doc(hidden)]
    #[must_use]
    pub fn root_failure_selected_v2(&self) -> bool {
        self.native
            .settlement
            .as_deref()
            .is_some_and(ControllerSettlementOriginalV2::root_selected)
    }
}

fn transaction_id(prepare: Prepare, terminal: bool) -> [u8; 16] {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller.no-apply-native-append.v2\0")
        .chain_update(prepare.operation.as_bytes())
        .chain_update(prepare.digest().as_bytes())
        .chain_update([u8::from(terminal)])
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
