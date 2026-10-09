//! Retained original construction custody beneath GPL native callbacks.
//!
//! The source selects the original cut at its authenticated RR preparation seam.
//! Reader requests recover retained values and never query or dispatch native
//! callbacks. Unknown effects retain the whole original journal and withhold
//! execution; construction ACKs establish no ready-state guarantee.

use std::sync::{Arc, Mutex};

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    CommandJournalDisposition, NativeCommandError, NativeInitializationAcknowledgement,
    NativeInitializationClass, NativeInitializationCommand, NativeInitializationCut,
    NativeInitializationPreparation, NativeInitializationReceipt, NativeInitializationRow,
    NativeInitializationStatus,
};

use super::initialization_abi::{
    NativeInitializationCommand as SourceCommand, NativeInitializationCut as SourceCut,
    NativeInitializationReceipt as SourceReceipt, NativeInitializationRow as SourceRow,
    QueryInitializationCut,
};

#[derive(Default)]
struct State {
    cut: Option<NativeInitializationCut>,
    command: Option<NativeInitializationCommand>,
    receipt: Option<NativeInitializationReceipt>,
    acknowledged: bool,
    acknowledgement: Option<NativeInitializationAcknowledgement>,
    failed: bool,
}

pub(crate) struct InitializationCustody {
    pub(crate) preparation: NativeInitializationPreparation,
    pub(crate) scope: [u8; 32],
    pub(crate) commitment: [u8; 32],
    query: QueryInitializationCut,
    owner: Arc<()>,
    state: Mutex<State>,
}

/// Retains one actually accepted ACK and its original Applied receipt.
///
/// The private owner identity prevents another initializer with equal portable
/// fields from adopting this record. It authenticates construction custody
/// only; native source roots, complete input and effect permission stay separate.
pub(crate) struct AcknowledgedInitialization {
    owner: Arc<()>,
    receipt: NativeInitializationReceipt,
    acknowledgement: NativeInitializationAcknowledgement,
}

impl AcknowledgedInitialization {
    pub(crate) fn receipt(&self) -> &NativeInitializationReceipt {
        &self.receipt
    }

    pub(crate) fn acknowledgement(&self) -> &NativeInitializationAcknowledgement {
        &self.acknowledgement
    }

    /// Rechecks actual original custody without sampling or admitting native work.
    ///
    /// # Errors
    /// Refuses another initializer, a fault, poisoned/busy ownership or changed
    /// original receipt/ACK. No refused validation replaces historical bytes.
    #[cfg(test)]
    pub(crate) fn validate_original(
        &self,
        initialization: &InitializationCustody,
    ) -> Result<(), NativeCommandError> {
        if self.try_validate_original(initialization)? {
            Ok(())
        } else {
            Err(NativeCommandError::Conflict)
        }
    }

    /// Checks retained original ACK ownership without waiting on the native journal.
    ///
    /// # Errors
    /// Refuses another owner, poison, fault or changed receipt/ACK. False reports
    /// only concurrent ownership; it supplies no effect or readiness authority.
    pub(crate) fn try_validate_original(
        &self,
        initialization: &InitializationCustody,
    ) -> Result<bool, NativeCommandError> {
        if !Arc::ptr_eq(&self.owner, &initialization.owner) {
            return Err(NativeCommandError::Conflict);
        }
        let state = match initialization.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed
            || !state.acknowledged
            || state.receipt.as_ref() != Some(&self.receipt)
            || state.acknowledgement.as_ref() != Some(&self.acknowledgement)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(true)
    }
}

impl InitializationCustody {
    pub(crate) fn new(
        preparation: NativeInitializationPreparation,
        query: QueryInitializationCut,
    ) -> Result<Self, NativeCommandError> {
        preparation.validate()?;
        Ok(Self {
            scope: preparation.preparation.scope.identity_digest()?,
            commitment: preparation.identity_digest()?,
            preparation,
            query,
            owner: Arc::new(()),
            state: Mutex::new(State::default()),
        })
    }

    /// Queries only the actual authenticated preparation callback seam.
    pub(crate) fn observe_original_cut(
        &self,
    ) -> Result<Option<NativeInitializationCut>, NativeCommandError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        if let Some(cut) = &state.cut {
            return Ok(Some(cut.clone()));
        }
        let mut summary = SourceCut::default();
        let mut rows = [SourceRow::default(); 64];
        let status = (self.query)(
            self.scope.as_ptr(),
            self.commitment.as_ptr(),
            &mut summary,
            rows.as_mut_ptr(),
            rows.len() as u32,
        );
        if status != 0 {
            if summary == SourceCut::default()
                && matches!(status, value if value == -libc::EAGAIN || value == -libc::EPERM)
            {
                return Ok(None);
            }
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        if summary.version != 1
            || summary.size != 120
            || summary.flags != 0
            || summary.row_count > 64
        {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        let converted_rows = rows[..summary.row_count as usize]
            .iter()
            .map(|row| {
                if row.flags != 0 {
                    return Err(NativeCommandError::Conflict);
                }
                let class = match row.class_id {
                    1 => NativeInitializationClass::QmpDispatcherStartup,
                    2 => NativeInitializationClass::EmptyCoroutineNotification,
                    4 => NativeInitializationClass::IdeZeroErrorRestart,
                    _ => return Err(NativeCommandError::Conflict),
                };
                Ok(NativeInitializationRow {
                    class,
                    callback_id: U64::new(row.callback_id),
                    arm_generation: U64::new(row.arm_generation),
                    context_id: U64::new(row.context_id),
                })
            })
            .collect::<Result<_, _>>();
        let rows = match converted_rows {
            Ok(rows) => rows,
            Err(error) => {
                state.failed = true;
                return Err(error);
            }
        };
        let cut = NativeInitializationCut {
            hold_generation: U64::new(summary.hold_generation),
            prepared_scope_hash: summary.prepared_scope_hash,
            initialization_commitment: summary.initialization_commitment,
            original_cut_digest: summary.original_cut_digest,
            rows,
        };
        if let Err(error) = cut.validate_against(&self.preparation) {
            state.failed = true;
            return Err(error);
        }
        state.cut = Some(cut.clone());
        Ok(Some(cut))
    }

    pub(crate) fn original_cut(&self) -> Option<NativeInitializationCut> {
        self.state.lock().ok()?.cut.clone()
    }

    pub(crate) fn retain(
        &self,
        command: NativeInitializationCommand,
    ) -> Result<CommandJournalDisposition, NativeCommandError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let cut = state.cut.as_ref().ok_or(NativeCommandError::Conflict)?;
        command.validate_against(&self.preparation, cut)?;
        if let Some(original) = &state.command {
            if original != &command {
                return Err(NativeCommandError::Conflict);
            }
            return Ok(if state.acknowledged {
                CommandJournalDisposition::Acknowledged
            } else if state.receipt.is_some() {
                CommandJournalDisposition::Stopped
            } else if state.failed {
                return Err(NativeCommandError::Conflict);
            } else {
                CommandJournalDisposition::Outstanding
            });
        }
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        state.command = Some(command);
        Ok(CommandJournalDisposition::New)
    }

    pub(crate) fn command(&self) -> Option<SourceCommand> {
        let state = self.state.lock().ok()?;
        if state.failed || state.receipt.is_some() {
            return None;
        }
        let original = state.command.as_ref()?;
        Some(SourceCommand {
            version: 1,
            size: 152,
            class_mask: original.class_mask,
            maximum_callbacks: original.maximum_callbacks,
            sequence: original.sequence.get(),
            prepared_scope_hash: original.prepared_scope_hash,
            realize_request_digest: original.realize_request_digest,
            policy_digest: original.policy_digest,
            original_cut_digest: original.original_cut_digest,
        })
    }

    pub(crate) fn record_receipt(
        &self,
        raw: SourceReceipt,
    ) -> Result<NativeInitializationReceipt, NativeCommandError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let result = validate_receipt(&state, raw);
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                state.failed = true;
                return Err(error);
            }
        };
        if state
            .receipt
            .as_ref()
            .is_some_and(|original| original != &receipt)
        {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        if receipt.status == NativeInitializationStatus::EffectsUnknown {
            state.failed = true;
        }
        state.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub(crate) fn original_receipt(&self) -> Option<NativeInitializationReceipt> {
        self.state.lock().ok()?.receipt.clone()
    }

    pub(crate) fn acknowledge(
        &self,
        ack: &NativeInitializationAcknowledgement,
    ) -> Result<(), NativeCommandError> {
        ack.encode()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if state.failed || state.receipt.is_none() {
            return Err(NativeCommandError::Conflict);
        }
        let original = state.command.as_ref().ok_or(NativeCommandError::Conflict)?;
        if ack.prepared_scope_hash != self.scope
            || ack.initialization_commitment != self.commitment
            || ack.sequence != original.sequence
            || ack.command_digest != original.identity_digest()?
        {
            return Err(NativeCommandError::Conflict);
        }
        state.acknowledged = true;
        // The accepted original frame remains distinct from an inferred ACK
        // assembled later from scalar Applied or matching preparation fields.
        state.acknowledgement = Some(ack.clone());
        Ok(())
    }

    /// Copies the actual original ACK under the initializer's private custody.
    ///
    /// # Errors
    /// Refuses an absent ACK, a non-Applied receipt, fault or busy/poisoned journal.
    /// Matching portable fields cannot mint this record for another live owner.
    #[cfg(test)]
    pub(crate) fn acknowledged_original(
        &self,
    ) -> Result<AcknowledgedInitialization, NativeCommandError> {
        self.try_acknowledged_original()?
            .ok_or(NativeCommandError::Conflict)
    }

    /// Distinguishes a temporarily owned journal from an invalid original ACK.
    ///
    /// # Errors
    /// Refuses an absent actual ACK, failed/poisoned custody or non-Applied receipt.
    /// None retains the same original owner while a native callback owns its lock.
    pub(crate) fn try_acknowledged_original(
        &self,
    ) -> Result<Option<AcknowledgedInitialization>, NativeCommandError> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed || !state.acknowledged {
            return Err(NativeCommandError::Conflict);
        }
        self.acknowledged_from_state(&state).map(Some)
    }

    /// Waits without holding admission when the original ACK has not arrived.
    ///
    /// # Errors
    /// Refuses failed/poisoned custody and original non-Applied receipts. None
    /// reports only a busy journal or the still-pending same-original ACK.
    pub(crate) fn try_pending_acknowledged_original(
        &self,
    ) -> Result<Option<AcknowledgedInitialization>, NativeCommandError> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed
            || state
                .receipt
                .as_ref()
                .is_some_and(|receipt| receipt.status != NativeInitializationStatus::Applied)
        {
            return Err(NativeCommandError::Conflict);
        }
        if !state.acknowledged {
            return Ok(None);
        }
        self.acknowledged_from_state(&state).map(Some)
    }

    fn acknowledged_from_state(
        &self,
        state: &State,
    ) -> Result<AcknowledgedInitialization, NativeCommandError> {
        let receipt = state
            .receipt
            .as_ref()
            .filter(|receipt| receipt.status == NativeInitializationStatus::Applied)
            .ok_or(NativeCommandError::Conflict)?;
        let acknowledgement = state
            .acknowledgement
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        Ok(AcknowledgedInitialization {
            owner: Arc::clone(&self.owner),
            receipt: receipt.clone(),
            acknowledgement: acknowledgement.clone(),
        })
    }

    pub(crate) fn permits_execution_transport(&self) -> bool {
        self.state.lock().ok().is_some_and(|state| {
            !state.failed
                && state.acknowledged
                && state
                    .receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.status == NativeInitializationStatus::Applied)
        })
    }

    pub(crate) fn fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.failed = true;
        }
    }
}

fn validate_receipt(
    state: &State,
    raw: SourceReceipt,
) -> Result<NativeInitializationReceipt, NativeCommandError> {
    if raw.version != 1 || raw.size != 160 {
        return Err(NativeCommandError::Conflict);
    }
    let status = match raw.status {
        1 => NativeInitializationStatus::Applied,
        2 => NativeInitializationStatus::Unsupported,
        3 => NativeInitializationStatus::Stale,
        4 => NativeInitializationStatus::Invalid,
        5 => NativeInitializationStatus::EffectsUnknown,
        _ => return Err(NativeCommandError::Conflict),
    };
    let receipt = NativeInitializationReceipt {
        status,
        applied_callbacks: raw.applied_callbacks,
        sequence: U64::new(raw.sequence),
        hold_generation: U64::new(raw.hold_generation),
        prepared_scope_hash: raw.prepared_scope_hash,
        initialization_commitment: raw.initialization_commitment,
        original_cut_digest: raw.original_cut_digest,
        realize_request_digest: raw.realize_request_digest,
    };
    receipt.validate_against(
        state.command.as_ref().ok_or(NativeCommandError::Conflict)?,
        state.cut.as_ref().ok_or(NativeCommandError::Conflict)?,
    )?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "initialization_custody_tests.rs"]
// crucible-lint: allow panic-shortcut -- These initialization custody tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests;
