//! Retains strict historical Create comparison on the actual Root C reader.
//!
//! Expected immutable rows stay borrowed from the existing geometry pass's
//! real canonical map. Only the same full role replay through COMMIT/EOF and
//! actual native posts can produce the closed historical receipt. It supplies
//! no current Start authority, account, scope, writer or deadline renewal.

use super::*;
use aos_sandbox_model::{OperationId, ProjectId, SandboxId};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    CreateStoppedNativeObservationDataV2, CreateStoppedNativeObservationErrorV2,
    CreateStoppedTerminalTransactionDataV1, CreateStoppedTerminalDataErrorV1,
    CreateStoppedRecoveredTerminalDataErrorV1,
    effect_decoding_receiving_bytes_v1,
};
use sha2::{Digest as _, Sha256};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(super) struct RootStoppedHistoryOriginalV2 {
    parent: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    pub(super) recipe_error: Option<CreateStoppedTerminalDataErrorV1>,
    pub(super) selector_error: Option<CreateStoppedRecoveredTerminalDataErrorV1>,
    pub(super) observation_error: Option<CreateStoppedNativeObservationErrorV2>,
    transaction: Option<[u8; 16]>,
    pub(super) complete: bool,
    taken: bool,
}

impl RootStoppedHistoryOriginalV2 {
    pub(super) fn new(parent: OperationId, project: ProjectId, sandbox: SandboxId) -> Self {
        Self {
            parent,
            project,
            sandbox,
            recipe_error: None,
            selector_error: None,
            observation_error: None,
            transaction: None,
            complete: false,
            taken: false,
        }
    }

    fn rows<'state>(&self, state: &'state State) -> Result<(&'state [u8], &'state [u8]), JournalError> {
        let effect = aos_sandbox_protocol::domain_ledger::operation::effect_key(self.parent, 0);
        let lookup = |namespace, key: &[u8]| {
            state.iter().find_map(|((actual, name), value)| {
                (*actual == namespace && name.as_slice() == key).then_some(value.as_slice())
            })
        };
        let operation = lookup(RecordNamespace::Operation, self.parent.as_bytes())
            .ok_or(JournalError::ProtectedBoundary)?;
        let effect = lookup(RecordNamespace::Effect, &effect)
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok((operation, effect))
    }

    pub(super) fn receiving_demand_v2(&self, audit: &audit::RootControllerReadonlyGeometryAuditV1)
        -> Result<ResourceVector, JournalError> {
        let state = audit.native_data_v1().and_then(|native| native.state())
            .ok_or(JournalError::ProtectedBoundary)?;
        let (_, effect) = self.rows(state)?;
        let effect = effect_decoding_receiving_bytes_v1(effect.len()).ok_or(JournalError::JournalTooLarge)?;
        let projection = aos_sandbox_protocol::public_api::projection::geometry::sandbox_projection_decoding_receiving_bytes_v2(
            audit.maximum_desired_state_value_bytes_v2()?).ok_or(JournalError::JournalTooLarge)?;
        let fixed = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CreateStoppedNativeObservationDataV2<'static>>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CreateStoppedNativeObservationErrorV2>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CreateStoppedRecoveredTerminalDataErrorV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootCreateStoppedHistoricalOriginalV2>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Sha256>()))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(JournalError::JournalTooLarge)?;
        let memory = effect.checked_add(fixed).and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(projection)).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
    }

    pub(super) fn prepare_v2<'audit>(&mut self,
        audit: &'audit audit::RootControllerReadonlyGeometryAuditV1,
    ) -> Result<CreateStoppedNativeObservationDataV2<'audit>, ColdReplayClosedV1> {
        if self.transaction.is_some() || self.recipe_error.is_some()
            || self.selector_error.is_some() || self.complete
        {
            return Err(ColdReplayClosedV1);
        }
        let state = audit.native_data_v1().and_then(|native| native.state()).ok_or(ColdReplayClosedV1)?;
        let (operation, effect) = self.rows(state).map_err(|_| ColdReplayClosedV1)?;
        // This closed purpose decodes only the existing V6/Q04 public Create
        // graph. A hostile V7 cannot enter its separate named-plan parser.
        if effect.first() != Some(&6) {
            self.recipe_error = Some(CreateStoppedTerminalDataErrorV1::Mismatch);
            return Err(ColdReplayClosedV1);
        }
        let base = match CreateStoppedTerminalTransactionDataV1::from_data_v1(
            self.parent, self.project, self.sandbox, operation, effect) {
            Ok(recipe) => recipe,
            Err(cause) => {
                self.recipe_error = Some(cause);
                return Err(ColdReplayClosedV1);
            }
        };
        // Source's common factory selects normal3 or authenticated recovered4
        // from this SAME map; it never borrows today's mutable projection.
        match CreateStoppedNativeObservationDataV2::terminal_from_state_v2(base, state) {
            Ok(observation) => {
                self.transaction = Some(observation.selected_transaction_id_v2());
                Ok(observation)
            }
            Err(cause) => {
                self.selector_error = Some(cause);
                Err(ColdReplayClosedV1)
            }
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.recipe_error.as_ref().map(|cause| cause as _)
            .or_else(|| self.selector_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.observation_error.as_ref().map(|cause| cause as _))
    }
}

/// Holds a historical transaction observed by the actual complete native reader.
///
/// Its private constructor requires real full role replay, exact native EOF,
/// same physical names and all independent mount/name/file posts. These fixed
/// row commitments identify that historical cut; they do not admit a new turn
/// or make a current model/native/Source relation on their own.
pub struct RootCreateStoppedHistoricalOriginalV2 {
    parent: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    operation: [u8; 32],
    effect: [u8; 32],
    transaction: [u8; 16],
    names: ProtectedJournalNamesV1,
    next: u64,
    end: u64,
}

impl RootCreateStoppedHistoricalOriginalV2 {
    /// Returns the historical parent, project and sandbox comparison identities.
    pub fn target_v2(&self) -> (OperationId, ProjectId, SandboxId) {
        (self.parent, self.project, self.sandbox)
    }

    /// Compares exact rows against this owner's actual observed historical cut.
    ///
    /// # Errors
    /// Returns a protected-boundary refusal for changed identities or row digests.
    pub fn require_rows_v2(&self, parent: OperationId, project: ProjectId, sandbox: SandboxId,
        operation: &[u8], effect: &[u8],
    ) -> Result<(), JournalError> {
        if self.parent != parent || self.project != project || self.sandbox != sandbox
            || self.operation != <[u8; 32]>::from(Sha256::digest(operation))
            || self.effect != <[u8; 32]>::from(Sha256::digest(effect)) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Compares this proof with the same actual native reader's cut DATA.
    ///
    /// # Errors
    /// Refuses different physical names or durable coordinates.
    pub fn require_cut_v2(&self, native: &RootFixedNativeReadbackV1<'_>) -> Result<(), JournalError> {
        if self.names != native.names || self.next != native.next || self.end != native.end {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl RootFixedNativeReadOriginalsV1 {
    /// Selects the same fixed C reader with an additional strict history check.
    pub(crate) fn controller_create_stopped_history_v2(parent: OperationId, project: ProjectId, sandbox: SandboxId) -> Self {
        Self { stopped_history: Some(RootStoppedHistoryOriginalV2::new(parent, project, sandbox)),
            ..Self::controller_current_v1() }
    }

    /// Moves a fixed historical receipt only after real full replay/native posts.
    ///
    /// # Errors
    /// Refuses missing selected history, incomplete native/semantic/EOF or any
    /// failed independent post. No stale copied success or amount can enter.
    pub(crate) fn take_create_stopped_historical_v2(&mut self) -> Result<RootCreateStoppedHistoricalOriginalV2, JournalError> {
        let native = self.terminal_native_v1()?;
        let cut = (native.names, native.next, native.end);
        let original = self.stopped_history.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if !original.complete || original.taken || original.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let state = self.audit.native_data_v1().and_then(|native| native.state()).ok_or(JournalError::ProtectedBoundary)?;
        let (operation, effect) = original.rows(state)?;
        let result = RootCreateStoppedHistoricalOriginalV2 {
            parent: original.parent,
            project: original.project,
            sandbox: original.sandbox,
            operation: Sha256::digest(operation).into(),
            effect: Sha256::digest(effect).into(),
            transaction: original.transaction.ok_or(JournalError::ProtectedBoundary)?,
            names: cut.0,
            next: cut.1,
            end: cut.2,
        };
        original.taken = true;
        Ok(result)
    }
}
