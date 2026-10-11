//! Original common admissions and typed results retained beside native resources.

use std::collections::BTreeMap;
use std::rc::Rc;

use crucible_node_contract::{Id, PreparedOwner, U64};
use crucible_node_provider::bodies::BeginRequest;

use crate::{
    node_contract::{
        ActivationRecord, CancelStatus, NativeReclamationReceipt, OperationAdmission,
        OperationFailure, OperationOutcome, ReadyAttestation, WorldActivation,
    },
    node_scheduling::{NativeInputAcknowledgement, NativeSchedulingObservation, RuntimeInputBatch},
};

use super::budget::SemanticCredit;

pub(super) struct OriginalOperation {
    pub(super) admission: OperationAdmission,
    pub(super) begin: BeginRequest,
    pub(super) outcome: Option<OperationOutcome>,
    pub(super) failure: Option<OperationFailure>,
    pub(super) polls: U64,
    pub(super) begin_acknowledged: bool,
    pub(super) cancellation: OriginalCancellation,
    pub(super) acknowledged: bool,
    pub(super) retirement: Option<crate::node_scheduling::InputPayload>,
}

// Only an authenticated Begin response permits an accepted retry. A pending
// record survives activation/upload refusal or unwind without redispatch.
impl OriginalOperation {
    pub(super) fn prepare(
        admission: &OperationAdmission,
        begin: BeginRequest,
        credit: &mut SemanticCredit,
        maximum: usize,
    ) -> Result<(Id, Self), OperationFailure> {
        let request = super::preparation::request_id("begin", admission.token().operation())?;
        credit.reserve(&begin, maximum)?;
        Ok((
            request,
            Self {
                admission: admission.clone(),
                begin,
                outcome: None,
                failure: None,
                polls: U64::new(0),
                begin_acknowledged: false,
                cancellation: OriginalCancellation::NotAttempted,
                acknowledged: false,
                retirement: None,
            },
        ))
    }

    pub(super) fn validate_repeated_begin(&self) -> Result<(), OperationFailure> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        if self.begin_acknowledged {
            return Ok(());
        }
        Err(super::unknown("generic original Begin remains unresolved"))
    }

    pub(super) fn retain_failure(&mut self, failure: &OperationFailure) {
        self.failure = Some(bounded_unknown(failure));
    }

    pub(super) fn cancellation_status(&self) -> Option<Result<CancelStatus, OperationFailure>> {
        if self.outcome.is_some() {
            return Some(Ok(CancelStatus::Terminal));
        }
        if let Some(failure) = &self.failure {
            return Some(Err(failure.clone()));
        }
        match &self.cancellation {
            OriginalCancellation::NotAttempted => None,
            OriginalCancellation::Pending => Some(Err(super::unknown(
                "generic original cancellation request remains unresolved",
            ))),
            OriginalCancellation::Requested => Some(Ok(CancelStatus::AlreadyRequested)),
            OriginalCancellation::Unsupported => Some(Ok(CancelStatus::Unsupported)),
            OriginalCancellation::Failed(failure) => Some(Err(failure.clone())),
        }
    }

    pub(super) fn complete_cancellation(
        &mut self,
        result: Result<bool, OperationFailure>,
    ) -> Result<CancelStatus, OperationFailure> {
        match result {
            Ok(true) => {
                self.cancellation = OriginalCancellation::Requested;
                Ok(CancelStatus::Requested)
            }
            Ok(false) => {
                self.cancellation = OriginalCancellation::Unsupported;
                Ok(CancelStatus::Unsupported)
            }
            Err(failure) => {
                let failure = bounded_unknown(&failure);
                self.cancellation = OriginalCancellation::Failed(failure.clone());
                Err(failure)
            }
        }
    }
}

pub(super) enum OriginalCancellation {
    NotAttempted,
    Pending,
    Requested,
    Unsupported,
    Failed(OperationFailure),
}

fn bounded_unknown(failure: &OperationFailure) -> OperationFailure {
    let mut end = failure.reason.len().min(4096);
    while !failure.reason.is_char_boundary(end) {
        end -= 1;
    }
    super::unknown(&failure.reason[..end])
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

pub(super) struct OriginalInput {
    pub(super) original: Rc<RuntimeInputBatch>,
    pub(super) acknowledgement: Option<NativeInputAcknowledgement>,
    pub(super) watermark: U64,
    pub(super) response: Option<crucible_node_provider::bodies::InputResult>,
}

/// Keeps complete original mutable common custody inside the native resource capsule.
///
/// Adapter Drop cannot discard these admissions, input bodies, failed originals
/// or retained results. The independently reserved supervisor receives them
/// with the same actual Child and complete raw CNP/content journals.
pub(super) struct SemanticRuntimeCustody {
    pub(super) arm_attempt: Option<ActivationRecord>,
    pub(super) ready: Option<ReadyAttestation>,
    pub(super) prepared_owner: Option<PreparedOwner>,
    pub(super) activate_response: Option<crucible_node_provider::bodies::WorldActivateResult>,
    pub(super) observe_sequence: U64,
    pub(super) activation_attempt: Option<WorldActivation>,
    pub(super) active: Option<WorldActivation>,
    pub(super) inputs: BTreeMap<Id, OriginalInput>,
    pub(super) operations: BTreeMap<Id, OriginalOperation>,
    pub(super) watermark: U64,
    pub(super) observation: Option<(WorldActivation, NativeSchedulingObservation)>,
    pub(super) reclaimed: Option<NativeReclamationReceipt>,
    pub(super) credit: SemanticCredit,
    pub(super) quarantined: bool,
}

impl Default for SemanticRuntimeCustody {
    fn default() -> Self {
        Self {
            arm_attempt: None,
            ready: None,
            prepared_owner: None,
            activate_response: None,
            observe_sequence: U64::new(0),
            activation_attempt: None,
            active: None,
            inputs: BTreeMap::new(),
            operations: BTreeMap::new(),
            watermark: U64::new(0),
            observation: None,
            reclaimed: None,
            credit: SemanticCredit::default(),
            quarantined: false,
        }
    }
}
