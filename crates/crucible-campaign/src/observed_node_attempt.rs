//! Independently identified observations from realization-aware node execution.
//!
//! A planned world does not identify an observed execution. Requests bind the
//! complete admitted realization and immutable inputs; results additionally bind
//! a fresh execution nonce and the actual boundary-input/output evidence. This
//! family never enters the legacy deterministic observation cache.
//!
//! ```text
//! ObservedRequestV1 = version | execution | capabilities | inputs
//! ConditionalRequestV2 = 2 | execution | capabilities | inputs | original-scope
//! ObservedResultV1 = version | request | incoming | outgoing | evidence | outcome
//! ObservedLedgerV1 = version | capabilities-digest | execution-index-root
//! ObservedStateV1 = version | request | reserved/completed/quarantined
//! ObservedDispatchReservationV1 = version | ledger-name | request
//! ```

use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{ContentId, ObjectKind};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::executor_node_capabilities::ExecutorNodeCapabilities;
use crate::{CampaignCodecError, CampaignHash, ExecutionId};

mod conditional;
mod envelope;
mod ledger;
mod request;
mod result;
mod worker;

pub use conditional::ConditionalReplayScope;
pub(crate) use envelope::ObservedEnvelopeRecord;
pub use ledger::{ObservedAttemptState, ObservedExecutionPermit, ObservedReservation};
pub(crate) use ledger::{ObservedDispatchReservation, ObservedLedger, execution_key};
pub use request::{ObservedAttemptAdmission, ObservedAttemptRequest};
pub use result::{ObservedAttemptId, ObservedAttemptOutcome, ObservedAttemptResult};
pub use worker::{ObservedAttemptBackend, ObservedAttemptWorker, ObservedWorkerError};

const VERSION: u32 = 1;
pub(crate) const MAX_OBSERVED_RECORD_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn require_version(decoder: &mut Decoder<'_>) -> Result<(), CampaignCodecError> {
    if decoder.u32()? != VERSION {
        return Err(CampaignCodecError::InvalidValue {
            reason: "unsupported observed-node-attempt schema version",
        });
    }
    Ok(())
}

pub(crate) fn envelope(
    schema: &str,
    children: impl IntoIterator<Item = (&'static str, ContentId)>,
    body: Vec<u8>,
) -> Result<ContentEnvelope, CampaignCodecError> {
    let children = children
        .into_iter()
        .map(|(role, id)| ContentChild::new(role, id))
        .collect::<Result<_, _>>()?;
    Ok(ContentEnvelope::new(schema, VERSION, children, body)?)
}

#[cfg(test)]
mod tests;
