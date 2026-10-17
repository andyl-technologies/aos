//! Closed baseline CNP/1 requests, results, operation arguments, and notifications.
//!
//! Method validation checks syntax and local consistency. It does not authenticate
//! owner coverage, native receipts, referenced schemas, or live effect authority.

use crucible_node_contract::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use crate::{
    ProviderError,
    envelope::{Method, Nullable},
    handshake::{HelloRequest, HelloResult},
};

mod operations;
mod requests;
mod responses;
mod results;

pub use operations::*;
pub use requests::*;
pub use responses::*;
pub use results::*;

pub(crate) fn invalid(field: &'static str, reason: &'static str) -> ContractError {
    ContractError::Invalid {
        field,
        reason: reason.to_owned(),
    }
}

fn count<T>(values: &[T], field: &'static str) -> Result<(), ContractError> {
    if values.len() > MAX_ARRAY_ELEMENTS {
        return Err(invalid(field, "array exceeds 65536 elements"));
    }
    Ok(())
}

fn sorted<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), ContractError> {
    count(values, field)?;
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(invalid(
            field,
            "set must be strictly sorted without duplicates",
        ));
    }
    Ok(())
}

fn ids(values: &[Id], field: &'static str) -> Result<(), ContractError> {
    sorted(values, Clone::clone, field)
}

fn domain(hash: &HashRef, expected: &'static str) -> Result<(), ContractError> {
    hash.validate()?;
    if hash.domain != expected {
        return Err(invalid("hash.domain", "incorrect typed identity domain"));
    }
    Ok(())
}

fn optional_nonnull<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn object<T: DeserializeOwned + Validate>(value: &Map<String, Value>) -> Result<T, ContractError> {
    // Programmatic callers receive the same hard nesting/array/frame ceilings
    // as decoded transport data, without enabling any legacy JSON features.
    let bytes = canonical::canonical_json(&Value::Object(value.clone()))?;
    if bytes.len() > 16_777_216 {
        return Err(invalid("body", "body exceeds hard frame ceiling"));
    }
    let decoded: T = serde_json::from_value(Value::Object(value.clone()))?;
    decoded.validate()?;
    Ok(decoded)
}

/// Selects a closed baseline begin-operation argument schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BeginKind {
    /// Executes qualified exact modeled work within an exclusive limit.
    ExactRun,
    /// Settles explicitly authorized same-time phase work.
    BoundarySettle,
    /// Starts one admitted physical execution window.
    QuantumBegin,
    /// Requests qualified physical suspension.
    Pause,
    /// Captures an unchanged complete owner boundary.
    Capture,
    /// Prepares compatible restoration under a closed gate.
    PrepareRestore,
    /// Stops and reaps owned resources.
    Shutdown,
}

/// Selects a qualified exact-stop representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryPolicy {
    /// Requires an ordinary representable stopped boundary.
    OrdinaryStop,
    /// Requires a separately qualified preservable input-boundary park.
    InputBlockedPark,
}

/// Reports admitted budget disposition without shifting modeled deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetOutcome {
    /// Completes within the admitted hardware budget.
    WithinBudget,
    /// Applies the admitted stall policy.
    Stall,
    /// Applies the admitted timeout policy.
    Timeout,
    /// Applies the admitted containment/failure policy.
    Fail,
}

/// Classifies an exact execution stop without substituting for native evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Parks administratively at the exclusive ceiling.
    Ceiling,
    /// Stops at a qualified next-attention boundary.
    Attention,
    /// Preserves unresolved input custody.
    InputRequired,
    /// Preserves newly produced pending output.
    Output,
    /// Reports a qualified idle boundary.
    Idle,
    /// Completes an authenticated cancellation.
    Canceled,
    /// Reports contained implementation failure.
    Failed,
}

/// Selects authenticated outcome retirement or inert transfer abandonment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementDisposition {
    /// Requires a nonnull durable acceptance or transferred-custody receipt.
    Consumed,
    /// Abandons only inert blob-transfer requests without custody receipt.
    AbandonedInertTransfer,
}

/// Contains a decoded baseline request without granting any effect authority.
#[derive(Clone, Debug, PartialEq)]
pub enum RequestBody {
    /// Contains the closed `Hello` request fields.
    Hello(HelloRequest),
    /// Contains the closed `Discover` request fields.
    Discover(DiscoverRequest),
    /// Contains the closed `Realize` request fields.
    Realize(RealizeRequest),
    /// Contains the closed `Admit` request fields.
    Admit(AdmitRequest),
    /// Contains the closed `Activate` request fields.
    Activate(ActivateRequest),
    /// Contains the closed `Input` request fields.
    Input(InputRequest),
    /// Contains the closed `Observe` request fields.
    Observe(ObserveRequest),
    /// Contains the closed `Begin` request fields.
    Begin(BeginRequest),
    /// Contains the closed `Poll` request fields.
    Poll(PollRequest),
    /// Contains the closed `Cancel` request fields.
    Cancel(CancelRequest),
    /// Contains the closed `QuantumClose` request fields.
    QuantumClose(QuantumCloseRequest),
    /// Contains the closed `WorldActivate` request fields.
    WorldActivate(WorldActivateRequest),
    /// Contains the closed `Abort` request fields.
    Abort(AbortRequest),
    /// Contains the closed `Retire` request fields.
    Retire(RetireRequest),
    /// Contains the closed `BlobBegin` request fields.
    BlobBegin(BlobBeginRequest),
    /// Contains the closed `BlobChunk` request fields.
    BlobChunk(BlobChunkRequest),
    /// Contains the closed `BlobFinish` request fields.
    BlobFinish(BlobFinishRequest),
    /// Contains the closed `Release` request fields.
    Release(ReleaseRequest),
}

/// Decodes the exact closed request schema selected by the envelope method.
///
/// # Errors
/// Rejects missing/unknown fields, noncanonical scalars, unsupported methods,
/// hard bounds, and locally inconsistent operation arguments.
pub fn decode_request(
    method: Method,
    body: &Map<String, Value>,
) -> Result<RequestBody, ProviderError> {
    Ok(match method {
        Method::Hello => RequestBody::Hello(object(body)?),
        Method::Discover => RequestBody::Discover(object(body)?),
        Method::Realize => RequestBody::Realize(object(body)?),
        Method::Admit => RequestBody::Admit(object(body)?),
        Method::Activate => RequestBody::Activate(object(body)?),
        Method::Input => RequestBody::Input(object(body)?),
        Method::Observe => RequestBody::Observe(object(body)?),
        Method::Begin => RequestBody::Begin(object(body)?),
        Method::Poll => RequestBody::Poll(object(body)?),
        Method::Cancel => RequestBody::Cancel(object(body)?),
        Method::QuantumClose => RequestBody::QuantumClose(object(body)?),
        Method::WorldActivate => RequestBody::WorldActivate(object(body)?),
        Method::Abort => RequestBody::Abort(object(body)?),
        Method::Retire => RequestBody::Retire(object(body)?),
        Method::BlobBegin => RequestBody::BlobBegin(object(body)?),
        Method::BlobChunk => RequestBody::BlobChunk(object(body)?),
        Method::BlobFinish => RequestBody::BlobFinish(object(body)?),
        Method::Release => RequestBody::Release(object(body)?),
        _ => {
            return Err(ProviderError::Frame(
                "notification method cannot originate a request",
            ));
        }
    })
}

/// Contains the selected baseline begin-operation arguments.
#[derive(Clone, Debug, PartialEq)]
pub enum BeginArguments {
    /// Contains exact execution grant arguments.
    ExactRun(ExactRunArguments),
    /// Contains same-time phased settlement arguments.
    BoundarySettle(ExactRunArguments),
    /// Contains bounded physical execution grant arguments.
    QuantumBegin(QuantumBeginArguments),
    /// Contains physical suspension arguments.
    Pause(PauseArguments),
    /// Contains unchanged capture arguments.
    Capture(CaptureArguments),
    /// Contains compatible preparation arguments.
    PrepareRestore(PrepareRestoreArguments),
    /// Contains stop/reap arguments.
    Shutdown(ShutdownArguments),
}

impl Validate for BeginArguments {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::ExactRun(value) => {
                value.validate()?;
                if value.limit.microstep.get() != 0
                    || value.limit.phase != crucible_node_contract::Phase::BoundaryControl
                {
                    return Err(invalid(
                        "limit",
                        "an exact physical ceiling excludes every position at its tick",
                    ));
                }
                Ok(())
            }
            Self::BoundarySettle(value) => {
                value.validate()?;
                if value.start.time_ps != value.limit.time_ps {
                    return Err(invalid(
                        "limit",
                        "boundary settlement must stay within one physical tick",
                    ));
                }
                Ok(())
            }
            Self::QuantumBegin(value) => value.validate(),
            Self::Pause(value) => value.validate(),
            Self::Capture(value) => value.validate(),
            Self::PrepareRestore(value) => value.validate(),
            Self::Shutdown(value) => value.validate(),
        }
    }
}

impl BeginRequest {
    /// Decodes the exact arguments selected by the operation kind.
    ///
    /// # Errors
    /// Rejects unknown fields, missing values, bounds, and a grant whose live
    /// generation or activation disagrees with the enclosing request.
    pub fn decoded_arguments(&self) -> Result<BeginArguments, ContractError> {
        let arguments = match self.kind {
            BeginKind::ExactRun => BeginArguments::ExactRun(object(&self.arguments)?),
            BeginKind::BoundarySettle => BeginArguments::BoundarySettle(object(&self.arguments)?),
            BeginKind::QuantumBegin => BeginArguments::QuantumBegin(object(&self.arguments)?),
            BeginKind::Pause => BeginArguments::Pause(object(&self.arguments)?),
            BeginKind::Capture => BeginArguments::Capture(object(&self.arguments)?),
            BeginKind::PrepareRestore => BeginArguments::PrepareRestore(object(&self.arguments)?),
            BeginKind::Shutdown => BeginArguments::Shutdown(object(&self.arguments)?),
        };
        let grant = match &arguments {
            BeginArguments::ExactRun(value) | BeginArguments::BoundarySettle(value) => Some((
                value.owner_generation,
                value.world_generation,
                &value.activation_id,
            )),
            BeginArguments::QuantumBegin(value) => Some((
                value.owner_generation,
                value.world_generation,
                &value.activation_id,
            )),
            _ => None,
        };
        if let Some((owner, world, activation)) = grant
            && (owner != self.owner_generation
                || world != self.world_generation
                || self.activation_id.0.as_ref() != Some(activation))
        {
            return Err(invalid(
                "arguments",
                "grant disagrees with enclosing live authority",
            ));
        }
        arguments.validate()?;
        Ok(arguments)
    }
}

impl InputRequest {
    /// Reconstructs and verifies the complete input batch for the envelope owner.
    ///
    /// # Errors
    /// Rejects input schema violations or a claimed batch hash that differs
    /// from the complete owner-scoped batch identity.
    pub fn verified_batch(&self, owner: &Id) -> Result<InputBatch, ContractError> {
        self.validate()?;
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: owner.clone(),
            input_epoch: self.input_epoch.clone(),
            batch_id: self.batch_id.clone(),
            batch_sequence: self.batch_sequence,
            events: self.events.clone(),
            extensions: self.extensions.clone(),
        };
        if batch.identity()? != self.batch_hash {
            return Err(invalid(
                "batch_hash",
                "input batch hash disagrees with reconstructed owner custody",
            ));
        }
        Ok(batch)
    }
}

impl PollResult {
    /// Decodes a retained terminal outcome against the original begin request.
    ///
    /// # Errors
    /// Rejects changed operation kind, malformed terminal evidence, or progress
    /// outside the original grant. Missing nonterminal outcomes return `None`.
    pub fn validated_outcome(
        &self,
        original: &BeginRequest,
    ) -> Result<Option<ResponseBody>, ProviderError> {
        self.validate()?;
        self.outcome
            .0
            .as_ref()
            .map(|outcome| decode_response(&RequestBody::Begin(original.clone()), outcome))
            .transpose()
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These bodies tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests;
