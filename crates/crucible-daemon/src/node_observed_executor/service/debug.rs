//! Owns live installed condition control and its original durable request history.
//!
//! ```text
//! DebugPreparation.1 = exact original start -> stopped report -> original resume
//! ```
//!
//! Historical records are status data. Only the current owning actor can use
//! its retained runtime fence; neither a nonce retry nor a daemon restart
//! creates native stop, report, acknowledgement or resume authority.

mod budget;
mod ledger;
#[cfg(test)]
mod tests;
mod worker;

use super::{NodeObservationServiceError, refused};
use crate::node_observed_executor::{InstalledNodeKind, InstalledNodeSelection};
use crucible_node_contract::{ContentRef, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
};

use super::{ActorStorage, ActorWorker, Command, NodeObservationService};
use crate::node_observed_executor::InstalledNodeCatalog;
use crucible_campaign::ExecutionId;

pub(super) use ledger::{DebugLedger, DebugReservation};
pub(super) use worker::DebugWorker;

/// Selects a complete installed live world and its explicit condition budget.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDebugStartRequest {
    /// Names this closed request format.
    pub format: String,
    /// Selects the explicit first live-control edition.
    pub version: u32,
    /// Retains the globally unique original execution nonce.
    pub execution: String,
    /// Names every actual installed participant and owner, in node order.
    pub selections: Vec<InstalledNodeSelection>,
    /// Names the selected condition observer in this complete world.
    pub observer: Id,
    /// Bounds physical work without claiming scenario EOF or finalization.
    pub maximum_physical_cut: U64,
}

impl NodeDebugStartRequest {
    /// Checks closed authored scope before reserving an original or allocating.
    ///
    /// # Errors
    /// Refuses unknown editions, unsafe nonces, incomplete or unordered rosters,
    /// an absent condition observer, unsupported model kinds or excessive bytes.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(&self.execution)?;
        self.observer.validate().map_err(refused)?;
        if self.format != "crucible.live-debug-start"
            || self.version != 1
            || self.maximum_physical_cut.get() == 0
            || self.selections.is_empty()
            || self.selections.len() > 64
            || self
                .selections
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
        {
            return Err(refused(
                "live Debug request edition or complete geometry differs",
            ));
        }
        let mut observers = 0;
        for selection in &self.selections {
            selection.node.validate().map_err(refused)?;
            selection.owner.validate().map_err(refused)?;
            match &selection.kind {
                InstalledNodeKind::HostConditionDebug { .. } if selection.node == self.observer => {
                    observers += 1;
                }
                InstalledNodeKind::HostClock
                | InstalledNodeKind::HostScripted { .. }
                | InstalledNodeKind::HostIo {
                    profile: crate::node_observed_executor::InstalledHostIoProfile::Block { .. },
                } => {}
                _ => return Err(refused("model is outside the qualified live Debug scope")),
            }
        }
        budget::bounded_json(self, 1024 * 1024)?;
        if observers != 1 || encode(self)?.len() > 1024 * 1024 {
            return Err(refused(
                "live Debug observer or original byte credit differs",
            ));
        }
        Ok(())
    }

    /// Decodes bounded duplicate-free JSON without installing client authority.
    ///
    /// # Errors
    /// Refuses excessive bytes, duplicate or unknown keys and invalid scope.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 1024 * 1024).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Requests one original resume of the retained, durably reported live stop.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDebugResumeRequest {
    /// Names this closed resume request format.
    pub format: String,
    /// Selects the explicit first live-control edition.
    pub version: u32,
    /// Names the unchanged original execution and current owning actor.
    pub execution: String,
    /// Names the original native resume operation, never a retry substitute.
    pub operation: Id,
    /// Bounds the original resumed suffix without declaring terminal EOF.
    pub horizon_ps: U64,
}

impl NodeDebugResumeRequest {
    /// Checks the original resume request before durable admission.
    ///
    /// # Errors
    /// Refuses unknown editions, malformed nonces or IDs and zero horizons.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(&self.execution)?;
        self.operation.validate().map_err(refused)?;
        if self.format != "crucible.live-debug-resume"
            || self.version != 1
            || self.horizon_ps.get() == 0
            || encode(self)?.len() > 4096
        {
            return Err(refused("live Debug resume edition or finite scope differs"));
        }
        Ok(())
    }

    /// Decodes a closed, bounded original resume request without native authority.
    ///
    /// # Errors
    /// Refuses excessive bytes, duplicate or unknown keys and malformed scope.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 4096).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Reports retained original custody without returning native authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeDebugState {
    /// Exact request bytes are durable, but native admission is not claimed.
    AwaitingAdmission {},
    /// The original live stop and current durable report were acknowledged.
    Stopped {
        /// Retains the authentic complete-world stop position.
        cut: Position,
        /// Names the unchanged original whole-world stop receipt.
        barrier: ContentRef,
        /// Names the original native condition report with durable dependencies.
        report: ContentRef,
    },
    /// One exact original resume request is durable, without completion authority.
    AwaitingResume {
        /// Roots its exact immutable request bytes.
        request: String,
    },
    /// The original resume and its continued suffix completed and were ACKed.
    Resumed {
        /// Names the original native resume receipt.
        receipt: ContentRef,
        /// Roots all unchanged native output bytes and coordinates from this run.
        publications: ContentRef,
    },
    /// Original custody requires reconciliation; retries never redispatch it.
    Unknown {
        /// Gives a bounded local diagnostic without claiming absence of effects.
        reason: String,
    },
}

/// Retains the original acknowledged Stop independently of later resume state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDebugStop {
    /// Retains the authentic whole-world stop position.
    pub cut: Position,
    /// Names the original stop receipt and its native dependency closure.
    pub barrier: ContentRef,
    /// Names the original condition report acknowledged before resume.
    pub report: ContentRef,
}

/// Retains an exact original request and its durable data-only control state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDebugRecord {
    /// Names this closed durable record format.
    pub format: String,
    /// Selects the first record edition independently of the transport.
    pub version: u32,
    /// Preserves the original execution nonce across actor incarnations.
    pub execution: String,
    /// Roots the exact original start bytes by their CAS identity.
    pub request: String,
    /// Roots the once-only original resume bytes after later state transitions.
    pub resume_request: Option<String>,
    /// Preserves the acknowledged stop through resume and later status reads.
    pub stop: Option<NodeDebugStop>,
    /// Retains current original custody without granting a native operation.
    pub outcome: NodeDebugState,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeObservationServiceError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(refused)?).map_err(refused)
}

impl NodeObservationService {
    /// Durably reserves a globally unique original live Debug request before queueing.
    ///
    /// A returned pending record grants no native authority. Exact retries read
    /// retained originals; an absent actor after restart never redispatches them.
    ///
    /// # Errors
    /// Refuses malformed scope, foreign nonce ownership, exhausted queue or
    /// durable storage failure. An ambiguously queued original remains reserved.
    pub fn start_debug(
        &self,
        request: NodeDebugStartRequest,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.debug.reserve_start(&request)?;
        let record = reservation.record.clone();
        if reservation.original_dispatch {
            self.send(Command::DebugStart {
                request,
                reservation,
            })?;
        }
        Ok(record)
    }

    /// Reserves the once-only resume of an original current-actor live stop.
    ///
    /// # Errors
    /// Refuses changed original resume bytes, a missing durable stop, foreign
    /// ownership, unavailable actor or bounded queue failure. Historical status
    /// alone never supplies a replacement runtime or resume authority.
    pub fn resume_debug(
        &self,
        request: NodeDebugResumeRequest,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.debug.reserve_resume(&request)?;
        let record = reservation.record.clone();
        if reservation.original_dispatch {
            self.send(Command::DebugResume {
                request,
                reservation,
            })?;
        }
        Ok(record)
    }

    /// Reads authenticated durable original status without native effects.
    ///
    /// # Errors
    /// Refuses an absent, corrupt or incompatible original record or request.
    pub fn debug_state(
        &self,
        execution: &str,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        self.debug.state(execution)
    }
}

pub(super) fn start_owned(
    request: NodeDebugStartRequest,
    reservation: DebugReservation,
    workers: &BTreeMap<ExecutionId, ActorWorker>,
    debug: &mut BTreeMap<ExecutionId, DebugWorker>,
    catalog: &mut InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: &ActorStorage,
) {
    let execution = match super::conditional_preparation::execution_id(&request.execution) {
        Ok(execution) => execution,
        Err(_) => return,
    };
    if workers.contains_key(&execution)
        || debug.contains_key(&execution)
        || storage
            .repository
            .observed_execution_state(execution)
            .map_or(true, |state| state.is_some())
        || workers.len().saturating_add(debug.len()) >= maximum_worlds
    {
        let _ = storage.debug.complete(
            &reservation,
            NodeDebugState::Unknown {
                reason: "original world ownership or aggregate capacity refused Debug admission"
                    .into(),
            },
        );
        return;
    }
    let owned = match DebugWorker::new(request, reservation) {
        Ok(owned) => owned,
        // Original durable reservation remains authoritative and cannot be
        // converted into dispatch by any retry when allocation is unavailable.
        Err(_) => return,
    };
    debug.insert(execution, owned);
    if let Some(owned) = debug.get_mut(&execution)
        && let Err(error) = owned.start(catalog, storage)
    {
        owned.fail(error);
    }
}

pub(super) fn resume_owned(
    request: NodeDebugResumeRequest,
    reservation: DebugReservation,
    debug: &mut BTreeMap<ExecutionId, DebugWorker>,
    storage: &ActorStorage,
) {
    let execution = match super::conditional_preparation::execution_id(&request.execution) {
        Ok(execution) => execution,
        Err(_) => return,
    };
    let Some(owned) = debug.get_mut(&execution) else {
        let _ = storage.debug.complete(
            &reservation,
            NodeDebugState::Unknown {
                reason: "historical Debug record has no current original native owner".into(),
            },
        );
        return;
    };
    if let Err(error) = owned.resume(request, reservation, storage) {
        owned.fail(error);
    }
}

pub(super) fn poll_owned(
    debug: &mut BTreeMap<ExecutionId, DebugWorker>,
    storage: &ActorStorage,
    stopping: &AtomicBool,
) {
    for owned in debug.values_mut() {
        if stopping.load(Ordering::Acquire) {
            if catch_unwind(AssertUnwindSafe(|| owned.contain())).is_err() {
                owned.fail("native Debug containment requires original reconciliation");
            }
            if owned.publication_pending() {
                let _ = catch_unwind(AssertUnwindSafe(|| owned.publish_completed_suffix(storage)));
            }
        } else {
            match catch_unwind(AssertUnwindSafe(|| owned.poll(storage))) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if !owned.publication_pending() {
                        owned.fail(error);
                    }
                }
                Err(_) => {
                    if !owned.publication_pending() {
                        owned.fail("original Debug callback unwound with complete world retained");
                    }
                    stopping.store(true, Ordering::Release);
                }
            }
        }
        if !owned.published
            && let Some(outcome) = &owned.outcome
        {
            // This exact outcome remains in the owner on ordinary failure or
            // callback unwind. Publication retry never reruns native control.
            match catch_unwind(AssertUnwindSafe(|| {
                storage.debug.complete(&owned.reservation, outcome.clone())
            })) {
                Ok(Ok(_)) => owned.published = true,
                Ok(Err(_)) => {}
                Err(_) => stopping.store(true, Ordering::Release),
            }
        }
    }
}
