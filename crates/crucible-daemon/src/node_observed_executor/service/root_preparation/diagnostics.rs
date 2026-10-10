//! Retains finite data-only diagnostics independently of the native actor queue.
//!
//! ```text
//! RootDiagnostic.1 = original request + revision + phase + original custody view + first refusal
//! ```
//!
//! A diagnostic neither changes admission status nor establishes reclamation. One
//! original writer publishes at most 64 changed snapshots of 16 KiB each, with
//! one additional slot reserved for its first refusal. Only
//! its current snapshot is a GC root; the first refusal remains in every successor.

use super::super::NodeObservationServiceError;
use super::ledger::RootPreparationLedger;
use super::{RootPreparationRecord, encode, refused, validate_execution};
use crucible_node_contract::{Id, Position, canonical};
use serde::{Deserialize, Serialize};

use crate::node_observed_executor::{InstalledRootCleanupFailure, InstalledRootCleanupStatus};

pub(super) const MAXIMUM_BYTES: usize = 16 * 1024;
const MAXIMUM_REVISIONS: u32 = 64;

/// Reports the actual admitted grant without furnishing its runtime authority.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootGrantedOperation {
    /// Names the original logical producer selected by the actual planner.
    pub node: Id,
    /// Names the actual original granted operation.
    pub operation: Id,
    /// Retains the actual grant's ordered start.
    pub start: Position,
    /// Retains the actual grant's exclusive ceiling.
    pub limit: Position,
}

/// Keeps the first refusal at its original diagnostic phase.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootFirstRefusal {
    /// Names the original substep which returned the refusal.
    pub phase: String,
    /// Retains at most 4096 bytes of the original refusal.
    pub reason: String,
}

/// Reports bounded original custody facts without dispatching native work.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPreparationDiagnostic {
    /// Names the independent diagnostic format.
    pub format: String,
    /// Names the diagnostic edition, independently of admission receipts.
    pub version: u32,
    /// Preserves the original execution nonce.
    pub execution: String,
    /// Names the exact retained original request's Trace.1 identity.
    pub request: String,
    /// Counts changed snapshots, never native progress.
    pub revision: u32,
    /// Names the last entered source-owned substep.
    pub phase: String,
    /// Identifies the wrapper still owned by this worker.
    pub owner: String,
    /// Reports an activation accessible through the initial/restored live wrapper.
    /// Retirement identifies separate retained custody; false does not prove that
    /// an original activation never occurred.
    pub activation_present: bool,
    /// Reports whether native preparation has been attempted.
    pub native_preparation_started: bool,
    /// Retains the actual original grant when one has been obtained.
    pub granted_operation: Option<RootGrantedOperation>,
    /// Retains the actual token's operation identity, without token authority.
    pub token_operation: Option<Id>,
    /// Retains the last recorded exact-target queue view; this is not a live query or proof.
    pub native_cleanup: Option<InstalledRootCleanupStatus>,
    /// Keeps the first original refusal, even while reclamation remains unresolved.
    pub first_refusal: Option<RootFirstRefusal>,
}

impl RootPreparationDiagnostic {
    /// Decodes bounded canonical diagnostic data without granting native authority.
    ///
    /// # Errors
    /// Refuses malformed editions, unsafe scope, excessive data and noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let value: Self =
            serde_json::from_value(canonical::parse_json(bytes, MAXIMUM_BYTES).map_err(refused)?)
                .map_err(refused)?;
        value.validate()?;
        if encode(&value)? != bytes {
            return Err(refused("Root diagnostic bytes are not canonical"));
        }
        Ok(value)
    }

    /// Encodes a finite diagnostic snapshot independently of native admission status.
    ///
    /// # Errors
    /// Refuses invalid scope or a snapshot exceeding its declared complete byte ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NodeObservationServiceError> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > MAXIMUM_BYTES {
            return Err(refused("Root diagnostic complete byte credit exhausted"));
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), NodeObservationServiceError> {
        use crucible_cas::content_store::{ContentId, ObjectKind};
        validate_execution(&self.execution)?;
        let request = ContentId::parse(&self.request).map_err(refused)?;
        if self.format != "crucible.root-diagnostic"
            || self.version != 1
            || self.revision == 0
            || self.revision > MAXIMUM_REVISIONS + 1
            || (self.revision > MAXIMUM_REVISIONS && self.first_refusal.is_none())
            || request.kind() != ObjectKind::Trace
            || request.schema_version() != 1
            || request.encode() != self.request
            || self.phase.is_empty()
            || self.phase.len() > 128
            || self.owner.len() > 64
            || self.native_cleanup.as_ref().is_some_and(|status| {
                matches!(&status.first_failure, Some(InstalledRootCleanupFailure::Refused { reason }) if reason.len() > 2048)
            })
            || self.first_refusal.as_ref().is_some_and(|first| {
                first.phase.is_empty() || first.phase.len() > 128 || first.reason.len() > 4096
            })
        {
            return Err(refused("Root diagnostic edition or bounded scope differs"));
        }
        Ok(())
    }
}

pub(in super::super) struct Journal {
    ledger: RootPreparationLedger,
    pub(super) current: RootPreparationDiagnostic,
    published: Option<RootPreparationDiagnostic>,
}

impl Journal {
    pub(in super::super) fn new(
        ledger: RootPreparationLedger,
        original: &RootPreparationRecord,
    ) -> Self {
        Self {
            ledger,
            current: RootPreparationDiagnostic {
                format: "crucible.root-diagnostic".into(),
                version: 1,
                execution: original.execution.clone(),
                request: original.request.clone(),
                revision: 0,
                phase: "queued".into(),
                owner: "empty".into(),
                activation_present: false,
                native_preparation_started: false,
                granted_operation: None,
                token_operation: None,
                native_cleanup: None,
                first_refusal: None,
            },
            published: None,
        }
    }

    pub(in super::super) fn enter(
        &mut self,
        phase: &str,
    ) -> Result<(), NodeObservationServiceError> {
        self.current.phase = phase.into();
        self.publish()
    }

    pub(super) fn first_refusal(&mut self, reason: &str) {
        if self.current.first_refusal.is_none() {
            self.current.first_refusal = Some(RootFirstRefusal {
                phase: self.current.phase.clone(),
                reason: super::diagnostic(reason),
            });
        }
    }

    pub(super) fn publish(&mut self) -> Result<(), NodeObservationServiceError> {
        if self.published.as_ref() == Some(&self.current) {
            return Ok(());
        }
        // Routine transitions cannot consume the one reserved first-refusal slot.
        let first_refusal_slot = self.current.revision == MAXIMUM_REVISIONS
            && self.current.first_refusal.is_some()
            && self
                .published
                .as_ref()
                .is_some_and(|prior| prior.first_refusal.is_none());
        if self.current.revision >= MAXIMUM_REVISIONS && !first_refusal_slot {
            return Err(refused(
                "Root original diagnostic revision credit exhausted",
            ));
        }
        let mut next = self.current.clone();
        next.revision += 1;
        self.ledger
            .publish_diagnostic(&next, self.published.as_ref())?;
        self.current = next;
        self.published = Some(self.current.clone());
        Ok(())
    }
}
