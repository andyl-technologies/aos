//! Read-only, replay-checked views of native activation journals.
//!
//! Inspection distinguishes a durable pending invocation, retained outcomes, and
//! a completed transaction. It never executes handlers or treats retained
//! outcomes as current observations of live resources. The native journal
//! decoder validates framing and the activation state machine checks ordering.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use super::journal::{Event, State};
use super::{Action, Invocation};
use crate::journal::{FileJournal, JournalLimits};

/// Identifies one exact dispatched invocation without exposing its payload.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIdentity {
    /// Names the logical effect in the retained graph.
    pub effect: String,
    /// Identifies the exact resolved invocation.
    pub revision: String,
    /// Distinguishes application from removal.
    pub action: Action,
    /// Names its original durable intent frame across recovery attempts.
    pub journal_sequence: u64,
}

impl DispatchIdentity {
    fn from_invocation(invocation: &Invocation, journal_sequence: u64) -> Self {
        Self {
            effect: invocation.id.clone(),
            revision: invocation.revision.clone(),
            action: invocation.action,
            journal_sequence,
        }
    }
}

/// Projects one digest-verified, state-machine-checked journal frame.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectionRecord {
    /// Orders complete records within the journal.
    pub sequence: u64,
    /// Names the journal event: begin, started, finished, released, or commit.
    pub event: &'static str,
    /// Names the owning transaction when one is active.
    pub transaction: Option<String>,
    /// Identifies the invocation associated with an intent or outcome.
    pub dispatch: Option<DispatchIdentity>,
}

/// Identifies the last transaction with a durable completion receipt.
#[derive(Clone, Debug, Serialize)]
pub struct CompletedTransaction {
    /// Names the caller-supplied transaction identity.
    pub transaction: String,
    /// Identifies the checked graph and explicit retirement decision.
    pub content: String,
}

/// Reports durable activation state without claiming live-state verification.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationInspection {
    /// Names the native inspection format.
    pub schema: &'static str,
    /// Explicitly distinguishes retained results from live observations.
    pub live_state_verified: bool,
    /// Reports an incomplete final frame without modifying the journal.
    pub incomplete_tail_bytes: u64,
    /// Names the active transaction, if any.
    pub transaction: Option<String>,
    /// Identifies its pending invocation, if any.
    pub pending: Option<DispatchIdentity>,
    /// Reports the most recent completed transaction separately from pending work.
    pub completed: Option<CompletedTransaction>,
    /// Preserves the active checked native graph when a transaction is pending.
    pub desired: Option<Value>,
    /// Contains checked retained outcomes, including persistent orphaned state.
    pub retained_outputs: BTreeMap<String, Value>,
    /// Identifies durably removed effects with no subsequent application.
    pub retired_effects: BTreeSet<String>,
    /// Lists complete frames in journal order without exposing handler arguments.
    pub records: Vec<InspectionRecord>,
}

/// Reads a bounded native journal without repair, dispatch, or mutation.
///
/// A running manager holds an exclusive lock. Inspection fails on contention;
/// callers must stop it before collecting a consistent interrupted-state view.
///
/// # Errors
/// Returns an error for insecure files, lock contention, corruption, exceeded
/// limits, or any record that violates native activation ordering or schemas.
pub fn inspect(path: impl AsRef<Path>, limits: JournalLimits) -> Result<ActivationInspection> {
    let snapshot = FileJournal::<Event>::read_only_snapshot(path, limits)?;
    let mut state = State::default();
    let mut pending_sequence = None;
    let mut records = Vec::with_capacity(snapshot.records().len());
    for record in snapshot.records() {
        let sequence = record.sequence();
        let dispatch = match record.body() {
            Event::Started { invocation } => {
                Some(DispatchIdentity::from_invocation(invocation, sequence))
            }
            Event::Finished { .. } => state
                .pending
                .as_ref()
                .zip(pending_sequence)
                .map(|(invocation, intent)| DispatchIdentity::from_invocation(invocation, intent)),
            _ => None,
        };
        let event = match record.body() {
            Event::Begin { .. } => "begin",
            Event::Started { .. } => "started",
            Event::Finished { .. } => "finished",
            Event::Released => "released",
            Event::Commit => "commit",
        };
        let transaction = match record.body() {
            Event::Begin { transaction, .. } => Some(transaction.clone()),
            _ => state.transaction.clone(),
        };
        state.apply(record.body())?;
        match record.body() {
            Event::Started { .. } => pending_sequence = Some(sequence),
            Event::Finished { .. } => pending_sequence = None,
            _ => {}
        }
        records.push(InspectionRecord {
            sequence,
            event,
            transaction,
            dispatch,
        });
    }

    Ok(ActivationInspection {
        retired_effects: state.retired.clone(),
        schema: "aos.activation.inspection",
        live_state_verified: false,
        incomplete_tail_bytes: snapshot.incomplete_tail_bytes(),
        pending: state
            .pending
            .as_ref()
            .zip(pending_sequence)
            .map(|(invocation, sequence)| DispatchIdentity::from_invocation(invocation, sequence)),
        completed: state
            .completed
            .as_ref()
            .map(|(transaction, content, _)| CompletedTransaction {
                transaction: transaction.clone(),
                content: content.clone(),
            }),
        desired: state
            .active
            .as_ref()
            .map(|graph| serde_json::to_value(graph.graph()))
            .transpose()?,
        transaction: state.transaction,
        retained_outputs: state
            .retained
            .into_iter()
            .map(|(id, retained)| (id, retained.outputs))
            .collect(),
        records,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;

    use super::super::tests::{Host, graph};
    use super::super::{Activation, Boundary};
    use super::*;
    use crate::adapter::CancellationToken;

    #[test]
    fn inspection_distinguishes_pending_dispatch_from_completed_receipt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("effects.journal");
        let desired = graph(Some("example"), "instance");
        let mut host = Host::default();
        host.halt_boundary = Some(Boundary::DispatchReturned);
        let mut activation = Activation::open(&path, JournalLimits::default())?;
        assert!(
            activation
                .activate_once(
                    "example",
                    &desired,
                    &BTreeSet::new(),
                    &mut host,
                    &CancellationToken::default()
                )
                .is_err()
        );
        drop(activation);

        let before = fs::read(&path)?;
        let pending = inspect(&path, JournalLimits::default())?;
        let identity = pending.pending.as_ref().expect("interrupted invocation");
        assert_eq!(
            identity.journal_sequence,
            pending.records.last().expect("intent").sequence
        );
        assert_eq!(pending.transaction.as_deref(), Some("example"));
        assert!(pending.desired.is_some());
        assert!(pending.completed.is_none());
        assert!(pending.retained_outputs.is_empty());
        assert!(!pending.live_state_verified);
        assert_eq!(fs::read(&path)?, before);

        host.halt_boundary = None;
        let mut activation = Activation::open(&path, JournalLimits::default())?;
        activation.activate_once(
            "example",
            &desired,
            &BTreeSet::new(),
            &mut host,
            &CancellationToken::default(),
        )?;
        drop(activation);
        let completed = inspect(&path, JournalLimits::default())?;
        assert!(completed.pending.is_none());
        assert!(completed.transaction.is_none());
        assert!(completed.desired.is_none());
        assert_eq!(
            completed
                .completed
                .as_ref()
                .expect("completion")
                .transaction,
            "example"
        );
        assert_eq!(completed.retained_outputs.len(), 1);
        let outcome = completed
            .records
            .iter()
            .find(|record| record.event == "finished")
            .expect("durable outcome");
        assert_eq!(
            outcome
                .dispatch
                .as_ref()
                .expect("outcome identity")
                .journal_sequence,
            identity.journal_sequence
        );
        Ok(())
    }

    #[test]
    fn incomplete_tail_is_reported_without_repair() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("effects.journal");
        let mut activation = Activation::open(&path, JournalLimits::default())?;
        activation.activate_once(
            "empty",
            &graph(None, "instance"),
            &BTreeSet::new(),
            &mut Host::default(),
            &CancellationToken::default(),
        )?;
        drop(activation);
        OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(&[1, 2, 3])?;
        let before = fs::read(&path)?;
        let snapshot = inspect(&path, JournalLimits::default())?;
        assert_eq!(snapshot.incomplete_tail_bytes, 3);
        assert_eq!(fs::read(&path)?, before);
        Ok(())
    }

    #[test]
    fn checksum_valid_but_out_of_order_records_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("effects.journal");
        let mut opened = FileJournal::<Event>::open(&path, JournalLimits::default())?;
        opened.journal.append(&Event::Finished {
            outputs: serde_json::json!({}),
        })?;
        drop(opened);
        assert!(inspect(&path, JournalLimits::default()).is_err());
        Ok(())
    }
}
