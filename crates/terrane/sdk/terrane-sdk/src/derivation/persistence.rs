//! Stores fresh common replay output through ordinary metadata admission.
//!
//! Every operation uses the existing common replay/cache service. Output Nodes
//! are acknowledged before the Memo; partial persistence is explicit ordinary
//! reporting. Neither metadata admission nor this report grants current serving,
//! producer, history, owner-binding or publication authority. Callers independently
//! qualify their operands and recheck their current native context.

use std::{collections::BTreeSet, fmt};

use super::{Error, Outcome, Selection};
use crate::store::{ContentStore, ContentUpload, MetaUpload, StoreFailure};
use terrane_format::derivation::cache::ReplayMode;
use terrane_format::derivation::evaluation::EvaluationInputs;
use terrane_format::identity::{Digest, Identity, IdentityError, IdentityKind, TERRANE_V1};

/// Selects optional storage without changing mandatory recipe evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceMode {
    /// Performs replay without attempting any metadata upload.
    Omit,
    /// Attempts all actual output Nodes before the unchanged common Memo.
    Store,
}

/// Identifies the actual stage at which optional storage stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceStage {
    /// One canonical output Node has not been acknowledged.
    Node(Digest),
    /// All output Nodes were acknowledged but the Memo has not been.
    Memo,
}

/// Preserves an optional storage or identity-check refusal.
#[derive(Debug)]
pub enum PersistenceFailure {
    /// Retains the exact requested subject and original storage diagnostic.
    Store {
        /// Expected domain-separated content identity.
        identity: Identity,
        /// Original metadata construction or backend upload failure.
        failure: StoreFailure,
    },
    /// Rejects an identity that differs from the actual expected content address.
    AddressMismatch {
        /// Independently expected content identity.
        expected: Identity,
        /// Identity calculated from bytes or returned by the backend.
        actual: Identity,
    },
    /// Retains a domain-separated identity construction failure.
    Identity(IdentityError),
}

impl fmt::Display for PersistenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { failure, .. } => failure.fmt(formatter),
            Self::AddressMismatch { .. } => {
                formatter.write_str("persisted content identity mismatch")
            }
            Self::Identity(failure) => failure.fmt(formatter),
        }
    }
}

impl std::error::Error for PersistenceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store { failure, .. } => Some(failure),
            Self::Identity(failure) => Some(failure),
            Self::AddressMismatch { .. } => None,
        }
    }
}

/// Describes acknowledged metadata uploads without claiming native authority.
///
/// A successful `ContentStore::put` is the store's acknowledgment contract.
/// This report is not a protected publication receipt or a GC retention promise.
#[derive(Debug, Default)]
pub struct PersistenceReport {
    /// Whether optional metadata persistence was requested.
    pub requested: bool,
    /// Output Node identities actually acknowledged before storage stopped.
    pub nodes: BTreeSet<Digest>,
    /// Immutable Memo record address m, present only after every Node and Memo put.
    /// This address is distinct from the recipe lookup key q.
    pub memo: Option<Identity>,
    /// Actual failed stage, absent for omitted or completely acknowledged storage.
    pub stopped: Option<PersistenceStage>,
    /// Exact optional refusal; a refusal never reports a successful Memo upload.
    pub failure: Option<Box<PersistenceFailure>>,
}

/// Owns valid mandatory replay output and its separate optional storage report.
#[derive(Debug)]
pub struct PersistedOutcome {
    /// Original common replay result, work and advisory diagnostics.
    pub outcome: Outcome,
    /// Actual metadata acknowledgments and any partial-storage refusal.
    pub persistence: PersistenceReport,
}

/// Replays once and optionally stores the complete actual output before its Memo.
///
/// Optional storage failures leave the freshly evaluated result available with
/// explicit partial acknowledgments and the original refusal. Missing inputs,
/// invalid checked context and Check-mode divergence remain errors before any
/// output upload. Disabled cache selection and omitted persistence are separate
/// ordinary choices; neither alters recipe semantics.
///
/// The caller supplies independently qualified immutable operands and genuine
/// checked provenance to the existing evaluator. Current native authorization
/// and Original-control checks remain the owning caller's responsibility, as
/// they are for `derivation::replay`; this function cannot make a Memo serving
/// authority. Returned addresses can be retained as untrusted advisory data.
///
/// # Errors
/// Returns the unchanged mandatory replay failure or divergent-association
/// refusal. Optional metadata storage failures are retained in the report.
///
/// # Panics
/// Propagates panics from the supplied store's content operations
/// or overlay policy context.
pub async fn replay_and_persist<S: ContentStore + ?Sized>(
    store: &S,
    recipe: &[u8],
    inputs: &EvaluationInputs<'_, '_>,
    mode: ReplayMode,
    selection: Selection<'_>,
    persistence_mode: PersistenceMode,
) -> Result<PersistedOutcome, Error> {
    let outcome = super::replay(store, recipe, inputs, mode, selection).await?;
    let mut persistence = PersistenceReport::default();

    if persistence_mode == PersistenceMode::Omit {
        return Ok(PersistedOutcome {
            outcome,
            persistence,
        });
    }
    persistence.requested = true;

    for (node, bytes) in &outcome.replay.evaluation.nodes {
        match put(store, IdentityKind::Node, *node, bytes).await {
            Ok(_) => {
                persistence.nodes.insert(*node);
            }
            Err(failure) => {
                persistence.stopped = Some(PersistenceStage::Node(*node));
                persistence.failure = Some(failure);
                return Ok(PersistedOutcome {
                    outcome,
                    persistence,
                });
            }
        }
    }

    // q is already bound to the original canonical recipe by mandatory replay.
    // m addresses these exact fresh Memo bytes, not the recipe lookup itself.
    let bytes = outcome.replay.memo.encode();
    let address = match outcome.replay.memo.identity() {
        Ok(address) => address,
        Err(failure) => {
            persistence.stopped = Some(PersistenceStage::Memo);
            persistence.failure = Some(Box::new(PersistenceFailure::Identity(failure)));
            return Ok(PersistedOutcome {
                outcome,
                persistence,
            });
        }
    };

    match put(store, IdentityKind::Memo, address, &bytes).await {
        Ok(identity) => persistence.memo = Some(identity),
        Err(failure) => {
            persistence.stopped = Some(PersistenceStage::Memo);
            persistence.failure = Some(failure);
        }
    }

    Ok(PersistedOutcome {
        outcome,
        persistence,
    })
}

/// Checks both the actual buffer and the backend acknowledgment's identity.
async fn put<S: ContentStore + ?Sized>(
    store: &S,
    kind: IdentityKind,
    digest: Digest,
    bytes: &[u8],
) -> Result<Identity, Box<PersistenceFailure>> {
    let expected = TERRANE_V1
        .from_digest(kind, &digest)
        .map_err(|failure| Box::new(PersistenceFailure::Identity(failure)))?;
    let actual = TERRANE_V1
        .calculate(kind, bytes)
        .map_err(|failure| Box::new(PersistenceFailure::Identity(failure)))?;
    if actual != expected {
        return Err(Box::new(PersistenceFailure::AddressMismatch {
            expected,
            actual,
        }));
    }

    let upload = MetaUpload::new(kind, bytes).map_err(|failure| {
        Box::new(PersistenceFailure::Store {
            identity: expected.clone(),
            failure,
        })
    })?;
    let actual = store
        .put(ContentUpload::Meta(upload))
        .await
        .map_err(|failure| {
            Box::new(PersistenceFailure::Store {
                identity: expected.clone(),
                failure,
            })
        })?;
    if actual != expected {
        return Err(Box::new(PersistenceFailure::AddressMismatch {
            expected,
            actual,
        }));
    }
    Ok(actual)
}
