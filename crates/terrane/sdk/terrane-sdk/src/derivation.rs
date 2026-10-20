//! Loads selected advisory derivation evidence and optionally persists fresh outputs.
//!
//! The common Memo service retains recipe lookup keys separately from immutable
//! record addresses. Native loading supplies actual fetched Memo/Node bytes to
//! that service without changing recipe inputs or inferring current authority.
//! Selection is caller supplied ordinary data. Loading never supplies source
//! operands, checked context, producer evidence, durable selection or authority.
//! Every operation performs one mandatory common replay. The [`persistence`]
//! module optionally admits its complete fresh output Nodes before its ordinary
//! Memo record, retaining semantic outcomes and exact optional storage failures.
//! Native loading and admission work remain separate from evaluation and queries.
//!
//! ```text
//! q -> (m, fetched Memo(q, R), optional fetched claimed Node map)
//! q hashes original recipe bytes; m hashes the encoded Memo record.
//! ```

mod loading;

/// Stores freshly replayed Nodes and Memo records through ordinary admission.
pub mod persistence;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fmt;

use crate::store::{ContentStore, StoreFailure};
use terrane_format::derivation::MemoError;
use terrane_format::derivation::cache::{self, ReplayError, ReplayMode, ReplayResult};
use terrane_format::derivation::evaluation::EvaluationInputs;
use terrane_format::identity::{Digest, Identity, IdentityError};

/// Selects optional untrusted immutable evidence for one replay.
#[derive(Clone, Copy, Debug)]
pub enum Selection<'a> {
    /// Disables advisory loading and the common cache.
    Disabled,
    /// Enables the common cache without a selected association.
    EnabledNoSelection,
    /// Supplies an immutable Memo address and optional claimed output inventory.
    Selected {
        /// Immutable encoded-record address, distinct from the recipe lookup key.
        memo: Digest,
        /// Caller-claimed complete Node set; an empty supplied set is a claim.
        nodes: Option<&'a BTreeSet<Digest>>,
    },
}

/// Counts native loading events without claiming a total CPU or query bound.
///
/// Common Memo decoding, evaluation and cache copies are excluded. If a counter
/// overflows, the report retains a diagnostic and its counters are incomplete.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LoadingWork {
    /// Whole-content Memo and Node get attempts, including failed gets.
    pub gets: usize,
    /// Actual byte lengths returned by successful gets.
    pub returned_bytes: usize,
    /// Domain-separated hash operations over original recipe or fetched bytes.
    pub identity_checks: usize,
    /// Common Memo schema decode attempts over actual fetched bytes.
    pub memo_decodes: usize,
}

/// Retains an advisory loading failure without altering mandatory replay.
#[derive(Debug)]
pub enum Diagnostic {
    /// Retains the exact requested subject and original typed storage failure.
    Store {
        /// Original requested identity, never an identity inferred from bytes.
        identity: Identity,
        /// Original store outcome and backend source chain.
        failure: StoreFailure,
    },
    /// Reports fetched bytes whose physical address differs from the request.
    AddressMismatch {
        /// Original requested immutable identity.
        identity: Identity,
        /// Independently calculated physical identity of the fetched bytes.
        actual: Identity,
    },
    /// Retains the Memo schema failure while preserving its actual bytes.
    Memo(MemoError),
    /// Retains a native identity calculation failure.
    Identity(IdentityError),
    /// Reports an overflowing loading counter; replay remains mandatory.
    CounterOverflow(&'static str),
}

/// Owns native loading work and diagnostics on every replay outcome.
#[derive(Debug, Default)]
pub struct LoadingReport {
    /// Selected native events, separate from the common evaluation's work.
    pub work: LoadingWork,
    /// Original advisory causes, including physical validation diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Owns the actual fresh output alongside its native loading evidence.
#[derive(Debug)]
pub struct Outcome {
    /// Unchanged result from the existing common replay service.
    pub replay: ReplayResult,
    /// Native read and validation evidence, including refused advisory data.
    pub loading: LoadingReport,
}

/// Retains mandatory replay failure and the preceding advisory load evidence.
#[derive(Debug)]
pub struct Error {
    /// Original semantic failure or typed divergent-association refusal.
    pub replay: ReplayError,
    /// Native diagnostics survive even when mandatory execution fails.
    pub loading: Box<LoadingReport>,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.replay.fmt(formatter)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.replay)
    }
}

/// Loads selected immutable evidence and performs one mandatory common replay.
///
/// Only whole-content Memo and caller-inventoried Node gets are performed.
/// Fetched bytes seed the existing RAM cache under the hash of the original
/// recipe bytes. No missing or corrupt claimed bytes are repaired from fresh
/// output. The borrowed operands and checked context reach replay unchanged.
/// Check-mode replacements and explicit rebuild both remain RAM-only.
///
/// # Errors
/// Returns the original common mandatory evaluation failure or Check-mode
/// divergence, retaining native storage subjects, failures and source chains.
/// Advisory loading failures alone do not fail successful semantic execution.
///
/// # Panics
/// Propagates panics from the caller-supplied store's `get` implementation
/// or overlay policy context.
pub async fn replay<S: ContentStore + ?Sized>(
    store: &S,
    recipe: &[u8],
    inputs: &EvaluationInputs<'_, '_>,
    mode: ReplayMode,
    selection: Selection<'_>,
) -> Result<Outcome, Error> {
    let (cache, loading) = loading::load(store, recipe, selection).await;
    complete(cache, loading, recipe, inputs, mode, selection)
}

fn complete(
    mut cache: loading::Availability,
    loading: LoadingReport,
    recipe: &[u8],
    inputs: &EvaluationInputs<'_, '_>,
    mode: ReplayMode,
    selection: Selection<'_>,
) -> Result<Outcome, Error> {
    let advisory = match selection {
        Selection::Disabled => None,
        _ => Some(&mut cache as &mut dyn cache::AdvisoryCache),
    };

    // Even failed loading and checked-counter overflow reach this one replay.
    match cache::replay(recipe, inputs, mode, advisory) {
        Ok(replay) => Ok(Outcome { replay, loading }),
        Err(replay) => Err(Error {
            replay,
            loading: Box::new(loading),
        }),
    }
}
