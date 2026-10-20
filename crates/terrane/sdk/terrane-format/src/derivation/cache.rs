//! Applies advisory Memo lookup, replay, refusal and explicit rebuild uniformly.
//!
//! The table associates a recipe lookup key `q` with an immutable record address
//! `m`; neither address nor raw bytes certify the recipe/result association.
//! ```text
//! q -> (m, canonical Memo(q, result), optional complete output Node closure)
//! ```
//! This pure service certifies associations only by fresh execution. Hits keep
//! the same mandatory current input/evidence checks and pay replay work; no
//! persisted receipt or current authority is inferred from the cache. Native
//! admission, opaque pointer persistence and root-associated GC are separate.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use super::Memo;
use super::evaluation::{Evaluation, EvaluationError, EvaluationInputs, evaluate};
use crate::identity::Digest;

/// Holds an untrusted advisory record and optional cached output bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheRecord {
    /// Immutable Memo-domain record identity, never the recipe lookup key.
    pub identity: Digest,
    /// Claimed canonical two-field Memo bytes.
    pub encoded: Vec<u8>,
    /// Claimed complete output closure; absence is an ordinary cache inability.
    pub nodes: Option<BTreeMap<Digest, Vec<u8>>>,
}

/// Reports an ordinary advisory storage inability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheUnavailable;

impl fmt::Display for CacheUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("advisory memo cache unavailable")
    }
}

impl core::error::Error for CacheUnavailable {}

/// Reads and replaces ordinary recipe-to-record advisory associations.
///
/// Implementations confer no serving, policy, producer or publication authority.
pub trait AdvisoryCache {
    /// Loads an untrusted association by recipe lookup key.
    ///
    /// # Errors
    /// Reports cache I/O or availability failures, never semantic input failures.
    fn lookup(&mut self, recipe: Digest) -> Result<Option<CacheRecord>, CacheUnavailable>;

    /// Replaces an advisory association with a freshly replayed complete output.
    ///
    /// # Errors
    /// Reports cache storage inability without changing the evaluated result.
    fn replace(&mut self, recipe: Digest, record: CacheRecord) -> Result<(), CacheUnavailable>;
}

/// Provides an optional in-memory advisory table for every supported recipe kind.
#[derive(Default)]
pub struct MemoryCache {
    records: BTreeMap<Digest, CacheRecord>,
}

impl MemoryCache {
    /// Creates an empty advisory table.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AdvisoryCache for MemoryCache {
    fn lookup(&mut self, recipe: Digest) -> Result<Option<CacheRecord>, CacheUnavailable> {
        Ok(self.records.get(&recipe).cloned())
    }

    fn replace(&mut self, recipe: Digest, record: CacheRecord) -> Result<(), CacheUnavailable> {
        self.records.insert(recipe, record);
        Ok(())
    }
}

/// Distinguishes ordinary replay from explicitly authorized divergent rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayMode {
    /// Refuses a divergent association without returning its claimed result.
    Check,
    /// Rebuilds the association using the same semantic evaluator and full closure.
    Rebuild,
}

/// Records why a cached claim was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheRefusal {
    /// Advisory storage could not provide the association.
    Unavailable,
    /// Bytes do not form the exact canonical Memo schema or advertised identity.
    CorruptRecord,
    /// Memo field 1 differs from the actual canonical recipe lookup key.
    WrongKey,
    /// The claimed result root differs from fresh semantic replay.
    Divergent(Digest),
    /// Claimed output closure is unavailable.
    MissingOutput,
    /// Claimed output bytes differ from the complete actual replay closure.
    InvalidOutput,
}

/// Records the advisory observation after mandatory semantic replay succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheObservation {
    /// Caching was disabled.
    Disabled,
    /// No advisory association existed.
    Miss,
    /// The complete association and output matched fresh replay.
    Hit,
    /// The cached claim was refused for the reported reason.
    Refused(CacheRefusal),
}

/// Reports advisory behavior separately from mandatory semantic execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheReport {
    /// Cache observation, including the previous disagreement on explicit rebuild.
    pub observation: CacheObservation,
    /// Whether explicit rebuild produced a complete fresh association.
    pub rebuilt: bool,
    /// Whether attempted advisory storage failed after successful execution.
    pub write_unavailable: bool,
}

/// Owns a valid semantic output with its fresh advisory record and status.
#[derive(Clone, Debug)]
pub struct ReplayResult {
    /// Actual complete evaluator output; never a rewritten claimed digest.
    pub evaluation: Evaluation,
    /// Fresh association independently established by the same evaluator.
    pub memo: Memo,
    /// Advisory observation, refusal and rebuild status.
    pub cache: CacheReport,
}

/// Refuses mandatory evaluation failures or a divergent cached association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// Mandatory input, recipe or checked-context validation failed.
    Evaluation(EvaluationError),
    /// An immutable record disagreed; explicit same-evaluator rebuild is required.
    Divergent {
        /// Actual recipe lookup key under the registered Memo domain.
        recipe: Digest,
        /// Root claimed by the refused advisory record.
        claimed: Digest,
        /// Root computed by fresh semantic replay.
        actual: Digest,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation(error) => error.fmt(formatter),
            Self::Divergent { .. } => {
                formatter.write_str("divergent memo association requires rebuild")
            }
        }
    }
}

impl core::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Evaluation(error) => Some(error),
            Self::Divergent { .. } => None,
        }
    }
}

fn observe(record: &CacheRecord, evaluation: &Evaluation) -> CacheObservation {
    let Ok(memo) = Memo::decode(&record.encoded) else {
        return CacheObservation::Refused(CacheRefusal::CorruptRecord);
    };
    if memo.identity().ok() != Some(record.identity) {
        return CacheObservation::Refused(CacheRefusal::CorruptRecord);
    }
    if memo.recipe_hash() != evaluation.recipe_hash {
        return CacheObservation::Refused(CacheRefusal::WrongKey);
    }
    if memo.result_root() != evaluation.root {
        return CacheObservation::Refused(CacheRefusal::Divergent(memo.result_root()));
    }
    match &record.nodes {
        None => CacheObservation::Refused(CacheRefusal::MissingOutput),
        Some(nodes) if nodes != &evaluation.nodes => {
            CacheObservation::Refused(CacheRefusal::InvalidOutput)
        }
        Some(_) => CacheObservation::Hit,
    }
}

/// Replays a T1 recipe and applies advisory cache refusal or explicit rebuild.
///
/// All paths invoke [`evaluate`] before consulting cached claims. Corruption,
/// wrong keys and unavailable records/outputs preserve valid semantic results.
/// A divergent result is reported and withheld until explicit rebuild; both
/// modes perform the same mandatory input/context/evidence checks. Rebuild
/// returns complete actual canonical Nodes even when advisory writes fail.
///
/// # Errors
/// Returns mandatory evaluation failures without hiding them as cache misses;
/// returns `Divergent` in check mode when the correctly keyed record disagrees.
///
/// # Panics
/// Propagates panics from the supplied advisory cache or overlay policy context.
pub fn replay(
    encoded: &[u8],
    inputs: &EvaluationInputs<'_, '_>,
    mode: ReplayMode,
    mut cache: Option<&mut dyn AdvisoryCache>,
) -> Result<ReplayResult, ReplayError> {
    let evaluation = evaluate(encoded, inputs).map_err(ReplayError::Evaluation)?;
    let observation = match cache.as_mut() {
        None => CacheObservation::Disabled,
        Some(cache) => match cache.lookup(evaluation.recipe_hash) {
            Ok(None) => CacheObservation::Miss,
            Ok(Some(record)) => observe(&record, &evaluation),
            Err(_) => CacheObservation::Refused(CacheRefusal::Unavailable),
        },
    };
    if let CacheObservation::Refused(CacheRefusal::Divergent(claimed)) = observation
        && mode == ReplayMode::Check
    {
        return Err(ReplayError::Divergent {
            recipe: evaluation.recipe_hash,
            claimed,
            actual: evaluation.root,
        });
    }

    let memo = Memo::new(evaluation.recipe_hash, evaluation.root);
    let rebuilt = mode == ReplayMode::Rebuild;
    let mut write_unavailable = false;
    if let Some(cache) = cache
        && (rebuilt || observation != CacheObservation::Hit)
    {
        let identity = memo
            .identity()
            .map_err(|error| ReplayError::Evaluation(EvaluationError::Identity(error)))?;
        let record = CacheRecord {
            identity,
            encoded: memo.encode(),
            nodes: Some(evaluation.nodes.clone()),
        };
        write_unavailable = cache.replace(evaluation.recipe_hash, record).is_err();
    }
    Ok(ReplayResult {
        evaluation,
        memo,
        cache: CacheReport {
            observation,
            rebuilt,
            write_unavailable,
        },
    })
}
