//! Queries immutable indexes while independently checking current native Read.
//!
//! Index rows supply discovery only. A result contains ordinary object digests,
//! incomplete coverage and measured operations; it cannot authorize content I/O.
//! Loading and exhaustive relationship verification precede indexed discovery and
//! are reported separately from candidate, occurrence and current checks.

#[cfg(unix)]
mod authorization;
#[cfg(unix)]
mod loading;
#[cfg(unix)]
pub(in crate::guard) mod retention;

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

#[cfg(unix)]
use std::collections::BTreeSet;
use std::fmt;

use super::AuthorizedSnapshot;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::Guard;
#[cfg(unix)]
use crate::guard::HistoryObservation;
use crate::indexing;
#[cfg(not(unix))]
use crate::store::StoreErrorKind;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::identity::Digest;
use terrane_format::indexing::{evaluation, lookup};

/// Names the discovery algorithm actually executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexLookupMethod {
    /// Seeks a completely verified immutable primary and its local routes.
    Index,
    /// Walks actual namespace entries after a genuine missing owner binding.
    Walk,
}

/// Explains incomplete authorized coverage without exposing denied paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexLookupGap {
    /// The selected owner has no binding, even when explicit fallback ran.
    MissingBinding,
    /// A currently readable and trusted occurrence lacks the inline attribute.
    MissingValue {
        /// Actual authorized absolute path in the selected immutable view.
        path: Vec<u8>,
    },
}

/// Counts current-check invocations separately from immutable route work.
///
/// Direct leaf boundary calls can load and verify complete metadata. Ordinary
/// authorization may complete further histories internally. These counts are
/// not exhaustive history counts and do not measure store reads, CPU or bytes.
/// A result never describes those opaque operations as constant time.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexLookupCurrentWork {
    /// Explicit leaf calls that freshly complete signed history or a snapshot.
    /// Nested history completions inside ordinary authorization are not counted.
    pub history_boundary_calls: usize,
    /// Candidate and gap paths presented to current Read/trust checks.
    pub occurrence_checks: usize,
    /// Signed-history attribute-origin resolutions actually attempted.
    pub attribute_origin_checks: usize,
    /// Independently verified producer namespace entries inspected for witnesses.
    pub producer_entries: usize,
    /// Matching producer paths presented to current Read/trust checks.
    pub producer_checks: usize,
    /// Selected snapshot/producer paths checked again before physical revalidation.
    pub final_path_checks: usize,
    /// Successful exact requests refreshed against the same actual clock.
    pub token_refreshes: usize,
    /// Captured Original records plus explicit leaf final-record readbacks.
    /// Nested initial pin/role/receipt reads are not an exhaustive I/O counter.
    pub control_record_checks: usize,
    /// Whole selected-observation revalidations performed by this leaf.
    pub selection_rechecks: usize,
    /// Exact physical preimages compared by this leaf before return.
    pub physical_read_checks: usize,
}

/// Separates loading and preparation from C/P/W and current operations.
#[derive(Clone, Debug)]
pub struct IndexLookupWork {
    /// Successful immutable acquisition operations from the ordinary loader.
    pub loading: indexing::Loading,
    /// Independent canonical namespace reconstruction operations.
    pub reconstruction: indexing::Reconstruction,
    /// Complete I/P/G verification and retained-query preparation, when indexed.
    /// Returning this report explicitly copies its retained verification traces.
    pub preparation: Option<lookup::Preparation>,
    /// Equality-range discovery before current filtering (including C).
    pub candidates: lookup::Work,
    /// Each complete candidate occurrence traversal (including P and W).
    pub present_routes: Vec<lookup::Work>,
    /// Missing-object discovery performed even when C is zero.
    pub gaps: lookup::Work,
    /// Each complete missing occurrence traversal, separately from candidate P.
    pub missing_routes: Vec<lookup::Work>,
    /// Actual regular-file entries inspected only by explicit fallback discovery.
    pub walked_files: usize,
    /// Independent live, trust, producer and physical-input checks.
    pub current: IndexLookupCurrentWork,
}

/// Returns deduplicated authorized objects and explicit incomplete coverage.
///
/// This ordinary data grants no future Read right, index qualification or cache
/// authority. A later content read still performs its own current checks.
#[derive(Clone, Debug)]
pub struct IndexLookup {
    /// Sorted object digests with an actually qualified matching occurrence.
    pub objects: Vec<Digest>,
    /// Nonempty gaps make the response explicitly partial and incomplete.
    pub gaps: Vec<IndexLookupGap>,
    /// Actual index seek or explicit missing-binding fallback.
    pub method: IndexLookupMethod,
    /// Work separated by phase, without a total native CPU or I/O bound.
    pub work: IndexLookupWork,
}

impl IndexLookup {
    /// Reports whether every relevant occurrence was qualified or excluded.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// Preserves original storage, immutable-loading and pure query failures.
#[derive(Debug)]
pub enum IndexLookupError {
    /// Current policy, metadata, Original, clock or physical input check failed.
    Store(StoreFailure),
    /// Native immutable loading or relationship verification failed.
    Index(indexing::Error),
    /// Pure indexed traversal or bounded counter accounting failed.
    Query(evaluation::Error),
}

impl fmt::Display for IndexLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Index(error) => error.fmt(formatter),
            Self::Query(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IndexLookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Index(error) => Some(error),
            Self::Query(error) => Some(error),
        }
    }
}

impl From<StoreFailure> for IndexLookupError {
    fn from(error: StoreFailure) -> Self {
        Self::Store(error)
    }
}

impl From<indexing::Error> for IndexLookupError {
    fn from(error: indexing::Error) -> Self {
        Self::Index(error)
    }
}

impl From<evaluation::Error> for IndexLookupError {
    fn from(error: evaluation::Error) -> Self {
        Self::Query(error)
    }
}

#[derive(Clone, Copy)]
enum Fallback {
    Refuse,
    Walk,
}

#[cfg(unix)]
fn count(counter: &mut usize, amount: usize) -> Result<(), IndexLookupError> {
    *counter = counter
        .checked_add(amount)
        .ok_or(evaluation::Error::Limit)?;
    Ok(())
}

impl<F, B, V, C> Guard<FileBucket<F, B, V>, C>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
    C: Clock + Sync,
{
    /// Queries a selected native immutable index with fresh current checks.
    ///
    /// The snapshot is only a selector for its exact signed view, token and
    /// requested scope. Its history and authority are freshly established beneath
    /// actual namespace and Original exclusions. Attribute/property revisions are
    /// independently selected for that exact view/root; index presence selects none.
    ///
    /// # Errors
    /// Preserves missing binding, divergence, unavailable metadata, unsupported
    /// profiles, invalid values, current denial and changed protected inputs.
    /// This method never replaces failed indexed discovery with a full walk.
    pub async fn lookup_index(
        &self,
        snapshot: &AuthorizedSnapshot,
        attribute: &str,
        canonical_value: &[u8],
    ) -> Result<IndexLookup, IndexLookupError> {
        self.lookup(snapshot, attribute, canonical_value, Fallback::Refuse)
            .await
    }

    /// Queries an index or explicitly walks a genuinely unbound owner.
    ///
    /// Only `indexing::Error::MissingBinding` chooses fallback. The result still
    /// reports that missing binding as incomplete under DRV-27, even if all
    /// observed regular files have values. Other failures preserve their cause.
    ///
    /// # Errors
    /// Reports the same current, physical, profile and canonical failures as
    /// `lookup_index`, except that genuine missing binding executes a measured walk.
    pub async fn lookup_index_or_walk(
        &self,
        snapshot: &AuthorizedSnapshot,
        attribute: &str,
        canonical_value: &[u8],
    ) -> Result<IndexLookup, IndexLookupError> {
        self.lookup(snapshot, attribute, canonical_value, Fallback::Walk)
            .await
    }

    #[cfg(not(unix))]
    async fn lookup(
        &self,
        _snapshot: &AuthorizedSnapshot,
        _attribute: &str,
        _canonical_value: &[u8],
        _fallback: Fallback,
    ) -> Result<IndexLookup, IndexLookupError> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported).into())
    }

    #[cfg(unix)]
    async fn lookup(
        &self,
        selector: &AuthorizedSnapshot,
        attribute: &str,
        canonical_value: &[u8],
        fallback: Fallback,
    ) -> Result<IndexLookup, IndexLookupError> {
        let holder = crate::bucket::held::SingleHeld::acquire_read_only(self.store()).await?;
        let held = holder.source();
        let observed = held.observe_publication_unrepaired().await?;
        let authority = self.configured_original_authority()?;
        let mut controls = self
            .hold_original_registration(&authority, observed.identity())
            .await?;
        let retained =
            retention::capture(self, &authority, &mut controls, &held, &observed).await?;
        let clock = self
            .clock()
            .retain_native_clock()
            .map_err(crate::guard::time::retention_failure)?;
        let guard = self.held_guard(holder.source(), clock)?;
        guard.retain_original_controls(&retained.controls)?;
        let consumed = crate::guard::ConsumedResolver::new(&guard, &authority)?;
        consumed.registration(&authority)?;
        let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);

        let (snapshot, initial_requests) = guard
            .read_commit_snapshot_authorizations_observed(
                selector.commit.identity(),
                &selector.token,
                &selector.scope,
                &selector.surface,
                observation,
            )
            .await?;
        if snapshot.interpretation != selector.interpretation
            || snapshot.storage_domain != selector.storage_domain
            || snapshot.authority_reference != selector.authority_reference
        {
            return Err(crate::guard::invalid().into());
        }
        let (_, profile) = guard.selected_view_profile(&snapshot.commit, observation)?;
        let mut loaded = loading::discover(
            guard.store(),
            &snapshot,
            attribute,
            canonical_value,
            &profile,
            guard.config().min_chunk_size,
            matches!(fallback, Fallback::Walk),
        )
        .await?;
        loaded.work.current.history_boundary_calls = 1;
        loaded.work.current.control_record_checks = retained.controls.records().len();
        let mut objects = BTreeSet::new();
        let mut gaps = if loaded.method == IndexLookupMethod::Walk {
            vec![IndexLookupGap::MissingBinding]
        } else {
            Vec::new()
        };
        let mut paths = vec![snapshot.scope.clone()];
        let mut producer_checks = Vec::new();
        let mut requests = initial_requests;

        for row in &loaded.present {
            if !authorization::within_scope(&snapshot, &row.path) {
                continue;
            }
            if !authorization::check_occurrence(
                &guard,
                &snapshot,
                row,
                attribute,
                observation,
                &mut requests,
                &mut loaded.work.current,
            )
            .await?
            {
                continue;
            }
            paths.push(row.path.clone());
            if let Some(check) = authorization::check_producer(
                &guard,
                &snapshot,
                row,
                attribute,
                observation,
                &mut requests,
                &mut loaded.work.current,
            )
            .await?
            {
                producer_checks.push(check);
                objects.insert(row.object());
            }
        }
        // Missing routes are independent inputs, including when there are no C rows.
        for row in &loaded.missing {
            if !authorization::within_scope(&snapshot, &row.path) {
                continue;
            }
            if authorization::check_occurrence(
                &guard,
                &snapshot,
                row,
                attribute,
                observation,
                &mut requests,
                &mut loaded.work.current,
            )
            .await?
            {
                paths.push(row.path.clone());
                gaps.push(IndexLookupGap::MissingValue {
                    path: row.path.clone(),
                });
            }
        }

        for path in paths {
            count(&mut loaded.work.current.final_path_checks, 1)?;
            let (fresh_snapshot, mut fresh) = guard
                .read_commit_snapshot_authorizations_observed(
                    snapshot.commit.identity(),
                    &snapshot.token,
                    &snapshot.scope,
                    &snapshot.surface,
                    observation,
                )
                .await?;
            count(&mut loaded.work.current.history_boundary_calls, 1)?;
            // Keep the original independently authorized selector scope. Resolving
            // a graft path as a new root selector would impose the root-only
            // configured-domain restriction on a lawful occurrence.
            fresh.extend(
                guard
                    .snapshot_authorizations_observed(&fresh_snapshot, &path, observation)
                    .await?,
            );
            requests.extend(fresh);
        }
        for check in &producer_checks {
            count(&mut loaded.work.current.final_path_checks, 1)?;
            let fresh = authorization::recheck_producer(
                &guard,
                &snapshot,
                check,
                observation,
                &mut loaded.work.current,
            )
            .await?;
            requests.extend(fresh);
        }
        retention::finish(
            self,
            &authority,
            &mut controls,
            &retained,
            &observed,
            &consumed,
            &mut loaded.work.current,
        )
        .await?;
        // This last synchronous check follows all awaited physical/history reads.
        for request in &requests {
            crate::guard::time::refresh(self.keys(), &self.config().home, guard.clock(), request)?;
            count(&mut loaded.work.current.token_refreshes, 1)?;
        }
        Ok(IndexLookup {
            objects: objects.into_iter().collect(),
            gaps,
            method: loaded.method,
            work: loaded.work,
        })
    }
}
