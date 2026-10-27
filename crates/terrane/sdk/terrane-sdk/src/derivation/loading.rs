//! Retains actual immutable bytes in the common RAM association before replay.
//!
//! Native counters exclude common Memo decoding, semantic evaluation and copies.
//! Checked-counter overflow retains diagnostics and leaves an incomplete report.

use std::collections::BTreeMap;

use super::{Diagnostic, LoadingReport, Selection};
use crate::store::ContentStore;
use terrane_format::derivation::Memo;
use terrane_format::derivation::cache::{
    AdvisoryCache, CacheRecord, CacheUnavailable, MemoryCache,
};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};

/// Retains the ordinary RAM association and its native loading availability.
///
/// Fetched bytes remain untrusted until common mandatory recipe replay succeeds.
/// This adapter neither persists records nor supplies current authority.
#[derive(Default)]
pub(super) struct Availability {
    cache: MemoryCache,
    unavailable: bool,
}

impl AdvisoryCache for Availability {
    /// Looks up the loaded claim under the original recipe's lookup hash.
    ///
    /// # Errors
    /// Returns `CacheUnavailable` when native loading could not retain the selected
    /// Memo association. Successful lookup does not validate the returned claim.
    fn lookup(&mut self, recipe: Digest) -> Result<Option<CacheRecord>, CacheUnavailable> {
        if self.unavailable {
            return Err(CacheUnavailable);
        }
        self.cache.lookup(recipe)
    }

    /// Replaces an advisory association in the ordinary RAM cache.
    ///
    /// # Errors
    /// This in-memory replacement does not return an error.
    fn replace(&mut self, recipe: Digest, record: CacheRecord) -> Result<(), CacheUnavailable> {
        self.cache.replace(recipe, record)
    }
}

/// Loads explicitly selected immutable evidence with fresh loading counters.
///
/// Storage, schema, address and counter failures remain in the returned report;
/// they do not supply mandatory recipe inputs or bypass common replay.
///
/// # Panics
/// Propagates panics from the supplied store's `get` implementation.
pub(super) async fn load<S: ContentStore + ?Sized>(
    store: &S,
    recipe: &[u8],
    selection: Selection<'_>,
) -> (Availability, LoadingReport) {
    load_with_report(store, recipe, selection, LoadingReport::default()).await
}

/// Loads explicitly selected evidence while preserving the supplied report.
///
/// Counters extend their existing values with checked arithmetic. Overflow leaves
/// a diagnostic and incomplete accounting for the caller's mandatory replay.
///
/// # Panics
/// Propagates panics from the supplied store's `get` implementation.
pub(super) async fn load_with_report<S: ContentStore + ?Sized>(
    store: &S,
    recipe: &[u8],
    selection: Selection<'_>,
    mut report: LoadingReport,
) -> (Availability, LoadingReport) {
    let mut cache = Availability::default();
    let Selection::Selected { memo, nodes } = selection else {
        return (cache, report);
    };

    let Some(encoded) = read(store, memo, IdentityKind::Memo, &mut report).await else {
        cache.unavailable = true;
        return (cache, report);
    };
    if increment(&mut report, Counter::Decode, 1)
        && let Err(error) = Memo::decode(&encoded)
    {
        report.diagnostics.push(Diagnostic::Memo(error));
    }

    let mut fetched = nodes.map(|_| BTreeMap::new());
    if let Some(nodes) = nodes {
        for node in nodes {
            match read(store, *node, IdentityKind::Node, &mut report).await {
                Some(bytes) => {
                    if let Some(fetched) = &mut fetched {
                        fetched.insert(*node, bytes);
                    }
                }
                None => fetched = None,
            }
        }
    }

    // An untrusted Memo field never selects the association's lookup key.
    let key = if increment(&mut report, Counter::Hash, 1) {
        TERRANE_V1
            .calculate(IdentityKind::Memo, recipe)
            .and_then(|identity| identity.terrane_v1_digest())
    } else {
        cache.unavailable = true;
        return (cache, report);
    };
    match key {
        Ok(key) => {
            let record = CacheRecord {
                identity: memo,
                encoded,
                nodes: fetched,
            };
            cache.unavailable = cache.cache.replace(key, record).is_err();
        }
        Err(error) => {
            report.diagnostics.push(Diagnostic::Identity(error));
            cache.unavailable = true;
        }
    }
    (cache, report)
}

async fn read<S: ContentStore + ?Sized>(
    store: &S,
    digest: Digest,
    kind: IdentityKind,
    report: &mut LoadingReport,
) -> Option<Vec<u8>> {
    let identity = match TERRANE_V1.from_digest(kind, &digest) {
        Ok(identity) => identity,
        Err(error) => {
            report.diagnostics.push(Diagnostic::Identity(error));
            return None;
        }
    };
    if !increment(report, Counter::Get, 1) {
        return None;
    }
    let bytes = match store.get(&identity, None).await {
        Ok(bytes) => bytes,
        Err(failure) => {
            report
                .diagnostics
                .push(Diagnostic::Store { identity, failure });
            return None;
        }
    };
    if !increment(report, Counter::Byte, bytes.len()) {
        return None;
    }
    if increment(report, Counter::Hash, 1) {
        match TERRANE_V1.calculate(kind, &bytes) {
            Ok(actual) if actual != identity => {
                report
                    .diagnostics
                    .push(Diagnostic::AddressMismatch { identity, actual });
            }
            Err(error) => report.diagnostics.push(Diagnostic::Identity(error)),
            Ok(_) => {}
        }
    }
    // Physical validation provides diagnostics; the original buffer remains the
    // sole claim for the common schema/key/root/complete-map refusal checks.
    Some(bytes)
}

enum Counter {
    Get,
    Byte,
    Hash,
    Decode,
}

fn increment(report: &mut LoadingReport, counter: Counter, amount: usize) -> bool {
    let (value, name) = match counter {
        Counter::Get => (&mut report.work.gets, "gets"),
        Counter::Byte => (&mut report.work.returned_bytes, "returned_bytes"),
        Counter::Hash => (&mut report.work.identity_checks, "identity_checks"),
        Counter::Decode => (&mut report.work.memo_decodes, "memo_decodes"),
    };
    if let Some(updated) = value.checked_add(amount) {
        *value = updated;
        true
    } else {
        report.diagnostics.push(Diagnostic::CounterOverflow(name));
        false
    }
}
