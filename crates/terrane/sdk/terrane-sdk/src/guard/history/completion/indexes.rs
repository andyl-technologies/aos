//! Checks historical owner-bound relationships using the ordinary native loader.
//!
//! Retained namespace and staged Node bytes remain immutable inputs. They never
//! supply producer trust, current permissions, or complete lookup coverage.
//!
//! ```text
//! signed namespace + selected profile -> local owner binding -> I / P / G
//! canonical source reconstruction -> exhaustive relationship preparation
//! ```

use std::collections::BTreeMap;
#[cfg(all(test, feature = "tokio", unix))]
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(test, feature = "tokio", unix))]
use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::{Digest, Identity, IdentityKind, TERRANE_V1};

use crate::guard::{StagedUpload, TreeEvidence, invalid};
#[cfg(all(test, feature = "tokio", unix))]
use crate::indexing::{self, SemanticRevisions};
use crate::indexing::{Error, ErrorKind};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    StoreErrorKind, StoreFailure,
};

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

/// Verifies each required immutable owner/name without flattening policy uses.
///
/// Empty requirements still validate every namespace placement in active context.
/// Source Trees and Prepared borrows are created only after loading completes and
/// dropped before another await. Repeated occurrences remain in the parent's
/// policy; only identical immutable owner/name checks share relationship work.
///
/// # Errors
/// Preserves original failed Node/store causes. Missing bindings and unsupported
/// conflict coverage remain incomplete, while divergent relationships refuse.
#[cfg(all(test, feature = "tokio", unix))]
pub(super) async fn verify<S: ContentStore>(
    store: &S,
    evidence: &TreeEvidence,
    uploads: &[StagedUpload],
    profile: &ConfiguredRegistryInputs,
    requirements: Vec<(Digest, String)>,
    minimum: u64,
) -> Result<(), StoreFailure> {
    let revisions = SemanticRevisions {
        property: profile.property_revision,
        attribute: profile.attribute_revision,
        tree: profile.tree_revision,
    };
    if (revisions.property, revisions.attribute, revisions.tree) != (3, 2, 1) {
        return if requirements.is_empty() {
            Ok(())
        } else {
            Err(failure(Error::Unsupported))
        };
    }

    let inputs = Inputs::new(store, evidence, uploads)?;
    let namespace = indexing::load_source_for(
        &inputs,
        evidence.root,
        revisions,
        minimum,
        evidence.root_usage(evidence.root),
    )
    .await
    .map_err(failure)?;
    // This reconstruction also checks physical summaries and canonical borders.
    // No borrowed Rc-backed source tree crosses the next loading await.
    namespace.sources().map_err(failure)?;

    let mut checked = BTreeSet::new();
    for (owner, attribute) in requirements {
        if !checked.insert((owner, attribute.clone())) {
            continue;
        }
        let loaded = match indexing::load_for(
            &inputs,
            owner,
            &attribute,
            revisions,
            minimum,
            evidence.root_usage(owner),
        )
        .await
        {
            Ok(loaded) => loaded,
            // DRV-27 permits an initial or preserved absent owner binding. Its
            // lookup remains incomplete; absence supplies no relationship proof.
            Err(Error::MissingBinding(_)) => continue,
            Err(error) => return Err(failure(error)),
        };
        let sources = loaded.sources().map_err(failure)?;
        loaded.prepare(&sources.trees).map_err(failure)?;
    }
    Ok(())
}

/// Translates an index failure while preserving its permitted kind and diagnostic.
///
/// Nested store failures keep their exact kind. Denied retains only its verb and
/// scope, without source detail; other outcomes attach the index diagnostic.
/// Invalid relationships become malformed requests; incomplete or unsupported
/// relationships become Unsupported, and unclassified store errors become Unavailable.
pub(in crate::guard) fn failure(error: Error) -> StoreFailure {
    let kind = match &error {
        Error::Store { failure, .. } => failure.kind().clone(),
        _ => match error.kind() {
            ErrorKind::Invalid => invalid().kind().clone(),
            ErrorKind::Incomplete | ErrorKind::Unsupported => StoreErrorKind::Unsupported,
            ErrorKind::Store => StoreErrorKind::Unavailable { retry_after: None },
        },
    };
    StoreFailure::with_source(kind, error)
}

/// Separates exact immutable overlay returns from delegated store GET calls.
///
/// Delegated calls are Store operations, not a count of native descriptor reads:
/// the configured store retains its ordinary verification and caching behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexInputReads {
    /// GET calls satisfied by the actual retained namespace evidence.
    pub retained_calls: usize,
    /// Bytes returned from actual retained namespace evidence.
    pub retained_bytes: usize,
    /// GET calls satisfied by exact staged Node declarations.
    pub staged_calls: usize,
    /// Bytes returned from exact staged Node declarations.
    pub staged_bytes: usize,
    /// GET calls delegated to the real configured ContentStore.
    pub store_calls: usize,
}

#[derive(Default)]
struct Counters {
    retained_calls: AtomicUsize,
    retained_bytes: AtomicUsize,
    staged_calls: AtomicUsize,
    staged_bytes: AtomicUsize,
    store_calls: AtomicUsize,
}

fn count(counter: &AtomicUsize, amount: usize) -> Result<(), StoreFailure> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(amount)
        })
        .map(|_| ())
        .map_err(|_| StoreFailure::new(StoreErrorKind::Capacity))
}

/// Borrows the exact reached namespace and owns ordinary staging declarations.
pub(in crate::guard) struct Inputs<'a, S> {
    store: &'a S,
    namespace: &'a BTreeMap<Digest, Vec<u8>>,
    staged: BTreeMap<Digest, Vec<u8>>,
    counters: Counters,
}

impl<'a, S> Inputs<'a, S> {
    /// Returns dispatch accounting after the exact loader has completed.
    pub(in crate::guard) fn reads(&self) -> IndexInputReads {
        IndexInputReads {
            retained_calls: self.counters.retained_calls.load(Ordering::Relaxed),
            retained_bytes: self.counters.retained_bytes.load(Ordering::Relaxed),
            staged_calls: self.counters.staged_calls.load(Ordering::Relaxed),
            staged_bytes: self.counters.staged_bytes.load(Ordering::Relaxed),
            store_calls: self.counters.store_calls.load(Ordering::Relaxed),
        }
    }

    /// Borrows exact reached namespace bytes and owns address-checked staged Nodes.
    ///
    /// # Errors
    /// Rejects malformed identities, conflicting retained bytes and duplicate declarations.
    pub(in crate::guard) fn new(
        store: &'a S,
        evidence: &'a TreeEvidence,
        uploads: &[StagedUpload],
    ) -> Result<Self, StoreFailure> {
        let mut staged = BTreeMap::new();
        for upload in uploads {
            let StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } = upload
            else {
                continue;
            };
            let identity = TERRANE_V1
                .calculate(IdentityKind::Node, bytes)
                .and_then(|identity| identity.terrane_v1_digest())
                .map_err(|_| invalid())?;
            if evidence
                .nodes
                .get(&identity)
                .is_some_and(|actual| actual != bytes)
                || staged.insert(identity, bytes.clone()).is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            store,
            namespace: &evidence.nodes,
            staged,
            counters: Counters::default(),
        })
    }
}

impl<S: CapabilityReport> CapabilityReport for Inputs<'_, S> {
    fn capabilities(&self) -> &Capabilities {
        self.store.capabilities()
    }
}

// Return the store's already boxed future directly. An async wrapper would
// unnecessarily require the borrowed store to be Sync in the Send profile.
#[cfg(feature = "send")]
type InputFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, StoreFailure>> + Send + 'a>>;

#[cfg(not(feature = "send"))]
type InputFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, StoreFailure>> + 'a>>;

impl<S: ContentStore> ContentStore for Inputs<'_, S> {
    fn put<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _: ContentUpload<'life1>,
    ) -> InputFuture<'async_trait, Identity>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(Err(StoreFailure::new(
            StoreErrorKind::ReadOnly,
        ))))
    }

    fn get<'life0, 'life1, 'async_trait>(
        &'life0 self,
        identity: &'life1 Identity,
        range: Option<ByteRange>,
    ) -> InputFuture<'async_trait, Vec<u8>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        if range.is_some() || identity.kind() != IdentityKind::Node {
            return Box::pin(std::future::ready(Err(StoreFailure::new(
                StoreErrorKind::Unsupported,
            ))));
        }
        let node = match identity.terrane_v1_digest() {
            Ok(node) => node,
            Err(_) => return Box::pin(std::future::ready(Err(invalid()))),
        };
        let retained = self.namespace.get(&node);
        let staged = self.staged.get(&node);
        let observed = match (retained, staged) {
            (Some(bytes), _) => count(&self.counters.retained_calls, 1)
                .and_then(|()| count(&self.counters.retained_bytes, bytes.len())),
            (None, Some(bytes)) => count(&self.counters.staged_calls, 1)
                .and_then(|()| count(&self.counters.staged_bytes, bytes.len())),
            (None, None) => count(&self.counters.store_calls, 1),
        };
        if let Err(error) = observed {
            return Box::pin(std::future::ready(Err(error)));
        }
        match retained.or(staged) {
            Some(bytes) => Box::pin(std::future::ready(Ok(bytes.clone()))),
            None => self.store.get(identity, None),
        }
    }

    fn has<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _: &'life1 [Identity],
    ) -> InputFuture<'async_trait, Vec<bool>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(Err(StoreFailure::new(
            StoreErrorKind::Unsupported,
        ))))
    }

    fn list<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _: &'life1 IdentityPrefix,
    ) -> InputFuture<'async_trait, Vec<Identity>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(Err(StoreFailure::new(
            StoreErrorKind::Unsupported,
        ))))
    }
}
