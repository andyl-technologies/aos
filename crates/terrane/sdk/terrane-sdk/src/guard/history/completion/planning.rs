//! Collects relationship subjects from policies already resolved in this call.
//!
//! Collection is infallible and creates ordinary owned data only. Pending's
//! signed-profile, namespace-role and owner checks finish before any plan escapes;
//! standalone planning retains its distinct original checks and diagnostics.

use super::{SelectedInputs, active};
use terrane_format::identity::Digest;
use terrane_format::properties::EffectiveProperties;
use terrane_format::tree_format::TreeUse;

/// Retains exact occurrence subjects until the enclosing preparation succeeds.
#[derive(Default)]
pub(super) struct Capture {
    owners: Vec<(Digest, Vec<String>, TreeUse)>,
}

impl Capture {
    /// Records required attributes and all present owner-local bindings in order.
    ///
    /// The caller has already checked its own Index support and occurrence roles.
    /// Bindings remain owner-local; collection does not validate a relationship.
    pub(super) fn record(
        &mut self,
        root: Digest,
        attributes: &[&str],
        effective: &EffectiveProperties<'_>,
        usage: TreeUse,
    ) {
        let mut checked = attributes
            .iter()
            .map(|attribute| (*attribute).to_owned())
            .collect::<Vec<_>>();
        if let Some(bindings) = effective.active_index_roots() {
            checked.extend(
                bindings
                    .as_bindings()
                    .iter()
                    .map(|binding| binding.attribute.to_owned()),
            );
        }
        checked.sort();
        checked.dedup();
        self.owners.push((root, checked, usage));
    }

    /// Returns subjects with the exact semantic revisions of this preparation.
    pub(super) fn finish(self, inputs: &SelectedInputs) -> active::Plan {
        active::Plan {
            owners: self.owners,
            revisions: crate::indexing::SemanticRevisions {
                property: inputs.registries.property_revision,
                attribute: inputs.registries.attribute_revision,
                tree: inputs.registries.tree_revision,
            },
        }
    }
}

#[cfg(all(test, feature = "tokio", unix))]
pub(super) mod work {
    //! Observes actual preparation call sites within one synchronous test scope.
    //!
    //! These counts exclude independent signature requirements, canonical owner
    //! validation and relationship I/O; they claim only the adjacent duplicated
    //! namespace decode, occurrence enumeration and policy resolution work.

    use std::cell::Cell;

    /// Counts actual attempts and emitted occurrences at preparation call sites.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(in super::super) struct Work {
        /// Counts raw namespace Node decode attempts in the explicit role loop.
        pub(in super::super) raw_nodes: usize,
        /// Counts actual calls to enumerate the addressed occurrence closure.
        pub(in super::super) occurrence_walks: usize,
        /// Counts emitted occurrences, including repeated targets and Conflict roles.
        pub(in super::super) occurrences: usize,
        /// Counts actual selected policy resolution attempts in occurrence loops.
        pub(in super::super) resolutions: usize,
    }

    std::thread_local! {
        static CURRENT: Cell<Option<Work>> = const { Cell::new(None) };
    }

    struct Scope(Option<Work>);

    impl Drop for Scope {
        fn drop(&mut self) {
            CURRENT.with(|current| current.set(self.0));
        }
    }

    /// Measures actual call sites during a synchronous action, restoring its scope.
    ///
    /// No scope crosses an await, persists across calls or grants any authority.
    ///
    /// # Panics
    /// Propagates an action's panic while still restoring the enclosing counter.
    pub(in super::super) fn measure<T>(action: impl FnOnce() -> T) -> (T, Work) {
        let _scope = Scope(CURRENT.with(|current| current.replace(Some(Work::default()))));
        let result = action();
        let work = CURRENT.with(|current| current.get().unwrap_or_default());
        (result, work)
    }

    fn observe(update: impl FnOnce(&mut Work)) {
        CURRENT.with(|current| {
            if let Some(mut work) = current.get() {
                update(&mut work);
                current.set(Some(work));
            }
        });
    }

    /// Observes one actual raw Node decode attempt.
    pub(in super::super) fn raw_node() {
        observe(|work| work.raw_nodes += 1);
    }

    /// Observes one actual occurrence-closure enumeration call.
    pub(in super::super) fn occurrence_walk() {
        observe(|work| work.occurrence_walks += 1);
    }

    /// Observes one occurrence returned to a preparation loop.
    pub(in super::super) fn occurrence() {
        observe(|work| work.occurrences += 1);
    }

    /// Observes one actual selected-policy resolution attempt.
    pub(in super::super) fn resolution() {
        observe(|work| work.resolutions += 1);
    }
}
