//! HAMT select-site policies and caches
//! (split from pic.rs under the §2 file-size cap).
use super::*;

/// The select-site policy for HAMT-backed attrsets.
///
/// HAMT values have no flat slot vector, so a shape-to-slot inline-cache entry
/// is not available. The site can either remember that HAMT values use the
/// keyed trie lookup path or abandon specialization when a HAMT value appears.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HamtSelectPolicy {
    /// Cache a distinguished HAMT entry and keep using keyed HAMT lookup.
    DistinguishedEntry,
    /// Treat a HAMT value as the point where the site becomes megamorphic.
    MegamorphicFallback,
}

/// The current HAMT select-cache state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HamtSelectCacheState {
    /// No HAMT value has reached the site.
    Uninitialized,
    /// A distinguished HAMT entry has been installed.
    DistinguishedHamt,
    /// The site uses the generic megamorphic path for HAMT values.
    Megamorphic,
}

impl HamtSelectCacheState {
    /// Returns whether this state has abandoned specialization.
    pub const fn is_megamorphic(self) -> bool {
        matches!(self, Self::Megamorphic)
    }
}

/// A safe HAMT-valued select-site policy precursor.
///
/// This cache binds one static select key, then applies the selected
/// [`HamtSelectPolicy`] whenever a HAMT-backed attrset reaches the site. It
/// does not install a shape slot and does not interact with
/// [`ShapedSelectCache`]. The active tree-walk evaluator uses this cache for
/// heap attrsets whose metadata projects a HAMT representation, while active
/// heap storage remains flat. The HAMT attrset and select key must come from
/// the same symbol universe.
#[derive(Clone, Debug)]
pub struct HamtSelectCache {
    key: Option<Symbol>,
    policy: HamtSelectPolicy,
    state: HamtSelectCacheState,
}

impl HamtSelectCache {
    /// Creates an uninitialized HAMT select cache with `policy`.
    pub const fn new(policy: HamtSelectPolicy) -> Self {
        Self {
            key: None,
            policy,
            state: HamtSelectCacheState::Uninitialized,
        }
    }

    /// Returns the configured HAMT select policy.
    pub const fn policy(&self) -> HamtSelectPolicy {
        self.policy
    }

    /// Returns the current HAMT select-cache state.
    pub const fn state(&self) -> HamtSelectCacheState {
        self.state
    }

    /// Returns the static key bound to this select-site cache, if observed.
    pub const fn key(&self) -> Option<Symbol> {
        self.key
    }

    /// Selects `key` from a HAMT attrset using this site's HAMT policy.
    ///
    /// The lookup itself resolves through the representation-dispatching
    /// `select_slow` HAMT branch. The cache records whether future HAMT values
    /// should stay on that distinguished path or use the megamorphic path.
    /// `attrs` and `key` must come from the same symbol universe.
    ///
    /// # Errors
    ///
    /// Returns [`HamtSelectError::KeyChanged`] if the cache is reused for a
    /// different static select key, or [`HamtSelectError::Select`] if the
    /// representation-dispatching resolver fails.
    pub fn select(
        &mut self,
        attrs: &HamtAttrs,
        key: Symbol,
    ) -> Result<HamtSelectOutcome, HamtSelectError> {
        self.bind_key(key)?;
        let source = self.observe_hamt();
        Ok(match select_slow(AttrSelectTarget::Hamt(attrs), key)? {
            AttrSelectOutcome::Hit { value, .. } => HamtSelectOutcome::Hit { value, source },
            AttrSelectOutcome::Missing { .. } => HamtSelectOutcome::Missing { source },
        })
    }

    fn observe_hamt(&mut self) -> HamtSelectSource {
        match (self.state, self.policy) {
            (HamtSelectCacheState::Uninitialized, HamtSelectPolicy::DistinguishedEntry) => {
                self.state = HamtSelectCacheState::DistinguishedHamt;
                HamtSelectSource::Resolved {
                    update: HamtSelectUpdate::InstalledDistinguishedHamt,
                }
            }
            (HamtSelectCacheState::DistinguishedHamt, HamtSelectPolicy::DistinguishedEntry) => {
                HamtSelectSource::CachedDistinguishedHamt
            }
            (HamtSelectCacheState::Uninitialized, HamtSelectPolicy::MegamorphicFallback)
            | (HamtSelectCacheState::DistinguishedHamt, HamtSelectPolicy::MegamorphicFallback) => {
                self.state = HamtSelectCacheState::Megamorphic;
                HamtSelectSource::Resolved {
                    update: HamtSelectUpdate::BecameMegamorphic,
                }
            }
            (HamtSelectCacheState::Megamorphic, _) => HamtSelectSource::Resolved {
                update: HamtSelectUpdate::AlreadyMegamorphic,
            },
        }
    }

    fn bind_key(&mut self, key: Symbol) -> Result<(), HamtSelectError> {
        match self.key {
            Some(previous) if previous != key => Err(HamtSelectError::KeyChanged {
                previous,
                attempted: key,
            }),
            Some(_) => Ok(()),
            None => {
                self.key = Some(key);
                Ok(())
            }
        }
    }
}

/// A HAMT select-cache lookup result.
#[derive(Clone, Copy, Debug)]
pub enum HamtSelectOutcome {
    /// The key was present.
    Hit {
        /// The selected value.
        value: Value,
        /// Whether the site used a cached HAMT policy or slow resolution.
        source: HamtSelectSource,
    },
    /// The key is absent from the HAMT attrset.
    Missing {
        /// Whether the site used a cached HAMT policy or slow resolution.
        source: HamtSelectSource,
    },
}

/// The path used to produce a HAMT select result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HamtSelectSource {
    /// A distinguished HAMT entry was already installed.
    CachedDistinguishedHamt,
    /// The HAMT policy was resolved, possibly updating the cache state.
    Resolved {
        /// The state-machine update produced by observing the HAMT value.
        update: HamtSelectUpdate,
    },
}

/// The HAMT policy update produced at one select site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HamtSelectUpdate {
    /// The first HAMT value installed a distinguished HAMT entry.
    InstalledDistinguishedHamt,
    /// The HAMT value forced this site to use the megamorphic path.
    BecameMegamorphic,
    /// The site was already megamorphic.
    AlreadyMegamorphic,
}

/// A failed HAMT select-cache operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HamtSelectError {
    /// A select-site cache was reused for a different static key.
    #[error("HAMT select-cache key changed from {previous:?} to {attempted:?}")]
    KeyChanged {
        /// The key already bound to the cache.
        previous: Symbol,
        /// The attempted replacement key.
        attempted: Symbol,
    },
    /// The representation-dispatching slow resolver failed.
    #[error("HAMT select-cache slow resolver failed: {0}")]
    Select(#[from] AttrSelectError),
}
