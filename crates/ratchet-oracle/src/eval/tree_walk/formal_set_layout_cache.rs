//! Per-pattern resolved layout cache for formal-set lambda patterns.
//!
//! A `{ a, b ? d, ... } @ args:` lambda lowers to an [`IrKind::FormalSet`] pattern
//! node. Binding an argument against it
//! ([`bind_formal_set_argument`](super::TreeWalk::bind_formal_set_argument))
//! originally re-derived the pattern's fixed shape on every call: it copied the
//! formal child slice, resolved and validated every formal name (and the `@`
//! alias) through the [`SymbolTable`](crate::compile::SymbolTable), and computed
//! the alias-slot and total-slot counts. All of that is a pure function of the
//! immutable pattern node, so this cache memoizes it once as a
//! [`FormalSetLayout`]; a later application reuses the layout and does only the
//! per-argument work (forcing the argument attrset, the unexpected-attribute
//! check, and the per-formal select with lazily-evaluated defaults).
//!
//! # Layout
//!
//! The cache is a dense two-level [`Vec`] indexed first by
//! [`EvalModuleId::index`] and then by the pattern [`IrId::index`]:
//!
//! ```text
//! modules[module.index()][pattern.index()] = Some(Arc<FormalSetLayout>) | None
//! ```
//!
//! Only patterns whose layout derivation *succeeds* are recorded, so a malformed
//! pattern re-produces its diagnostic on every evaluation. The layout is held
//! behind an [`Arc`] so a hit clones a reference-count rather than the formal
//! array, and the clone can outlive the borrow of the cache while the binder
//! calls back into the evaluator.
//!
//! [`IrKind::FormalSet`]: crate::compile::IrKind::FormalSet

use super::*;

/// One resolved formal of a formal-set pattern.
///
/// The formal's name has already been validated against the symbol table; its
/// `default` is carried as an unevaluated IR node id so the binder mints the
/// default thunk with the same laziness as an uncached bind.
#[derive(Clone, Copy, Debug)]
pub(in crate::eval::tree_walk) struct FormalSlot {
    /// The formal's attribute name.
    pub(in crate::eval::tree_walk) name: Symbol,
    /// The default-value expression, evaluated lazily only when the attribute is absent.
    pub(in crate::eval::tree_walk) default: Option<IrId>,
}

/// The immutable, resolved shape of a formal-set lambda pattern.
///
/// Derived once per pattern node and reused across every application of the
/// lambda. See the [module documentation](self) for the caching rationale.
#[derive(Debug)]
pub(in crate::eval::tree_walk) struct FormalSetLayout {
    /// The formals in declaration order; the binder fills frame slots `0..len`.
    entries: Box<[FormalSlot]>,
    /// Whether the pattern ends in `...` (extra argument attributes are allowed).
    ellipsis: bool,
    /// Whether the `@`-alias occupies its own frame slot (it does unless its name
    /// coincides with a formal's).
    alias_has_own_slot: bool,
    /// Total frame slots the pattern binds: one per formal plus the alias slot.
    pattern_slots: usize,
}

impl FormalSetLayout {
    /// Creates a resolved formal-set layout.
    pub(in crate::eval::tree_walk) fn new(
        entries: Box<[FormalSlot]>,
        ellipsis: bool,
        alias_has_own_slot: bool,
        pattern_slots: usize,
    ) -> Self {
        Self {
            entries,
            ellipsis,
            alias_has_own_slot,
            pattern_slots,
        }
    }

    /// Returns the formals in declaration order.
    pub(in crate::eval::tree_walk) fn entries(&self) -> &[FormalSlot] {
        &self.entries
    }

    /// Returns whether the pattern allows extra argument attributes (`...`).
    pub(in crate::eval::tree_walk) fn ellipsis(&self) -> bool {
        self.ellipsis
    }

    /// Returns whether the `@`-alias binds its own frame slot.
    pub(in crate::eval::tree_walk) fn alias_has_own_slot(&self) -> bool {
        self.alias_has_own_slot
    }

    /// Returns the total number of frame slots the pattern binds.
    pub(in crate::eval::tree_walk) fn pattern_slots(&self) -> usize {
        self.pattern_slots
    }

    /// Returns whether `name` is one of the pattern's formals.
    pub(in crate::eval::tree_walk) fn contains_name(&self, name: Symbol) -> bool {
        self.entries.iter().any(|entry| entry.name == name)
    }
}

/// Dense per-module memo of resolved formal-set pattern layouts.
///
/// See the [module documentation](self) for the layout and soundness rationale.
#[derive(Debug, Default)]
pub(in crate::eval::tree_walk) struct FormalSetLayoutCache {
    /// Outer index is [`EvalModuleId::index`]; inner index is the pattern [`IrId::index`].
    modules: Vec<Vec<Option<Arc<FormalSetLayout>>>>,
    /// Count of bindings served from a cached layout.
    hits: u64,
    /// Count of bindings that had to derive the layout.
    misses: u64,
}

impl FormalSetLayoutCache {
    /// Returns the cached layout for a pattern node, if one was recorded.
    pub(in crate::eval::tree_walk) fn get(
        &self,
        module: EvalModuleId,
        pattern: IrId,
    ) -> Option<&Arc<FormalSetLayout>> {
        self.modules
            .get(module.index())
            .and_then(|slots| slots.get(pattern.index()))
            .and_then(Option::as_ref)
    }

    /// Records a derived layout, growing the dense tables as needed.
    pub(in crate::eval::tree_walk) fn insert(
        &mut self,
        module: EvalModuleId,
        pattern: IrId,
        layout: Arc<FormalSetLayout>,
    ) {
        let module_index = module.index();
        if module_index >= self.modules.len() {
            self.modules.resize_with(module_index + 1, Vec::new);
        }
        let slots = &mut self.modules[module_index];
        let node_index = pattern.index();
        if node_index >= slots.len() {
            slots.resize_with(node_index + 1, || None);
        }
        slots[node_index] = Some(layout);
    }

    /// Records that a binding was served from a cached layout.
    pub(in crate::eval::tree_walk) fn record_hit(&mut self) {
        self.hits = self.hits.saturating_add(1);
    }

    /// Records that a binding had to derive the layout.
    pub(in crate::eval::tree_walk) fn record_miss(&mut self) {
        self.misses = self.misses.saturating_add(1);
    }

    /// Returns the number of bindings served from a cached layout.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn hits(&self) -> u64 {
        self.hits
    }

    /// Returns the number of bindings that derived the layout.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn misses(&self) -> u64 {
        self.misses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(raw: u32) -> EvalModuleId {
        EvalModuleId::new(raw)
    }

    fn layout(names: &[u32]) -> Arc<FormalSetLayout> {
        let entries = names
            .iter()
            .map(|raw| FormalSlot {
                name: Symbol::new(*raw),
                default: None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let pattern_slots = entries.len();
        Arc::new(FormalSetLayout::new(entries, false, false, pattern_slots))
    }

    #[test]
    fn get_returns_none_before_any_insert() {
        let cache = FormalSetLayoutCache::default();
        assert!(cache.get(module(0), IrId::new(0)).is_none());
        assert!(cache.get(module(4), IrId::new(11)).is_none());
    }

    #[test]
    fn insert_then_get_returns_the_same_layout() {
        let mut cache = FormalSetLayoutCache::default();
        let entry = layout(&[1, 2]);
        cache.insert(module(2), IrId::new(9), Arc::clone(&entry));
        let hit = cache.get(module(2), IrId::new(9)).expect("recorded layout");
        assert!(Arc::ptr_eq(hit, &entry));
        assert_eq!(hit.pattern_slots(), 2);
        assert!(hit.contains_name(Symbol::new(1)));
        assert!(!hit.contains_name(Symbol::new(3)));
        // A different pattern in the same module remains unresolved.
        assert!(cache.get(module(2), IrId::new(8)).is_none());
        // A different module remains unresolved even at the same node index.
        assert!(cache.get(module(1), IrId::new(9)).is_none());
    }

    #[test]
    fn dense_growth_preserves_earlier_entries() {
        let mut cache = FormalSetLayoutCache::default();
        let low = layout(&[1]);
        let high = layout(&[2]);
        cache.insert(module(0), IrId::new(1), Arc::clone(&low));
        cache.insert(module(0), IrId::new(1000), Arc::clone(&high));
        assert!(Arc::ptr_eq(
            cache.get(module(0), IrId::new(1)).expect("low"),
            &low
        ));
        assert!(Arc::ptr_eq(
            cache.get(module(0), IrId::new(1000)).expect("high"),
            &high
        ));
        assert!(cache.get(module(0), IrId::new(500)).is_none());
    }
}
