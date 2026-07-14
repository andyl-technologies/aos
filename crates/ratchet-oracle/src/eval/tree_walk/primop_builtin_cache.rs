//! Per-call-site resolution cache for direct primop IR nodes.
//!
//! A lowered [`IrKind::PrimOp`] node names its builtin by [`Symbol`]. Executing
//! it through [`TreeWalk::eval_primop`](super::TreeWalk) originally re-resolved
//! that name on every call: [`SymbolTable::resolve`](crate::compile::SymbolTable)
//! to recover the name bytes, then [`lookup_builtin`](crate::compile::builtins::lookup_builtin)
//! to hash and match those bytes against the builtin registry. The lowered IR is
//! immutable, so a given `(module, node)` pair always resolves to the same
//! builtin; this cache memoizes that resolution once and replaces the per-call
//! name hash with an array index.
//!
//! # Layout
//!
//! The cache is a dense two-level [`Vec`] indexed first by
//! [`EvalModuleId::index`] and then by [`IrId::index`]:
//!
//! ```text
//! modules[module.index()][id.index()] = Some(kind) | None
//! ```
//!
//! Only *successful* resolutions are recorded. A `None` slot (or an index beyond
//! the grown length) means "not yet resolved"; unknown-symbol and unsupported-primop
//! call sites are never cached, so their diagnostics re-surface identically on
//! every call. Slots store the compact [`BuiltinKind`] discriminant (one byte)
//! rather than the wider [`Builtin`] record; [`Builtin::from_kind`] reconstructs
//! the full declaration on a hit.
//!
//! [`IrKind::PrimOp`]: crate::compile::IrKind::PrimOp
//! [`Symbol`]: crate::compile::Symbol

use super::*;

/// Dense per-module memo of resolved builtin kinds for direct primop nodes.
///
/// See the [module documentation](self) for the layout and soundness rationale.
#[derive(Debug, Default)]
pub(in crate::eval::tree_walk) struct PrimopBuiltinCache {
    /// Outer index is [`EvalModuleId::index`]; inner index is [`IrId::index`].
    modules: Vec<Vec<Option<BuiltinKind>>>,
    /// Count of resolutions served from a cached slot.
    hits: u64,
    /// Count of resolutions that had to consult the builtin registry.
    misses: u64,
}

impl PrimopBuiltinCache {
    /// Returns the cached builtin kind for a primop node, if one was recorded.
    pub(in crate::eval::tree_walk) fn get(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Option<BuiltinKind> {
        self.modules
            .get(module.index())
            .and_then(|slots| slots.get(id.index()).copied().flatten())
    }

    /// Records a successful resolution, growing the dense tables as needed.
    pub(in crate::eval::tree_walk) fn insert(
        &mut self,
        module: EvalModuleId,
        id: IrId,
        kind: BuiltinKind,
    ) {
        let module_index = module.index();
        if module_index >= self.modules.len() {
            self.modules.resize_with(module_index + 1, Vec::new);
        }
        let slots = &mut self.modules[module_index];
        let node_index = id.index();
        if node_index >= slots.len() {
            slots.resize(node_index + 1, None);
        }
        slots[node_index] = Some(kind);
    }

    /// Records that a resolution was served from the cache.
    pub(in crate::eval::tree_walk) fn record_hit(&mut self) {
        self.hits = self.hits.saturating_add(1);
    }

    /// Records that a resolution consulted the builtin registry.
    pub(in crate::eval::tree_walk) fn record_miss(&mut self) {
        self.misses = self.misses.saturating_add(1);
    }

    /// Returns the number of resolutions served from a cached slot.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn hits(&self) -> u64 {
        self.hits
    }

    /// Returns the number of resolutions that consulted the builtin registry.
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

    #[test]
    fn get_returns_none_before_any_insert() {
        let cache = PrimopBuiltinCache::default();
        assert_eq!(cache.get(module(0), IrId::new(0)), None);
        assert_eq!(cache.get(module(7), IrId::new(42)), None);
    }

    #[test]
    fn insert_then_get_returns_recorded_kind() {
        let mut cache = PrimopBuiltinCache::default();
        cache.insert(module(2), IrId::new(9), BuiltinKind::StringLengthBuiltin);
        assert_eq!(
            cache.get(module(2), IrId::new(9)),
            Some(BuiltinKind::StringLengthBuiltin)
        );
        // A different node in the same module remains unresolved.
        assert_eq!(cache.get(module(2), IrId::new(8)), None);
        // A different module remains unresolved even at the same node index.
        assert_eq!(cache.get(module(1), IrId::new(9)), None);
    }

    #[test]
    fn dense_growth_preserves_earlier_entries() {
        let mut cache = PrimopBuiltinCache::default();
        cache.insert(module(0), IrId::new(1), BuiltinKind::StringLengthBuiltin);
        // Inserting at a much higher index must grow without clobbering.
        cache.insert(module(0), IrId::new(1000), BuiltinKind::MapBuiltin);
        assert_eq!(
            cache.get(module(0), IrId::new(1)),
            Some(BuiltinKind::StringLengthBuiltin)
        );
        assert_eq!(
            cache.get(module(0), IrId::new(1000)),
            Some(BuiltinKind::MapBuiltin)
        );
        assert_eq!(cache.get(module(0), IrId::new(500)), None);
    }

    #[test]
    fn from_kind_round_trips_recorded_kind() {
        let mut cache = PrimopBuiltinCache::default();
        cache.insert(module(3), IrId::new(4), BuiltinKind::StringLengthBuiltin);
        let kind = cache.get(module(3), IrId::new(4)).expect("recorded kind");
        let builtin = Builtin::from_kind(kind);
        assert_eq!(builtin.kind(), BuiltinKind::StringLengthBuiltin);
    }
}
