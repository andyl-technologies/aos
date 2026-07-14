//! Per-call-site resolution cache for direct primop IR nodes.
//!
//! A lowered [`IrKind::PrimOp`] node names its builtin by [`Symbol`] and points
//! at its argument node ids through the arena child pool. Executing it through
//! [`TreeWalk::eval_primop`](super::TreeWalk) originally re-did that work on every
//! call: [`SymbolTable::resolve`](crate::compile::SymbolTable) to recover the name
//! bytes, [`lookup_builtin`](crate::compile::builtins::lookup_builtin) to hash and
//! match those bytes against the builtin registry, and a
//! [`child_slice`](crate::compile::IrArena::child_slice) bounds-check to recover
//! the argument ids. The lowered IR is immutable, so a given `(module, node)` pair
//! always resolves to the same builtin and the same argument ids; this cache
//! memoizes both once so a repeat evaluation is an array index with no name hash
//! and no arena access.
//!
//! # Layout
//!
//! The cache is a dense two-level [`Vec`] indexed first by
//! [`EvalModuleId::index`] and then by [`IrId::index`]:
//!
//! ```text
//! modules[module.index()][id.index()] = Some(CachedPrimop) | None
//! ```
//!
//! Only *successful* resolutions with an argument count that fits a direct call
//! ([`MAX_DIRECT_PRIMOP_ARGS`]) are recorded. A `None` slot (or an index beyond the
//! grown length) means "not yet resolved or not cacheable"; unknown-symbol,
//! unsupported-primop, and over-arity call sites are never cached, so their
//! diagnostics re-surface identically on every call. Each slot stores the compact
//! [`BuiltinKind`] discriminant plus the argument ids inline (a
//! [`CachedPrimop`] is ~16 bytes); [`Builtin::from_kind`] reconstructs the full
//! declaration on a hit.
//!
//! [`IrKind::PrimOp`]: crate::compile::IrKind::PrimOp
//! [`Symbol`]: crate::compile::Symbol

use super::*;

/// Largest argument count a direct-lowered builtin call site can have.
///
/// The widest [`BuiltinDirect`](crate::compile::builtins::BuiltinDirect) shape is
/// `StrictTernary` (three arguments), so an argument id list no longer than this
/// fits inline in a [`CachedPrimop`] and in the stack buffer
/// [`TreeWalk::eval_primop`](super::TreeWalk) hands to a direct builtin. A call
/// with more arguments cannot be a valid direct primop; it is never cached and is
/// routed to the arity check on every evaluation.
pub(in crate::eval::tree_walk) const MAX_DIRECT_PRIMOP_ARGS: usize = 3;

/// A resolved direct primop call site: its builtin and pre-validated argument ids.
///
/// Recorded once per `(module, node)` on the first evaluation and reused on every
/// later one. Because the lowered IR is immutable, the stored argument ids stay
/// valid for the life of the evaluation, so a hit needs neither a registry lookup
/// nor an arena child-slice bounds check.
#[derive(Clone, Copy, Debug)]
pub(in crate::eval::tree_walk) struct CachedPrimop {
    /// The resolved builtin discriminant; expand with [`Builtin::from_kind`].
    kind: BuiltinKind,
    /// Number of valid entries in [`Self::args`] (always `1..=MAX_DIRECT_PRIMOP_ARGS`).
    arg_len: u8,
    /// The argument node ids; only the first [`Self::arg_len`] entries are meaningful.
    args: [IrId; MAX_DIRECT_PRIMOP_ARGS],
}

impl CachedPrimop {
    /// Creates a cache entry from a resolved builtin kind and its argument ids.
    ///
    /// # Panics
    ///
    /// Panics if `args` holds more than [`MAX_DIRECT_PRIMOP_ARGS`] ids; callers
    /// gate on the argument count before constructing an entry, so an over-arity
    /// call site is never cached.
    pub(in crate::eval::tree_walk) fn new(kind: BuiltinKind, args: &[IrId]) -> Self {
        assert!(
            args.len() <= MAX_DIRECT_PRIMOP_ARGS,
            "over-arity primop call sites are not cacheable",
        );
        let mut buffer = [IrId::new(0); MAX_DIRECT_PRIMOP_ARGS];
        buffer[..args.len()].copy_from_slice(args);
        Self {
            kind,
            arg_len: args.len() as u8,
            args: buffer,
        }
    }

    /// Returns the resolved builtin discriminant.
    pub(in crate::eval::tree_walk) fn kind(self) -> BuiltinKind {
        self.kind
    }

    /// Returns the pre-validated argument node ids for this call site.
    pub(in crate::eval::tree_walk) fn args(&self) -> &[IrId] {
        &self.args[..self.arg_len as usize]
    }
}

/// Dense per-module memo of resolved builtins and argument ids for primop nodes.
///
/// See the [module documentation](self) for the layout and soundness rationale.
#[derive(Debug, Default)]
pub(in crate::eval::tree_walk) struct PrimopBuiltinCache {
    /// Outer index is [`EvalModuleId::index`]; inner index is [`IrId::index`].
    modules: Vec<Vec<Option<CachedPrimop>>>,
    /// Count of resolutions served from a cached slot.
    hits: u64,
    /// Count of resolutions that had to consult the builtin registry.
    misses: u64,
}

impl PrimopBuiltinCache {
    /// Returns the cache entry for a primop node, if one was recorded.
    pub(in crate::eval::tree_walk) fn get(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Option<CachedPrimop> {
        self.modules
            .get(module.index())
            .and_then(|slots| slots.get(id.index()).copied().flatten())
    }

    /// Records a successful resolution, growing the dense tables as needed.
    pub(in crate::eval::tree_walk) fn insert(
        &mut self,
        module: EvalModuleId,
        id: IrId,
        entry: CachedPrimop,
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
        slots[node_index] = Some(entry);
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

    fn entry(kind: BuiltinKind, args: &[IrId]) -> CachedPrimop {
        CachedPrimop::new(kind, args)
    }

    #[test]
    fn get_returns_none_before_any_insert() {
        let cache = PrimopBuiltinCache::default();
        assert!(cache.get(module(0), IrId::new(0)).is_none());
        assert!(cache.get(module(7), IrId::new(42)).is_none());
    }

    #[test]
    fn insert_then_get_returns_recorded_entry() {
        let mut cache = PrimopBuiltinCache::default();
        let args = [IrId::new(5)];
        cache.insert(
            module(2),
            IrId::new(9),
            entry(BuiltinKind::StringLengthBuiltin, &args),
        );
        let hit = cache.get(module(2), IrId::new(9)).expect("recorded entry");
        assert_eq!(hit.kind(), BuiltinKind::StringLengthBuiltin);
        assert_eq!(hit.args(), &args);
        // A different node in the same module remains unresolved.
        assert!(cache.get(module(2), IrId::new(8)).is_none());
        // A different module remains unresolved even at the same node index.
        assert!(cache.get(module(1), IrId::new(9)).is_none());
    }

    #[test]
    fn cached_args_round_trip_multiple_arities() {
        let mut cache = PrimopBuiltinCache::default();
        let binary = [IrId::new(3), IrId::new(4)];
        let ternary = [IrId::new(7), IrId::new(8), IrId::new(9)];
        cache.insert(
            module(0),
            IrId::new(1),
            entry(BuiltinKind::MapBuiltin, &binary),
        );
        cache.insert(
            module(0),
            IrId::new(2),
            entry(BuiltinKind::SubstringBuiltin, &ternary),
        );
        assert_eq!(
            cache.get(module(0), IrId::new(1)).expect("binary").args(),
            &binary
        );
        assert_eq!(
            cache.get(module(0), IrId::new(2)).expect("ternary").args(),
            &ternary
        );
    }

    #[test]
    fn dense_growth_preserves_earlier_entries() {
        let mut cache = PrimopBuiltinCache::default();
        let one = [IrId::new(11)];
        let two = [IrId::new(22)];
        cache.insert(
            module(0),
            IrId::new(1),
            entry(BuiltinKind::StringLengthBuiltin, &one),
        );
        // Inserting at a much higher index must grow without clobbering.
        cache.insert(
            module(0),
            IrId::new(1000),
            entry(BuiltinKind::StringLengthBuiltin, &two),
        );
        assert_eq!(
            cache.get(module(0), IrId::new(1)).expect("low").args(),
            &one
        );
        assert_eq!(
            cache.get(module(0), IrId::new(1000)).expect("high").args(),
            &two
        );
        assert!(cache.get(module(0), IrId::new(500)).is_none());
    }

    #[test]
    fn from_kind_round_trips_recorded_kind() {
        let mut cache = PrimopBuiltinCache::default();
        cache.insert(
            module(3),
            IrId::new(4),
            entry(BuiltinKind::StringLengthBuiltin, &[IrId::new(0)]),
        );
        let kind = cache
            .get(module(3), IrId::new(4))
            .expect("recorded kind")
            .kind();
        let builtin = Builtin::from_kind(kind);
        assert_eq!(builtin.kind(), BuiltinKind::StringLengthBuiltin);
    }

    #[test]
    #[should_panic(expected = "over-arity")]
    fn new_rejects_over_arity_argument_lists() {
        let too_many = [IrId::new(0), IrId::new(1), IrId::new(2), IrId::new(3)];
        let _ = CachedPrimop::new(BuiltinKind::StringLengthBuiltin, &too_many);
    }
}
