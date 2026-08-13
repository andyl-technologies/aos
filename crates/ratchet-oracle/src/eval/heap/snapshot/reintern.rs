//! Cross-evaluator identity re-interning (RFC-0007 doc 31 §1 step 4, W1).
//!
//! Raw interned symbol ids and raw module ids ride in an image's payloads
//! (attrs entry keys and positions, primop symbols and applied-argument
//! provenance, builtin-attr symbols). Both id spaces are per-evaluator:
//! symbol ids follow the consuming evaluator's interning history and module
//! ids its import order, so restoring into a *fresh* evaluator without
//! rewriting them silently rebinds names. This module builds the rewrite
//! maps at restore:
//!
//! - **Symbols**: the image's v9 symbol-name table (names in capture-time id
//!   order) is re-interned into the consuming evaluator's [`SymbolTable`];
//!   `old id -> new id` is total over the table and every raw id in the image
//!   must be within it (untrusted input: out-of-table ids refuse).
//! - **Modules**: the image's v9 module-fingerprint table re-resolves each
//!   capture-time module id through the [`LambdaCodeResolver`] — the same
//!   refuse-on-drift discipline as closure code refs. A module captured
//!   without a content fingerprint (all-zero entry) refuses if anything
//!   references it.
//!
//! When both maps are the identity (the same-evaluator restore of the step-3
//! acceptance), the rewrite passes are skipped entirely.

use crate::cache::{CacheExprSourceHash, DurableBlake3Hash};
use crate::eval::module::EvalModuleId;
use crate::syntax::{Symbol, SymbolTable};

use super::super::closure_code_ref::LambdaCodeResolver;
use super::EvalHeapSnapshotError;

/// The restore-side rewrite maps for raw symbol and module ids.
#[derive(Debug)]
pub(super) struct IdentityRemap {
    /// `old symbol id -> new symbol`, indexed by old id.
    symbols: Vec<Symbol>,
    /// `old module id -> resolved live module`, indexed by old id; `None`
    /// records a capture-time module with no content fingerprint.
    modules: Vec<Option<EvalModuleId>>,
    /// Whether both maps are the identity (same-evaluator restore).
    identity: bool,
}

impl IdentityRemap {
    /// Builds the rewrite maps by re-interning the image's symbol names into
    /// `symbols` and re-resolving its module fingerprints through `resolver`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::SymbolInternFailed`] when a name
    /// cannot be interned into the consuming table.
    pub(super) fn build(
        symbol_names: &[Vec<u8>],
        module_fingerprints: &[[u8; 32]],
        resolver: &dyn LambdaCodeResolver,
        symbols: &mut SymbolTable,
    ) -> Result<Self, EvalHeapSnapshotError> {
        let mut symbol_map = Vec::with_capacity(symbol_names.len());
        let mut identity = true;
        for (old, name) in symbol_names.iter().enumerate() {
            let new = symbols
                .intern(name)
                .map_err(|_| EvalHeapSnapshotError::SymbolInternFailed { symbol: old as u32 })?;
            identity &= new.as_u32() as usize == old;
            symbol_map.push(new);
        }
        let mut module_map = Vec::with_capacity(module_fingerprints.len());
        for (old, fingerprint) in module_fingerprints.iter().enumerate() {
            let resolved = if fingerprint == &[0u8; 32] {
                None
            } else {
                resolver.resolve(CacheExprSourceHash::from_persisted_hash(
                    DurableBlake3Hash::from_bytes(*fingerprint),
                ))
            };
            identity &= resolved == Some(EvalModuleId::new(old as u32));
            module_map.push(resolved);
        }
        Ok(Self {
            symbols: symbol_map,
            modules: module_map,
            identity,
        })
    }

    /// Returns whether both maps are the identity (rewrites can be skipped).
    pub(super) fn is_identity(&self) -> bool {
        self.identity
    }

    /// Rewrites one raw symbol id, refusing ids outside the captured table.
    pub(super) fn symbol(&self, old: Symbol) -> Option<Symbol> {
        self.symbols.get(old.as_u32() as usize).copied()
    }

    /// Rewrites one raw module id, refusing unfingerprintable or drifted
    /// modules (the position/provenance analog of `ClosureCodeDrift`).
    pub(super) fn module(&self, old: EvalModuleId) -> Option<EvalModuleId> {
        self.modules.get(old.index()).copied().flatten()
    }
}

use std::ptr::NonNull;

use ratchet_value::heap::FlatObjectKind;

use super::super::EvalHeap;
use super::super::arena::attrs_structural_hash;
use crate::value::HeapObject;

impl EvalHeap {
    /// Rewrites every relocated arena-inline attrset into the consuming
    /// evaluator's id spaces (step-4 W1).
    ///
    /// For each attrset: entry keys re-intern and position provenance
    /// re-resolves through `remap` (the entry array re-sorts and both
    /// permutations recompose inside [`FlatAttrs::reintern_entries`]);
    /// foreign shape projections reset to unshaped; and the structural hash
    /// — which is id-derived over entry keys, position modules, the shape
    /// metadata, and both permutations (`attrs_structural_hash`,
    /// eval/heap/arena.rs) — is recomputed through the safe header-update
    /// door, the increment-4 pattern.
    ///
    /// [`FlatAttrs::reintern_entries`]: crate::attrs::FlatAttrs::reintern_entries
    ///
    /// A position whose module identity cannot re-resolve degrades to no
    /// position (diagnostic provenance of a module with no counterpart in
    /// the consuming evaluator); an unmappable *key* refuses.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::MalformedAttrsPayload`] when a key id
    /// is outside the image's symbol table (or a forged table repeats names),
    /// and [`EvalHeapSnapshotError::FlatResolve`] when an attrset cannot be
    /// resolved for rewriting.
    pub(super) fn reintern_relocated_attrs(
        &mut self,
        ptrs: &[NonNull<HeapObject>],
        remap: &IdentityRemap,
    ) -> Result<(), EvalHeapSnapshotError> {
        for &ptr in ptrs {
            let index = self
                .flat_arena
                .index_for_pointer(ptr)
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?
                .raw();
            let hash = {
                let payload = self
                    .flat_attrs
                    .resolve_mut(ptr, FlatObjectKind::Attrs)
                    .map_err(EvalHeapSnapshotError::FlatResolve)?;
                payload
                    .attrs
                    .reintern_entries(&mut |symbol| remap.symbol(symbol), &mut |module| {
                        remap
                            .module(EvalModuleId::new(module))
                            .map(|new| new.as_u32())
                    })
                    .map_err(|()| EvalHeapSnapshotError::MalformedAttrsPayload { index })?;
                payload.metadata = payload.metadata.without_projected_shape();
                attrs_structural_hash(payload.metadata, &payload.attrs)
            };
            self.flat_attrs
                .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
        }
        Ok(())
    }
}
