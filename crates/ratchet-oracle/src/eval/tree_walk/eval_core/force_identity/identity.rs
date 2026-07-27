//! Expression cache-identity derivation.
//!
//! Builds the [`CacheExprIdentity`] domain hashes for inline expressions,
//! first-class primop calls, and derivation aterm/output subjects from the
//! owning module's content hash and the node's span.

use super::*;
use crate::cache::hashing::CacheDigestHasher;

impl TreeWalk {
    pub(in crate::eval::tree_walk::eval_core) fn cache_identity_for_node(
        &self,
        body: EvalNodeRef,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if !Self::subtree_is_speculable(&module.ir, &self.symbols, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    pub(in crate::eval::tree_walk::eval_core) fn cache_lookup_identity_for_node(
        &self,
        body: EvalNodeRef,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if module
            .ir
            .arena
            .node(body.id())
            .is_some_and(|node| Self::search_path_has_cacheable_origin(&module.ir, node))
        {
            return Self::cache_expression_identity_for_node(module, body.id());
        }
        if !Self::subtree_is_force_lookup_safe(&module.ir, &self.symbols, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    pub(in crate::eval::tree_walk::eval_core) fn cache_observation_identity_for_node(
        &self,
        body: EvalNodeRef,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(body.module().index())?;
        if module
            .ir
            .arena
            .node(body.id())
            .is_some_and(|node| Self::search_path_has_cacheable_origin(&module.ir, node))
        {
            return Self::cache_expression_identity_for_node(module, body.id());
        }
        if !Self::subtree_is_force_observation_safe(&module.ir, &self.symbols, body.id()) {
            return None;
        }
        Self::cache_expression_identity_for_node(module, body.id())
    }

    pub(in crate::eval::tree_walk) fn cache_expression_identity_for_node(
        module: &TreeWalkModule,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        let module_hash = Self::cache_module_identity_hash(module)?;
        let node = module.ir.arena.node(id)?;
        Some(Self::cache_expression_identity_for_module_hash_and_span(
            module_hash,
            id,
            node.span,
        ))
    }

    fn cache_expression_identity_for_module_hash_and_span(
        module_hash: DurableBlake3Hash,
        id: IrId,
        span: Span,
    ) -> CacheExprIdentity {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(&module_hash.as_bytes());
        hasher.update(&span.start.to_le_bytes());
        hasher.update(&span.end.to_le_bytes());
        CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            id,
        )
    }

    /// Builds a node expression identity from a fixed module hash for tests.
    #[cfg(test)]
    pub(crate) fn test_cache_expression_identity_for_module_hash_and_span(
        module_hash: DurableBlake3Hash,
        id: IrId,
        span: Span,
    ) -> CacheExprIdentity {
        Self::cache_expression_identity_for_module_hash_and_span(module_hash, id, span)
    }

    pub(in crate::eval::tree_walk::eval_core) fn cache_first_class_primop_call_identity_for_current_node(
        &self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(self.current_module.index())?;
        let module_hash =
            Self::cache_first_class_primop_module_identity_hash(module, builtin.execution())
                .or_else(|| Self::cache_module_identity_hash(module))?;
        let node = module.ir.arena.node(id)?;
        if node.kind != IrKind::Apply {
            return None;
        }
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_FIRST_CLASS_PRIMOP_CALL_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(&module_hash.as_bytes());
        hasher.update(&node.span.start.to_le_bytes());
        hasher.update(&node.span.end.to_le_bytes());
        Self::update_cache_identity_chunk(&mut hasher, builtin.name())?;
        Some(CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            id,
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_cache_first_class_primop_call_identity_for_current_node(
        &self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        self.cache_first_class_primop_call_identity_for_current_node(id, builtin)
    }

    pub(super) fn derivation_aterm_cache_identity_for_current_node(
        &self,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        self.derivation_cache_identity_for_current_node(id, b"final-aterm-path-v1")
    }

    pub(super) fn static_derivation_outputs_cache_identity_for_current_node(
        &self,
        id: IrId,
    ) -> Option<CacheExprIdentity> {
        self.derivation_cache_identity_for_current_node(id, b"static-output-paths-v1")
    }

    fn derivation_cache_identity_for_current_node(
        &self,
        id: IrId,
        stage: &[u8],
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(self.current_module.index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let node = module.ir.arena.node(id)?;
        let mut hasher = CacheDigestHasher::new();
        hasher.update(DERIVATION_ATERM_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        hasher.update(b"node-v1");
        hasher.update(stage);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&node.span.start.to_le_bytes());
        hasher.update(&node.span.end.to_le_bytes());
        Some(CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            id,
        ))
    }
}
