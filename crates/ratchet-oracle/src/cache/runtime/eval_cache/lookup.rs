//! `EvalCache` inline-expression lookup methods, split from the parent for the §2 line cap.

use super::*;

impl EvalCache {
    /// Looks up a memoized expression payload.
    ///
    /// This is a precursor memo path for force-time cache hits. It returns a
    /// payload when the expression key already exists, the side payload record
    /// is reusable without input revalidation, and that payload still matches
    /// the node's value hash. Clean nodes hit directly. Dependency-free dirty
    /// nodes may cut off locally by reconsidering the stored payload hash,
    /// mirroring trace-backed revalidation for pure records. Unknown,
    /// missing-payload, trace-backed, stale-payload, dirty nodes with
    /// dependencies, and dirty memo-read supplier nodes are cache misses. Dirty
    /// memo-read suppliers also purge the node's side payload records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub fn lookup_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        Ok(self
            .lookup_inline_expression_payload_hit(identity, free_var_value_hashes)?
            .map(CachedExpressionPayloadHit::into_value))
    }

    pub(crate) fn lookup_inline_expression_payload_hit<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionPayloadHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let graph_value_hash = graph_node.value_hash();
        let graph_freshness = graph_node.freshness();
        let graph_has_dependencies = !graph_node.dependencies().is_empty();
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if !record.is_reusable_without_revalidation() {
            return Ok(None);
        }
        if graph_value_hash != Some(record.value_hash) {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if graph_freshness == NodeFreshness::Dirty {
            if graph_has_dependencies {
                return Ok(None);
            }
            let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
            return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                node,
                record.value(),
                reconsideration,
            )));
        }
        if graph_freshness != NodeFreshness::Clean {
            return Ok(None);
        }
        Ok(Some(CachedExpressionPayloadHit::new(node, record.value())))
    }

    /// Looks up a clean memoized immediate expression result.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub fn lookup_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        Ok(self
            .lookup_inline_expression_payload(identity, free_var_value_hashes)?
            .and_then(|value| value.immediate_value()))
    }

    /// Looks up an expression payload after impure-input revalidation.
    ///
    /// Pure payload records are handled identically to
    /// [`EvalCache::lookup_inline_expression_payload`]. Trace-backed payload
    /// records are returned only if every stored cacheable input identity can be
    /// revalidated, the fresh identity still matches the stored identity, the
    /// fresh observation hash still matches the stored observation hash, and the
    /// expression node is clean or can be cleaned with the recorded value hash.
    /// Revalidation observes fresh input leaves through the demand graph so
    /// changed inputs dirty dependents through the ordinary cutoff path. Dirty
    /// trace-backed payload nodes whose inputs and payload hash still match and
    /// that have no memo-read dependencies are reconsidered and can cut off
    /// locally.
    ///
    /// Inputs that cannot be revalidated, revalidate to an uncacheable
    /// fingerprint, revalidate to a different identity, or depend on a dirty
    /// memo-read supplier invalidate the expression payload and return a miss.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_payload_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .lookup_inline_expression_payload_hit_with_impure_inputs(
                identity,
                free_var_value_hashes,
                revalidator,
            )?
            .map(CachedExpressionPayloadHit::into_value))
    }

    pub(crate) fn lookup_inline_expression_payload_hit_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionPayloadHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let graph_value_hash = graph_node.value_hash();
        let graph_freshness = graph_node.freshness();
        let graph_has_dependencies = !graph_node.dependencies().is_empty();
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if graph_value_hash != Some(record.value_hash) {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if record.is_reusable_without_revalidation() {
            if graph_freshness == NodeFreshness::Dirty {
                if graph_has_dependencies {
                    return Ok(None);
                }
                let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
                return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                    node,
                    record.value(),
                    reconsideration,
                )));
            }
            if graph_freshness != NodeFreshness::Clean {
                return Ok(None);
            }
            return Ok(Some(CachedExpressionPayloadHit::new(node, record.value())));
        }
        if !self.revalidate_inline_record_inputs(node, &record, revalidator)? {
            return Ok(None);
        }
        let graph_node = self.graph.node(node)?;
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        if graph_node.freshness() == NodeFreshness::Dirty {
            if graph_node
                .dependencies_in_group(DemandDependencyGroup::MemoRead)
                .is_some_and(|dependencies| !dependencies.is_empty())
            {
                return Ok(None);
            }
            if self.has_dirty_memo_read_dependency(node)? {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(None);
            }
            let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
            return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                node,
                record.value(),
                reconsideration,
            )));
        }
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        Ok(Some(CachedExpressionPayloadHit::new(node, record.value())))
    }

    /// Looks up a clean immediate result after impure-input revalidation.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_result_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .lookup_inline_expression_payload_with_impure_inputs(
                identity,
                free_var_value_hashes,
                revalidator,
            )?
            .and_then(|value| value.immediate_value()))
    }

    /// Gets or inserts an expression node in the underlying demand graph.
    ///
    /// This is an explicit graph-allocation helper. Callers still supply the
    /// expression identity, ordered free-variable value hashes, and optional
    /// current value hash.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or if the
    /// underlying graph cannot reserve node/key storage.
    pub fn get_or_insert_expression_node<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        let node = self.graph.get_or_insert_node(key, value_hash)?;
        self.remember_persist_node_key(node, persist_key)?;
        Ok(node)
    }
}
