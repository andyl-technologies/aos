//! Derivation-side payload lookup and observation methods for `EvalCache`.

use super::*;

impl EvalCache {
    /// Looks up a clean cached derivation `.drv` path for matching ATerm bytes.
    ///
    /// This is a path-lookup precursor for future derivationStrict SHA-256
    /// short-circuiting. It returns stored `.drv` path bytes only when the
    /// caller-supplied expression key exists, the demand node is clean, a
    /// derivation path side record exists, the side record's ATerm hash matches
    /// `aterm`, and the graph node's value hash still matches the full side
    /// payload hash. Unknown, dirty, missing, stale, and dirty memo-read
    /// supplier records are misses. Dirty memo-read suppliers also purge the
    /// node's side payload records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub(crate) fn lookup_derivation_aterm_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Vec<u8>>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        Ok(self
            .lookup_derivation_aterm_path_hit(identity, free_var_value_hashes, aterm)?
            .map(CachedDerivationAtermPathHit::into_path_bytes))
    }

    pub(crate) fn lookup_derivation_aterm_path_hit<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<CachedDerivationAtermPathHit>, DemandGraphError>
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
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.derivation_aterm_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let aterm_value_hash = ValueHash::from_derivation_aterm_bytes(aterm);
        if record.aterm_value_hash != aterm_value_hash
            || graph_value_hash != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        Ok(Some(CachedDerivationAtermPathHit::new(
            node,
            record.path_bytes(),
            record.hash_derivation_modulo(),
        )))
    }

    pub(crate) fn lookup_derivation_aterm_path_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<CachedDerivationAtermPathHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let graph_freshness = graph_node.freshness();
        let graph_value_hash = graph_node.value_hash();
        let Some(record) = self.derivation_aterm_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let aterm_value_hash = ValueHash::from_derivation_aterm_bytes(aterm);
        if record.aterm_value_hash != aterm_value_hash
            || graph_value_hash != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if graph_freshness == NodeFreshness::Clean {
            return Ok(Some(CachedDerivationAtermPathHit::new(
                node,
                record.path_bytes(),
                record.hash_derivation_modulo(),
            )));
        }
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        Ok(Some(CachedDerivationAtermPathHit::with_reconsideration(
            node,
            record.path_bytes(),
            record.hash_derivation_modulo(),
            reconsideration,
        )))
    }

    /// Looks up clean cached static derivation output paths for matching ATerm bytes.
    ///
    /// This is a pre-output-path precursor for future `derivationStrict`
    /// SHA-256 short-circuiting. It returns stored output paths and the final
    /// derivation hash modulo only when the caller-supplied expression key
    /// exists, the demand node is clean, a static-output side record exists,
    /// the side record's pre-output hash matches `pre_output_aterm`, and the
    /// graph node's value hash still matches the full side payload hash.
    /// Unknown, dirty, missing, stale, and dirty memo-read supplier records are
    /// misses. Dirty memo-read suppliers also purge the node's side payload
    /// records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub(crate) fn lookup_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedDerivationOutputPaths>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        Ok(self
            .lookup_static_derivation_output_paths_hit(
                identity,
                free_var_value_hashes,
                pre_output_aterm,
            )?
            .map(CachedStaticDerivationOutputPathsHit::into_output_paths))
    }

    pub(crate) fn lookup_static_derivation_output_paths_hit<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedStaticDerivationOutputPathsHit>, DemandGraphError>
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
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.static_derivation_output_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let pre_output_value_hash = ValueHash::from_derivation_aterm_bytes(pre_output_aterm);
        if record.pre_output_value_hash != pre_output_value_hash
            || graph_value_hash != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        Ok(Some(CachedStaticDerivationOutputPathsHit::new(
            node,
            record.output_paths(),
        )))
    }

    pub(crate) fn lookup_static_derivation_output_paths_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedStaticDerivationOutputPathsHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let graph_freshness = graph_node.freshness();
        let graph_value_hash = graph_node.value_hash();
        let Some(record) = self.static_derivation_output_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let pre_output_value_hash = ValueHash::from_derivation_aterm_bytes(pre_output_aterm);
        if record.pre_output_value_hash != pre_output_value_hash
            || graph_value_hash != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if graph_freshness == NodeFreshness::Clean {
            return Ok(Some(CachedStaticDerivationOutputPathsHit::new(
                node,
                record.output_paths(),
            )));
        }
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        Ok(Some(
            CachedStaticDerivationOutputPathsHit::with_reconsideration(
                node,
                record.output_paths(),
                reconsideration,
            ),
        ))
    }

    /// Observes one recomputed derivation ATerm expression.
    ///
    /// Callers still provide the expression identity and ordered free-variable
    /// hashes. The cache hashes the recorded `.drv` ATerm bytes as a comparison
    /// key and reconsiders the expression node, but it does not memoize a value
    /// payload or compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_derivation_aterm_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        self.graph.reconsider_derivation_aterm_node(node, aterm)
    }

    /// Observes one recomputed derivation ATerm expression and `.drv` path.
    ///
    /// This extends [`Self::observe_derivation_aterm_expression`] with a side
    /// record containing caller-supplied `.drv` path bytes. The path record is
    /// usable only through [`Self::lookup_derivation_aterm_path`] when the graph
    /// node remains clean, the same ATerm hash still matches, and the graph
    /// node still carries the full ATerm/path payload hash. This API does not
    /// compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_derivation_aterm_expression_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        self.observe_derivation_aterm_expression_path_with_hash(
            identity,
            free_var_value_hashes,
            aterm,
            drv_path,
            None,
        )
    }

    pub(crate) fn observe_derivation_aterm_expression_path_with_hash<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
        hash_derivation_modulo: Option<NixSha256Digest>,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = DerivationAtermPathRecord::new(aterm, drv_path, hash_derivation_modulo);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(reconsideration);
        }
        self.derivation_aterm_paths.insert(node, record);
        Ok(reconsideration)
    }

    /// Observes resolved static derivation output paths for pre-output ATerm bytes.
    ///
    /// This records a side payload containing caller-supplied output paths and
    /// the final derivation hash modulo. The payload is usable only through
    /// [`Self::lookup_static_derivation_output_paths`] while the graph node
    /// remains clean, the same pre-output ATerm hash still matches, and the
    /// graph node still carries the full side payload hash. This API does not
    /// compute Nix-observed SHA-256 output paths itself.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = StaticDerivationOutputPathRecord::new(pre_output_aterm, output_paths);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(reconsideration);
        }
        self.static_derivation_output_paths.insert(node, record);
        Ok(reconsideration)
    }
}
