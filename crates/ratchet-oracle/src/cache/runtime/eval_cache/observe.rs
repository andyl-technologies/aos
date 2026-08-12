//! `EvalCache` impure-input and inline-payload observation methods, split from the parent for the §2 line cap.

use super::*;

impl EvalCache {
    /// Observes impure inputs from one completed evaluator trace source.
    ///
    /// This delegates to [`DemandGraph::observe_impure_trace`]. It records only
    /// cacheable input leaves and cacheability status; it does not create
    /// evaluating-node demand edges or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the underlying graph cannot reserve
    /// storage or cannot insert/reconsider a cacheable input leaf.
    pub fn observe_impure_inputs<T>(
        &mut self,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        self.graph.observe_impure_trace(
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )
    }

    /// Observes impure inputs and wires cacheable leaves to an existing node.
    ///
    /// `dependent` must be a caller-supplied node in this cache's demand graph.
    /// This delegates trace edge wiring to
    /// [`DemandGraph::observe_impure_trace_for_node`]. Incomplete or
    /// uncacheable traces also remove side payload records for `dependent` and
    /// its transitive memo-read dependents. This does not create evaluating
    /// nodes or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the dependent node is unknown, if
    /// trace observation fails, or if dependency edge insertion fails.
    pub fn observe_impure_inputs_for_node<T>(
        &mut self,
        dependent: DemandNodeId,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let observation = self.graph.observe_impure_trace_for_node(
            dependent,
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )?;
        if observation.status() != ImpureTraceStatus::Cacheable {
            let affected_dependents = self.graph.invalidate_node(dependent)?;
            self.remove_side_payloads(dependent);
            for dependent in affected_dependents {
                self.remove_side_payloads(dependent);
            }
        }
        Ok(observation)
    }

    /// Observes an expression evaluation trace and wires cacheable leaves to its node.
    ///
    /// This first computes the expression key and observes the trace.
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node; if the expression key already exists, any side
    /// inline payload is invalidated, its transitive memo-read dependents are
    /// dirtied, and its stale input dependencies are cleared.
    /// Complete cacheable traces get or insert the caller-supplied expression
    /// node, invalidate any prior side inline payload, and then replace that
    /// node's impure-input dependency group with the observed input leaves.
    ///
    /// This is still an explicit adapter: callers supply expression identity,
    /// ordered free-variable value hashes, and the optional current value hash.
    /// It does not compute evaluator identities, perform memo lookup, or own
    /// dynamic evaluator node lifecycle.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation or edge replacement later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, an existing payload cannot be
    /// invalidated, or dependency edge replacement fails.
    pub fn observe_expression_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            if let Some(node) = existing_node {
                self.invalidate_existing_inline_payload(Some(node))?;
                self.graph.replace_dependency_group(
                    node,
                    DemandDependencyGroup::ImpureInput,
                    std::iter::empty::<DemandNodeId>(),
                )?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        self.invalidate_existing_inline_payload_if_present(existing_node)?;
        let node = self.graph.get_or_insert_node(key, value_hash)?;
        self.remember_persist_node_key(node, persist_key)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        Ok(ExpressionTraceObservation::new(Some(node), trace))
    }

    /// Observes one recomputed pure expression payload.
    ///
    /// This is the first force-path integration point for the demand graph:
    /// callers still provide the expression identity and ordered free-variable
    /// hashes, and the cache only records/reconsiders the payload value hash.
    /// It does not perform memo lookup, compute free-variable hashes, or
    /// serialize general heap-backed values. Pure observations own no
    /// impure-input edges, so replacing a prior trace-backed payload clears only
    /// the node's impure-input dependency group while preserving memo-read
    /// dependencies.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let record = InlineValueRecord::reusable_without_revalidation(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            std::iter::empty::<DemandNodeId>(),
        )?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(reconsideration);
        }
        self.inline_values.insert(node, record);
        Ok(reconsideration)
    }

    /// Invalidates an existing inline expression payload.
    ///
    /// If the expression key already exists, the node and its transitive
    /// memo-read dependents are marked dirty and their side payloads are
    /// removed. Missing keys return `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or the
    /// existing node cannot be marked dirty.
    pub fn invalidate_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<bool, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(false);
        };
        self.invalidate_existing_inline_payload(Some(node))?;
        Ok(true)
    }

    /// Observes one recomputed immediate expression result.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, the node cannot be reconsidered, or the value is not an
    /// inline scalar supported by [`ValueHash::from_inline_value`].
    pub fn observe_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let value = CachedExpressionValue::immediate(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        self.observe_inline_expression_payload(identity, free_var_value_hashes, value)
    }

    /// Observes one recomputed expression payload with its impure inputs.
    ///
    /// Cacheable traces get or insert the expression node, replace its
    /// dependencies with the observed input leaves, reconsider the node from
    /// the payload value hash, and store the side payload plus the cacheable
    /// input fingerprints
    /// required by
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node or payload; if the expression key already exists,
    /// its prior inline payload and stale dependencies are removed and the node
    /// is marked dirty.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation, edge replacement, or value reconsideration later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, dependency edge replacement
    /// fails, dirty marking fails, or node reconsideration fails.
    pub fn observe_inline_expression_payload_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        self.observe_inline_expression_payload_for_key_with_impure_inputs(
            key,
            persist_key,
            value,
            source,
        )
    }

    fn observe_inline_expression_payload_for_key_with_impure_inputs<T>(
        &mut self,
        key: DemandCacheKey,
        persist_key: PersistNodeMetadataKey,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            self.invalidate_existing_inline_payload(existing_node)?;
            if let Some(node) = existing_node {
                self.graph.replace_dependency_group(
                    node,
                    DemandDependencyGroup::ImpureInput,
                    std::iter::empty::<DemandNodeId>(),
                )?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let record = match InlineValueRecord::requires_revalidation(value, source) {
            Ok(record) => record,
            Err(error) => {
                self.invalidate_existing_inline_payload(existing_node)?;
                if let Some(node) = existing_node {
                    self.graph.replace_dependency_group(
                        node,
                        DemandDependencyGroup::ImpureInput,
                        std::iter::empty::<DemandNodeId>(),
                    )?;
                }
                return Err(error);
            }
        };
        let node = self.graph.get_or_insert_node(key, None)?;
        self.remember_persist_node_key(node, persist_key)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        let payload_reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(ExpressionTraceObservation::with_payload_reconsideration(
                node,
                trace,
                payload_reconsideration,
            ));
        }
        self.inline_values.insert(node, record);
        Ok(ExpressionTraceObservation::with_payload_reconsideration(
            node,
            trace,
            payload_reconsideration,
        ))
    }

    /// Observes one recomputed immediate expression result with its impure inputs.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if inline value hashing fails, trace
    /// observation fails, expression cache-key construction or insertion fails,
    /// dependency edge insertion fails, dirty marking fails, or node
    /// reconsideration fails.
    pub fn observe_inline_expression_result_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        let value = match CachedExpressionValue::immediate(value) {
            Ok(value) => value,
            Err(source) => {
                let existing_node = self.graph.node_id_for_key(key);
                self.invalidate_existing_inline_payload(existing_node)?;
                if let Some(node) = existing_node {
                    self.graph.replace_dependency_group(
                        node,
                        DemandDependencyGroup::ImpureInput,
                        std::iter::empty::<DemandNodeId>(),
                    )?;
                }
                return Err(DemandGraphError::ValueHash { source });
            }
        };
        self.observe_inline_expression_payload_for_key_with_impure_inputs(
            key,
            persist_key,
            value,
            source,
        )
    }
}
