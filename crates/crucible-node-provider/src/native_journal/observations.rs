//! Original owner observation streams with captured monotonic cursors.

use crucible_node_contract::ObservationBatch;

use super::*;

/// Authenticates observed native output custody and its visibility disposition.
pub trait NativeObservationVerifier<C> {
    /// Verifies the original operation's complete observed event and payload custody.
    ///
    /// # Errors
    /// Rejects unavailable output pins, changed receipts, unsupported schemas,
    /// false closure, unauthorized visibility, or foreign operation lineage.
    fn verify_observation(
        &self,
        resources: &C,
        original: &OperationSnapshot,
        batch: &ObservationBatch,
    ) -> Result<(), ProviderError>;
}

impl<C: 'static> NativeJournal<C> {
    /// Retains an original verified observation batch without changing its visibility.
    ///
    /// Exact retries keep the original batch. Nonempty owner stream ranges must
    /// begin immediately after the retained cursor, including after reconnect.
    ///
    /// # Errors
    /// Rejects foreign scope/grants, changed sequence material, gaps, missing
    /// native content custody, or exhausted metadata storage before publication.
    pub fn append_observation(
        &mut self,
        permit: &NativeOperationPermit,
        batch: &ObservationBatch,
        verifier: &dyn NativeObservationVerifier<C>,
    ) -> Result<(), ProviderError> {
        self.check_operation_permit(permit)?;
        batch.validate()?;
        let original = self.operation(permit.operation_id())?.clone();
        if batch.operation_id != original.operation_id
            || batch.execution_owner_id != original.scope.execution_owner
            || batch.owner_generation != original.scope.owner_generation
            || batch.owner_binding_hash != original.original.binding_hash
            || original.original.activation_id.0.as_ref() != Some(&batch.activation_id)
            || original.original.world_generation != batch.world_generation
        {
            return Err(ProviderError::Correlation(
                "observation changed original operation scope",
            ));
        }
        let arguments = original.original.decoded_arguments()?;
        let grant = match &arguments {
            bodies::BeginArguments::ExactRun(value)
            | bodies::BeginArguments::BoundarySettle(value) => Some(&value.grant_id),
            bodies::BeginArguments::QuantumBegin(value) => Some(&value.grant_id),
            _ => None,
        };
        if batch.grant_id.as_ref() != grant {
            return Err(ProviderError::Correlation(
                "observation changed original grant lineage",
            ));
        }
        let hash = batch.identity()?;
        for existing in &self.custody().observations {
            if existing.execution_owner_id == batch.execution_owner_id
                && existing.owner_generation == batch.owner_generation
                && existing.first_sequence == batch.first_sequence
                && existing.last_sequence == batch.last_sequence
                && (!batch.events.is_empty() || existing.operation_id == batch.operation_id)
            {
                if existing.identity()? == hash {
                    return Ok(());
                }
                return Err(ProviderError::Conflict(
                    "original observation sequence changed material",
                ));
            }
        }
        if self.custody().observations.len() >= self.limits.observation_batches {
            return Err(ProviderError::ResourceExhausted(
                "native observation batch credit",
            ));
        }
        for retained in self.custody().observations.iter().filter(|old| {
            old.execution_owner_id == batch.execution_owner_id
                && old.owner_generation == batch.owner_generation
        }) {
            if retained.events.iter().any(|old| {
                batch.events.iter().any(|new| {
                    old.source.node_id == new.source.node_id
                        && old.source_sequence == new.source_sequence
                })
            }) {
                return Err(ProviderError::Conflict(
                    "producer sequence repeats across observations",
                ));
            }
        }
        let stream = OwnerStream {
            owner: batch.execution_owner_id.clone(),
            generation: batch.owner_generation,
        };
        let cursor = self
            .custody()
            .observation_streams
            .get(&stream)
            .copied()
            .unwrap_or(U64::new(0));
        if !batch.events.is_empty() && batch.first_sequence != cursor.checked_add(U64::new(1))? {
            return Err(ProviderError::Conflict(
                "native observation cursor has a gap",
            ));
        }
        let bytes = canonical::canonical_json(
            &serde_json::to_value(batch).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let retained_bytes = self.reserve_bytes(bytes.len())?;
        verifier.verify_observation(self.resources(), &original, batch)?;
        self.custody_mut().observations.push(batch.clone());
        if !batch.events.is_empty() {
            self.custody_mut()
                .observation_streams
                .insert(stream, batch.last_sequence);
        }
        self.custody_mut().retained_bytes = retained_bytes;
        Ok(())
    }

    pub(super) fn observations_after(
        &self,
        stream: &OwnerStream,
        after: U64,
        maximum: usize,
    ) -> Result<(Vec<ObservationBatch>, U64), ProviderError> {
        if maximum > self.limits.observation_batches {
            return Err(ProviderError::ResourceExhausted(
                "native observation read allowance",
            ));
        }
        let cursor = self
            .custody()
            .observation_streams
            .get(stream)
            .copied()
            .unwrap_or(U64::new(0));
        if after > cursor {
            return Err(ProviderError::Conflict(
                "observation cursor exceeds retained stream",
            ));
        }
        if self.custody().observations.iter().any(|batch| {
            batch.execution_owner_id == stream.owner
                && batch.owner_generation == stream.generation
                && batch.first_sequence <= after
                && after < batch.last_sequence
        }) {
            return Err(ProviderError::Conflict(
                "observation cursor splits an immutable retained batch",
            ));
        }
        let observations: Vec<_> = self
            .custody()
            .observations
            .iter()
            .filter(|batch| {
                batch.execution_owner_id == stream.owner
                    && batch.owner_generation == stream.generation
                    && batch.last_sequence > after
            })
            .take(maximum)
            .cloned()
            .collect();
        let next = observations
            .last()
            .map_or(after, |batch| batch.last_sequence);
        Ok((observations, next))
    }

    /// Enumerates complete original observation batches beneath an owner cursor.
    ///
    /// A cursor must come from an earlier complete-batch response; splitting a
    /// retained batch would change its immutable content identity. Zero maximum
    /// is a bounded empty enumeration and grants no absence beyond its cursor.
    ///
    /// # Errors
    /// Rejects future or split-batch cursors and excessive page bounds.
    pub fn observe(
        &self,
        stream: &OwnerStream,
        after: U64,
        maximum_batches: usize,
    ) -> Result<ObservationPage, ProviderError> {
        let (observations, next_sequence) =
            self.observations_after(stream, after, maximum_batches)?;
        let cursor = self
            .custody()
            .observation_streams
            .get(stream)
            .copied()
            .unwrap_or(U64::new(0));
        Ok(ObservationPage {
            observations,
            next_sequence,
            complete: next_sequence == cursor,
        })
    }
}
