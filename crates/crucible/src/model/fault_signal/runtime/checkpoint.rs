//! Capture, restore, identity, and validation for fault-runtime checkpoints.

use super::{checkpoint_codec, *};

impl FaultRuntimeCheckpoint {
    /// Encodes the complete continuation as deterministic CBOR.
    ///
    /// This is the authoritative aggregate representation for the checkpoint
    /// byte limit and content identity. Every nested mutable field participates.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when serialization fails, the byte count
    /// is not representable, or the complete checkpoint exceeds the plan's
    /// `fat_checkpoint_bytes` limit.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultRuntimeError> {
        self.canonical_bytes_with_limit(self.resource_limits.fat_checkpoint_bytes)
    }

    /// Encodes the continuation under an additional aggregate byte ceiling.
    ///
    /// The serialized resource contract is unchanged; `maximum` only narrows
    /// the allocation and representation admitted by this operation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] under the same conditions as
    /// [`Self::canonical_bytes`], or when the representation exceeds
    /// `maximum`.
    pub fn canonical_bytes_with_limit(&self, maximum: u64) -> Result<Vec<u8>, FaultRuntimeError> {
        let mut limits = self.resource_limits;
        limits.fat_checkpoint_bytes = limits.fat_checkpoint_bytes.min(maximum);
        checkpoint_codec::encode(self, limits)
    }

    /// Decodes one canonical evaluator checkpoint and validates it against its plan.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when CBOR is malformed or noncanonical, or
    /// when versions, identities, nested state, or resource limits are invalid.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
    ) -> Result<Self, FaultRuntimeError> {
        checkpoint_codec::admit_input(bytes, plan.resource_limits())?;
        let checkpoint: Self =
            ciborium::de::from_reader(bytes).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        checkpoint.validate(plan, scenario_seed)?;
        if checkpoint.canonical_bytes()?.as_slice() != bytes {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        Ok(checkpoint)
    }

    /// Returns the content identity of the complete mutable continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] under the same conditions as
    /// [`Self::canonical_bytes`].
    pub fn content_id(&self) -> Result<ContentHash, FaultRuntimeError> {
        Ok(ContentHash::from_bytes(&self.canonical_bytes()?))
    }

    /// Validates versions, all nested state, and hard collection limits.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when any state is malformed, unsupported,
    /// or exceeds a compiled bound.
    pub fn validate(
        &self,
        plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
    ) -> Result<(), FaultRuntimeError> {
        let _ = self.canonical_bytes()?;
        let [program] = plan.programs() else {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        };
        let bindings = plan.bindings();
        if self.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || self.signal_plan != plan.id()
            || self.resource_limits != plan.resource_limits()
            || self.binding_runtime.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || self.binding_runtime.signal_program != program.id()
            || self.binding_runtime.resource_limits != self.resource_limits
            || self.binding_runtime.binding_contracts != bindings
        {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        }
        match self
            .binding_runtime
            .validate(program, bindings, scenario_seed, self.resource_limits)
        {
            Ok(()) => {}
            Err(BindingRuntimeError::ResourceLimit(error)) => {
                return Err(FaultRuntimeError::ResourceLimit(error));
            }
            Err(_) => return Err(FaultRuntimeError::VersionOrIdentityMismatch),
        }
        let search_overrides = u64::try_from(self.binding_runtime.search_overrides.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("search_choices_per_state"))?;
        self.resource_limits
            .reserve("search_choices_per_state", 0, search_overrides)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        self.binding_runtime
            .evaluator
            .validate_for_program(program, self.resource_limits)
            .map_err(|_| FaultRuntimeError::InvalidEvaluatorCheckpoint)?;
        let required_bindings = bindings
            .iter()
            .map(FaultBinding::id)
            .collect::<BTreeSet<_>>();
        if required_bindings.len() != bindings.len()
            || self
                .binding_runtime
                .bindings
                .keys()
                .collect::<BTreeSet<_>>()
                != required_bindings
        {
            return Err(FaultRuntimeError::IncompleteBindingState);
        }
        let required_adapters = BTreeSet::from([
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ]);
        if self.adapters.keys().copied().collect::<BTreeSet<_>>() != required_adapters {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        for state in self.adapters.values() {
            state.validate(self.resource_limits)?;
        }
        for (key, contribution) in self.binding_runtime.active.entries() {
            validate_contribution_key(key, contribution.request.kind())?;
            if !self
                .binding_runtime
                .bindings
                .get(&key.binding)
                .is_some_and(|state| state.active)
            {
                return Err(FaultRuntimeError::OrphanActiveContribution);
            }
        }
        if let Some(replay) = &self.replay {
            replay.validate(self.resource_limits)?;
        }
        let recorded_work_items = u64::try_from(self.recorded_work_items.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("thin_replay_events"))?;
        self.resource_limits
            .reserve("thin_replay_events", 0, recorded_work_items)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let mut recorded_effects = 0_u64;
        for item in &self.recorded_work_items {
            item.validate()?;
            let additional = u64::try_from(item.records.len())
                .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            recorded_effects = recorded_effects
                .checked_add(additional)
                .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            self.resource_limits
                .reserve("resolved_effect_records", 0, recorded_effects)
                .map_err(FaultRuntimeError::ResourceLimit)?;
        }
        Ok(())
    }
}
