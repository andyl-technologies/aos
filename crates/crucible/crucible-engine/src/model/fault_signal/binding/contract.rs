//! Fully admitted binding contracts and signal/effect compatibility validation.

use super::*;

fn admit_name_copy(name: &str) -> Result<(), BindingError> {
    crate::owned_decode::charge_array::<u8>(name.len()).map_err(BindingError::OriginalAdmission)
}

fn admit_type_copy(value: &SignalValueType) -> Result<(), BindingError> {
    match value {
        SignalValueType::Enum(schema) | SignalValueType::Event(schema) => {
            admit_name_copy(schema.as_str())
        }
        _ => Ok(()),
    }
}

fn admit_value_copy(value: &SignalValue) -> Result<(), BindingError> {
    match value {
        SignalValue::Enum { schema, variant } => {
            admit_name_copy(schema.as_str())?;
            admit_name_copy(variant.as_str())
        }
        SignalValue::Event { schema, payload } => {
            admit_name_copy(schema.as_str())?;
            crate::owned_decode::charge_array::<u8>(payload.len())
                .map_err(BindingError::OriginalAdmission)
        }
        SignalValue::Bytes(bytes) => crate::owned_decode::charge_array::<u8>(bytes.len())
            .map_err(BindingError::OriginalAdmission),
        SignalValue::Vector2(values) | SignalValue::Vector3(values) => {
            crate::owned_decode::charge_array::<SignalValue>(values.len())
                .map_err(BindingError::OriginalAdmission)?;
            for value in values {
                admit_value_copy(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn admit_transition_copy(value: &StateTransitionTableDeclaration) -> Result<(), BindingError> {
    admit_name_copy(value.id.as_str())?;
    admit_name_copy(value.default_transition.as_str())?;
    admit_type_copy(&value.input)?;
    for (request, output) in &value.transitions {
        crate::owned_decode::charge_btree_entry::<SignalValue, FaultObjectId>()
            .map_err(BindingError::OriginalAdmission)?;
        admit_value_copy(request)?;
        admit_name_copy(output.as_str())?;
    }
    Ok(())
}

fn admit_service_copy(value: &ServiceProfileDeclaration) -> Result<(), BindingError> {
    admit_name_copy(value.id.as_str())?;
    crate::owned_decode::charge_array::<ServiceProfileInput>(value.inputs.len())
        .map_err(BindingError::OriginalAdmission)?;
    crate::owned_decode::charge_array::<MappedEffectParameter>(value.parameters.len())
        .map_err(BindingError::OriginalAdmission)?;
    for input in &value.inputs {
        admit_name_copy(input.role.as_str())?;
        admit_type_copy(&input.shape.value_type)?;
    }
    Ok(())
}
/// One fully admitted signal-to-effect binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultBinding {
    id: FaultObjectId,
    program: ContentHash,
    signals: Vec<SignalId>,
    sampling: BindingSampling,
    mapping: BindingMapping,
    selector: TargetSelector,
    phases: BTreeSet<FaultPhase>,
    effect: EffectRequest,
    opportunity_filter: Option<OpportunityFilter>,
    search: BindingSearchPolicy,
    observability: BindingObservabilityPolicy,
    transition_declaration: Option<StateTransitionTableDeclaration>,
    service_declaration: Option<ServiceProfileDeclaration>,
}

impl FaultBinding {
    /// Validates a binding that references no named mapping declarations.
    ///
    /// Use [`Self::new_with_registry`] for `state_transition` and
    /// `service_profile` mappings.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] under the same conditions as
    /// [`Self::new_with_registry`]. Named mappings fail closed because the
    /// implicit registry is empty.
    // crucible-lint: allow rust-allow -- the constructor keeps each binding contract field explicit for validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FaultObjectId,
        signals: Vec<SignalId>,
        sampling: BindingSampling,
        mapping: BindingMapping,
        selector: TargetSelector,
        phases: BTreeSet<FaultPhase>,
        effect: EffectRequest,
        opportunity_filter: Option<OpportunityFilter>,
        search: BindingSearchPolicy,
        observability: BindingObservabilityPolicy,
        program: &SignalProgram,
    ) -> Result<Self, BindingError> {
        Self::new_with_registry(
            id,
            signals,
            sampling,
            mapping,
            selector,
            phases,
            effect,
            opportunity_filter,
            search,
            observability,
            program,
            &BindingMappingRegistry::default(),
        )
    }

    /// Validates a binding against one canonical signal program.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] for an unexported input, incompatible shape,
    /// illegal target, missing filter, or unbounded search policy.
    // crucible-lint: allow rust-allow -- registry validation needs the complete binding contract and resource limits together.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_registry(
        id: FaultObjectId,
        mut signals: Vec<SignalId>,
        sampling: BindingSampling,
        mapping: BindingMapping,
        selector: TargetSelector,
        phases: BTreeSet<FaultPhase>,
        effect: EffectRequest,
        opportunity_filter: Option<OpportunityFilter>,
        mut search: BindingSearchPolicy,
        observability: BindingObservabilityPolicy,
        program: &SignalProgram,
        mapping_registry: &BindingMappingRegistry,
    ) -> Result<Self, BindingError> {
        if signals.is_empty() {
            return Err(BindingError::NoSignals);
        }
        if signals.len() > HARD_BINDING_SIGNAL_INPUT_LIMIT {
            return Err(BindingError::TooManySignals);
        }
        signals.sort_unstable();
        if signals.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BindingError::DuplicateSignal);
        }
        let mut shapes = Vec::new();
        crate::owned_decode::reserve_vec(&mut shapes, signals.len())
            .map_err(BindingError::OriginalAdmission)?;
        for signal in &signals {
            shapes.push(
                program
                    .exported_shape(signal)
                    .ok_or_else(|| BindingError::MissingSignal(signal.clone()))?,
            );
        }
        let opportunity_sampling = sampling == BindingSampling::AtOpportunity
            || matches!(
                &sampling,
                BindingSampling::AtEvent(parent) if parent.requires_opportunity()
            );
        if signals.iter().any(|signal| {
            program.exported_node(signal).is_some_and(|node| {
                (matches!(
                    node.domain,
                    SignalDomain::Operation | SignalDomain::State | SignalDomain::NodeCounter
                ) && !opportunity_sampling)
                    || (node.domain == SignalDomain::Event
                        && !matches!(&sampling, BindingSampling::AtEvent(_)))
                    || node.domain == SignalDomain::Spatial
            })
        }) || matches!(&sampling, BindingSampling::AtEvent(_))
            && !signals.iter().all(|signal| {
                program
                    .exported_node(signal)
                    .is_some_and(|node| node.domain == SignalDomain::Event)
            })
        {
            return Err(BindingError::InvalidSignalDomain);
        }
        validate_mapping(&mapping, &shapes, effect.kind(), effect.lifetime())?;
        mapping_registry.validate_mapping(&mapping, &shapes, effect.kind())?;
        let transition = match &mapping {
            BindingMapping::StateTransition { transition_table } => {
                mapping_registry.transition_tables.get(transition_table)
            }
            _ => None,
        };
        let service = match &mapping {
            BindingMapping::ServiceProfile { service_profile } => {
                mapping_registry.service_profiles.get(service_profile)
            }
            _ => None,
        };
        if let Some(declaration) = transition {
            admit_transition_copy(declaration)?;
        }
        if let Some(declaration) = service {
            admit_service_copy(declaration)?;
        }
        let transition_declaration = transition.cloned();
        let service_declaration = service.cloned();
        if let (BindingSearchPolicy::BranchTransition { candidates }, Some(declaration)) =
            (&search, &transition_declaration)
            && candidates.iter().any(|candidate| {
                candidate != &declaration.default_transition
                    && !declaration
                        .transitions
                        .values()
                        .any(|transition| transition == candidate)
            })
        {
            return Err(BindingError::InvalidSearchPolicy);
        }
        if phases.is_empty()
            || phases
                .iter()
                .any(|phase| !effect.kind().descriptor().phases.contains(phase))
        {
            return Err(BindingError::InvalidBindingPhases);
        }
        if opportunity_sampling && effect.lifetime() == EffectLifetime::Persistent {
            return Err(BindingError::PersistentOpportunitySampling);
        }
        if let BindingMapping::Threshold {
            comparison,
            threshold,
            clear_threshold: Some(clear_threshold),
            residence_nanos,
        } = &mapping
        {
            let ordering = compare_numeric(threshold, clear_threshold)
                .map_err(|_| BindingError::InvalidHysteresis)?;
            let valid_deadband = match comparison {
                ThresholdComparison::LessThan | ThresholdComparison::LessThanOrEqual => {
                    ordering.is_lt()
                }
                ThresholdComparison::GreaterThan | ThresholdComparison::GreaterThanOrEqual => {
                    ordering.is_gt()
                }
            };
            if !valid_deadband || (sampling == BindingSampling::AtChange && *residence_nanos > 0) {
                return Err(BindingError::InvalidHysteresis);
            }
        }
        if matches!(
            mapping,
            BindingMapping::Threshold {
                residence_nanos: 1..,
                ..
            }
        ) && sampling == BindingSampling::AtChange
        {
            return Err(BindingError::InvalidHysteresis);
        }
        selector.validate()?;
        for target in selector.resolved().targets() {
            if !effect.kind().descriptor().targets.contains(&target.kind()) {
                return Err(BindingError::EffectTarget {
                    effect: effect.kind(),
                    target: target.kind(),
                });
            }
        }
        if selector
            .resolved()
            .adapter()
            .is_some_and(|adapter| adapter != effect.kind().descriptor().adapter)
        {
            return Err(BindingError::EffectAdapter);
        }
        if matches!(selector, TargetSelector::DynamicPath { .. })
            && effect.kind().descriptor().adapter != FaultAdapter::Network
        {
            return Err(BindingError::DynamicSelectorAdapter);
        }
        match (opportunity_sampling, opportunity_filter.is_some()) {
            (true, false) => return Err(BindingError::MissingOpportunityFilter),
            (false, true) => return Err(BindingError::UnexpectedOpportunityFilter),
            _ => {}
        }
        if matches!(mapping, BindingMapping::Hazard) && !opportunity_sampling {
            return Err(BindingError::HazardSampling);
        }
        if let Some(filter) = &opportunity_filter {
            filter.validate(effect.kind())?;
            if filter.phases != phases {
                return Err(BindingError::InvalidBindingPhases);
            }
        }
        search.validate(&mapping, &signals, program)?;
        Ok(Self {
            id,
            program: program.id(),
            signals,
            sampling,
            mapping,
            selector,
            phases,
            effect,
            opportunity_filter,
            search,
            observability,
            transition_declaration,
            service_declaration,
        })
    }

    /// Returns the stable binding identity.
    #[must_use]
    pub const fn id(&self) -> &FaultObjectId {
        &self.id
    }

    /// Returns the exact signal program against which this binding was admitted.
    #[must_use]
    pub const fn program(&self) -> ContentHash {
        self.program
    }

    /// Returns canonical input signal IDs.
    #[must_use]
    pub fn signals(&self) -> &[SignalId] {
        &self.signals
    }

    /// Returns the sampling rule.
    #[must_use]
    pub const fn sampling(&self) -> &BindingSampling {
        &self.sampling
    }

    /// Returns the mapping rule.
    #[must_use]
    pub const fn mapping(&self) -> &BindingMapping {
        &self.mapping
    }

    /// Returns the selector.
    #[must_use]
    pub const fn selector(&self) -> &TargetSelector {
        &self.selector
    }

    /// Returns the nonempty canonical adapter phases authored for this binding.
    #[must_use]
    pub const fn phases(&self) -> &BTreeSet<FaultPhase> {
        &self.phases
    }

    /// Returns the typed effect request.
    #[must_use]
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    /// Returns the optional opportunity filter.
    #[must_use]
    pub const fn opportunity_filter(&self) -> Option<&OpportunityFilter> {
        self.opportunity_filter.as_ref()
    }

    /// Returns the bounded search policy.
    #[must_use]
    pub const fn search(&self) -> &BindingSearchPolicy {
        &self.search
    }

    /// Returns the event-retention policy.
    #[must_use]
    pub const fn observability(&self) -> BindingObservabilityPolicy {
        self.observability
    }

    /// Returns the admitted exhaustive state-transition declaration.
    #[must_use]
    pub const fn transition_declaration(&self) -> Option<&StateTransitionTableDeclaration> {
        self.transition_declaration.as_ref()
    }

    /// Returns the admitted service-profile declaration.
    #[must_use]
    pub const fn service_declaration(&self) -> Option<&ServiceProfileDeclaration> {
        self.service_declaration.as_ref()
    }

    /// Encodes and hashes every executable field using the versioned wire form.
    pub(crate) fn contract_digest(&self) -> Result<ContentHash, serde_json::Error> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.fault-binding-contract.json.v1\0");
        serde_json::to_writer(&mut hasher, self)?;
        Ok(ContentHash {
            bytes: *hasher.finalize().as_bytes(),
        })
    }

    pub(crate) fn materialize_fixed(
        &self,
        program: &SignalProgram,
        mapping: BindingMapping,
    ) -> Result<Self, BindingError> {
        let registry = BindingMappingRegistry::new(
            self.transition_declaration.clone().into_iter().collect(),
            self.service_declaration.clone().into_iter().collect(),
        )?;
        Self::new_with_registry(
            self.id.clone(),
            self.signals.clone(),
            self.sampling.clone(),
            mapping,
            self.selector.clone(),
            self.phases.clone(),
            self.effect.clone(),
            self.opportunity_filter.clone(),
            BindingSearchPolicy::Fixed,
            self.observability,
            program,
            &registry,
        )
    }

    pub(crate) fn rebind_program(
        &self,
        program: &SignalProgram,
        search: BindingSearchPolicy,
    ) -> Result<Self, BindingError> {
        let registry = BindingMappingRegistry::new(
            self.transition_declaration.clone().into_iter().collect(),
            self.service_declaration.clone().into_iter().collect(),
        )?;
        Self::new_with_registry(
            self.id.clone(),
            self.signals.clone(),
            self.sampling.clone(),
            self.mapping.clone(),
            self.selector.clone(),
            self.phases.clone(),
            self.effect.clone(),
            self.opportunity_filter.clone(),
            search,
            self.observability,
            program,
            &registry,
        )
    }
}

pub(super) fn validate_mapping(
    mapping: &BindingMapping,
    shapes: &[&SignalShape],
    effect: EffectKind,
    lifetime: EffectLifetime,
) -> Result<(), BindingError> {
    let exactly_one = || {
        shapes
            .first()
            .filter(|_| shapes.len() == 1)
            .copied()
            .ok_or(BindingError::MappingArity)
    };
    match mapping {
        BindingMapping::ActiveWhenTrue { .. } => {
            let shape = exactly_one()?;
            if shape.value_type != SignalValueType::Bool || lifetime != EffectLifetime::Persistent {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ActiveWhenEqual { .. } => {
            let shape = exactly_one()?;
            if !matches!(shape.value_type, SignalValueType::Enum(_))
                || lifetime != EffectLifetime::Persistent
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::Threshold {
            threshold,
            clear_threshold,
            ..
        } => {
            let shape = exactly_one()?;
            if !shape.value_type.is_numeric()
                || !threshold.has_type(&shape.value_type)
                || clear_threshold
                    .as_ref()
                    .is_some_and(|value| !value.has_type(&shape.value_type))
                || lifetime != EffectLifetime::Persistent
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::MapParameter { parameter } => {
            if !parameter.accepts(exactly_one()?) || !parameter.belongs_to(effect) {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::PiecewiseParameter {
            parameter, points, ..
        } => {
            let input = exactly_one()?;
            if points.len() < 2
                || points.len() > HARD_SEARCH_CANDIDATE_LIMIT
                || points.windows(2).any(|pair| pair[0].input >= pair[1].input)
                || points
                    .iter()
                    .any(|point| !point.input.has_type(&input.value_type))
            {
                return Err(BindingError::InvalidPiecewiseMapping);
            }
            let output_type = points[0]
                .output
                .scalar_type()
                .ok_or(BindingError::MappingShape)?;
            let output_shape = SignalShape {
                value_type: output_type.clone(),
                unit: input.unit,
                scale_decimal_exponent: input.scale_decimal_exponent,
            };
            if points
                .iter()
                .any(|point| !point.output.has_type(&output_type))
                || !parameter.accepts(&output_shape)
                || !parameter.belongs_to(effect)
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::Hazard => {
            if !MappedEffectParameter::Probability.accepts(exactly_one()?)
                || lifetime != EffectLifetime::Opportunity
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ImpulseOnEvent => {
            if !matches!(exactly_one()?.value_type, SignalValueType::Event(_))
                || lifetime != EffectLifetime::Impulse
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::StateTransition { .. } => {
            if !matches!(
                exactly_one()?.value_type,
                SignalValueType::Event(_) | SignalValueType::Enum(_)
            ) || !matches!(
                lifetime,
                EffectLifetime::Impulse | EffectLifetime::StateMachine
            ) {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ServiceProfile { .. } => {
            if shapes.is_empty() || shapes.iter().any(|shape| !shape.value_type.is_numeric()) {
                return Err(BindingError::MappingShape);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
