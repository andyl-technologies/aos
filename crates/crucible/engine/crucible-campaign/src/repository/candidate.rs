//! Structural construction and bounded choice material for immutable executor candidates.

use super::*;

impl ChoiceDiscovery {
    /// Builds one self-contained choice discovery record set.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the opportunity does not bind the
    /// exact declaration and domain.
    pub fn new(
        declaration: SelectableDeclaration,
        domain: ChoiceDomain,
        opportunity: ChoiceOpportunity,
    ) -> Result<Self, CampaignCodecError> {
        Self::from_shared(Arc::new(declaration), Arc::new(domain), opportunity)
    }

    /// Builds one discovery by sharing immutable declaration and domain values.
    ///
    /// This form avoids copying large records when many opportunities share one
    /// producer contract.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the opportunity does not bind the
    /// exact declaration and domain.
    pub(super) fn from_shared(
        declaration: Arc<SelectableDeclaration>,
        domain: Arc<ChoiceDomain>,
        opportunity: ChoiceOpportunity,
    ) -> Result<Self, CampaignCodecError> {
        opportunity.validate_references(&declaration, &domain)?;
        Ok(Self {
            declaration,
            domain,
            opportunity,
        })
    }

    /// Returns the reusable selectable declaration.
    #[must_use]
    pub fn declaration(&self) -> &SelectableDeclaration {
        self.declaration.as_ref()
    }

    /// Returns the exact offered domain.
    #[must_use]
    pub fn domain(&self) -> &ChoiceDomain {
        self.domain.as_ref()
    }

    /// Returns the dynamic opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    /// Reuses dependencies from another validated discovery with the same contract.
    ///
    /// Both values were validated when constructed. This operation compares
    /// their compact content-addressed reference contract before sharing the
    /// already-authenticated immutable values, avoiding repeated hashing of a
    /// large domain used by many opportunities.
    ///
    /// # Errors
    ///
    /// Returns an error when the discoveries name different declaration or
    /// domain records, or when their copied reference contracts differ.
    pub fn share_dependencies_from(&mut self, validated: &Self) -> Result<(), CampaignCodecError> {
        if self.opportunity.declaration() != validated.opportunity.declaration()
            || self.opportunity.domain() != validated.opportunity.domain()
            || self.opportunity.reference_contract_hash()
                != validated.opportunity.reference_contract_hash()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice discoveries do not share one validated dependency contract",
            });
        }
        self.declaration = Arc::clone(&validated.declaration);
        self.domain = Arc::clone(&validated.domain);
        Ok(())
    }
}

impl ObservationCandidate {
    /// Builds one executor-produced immutable result bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when discovered records exceed the observation count or
    /// aggregate-byte bound, contain duplicate opportunity IDs, disagree with
    /// one another, or do not exactly match the observation's choice set.
    pub fn new(
        child: ConfigurationArtifact,
        measurements: MeasurementSet,
        properties: PropertyVerdictSet,
        coverage: CoverageProjection,
        discovered_choices: Vec<ChoiceDiscovery>,
        observation: Observation,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_structural(
            child,
            measurements,
            properties,
            coverage,
            discovered_choices,
            observation,
            false,
        )
    }

    /// Reconstructs a candidate whose observation already names produced selections.
    ///
    /// # Errors
    ///
    /// Returns an error under the same structural bounds as [`Self::new`], or
    /// when the recorded selection bodies do not exactly match the observation.
    pub fn from_recorded_parts(
        child: ConfigurationArtifact,
        measurements: MeasurementSet,
        properties: PropertyVerdictSet,
        coverage: CoverageProjection,
        discovered_choices: Vec<ChoiceDiscovery>,
        produced_selections: Vec<Selection>,
        observation: Observation,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_structural(
            child,
            measurements,
            properties,
            coverage,
            discovered_choices,
            observation,
            true,
        )?
        .attach_produced_selections(produced_selections, false)
    }

    // crucible-lint: allow rust-allow -- each authenticated observation component remains explicit at this structural boundary.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_structural(
        child: ConfigurationArtifact,
        measurements: MeasurementSet,
        properties: PropertyVerdictSet,
        coverage: CoverageProjection,
        discovered_choices: Vec<ChoiceDiscovery>,
        observation: Observation,
        allow_recorded_selection_ids: bool,
    ) -> Result<Self, CampaignCodecError> {
        if discovered_choices.len() > MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate has too many discovered choices",
            });
        }
        let mut discovered_ids = BTreeSet::new();
        let mut shared_declarations: BTreeMap<SelectableId, Arc<SelectableDeclaration>> =
            BTreeMap::new();
        let mut shared_domains: BTreeMap<ChoiceDomainId, Arc<ChoiceDomain>> = BTreeMap::new();
        let mut validated_contracts = BTreeMap::new();
        let mut charged_records = BTreeSet::new();
        let mut charged_bytes = 0usize;
        let mut discovered_choices = discovered_choices;
        for discovery in &mut discovered_choices {
            let declaration = discovery.opportunity.declaration();
            let domain = discovery.opportunity.domain();
            let contract = discovery.opportunity.reference_contract_hash();
            match validated_contracts.get(&(declaration, domain)) {
                Some(validated) if *validated == contract => {}
                Some(_) => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "choice opportunities sharing references disagree on their contract",
                    });
                }
                None => {
                    discovery
                        .opportunity
                        .validate_references(&discovery.declaration, &discovery.domain)?;
                    validated_contracts.insert((declaration, domain), contract);
                }
            }
            let opportunity = discovery.opportunity.id()?;
            if !discovered_ids.insert(opportunity) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate contains duplicate choice opportunities",
                });
            }
            if let Some(existing) = shared_declarations.get(&declaration) {
                discovery.declaration = Arc::clone(existing);
            } else {
                shared_declarations.insert(declaration, Arc::clone(&discovery.declaration));
            }
            if let Some(existing) = shared_domains.get(&domain) {
                discovery.domain = Arc::clone(existing);
            } else {
                shared_domains.insert(domain, Arc::clone(&discovery.domain));
            }
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                declaration.content_id(),
                || discovery.declaration.canonical_bytes().len(),
            )?;
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                domain.content_id(),
                || discovery.domain.canonical_bytes().len(),
            )?;
            charge_choice_discovery_record(
                &mut charged_records,
                &mut charged_bytes,
                opportunity.content_id(),
                || discovery.opportunity.canonical_bytes().len(),
            )?;
        }
        if &discovered_ids != observation.discovered_choices() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate choice bodies differ from observation IDs",
            });
        }
        if !allow_recorded_selection_ids && !observation.produced_selections().is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate must carry produced selection bodies",
            });
        }
        Ok(Self {
            child,
            measurements,
            properties,
            coverage,
            discovered_choices,
            produced_selections: Vec::new(),
            choice_material_bytes: charged_bytes,
            observation,
            resolved_effect_trace: None,
        })
    }

    /// Attaches the exact bounded trace already named by the observation.
    ///
    /// Typed canonical validation belongs to the Crucible producer and reader;
    /// the campaign repository authenticates its opaque content identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the trace is oversized or its content identity
    /// differs from the observation's immutable reference.
    pub fn with_resolved_effect_trace(
        mut self,
        bytes: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        const MAX_TRACE_BYTES: usize = 64 * 1024 * 1024;
        if bytes.len() > MAX_TRACE_BYTES
            || self.observation.resolved_effect_trace()
                != Some(ContentId::for_bytes(ObjectKind::Trace, 1, &bytes))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate resolved-effect trace differs from observation",
            });
        }
        self.resolved_effect_trace = Some(bytes);
        Ok(self)
    }

    /// Attaches selections produced from discoveries during this execution.
    ///
    /// # Errors
    ///
    /// Returns an error after a nonempty attachment, for duplicate selections,
    /// when a `NextChoice` attachment resolves every discovered opportunity,
    /// for a selection without its exact discovered opportunity and domain,
    /// for invalid provenance, or for choice material beyond the observation
    /// count or aggregate-byte bound.
    pub fn with_produced_selections(
        self,
        selections: Vec<Selection>,
    ) -> Result<Self, CampaignCodecError> {
        self.attach_produced_selections(selections, true)
    }

    pub(super) fn attach_produced_selections(
        mut self,
        selections: Vec<Selection>,
        attach_to_observation: bool,
    ) -> Result<Self, CampaignCodecError> {
        if !self.produced_selections.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate already carries produced selections",
            });
        }
        if selections.len() > MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate has too many produced selections",
            });
        }
        let discoveries = self
            .discovered_choices
            .iter()
            .map(|discovery| {
                discovery
                    .opportunity()
                    .id()
                    .map(|opportunity| (opportunity, discovery))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut selection_ids = BTreeSet::new();
        let mut selected_opportunities = BTreeSet::new();
        for selection in &selections {
            if !selection_ids.insert(selection.id()?) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate contains duplicate produced selections",
                });
            }
            if !selected_opportunities.insert(selection.opportunity()) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate selects one discovered opportunity more than once",
                });
            }
            let discovery = discoveries.get(&selection.opportunity()).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "produced selection has no matching discovered opportunity",
                },
            )?;
            selection.validate_resolved_references(discovery.opportunity(), discovery.domain())?;
            self.choice_material_bytes = self
                .choice_material_bytes
                .checked_add(selection.canonical_bytes().len())
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "observation-choice-discovery-bytes",
                })?;
            if self.choice_material_bytes > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
                return Err(CampaignCodecError::LimitExceeded {
                    limit: "observation-choice-discovery-bytes",
                });
            }
        }
        if self.observation.stop().reached_next_choice()
            && discoveries
                .keys()
                .all(|opportunity| selected_opportunities.contains(opportunity))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "next-choice observation has no unresolved choice",
            });
        }
        if attach_to_observation {
            self.observation = self.observation.with_produced_selections(selection_ids)?;
        } else if self.observation.produced_selections() != &selection_ids {
            return Err(CampaignCodecError::InvalidValue {
                reason: "produced selection bodies differ from observation IDs",
            });
        }
        self.produced_selections = selections;
        Ok(self)
    }

    /// Returns the exact child configuration artifact.
    #[must_use]
    pub const fn child(&self) -> &ConfigurationArtifact {
        &self.child
    }

    /// Returns the exact modeled measurements.
    #[must_use]
    pub const fn measurements(&self) -> &MeasurementSet {
        &self.measurements
    }

    /// Returns the exact property verdicts.
    #[must_use]
    pub const fn properties(&self) -> &PropertyVerdictSet {
        &self.properties
    }

    /// Returns the exact coverage projection.
    #[must_use]
    pub const fn coverage(&self) -> &CoverageProjection {
        &self.coverage
    }

    /// Returns exact declaration/domain/opportunity records discovered by the
    /// execution.
    #[must_use]
    pub fn discovered_choices(&self) -> &[ChoiceDiscovery] {
        &self.discovered_choices
    }

    /// Returns selections produced while continuing through discovered choices.
    #[must_use]
    pub fn produced_selections(&self) -> &[Selection] {
        &self.produced_selections
    }

    /// Returns the canonical observation that binds every bundle member.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Returns the authenticated opaque trace bytes attached to this candidate.
    #[must_use]
    pub fn resolved_effect_trace(&self) -> Option<&[u8]> {
        self.resolved_effect_trace.as_deref()
    }
}
