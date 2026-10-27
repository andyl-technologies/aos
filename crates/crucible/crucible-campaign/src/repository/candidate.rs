//! Structural construction and bounded choice material for immutable executor candidates.

use super::*;

/// Largest resolved-effect trace manifest leaf a candidate may carry.
///
/// The manifest lists at most
/// [`MAX_MANIFEST_SEGMENTS`](crucible_store::segment_store::MAX_MANIFEST_SEGMENTS)
/// segment references, so its encoding stays far below this bound.
pub const MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES: usize = 1024 * 1024;

/// Content of the segmented resolved-effect trace attached to a candidate.
///
/// The manifest bytes travel with the candidate; segments stay in the
/// producer's stores and are streamed one at a time during publication, so a
/// candidate's size does not grow with the trace. Two values are equal when
/// their manifests are: the observation names every segment by identity, and
/// publication authenticates each one.
#[derive(Clone, Debug)]
pub(super) struct ResolvedEffectTraceContent {
    manifest: Vec<u8>,
    segments: SegmentSources,
}

impl PartialEq for ResolvedEffectTraceContent {
    fn eq(&self, other: &Self) -> bool {
        self.manifest == other.manifest
    }
}

impl Eq for ResolvedEffectTraceContent {}

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
    /// Discoveries are held in canonical opportunity-identity order, which is
    /// also the key order of the observation's paged discovered-choice set.
    ///
    /// # Errors
    ///
    /// Returns an error when discovered records exceed the aggregate-byte
    /// bound, contain duplicate opportunity IDs, disagree with one another, or
    /// do not exactly derive the observation's discovered-choice root.
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
    /// when the recorded selection bodies do not exactly derive the
    /// observation's produced-selection root.
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
        let mut identified = discovered_choices
            .into_iter()
            .map(|discovery| {
                discovery
                    .opportunity
                    .id()
                    .map(|opportunity| (opportunity, discovery))
            })
            .collect::<Result<Vec<_>, _>>()?;
        identified.sort_unstable_by_key(|(opportunity, _)| *opportunity);
        if identified.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate contains duplicate choice opportunities",
            });
        }

        let mut shared_declarations: BTreeMap<SelectableId, Arc<SelectableDeclaration>> =
            BTreeMap::new();
        let mut shared_domains: BTreeMap<ChoiceDomainId, Arc<ChoiceDomain>> = BTreeMap::new();
        let mut validated_contracts = BTreeMap::new();
        let mut charged_records = BTreeSet::new();
        let mut charged_bytes = 0usize;
        for (opportunity, discovery) in &mut identified {
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

        let (discovered_ids, discovered_choices): (Vec<_>, Vec<_>) = identified.into_iter().unzip();
        let discovered_root = crate::observation::derive_choice_set_root(
            discovered_ids
                .iter()
                .map(|opportunity| (choice_set_key(*opportunity), opportunity.content_id())),
        )?;
        if discovered_root != observation.discovered_choices() {
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
            discovered_ids,
            discovered_choices,
            produced_selections: Vec::new(),
            choice_material_bytes: charged_bytes,
            observation,
            resolved_effect_trace: None,
        })
    }

    /// Attaches the segmented trace already named by the observation.
    ///
    /// `manifest` is the trace's opaque manifest leaf and `segments` reads the
    /// segments the observation lists. Typed canonical validation belongs to
    /// the Crucible producer and reader; the campaign repository authenticates
    /// the manifest's content identity here and each segment's identity when
    /// it streams the segment during publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation names no trace, the manifest
    /// exceeds [`MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES`], or its content
    /// identity differs from the observation's manifest reference.
    pub fn with_resolved_effect_trace(
        mut self,
        manifest: Vec<u8>,
        segments: SegmentSources,
    ) -> Result<Self, CampaignCodecError> {
        let expected = self
            .observation
            .resolved_effect_trace()
            .map(ResolvedEffectTraceRef::manifest);
        if manifest.len() > MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES
            || expected
                != Some(ContentId::for_bytes(
                    ObjectKind::Trace,
                    crate::observation::RESOLVED_EFFECT_TRACE_MANIFEST_SCHEMA,
                    &manifest,
                ))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation candidate resolved-effect trace differs from observation",
            });
        }
        self.resolved_effect_trace = Some(ResolvedEffectTraceContent { manifest, segments });
        Ok(self)
    }

    /// Attaches selections produced from discoveries during this execution.
    ///
    /// Selections are held in the key order of the observation's paged
    /// produced-selection set: ascending selected-opportunity identity.
    ///
    /// # Errors
    ///
    /// Returns an error after a nonempty attachment, for duplicate selections,
    /// when a `NextChoice` attachment resolves every discovered opportunity,
    /// for a selection without its exact discovered opportunity and domain,
    /// for invalid provenance, or for choice material beyond the aggregate-byte
    /// bound.
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

        let mut keyed = BTreeMap::new();
        let mut selection_ids = BTreeSet::new();
        for selection in selections {
            let selection_id = selection.id()?;
            if !selection_ids.insert(selection_id) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate contains duplicate produced selections",
                });
            }
            if keyed
                .insert(selection.opportunity(), (selection_id, selection))
                .is_some()
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "observation candidate selects one discovered opportunity more than once",
                });
            }
        }
        for (opportunity, (_, selection)) in &keyed {
            let discovery =
                self.discovery(*opportunity)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "produced selection has no matching discovered opportunity",
                    })?;
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
        // Every key names a distinct discovered opportunity, so equal counts
        // mean the attachment resolved every discovery.
        if self.observation.stop().reached_next_choice()
            && keyed.len() == self.discovered_choices.len()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "next-choice observation has no unresolved choice",
            });
        }

        let produced = keyed
            .iter()
            .map(|(opportunity, (selection, _))| (*opportunity, *selection))
            .collect::<BTreeMap<_, _>>();
        if attach_to_observation {
            self.observation = self.observation.with_produced_selections(produced)?;
        } else {
            let produced_root = crate::observation::derive_choice_set_root(produced.iter().map(
                |(opportunity, selection)| (choice_set_key(*opportunity), selection.content_id()),
            ))?;
            if self.observation.produced_selections() != produced_root {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "produced selection bodies differ from observation IDs",
                });
            }
        }
        self.produced_selections = keyed
            .into_values()
            .map(|(_, selection)| selection)
            .collect();
        Ok(self)
    }

    /// Finds one carried discovery by its opportunity identity.
    ///
    /// Discoveries are sorted by identity at construction, so this is a binary
    /// search over the parallel identity list rather than a second index.
    pub(super) fn discovery(&self, opportunity: ChoiceOpportunityId) -> Option<&ChoiceDiscovery> {
        self.discovered_ids
            .binary_search(&opportunity)
            .ok()
            .and_then(|index| self.discovered_choices.get(index))
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
    /// execution, in ascending opportunity-identity order.
    #[must_use]
    pub fn discovered_choices(&self) -> &[ChoiceDiscovery] {
        &self.discovered_choices
    }

    /// Returns selections produced while continuing through discovered choices,
    /// in ascending selected-opportunity order.
    #[must_use]
    pub fn produced_selections(&self) -> &[Selection] {
        &self.produced_selections
    }

    /// Returns the identities of the carried discoveries, in the same order as
    /// [`Self::discovered_choices`].
    #[must_use]
    pub fn discovered_opportunities(&self) -> &[ChoiceOpportunityId] {
        &self.discovered_ids
    }

    /// Returns whether the candidate carries a discovery of `opportunity`.
    #[must_use]
    pub fn discovers(&self, opportunity: ChoiceOpportunityId) -> bool {
        self.discovered_ids.binary_search(&opportunity).is_ok()
    }

    /// Returns whether `id` names a discovered opportunity or produced selection.
    ///
    /// These are the choice records the observation owns through its paged
    /// sets rather than as direct envelope children.
    ///
    /// # Errors
    ///
    /// Returns an error when a produced selection identity cannot be derived.
    pub fn carries_choice_record(&self, id: ContentId) -> Result<bool, CampaignCodecError> {
        if self
            .discovered_ids
            .binary_search_by(|opportunity| opportunity.content_id().cmp(&id))
            .is_ok()
        {
            return Ok(true);
        }
        for selection in &self.produced_selections {
            if selection.id()?.content_id() == id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the canonical observation that binds every bundle member.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Returns the authenticated opaque trace manifest attached to this
    /// candidate.
    ///
    /// The segment identities are listed by the observation's
    /// [`ResolvedEffectTraceRef`].
    #[must_use]
    pub fn resolved_effect_trace_manifest(&self) -> Option<&[u8]> {
        self.resolved_effect_trace
            .as_ref()
            .map(|trace| trace.manifest.as_slice())
    }

    /// Returns read handles to the stores holding the trace's segments.
    #[must_use]
    pub fn resolved_effect_trace_segments(&self) -> Option<&SegmentSources> {
        self.resolved_effect_trace
            .as_ref()
            .map(|trace| &trace.segments)
    }

    /// Reads the attached trace's segments from `segments` instead.
    ///
    /// A producer that copies the segments into its own staging store rebinds
    /// the candidate to that store; the manifest and the observation's segment
    /// list are unchanged, and publication still authenticates each segment.
    /// A candidate without a trace is returned unchanged.
    #[must_use]
    pub fn with_resolved_effect_trace_segments(mut self, segments: SegmentSources) -> Self {
        if let Some(trace) = self.resolved_effect_trace.as_mut() {
            trace.segments = segments;
        }
        self
    }
}
