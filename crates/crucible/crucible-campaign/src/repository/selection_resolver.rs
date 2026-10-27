//! Streamed selection resolution with bounded dependency caches.
//!
//! A [`SelectionResolver`] authenticates one selection at a time: the selection
//! record, the opportunity it names, and that opportunity's declaration and
//! domain. Callers fold over the results instead of collecting a batch, so the
//! number of selections one configuration or observation names is not bounded
//! by resolution.
//!
//! Declarations and domains are typically shared by many opportunities, so
//! the resolver keeps decoded copies in caches whose canonical bytes are
//! bounded. A cache miss re-reads and re-authenticates the record, so the
//! bound affects only cost, never results. A resolver with a caller-supplied
//! resident limit also charges the current selection's uncached records
//! against that limit, and empties its caches before it reports the limit as
//! exceeded.

use super::*;

/// Canonical bytes of decoded declarations and domains one resolver retains.
const SELECTION_RESOLUTION_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// One authenticated dependency kept for later selections.
struct CachedRecord<T> {
    value: Arc<T>,
    canonical_bytes: usize,
}

/// Pull-based selection resolver with bounded shared dependency caches.
///
/// Each [`resolve`](Self::resolve) call returns one fully authenticated
/// [`ResolvedSelection`]. The resolver holds no per-selection state between
/// calls beyond its declaration and domain caches.
///
/// # Examples
///
/// ```no_run
/// # fn example(
/// #     store: &crucible_campaign::CampaignExecutorStore,
/// #     ids: &[crucible_campaign::SelectionId],
/// # ) -> Result<(), crucible_campaign::CampaignRepositoryError> {
/// let mut resolver = store.selection_resolver();
/// for id in ids {
///     let resolved = resolver.resolve(*id)?;
///     assert_eq!(resolved.selection().id()?, *id);
/// }
/// # Ok(())
/// # }
/// ```
pub struct SelectionResolver<'a> {
    repository: &'a CampaignRepository,
    owned: Option<OwnedSelections<'a>>,
    maximum_resident_bytes: Option<usize>,
    cache_budget: usize,
    declarations: BTreeMap<ContentId, CachedRecord<SelectableDeclaration>>,
    domains: BTreeMap<ContentId, CachedRecord<ChoiceDomain>>,
    cached_bytes: usize,
}

/// Selections carried by one unpublished observation candidate.
struct OwnedSelections<'a> {
    candidate: &'a ObservationCandidate,
    positions: BTreeMap<SelectionId, usize>,
}

/// Resident canonical bytes charged while resolving one selection.
#[derive(Default)]
struct StepCharge {
    // Records decoded for this selection and not (yet) retained by a cache.
    decoded: usize,
    // Cache entries this selection already uses; they stay resident even if
    // the caches are emptied before the selection completes.
    cache_hits: usize,
}

impl<'a> SelectionResolver<'a> {
    pub(super) fn new(repository: &'a CampaignRepository) -> Self {
        Self {
            repository,
            owned: None,
            maximum_resident_bytes: None,
            cache_budget: SELECTION_RESOLUTION_CACHE_BYTES,
            declarations: BTreeMap::new(),
            domains: BTreeMap::new(),
            cached_bytes: 0,
        }
    }

    pub(super) fn within(
        repository: &'a CampaignRepository,
        maximum_resident_bytes: usize,
    ) -> Self {
        Self {
            maximum_resident_bytes: Some(maximum_resident_bytes),
            cache_budget: SELECTION_RESOLUTION_CACHE_BYTES.min(maximum_resident_bytes),
            ..Self::new(repository)
        }
    }

    pub(super) fn with_owned_candidate(
        repository: &'a CampaignRepository,
        candidate: &'a ObservationCandidate,
    ) -> Result<Self, CampaignRepositoryError> {
        let positions = candidate
            .produced_selections
            .iter()
            .enumerate()
            .map(|(position, selection)| selection.id().map(|id| (id, position)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Self {
            owned: Some(OwnedSelections {
                candidate,
                positions,
            }),
            ..Self::new(repository)
        })
    }

    /// Authenticates one selection with its opportunity, declaration, and domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::SelectionResolutionBudgetExceeded`]
    /// when this resolver has a resident limit and one selection's records
    /// exceed it with every cache emptied. Otherwise returns a store, codec,
    /// or integrity error for a missing, corrupt, or inconsistent record.
    pub fn resolve(
        &mut self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        if let Some(resolved) = self.resolve_owned(id)? {
            return Ok(resolved);
        }

        let mut charge = StepCharge::default();
        let selection_envelope = self.read_record(
            id.content_id(),
            crate::CampaignRecordKind::Selection,
            &mut charge,
        )?;
        let selection = Selection::from_canonical_bytes(selection_envelope.body())?;
        if selection.id()? != id {
            return Err(integrity("selection-envelope-shape"));
        }

        let opportunity_id = required_child(&selection_envelope, "opportunity")?;
        let selection_domain_id = required_child(&selection_envelope, "domain")?;
        let opportunity_envelope = self.read_record(
            opportunity_id,
            crate::CampaignRecordKind::ChoiceOpportunity,
            &mut charge,
        )?;
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(opportunity_envelope.body())?;
        if opportunity.id()?.content_id() != opportunity_id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }

        let declaration = self.declaration(opportunity.declaration().content_id(), &mut charge)?;
        let domain_id = opportunity.domain().content_id();
        if domain_id != selection_domain_id {
            return Err(integrity("selection-envelope-domain-mismatch"));
        }
        let domain = self.domain(domain_id, &mut charge)?;

        opportunity.validate_references(&declaration, &domain)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(ResolvedSelection {
            selection,
            opportunity: Arc::new(opportunity),
            declaration,
            domain,
        })
    }

    /// Resolves a selection carried by the owned candidate, if any.
    ///
    /// The candidate's constructor already authenticated the selection against
    /// its exact discovery; this repeats the provenance check on the shared
    /// records it hands out.
    fn resolve_owned(
        &self,
        id: SelectionId,
    ) -> Result<Option<ResolvedSelection>, CampaignRepositoryError> {
        let Some(owned) = &self.owned else {
            return Ok(None);
        };
        let Some(selection) = owned
            .positions
            .get(&id)
            .and_then(|position| owned.candidate.produced_selections.get(*position))
        else {
            return Ok(None);
        };
        let discovery = owned
            .candidate
            .discovery(selection.opportunity())
            .ok_or_else(|| integrity("owned-candidate-selection-opportunity-missing"))?;
        selection.validate_resolved_references(&discovery.opportunity, &discovery.domain)?;
        Ok(Some(ResolvedSelection {
            selection: selection.clone(),
            opportunity: Arc::new(discovery.opportunity.clone()),
            declaration: Arc::clone(&discovery.declaration),
            domain: Arc::clone(&discovery.domain),
        }))
    }

    fn declaration(
        &mut self,
        id: ContentId,
        charge: &mut StepCharge,
    ) -> Result<Arc<SelectableDeclaration>, CampaignRepositoryError> {
        if let Some(cached) = self.declarations.get(&id) {
            charge.cache_hits = charge.cache_hits.saturating_add(cached.canonical_bytes);
            return Ok(Arc::clone(&cached.value));
        }
        let (envelope, canonical_bytes) =
            self.read_record_sized(id, crate::CampaignRecordKind::SelectableDeclaration, charge)?;
        let declaration = SelectableDeclaration::from_canonical_bytes(envelope.body())?;
        if declaration.id()?.content_id() != id {
            return Err(integrity("selectable-envelope-shape"));
        }
        let declaration = Arc::new(declaration);
        if self.retain(canonical_bytes, charge) {
            self.declarations.insert(
                id,
                CachedRecord {
                    value: Arc::clone(&declaration),
                    canonical_bytes,
                },
            );
        }
        Ok(declaration)
    }

    fn domain(
        &mut self,
        id: ContentId,
        charge: &mut StepCharge,
    ) -> Result<Arc<ChoiceDomain>, CampaignRepositoryError> {
        if let Some(cached) = self.domains.get(&id) {
            charge.cache_hits = charge.cache_hits.saturating_add(cached.canonical_bytes);
            return Ok(Arc::clone(&cached.value));
        }
        let (envelope, canonical_bytes) =
            self.read_record_sized(id, crate::CampaignRecordKind::ChoiceDomain, charge)?;
        let domain = ChoiceDomain::from_canonical_bytes(envelope.body())?;
        if domain.id()?.content_id() != id {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        let domain = Arc::new(domain);
        if self.retain(canonical_bytes, charge) {
            self.domains.insert(
                id,
                CachedRecord {
                    value: Arc::clone(&domain),
                    canonical_bytes,
                },
            );
        }
        Ok(domain)
    }

    /// Moves one just-decoded record from the step charge into the caches.
    ///
    /// The record was already charged as resident, so retaining it never
    /// raises the resident total; it only has to fit the cache budget.
    fn retain(&mut self, canonical_bytes: usize, charge: &mut StepCharge) -> bool {
        let Some(cached) = self.cached_bytes.checked_add(canonical_bytes) else {
            return false;
        };
        if cached > self.cache_budget {
            return false;
        }
        self.cached_bytes = cached;
        charge.decoded = charge.decoded.saturating_sub(canonical_bytes);
        charge.cache_hits = charge.cache_hits.saturating_add(canonical_bytes);
        true
    }

    fn read_record(
        &mut self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
        charge: &mut StepCharge,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        self.read_record_sized(id, expected, charge)
            .map(|(envelope, _)| envelope)
    }

    /// Reads one record within the resident limit, emptying caches once if needed.
    fn read_record_sized(
        &mut self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
        charge: &mut StepCharge,
    ) -> Result<(ObjectEnvelope, usize), CampaignRepositoryError> {
        let Some(maximum) = self.maximum_resident_bytes else {
            let (envelope, bytes) = self
                .repository
                .require_record_kind_with_canonical_byte_limit(
                    id,
                    expected,
                    usize::MAX,
                    usize::MAX,
                )?;
            charge.decoded = charge.decoded.saturating_add(bytes);
            return Ok((envelope, bytes));
        };

        let repository = self.repository;
        let read = |resident: usize| {
            repository.require_record_kind_with_canonical_byte_limit(
                id,
                expected,
                maximum.saturating_sub(resident),
                maximum,
            )
        };
        let resident = self.resident_bytes(charge);
        let (envelope, bytes) = match read(resident) {
            Err(CampaignRepositoryError::SelectionResolutionBudgetExceeded { .. })
                if self.cached_bytes > 0 =>
            {
                self.clear_caches(charge);
                read(self.resident_bytes(charge))?
            }
            result => result?,
        };
        charge.decoded = charge.decoded.saturating_add(bytes);
        Ok((envelope, bytes))
    }

    fn resident_bytes(&self, charge: &StepCharge) -> usize {
        self.cached_bytes.saturating_add(charge.decoded)
    }

    /// Empties both caches while keeping entries this selection still uses charged.
    fn clear_caches(&mut self, charge: &mut StepCharge) {
        self.declarations.clear();
        self.domains.clear();
        self.cached_bytes = 0;
        charge.decoded = charge.decoded.saturating_add(charge.cache_hits);
        charge.cache_hits = 0;
    }
}

impl CampaignRepository {
    /// Starts a streamed selection resolver over this repository.
    #[must_use]
    pub fn selection_resolver(&self) -> SelectionResolver<'_> {
        SelectionResolver::new(self)
    }

    /// Loads a selection with the opportunity and domain needed to trust it.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing/corrupt records,
    /// illegal values, or invalid self-contained provenance. Model samples
    /// still require their pure model verifier before execution.
    pub fn resolve_selection(
        &self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        self.selection_resolver().resolve(id)
    }

    /// Visits one exact duplicate-free selection list in order.
    ///
    /// This stricter form is intended for immutable configuration admission,
    /// where a repeated selection identity would make the schedule-to-record
    /// correspondence ambiguous. Every identity is checked for repetition
    /// before the first record is read.
    ///
    /// # Errors
    ///
    /// Returns an integrity error for repeated input identities, the first
    /// error returned by `visit`, or the store, codec, or dependency error
    /// produced while authenticating a record.
    pub fn for_each_resolved_distinct_selection<E>(
        &self,
        ids: &[SelectionId],
        mut visit: impl FnMut(ResolvedSelection) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        let mut distinct = BTreeSet::new();
        if !ids.iter().all(|id| distinct.insert(*id)) {
            return Err(integrity("configuration-selection-identity-repeated").into());
        }
        drop(distinct);

        let mut resolver = self.selection_resolver();
        for id in ids {
            visit(resolver.resolve(*id)?)?;
        }
        Ok(())
    }
}
