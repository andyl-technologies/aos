//! Paged reads of an observation's discovered-choice and produced-selection sets.
//!
//! Both sets are Merkle maps keyed by [`choice_set_key`] of an opportunity, so
//! they share one ascending order. Readers walk them a page at a time; a full
//! walk also checks that the observed entry count equals the count the
//! observation commits to.

use super::*;

/// Entries read from one choice set per Merkle scan.
const CHOICE_SET_PAGE_ITEMS: usize = 1_024;

/// Forward cursor over one choice set, reading one bounded page at a time.
pub(in crate::repository) struct ChoiceSetCursor<'a> {
    merkle: &'a MerkleMap,
    root: MerkleMapRoot,
    page: std::vec::IntoIter<(CampaignHash, ContentId)>,
    after: Option<CampaignHash>,
    exhausted: bool,
    visited: u64,
}

impl<'a> ChoiceSetCursor<'a> {
    pub(in crate::repository) fn new(merkle: &'a MerkleMap, root: MerkleMapRoot) -> Self {
        Self {
            merkle,
            root,
            page: Vec::new().into_iter(),
            after: None,
            exhausted: root.is_empty(),
            visited: 0,
        }
    }

    /// Returns the next entry in ascending key order.
    ///
    /// Reaching the end checks the visited count against the committed count.
    pub(in crate::repository) fn next_entry(
        &mut self,
    ) -> Result<Option<(CampaignHash, ContentId)>, CampaignRepositoryError> {
        loop {
            if let Some(entry) = self.page.next() {
                self.visited = self
                    .visited
                    .checked_add(1)
                    .ok_or_else(|| integrity("observation-choice-set-count-mismatch"))?;
                return Ok(Some(entry));
            }
            if self.exhausted {
                if self.visited != self.root.entry_count() {
                    return Err(integrity("observation-choice-set-count-mismatch"));
                }
                return Ok(None);
            }

            let page =
                self.merkle
                    .scan(self.root.content_id(), self.after, CHOICE_SET_PAGE_ITEMS)?;
            self.after = page.next_after();
            self.exhausted = self.after.is_none();
            self.page = page.entries().to_vec().into_iter();
        }
    }
}

/// Iterator over one observation's discovered opportunities in identity order.
///
/// Entries are read from the observation's paged discovered-choice set one
/// bounded page at a time. The iterator yields an error, then ends, when a
/// page is unavailable or an entry or the final count disagrees with the
/// observation.
///
/// # Examples
///
/// ```no_run
/// # fn example(
/// #     repository: &crucible_campaign::CampaignRepository,
/// #     observation: &crucible_campaign::Observation,
/// # ) -> Result<(), crucible_campaign::CampaignRepositoryError> {
/// for opportunity in repository.discovered_choices(observation) {
///     let opportunity = repository.load_choice_opportunity(opportunity?)?;
///     println!("{}", opportunity.instance());
/// }
/// # Ok(())
/// # }
/// ```
pub struct DiscoveredChoices<'a> {
    cursor: ChoiceSetCursor<'a>,
    failed: bool,
}

impl Iterator for DiscoveredChoices<'_> {
    type Item = Result<ChoiceOpportunityId, CampaignRepositoryError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let entry = self.cursor.next_entry().and_then(|entry| {
            entry
                .map(|(key, value)| discovered_choice_entry(key, value))
                .transpose()
        });
        match entry {
            Ok(None) => None,
            Ok(Some(opportunity)) => Some(Ok(opportunity)),
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

/// Iterator over one observation's produced selections in selected-opportunity order.
///
/// Like [`DiscoveredChoices`], it reads one bounded page at a time and yields
/// an error, then ends, when the paged set disagrees with the observation.
pub struct ProducedSelections<'a> {
    cursor: ChoiceSetCursor<'a>,
    failed: bool,
}

impl Iterator for ProducedSelections<'_> {
    type Item = Result<SelectionId, CampaignRepositoryError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let entry = self.cursor.next_entry().and_then(|entry| {
            entry
                .map(|(_, value)| SelectionId::from_content_id(value).map_err(Into::into))
                .transpose()
        });
        match entry {
            Ok(None) => None,
            Ok(Some(selection)) => Some(Ok(selection)),
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

impl CampaignRepository {
    /// Returns an iterator over an observation's produced selections.
    #[must_use]
    pub fn produced_selections<'a>(&'a self, observation: &Observation) -> ProducedSelections<'a> {
        ProducedSelections {
            cursor: ChoiceSetCursor::new(&self.merkle, observation.produced_selections()),
            failed: false,
        }
    }

    /// Returns an iterator over an observation's discovered opportunities.
    ///
    /// The observation's discovered choices are a paged set rather than an
    /// in-record list, so reading them requires the repository holding its
    /// nodes.
    #[must_use]
    pub fn discovered_choices<'a>(&'a self, observation: &Observation) -> DiscoveredChoices<'a> {
        DiscoveredChoices {
            cursor: ChoiceSetCursor::new(&self.merkle, observation.discovered_choices()),
            failed: false,
        }
    }

    /// Builds both candidate choice sets in durable storage and checks their roots.
    ///
    /// The candidate holds discoveries and selections in canonical key order,
    /// so the sorted builder streams them and publishes only final nodes. The
    /// rebuilt roots must equal the ones the observation commits to.
    pub(in crate::repository) fn publish_candidate_choice_sets(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<(), CampaignRepositoryError> {
        let discovered = self.merkle.build_from_sorted(
            candidate
                .discovered_ids
                .iter()
                .map(|opportunity| (choice_set_key(*opportunity), opportunity.content_id())),
        )?;
        let produced_entries = candidate
            .produced_selections
            .iter()
            .map(|selection| {
                selection
                    .id()
                    .map(|id| (choice_set_key(selection.opportunity()), id.content_id()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let produced = self.merkle.build_from_sorted(produced_entries)?;

        let observation = candidate.observation();
        if discovered != observation.discovered_choices()
            || produced != observation.produced_selections()
        {
            return Err(integrity("observation-choice-set-publication-mismatch"));
        }
        Ok(())
    }

    /// Visits every discovered opportunity in ascending identity order.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or an integrity or store error
    /// for a set whose entries, keys, or count disagree with the observation.
    pub(in crate::repository) fn for_each_discovered_choice(
        &self,
        observation: &Observation,
        mut visit: impl FnMut(ChoiceOpportunityId) -> Result<(), CampaignRepositoryError>,
    ) -> Result<(), CampaignRepositoryError> {
        for opportunity in self.discovered_choices(observation) {
            visit(opportunity?)?;
        }
        Ok(())
    }

    /// Visits every produced selection with the key of the opportunity it selects.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or an integrity or store error
    /// for a set whose entries or count disagree with the observation.
    pub(in crate::repository) fn for_each_produced_selection(
        &self,
        observation: &Observation,
        mut visit: impl FnMut(CampaignHash, SelectionId) -> Result<(), CampaignRepositoryError>,
    ) -> Result<(), CampaignRepositoryError> {
        let mut cursor = ChoiceSetCursor::new(&self.merkle, observation.produced_selections());
        while let Some((key, value)) = cursor.next_entry()? {
            visit(key, SelectionId::from_content_id(value)?)?;
        }
        Ok(())
    }

    /// Returns whether the observation discovered `opportunity`.
    pub(in crate::repository) fn observation_discovers(
        &self,
        observation: &Observation,
        opportunity: ChoiceOpportunityId,
    ) -> Result<bool, CampaignRepositoryError> {
        Ok(self.merkle.get(
            observation.discovered_choices().content_id(),
            choice_set_key(opportunity),
        )? == Some(opportunity.content_id()))
    }

    /// Returns whether one evidence object belongs to the observation.
    ///
    /// The fixed envelope children belong directly. A choice opportunity
    /// belongs when the discovered set holds it, and a selection belongs when
    /// the produced set holds it under the opportunity it selects.
    pub(in crate::repository) fn observation_owns(
        &self,
        observation: &Observation,
        evidence: ContentId,
    ) -> Result<bool, CampaignRepositoryError> {
        if observation
            .content_children()
            .iter()
            .any(|(_, child)| *child == evidence)
        {
            return Ok(true);
        }
        if let Ok(opportunity) = ChoiceOpportunityId::from_content_id(evidence)
            && self.observation_discovers(observation, opportunity)?
        {
            return Ok(true);
        }
        let Ok(selection) = SelectionId::from_content_id(evidence) else {
            return Ok(false);
        };
        if !self.blobs.contains(selection.content_id())? {
            return Ok(false);
        }
        let envelope =
            self.require_record_kind(selection.content_id(), crate::CampaignRecordKind::Selection)?;
        let opportunity =
            ChoiceOpportunityId::from_content_id(required_child(&envelope, "opportunity")?)?;
        Ok(self.merkle.get(
            observation.produced_selections().content_id(),
            choice_set_key(opportunity),
        )? == Some(selection.content_id()))
    }
}

/// Converts one discovered-set entry to its opportunity, checking its key.
fn discovered_choice_entry(
    key: CampaignHash,
    value: ContentId,
) -> Result<ChoiceOpportunityId, CampaignRepositoryError> {
    let opportunity = ChoiceOpportunityId::from_content_id(value)?;
    if choice_set_key(opportunity) != key {
        return Err(integrity("observation-discovered-choice-key-mismatch"));
    }
    Ok(opportunity)
}
