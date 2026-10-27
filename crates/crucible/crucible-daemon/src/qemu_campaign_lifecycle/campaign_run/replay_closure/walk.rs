//! Canonical-form and provenance checks applied while walking a closure.
//!
//! A decoded closure is proven canonical by re-encoding the entries a walk
//! consumes and comparing the resulting root with the stored one; each
//! resolved record is then checked against its scenario and schedule.

use std::sync::Arc;

use crucible_engine::{Configuration, ConfigurationPrefix, ScenarioDefForm, Schedule};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceDomain, ChoiceOpportunity, ChoiceSource,
    SelectableDeclaration, Selection, SelectionOrigin,
};
use crucible_store::content_store::ContentId;

use super::builder::{ClosureBuilder, FrameRetention};
use super::format::{ClosureRoot, Entry, RecordKind, invalid};
use super::reader::FrameReader;
use super::{GuardedCampaignReplayClosureError, GuardedCampaignReplaySelection};

/// Which of an entry's records it references first.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct FreshRecords {
    pub(super) domain: bool,
    pub(super) declaration: bool,
    pub(super) opportunity: bool,
}

/// One entry's decoded records.
pub(super) struct RecordSet {
    pub(super) domain: Arc<ChoiceDomain>,
    pub(super) declaration: Arc<SelectableDeclaration>,
    pub(super) opportunity: ChoiceOpportunity,
    pub(super) fresh: FreshRecords,
}

impl RecordSet {
    pub(super) fn read(
        reader: &mut FrameReader<'_>,
        entry: Entry,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        Ok(Self {
            domain: reader.domain(entry.domain)?,
            declaration: reader.declaration(entry.declaration)?,
            opportunity: reader.opportunity(entry.opportunity)?,
            fresh: FreshRecords::default(),
        })
    }

    pub(super) fn with_selection(self, selection: Selection) -> GuardedCampaignReplaySelection {
        GuardedCampaignReplaySelection {
            domain: self.domain,
            declaration: self.declaration,
            opportunity: self.opportunity,
            selection,
        }
    }
}

/// Re-encodes consumed entries to prove a decoded closure canonical.
///
/// A record must be introduced at exactly the next ordinal and never twice;
/// earlier ordinals are references. Matching the re-encoded root then also
/// proves frame packing.
pub(super) struct CanonicalWalk {
    builder: ClosureBuilder,
}

impl CanonicalWalk {
    pub(super) fn new() -> Self {
        Self {
            builder: ClosureBuilder::new(FrameRetention::DigestOnly),
        }
    }

    pub(super) fn resolve(
        &mut self,
        reader: &mut FrameReader<'_>,
        entry: Entry,
    ) -> Result<RecordSet, GuardedCampaignReplayClosureError> {
        let mut records = RecordSet::read(reader, entry)?;
        records.fresh = FreshRecords {
            domain: self.introduce(reader, RecordKind::Domain, entry.domain, || {
                Ok(records.domain.id()?.content_id())
            })?,
            declaration: self.introduce(
                reader,
                RecordKind::Declaration,
                entry.declaration,
                || Ok(records.declaration.id()?.content_id()),
            )?,
            opportunity: self.introduce(
                reader,
                RecordKind::Opportunity,
                entry.opportunity,
                || Ok(records.opportunity.id()?.content_id()),
            )?,
        };
        self.builder.entry(entry)?;
        Ok(records)
    }

    /// Appends a record when `ordinal` introduces it; returns whether it did.
    fn introduce(
        &mut self,
        reader: &mut FrameReader<'_>,
        kind: RecordKind,
        ordinal: u64,
        id: impl FnOnce() -> Result<ContentId, CampaignCodecError>,
    ) -> Result<bool, GuardedCampaignReplayClosureError> {
        match ordinal.cmp(&self.builder.next_record()) {
            std::cmp::Ordering::Less => Ok(false),
            std::cmp::Ordering::Equal => {
                let (bytes, range) = reader.record_bytes(kind, ordinal)?;
                self.builder
                    .append_new(kind, id()?.digest(), &bytes[range])?;
                Ok(true)
            }
            std::cmp::Ordering::Greater => Err(invalid(
                "replay closure references a record before introducing it",
            )),
        }
    }

    pub(super) fn finish(
        self,
        root: &ClosureRoot,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        let (canonical, _) = self.builder.finish()?;
        if canonical.bytes != root.bytes {
            return Err(invalid("replay closure is not canonically encoded"));
        }
        Ok(())
    }
}

/// Scenario and branch provenance checks for one schedule.
pub(super) struct Provenance<'a> {
    scenario: &'a ScenarioDefForm,
    scenario_id: crucible_campaign::ScenarioDefId,
    configuration: Configuration,
}

impl<'a> Provenance<'a> {
    pub(super) fn new(scenario: &'a ScenarioDefForm, schedule: &Schedule) -> Self {
        Self {
            scenario,
            scenario_id: crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(
                scenario.id().bytes,
            )),
            // Schedules share their storage, so this clone is constant-time.
            configuration: Configuration {
                def: scenario.scenario_def(),
                schedule: schedule.clone(),
            },
        }
    }

    pub(super) fn validate(
        &self,
        index: usize,
        record: &GuardedCampaignReplaySelection,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        let selection = &record.selection;
        if record.opportunity.scenario() != self.scenario_id {
            return Err(invalid(
                "replay selection record differs from its schedule or scenario",
            ));
        }
        // Model-sampled app-random choices use the white-box doorbell rather
        // than the guest selectable catalog; their provenance is checked below.
        if matches!(record.opportunity.source(), ChoiceSource::Guest { .. })
            && !matches!(selection.origin(), SelectionOrigin::ModelSample(_))
            && self
                .scenario
                .selectables()
                .declaration(record.declaration.name())
                != Some(&*record.declaration)
        {
            return Err(invalid(
                "guest replay choice is not declared by its scenario",
            ));
        }

        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(&record.opportunity, &record.domain)?;
            }
            SelectionOrigin::CampaignBranch { .. } => {
                // The parent is an identified prefix of the shared schedule,
                // so no prefix is copied.
                let parent = ConfigurationPrefix::new(&self.configuration, index)?;
                let parent = crucible_campaign::ConfigurationId::from_hash(
                    CampaignHash::from_bytes(parent.id().bytes),
                );
                selection.validate_branch_replay(
                    &record.opportunity,
                    &record.domain,
                    record.opportunity.branch_point_id(parent),
                )?;
            }
            SelectionOrigin::ModelSample(_) => {
                crucible_engine::validate_app_random_model_selection(
                    selection,
                    &record.declaration,
                    &record.opportunity,
                    &record.domain,
                )
                .map_err(|_| invalid("replay closure has unverified model-sample provenance"))?;
            }
        }
        Ok(())
    }
}
