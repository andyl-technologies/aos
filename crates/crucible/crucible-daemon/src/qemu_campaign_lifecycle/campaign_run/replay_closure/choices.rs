//! Replay choices for a validated schedule and their in-order cursor.
//!
//! A raw checkpoint's closure may omit selections its execution did not
//! discover; the cursor resolves each omitted one from the campaign store
//! when replay reaches it, so promotion never copies the whole schedule.

use crucible_campaign::{CampaignExecutorStore, Selection};
use crucible_engine::{Decision, ScenarioDefForm, Schedule};

use super::format::{Entry, invalid};
use super::reader::FrameReader;
use super::walk::RecordSet;
use super::{
    Coverage, GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    GuardedCampaignReplaySelection, selection_digest,
};

/// Replay choices for one validated schedule: a closure plus, for a raw
/// checkpoint, the campaign store that holds the selections it omits.
#[derive(Clone)]
pub(crate) struct GuardedCampaignReplayChoices {
    pub(super) owned: GuardedCampaignReplayClosure,
    pub(super) store: Option<CampaignExecutorStore>,
}

impl GuardedCampaignReplayChoices {
    /// Validates these choices again for exactly `schedule`.
    ///
    /// Selections the closure omits are resolved from the store again.
    ///
    /// # Errors
    ///
    /// Returns the errors of
    /// [`GuardedCampaignReplayClosure::validate_for_schedule`], or a
    /// repository error for an omitted selection.
    pub(crate) fn validate_for_schedule(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        let coverage = match &self.store {
            Some(store) => Coverage::Repository(store),
            None => Coverage::Complete,
        };
        self.owned.walk(scenario, schedule, coverage, |_, _| Ok(()))
    }

    /// Returns a cursor that serves decisions of `schedule` in order.
    pub(crate) fn cursor<'a>(&'a self, schedule: &'a Schedule) -> ReplayChoiceCursor<'a> {
        ReplayChoiceCursor {
            choices: self,
            schedule,
            reader: FrameReader::new(&self.owned),
            position: 0,
            next_entry: 0,
        }
    }
}

/// Sequential lookup of the records behind each schedule decision.
///
/// Ascending queries cost one pass over the schedule; a query before the
/// previous one restarts the walk.
pub(crate) struct ReplayChoiceCursor<'a> {
    choices: &'a GuardedCampaignReplayChoices,
    schedule: &'a Schedule,
    reader: FrameReader<'a>,
    position: usize,
    next_entry: u64,
}

impl ReplayChoiceCursor<'_> {
    /// Returns the authenticated choice record for one schedule decision.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is outside the schedule, a recorded
    /// selection cannot be decoded, or it is neither in the closure nor in
    /// the campaign store.
    pub(crate) fn selection_for_decision(
        &mut self,
        index: usize,
    ) -> Result<Option<GuardedCampaignReplaySelection>, GuardedCampaignReplayClosureError> {
        let history = self.schedule.decision_history();
        if index >= history.len() {
            return Err(invalid("replay decision index is outside the schedule"));
        }
        if index < self.position {
            self.position = 0;
            self.next_entry = 0;
        }
        while self.position < index {
            if let Some(Decision::Selection(decision)) = history.get(self.position)
                && self.next_owned(&decision.selection()?)?.is_some()
            {
                self.next_entry += 1;
            }
            self.position += 1;
        }

        self.position = index + 1;
        let Some(Decision::Selection(decision)) = history.get(index) else {
            return Ok(None);
        };
        let selection = decision.selection()?;
        if let Some(entry) = self.next_owned(&selection)? {
            self.next_entry += 1;
            let records = RecordSet::read(&mut self.reader, entry)?;
            let record = records.with_selection(selection);
            record.validate_references()?;
            return Ok(Some(record));
        }

        let store = self
            .choices
            .store
            .as_ref()
            .ok_or_else(|| invalid("replay closure is missing a schedule selection"))?;
        let record = GuardedCampaignReplaySelection::from_resolved(
            &store.resolve_selection(selection.id()?)?,
        );
        if record.selection != selection {
            return Err(invalid("resolved replay selection differs"));
        }
        Ok(Some(record))
    }

    fn next_owned(
        &mut self,
        selection: &Selection,
    ) -> Result<Option<Entry>, GuardedCampaignReplayClosureError> {
        if self.next_entry >= self.choices.owned.root.entry_count {
            return Ok(None);
        }
        let entry = self.reader.entry(self.next_entry)?;
        Ok((entry.selection == selection_digest(selection)?).then_some(entry))
    }
}
