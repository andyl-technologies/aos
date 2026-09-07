//! Authenticated choice records needed to replay a selected campaign schedule.
//!
//! The bounded canonical binary layout is:
//!
//! ```text
//! magic:          8 bytes, "CCRC\0\0\0\x01"
//! selection_count: u32 little-endian
//! selections:     selection_count repetitions of:
//!   domain:       u32 little-endian byte length, canonical ChoiceDomain bytes
//!   declaration:  u32 little-endian byte length, canonical SelectableDeclaration bytes
//!   opportunity:  u32 little-endian byte length, canonical ChoiceOpportunity bytes
//!   selection:    u32 little-endian byte length, canonical Selection bytes
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crucible::{Configuration, Decision, ScenarioDefForm, Schedule};
#[cfg(test)]
use crucible_campaign::ChoiceValue;
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, CampaignRepository,
    CampaignRepositoryError, ChoiceDomain, ChoiceOpportunity, SelectableDeclaration, Selection,
    SelectionId, SelectionOrigin,
};
use thiserror::Error;

const REPLAY_CLOSURE_MAGIC: &[u8; 8] = b"CCRC\0\0\0\x01";
const MAX_REPLAY_CLOSURE_SELECTIONS: usize = 65_536;
const MAX_REPLAY_CLOSURE_BYTES: usize = 128 * 1024 * 1024;

/// A bounded canonical set of records needed to authenticate schedule selections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignReplayClosure {
    selections: Vec<GuardedCampaignReplaySelection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GuardedCampaignReplaySelection {
    domain: ChoiceDomain,
    declaration: SelectableDeclaration,
    opportunity: ChoiceOpportunity,
    selection: Selection,
}

impl GuardedCampaignReplayClosure {
    pub(super) fn collect(
        store: &CampaignExecutorStore,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let selection_ids = schedule_selection_ids(schedule)?;
        let mut records = Vec::new();
        records
            .try_reserve(selection_ids.len())
            .map_err(GuardedCampaignReplayClosureError::Allocation)?;
        let mut encoded_bytes = REPLAY_CLOSURE_MAGIC.len() + std::mem::size_of::<u32>();

        // A single selection can reference a 32 MiB domain. Singleton loads
        // keep the repository's independent 128 MiB resolution cap meaningful.
        for selection in selection_ids {
            let resolved = store.resolve_selection(selection)?;
            charge_resolved_selection(&mut encoded_bytes, &resolved)?;
            records.push(GuardedCampaignReplaySelection {
                domain: resolved.domain().clone(),
                declaration: resolved.declaration().clone(),
                opportunity: resolved.opportunity().clone(),
                selection: resolved.selection().clone(),
            });
        }

        let closure = Self::new(records)?;
        closure.validate_for_schedule(scenario, schedule)?;
        Ok(closure)
    }

    fn new(
        records: Vec<GuardedCampaignReplaySelection>,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        if records.len() > MAX_REPLAY_CLOSURE_SELECTIONS {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "selection count exceeds the replay-closure bound",
            });
        }

        let mut by_selection = BTreeMap::new();
        for record in records {
            record.validate_references()?;
            let selection = record.selection.id()?;
            if by_selection.insert(selection, record).is_some() {
                return Err(GuardedCampaignReplayClosureError::Invalid {
                    reason: "replay closure contains a duplicate selection",
                });
            }
        }
        Ok(Self {
            selections: by_selection.into_values().collect(),
        })
    }

    #[cfg(test)]
    pub(super) fn with_alternate_boolean_branch_selection(
        &self,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let mut records = self.selections.clone();
        let record = records
            .first_mut()
            .ok_or(GuardedCampaignReplayClosureError::Invalid {
                reason: "test replay closure has no selection",
            })?;
        let ChoiceValue::Boolean(selected) = record.selection.value() else {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "test replay closure selection is not boolean",
            });
        };
        let SelectionOrigin::CampaignBranch { branch_point, .. } = record.selection.origin() else {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "test replay closure selection is not a campaign branch",
            });
        };
        record.selection = Selection::new_campaign_branch(
            &record.opportunity,
            &record.domain,
            ChoiceValue::Boolean(!selected),
            branch_point,
        )?;
        Self::new(records)
    }

    /// Encodes the closure in canonical selection-identity order.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] when a record or the
    /// aggregate encoded closure exceeds its fixed bound.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, GuardedCampaignReplayClosureError> {
        let count = u32::try_from(self.selections.len()).map_err(|_| {
            GuardedCampaignReplayClosureError::Invalid {
                reason: "selection count cannot be represented",
            }
        })?;
        let mut bytes = Vec::from(REPLAY_CLOSURE_MAGIC.as_slice());
        append_bytes(&mut bytes, &count.to_le_bytes())?;
        for record in &self.selections {
            append_record(&mut bytes, &record.domain.canonical_bytes())?;
            append_record(&mut bytes, &record.declaration.canonical_bytes())?;
            append_record(&mut bytes, &record.opportunity.canonical_bytes())?;
            append_record(&mut bytes, &record.selection.canonical_bytes())?;
        }
        Ok(bytes)
    }

    /// Decodes and authenticates one canonical replay closure.
    ///
    /// The decoded records remain unusable until
    /// [`Self::validate_for_schedule`] proves exact coverage for a scenario and
    /// schedule.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] for a malformed,
    /// noncanonical, duplicate, oversized, or internally inconsistent closure.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GuardedCampaignReplayClosureError> {
        if bytes.len() > MAX_REPLAY_CLOSURE_BYTES {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure exceeds its encoded byte bound",
            });
        }
        let mut decoder = ReplayClosureDecoder::new(bytes)?;
        let count = decoder.read_u32()? as usize;
        if count > MAX_REPLAY_CLOSURE_SELECTIONS {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "selection count exceeds the replay-closure bound",
            });
        }
        let mut records = Vec::new();
        records
            .try_reserve(count)
            .map_err(GuardedCampaignReplayClosureError::Allocation)?;
        for _ in 0..count {
            records.push(GuardedCampaignReplaySelection {
                domain: ChoiceDomain::from_canonical_bytes(decoder.read_record()?)?,
                declaration: SelectableDeclaration::from_canonical_bytes(decoder.read_record()?)?,
                opportunity: ChoiceOpportunity::from_canonical_bytes(decoder.read_record()?)?,
                selection: Selection::from_canonical_bytes(decoder.read_record()?)?,
            });
        }
        decoder.finish()?;

        let closure = Self::new(records)?;
        if closure.to_canonical_bytes()?.as_slice() != bytes {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure is not canonically ordered",
            });
        }
        Ok(closure)
    }

    /// Validates exact record coverage and provenance for a selected schedule.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] when any schedule
    /// selection is missing, any closure selection is unused, or exact
    /// scenario, domain, default, model, or branch provenance differs.
    pub fn validate_for_schedule(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        let scenario_id = crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(
            scenario.id().bytes,
        ));
        let records = self
            .selections
            .iter()
            .map(|record| Ok((record.selection.id()?, record)))
            .collect::<Result<BTreeMap<_, _>, GuardedCampaignReplayClosureError>>()?;
        let mut used = BTreeSet::new();

        for (index, decision) in schedule.decisions().iter().enumerate() {
            let Decision::Selection(decision) = decision else {
                continue;
            };
            let selection = decision.selection()?;
            let selection_id = selection.id()?;
            let record =
                records
                    .get(&selection_id)
                    .ok_or(GuardedCampaignReplayClosureError::Invalid {
                        reason: "replay closure is missing a schedule selection",
                    })?;
            if record.selection != selection || record.opportunity.scenario() != scenario_id {
                return Err(GuardedCampaignReplayClosureError::Invalid {
                    reason: "replay selection record differs from its schedule or scenario",
                });
            }
            record.validate_references()?;
            match selection.origin() {
                SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                    selection.validate_replay(&record.opportunity, &record.domain)?;
                }
                SelectionOrigin::CampaignBranch { .. } => {
                    let prefix = schedule.prefix(index)?;
                    let parent = Configuration {
                        def: scenario.scenario_def(),
                        schedule: prefix,
                    };
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
                    crucible::validate_app_random_model_selection(
                        &selection,
                        &record.declaration,
                        &record.opportunity,
                        &record.domain,
                    )
                    .map_err(|_| {
                        GuardedCampaignReplayClosureError::Invalid {
                            reason: "replay closure has unverified model-sample provenance",
                        }
                    })?;
                }
            }
            used.insert(selection_id);
        }
        if used.len() != records.len() {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure contains a selection absent from the schedule",
            });
        }
        Ok(())
    }

    pub(super) fn publish(
        &self,
        repository: &CampaignRepository,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        self.validate_for_schedule(scenario, schedule)?;
        for record in &self.selections {
            let domain = repository.publish_choice_domain(&record.domain)?;
            let declaration = repository.publish_selectable(&record.declaration)?;
            let opportunity = repository.publish_choice_opportunity(&record.opportunity)?;
            let selection = repository.publish_selection(&record.selection)?;
            if domain != record.selection.domain()
                || declaration != record.opportunity.declaration()
                || opportunity != record.selection.opportunity()
                || selection != record.selection.id()?
            {
                return Err(GuardedCampaignReplayClosureError::Invalid {
                    reason: "published replay closure identity changed",
                });
            }
        }
        Ok(())
    }
}

fn charge_resolved_selection(
    encoded_bytes: &mut usize,
    resolved: &crucible_campaign::ResolvedSelection,
) -> Result<(), GuardedCampaignReplayClosureError> {
    charge_canonical_record(encoded_bytes, resolved.domain().canonical_bytes())?;
    charge_canonical_record(encoded_bytes, resolved.declaration().canonical_bytes())?;
    charge_canonical_record(encoded_bytes, resolved.opportunity().canonical_bytes())?;
    charge_canonical_record(encoded_bytes, resolved.selection().canonical_bytes())?;
    Ok(())
}

fn charge_canonical_record(
    encoded_bytes: &mut usize,
    record: Vec<u8>,
) -> Result<(), GuardedCampaignReplayClosureError> {
    *encoded_bytes = encoded_bytes
        .checked_add(std::mem::size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(record.len()))
        .ok_or(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure encoded size overflowed",
        })?;
    if *encoded_bytes > MAX_REPLAY_CLOSURE_BYTES {
        return Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure exceeds its encoded byte bound",
        });
    }
    Ok(())
}

impl GuardedCampaignReplaySelection {
    fn validate_references(&self) -> Result<(), GuardedCampaignReplayClosureError> {
        self.opportunity
            .validate_references(&self.declaration, &self.domain)?;
        self.selection
            .validate_resolved_references(&self.opportunity, &self.domain)?;
        Ok(())
    }
}

/// Failure while encoding, decoding, or authenticating a replay closure.
#[derive(Debug, Error)]
pub enum GuardedCampaignReplayClosureError {
    /// A canonical campaign choice record was invalid.
    #[error("campaign replay closure record is invalid: {0}")]
    Codec(#[from] CampaignCodecError),
    /// A schedule prefix could not be reconstructed canonically.
    #[error("campaign replay closure schedule is invalid: {0}")]
    Schedule(#[from] crucible::ScheduleError),
    /// Publishing or resolving a closure record failed.
    #[error("campaign replay closure repository operation failed: {0}")]
    Repository(#[from] CampaignRepositoryError),
    /// Reserving bounded closure storage failed.
    #[error("campaign replay closure allocation failed: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
    /// The closure did not match its canonical schema or selected schedule.
    #[error("campaign replay closure is invalid: {reason}")]
    Invalid {
        /// Stable failure reason.
        reason: &'static str,
    },
}

fn schedule_selection_ids(
    schedule: &Schedule,
) -> Result<Vec<SelectionId>, GuardedCampaignReplayClosureError> {
    let mut ids = BTreeSet::new();
    for decision in schedule.decisions() {
        if let Decision::Selection(decision) = decision {
            ids.insert(decision.selection()?.id()?);
            if ids.len() > MAX_REPLAY_CLOSURE_SELECTIONS {
                return Err(GuardedCampaignReplayClosureError::Invalid {
                    reason: "selection count exceeds the replay-closure bound",
                });
            }
        }
    }
    Ok(ids.into_iter().collect())
}

fn append_record(
    output: &mut Vec<u8>,
    record: &[u8],
) -> Result<(), GuardedCampaignReplayClosureError> {
    let length =
        u32::try_from(record.len()).map_err(|_| GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure record length cannot be represented",
        })?;
    append_bytes(output, &length.to_le_bytes())?;
    append_bytes(output, record)
}

fn append_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), GuardedCampaignReplayClosureError> {
    let next = output.len().checked_add(bytes.len()).ok_or(
        GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure encoded size overflowed",
        },
    )?;
    if next > MAX_REPLAY_CLOSURE_BYTES {
        return Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure exceeds its encoded byte bound",
        });
    }
    output
        .try_reserve(bytes.len())
        .map_err(GuardedCampaignReplayClosureError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct ReplayClosureDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ReplayClosureDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, GuardedCampaignReplayClosureError> {
        if bytes.get(..REPLAY_CLOSURE_MAGIC.len()) != Some(REPLAY_CLOSURE_MAGIC) {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure has an invalid header",
            });
        }
        Ok(Self {
            bytes,
            cursor: REPLAY_CLOSURE_MAGIC.len(),
        })
    }

    fn read_u32(&mut self) -> Result<u32, GuardedCampaignReplayClosureError> {
        let end = self
            .cursor
            .checked_add(4)
            .ok_or(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure offset overflowed",
            })?;
        let value =
            self.bytes
                .get(self.cursor..end)
                .ok_or(GuardedCampaignReplayClosureError::Invalid {
                    reason: "replay closure is truncated",
                })?;
        self.cursor = end;
        Ok(u32::from_le_bytes(value.try_into().map_err(|_| {
            GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure integer is truncated",
            }
        })?))
    }

    fn read_record(&mut self) -> Result<&'a [u8], GuardedCampaignReplayClosureError> {
        let length = self.read_u32()? as usize;
        let end =
            self.cursor
                .checked_add(length)
                .ok_or(GuardedCampaignReplayClosureError::Invalid {
                    reason: "replay closure record offset overflowed",
                })?;
        let record =
            self.bytes
                .get(self.cursor..end)
                .ok_or(GuardedCampaignReplayClosureError::Invalid {
                    reason: "replay closure record is truncated",
                })?;
        self.cursor = end;
        Ok(record)
    }

    fn finish(self) -> Result<(), GuardedCampaignReplayClosureError> {
        if self.cursor != self.bytes.len() {
            return Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure has trailing bytes",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_charge_includes_record_framing_before_retention() {
        let mut encoded_bytes = MAX_REPLAY_CLOSURE_BYTES - std::mem::size_of::<u32>();
        assert!(matches!(
            charge_canonical_record(&mut encoded_bytes, vec![0]),
            Err(GuardedCampaignReplayClosureError::Invalid {
                reason: "replay closure exceeds its encoded byte bound"
            })
        ));
    }
}
