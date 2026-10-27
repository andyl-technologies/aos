//! Authenticated choice records needed to replay a selected campaign schedule.
//!
//! A replay closure lists one entry per covered selection decision, in
//! schedule order, naming the selection by identity digest and its domain,
//! declaration, and opportunity by record ordinal. Each distinct record is
//! stored once, so a domain shared by many selections costs one copy. The
//! selection itself is never stored: the schedule carries it, and the entry
//! digest binds the two. The encoding is a small root plus frames of at most
//! 64 MiB each; the `format` module shows the layout.
//!
//! Frames stay where they are. A closure built by this process holds them in
//! memory, a checkpoint loader hands over reopenable store handles, and
//! validation walks the schedule reading one frame at a time. A checkpoint
//! may cover only the selections its execution discovered; the rest resolve
//! from the campaign repository one at a time through
//! [`GuardedCampaignReplayChoices`].
//!
//! ```text
//! module    owns
//! format    root, frame, and bundle encodings
//! builder   the canonical encoder, also used to prove decoded closures canonical
//! reader    lazy frame reads and bounded record caches
//! walk      canonical-form proof and provenance checks during a walk
//! choices   replay choices for a schedule and their in-order cursor
//! ```

mod builder;
mod choices;
mod format;
mod reader;
#[cfg(test)]
mod tests;
mod walk;

use std::collections::BTreeMap;
use std::sync::Arc;

use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignRepository, CampaignRepositoryError,
    ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ResolvedSelection,
    SelectableDeclaration, Selection, SelectionId,
};
#[cfg(test)]
use crucible_campaign::{ChoiceValue, SelectionOrigin};
use crucible_engine::{Configuration, Decision, ScenarioDefForm, Schedule};
use crucible_store::content_store::{BlobHandle, ContentId, StoreError};
use thiserror::Error;

use builder::{ClosureBuilder, FrameRetention};
use format::{ClosureRoot, Entry, RecordKind, decode_bundle, encode_bundle, invalid};
pub(crate) use format::{
    MAX_REPLAY_CLOSURE_FRAME_BYTES, MAX_REPLAY_CLOSURE_FRAMES, MAX_REPLAY_CLOSURE_ROOT_BYTES,
    REPLAY_CLOSURE_OBJECT_KIND, REPLAY_CLOSURE_OBJECT_SCHEMA_VERSION, closure_object_id,
};
use reader::{ClosureFrameSource, FrameReader};
use walk::{CanonicalWalk, FreshRecords, Provenance};

pub(crate) use choices::GuardedCampaignReplayChoices;

/// A canonical set of records that authenticates schedule selections.
///
/// Clones share the root and frames. Two closures are equal when their roots
/// are, because a root names every frame by digest.
#[derive(Clone)]
pub struct GuardedCampaignReplayClosure {
    root: Arc<ClosureRoot>,
    frames: Arc<[ClosureFrameSource]>,
}

impl PartialEq for GuardedCampaignReplayClosure {
    fn eq(&self, other: &Self) -> bool {
        self.root.bytes == other.root.bytes
    }
}

impl Eq for GuardedCampaignReplayClosure {}

impl std::fmt::Debug for GuardedCampaignReplayClosure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardedCampaignReplayClosure")
            .field("entries", &self.root.entry_count)
            .field("records", &self.root.record_count)
            .field("frames", &self.root.frames.len())
            .finish()
    }
}

/// The records that authenticate one schedule selection decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuardedCampaignReplaySelection {
    domain: Arc<ChoiceDomain>,
    declaration: Arc<SelectableDeclaration>,
    opportunity: ChoiceOpportunity,
    selection: Selection,
}

/// Which schedule selections a closure must hold records for.
#[derive(Clone, Copy)]
enum Coverage<'a> {
    /// Every selection.
    Complete,
    /// Any subsequence of selections; the rest are not checked.
    Owned,
    /// Any subsequence; the rest resolve from this store and are checked.
    Repository(&'a CampaignExecutorStore),
}

impl GuardedCampaignReplayClosure {
    /// Canonical schema version carried by the remote resume envelope.
    pub const SCHEMA_VERSION: u32 = 2;

    /// Returns the closure that covers no selection.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            root: Arc::new(ClosureRoot::empty()),
            frames: Arc::from(Vec::new()),
        }
    }

    /// Builds the root-bound choice records that this execution discovered.
    ///
    /// Earlier schedule selections remain in the campaign repository. A raw
    /// checkpoint must retain newly discovered records before the observation
    /// that would otherwise publish them exists.
    pub(crate) fn from_owned_discoveries(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        discoveries: &BTreeMap<crucible_campaign::ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let mut builder = ClosureBuilder::new(FrameRetention::Retain);
        for decision in schedule.decision_history().iter() {
            let Decision::Selection(decision) = decision else {
                continue;
            };
            let selection = decision.selection()?;
            let Some(discovery) = discoveries.get(&selection.opportunity()) else {
                continue;
            };
            push_selection(
                &mut builder,
                &selection,
                discovery.domain(),
                discovery.declaration(),
                discovery.opportunity(),
            )?;
        }

        let closure = Self::from_builder(builder)?;
        closure.walk(scenario, schedule, Coverage::Owned, |_, _| Ok(()))?;
        Ok(closure)
    }

    /// Completes a raw-root choice closure from already published records.
    ///
    /// Selections this closure does not hold are resolved and authenticated
    /// one at a time; none are copied into the result.
    ///
    /// # Errors
    ///
    /// Returns an error if any inherited selection is unavailable or the
    /// combined records fail exact scenario and schedule validation.
    pub(crate) fn complete_from_repository(
        &self,
        store: &CampaignExecutorStore,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<GuardedCampaignReplayChoices, GuardedCampaignReplayClosureError> {
        self.walk(scenario, schedule, Coverage::Repository(store), |_, _| {
            Ok(())
        })?;
        Ok(GuardedCampaignReplayChoices {
            owned: self.clone(),
            store: Some(store.clone()),
        })
    }

    /// Validates complete coverage and returns the closure as replay choices.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::validate_for_schedule`].
    pub(crate) fn into_validated_choices(
        self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<GuardedCampaignReplayChoices, GuardedCampaignReplayClosureError> {
        self.validate_for_schedule(scenario, schedule)?;
        Ok(GuardedCampaignReplayChoices {
            owned: self,
            store: None,
        })
    }

    /// Returns the authenticated choice record for one schedule decision.
    ///
    /// This walks the schedule from its start; replay loops use
    /// [`GuardedCampaignReplayChoices::cursor`] instead.
    #[cfg(test)]
    pub(crate) fn selection_for_decision(
        &self,
        index: usize,
        schedule: &Schedule,
    ) -> Result<Option<GuardedCampaignReplaySelection>, GuardedCampaignReplayClosureError> {
        let choices = GuardedCampaignReplayChoices {
            owned: self.clone(),
            store: None,
        };
        choices.cursor(schedule).selection_for_decision(index)
    }

    /// Copies every schedule selection's records out of a repository.
    ///
    /// Repository-less carriers, such as a guarded run's result after its
    /// private repository is released, need the records themselves.
    pub(crate) fn collect(
        store: &CampaignExecutorStore,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let mut builder = ClosureBuilder::new(FrameRetention::Retain);
        // A single selection can reference a 32 MiB domain. Singleton loads
        // keep the repository's independent resolution bound meaningful.
        for decision in schedule.decision_history().iter() {
            let Decision::Selection(decision) = decision else {
                continue;
            };
            let selection = decision.selection()?;
            let resolved = store.resolve_selection(selection.id()?)?;
            push_selection(
                &mut builder,
                &selection,
                resolved.domain(),
                resolved.declaration(),
                resolved.opportunity(),
            )?;
        }

        let closure = Self::from_builder(builder)?;
        closure.validate_for_schedule(scenario, schedule)?;
        Ok(closure)
    }

    pub(crate) fn from_resolved_selections(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        selections: &[ResolvedSelection],
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let resolved = selections
            .iter()
            .map(|resolved| Ok((resolved.selection().id()?, resolved)))
            .collect::<Result<BTreeMap<SelectionId, &ResolvedSelection>, CampaignCodecError>>()?;

        let mut builder = ClosureBuilder::new(FrameRetention::Retain);
        for decision in schedule.decision_history().iter() {
            let Decision::Selection(decision) = decision else {
                continue;
            };
            let selection = decision.selection()?;
            let record = resolved
                .get(&selection.id()?)
                .ok_or_else(|| invalid("replay closure is missing a schedule selection"))?;
            push_selection(
                &mut builder,
                &selection,
                record.domain(),
                record.declaration(),
                record.opportunity(),
            )?;
        }

        let closure = Self::from_builder(builder)?;
        closure.validate_for_schedule(scenario, schedule)?;
        Ok(closure)
    }

    /// Rebuilds this closure with the first selection's boolean branch flipped.
    #[cfg(test)]
    pub(super) fn with_alternate_boolean_branch_selection(
        &self,
        schedule: &Schedule,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let record = self
            .selection_for_decision(0, schedule)?
            .ok_or_else(|| invalid("test replay closure has no selection"))?;
        let ChoiceValue::Boolean(selected) = record.selection.value() else {
            return Err(invalid("test replay closure selection is not boolean"));
        };
        let SelectionOrigin::CampaignBranch { branch_point, .. } = record.selection.origin() else {
            return Err(invalid(
                "test replay closure selection is not a campaign branch",
            ));
        };
        let alternate = Selection::new_campaign_branch(
            &record.opportunity,
            &record.domain,
            ChoiceValue::Boolean(!selected),
            branch_point,
        )?;

        let mut builder = ClosureBuilder::new(FrameRetention::Retain);
        push_selection(
            &mut builder,
            &alternate,
            &record.domain,
            &record.declaration,
            &record.opportunity,
        )?;
        Self::from_builder(builder)
    }

    /// Builds a structurally well-formed closure over opaque record bytes.
    ///
    /// Every entry shares one domain and one declaration and introduces its
    /// own opportunity. The records do not decode, so only storage and
    /// format paths accept the result.
    #[cfg(test)]
    pub(crate) fn synthetic_for_test(
        entries: u64,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let mut builder = ClosureBuilder::new(FrameRetention::Retain);
        for index in 0..entries {
            let mut opportunity_id = [3_u8; 32];
            opportunity_id[..8].copy_from_slice(&index.to_le_bytes());
            let mut selection = [4_u8; 32];
            selection[..8].copy_from_slice(&index.to_le_bytes());

            let domain = builder.record(RecordKind::Domain, [1; 32], || b"domain".to_vec())?;
            let declaration =
                builder.record(RecordKind::Declaration, [2; 32], || b"declaration".to_vec())?;
            let opportunity = builder.record(RecordKind::Opportunity, opportunity_id, || {
                index.to_le_bytes().to_vec()
            })?;
            builder.entry(Entry {
                selection,
                domain,
                declaration,
                opportunity,
            })?;
        }
        Self::from_builder(builder)
    }

    /// Encodes the closure as one canonical bundle buffer.
    ///
    /// Bundles serve carriers that hold one buffer, such as a savepoint
    /// file; stores and service messages keep the root and frames separate.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] when a stored frame
    /// cannot be read or authenticated, or the buffer cannot be allocated.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, GuardedCampaignReplayClosureError> {
        let frames = (0..self.frames.len())
            .map(|index| self.frame_bytes(index))
            .collect::<Result<Vec<_>, _>>()?;
        encode_bundle(&self.root.bytes, &frames)
    }

    /// Decodes and authenticates one canonical bundle.
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
        let (root, frames) = decode_bundle(bytes)?;
        Self::from_frame_parts(root, frames)
    }

    /// Returns the root followed by every frame, each a separate object.
    ///
    /// No object exceeds the 64 MiB component-message bound, so a service
    /// message can carry each one as its own element.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] when a stored frame
    /// cannot be read or authenticated.
    pub fn to_frame_objects(&self) -> Result<Vec<Vec<u8>>, GuardedCampaignReplayClosureError> {
        let mut objects = Vec::with_capacity(self.frames.len() + 1);
        objects.push(self.root.bytes.to_vec());
        for index in 0..self.frames.len() {
            objects.push(self.frame_bytes(index)?.to_vec());
        }
        Ok(objects)
    }

    /// Decodes and authenticates a root followed by its frames.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::from_canonical_bytes`], or an error when
    /// `objects` is empty.
    pub fn from_frame_objects<T: AsRef<[u8]>>(
        objects: &[T],
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let (root, frames) = objects
            .split_first()
            .ok_or_else(|| invalid("replay closure has no root object"))?;
        if root.as_ref().len() > MAX_REPLAY_CLOSURE_ROOT_BYTES {
            return Err(invalid("replay closure root exceeds its byte bound"));
        }
        let frames = frames
            .iter()
            .map(|frame| Arc::from(frame.as_ref()))
            .collect();
        Self::from_frame_parts(Arc::from(root.as_ref()), frames)
    }

    /// Opens a closure whose frames stay behind reopenable store handles.
    ///
    /// Only the root and frame lengths are checked here. Each frame is read
    /// and authenticated against its root digest when a walk reaches it, and
    /// canonical form is proven by the first validating walk.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] for a malformed root or
    /// a frame count or length that differs from it.
    pub(crate) fn from_stored(
        root: Vec<u8>,
        frames: Vec<BlobHandle>,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let root = ClosureRoot::decode(root.into())?;
        if frames.len() != root.frames.len() {
            return Err(invalid("stored replay closure frame count differs"));
        }
        for (handle, summary) in frames.iter().zip(&root.frames) {
            if handle.logical_length() != u64::from(summary.length) {
                return Err(invalid("stored replay closure frame length differs"));
            }
        }

        Ok(Self {
            root: Arc::new(root),
            frames: frames.into_iter().map(ClosureFrameSource::Stored).collect(),
        })
    }

    /// Returns whether two closures share one root and frame list.
    #[cfg(test)]
    pub(crate) fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root) && Arc::ptr_eq(&self.frames, &other.frames)
    }

    /// Returns the encoded root.
    pub(crate) fn root_bytes(&self) -> &[u8] {
        &self.root.bytes
    }

    /// Returns the content identity of the encoded root.
    pub(crate) fn root_id(&self) -> ContentId {
        closure_object_id(&self.root.bytes)
    }

    /// Returns each frame's content identity, in frame order.
    pub(crate) fn frame_ids(&self) -> impl ExactSizeIterator<Item = ContentId> + '_ {
        self.root.frames.iter().map(|frame| frame.id())
    }

    /// Validates exact record coverage and provenance for a selected schedule.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignReplayClosureError`] when any schedule
    /// selection is missing, any closure selection is unused, the closure is
    /// not canonical, or exact scenario, domain, default, model, or branch
    /// provenance differs.
    pub fn validate_for_schedule(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        self.walk(scenario, schedule, Coverage::Complete, |_, _| Ok(()))
    }

    pub(super) fn publish(
        &self,
        repository: &CampaignRepository,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        self.walk(scenario, schedule, Coverage::Complete, |record, fresh| {
            // Each record is published when first referenced; later entries
            // name the same immutable object.
            let mut unchanged = true;
            if fresh.domain {
                unchanged &=
                    repository.publish_choice_domain(&record.domain)? == record.selection.domain();
            }
            if fresh.declaration {
                unchanged &= repository.publish_selectable(&record.declaration)?
                    == record.opportunity.declaration();
            }
            if fresh.opportunity {
                unchanged &= repository.publish_choice_opportunity(&record.opportunity)?
                    == record.selection.opportunity();
            }
            unchanged &=
                repository.publish_selection(&record.selection)? == record.selection.id()?;
            if !unchanged {
                return Err(invalid("published replay closure identity changed"));
            }
            Ok(())
        })
    }

    fn from_builder(builder: ClosureBuilder) -> Result<Self, GuardedCampaignReplayClosureError> {
        let (root, frames) = builder.finish()?;
        Ok(Self {
            root: Arc::new(root),
            frames: frames.into_iter().map(ClosureFrameSource::Memory).collect(),
        })
    }

    /// Authenticates in-memory frames against a root, then proves the whole
    /// closure structurally canonical.
    fn from_frame_parts(
        root: Arc<[u8]>,
        frames: Vec<Arc<[u8]>>,
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        let root = ClosureRoot::decode(root)?;
        if frames.len() != root.frames.len() {
            return Err(invalid("replay closure frame count differs from its root"));
        }
        for (frame, summary) in frames.iter().zip(&root.frames) {
            if frame.len() != summary.length as usize || closure_object_id(frame) != summary.id() {
                return Err(invalid("replay closure frame differs from its root digest"));
            }
        }

        let closure = Self {
            root: Arc::new(root),
            frames: frames.into_iter().map(ClosureFrameSource::Memory).collect(),
        };
        closure.validate_structure()?;
        Ok(closure)
    }

    /// Proves record references and frame packing canonical without a schedule.
    fn validate_structure(&self) -> Result<(), GuardedCampaignReplayClosureError> {
        let mut reader = FrameReader::new(self);
        let mut canonical = CanonicalWalk::new();
        for ordinal in 0..self.root.entry_count {
            let entry = reader.entry(ordinal)?;
            let records = canonical.resolve(&mut reader, entry)?;
            records
                .opportunity
                .validate_references(&records.declaration, &records.domain)?;
        }
        canonical.finish(&self.root)
    }

    /// Walks the schedule with this closure's entries in lockstep.
    ///
    /// Every covered selection is authenticated against its records and
    /// scenario provenance, then passed to `visit` with the records first
    /// referenced by its entry. The walk re-encodes the entries it consumes
    /// and requires the result to equal this closure's root.
    fn walk(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        coverage: Coverage<'_>,
        mut visit: impl FnMut(
            &GuardedCampaignReplaySelection,
            FreshRecords,
        ) -> Result<(), GuardedCampaignReplayClosureError>,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        let provenance = Provenance::new(scenario, schedule);
        let mut reader = FrameReader::new(self);
        let mut canonical = CanonicalWalk::new();
        let mut next_entry = 0_u64;

        for (index, decision) in schedule.decision_history().iter().enumerate() {
            let Decision::Selection(decision) = decision else {
                continue;
            };
            let selection = decision.selection()?;
            let digest = selection_digest(&selection)?;
            let entry = match next_entry < self.root.entry_count {
                true => Some(reader.entry(next_entry)?).filter(|entry| entry.selection == digest),
                false => None,
            };

            let Some(entry) = entry else {
                match coverage {
                    Coverage::Complete => {
                        return Err(invalid("replay closure is missing a schedule selection"));
                    }
                    Coverage::Owned => {}
                    Coverage::Repository(store) => {
                        let resolved = store.resolve_selection(selection.id()?)?;
                        let record = GuardedCampaignReplaySelection::from_resolved(&resolved);
                        if record.selection != selection {
                            return Err(invalid("resolved replay selection differs"));
                        }
                        record.validate_references()?;
                        provenance.validate(index, &record)?;
                    }
                }
                continue;
            };

            next_entry += 1;
            let records = canonical.resolve(&mut reader, entry)?;
            let fresh = records.fresh;
            let record = records.with_selection(selection);
            record.validate_references()?;
            provenance.validate(index, &record)?;
            visit(&record, fresh)?;
        }

        if next_entry != self.root.entry_count {
            return Err(invalid(
                "replay closure contains a selection absent from the schedule",
            ));
        }
        canonical.finish(&self.root)
    }
}

/// Authenticates a remote resume envelope against its exact checkpoint source.
///
/// # Errors
///
/// Returns [`GuardedCampaignReplayClosureError`] when the envelope uses an
/// unknown schema, the restored checkpoint identity differs, or the canonical
/// closure does not cover the exact supplied scenario and schedule.
pub fn validate_remote_resume_replay_closure(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    checkpoint: &crucible_engine::Checkpoint,
    envelope: &crucible_control_api::ResumeReplayClosure,
) -> Result<(), GuardedCampaignReplayClosureError> {
    if envelope.schema_version() != GuardedCampaignReplayClosure::SCHEMA_VERSION {
        return Err(GuardedCampaignReplayClosureError::UnsupportedSchema {
            actual: envelope.schema_version(),
            expected: GuardedCampaignReplayClosure::SCHEMA_VERSION,
        });
    }

    let scenario_def = scenario.scenario_def();
    let configuration_id = configuration.id();
    if scenario_def != configuration.def
        || checkpoint.id != configuration_id
        || checkpoint.configuration != configuration_id
        || checkpoint.scenario_ref != scenario_def.id()
    {
        return Err(GuardedCampaignReplayClosureError::ResumeSourceMismatch);
    }

    let closure = GuardedCampaignReplayClosure::from_frame_objects(envelope.frames())?;
    closure.validate_for_schedule(scenario, &configuration.schedule)
}

/// Returns whether a schedule holds any selection decision.
pub(super) fn schedule_has_selection(schedule: &Schedule) -> bool {
    schedule
        .decision_history()
        .iter()
        .any(|decision| matches!(decision, Decision::Selection(_)))
}

fn selection_digest(selection: &Selection) -> Result<[u8; 32], GuardedCampaignReplayClosureError> {
    Ok(selection.id()?.content_id().digest())
}

/// Appends one selection's entry and any records it introduces.
fn push_selection(
    builder: &mut ClosureBuilder,
    selection: &Selection,
    domain: &ChoiceDomain,
    declaration: &SelectableDeclaration,
    opportunity: &ChoiceOpportunity,
) -> Result<(), GuardedCampaignReplayClosureError> {
    // Records are keyed by the identities the selection and opportunity
    // name, so a re-referenced record is neither encoded nor hashed again.
    // A record that does not match its claimed identity fails the walk
    // that validates every constructed closure.
    let domain = builder.record(
        RecordKind::Domain,
        selection.domain().content_id().digest(),
        || domain.canonical_bytes(),
    )?;
    let declaration = builder.record(
        RecordKind::Declaration,
        opportunity.declaration().content_id().digest(),
        || declaration.canonical_bytes(),
    )?;
    let opportunity = builder.record(
        RecordKind::Opportunity,
        selection.opportunity().content_id().digest(),
        || opportunity.canonical_bytes(),
    )?;
    builder.entry(Entry {
        selection: selection_digest(selection)?,
        domain,
        declaration,
        opportunity,
    })
}

impl GuardedCampaignReplaySelection {
    fn from_resolved(resolved: &ResolvedSelection) -> Self {
        Self {
            domain: Arc::new(resolved.domain().clone()),
            declaration: Arc::new(resolved.declaration().clone()),
            opportunity: resolved.opportunity().clone(),
            selection: resolved.selection().clone(),
        }
    }

    pub(crate) const fn selection(&self) -> &Selection {
        &self.selection
    }

    pub(crate) const fn opportunity(&self) -> &ChoiceOpportunity {
        &self.opportunity
    }

    pub(crate) fn declaration(&self) -> &SelectableDeclaration {
        &self.declaration
    }

    pub(crate) fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    pub(crate) fn guest_owner(&self) -> Option<&str> {
        match self.opportunity.source() {
            ChoiceSource::Guest { node, .. } => Some(node),
            _ => None,
        }
    }

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
    /// The remote envelope uses a closure schema this daemon does not understand.
    #[error("unsupported campaign replay closure schema version {actual}; expected {expected}")]
    UnsupportedSchema {
        /// Version supplied by the caller.
        actual: u32,
        /// Version supported by this daemon.
        expected: u32,
    },
    /// The envelope source differs from the checkpoint configuration being restored.
    #[error("campaign replay closure source differs from the restored checkpoint configuration")]
    ResumeSourceMismatch,
    /// A canonical campaign choice record was invalid.
    #[error("campaign replay closure record is invalid: {0}")]
    Codec(#[from] CampaignCodecError),
    /// A schedule prefix could not be reconstructed canonically.
    #[error("campaign replay closure schedule is invalid: {0}")]
    Schedule(#[from] crucible_engine::ScheduleError),
    /// Publishing or resolving a closure record failed.
    #[error("campaign replay closure repository operation failed: {0}")]
    Repository(#[from] CampaignRepositoryError),
    /// Reading a stored closure frame failed.
    #[error("campaign replay closure frame could not be read: {0}")]
    Store(#[source] StoreError),
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
