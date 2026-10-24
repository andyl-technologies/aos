//! Defines inert ordered coordinator checkpoint17 records.
//!
//! The Core issuer alone authenticates a live causal safe point. This paired
//! grammar checks historical correspondence after separately admitted parsing;
//! it cannot issue a World, ticket, grant or native spending scope.
//!
//! ```text
//! checkpoint = { schema_version, ordering_profile, activation, parent, maximum_records,
//!                first_sequence, next_sequence, first_event_ordinal, entries, safe_point }
//! ```

use crucible_node_format::{ContentRef, HashRef, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::ProviderError;

/// Retains the exact current activation independently of a later capture cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCommitmentActivation17 {
    /// Names the actual current activation, never a previous incarnation.
    pub activation_id: Id,
    /// Retains the actual World generation.
    pub world_generation: U64,
    /// Binds the complete immutable World definition.
    pub world_binding: HashRef,
    /// Retains the actual activation boundary independently of current progress.
    pub boundary: Position,
}

/// Identifies an actual coordinator boundary in retained append order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoordinatorCommitmentKind17 {
    /// Records activation publication.
    Activation,
    /// Records native execution submission.
    Begin,
    /// Records a retained completion or unresolved polling attempt.
    Poll,
    /// Records durable common result publication.
    StoredResult,
    /// Records actual Scheduler acceptance of that result.
    SchedulingCommit,
    /// Records actual native retirement acknowledgement.
    Retire,
    /// Records a freshly authenticated current native observation.
    Observe,
    /// Records actual immutable input staging.
    InputStage,
    /// Records native input acknowledgement.
    InputAcknowledgement,
    /// Records actual Scheduler input commitment.
    InputCommit,
    /// Records another explicitly supported ordered control boundary.
    Control,
}

/// Preserves actual effect knowledge without recycling an attempt identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoordinatorCommitmentState17 {
    /// Retains an attempted boundary whose disposition is not yet known.
    Reserved,
    /// Retains a positively authenticated completed boundary.
    Committed,
    /// Retains positive evidence that the attempted boundary had no effect.
    Refused,
    /// Retains an uncertain attempt and its continuing custody obligation.
    Uncertain,
}

/// Retains one actual ordered boundary without pointer or token serialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCommitmentEntry17 {
    /// Names its nonreusable position in the cumulative ordered ledger.
    pub sequence: U64,
    /// Identifies the actual measured boundary.
    pub kind: CoordinatorCommitmentKind17,
    /// Retains the original operation or input identity, when applicable.
    #[serde(deserialize_with = "required_nullable")]
    pub operation: Option<Id>,
    /// Retains the actual selected node, when applicable.
    #[serde(deserialize_with = "required_nullable")]
    pub node: Option<Id>,
    /// Retains an actual boundary coordinate, never a derived global maximum.
    #[serde(deserialize_with = "required_nullable")]
    pub position: Option<Position>,
    /// Binds immutable evidence retained by this boundary, when applicable.
    #[serde(deserialize_with = "required_nullable")]
    pub evidence: Option<ContentRef>,
    /// Preserves the actual known disposition of this attempt.
    pub state: CoordinatorCommitmentState17,
    /// Retains a real committed semantic ordinal; operational attempts keep null.
    #[serde(deserialize_with = "required_nullable")]
    pub event_ordinal: Option<U64>,
}

/// Binds historical coordinates to the exact current coordinator objects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCommitmentSafePoint17 {
    /// Retains the coordinate selected by the live causal eligibility issuer.
    pub position: Position,
    /// Retains the coordinator-issued event ordinal at that safe point.
    pub event_ordinal: U64,
    /// Commits the exact ordered prefix, excluding this safe-point wrapper.
    pub prefix: HashRef,
    /// Names the actual complete Runtime7 body.
    pub runtime: ContentRef,
    /// Names the actual complete Scheduler body.
    pub scheduling: ContentRef,
}

/// Preserves a finite logical coordinator ledger and its explicit lifetime bound.
///
/// A decoded value is inert DATA. Fresh allocation cannot increase its funded
/// maximum or reset its cumulative sequence. Earlier immutable prefix bodies
/// remain separately reachable through the authenticated parent reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCommitmentCheckpoint17 {
    /// Selects only this explicitly declared grammar.
    pub schema_version: u16,
    /// Selects the explicit semantic/public event-order correspondence.
    pub ordering_profile: String,
    /// Retains the actual current activation.
    pub activation: CoordinatorCommitmentActivation17,
    /// Names the imported verified prefix, or null at the actual original birth.
    #[serde(deserialize_with = "required_nullable")]
    pub parent: Option<ContentRef>,
    /// Retains the explicitly funded cumulative record ceiling.
    pub maximum_records: U64,
    /// Retains the first sequence represented by this local continuation.
    pub first_sequence: U64,
    /// Retains the next nonreusable cumulative sequence.
    pub next_sequence: U64,
    /// Retains the inherited next semantic ordinal independently of attempts.
    pub first_event_ordinal: U64,
    /// Retains every local attempt in actual append order, including refusals.
    pub entries: Vec<CoordinatorCommitmentEntry17>,
    /// Binds the actual ordered prefix to the two current coordinator bodies.
    pub safe_point: CoordinatorCommitmentSafePoint17,
}

/// Bounds a separately admitted typed parse of this exact closed grammar.
///
/// This is constructor DATA derived from an explicit encoded input ceiling,
/// never a coordinator lifetime policy or a native receive permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorCheckpointStorageData17 {
    retained: usize,
    transient: usize,
    scratch: usize,
    total: usize,
}

impl CoordinatorCheckpointStorageData17 {
    /// Returns the prospective root and complete typed container/leaf backing.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independently simultaneous parser, DOM and canonical work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns defining fixed constructor and validator views.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked sum under the independently supplied parse ceiling.
    pub const fn requested_bytes_data(&self) -> usize {
        self.total
    }
}

#[derive(Serialize)]
struct Prefix<'a> {
    schema_version: u16,
    ordering_profile: &'a str,
    activation: &'a CoordinatorCommitmentActivation17,
    parent: &'a Option<ContentRef>,
    maximum_records: U64,
    first_sequence: U64,
    next_sequence: U64,
    first_event_ordinal: U64,
    entries: &'a [CoordinatorCommitmentEntry17],
}

impl CoordinatorCommitmentCheckpoint17 {
    /// Prices a complete prospective parse before any typed allocation.
    ///
    /// The real lexical value-node bound prices actual closed entry/container
    /// layouts. Four typed slots cover pinned parser/Vec growth; four encoded
    /// bytes cover all independently grown typed String backing together. This
    /// bound includes invalid late fields, rather than assuming validated leaf
    /// length limits before parsing. Existing borrowed raw input is separate.
    ///
    /// # Errors
    /// Refuses zero input, checked overflow or an independently supplied byte cap.
    pub fn prospective_storage_data(
        encoded_upper: usize,
        maximum: usize,
    ) -> Result<CoordinatorCheckpointStorageData17, ProviderError> {
        use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
        use std::mem::size_of;
        if encoded_upper == 0 {
            return Err(refused());
        }
        let extent = original_json_value_storage_extent_data(encoded_upper)?;
        let slot = size_of::<CoordinatorCommitmentEntry17>()
            .checked_add(size_of::<ContentRef>())
            .and_then(|n| n.checked_add(size_of::<HashRef>()))
            .and_then(|n| n.checked_add(size_of::<Id>()))
            .and_then(|n| n.checked_add(size_of::<String>()))
            .ok_or_else(refused)?;
        let typed = extent
            .maximum_value_nodes
            .checked_mul(4)
            .and_then(|n| n.checked_mul(slot))
            .and_then(|n| n.checked_add(encoded_upper.checked_mul(4)?))
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or_else(refused)?;
        let transient = typed
            .checked_add(extent.value_dom_requested_bytes)
            .and_then(|n| n.checked_add(extent.canonical_pass_requested_bytes().ok()?))
            .ok_or_else(refused)?;
        let scratch = Self::counter_scratch_data()
            .checked_add(size_of::<CoordinatorCheckpointStorageData17>())
            .and_then(|n| n.checked_add(size_of::<Result<CoordinatorCheckpointStorageData17, ProviderError>>()))
            .and_then(|n| n.checked_add(crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()))
            .ok_or_else(refused)?;
        let total = typed
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .ok_or_else(refused)?;
        Ok(CoordinatorCheckpointStorageData17 {
            retained: typed,
            transient,
            scratch,
            total,
        })
    }

    /// Checks the exact bounded historical grammar and requested correspondence.
    ///
    /// Canonical object/full-reference validation and precredited typed parsing
    /// precede this check. The native reader additionally authenticates the
    /// actual Source MAC; Core separately proves live causal eligibility.
    /// This function performs no IO and issues no executable authority.
    ///
    /// # Errors
    /// Refuses an unknown edition, changed Runtime/cut/ordinal, sequence gap,
    /// missing original identifiers, invalid reference, unresolved attempt,
    /// exhausted/changed lifetime policy or malformed activation correspondence.
    pub fn authenticate_structure_data(
        &self,
        runtime: &ContentRef,
        cut: Position,
        ordinal: U64,
    ) -> Result<(), ProviderError> {
        if self.schema_version != 17
            || self.ordering_profile != "coordinator-public-events-v17"
            || self.maximum_records.get() == 0
            || self.first_sequence > self.next_sequence
            || self.next_sequence > self.maximum_records
            || u64::try_from(self.entries.len()).map_err(|_| refused())?
                != self.next_sequence.get() - self.first_sequence.get()
            || (self.first_sequence.get() == 0) != self.parent.is_none()
            || self.safe_point.position != cut
            || self.safe_point.event_ordinal != ordinal
            || self.safe_point.runtime != *runtime
            || self.activation.boundary > cut
            || self.activation.world_generation.get() == 0
        {
            return Err(refused());
        }
        self.activation.world_binding.validate()?;
        self.activation.boundary.validate()?;
        self.safe_point.position.validate()?;
        self.safe_point.prefix.validate()?;
        self.safe_point.runtime.validate()?;
        self.safe_point.scheduling.validate()?;
        if self.safe_point.runtime.media_type
            != "application/vnd.crucible.runtime-original-lineage+json;version=7"
            || self.safe_point.runtime.length.get() == 0
            || self.safe_point.scheduling.length.get() == 0
            || self.safe_point.prefix.domain != "crucible.coordinator-prefix.v17"
        {
            return Err(refused());
        }
        if let Some(parent) = &self.parent {
            parent.validate()?;
            if parent.media_type != super::COORDINATOR_CHECKPOINT17_MEDIA
                || parent.length.get() == 0
            {
                return Err(refused());
            }
        }

        // Initial archive support is explicit: the real original publisher
        // commits one initial-world-ready control after durable World readiness.
        // Empty legacy archives and requested starting ordinals cannot stand in
        // for that actual event. A fresh suffix inherits its original counters.
        if self.parent.is_none() {
            let Some(activation) = self.entries.first() else {
                return Err(refused());
            };
            let Some(ready) = self.entries.get(1) else {
                return Err(refused());
            };
            if self.first_event_ordinal.get() != 0
                || activation.kind != CoordinatorCommitmentKind17::Activation
                || activation.state != CoordinatorCommitmentState17::Committed
                || activation.operation.is_some()
                || activation.node.is_some()
                || activation.position != Some(self.activation.boundary)
                || activation.evidence.is_none()
                || activation.event_ordinal.is_some()
                || ready.kind != CoordinatorCommitmentKind17::Control
                || ready.state != CoordinatorCommitmentState17::Committed
                || ready.operation.is_some()
                || ready.node.is_some()
                || ready.position != Some(self.activation.boundary)
                || ready.evidence != activation.evidence
                || ready.event_ordinal != Some(U64::new(0))
            {
                return Err(refused());
            }
        }

        let mut event_ordinal = self.first_event_ordinal;
        for (offset, entry) in self.entries.iter().enumerate() {
            let sequence = self
                .first_sequence
                .get()
                .checked_add(u64::try_from(offset).map_err(|_| refused())?)
                .ok_or_else(refused)?;
            if entry.sequence.get() != sequence
                || matches!(
                    entry.state,
                    CoordinatorCommitmentState17::Reserved
                        | CoordinatorCommitmentState17::Uncertain
                )
                || entry.position.is_some_and(|position| position > cut)
            {
                return Err(refused());
            }
            match entry.kind {
                CoordinatorCommitmentKind17::Activation => {
                    if entry.operation.is_some() || entry.node.is_some() {
                        return Err(refused());
                    }
                }
                CoordinatorCommitmentKind17::Observe => {
                    if entry.node.is_none() {
                        return Err(refused());
                    }
                }
                CoordinatorCommitmentKind17::Control => {}
                _ => {
                    if entry.operation.is_none() || entry.node.is_none() {
                        return Err(refused());
                    }
                }
            }
            if let Some(actual) = entry.event_ordinal {
                if actual != event_ordinal
                    || entry.state != CoordinatorCommitmentState17::Committed
                    || !matches!(
                        entry.kind,
                        CoordinatorCommitmentKind17::SchedulingCommit
                            | CoordinatorCommitmentKind17::InputCommit
                            | CoordinatorCommitmentKind17::Control
                    )
                    || entry.position.is_none()
                    || entry.evidence.is_none()
                {
                    return Err(refused());
                }
                event_ordinal = event_ordinal.checked_add(U64::new(1))?;
            }
            if let Some(reference) = &entry.evidence {
                reference.validate()?;
                if reference.length.get() == 0 {
                    return Err(refused());
                }
            }
        }
        if event_ordinal != self.safe_point.event_ordinal {
            return Err(refused());
        }
        Ok(())
    }

    /// Joins inherited cumulative counters to the independently decoded full parent.
    ///
    /// The caller must first authenticate the complete parent bytes against this
    /// exact reference in the signed closure, and admit both typed/canonical
    /// owners. This data comparison cannot authenticate an archive or create a
    /// live coordinator bank from matching counter values.
    ///
    /// # Errors
    /// Refuses a foreign parent reference, changed funded lifetime ceiling,
    /// reused operational/semantic counters, a different immutable World, or a
    /// fresh activation boundary that does not preserve the original safe point.
    pub fn authenticate_parent_counters_data(
        &self,
        reference: &ContentRef,
        parent: &Self,
    ) -> Result<(), ProviderError> {
        reference.validate()?;
        self.authenticate_structure_data(
            &self.safe_point.runtime,
            self.safe_point.position,
            self.safe_point.event_ordinal,
        )?;
        parent.authenticate_structure_data(
            &parent.safe_point.runtime,
            parent.safe_point.position,
            parent.safe_point.event_ordinal,
        )?;
        if self.parent.as_ref() != Some(reference)
            || reference.media_type != super::COORDINATOR_CHECKPOINT17_MEDIA
            || self.maximum_records != parent.maximum_records
            || self.first_sequence != parent.next_sequence
            || self.first_event_ordinal != parent.safe_point.event_ordinal
            || self.activation.world_binding != parent.activation.world_binding
            || self.activation.boundary != parent.safe_point.position
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Compares the historical ceiling with independently authenticated policy.
    ///
    /// Native structural validation does not possess this Core policy and must
    /// not substitute its receive ceiling or this decoded value for that loan.
    ///
    /// # Errors
    /// Refuses zero or different genuine funded policy; creates no permission.
    pub fn authenticate_policy_data(&self, maximum_records: U64) -> Result<(), ProviderError> {
        if maximum_records.get() == 0 || self.maximum_records != maximum_records {
            return Err(refused());
        }
        Ok(())
    }

    /// Counts actual typed backing without using encoded extent as heap demand.
    ///
    /// # Errors
    /// Refuses the defining metadata traversal or checked requested-byte overflow.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        use crate::retained_metadata::MetadataObserver;
        let Self {
            schema_version: _,
            ordering_profile,
            activation,
            parent,
            maximum_records: _,
            first_sequence: _,
            next_sequence: _,
            first_event_ordinal: _,
            entries,
            safe_point,
        } = self;
        let CoordinatorCommitmentActivation17 {
            activation_id,
            world_generation: _,
            world_binding,
            boundary: _,
        } = activation;
        let mut observer = MetadataObserver::new();
        observer.observe(ordering_profile)?;
        observer.observe(activation_id)?;
        observer.observe(world_binding)?;
        observer.observe(parent)?;
        observer.vector::<CoordinatorCommitmentEntry17>(entries.capacity())?;
        for entry in entries {
            let CoordinatorCommitmentEntry17 {
                sequence: _,
                kind: _,
                operation,
                node,
                position: _,
                evidence,
                state: _,
                event_ordinal: _,
            } = entry;
            observer.observe(operation)?;
            observer.observe(node)?;
            observer.observe(evidence)?;
        }
        let CoordinatorCommitmentSafePoint17 {
            position: _,
            event_ordinal: _,
            prefix,
            runtime,
            scheduling,
        } = safe_point;
        observer.observe(prefix)?;
        observer.observe(runtime)?;
        observer.observe(scheduling)?;
        Ok(observer.finish())
    }

    /// Counts actual owned backing, excluding this record's inline root.
    ///
    /// # Errors
    /// Refuses unsupported metadata or checked requested-layout overflow.
    pub fn retained_backing_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::requested_metadata_backing_storage_data(
            &self.retained_metadata_data()?,
        )
    }

    /// Names the actual direct structured, metadata and prefix-check fixed views.
    pub fn counter_scratch_data() -> usize {
        use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<Prefix<'static>>()
            + size_of::<&CoordinatorCommitmentActivation17>()
            + size_of::<&CoordinatorCommitmentSafePoint17>()
            + size_of::<&Vec<CoordinatorCommitmentEntry17>>()
            + size_of::<&CoordinatorCommitmentEntry17>()
            + size_of::<&[CoordinatorCommitmentEntry17]>()
            + size_of::<std::slice::Iter<'static, CoordinatorCommitmentEntry17>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, CoordinatorCommitmentEntry17>>>(
            )
            + size_of::<(usize, &CoordinatorCommitmentEntry17)>()
            + size_of::<&Option<ContentRef>>() * 2
            + size_of::<&Option<Id>>() * 2
            + size_of::<&ContentRef>() * 3
            + size_of::<&Id>()
            + size_of::<&HashRef>() * 2
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<HashRef, crucible_node_format::ContractError>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<Result<u64, ProviderError>>()
            + size_of::<Option<u64>>()
            + size_of::<Option<Position>>()
            + size_of::<(u16, U64, U64, U64)>()
    }

    /// Authenticates the exact domain-separated prefix under admitted work.
    ///
    /// The caller independently reserves complete Value/canonical transient
    /// storage before this serializer runs; encoded length alone is not its
    /// requested-heap census. A hash match supplies historical integrity only.
    ///
    /// # Errors
    /// Refuses serialization/canonicalization failure or changed ordered content.
    pub fn authenticate_prefix_data(&self) -> Result<(), ProviderError> {
        if canonical::json_hash("crucible.coordinator-prefix.v17", &self.prefix_data())?
            != self.safe_point.prefix
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the exact prefix fields for the owning prequote and live issuer.
    pub fn prefix_data(&self) -> impl Serialize + '_ {
        Prefix {
            schema_version: self.schema_version,
            ordering_profile: &self.ordering_profile,
            activation: &self.activation,
            parent: &self.parent,
            maximum_records: self.maximum_records,
            first_sequence: self.first_sequence,
            next_sequence: self.next_sequence,
            first_event_ordinal: self.first_event_ordinal,
            entries: &self.entries,
        }
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("coordinator checkpoint17 correspondence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::Phase;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn checkpoint() -> Result<CoordinatorCommitmentCheckpoint17, Box<dyn std::error::Error>> {
        let position = Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl);
        let runtime = canonical::content_ref(
            b"{}",
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
        )?;
        let mut value = CoordinatorCommitmentCheckpoint17 {
            schema_version: 17,
            ordering_profile: "coordinator-public-events-v17".into(),
            activation: CoordinatorCommitmentActivation17 {
                activation_id: Id::new("checkpoint-test-world")?,
                world_generation: U64::new(1),
                world_binding: canonical::hash("cnp.world-binding.v1", b"world")?,
                boundary: position,
            },
            parent: None,
            maximum_records: U64::new(8),
            first_sequence: U64::new(0),
            next_sequence: U64::new(5),
            first_event_ordinal: U64::new(0),
            entries: vec![
                CoordinatorCommitmentEntry17 {
                    sequence: U64::new(0),
                    kind: CoordinatorCommitmentKind17::Activation,
                    operation: None,
                    node: None,
                    position: Some(position),
                    evidence: Some(runtime.clone()),
                    state: CoordinatorCommitmentState17::Committed,
                    event_ordinal: None,
                },
                CoordinatorCommitmentEntry17 {
                    sequence: U64::new(1),
                    kind: CoordinatorCommitmentKind17::Control,
                    operation: None,
                    node: None,
                    position: Some(position),
                    evidence: Some(runtime.clone()),
                    state: CoordinatorCommitmentState17::Committed,
                    event_ordinal: Some(U64::new(0)),
                },
                CoordinatorCommitmentEntry17 {
                    sequence: U64::new(2),
                    kind: CoordinatorCommitmentKind17::Begin,
                    operation: Some(Id::new("operation-one")?),
                    node: Some(Id::new("producer")?),
                    position: Some(position),
                    evidence: None,
                    state: CoordinatorCommitmentState17::Refused,
                    event_ordinal: None,
                },
                CoordinatorCommitmentEntry17 {
                    sequence: U64::new(3),
                    kind: CoordinatorCommitmentKind17::Observe,
                    operation: None,
                    node: Some(Id::new("producer")?),
                    position: Some(position),
                    evidence: None,
                    state: CoordinatorCommitmentState17::Committed,
                    event_ordinal: None,
                },
                CoordinatorCommitmentEntry17 {
                    sequence: U64::new(4),
                    kind: CoordinatorCommitmentKind17::SchedulingCommit,
                    operation: Some(Id::new("operation-two")?),
                    node: Some(Id::new("producer")?),
                    position: Some(position),
                    evidence: Some(runtime.clone()),
                    state: CoordinatorCommitmentState17::Committed,
                    event_ordinal: Some(U64::new(1)),
                },
            ],
            safe_point: CoordinatorCommitmentSafePoint17 {
                position,
                event_ordinal: U64::new(2),
                prefix: canonical::hash("crucible.coordinator-prefix.v17", b"initial")?,
                runtime,
                scheduling: canonical::content_ref(b"{}", "application/json")?,
            },
        };
        let prefix = canonical::json_hash("crucible.coordinator-prefix.v17", &value.prefix_data())?;
        value.safe_point.prefix = prefix;
        Ok(value)
    }

    #[test]
    fn attempts_do_not_become_semantic_ordinals_and_prefix_order_is_authenticated() -> TestResult {
        let value = checkpoint()?;
        value.authenticate_structure_data(
            &value.safe_point.runtime,
            value.safe_point.position,
            U64::new(2),
        )?;
        value.authenticate_prefix_data()?;

        let mut changed = value.clone();
        changed.entries[3].event_ordinal = Some(U64::new(1));
        assert!(
            changed
                .authenticate_structure_data(
                    &value.safe_point.runtime,
                    value.safe_point.position,
                    U64::new(2)
                )
                .is_err()
        );

        changed = value.clone();
        changed.entries.swap(0, 1);
        assert!(
            changed
                .authenticate_structure_data(
                    &value.safe_point.runtime,
                    value.safe_point.position,
                    U64::new(2)
                )
                .is_err()
        );
        assert!(changed.authenticate_prefix_data().is_err());

        changed = value.clone();
        changed.entries[0].state = CoordinatorCommitmentState17::Uncertain;
        assert!(
            changed
                .authenticate_structure_data(
                    &value.safe_point.runtime,
                    value.safe_point.position,
                    U64::new(2)
                )
                .is_err()
        );
        assert!(value.authenticate_policy_data(U64::new(9)).is_err());
        Ok(())
    }

    #[test]
    fn missing_nullable_and_unknown_boundary_fields_refuse_before_historical_acceptance()
    -> TestResult {
        let value = serde_json::to_value(checkpoint()?)?;
        let mut missing = value.clone();
        missing["entries"][0]
            .as_object_mut()
            .ok_or_else(refused)?
            .remove("evidence");
        assert!(serde_json::from_value::<CoordinatorCommitmentCheckpoint17>(missing).is_err());

        let mut unknown = value.clone();
        unknown["entries"][0]["kind"] = serde_json::Value::String("invented-control".into());
        assert!(serde_json::from_value::<CoordinatorCommitmentCheckpoint17>(unknown).is_err());

        let mut extra = value;
        extra["safe_point"]["authority"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<CoordinatorCommitmentCheckpoint17>(extra).is_err());
        Ok(())
    }
    #[test]
    fn initial_world_ready_cannot_be_invented_from_a_requested_ordinal() -> TestResult {
        let value = checkpoint()?;
        for axis in 0..3 {
            let mut changed = value.clone();
            match axis {
                0 => {
                    changed.entries.clear();
                    changed.next_sequence = U64::new(0);
                    changed.safe_point.event_ordinal = U64::new(0);
                }
                1 => changed.first_event_ordinal = U64::new(1),
                _ => {
                    changed.entries[1].evidence = Some(canonical::content_ref(
                        b"substituted ready evidence",
                        "application/json",
                    )?)
                }
            }
            let prefix =
                canonical::json_hash("crucible.coordinator-prefix.v17", &changed.prefix_data())?;
            changed.safe_point.prefix = prefix;
            assert!(
                changed
                    .authenticate_structure_data(
                        &changed.safe_point.runtime,
                        changed.safe_point.position,
                        changed.safe_point.event_ordinal
                    )
                    .is_err()
            );
        }
        Ok(())
    }
}
