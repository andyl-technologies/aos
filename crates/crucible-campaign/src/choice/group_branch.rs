//! Canonical proposals and selections for one atomic group branch.
//!
//! A proposal contains the complete tuple and the constraint result under the
//! exact group schema. The selected tuple produces one branch edge. Decoding
//! checks structure and derived identities; the owner must resolve the group
//! and call `validate_resolved` before execution or replay.

use crate::choice::group::{ChoiceGroup, ChoiceGroupValue, ChoiceTuple};
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::validate_identifier;
use crate::{BranchEdgeId, BranchPointId, CampaignCodecError, CampaignHash, ConfigurationId};

const GROUP_PROPOSAL_SCHEMA_VERSION: u32 = 1;
const GROUP_SELECTION_SCHEMA_VERSION: u32 = 1;
const GROUP_CONSTRAINT_SCHEMA_VERSION: u32 = 1;

/// Result of checking a complete tuple against the resolved group domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceGroupConstraintResult {
    /// Every member and relational constraint admitted the tuple.
    Admitted,
}

impl Canonical for ChoiceGroupConstraintResult {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(1);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            1 => Ok(Self::Admitted),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "choice-group-constraint-result",
                tag,
            }),
        }
    }
}

/// Versioned evidence for the constraint check retained with a group proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChoiceGroupConstraintEvidence {
    group_schema_version: u32,
    constraint_schema_version: u32,
    result: ChoiceGroupConstraintResult,
}

impl ChoiceGroupConstraintEvidence {
    fn admitted(group: &ChoiceGroup) -> Self {
        Self {
            group_schema_version: group.schema_version(),
            constraint_schema_version: GROUP_CONSTRAINT_SCHEMA_VERSION,
            result: ChoiceGroupConstraintResult::Admitted,
        }
    }

    /// Returns the exact group schema used to interpret the selected tuple.
    #[must_use]
    pub const fn group_schema_version(self) -> u32 {
        self.group_schema_version
    }

    /// Returns the exact version of the constraint-result contract.
    #[must_use]
    pub const fn constraint_schema_version(self) -> u32 {
        self.constraint_schema_version
    }

    /// Returns the recorded result of checking the complete tuple.
    #[must_use]
    pub const fn result(self) -> ChoiceGroupConstraintResult {
        self.result
    }

    fn validate_resolved(self, group: &ChoiceGroup) -> Result<(), CampaignCodecError> {
        if self.group_schema_version != group.schema_version()
            || self.constraint_schema_version != GROUP_CONSTRAINT_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group constraint evidence uses an unsupported schema",
            });
        }
        Ok(())
    }
}

impl Canonical for ChoiceGroupConstraintEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.group_schema_version.encode(encoder);
        self.constraint_schema_version.encode(encoder);
        self.result.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let evidence = Self {
            group_schema_version: u32::decode(decoder)?,
            constraint_schema_version: u32::decode(decoder)?,
            result: ChoiceGroupConstraintResult::decode(decoder)?,
        };
        if evidence.group_schema_version == 0
            || evidence.constraint_schema_version != GROUP_CONSTRAINT_SCHEMA_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group constraint evidence uses an unsupported schema",
            });
        }
        Ok(evidence)
    }
}

/// One complete, constrained tuple proposed at an exact parent and occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceGroupProposal {
    schema_version: u32,
    parent: ConfigurationId,
    instance: String,
    branch_point: BranchPointId,
    value: ChoiceGroupValue,
    constraint_evidence: ChoiceGroupConstraintEvidence,
    ordinal: u64,
}

impl ChoiceGroupProposal {
    /// Builds one proposal after checking the entire tuple against the group.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid instance, zero ordinal,
    /// incomplete tuple, or failed member or relational constraint.
    pub fn new(
        parent: ConfigurationId,
        instance: impl Into<String>,
        group: &ChoiceGroup,
        tuple: ChoiceTuple,
        ordinal: u64,
    ) -> Result<Self, CampaignCodecError> {
        let instance = instance.into();
        validate_identifier(&instance, "choice-group instance is invalid")?;
        if ordinal == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group proposal ordinal is zero",
            });
        }
        let value = group.select(tuple)?;
        let branch_point = derive_group_branch_point(parent, &instance, value.group());
        Ok(Self {
            schema_version: GROUP_PROPOSAL_SCHEMA_VERSION,
            parent,
            instance,
            branch_point,
            value,
            constraint_evidence: ChoiceGroupConstraintEvidence::admitted(group),
            ordinal,
        })
    }

    /// Returns the exact parent configuration.
    #[must_use]
    pub const fn parent(&self) -> ConfigurationId {
        self.parent
    }

    /// Returns the runtime occurrence key.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Returns the one branch point shared by every tuple for this occurrence.
    #[must_use]
    pub const fn branch_point(&self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the complete tuple and its exact group identity.
    #[must_use]
    pub const fn value(&self) -> &ChoiceGroupValue {
        &self.value
    }

    /// Returns the versioned result of validating the complete tuple.
    #[must_use]
    pub const fn constraint_evidence(&self) -> ChoiceGroupConstraintEvidence {
        self.constraint_evidence
    }

    /// Returns the one-based proposal ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Authenticates a decoded proposal against the exact group definition.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a group mismatch, invalid complete
    /// tuple, unsupported evidence version, or changed branch-point identity.
    pub fn validate_resolved(&self, group: &ChoiceGroup) -> Result<(), CampaignCodecError> {
        self.value.validate_resolved(group)?;
        self.constraint_evidence.validate_resolved(group)?;
        self.validate_structure()
    }

    /// Returns strict canonical proposal bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a proposal; call [`Self::validate_resolved`] with its exact
    /// group before admission or execution.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    fn validate_structure(&self) -> Result<(), CampaignCodecError> {
        validate_identifier(&self.instance, "choice-group instance is invalid")?;
        if self.schema_version != GROUP_PROPOSAL_SCHEMA_VERSION
            || self.ordinal == 0
            || self.branch_point
                != derive_group_branch_point(self.parent, &self.instance, self.value.group())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group proposal has inconsistent branch identity",
            });
        }
        Ok(())
    }
}

impl Canonical for ChoiceGroupProposal {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.parent.encode(encoder);
        self.instance.encode(encoder);
        self.branch_point.encode(encoder);
        self.value.encode(encoder);
        self.constraint_evidence.encode(encoder);
        self.ordinal.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let proposal = Self {
            schema_version: u32::decode(decoder)?,
            parent: ConfigurationId::decode(decoder)?,
            instance: String::decode(decoder)?,
            branch_point: BranchPointId::decode(decoder)?,
            value: ChoiceGroupValue::decode(decoder)?,
            constraint_evidence: ChoiceGroupConstraintEvidence::decode(decoder)?,
            ordinal: u64::decode(decoder)?,
        };
        proposal.validate_structure()?;
        Ok(proposal)
    }
}

/// One atomic application of a complete proposed tuple to a branch edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceGroupSelection {
    schema_version: u32,
    proposal: ChoiceGroupProposal,
    edge: BranchEdgeId,
}

impl ChoiceGroupSelection {
    /// Selects a resolved proposal and derives one edge for the complete tuple.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the proposal fails group validation.
    pub fn new(
        proposal: ChoiceGroupProposal,
        group: &ChoiceGroup,
    ) -> Result<Self, CampaignCodecError> {
        proposal.validate_resolved(group)?;
        let edge = derive_group_branch_edge(proposal.branch_point, &proposal.value);
        Ok(Self {
            schema_version: GROUP_SELECTION_SCHEMA_VERSION,
            proposal,
            edge,
        })
    }

    /// Returns the complete proposal and its constraint evidence.
    #[must_use]
    pub const fn proposal(&self) -> &ChoiceGroupProposal {
        &self.proposal
    }

    /// Returns the single edge created for the complete tuple.
    #[must_use]
    pub const fn edge(&self) -> BranchEdgeId {
        self.edge
    }

    /// Revalidates the exact group, expected parent, occurrence, and joint edge.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for identity drift, invalid constraints,
    /// or a selection at another parent or occurrence.
    pub fn validate_replay(
        &self,
        group: &ChoiceGroup,
        parent: ConfigurationId,
        instance: &str,
    ) -> Result<(), CampaignCodecError> {
        self.proposal.validate_resolved(group)?;
        if self.proposal.parent != parent
            || self.proposal.instance != instance
            || self.edge
                != derive_group_branch_edge(self.proposal.branch_point, &self.proposal.value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group selection replay identity mismatch",
            });
        }
        Ok(())
    }

    /// Returns strict canonical selection bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a selection; call [`Self::validate_replay`] against the exact
    /// runtime occurrence before applying it.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for ChoiceGroupSelection {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.proposal.encode(encoder);
        self.edge.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        let proposal = ChoiceGroupProposal::decode(decoder)?;
        let edge = BranchEdgeId::decode(decoder)?;
        if schema_version != GROUP_SELECTION_SCHEMA_VERSION
            || edge != derive_group_branch_edge(proposal.branch_point, &proposal.value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group selection has inconsistent edge identity",
            });
        }
        Ok(Self {
            schema_version,
            proposal,
            edge,
        })
    }
}

fn derive_group_branch_point(
    parent: ConfigurationId,
    instance: &str,
    group: crate::ChoiceGroupId,
) -> BranchPointId {
    let mut encoder = Encoder::new();
    parent.encode(&mut encoder);
    instance.to_owned().encode(&mut encoder);
    group.encode(&mut encoder);
    BranchPointId::from_hash(CampaignHash::derive(
        "crucible.choice-group.branch-point.v1",
        &encoder.finish(),
    ))
}

fn derive_group_branch_edge(point: BranchPointId, value: &ChoiceGroupValue) -> BranchEdgeId {
    let mut encoder = Encoder::new();
    point.encode(&mut encoder);
    value.encode(&mut encoder);
    BranchEdgeId::from_hash(CampaignHash::derive(
        "crucible.choice-group.branch-edge.v1",
        &encoder.finish(),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        AlternativeId, BooleanDomain, ChoiceClassContext, ChoiceDomain, ChoiceGroupApplication,
        ChoiceGroupDomain, ChoiceRelationalConstraint, ChoiceSource, ChoiceValue,
        SelectableDeclaration,
    };

    fn fixture() -> (ChoiceGroup, crate::SelectableId, crate::SelectableId) {
        let enabled_domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
        let mode_id = AlternativeId::from_hash(CampaignHash::derive("test.mode", b"active"));
        let mode_domain = ChoiceDomain::Discrete(
            crate::DiscreteDomain::new(
                1,
                BTreeMap::from([(
                    mode_id,
                    crate::DiscreteAlternative::new(mode_id, "active", None)
                        .expect("mode alternative"),
                )]),
            )
            .expect("mode domain"),
        );
        let context = ChoiceClassContext::new(BTreeSet::new()).expect("class context");
        let enabled = SelectableDeclaration::new(
            "fault.enabled",
            ChoiceSource::Workload {
                producer: "atomic-group-test".to_owned(),
            },
            enabled_domain.clone(),
            ChoiceValue::Boolean(false),
            context.clone(),
            BTreeSet::new(),
            true,
        )
        .expect("enabled declaration");
        let mode = SelectableDeclaration::new(
            "fault.mode",
            ChoiceSource::Workload {
                producer: "atomic-group-test".to_owned(),
            },
            mode_domain.clone(),
            ChoiceValue::Discrete(mode_id),
            context,
            BTreeSet::new(),
            true,
        )
        .expect("mode declaration");
        let enabled_id = enabled.id().expect("enabled id");
        let mode_selectable_id = mode.id().expect("mode id");
        let group = ChoiceGroup::new(
            &BTreeMap::from([(enabled_id, enabled), (mode_selectable_id, mode)]),
            ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([
                    (enabled_id, enabled_domain),
                    (mode_selectable_id, mode_domain),
                ]),
                constraints: BTreeSet::from([ChoiceRelationalConstraint::Implies {
                    if_member: mode_selectable_id,
                    if_alternative: mode_id,
                    then_member: enabled_id,
                    allowed: BTreeSet::from([ChoiceValue::Boolean(true)]),
                }]),
            },
            ChoiceGroupApplication::new("network.fault", 1).expect("application"),
        )
        .expect("group");
        (group, enabled_id, mode_selectable_id)
    }

    fn valid_tuple(enabled: crate::SelectableId, mode: crate::SelectableId) -> ChoiceTuple {
        let mode_id = AlternativeId::from_hash(CampaignHash::derive("test.mode", b"active"));
        ChoiceTuple::new(BTreeMap::from([
            (enabled, ChoiceValue::Boolean(true)),
            (mode, ChoiceValue::Discrete(mode_id)),
        ]))
    }

    #[test]
    fn complete_tuple_produces_one_replayable_edge_with_constraint_evidence() {
        let (group, enabled, mode) = fixture();
        let parent = ConfigurationId::from_hash(CampaignHash::derive("test.parent", b"one"));
        let proposal =
            ChoiceGroupProposal::new(parent, "fault.first", &group, valid_tuple(enabled, mode), 1)
                .expect("complete proposal");
        assert_eq!(
            proposal.value().group(),
            group.id().expect("group identity")
        );
        assert_eq!(
            proposal.constraint_evidence().group_schema_version(),
            group.schema_version()
        );
        assert_eq!(
            proposal.constraint_evidence().constraint_schema_version(),
            1
        );
        assert_eq!(
            proposal.constraint_evidence().result(),
            ChoiceGroupConstraintResult::Admitted
        );

        let decoded = ChoiceGroupProposal::from_canonical_bytes(&proposal.canonical_bytes())
            .expect("canonical proposal");
        decoded
            .validate_resolved(&group)
            .expect("resolved proposal");
        let selection = ChoiceGroupSelection::new(decoded, &group).expect("group selection");
        let decoded = ChoiceGroupSelection::from_canonical_bytes(&selection.canonical_bytes())
            .expect("canonical selection");
        decoded
            .validate_replay(&group, parent, "fault.first")
            .expect("exact replay");

        let same_tuple_at_another_occurrence = ChoiceGroupProposal::new(
            parent,
            "fault.followup",
            &group,
            valid_tuple(enabled, mode),
            1,
        )
        .expect("followup proposal");
        let followup = ChoiceGroupSelection::new(same_tuple_at_another_occurrence, &group)
            .expect("followup selection");
        assert_ne!(selection.edge(), followup.edge());
        assert!(
            decoded
                .validate_replay(&group, parent, "fault.followup")
                .is_err()
        );
        let different_parent =
            ConfigurationId::from_hash(CampaignHash::derive("test.parent", b"two"));
        assert!(
            decoded
                .validate_replay(&group, different_parent, "fault.first")
                .is_err()
        );
    }

    #[test]
    fn invalid_or_incomplete_tuple_and_tampered_evidence_fail_closed() {
        let (group, enabled, mode) = fixture();
        let parent = ConfigurationId::from_hash(CampaignHash::derive("test.parent", b"one"));
        let invalid = ChoiceTuple::new(BTreeMap::from([
            (enabled, ChoiceValue::Boolean(false)),
            (
                mode,
                ChoiceValue::Discrete(AlternativeId::from_hash(CampaignHash::derive(
                    "test.mode",
                    b"active",
                ))),
            ),
        ]));
        assert!(ChoiceGroupProposal::new(parent, "fault.first", &group, invalid, 1).is_err());
        assert!(
            ChoiceGroupProposal::new(
                parent,
                "fault.first",
                &group,
                ChoiceTuple::new(BTreeMap::from([(enabled, ChoiceValue::Boolean(true))])),
                1,
            )
            .is_err()
        );

        let mut proposal =
            ChoiceGroupProposal::new(parent, "fault.first", &group, valid_tuple(enabled, mode), 1)
                .expect("complete proposal");
        proposal.constraint_evidence.constraint_schema_version += 1;
        assert!(proposal.validate_resolved(&group).is_err());
        assert!(ChoiceGroupProposal::from_canonical_bytes(&proposal.canonical_bytes()).is_err());

        proposal.constraint_evidence.constraint_schema_version = 1;
        proposal.constraint_evidence.group_schema_version += 1;
        assert!(proposal.validate_resolved(&group).is_err());

        let proposal =
            ChoiceGroupProposal::new(parent, "fault.first", &group, valid_tuple(enabled, mode), 1)
                .expect("complete proposal");
        let mut selection = ChoiceGroupSelection::new(proposal, &group).expect("selection");
        selection.edge = BranchEdgeId::from_hash(CampaignHash::derive("test.edge", b"wrong"));
        assert!(ChoiceGroupSelection::from_canonical_bytes(&selection.canonical_bytes()).is_err());
    }
}
