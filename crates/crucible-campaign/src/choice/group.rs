//! Atomic multi-selectable groups, typed tuple domains, and constraints.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::choice::domain::{ChoiceDomain, ChoiceValue, IntegerDomain, IntegerValue};
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{AlternativeId, CampaignCodecError, ChoiceGroupId, SelectableId, SelectableSemanticId};

use super::model::SelectableDeclaration;

pub(crate) const CHOICE_GROUP_SCHEMA_VERSION: u32 = 3;
const MAX_GROUP_MEMBERS: usize = 64;
const MAX_GROUP_TUPLES: usize = 4096;
const MAX_GROUP_CONSTRAINTS: usize = 256;
const MAX_CONSTRAINT_VALUES: usize = 256;
const MAX_CHOICE_GROUP_BYTES: usize = 32 * 1024 * 1024;

/// Canonically member-ordered tuple of group choice values.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChoiceTuple(BTreeMap<SelectableId, ChoiceValue>);

impl ChoiceTuple {
    /// Builds a tuple whose order is always selectable-ID order.
    #[must_use]
    pub fn new(values: BTreeMap<SelectableId, ChoiceValue>) -> Self {
        Self(values)
    }

    /// Returns canonical member values.
    #[must_use]
    pub fn values(&self) -> &BTreeMap<SelectableId, ChoiceValue> {
        &self.0
    }
}

impl Canonical for ChoiceTuple {
    fn encode(&self, encoder: &mut Encoder) {
        self.0.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        decoder
            .map_bounded(MAX_GROUP_MEMBERS, "choice-group-tuple-member-count")
            .map(Self)
    }
}

/// Closed typed relational constraint admitted for a Cartesian choice group.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChoiceRelationalConstraint {
    /// Two member values must compare equal.
    Equal(SelectableId, SelectableId),
    /// The left member must be strictly less than the right member.
    LessThan(SelectableId, SelectableId),
    /// One member value must belong to an explicit finite set.
    Member(SelectableId, BTreeSet<ChoiceValue>),
    /// A discrete antecedent requires an allowed consequent set.
    Implies {
        /// Antecedent member.
        if_member: SelectableId,
        /// Antecedent alternative.
        if_alternative: AlternativeId,
        /// Consequent member.
        then_member: SelectableId,
        /// Legal consequent values when the antecedent matches.
        allowed: BTreeSet<ChoiceValue>,
    },
}

impl ChoiceRelationalConstraint {
    fn validate_types(
        &self,
        members: &BTreeMap<SelectableId, ChoiceDomain>,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::Equal(left, right) | Self::LessThan(left, right) => {
                let left_domain = members.get(left).ok_or(CampaignCodecError::InvalidValue {
                    reason: "choice-group constraint names an unknown member",
                })?;
                let right_domain = members.get(right).ok_or(CampaignCodecError::InvalidValue {
                    reason: "choice-group constraint names an unknown member",
                })?;
                match self {
                    Self::Equal(_, _)
                        if left_domain.semantic_id() == right_domain.semantic_id() =>
                    {
                        Ok(())
                    }
                    Self::LessThan(_, _) => match (left_domain, right_domain) {
                        (ChoiceDomain::Integer(left), ChoiceDomain::Integer(right))
                            if left.representation() == right.representation()
                                && left.unit() == right.unit()
                                && left.scale() == right.scale() =>
                        {
                            Ok(())
                        }
                        _ => Err(CampaignCodecError::InvalidValue {
                            reason: "choice-group ordering requires compatible integer domains",
                        }),
                    },
                    _ => Err(CampaignCodecError::InvalidValue {
                        reason: "choice-group equality requires identical domain semantics",
                    }),
                }
            }
            Self::Member(member, admitted) => {
                let domain = members
                    .get(member)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "choice-group constraint names an unknown member",
                    })?;
                if admitted.is_empty()
                    || admitted.len() > MAX_CONSTRAINT_VALUES
                    || admitted.iter().any(|value| !domain.contains(value))
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "choice-group membership set is empty or contains an illegal value",
                    });
                }
                Ok(())
            }
            Self::Implies {
                if_member,
                if_alternative,
                then_member,
                allowed,
            } => {
                let antecedent =
                    members
                        .get(if_member)
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "choice-group constraint names an unknown member",
                        })?;
                let consequent =
                    members
                        .get(then_member)
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "choice-group constraint names an unknown member",
                        })?;
                if !matches!(
                    antecedent,
                    ChoiceDomain::Discrete(domain)
                        if domain.alternatives().contains_key(if_alternative)
                ) || allowed.is_empty()
                    || allowed.len() > MAX_CONSTRAINT_VALUES
                    || allowed.iter().any(|value| !consequent.contains(value))
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "choice-group implication has an illegal antecedent or consequent",
                    });
                }
                Ok(())
            }
        }
    }

    fn accepts(&self, tuple: &ChoiceTuple) -> bool {
        match self {
            Self::Equal(left, right) => tuple.0.get(left) == tuple.0.get(right),
            Self::LessThan(left, right) => {
                tuple
                    .0
                    .get(left)
                    .zip(tuple.0.get(right))
                    .and_then(|(left, right)| comparable_order(left, right))
                    == Some(Ordering::Less)
            }
            Self::Member(member, admitted) => tuple
                .0
                .get(member)
                .is_some_and(|value| admitted.contains(value)),
            Self::Implies {
                if_member,
                if_alternative,
                then_member,
                allowed,
            } => {
                if tuple.0.get(if_member) == Some(&ChoiceValue::Discrete(*if_alternative)) {
                    tuple
                        .0
                        .get(then_member)
                        .is_some_and(|value| allowed.contains(value))
                } else {
                    true
                }
            }
        }
    }
}

impl Canonical for ChoiceRelationalConstraint {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Equal(left, right) => {
                encoder.u8(0);
                left.encode(encoder);
                right.encode(encoder);
            }
            Self::LessThan(left, right) => {
                encoder.u8(1);
                left.encode(encoder);
                right.encode(encoder);
            }
            Self::Member(member, admitted) => {
                encoder.u8(2);
                member.encode(encoder);
                admitted.encode(encoder);
            }
            Self::Implies {
                if_member,
                if_alternative,
                then_member,
                allowed,
            } => {
                encoder.u8(3);
                if_member.encode(encoder);
                if_alternative.encode(encoder);
                then_member.encode(encoder);
                allowed.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Equal(
                SelectableId::decode(decoder)?,
                SelectableId::decode(decoder)?,
            )),
            1 => Ok(Self::LessThan(
                SelectableId::decode(decoder)?,
                SelectableId::decode(decoder)?,
            )),
            2 => Ok(Self::Member(
                SelectableId::decode(decoder)?,
                decoder.set_bounded(MAX_CONSTRAINT_VALUES, "choice-constraint-value-count")?,
            )),
            3 => Ok(Self::Implies {
                if_member: SelectableId::decode(decoder)?,
                if_alternative: AlternativeId::decode(decoder)?,
                then_member: SelectableId::decode(decoder)?,
                allowed: decoder
                    .set_bounded(MAX_CONSTRAINT_VALUES, "choice-constraint-value-count")?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "choice-relational-constraint",
                tag,
            }),
        }
    }
}

/// Finite tuple set or lazy constrained Cartesian group domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChoiceGroupDomain {
    /// Explicit finite admitted tuple set.
    Finite {
        /// Member domains used to type-check every explicit tuple.
        members: BTreeMap<SelectableId, ChoiceDomain>,
        /// Complete explicit tuple set.
        tuples: BTreeSet<ChoiceTuple>,
    },
    /// Product of independent members with closed typed constraints.
    Cartesian {
        /// Member domains keyed in canonical selectable-ID order.
        members: BTreeMap<SelectableId, ChoiceDomain>,
        /// Constraints all yielded tuples must satisfy.
        constraints: BTreeSet<ChoiceRelationalConstraint>,
    },
}

impl ChoiceGroupDomain {
    fn member_domains(&self) -> &BTreeMap<SelectableId, ChoiceDomain> {
        match self {
            Self::Finite { members, .. } | Self::Cartesian { members, .. } => members,
        }
    }

    fn validate_shape(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Finite { members, tuples } => {
                if members.is_empty()
                    || members.len() > MAX_GROUP_MEMBERS
                    || tuples.is_empty()
                    || tuples.len() > MAX_GROUP_TUPLES
                    || members
                        .values()
                        .any(|domain| matches!(domain, ChoiceDomain::Group(_)))
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finite choice-group tuple set is empty or oversized",
                    });
                }
                if tuples.iter().any(|tuple| {
                    tuple.0.len() != members.len()
                        || members.iter().any(|(id, domain)| {
                            tuple.0.get(id).is_none_or(|value| !domain.contains(value))
                        })
                }) {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finite choice-group tuple violates a member domain",
                    });
                }
            }
            Self::Cartesian {
                members,
                constraints,
            } => {
                if members.is_empty()
                    || members.len() > MAX_GROUP_MEMBERS
                    || constraints.len() > MAX_GROUP_CONSTRAINTS
                    || members
                        .values()
                        .any(|domain| matches!(domain, ChoiceDomain::Group(_)))
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "Cartesian choice group is empty or oversized",
                    });
                }
                for constraint in constraints {
                    constraint.validate_types(members)?;
                }
            }
        }
        Ok(())
    }

    /// Returns whether a complete tuple is admitted by every member and constraint.
    #[must_use]
    pub fn contains(&self, tuple: &ChoiceTuple) -> bool {
        match self {
            Self::Finite { tuples, .. } => tuples.contains(tuple),
            Self::Cartesian {
                members,
                constraints,
            } => {
                tuple.0.len() == members.len()
                    && members.iter().all(|(id, domain)| {
                        tuple.0.get(id).is_some_and(|value| domain.contains(value))
                    })
                    && constraints
                        .iter()
                        .all(|constraint| constraint.accepts(tuple))
            }
        }
    }
}

impl Canonical for ChoiceGroupDomain {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Finite { members, tuples } => {
                encoder.u8(0);
                members.encode(encoder);
                tuples.encode(encoder);
            }
            Self::Cartesian {
                members,
                constraints,
            } => {
                encoder.u8(1);
                members.encode(encoder);
                constraints.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let domain = match decoder.u8()? {
            0 => Self::Finite {
                members: decoder.map_bounded(MAX_GROUP_MEMBERS, "choice-group-member-count")?,
                tuples: decoder.set_bounded(MAX_GROUP_TUPLES, "choice-group-tuple-count")?,
            },
            1 => Self::Cartesian {
                members: decoder.map_bounded(MAX_GROUP_MEMBERS, "choice-group-member-count")?,
                constraints: decoder
                    .set_bounded(MAX_GROUP_CONSTRAINTS, "choice-group-constraint-count")?,
            },
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "choice-group-domain",
                    tag,
                });
            }
        };
        domain.validate_shape()?;
        Ok(domain)
    }
}

/// Named typed adapter transaction used to apply a group atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceGroupApplication {
    adapter: String,
    version: u32,
}

impl ChoiceGroupApplication {
    /// Builds a versioned group application contract.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid adapter or zero version.
    pub fn new(adapter: impl Into<String>, version: u32) -> Result<Self, CampaignCodecError> {
        let adapter = adapter.into();
        validate_identifier(&adapter, "choice-group application adapter is invalid")?;
        if version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group application version is zero",
            });
        }
        Ok(Self { adapter, version })
    }

    /// Returns the named atomic application adapter.
    #[must_use]
    pub fn adapter(&self) -> &str {
        &self.adapter
    }

    /// Returns the adapter contract version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

impl Canonical for ChoiceGroupApplication {
    fn encode(&self, encoder: &mut Encoder) {
        self.adapter.encode(encoder);
        self.version.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-group-adapter-name-bytes")?,
            u32::decode(decoder)?,
        )
    }
}

/// Atomically applied member group with a closed tuple domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceGroup {
    schema_version: u32,
    members: BTreeSet<SelectableId>,
    declaration_semantics: BTreeMap<SelectableId, SelectableSemanticId>,
    declarations: BTreeMap<SelectableId, SelectableDeclaration>,
    domain: ChoiceGroupDomain,
    application: ChoiceGroupApplication,
}

impl ChoiceGroup {
    /// Builds a group whose members are bound to exact declarations.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for empty, oversized, inconsistent, or
    /// invalid group domains.
    pub fn new(
        declarations: &BTreeMap<SelectableId, SelectableDeclaration>,
        domain: ChoiceGroupDomain,
        application: ChoiceGroupApplication,
    ) -> Result<Self, CampaignCodecError> {
        let members = declarations.keys().copied().collect::<BTreeSet<_>>();
        for (id, declaration) in declarations {
            if *id != declaration.id()? {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "choice group declaration key disagrees with its content identity",
                });
            }
        }
        let declaration_semantics = declarations
            .iter()
            .map(|(id, declaration)| (*id, declaration.semantic_id()))
            .collect();
        let group = Self::new_structural(
            members,
            declaration_semantics,
            declarations.clone(),
            domain,
            application,
        )?;
        group.validate_declarations(declarations)?;
        Ok(group)
    }

    fn new_structural(
        members: BTreeSet<SelectableId>,
        declaration_semantics: BTreeMap<SelectableId, SelectableSemanticId>,
        declarations: BTreeMap<SelectableId, SelectableDeclaration>,
        domain: ChoiceGroupDomain,
        application: ChoiceGroupApplication,
    ) -> Result<Self, CampaignCodecError> {
        if members.is_empty() || members.len() > MAX_GROUP_MEMBERS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice group member set is empty or oversized",
            });
        }
        domain.validate_shape()?;
        let shape_matches = domain
            .member_domains()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            == members
            && declaration_semantics
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                == members
            && declarations.keys().copied().collect::<BTreeSet<_>>() == members;
        if !shape_matches {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice group domain members disagree with group members",
            });
        }
        let group = Self {
            schema_version: CHOICE_GROUP_SCHEMA_VERSION,
            members,
            declaration_semantics,
            declarations,
            domain,
            application,
        };
        group.validate_declarations(&group.declarations)?;
        codec::ensure_encoded_size(&group, MAX_CHOICE_GROUP_BYTES, "choice-group-encoded-bytes")?;
        Ok(group)
    }

    /// Revalidates every member's exact declaration and narrowed domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when declarations are missing, renamed,
    /// semantically changed, or paired with a widening/incompatible domain.
    pub fn validate_declarations(
        &self,
        declarations: &BTreeMap<SelectableId, SelectableDeclaration>,
    ) -> Result<(), CampaignCodecError> {
        if declarations.keys().copied().collect::<BTreeSet<_>>() != self.members {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice group declarations disagree with group members",
            });
        }
        for (id, declaration) in declarations {
            let domain =
                self.domain
                    .member_domains()
                    .get(id)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "choice group member domain is missing",
                    })?;
            if *id != declaration.id()?
                || self.declaration_semantics.get(id) != Some(&declaration.semantic_id())
                || !domain.is_subset_of(declaration.domain())
                || !domain.contains(declaration.default())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "choice group member domain disagrees with its declaration",
                });
            }
        }
        Ok(())
    }

    /// Returns the canonical group member set.
    #[must_use]
    pub const fn members(&self) -> &BTreeSet<SelectableId> {
        &self.members
    }

    /// Returns each exact member's presentation-independent declaration identity.
    #[must_use]
    pub const fn declaration_semantics(&self) -> &BTreeMap<SelectableId, SelectableSemanticId> {
        &self.declaration_semantics
    }

    /// Returns the exact member declarations carried by this group schema.
    #[must_use]
    pub const fn declarations(&self) -> &BTreeMap<SelectableId, SelectableDeclaration> {
        &self.declarations
    }

    /// Returns the typed finite or Cartesian group domain.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceGroupDomain {
        &self.domain
    }

    /// Returns the atomic application contract.
    #[must_use]
    pub const fn application(&self) -> &ChoiceGroupApplication {
        &self.application
    }

    /// Returns the exact schema used to interpret this group's constraints.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the stable group identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ChoiceGroupId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceGroup,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        ChoiceGroupId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(String, crucible_cas::content_store::ContentId)> {
        self.members
            .iter()
            .map(|member| ("member".to_owned(), member.content_id()))
            .collect()
    }

    /// Validates a proposed tuple before atomic application.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the tuple is incomplete or violates
    /// a member domain or relational constraint.
    pub fn select(&self, tuple: ChoiceTuple) -> Result<ChoiceGroupValue, CampaignCodecError> {
        if !self.domain.contains(&tuple) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group tuple is not admitted",
            });
        }
        Ok(ChoiceGroupValue {
            group: self.id()?,
            tuple,
        })
    }

    /// Returns whether bounded tuple generation has an unconstrained integer
    /// member that distinguishes every emitted proposal.
    #[must_use]
    pub fn supports_progressive_generation(&self, maximum_proposals: u32) -> bool {
        self.progressive_identity_member(maximum_proposals)
            .is_some()
            && self.progressive_fixed_members().is_some()
    }

    /// Produces one complete tuple under the bounded group generator contract.
    ///
    /// An unconstrained integer member emits its default, boundaries, and
    /// landmarks before the remaining stepped range. This gives every emitted
    /// tuple a distinct identity without enumerating a large Cartesian product.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unsupported group, an ordinal
    /// outside the generator bound, or a conflicting constraint set.
    pub fn progressive_candidate(
        &self,
        ordinal: u64,
        maximum_proposals: u32,
    ) -> Result<ChoiceGroupValue, CampaignCodecError> {
        if ordinal == 0 || ordinal > u64::from(maximum_proposals) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "group proposal ordinal exceeds its bound",
            });
        }
        let identity = self.progressive_identity_member(maximum_proposals).ok_or(
            CampaignCodecError::InvalidValue {
                reason: "group does not support bounded progressive generation",
            },
        )?;
        let fixed_members =
            self.progressive_fixed_members()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "group generator constraints have no common admitted values",
                })?;
        let ChoiceGroupDomain::Cartesian { members, .. } = &self.domain else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "group progressive generation requires a Cartesian domain",
            });
        };

        let mut values = BTreeMap::new();
        for (id, domain) in members {
            let declaration =
                self.declarations
                    .get(id)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "group generator member declaration is missing",
                    })?;
            values.insert(
                *id,
                group_member_candidate(domain, declaration.default(), ordinal, *id == identity)?,
            );
        }
        // Constrained antecedents use a stable common value before evaluating
        // implications. Other consequents can still vary when the implication
        // for the current discrete choice does not apply.
        for (id, value) in fixed_members {
            if matches!(members.get(&id), Some(ChoiceDomain::Discrete(_))) {
                values.insert(id, value);
            }
        }
        let ChoiceGroupDomain::Cartesian { constraints, .. } = &self.domain else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "group progressive generation requires a Cartesian domain",
            });
        };
        let mut active: BTreeMap<SelectableId, BTreeSet<ChoiceValue>> = BTreeMap::new();
        for constraint in constraints {
            let admitted = match constraint {
                ChoiceRelationalConstraint::Member(member, allowed) => Some((member, allowed)),
                ChoiceRelationalConstraint::Implies {
                    if_member,
                    if_alternative,
                    then_member,
                    allowed,
                } if values.get(if_member) == Some(&ChoiceValue::Discrete(*if_alternative)) => {
                    Some((then_member, allowed))
                }
                _ => None,
            };
            if let Some((member, allowed)) = admitted {
                active
                    .entry(*member)
                    .and_modify(|common| common.retain(|value| allowed.contains(value)))
                    .or_insert_with(|| allowed.clone());
            }
        }
        for (id, admitted) in active {
            if !values
                .get(&id)
                .is_some_and(|value| admitted.contains(value))
            {
                let selected =
                    admitted
                        .into_iter()
                        .next()
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "group generator active constraints conflict",
                        })?;
                values.insert(id, selected);
            }
        }
        self.select(ChoiceTuple::new(values))
    }

    fn progressive_fixed_members(&self) -> Option<BTreeMap<SelectableId, ChoiceValue>> {
        let ChoiceGroupDomain::Cartesian { constraints, .. } = &self.domain else {
            return None;
        };
        let mut intersections: BTreeMap<SelectableId, BTreeSet<ChoiceValue>> = BTreeMap::new();
        for constraint in constraints {
            let (member, allowed) = match constraint {
                ChoiceRelationalConstraint::Member(member, allowed) => (member, allowed),
                ChoiceRelationalConstraint::Implies {
                    then_member,
                    allowed,
                    ..
                } => (then_member, allowed),
                ChoiceRelationalConstraint::Equal(_, _)
                | ChoiceRelationalConstraint::LessThan(_, _) => return None,
            };
            intersections
                .entry(*member)
                .and_modify(|common| common.retain(|value| allowed.contains(value)))
                .or_insert_with(|| allowed.clone());
        }
        intersections
            .into_iter()
            .map(|(member, values)| values.into_iter().next().map(|value| (member, value)))
            .collect()
    }

    fn progressive_identity_member(&self, maximum_proposals: u32) -> Option<SelectableId> {
        if maximum_proposals == 0 {
            return None;
        }
        let ChoiceGroupDomain::Cartesian {
            members,
            constraints,
        } = &self.domain
        else {
            return None;
        };
        if constraints.iter().any(|constraint| {
            matches!(
                constraint,
                ChoiceRelationalConstraint::Equal(_, _)
                    | ChoiceRelationalConstraint::LessThan(_, _)
            )
        }) {
            return None;
        }
        members.iter().find_map(|(id, domain)| {
            let ChoiceDomain::Integer(integer) = domain else {
                return None;
            };
            (integer.cardinality() >= u128::from(maximum_proposals)
                && !constraints.iter().any(|constraint| match constraint {
                    ChoiceRelationalConstraint::Member(member, _) => member == id,
                    ChoiceRelationalConstraint::Implies { then_member, .. } => then_member == id,
                    _ => false,
                }))
            .then_some(*id)
        })
    }
}

fn group_member_candidate(
    domain: &ChoiceDomain,
    default: &ChoiceValue,
    ordinal: u64,
    identity: bool,
) -> Result<ChoiceValue, CampaignCodecError> {
    let offset = u128::from(ordinal - 1);
    match domain {
        ChoiceDomain::Boolean(_) => Ok(ChoiceValue::Boolean(ordinal.is_multiple_of(2))),
        ChoiceDomain::Discrete(discrete) => {
            let index =
                usize::try_from(offset % discrete.alternatives().len() as u128).map_err(|_| {
                    CampaignCodecError::InvalidValue {
                        reason: "group discrete candidate index overflow",
                    }
                })?;
            discrete
                .alternatives()
                .keys()
                .nth(index)
                .copied()
                .map(ChoiceValue::Discrete)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "group discrete candidate is missing",
                })
        }
        ChoiceDomain::Integer(integer) if identity => {
            let anchors = integer_anchors(integer, default);
            if let Some(value) = anchors.get(usize::try_from(offset).unwrap_or(usize::MAX)) {
                return Ok(ChoiceValue::Integer(*value));
            }

            // Skip anchors while walking the stepped range, so the integer
            // member remains a one-to-one proof of proposal identity.
            let mut candidate_offset = offset - anchors.len() as u128;
            let anchor_offsets = anchors
                .into_iter()
                .map(|anchor| integer.offset_of(anchor))
                .collect::<Result<BTreeSet<_>, _>>()?;
            for anchor_offset in anchor_offsets {
                if anchor_offset <= candidate_offset {
                    candidate_offset += 1;
                }
            }
            integer
                .value_at_offset(candidate_offset)
                .map(ChoiceValue::Integer)
        }
        ChoiceDomain::Integer(integer) => {
            let anchors = integer_anchors(integer, default);
            if let Some(value) = anchors.get(usize::try_from(offset).unwrap_or(usize::MAX)) {
                Ok(ChoiceValue::Integer(*value))
            } else {
                let offset = (offset - anchors.len() as u128) % integer.cardinality();
                integer.value_at_offset(offset).map(ChoiceValue::Integer)
            }
        }
        ChoiceDomain::Group(_) => Err(CampaignCodecError::InvalidValue {
            reason: "group generator cannot nest atomic groups",
        }),
    }
}

fn integer_anchors(integer: &IntegerDomain, default: &ChoiceValue) -> Vec<IntegerValue> {
    let mut anchors = Vec::with_capacity(integer.landmarks().len() + 3);
    for anchor in std::iter::once(default)
        .chain(std::iter::once(&ChoiceValue::Integer(integer.minimum())))
        .chain(std::iter::once(&ChoiceValue::Integer(integer.maximum())))
    {
        if let ChoiceValue::Integer(value) = anchor
            && !anchors.contains(value)
        {
            anchors.push(*value);
        }
    }
    for landmark in integer.landmarks() {
        if !anchors.contains(landmark) {
            anchors.push(*landmark);
        }
    }
    anchors
}

impl Canonical for ChoiceGroup {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        // Exact member IDs and semantics are derivable from the declarations.
        // Keeping only one copy makes a complete group fit the guest envelope.
        self.declarations.encode(encoder);
        self.domain.encode(encoder);
        self.application.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != CHOICE_GROUP_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported choice-group schema version",
            });
        }
        let declarations: BTreeMap<SelectableId, SelectableDeclaration> =
            decoder.map_bounded(MAX_GROUP_MEMBERS, "choice-group-declaration-count")?;
        let members = declarations.keys().copied().collect();
        let declaration_semantics = declarations
            .iter()
            .map(|(id, declaration)| (*id, declaration.semantic_id()))
            .collect();

        Self::new_structural(
            members,
            declaration_semantics,
            declarations,
            ChoiceGroupDomain::decode(decoder)?,
            ChoiceGroupApplication::decode(decoder)?,
        )
    }
}

/// Validated atomically applied value for one choice group.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChoiceGroupValue {
    group: ChoiceGroupId,
    tuple: ChoiceTuple,
}

impl ChoiceGroupValue {
    /// Returns the group whose application contract owns the transaction.
    #[must_use]
    pub const fn group(&self) -> ChoiceGroupId {
        self.group
    }

    /// Returns the complete canonical member tuple.
    #[must_use]
    pub const fn tuple(&self) -> &ChoiceTuple {
        &self.tuple
    }

    /// Revalidates a decoded value against its exact group and constraints.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the group identity differs or the
    /// complete tuple is not admitted by its member domains and constraints.
    pub fn validate_resolved(&self, group: &ChoiceGroup) -> Result<(), CampaignCodecError> {
        if self.group != group.id()? || !group.domain.contains(&self.tuple) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-group value disagrees with its resolved group",
            });
        }
        Ok(())
    }

    /// Returns the strict canonical value bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a structurally valid group value; call [`Self::validate_resolved`]
    /// before accepting it as a selection.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed or noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for ChoiceGroupValue {
    fn encode(&self, encoder: &mut Encoder) {
        self.group.encode(encoder);
        self.tuple.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            group: ChoiceGroupId::decode(decoder)?,
            tuple: ChoiceTuple::decode(decoder)?,
        })
    }
}

fn comparable_order(left: &ChoiceValue, right: &ChoiceValue) -> Option<Ordering> {
    match (left, right) {
        (ChoiceValue::Boolean(left), ChoiceValue::Boolean(right)) => Some(left.cmp(right)),
        (ChoiceValue::Discrete(left), ChoiceValue::Discrete(right)) => Some(left.cmp(right)),
        (
            ChoiceValue::Integer(IntegerValue::Signed(left)),
            ChoiceValue::Integer(IntegerValue::Signed(right)),
        ) => Some(left.cmp(right)),
        (
            ChoiceValue::Integer(IntegerValue::Unsigned(left)),
            ChoiceValue::Integer(IntegerValue::Unsigned(right)),
        ) => Some(left.cmp(right)),
        _ => None,
    }
}
