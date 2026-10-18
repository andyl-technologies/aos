//! Guest encoding of Cartesian groups in campaign wire format.
//!
//! Campaign admission validates the complete group. This L1 encoder emits its
//! exact canonical bytes and identities without linking host campaign state.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    AlternativeId, CHOICE_DOMAIN_SCHEMA_VERSION, ChoiceCodecError, ChoiceDomain, ChoiceValue,
    Decoder, Encoder, IntegerValue, decode_value, encode_domain, encode_value,
};
use crate::{SELECTABLE_MESSAGE_MAX_BYTES, SELECTABLE_PROTOCOL_VERSION};

const MAX_GROUP_MEMBERS: usize = 64;
const MAX_GROUP_CONSTRAINTS: usize = 256;
const MAX_CONSTRAINT_VALUES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 512;
const SELECTABLE_TAG: &str = "crucible.campaign.selectable-declaration";
const GROUP_TAG: &str = "crucible.campaign.choice-group";
const DOMAIN_TAG: &str = "crucible.campaign.choice-domain";

#[derive(Clone, Debug, PartialEq, Eq)]
struct GroupMember {
    name: String,
    domain: ChoiceDomain,
    default: ChoiceValue,
    id: ContentIdentity,
    declaration_bytes: Vec<u8>,
}

/// A typed relational condition over guest-declared member names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestChoiceConstraint {
    /// Requires equal member values from semantically identical domains.
    Equal(String, String),
    /// Requires the left compatible integer to be strictly smaller.
    LessThan(String, String),
    /// Requires one member's value to belong to a finite admitted set.
    Member(String, BTreeSet<ChoiceValue>),
    /// Requires an admitted consequent when a discrete antecedent matches.
    Implies {
        /// Name of the antecedent member.
        if_member: String,
        /// Alternative that activates the condition.
        if_alternative: AlternativeId,
        /// Name of the consequent member.
        then_member: String,
        /// Admitted consequent values.
        allowed: BTreeSet<ChoiceValue>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResolvedConstraint {
    Equal([u8; 32], [u8; 32]),
    LessThan([u8; 32], [u8; 32]),
    Member([u8; 32], BTreeSet<ChoiceValue>),
    Implies {
        if_member: [u8; 32],
        if_alternative: AlternativeId,
        then_member: [u8; 32],
        allowed: BTreeSet<ChoiceValue>,
    },
}

/// A guest-declared atomic group with campaign-compatible wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestChoiceGroup {
    members: BTreeMap<[u8; 32], GroupMember>,
    constraints: BTreeSet<ResolvedConstraint>,
    id: ContentIdentity,
    domain_bytes: Vec<u8>,
    default_bytes: Vec<u8>,
}

impl GuestChoiceGroup {
    /// Builds a group of scalar members with typed relational constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for invalid identifiers, member counts,
    /// duplicate names or identities, invalid constraints, or illegal defaults.
    pub fn new(
        node: &str,
        adapter: &str,
        application_version: u32,
        members: Vec<(String, ChoiceDomain, ChoiceValue)>,
        constraints: BTreeSet<GuestChoiceConstraint>,
    ) -> Result<Self, ChoiceCodecError> {
        validate_identifier(node)?;
        validate_identifier(adapter)?;
        if application_version == 0 || members.is_empty() || members.len() > MAX_GROUP_MEMBERS {
            return Err(invalid("guest group version or member count is invalid"));
        }

        let mut by_id = BTreeMap::new();
        let mut by_name = BTreeSet::new();
        let mut minimum_wire_bytes = 0_usize;
        for (name, domain, default) in members {
            validate_identifier(&name)?;
            if !by_name.insert(name.clone()) || !domain.contains(&default) {
                return Err(invalid(
                    "guest group member is duplicate or its default is illegal",
                ));
            }
            // Each member is encoded at least once in the registration. Bound
            // the aggregate before duplicating declarations into a group.
            minimum_wire_bytes = minimum_wire_bytes
                .checked_add(name.len())
                .and_then(|size| size.checked_add(scalar_domain_size(&domain)))
                .and_then(|size| size.checked_add(scalar_value_size(&default)))
                .ok_or(ChoiceCodecError::LimitExceeded {
                    limit: "guest-selectable-envelope-bytes",
                })?;
            if minimum_wire_bytes > SELECTABLE_MESSAGE_MAX_BYTES {
                return Err(ChoiceCodecError::LimitExceeded {
                    limit: "guest-selectable-envelope-bytes",
                });
            }
            let declaration_bytes = encode_declaration(&name, node, &domain, &default);
            let id = content_identity(SELECTABLE_TAG, 1, &[], &declaration_bytes);
            if by_id
                .insert(
                    id.digest,
                    GroupMember {
                        name,
                        domain,
                        default,
                        id,
                        declaration_bytes,
                    },
                )
                .is_some()
            {
                return Err(invalid("guest group declaration identities collide"));
            }
        }

        if constraints.len() > MAX_GROUP_CONSTRAINTS {
            return Err(invalid("guest group has too many relational constraints"));
        }
        let constraints = constraints
            .iter()
            .map(|constraint| resolve_constraint(constraint, &by_id))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let defaults = by_id
            .iter()
            .map(|(id, member)| (*id, member.default.clone()))
            .collect();
        if !constraints
            .iter()
            .all(|constraint| constraint.accepts(&defaults))
        {
            return Err(invalid(
                "guest group default violates a relational constraint",
            ));
        }

        // Constraint sets can be much larger than the scalar members. Bound
        // their aggregate before encoding the canonical group and envelope.
        let constraint_bytes = constraints
            .iter()
            .map(ResolvedConstraint::encoded_size)
            .fold(0_usize, usize::saturating_add);
        if minimum_wire_bytes.saturating_add(constraint_bytes) > SELECTABLE_MESSAGE_MAX_BYTES {
            return Err(ChoiceCodecError::LimitExceeded {
                limit: "guest-selectable-envelope-bytes",
            });
        }

        let group_bytes = encode_group(&by_id, &constraints, adapter, application_version);
        let children = by_id
            .values()
            .map(|member| ("member", member.id))
            .collect::<Vec<_>>();
        let id = content_identity(GROUP_TAG, 3, &children, &group_bytes);
        let domain_bytes = encode_group_domain(&group_bytes);
        let default_bytes = encode_tuple_value(&id, &by_id);
        if domain_bytes.len().saturating_add(default_bytes.len()) > SELECTABLE_MESSAGE_MAX_BYTES {
            return Err(ChoiceCodecError::LimitExceeded {
                limit: "guest-selectable-envelope-bytes",
            });
        }
        Ok(Self {
            members: by_id,
            constraints,
            id,
            domain_bytes,
            default_bytes,
        })
    }

    /// Returns the canonical group-domain registration bytes.
    #[must_use]
    pub fn domain_bytes(&self) -> &[u8] {
        &self.domain_bytes
    }

    /// Returns the canonical complete default tuple bytes.
    #[must_use]
    pub fn default_bytes(&self) -> &[u8] {
        &self.default_bytes
    }

    /// Returns the exact domain content digest carried by a selected reply.
    #[must_use]
    pub fn domain_digest(&self) -> [u8; 32] {
        content_identity(
            DOMAIN_TAG,
            CHOICE_DOMAIN_SCHEMA_VERSION,
            &[("group", self.id)],
            &self.domain_bytes,
        )
        .digest
    }

    /// Decodes and validates a complete selected tuple for this group.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for malformed, incomplete, foreign, or
    /// out-of-domain tuples.
    pub fn decode_selection(
        &self,
        bytes: &[u8],
    ) -> Result<BTreeMap<String, ChoiceValue>, ChoiceCodecError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != 3 || decode_typed_id(&mut decoder, GROUP_TAG, 3)? != self.id {
            return Err(invalid("selected value has the wrong atomic group"));
        }
        let count = decoder.count(MAX_GROUP_MEMBERS, "choice-group-tuple-member-count")?;
        if count != self.members.len() {
            return Err(invalid("selected group tuple is incomplete"));
        }
        let mut values = BTreeMap::new();
        let mut tuple = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let id = decode_typed_id(&mut decoder, SELECTABLE_TAG, 1)?;
            if previous.is_some_and(|previous| previous >= id.digest) {
                return Err(ChoiceCodecError::NonCanonical);
            }
            previous = Some(id.digest);
            let member = self
                .members
                .get(&id.digest)
                .ok_or(invalid("selected group tuple names an unknown member"))?;
            let value = decode_value(&mut decoder)?;
            if !member.domain.contains(&value) {
                return Err(invalid("selected group member is outside its domain"));
            }
            values.insert(member.name.clone(), value.clone());
            tuple.insert(id.digest, value);
        }
        decoder.finish()?;
        if !self
            .constraints
            .iter()
            .all(|constraint| constraint.accepts(&tuple))
        {
            return Err(invalid(
                "selected group tuple violates a relational constraint",
            ));
        }
        Ok(values)
    }
}

fn encode_declaration(
    name: &str,
    node: &str,
    domain: &ChoiceDomain,
    default: &ChoiceValue,
) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u32(1);
    encoder.string(name);
    encoder.u8(1); // Guest source.
    encoder.string(node);
    encoder.u32(u32::from(SELECTABLE_PROTOCOL_VERSION));
    encode_domain(&mut encoder, domain);
    encode_value(&mut encoder, default);
    encoder.u64(0); // Class context tags.
    encoder.u64(0); // Semantic tags.
    encoder.bool(true);
    encoder.bytes
}

fn encode_group(
    members: &BTreeMap<[u8; 32], GroupMember>,
    constraints: &BTreeSet<ResolvedConstraint>,
    adapter: &str,
    application_version: u32,
) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u32(3);
    encoder.u64(members.len() as u64);
    for member in members.values() {
        encode_typed_id(&mut encoder, SELECTABLE_TAG, &member.id);
        encoder.bytes.extend_from_slice(&member.declaration_bytes);
    }
    encoder.u8(1); // Cartesian domain.
    encoder.u64(members.len() as u64);
    for member in members.values() {
        encode_typed_id(&mut encoder, SELECTABLE_TAG, &member.id);
        encode_domain(&mut encoder, &member.domain);
    }
    encoder.u64(constraints.len() as u64);
    for constraint in constraints {
        constraint.encode(&mut encoder, members);
    }
    encoder.string(adapter);
    encoder.u32(application_version);
    encoder.bytes
}

fn encode_group_domain(group_bytes: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u32(CHOICE_DOMAIN_SCHEMA_VERSION);
    encoder.u8(3);
    encoder.bytes.extend_from_slice(group_bytes);
    encoder.bytes
}

fn encode_tuple_value(
    group: &ContentIdentity,
    members: &BTreeMap<[u8; 32], GroupMember>,
) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u8(3);
    encode_typed_id(&mut encoder, GROUP_TAG, group);
    encoder.u64(members.len() as u64);
    for member in members.values() {
        encode_typed_id(&mut encoder, SELECTABLE_TAG, &member.id);
        encode_value(&mut encoder, &member.default);
    }
    encoder.bytes
}

fn resolve_constraint(
    constraint: &GuestChoiceConstraint,
    members: &BTreeMap<[u8; 32], GroupMember>,
) -> Result<ResolvedConstraint, ChoiceCodecError> {
    let member = |name: &str| {
        members
            .values()
            .find(|member| member.name == name)
            .ok_or(invalid("guest group constraint names an unknown member"))
    };
    match constraint {
        GuestChoiceConstraint::Equal(left, right) => {
            let left = member(left)?;
            let right = member(right)?;
            if !same_semantic_domain(&left.domain, &right.domain) {
                return Err(invalid(
                    "group equality requires identical domain semantics",
                ));
            }
            Ok(ResolvedConstraint::Equal(left.id.digest, right.id.digest))
        }
        GuestChoiceConstraint::LessThan(left, right) => {
            let left = member(left)?;
            let right = member(right)?;
            let (ChoiceDomain::Integer(left_domain), ChoiceDomain::Integer(right_domain)) =
                (&left.domain, &right.domain)
            else {
                return Err(invalid(
                    "group ordering requires compatible integer domains",
                ));
            };
            if left_domain.representation != right_domain.representation
                || left_domain.unit != right_domain.unit
                || left_domain.scale != right_domain.scale
            {
                return Err(invalid(
                    "group ordering requires compatible integer domains",
                ));
            }
            Ok(ResolvedConstraint::LessThan(
                left.id.digest,
                right.id.digest,
            ))
        }
        GuestChoiceConstraint::Member(name, admitted) => {
            let member = member(name)?;
            validate_admitted(&member.domain, admitted)?;
            Ok(ResolvedConstraint::Member(
                member.id.digest,
                admitted.clone(),
            ))
        }
        GuestChoiceConstraint::Implies {
            if_member,
            if_alternative,
            then_member,
            allowed,
        } => {
            let antecedent = member(if_member)?;
            let consequent = member(then_member)?;
            if !matches!(&antecedent.domain, ChoiceDomain::Discrete(domain)
                if domain.alternatives.contains_key(if_alternative))
            {
                return Err(invalid("group implication has an illegal antecedent"));
            }
            validate_admitted(&consequent.domain, allowed)?;
            Ok(ResolvedConstraint::Implies {
                if_member: antecedent.id.digest,
                if_alternative: *if_alternative,
                then_member: consequent.id.digest,
                allowed: allowed.clone(),
            })
        }
    }
}

fn validate_admitted(
    domain: &ChoiceDomain,
    admitted: &BTreeSet<ChoiceValue>,
) -> Result<(), ChoiceCodecError> {
    if admitted.is_empty()
        || admitted.len() > MAX_CONSTRAINT_VALUES
        || admitted.iter().any(|value| !domain.contains(value))
    {
        return Err(invalid(
            "group constraint has an empty or illegal value set",
        ));
    }
    Ok(())
}

fn same_semantic_domain(left: &ChoiceDomain, right: &ChoiceDomain) -> bool {
    match (left, right) {
        (ChoiceDomain::Boolean(left), ChoiceDomain::Boolean(right)) => {
            left.semantic_version == right.semantic_version
        }
        (ChoiceDomain::Discrete(left), ChoiceDomain::Discrete(right)) => {
            left.semantic_version == right.semantic_version
                && left.alternatives.keys().eq(right.alternatives.keys())
        }
        (ChoiceDomain::Integer(left), ChoiceDomain::Integer(right)) => {
            left.semantic_version == right.semantic_version
                && left.representation == right.representation
                && left.minimum == right.minimum
                && left.maximum == right.maximum
                && left.step == right.step
                && left.unit == right.unit
                && left.scale == right.scale
        }
        _ => false,
    }
}

impl ResolvedConstraint {
    fn encoded_size(&self) -> usize {
        const TYPED_MEMBER_ID_BYTES: usize =
            8 + SELECTABLE_TAG.len() + 8 + "campaign-fact.1.".len() + 64;

        match self {
            Self::Equal(_, _) | Self::LessThan(_, _) => 1 + 2 * TYPED_MEMBER_ID_BYTES,
            Self::Member(_, values) => 1 + TYPED_MEMBER_ID_BYTES + encoded_value_set_size(values),
            Self::Implies { allowed, .. } => {
                1 + 2 * TYPED_MEMBER_ID_BYTES + 32 + encoded_value_set_size(allowed)
            }
        }
    }

    fn encode(&self, encoder: &mut Encoder, members: &BTreeMap<[u8; 32], GroupMember>) {
        let id = |encoder: &mut Encoder, digest: &[u8; 32]| {
            encode_typed_id(encoder, SELECTABLE_TAG, &members[digest].id);
        };
        match self {
            Self::Equal(left, right) => {
                encoder.u8(0);
                id(encoder, left);
                id(encoder, right);
            }
            Self::LessThan(left, right) => {
                encoder.u8(1);
                id(encoder, left);
                id(encoder, right);
            }
            Self::Member(member, admitted) => {
                encoder.u8(2);
                id(encoder, member);
                encode_value_set(encoder, admitted);
            }
            Self::Implies {
                if_member,
                if_alternative,
                then_member,
                allowed,
            } => {
                encoder.u8(3);
                id(encoder, if_member);
                encoder.bytes.extend_from_slice(&if_alternative.0);
                id(encoder, then_member);
                encode_value_set(encoder, allowed);
            }
        }
    }

    fn accepts(&self, values: &BTreeMap<[u8; 32], ChoiceValue>) -> bool {
        match self {
            Self::Equal(left, right) => values.get(left) == values.get(right),
            Self::LessThan(left, right) => {
                values
                    .get(left)
                    .zip(values.get(right))
                    .and_then(|(left, right)| comparable_order(left, right))
                    == Some(Ordering::Less)
            }
            Self::Member(member, admitted) => values
                .get(member)
                .is_some_and(|value| admitted.contains(value)),
            Self::Implies {
                if_member,
                if_alternative,
                then_member,
                allowed,
            } => {
                if values.get(if_member) == Some(&ChoiceValue::Discrete(*if_alternative)) {
                    values
                        .get(then_member)
                        .is_some_and(|value| allowed.contains(value))
                } else {
                    true
                }
            }
        }
    }
}

fn encode_value_set(encoder: &mut Encoder, values: &BTreeSet<ChoiceValue>) {
    encoder.u64(values.len() as u64);
    for value in values {
        encode_value(encoder, value);
    }
}

fn encoded_value_set_size(values: &BTreeSet<ChoiceValue>) -> usize {
    8 + values.iter().map(scalar_value_size).sum::<usize>()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContentIdentity {
    schema_version: u32,
    digest: [u8; 32],
}

impl ContentIdentity {
    fn text(self) -> String {
        let mut text = format!("campaign-fact.{}.", self.schema_version);
        for byte in self.digest {
            use std::fmt::Write;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}

fn encode_typed_id(encoder: &mut Encoder, tag: &str, id: &ContentIdentity) {
    encoder.string(tag);
    encoder.string(&id.text());
}

fn decode_typed_id(
    decoder: &mut Decoder<'_>,
    tag: &str,
    schema_version: u32,
) -> Result<ContentIdentity, ChoiceCodecError> {
    if decoder.string(tag.len(), "typed-content-id-tag-bytes")? != tag {
        return Err(invalid("typed group identity has the wrong tag"));
    }
    let encoded = decoder.string(256, "content-id-text-bytes")?;
    let prefix = format!("campaign-fact.{schema_version}.");
    let hex = encoded
        .strip_prefix(&prefix)
        .ok_or(invalid("typed group identity has the wrong schema"))?;
    let digest = super::AlternativeId::parse(hex)?.0;
    Ok(ContentIdentity {
        schema_version,
        digest,
    })
}

fn content_identity(
    schema_name: &str,
    schema_version: u32,
    children: &[(&'static str, ContentIdentity)],
    body: &[u8],
) -> ContentIdentity {
    let mut envelope = Vec::new();
    envelope.extend_from_slice(b"CRUCOBJE");
    envelope.extend_from_slice(&1_u32.to_be_bytes());
    short_bytes(&mut envelope, schema_name.as_bytes());
    envelope.extend_from_slice(&schema_version.to_be_bytes());
    envelope.extend_from_slice(&(children.len() as u32).to_be_bytes());
    for (role, child) in children {
        short_bytes(&mut envelope, role.as_bytes());
        short_bytes(&mut envelope, child.text().as_bytes());
    }
    envelope.extend_from_slice(&(body.len() as u64).to_be_bytes());
    envelope.extend_from_slice(body);

    let mut hasher = blake3::Hasher::new();
    hash_component(&mut hasher, b"crucible.content-object.v1");
    hash_component(&mut hasher, b"campaign-fact");
    hasher.update(&schema_version.to_be_bytes());
    hasher.update(&(envelope.len() as u64).to_be_bytes());
    hasher.update(&envelope);
    ContentIdentity {
        schema_version,
        digest: *hasher.finalize().as_bytes(),
    }
}

fn hash_component(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn short_bytes(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buffer.extend_from_slice(value);
}

fn validate_identifier(value: &str) -> Result<(), ChoiceCodecError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
        return Err(invalid("guest group identifier is invalid"));
    }
    Ok(())
}

const fn invalid(reason: &'static str) -> ChoiceCodecError {
    ChoiceCodecError::InvalidValue { reason }
}

fn scalar_domain_size(domain: &ChoiceDomain) -> usize {
    const SCHEMA_AND_TAG_BYTES: usize = 5;
    match domain {
        ChoiceDomain::Boolean(_) => SCHEMA_AND_TAG_BYTES + 4,
        ChoiceDomain::Discrete(domain) => {
            SCHEMA_AND_TAG_BYTES
                + 4
                + 8
                + domain
                    .alternatives
                    .values()
                    .map(|alternative| {
                        32 + 32
                            + 8
                            + alternative.label.len()
                            + 1
                            + alternative
                                .description
                                .as_ref()
                                .map_or(0, |description| 8 + description.len())
                    })
                    .sum::<usize>()
        }
        ChoiceDomain::Integer(domain) => {
            SCHEMA_AND_TAG_BYTES
                + 4
                + 1
                + 9
                + 9
                + 8
                + 1
                + domain.unit.as_ref().map_or(0, |unit| 8 + unit.len())
                + 16
                + 8
                + 9 * domain.landmarks.len()
        }
    }
}

const fn scalar_value_size(value: &ChoiceValue) -> usize {
    match value {
        ChoiceValue::Boolean(_) => 2,
        ChoiceValue::Discrete(_) => 33,
        ChoiceValue::Integer(_) => 10,
    }
}
