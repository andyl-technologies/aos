//! Guest encoding of unconstrained Cartesian groups in campaign wire format.
//!
//! Campaign admission validates the complete group. This L1 encoder emits its
//! exact canonical bytes and identities without linking host campaign state.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CHOICE_DOMAIN_SCHEMA_VERSION, ChoiceCodecError, ChoiceDomain, ChoiceValue, Decoder, Encoder,
    decode_value, encode_domain, encode_value,
};
use crate::SELECTABLE_PROTOCOL_VERSION;

const MAX_GROUP_MEMBERS: usize = 64;
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

/// A guest-declared atomic group with campaign-compatible wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestChoiceGroup {
    members: BTreeMap<[u8; 32], GroupMember>,
    id: ContentIdentity,
    domain_bytes: Vec<u8>,
    default_bytes: Vec<u8>,
}

impl GuestChoiceGroup {
    /// Builds a group of uniquely named scalar members with legal defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ChoiceCodecError`] for invalid identifiers, member counts,
    /// duplicate names or identities, or a default outside its domain.
    pub fn new(
        node: &str,
        adapter: &str,
        application_version: u32,
        members: Vec<(String, ChoiceDomain, ChoiceValue)>,
    ) -> Result<Self, ChoiceCodecError> {
        validate_identifier(node)?;
        validate_identifier(adapter)?;
        if application_version == 0 || members.is_empty() || members.len() > MAX_GROUP_MEMBERS {
            return Err(invalid("guest group version or member count is invalid"));
        }

        let mut by_id = BTreeMap::new();
        let mut by_name = BTreeSet::new();
        for (name, domain, default) in members {
            validate_identifier(&name)?;
            if !by_name.insert(name.clone()) || !domain.contains(&default) {
                return Err(invalid(
                    "guest group member is duplicate or its default is illegal",
                ));
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

        let group_bytes = encode_group(&by_id, adapter, application_version);
        let children = by_id
            .values()
            .map(|member| ("member", member.id))
            .collect::<Vec<_>>();
        let id = content_identity(GROUP_TAG, 3, &children, &group_bytes);
        let domain_bytes = encode_group_domain(&group_bytes);
        let default_bytes = encode_tuple_value(&id, &by_id);
        Ok(Self {
            members: by_id,
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
            values.insert(member.name.clone(), value);
        }
        decoder.finish()?;
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
    encoder.u64(0); // Relational constraints.
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
