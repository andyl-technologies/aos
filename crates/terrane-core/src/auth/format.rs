//! Encodes and validates the closed Terrane v1 capability-token CBOR schema.
//!
//! ```text
//! authority = {1:issuer,2:key-id,3:subject,4:kind,5:groups,6:expiry,
//!              ?7:start,8:id,9:grants,?10:workload,11:next-key,12:signature}
//! attenuation = {?1:expiry,?2:start,?3:grants,?4:caveats,5:next-key,6:signature}
//! ```

use alloc::{string::{String, ToString}, vec::Vec};
use crate::cbor::{self, Decoder, Error};
use super::{Attenuation, Authority, Caveat, Grant, Locality, PrincipalKind, Signed, Token, Verbs};

const MAX_TOKEN: usize = 65_536;
const MAX_BLOCKS: usize = 64;
const MAX_ITEMS: usize = 256;
const MAX_TEXT: usize = 4096;

type Result<T> = core::result::Result<T, Error>;

fn text(decoder: &mut Decoder<'_>) -> Result<String> {
    Ok(decoder.text(MAX_TEXT)?.to_string())
}

fn fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N]> {
    decoder.bytes(N)?.try_into().map_err(|_| Error::Malformed)
}

fn required<T>(value: Option<T>) -> Result<T> {
    value.ok_or(Error::Malformed)
}

fn verbs(decoder: &mut Decoder<'_>) -> Result<Verbs> {
    let mask = u8::try_from(decoder.uint()?).map_err(|_| Error::Malformed)?;
    Verbs::new(mask).map_err(|_| Error::Malformed)
}

fn grants(decoder: &mut Decoder<'_>) -> Result<Vec<Grant>> {
    let count = decoder.array(MAX_ITEMS)?;
    if count == 0 { return Err(Error::Malformed); }
    let mut result = Vec::new();
    for _ in 0..count {
        if decoder.array(2)? != 2 { return Err(Error::Malformed); }
        let pattern = text(decoder)?;
        result.push(Grant::new(pattern, verbs(decoder)?).map_err(|_| Error::Malformed)?);
    }
    Ok(result)
}

fn map_key(decoder: &mut Decoder<'_>, previous: &mut u64) -> Result<u64> {
    let key = decoder.uint()?;
    if key <= *previous { return Err(Error::NonCanonical); }
    *previous = key;
    Ok(key)
}

fn locality(decoder: &mut Decoder<'_>) -> Result<Locality> {
    let count = decoder.map(3)?;
    let mut result = Locality::default();
    let mut previous = 0;
    for _ in 0..count {
        match map_key(decoder, &mut previous)? {
            1 => result.region = Some(text(decoder)?),
            2 => result.zone = Some(text(decoder)?),
            3 => result.host = Some(text(decoder)?),
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(result)
}

fn caveat(decoder: &mut Decoder<'_>) -> Result<Caveat> {
    let count = decoder.array(3)?;
    let name = decoder.text(16)?;
    if count != if name == "epoch" { 3 } else { 2 } { return Err(Error::Malformed); }
    Ok(match name {
        "before" => Caveat::Before(decoder.uint()?),
        "after" => Caveat::After(decoder.uint()?),
        "ref" => Caveat::Ref(text(decoder)?),
        "root" => Caveat::Root(text(decoder)?),
        "verb" => Caveat::Verb(verbs(decoder)?),
        "domain" => Caveat::Domain(text(decoder)?),
        "surface" => Caveat::Surface(text(decoder)?),
        "locality" => Caveat::Locality(locality(decoder)?),
        "epoch" => {
            let reference = text(decoder)?;
            if !super::pattern::canonical_reference(reference.as_bytes()) { return Err(Error::Malformed); }
            Caveat::Epoch(reference, decoder.uint()?)
        },
        _ => return Err(Error::Unsupported),
    })
}

fn authority(decoder: &mut Decoder<'_>) -> Result<Signed<Authority>> {
    let count = decoder.map(12)?;
    let (mut issuer, mut key_id, mut subject, mut kind) = (None, None, None, None);
    let (mut groups, mut not_after, mut not_before, mut token_id) = (None, None, None, None);
    let (mut grant_set, mut workload, mut next_key, mut signature) = (None, None, None, None);
    let mut previous = 0;
    for _ in 0..count {
        match map_key(decoder, &mut previous)? {
            1 => issuer = Some(text(decoder)?),
            2 => key_id = Some(text(decoder)?),
            3 => subject = Some(text(decoder)?),
            4 => kind = Some(match decoder.uint()? {
                1 => PrincipalKind::Human,
                2 => PrincipalKind::Workload,
                3 => PrincipalKind::Service,
                _ => return Err(Error::Unsupported),
            }),
            5 => {
                let count = decoder.array(MAX_ITEMS)?;
                let mut names = Vec::new();
                for _ in 0..count { names.push(text(decoder)?); }
                groups = Some(names);
            },
            6 => not_after = Some(decoder.uint()?),
            7 => not_before = Some(decoder.uint()?),
            8 => token_id = Some(fixed(decoder)?),
            9 => grant_set = Some(grants(decoder)?),
            10 => workload = Some(text(decoder)?),
            11 => next_key = Some(fixed(decoder)?),
            12 => signature = Some(fixed(decoder)?),
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(Signed {
        body: Authority { issuer: required(issuer)?, key_id: required(key_id)?, subject: required(subject)?,
            kind: required(kind)?, groups: required(groups)?, not_after: required(not_after)?, not_before,
            token_id: required(token_id)?, grants: required(grant_set)?, workload },
        next_key: required(next_key)?, signature: required(signature)?,
    })
}

fn attenuation(decoder: &mut Decoder<'_>) -> Result<Signed<Attenuation>> {
    let count = decoder.map(6)?;
    let mut body = Attenuation::default();
    let (mut next_key, mut signature) = (None, None);
    let mut previous = 0;
    for _ in 0..count {
        match map_key(decoder, &mut previous)? {
            1 => body.not_after = Some(decoder.uint()?),
            2 => body.not_before = Some(decoder.uint()?),
            3 => body.grants = Some(grants(decoder)?),
            4 => {
                let count = decoder.array(MAX_ITEMS)?;
                if count == 0 { return Err(Error::Malformed); }
                for _ in 0..count { body.caveats.push(caveat(decoder)?); }
            },
            5 => next_key = Some(fixed(decoder)?),
            6 => signature = Some(fixed(decoder)?),
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(Signed { body, next_key: required(next_key)?, signature: required(signature)? })
}

pub(super) fn decode(bytes: &[u8]) -> Result<Token> {
    if bytes.len() > MAX_TOKEN { return Err(Error::Limit); }
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array(MAX_BLOCKS)?;
    if count == 0 { return Err(Error::Malformed); }
    let authority = authority(&mut decoder)?;
    let mut blocks = Vec::new();
    for _ in 1..count { blocks.push(attenuation(&mut decoder)?); }
    decoder.finish()?;
    Ok(Token { authority, blocks })
}

fn field(output: &mut Vec<u8>, key: u64) { cbor::write_uint(output, key); }

fn write_grants(output: &mut Vec<u8>, grants: &[Grant]) {
    cbor::write_array(output, grants.len());
    for grant in grants {
        cbor::write_array(output, 2);
        cbor::write_text(output, &grant.pattern);
        cbor::write_uint(output, u64::from(grant.verbs.bits()));
    }
}

fn write_locality(output: &mut Vec<u8>, label: &Locality) {
    let values = [(1, &label.region), (2, &label.zone), (3, &label.host)];
    cbor::write_map(output, values.iter().filter(|(_, value)| value.is_some()).count());
    for (key, value) in values {
        if let Some(value) = value {
            field(output, key);
            cbor::write_text(output, value);
        }
    }
}

fn write_caveat(output: &mut Vec<u8>, caveat: &Caveat) {
    cbor::write_array(output, if matches!(caveat, Caveat::Epoch(..)) { 3 } else { 2 });
    let name = match caveat {
        Caveat::Before(_) => "before", Caveat::After(_) => "after", Caveat::Ref(_) => "ref",
        Caveat::Root(_) => "root", Caveat::Verb(_) => "verb", Caveat::Domain(_) => "domain",
        Caveat::Surface(_) => "surface", Caveat::Locality(_) => "locality", Caveat::Epoch(..) => "epoch",
    };
    cbor::write_text(output, name);
    match caveat {
        Caveat::Before(time) | Caveat::After(time) => cbor::write_uint(output, *time),
        Caveat::Ref(value) | Caveat::Root(value) | Caveat::Domain(value) | Caveat::Surface(value) => cbor::write_text(output, value),
        Caveat::Verb(verbs) => cbor::write_uint(output, u64::from(verbs.bits())),
        Caveat::Locality(label) => write_locality(output, label),
        Caveat::Epoch(reference, epoch) => {
            cbor::write_text(output, reference);
            cbor::write_uint(output, *epoch);
        },
    }
}

fn write_authority(block: &Signed<Authority>, signature: bool) -> Vec<u8> {
    let body = &block.body;
    let mut output = Vec::new();
    cbor::write_map(&mut output, 9 + usize::from(body.not_before.is_some()) + usize::from(body.workload.is_some()) + usize::from(signature));
    for (key, value) in [(1, &body.issuer), (2, &body.key_id), (3, &body.subject)] {
        field(&mut output, key); cbor::write_text(&mut output, value);
    }
    field(&mut output, 4);
    cbor::write_uint(&mut output, match body.kind { PrincipalKind::Human => 1, PrincipalKind::Workload => 2, PrincipalKind::Service => 3 });
    field(&mut output, 5); cbor::write_array(&mut output, body.groups.len());
    for group in &body.groups { cbor::write_text(&mut output, group); }
    field(&mut output, 6); cbor::write_uint(&mut output, body.not_after);
    if let Some(time) = body.not_before { field(&mut output, 7); cbor::write_uint(&mut output, time); }
    field(&mut output, 8); cbor::write_bytes(&mut output, &body.token_id);
    field(&mut output, 9); write_grants(&mut output, &body.grants);
    if let Some(workload) = &body.workload { field(&mut output, 10); cbor::write_text(&mut output, workload); }
    field(&mut output, 11); cbor::write_bytes(&mut output, &block.next_key);
    if signature { field(&mut output, 12); cbor::write_bytes(&mut output, &block.signature); }
    output
}

fn write_attenuation(block: &Signed<Attenuation>, signature: bool) -> Vec<u8> {
    let body = &block.body;
    let mut output = Vec::new();
    cbor::write_map(&mut output, 1 + usize::from(body.not_after.is_some()) + usize::from(body.not_before.is_some())
        + usize::from(body.grants.is_some()) + usize::from(!body.caveats.is_empty()) + usize::from(signature));
    if let Some(time) = body.not_after { field(&mut output, 1); cbor::write_uint(&mut output, time); }
    if let Some(time) = body.not_before { field(&mut output, 2); cbor::write_uint(&mut output, time); }
    if let Some(grants) = &body.grants { field(&mut output, 3); write_grants(&mut output, grants); }
    if !body.caveats.is_empty() {
        field(&mut output, 4); cbor::write_array(&mut output, body.caveats.len());
        for caveat in &body.caveats { write_caveat(&mut output, caveat); }
    }
    field(&mut output, 5); cbor::write_bytes(&mut output, &block.next_key);
    if signature { field(&mut output, 6); cbor::write_bytes(&mut output, &block.signature); }
    output
}

pub(super) fn authority_preimage(block: &Signed<Authority>) -> Vec<u8> { write_authority(block, false) }

pub(super) fn attenuation_preimage(block: &Signed<Attenuation>) -> Vec<u8> { write_attenuation(block, false) }

pub(super) fn encode(token: &Token) -> Vec<u8> {
    let mut output = Vec::new();
    cbor::write_array(&mut output, 1 + token.blocks.len());
    output.extend(write_authority(&token.authority, true));
    for block in &token.blocks { output.extend(write_attenuation(block, true)); }
    output
}
