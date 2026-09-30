//! Owns the closed v1 property-name vocabulary and typed value validation.
//!
//! Property maps contain registered values or reserved inheritance bindings:
//!
//! ```text
//! {"domain": "public", "store": {"value": "local", "inherit": false}}
//! ```
//!
//! Bare values inherit. A reserved binding replaces both the value and its
//! inheritance flag when supplied by a graft-local override.

use super::{Defaults, Domain, Error};
use crate::cbor::Decoder;
use crate::tree_format::Property;
use alloc::vec;
use alloc::vec::Vec;

/// The layer that consumes a registered property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Placement, retention, or admission policy.
    Storage,
    /// Provenance, merge, or writer policy.
    Trust,
    /// Host or surface realization policy.
    Realization,
    /// Principal authority policy.
    Authority,
    /// Attribute or index requirements.
    Requirement,
}

macro_rules! property_names {
    ($( $variant:ident => ($name:literal, $class:ident) ),+ $(,)?) => {
        /// A property name registered for Terrane v1.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum PropertyName {
            $(#[doc = concat!("The `", $name, "` property.")] $variant),+
        }

        impl PropertyName {
            /// Lists every registered property in registry order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Parses a closed property name.
            ///
            /// # Errors
            /// Returns [`Error::UnknownProperty`] for unregistered names.
            pub fn parse(name: &str) -> Result<Self, Error> {
                match name { $($name => Ok(Self::$variant)),+, _ => Err(Error::UnknownProperty) }
            }

            /// Returns the registered wire name.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            /// Returns the consuming policy class.
            pub const fn class(self) -> Class {
                match self { $(Self::$variant => Class::$class),+ }
            }

            /// Reports whether flatten must preserve this boundary.
            pub const fn is_boundary(self) -> bool {
                matches!(self, Self::Store | Self::Domain | Self::Acl)
            }
        }
    }
}

property_names! {
    Store => ("store", Storage), Chunk => ("chunk", Storage),
    Compression => ("compression", Storage), Encryption => ("encryption", Storage),
    Retain => ("retain", Storage), Domain => ("domain", Storage),
    Dedup => ("dedup", Storage), Redundancy => ("redundancy", Storage),
    Degraded => ("degraded", Storage), Durability => ("durability", Storage),
    Replicate => ("replicate", Storage), Home => ("home", Storage),
    Warm => ("warm", Storage), Quota => ("quota", Storage),
    CompactionThreshold => ("compaction_threshold", Storage),
    WholePackThreshold => ("whole_pack_threshold", Storage),
    GapMergeBytes => ("gap_merge_bytes", Storage), SpanMaxBytes => ("span_max_bytes", Storage),
    Trust => ("trust", Trust), Baseline => ("baseline", Trust),
    Merge => ("merge", Trust), Writers => ("writers", Trust), ReflogRetain => ("reflog_retain", Trust),
    Prefetch => ("prefetch", Realization), Reassembly => ("reassembly", Realization),
    Passthrough => ("passthrough", Realization), Wipe => ("wipe", Realization),
    OnRelease => ("on-release", Realization), Acl => ("acl", Authority),
    Hashes => ("hashes", Requirement), Classify => ("classify", Requirement),
    Index => ("index", Requirement), StrictAttrs => ("strict-attrs", Requirement),
}

/// A validated, typed property value borrowing encoded text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value<'a> {
    /// A closed enum or named reference.
    Text(&'a str),
    /// An unsigned quantity in its property's registered units.
    Unsigned(u64),
    /// A boolean requirement flag.
    Boolean(bool),
    /// An ordered list or set of validated text names.
    Names(Vec<&'a str>),
    /// A TTL in seconds.
    Ttl(u64),
    /// A reflog entry count.
    Count(u64),
    /// Per-root and unreferenced per-principal byte quotas.
    Quota {
        /// Maximum bytes held by the root.
        root: u64,
        /// Maximum unreferenced bytes admitted for one principal.
        principal: u64,
    },
    /// Ordered principal and verb-bitmask grants.
    Grants(Vec<(&'a str, u8)>),
    /// A schema-validated canonical trust selector.
    Selector(&'a [u8]),
    /// A context-dependent unset value such as unlimited quota.
    Unset,
}

fn choice(value: &str, choices: &[&str]) -> Result<(), Error> {
    if choices.contains(&value) {
        Ok(())
    } else {
        Err(Error::InvalidValue)
    }
}

fn nonempty(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn names<'a>(
    decoder: &mut Decoder<'a>,
    choices: Option<&[&str]>,
    set: bool,
) -> Result<Vec<&'a str>, Error> {
    // The encoded value's byte bound limits cardinality before allocation.
    let count = decoder.array(65536)?;
    let mut result = Vec::new();
    for _ in 0..count {
        let value = decoder.text(65536)?;
        nonempty(value)?;
        if let Some(choices) = choices {
            choice(value, choices)?;
        }
        if set && result.contains(&value) {
            return Err(Error::InvalidValue);
        }
        result.push(value);
    }
    Ok(result)
}

const HASHES: &[&str] = &["sha256", "sha512", "git-blob-sha1", "git-blob-sha256"];
const CLASSIFIERS: &[&str] = &[
    "elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other",
];
const PRESETS: &[&str] = &["any", "signed-baseline", "strict", "attested"];
const MERGE: &[&str] = &[
    "prefer-ours",
    "prefer-theirs",
    "prefer-trusted",
    "prefer-newer",
    "keep-conflict",
    "error",
];

/// Validates one registered property against its wire type and vocabulary.
///
/// # Errors
/// Rejects unregistered names, malformed or oversized CBOR, unsupported
/// encryption, invalid registered values, or trailing bytes.
pub fn validate_property<'a>(property: &Property<'a>) -> Result<(PropertyName, Value<'a>), Error> {
    let name = PropertyName::parse(property.name)?;
    if property.value.len() > 65536 {
        return Err(Error::Limit);
    }
    // Check canonical ordering before typed parsers allocate. Generic nesting
    // consumes traversal state proportional to the bounded encoded input.
    let mut canonical = Decoder::new(property.value);
    super::value::skip_value(&mut canonical, 65536)?;
    canonical.finish()?;

    let (encoded, inherit) = binding(property.value)?;
    if name == PropertyName::Acl && !inherit {
        return Err(Error::InvalidValue);
    }
    let mut decoder = Decoder::new(encoded);
    let value = match name {
        PropertyName::StrictAttrs => match decoder.simple()? {
            0xf4 => Value::Boolean(false),
            0xf5 => Value::Boolean(true),
            _ => return Err(Error::InvalidValue),
        },
        PropertyName::CompactionThreshold | PropertyName::WholePackThreshold => {
            let value = decoder.uint()?;
            if value > 10000 {
                return Err(Error::InvalidValue);
            }
            Value::Unsigned(value)
        }
        PropertyName::GapMergeBytes | PropertyName::SpanMaxBytes => {
            Value::Unsigned(decoder.uint()?)
        }
        PropertyName::Warm => Value::Names(names(&mut decoder, None, false)?),
        PropertyName::Hashes => Value::Names(names(&mut decoder, Some(HASHES), true)?),
        PropertyName::Classify => Value::Names(names(&mut decoder, Some(CLASSIFIERS), true)?),
        PropertyName::Index => {
            let values = names(&mut decoder, None, true)?;
            for value in &values {
                if !super::registered_attribute(value) {
                    return Err(Error::UnknownAttribute);
                }
            }
            Value::Names(values)
        }
        PropertyName::Merge => {
            let values = names(&mut decoder, Some(MERGE), false)?;
            if values.is_empty() {
                return Err(Error::InvalidValue);
            }
            Value::Names(values)
        }
        PropertyName::Acl => {
            let count = decoder.array(65536)?;
            let mut grants = Vec::new();
            for _ in 0..count {
                if decoder.array(2)? != 2 {
                    return Err(Error::InvalidValue);
                }
                let principal = decoder.text(65536)?;
                nonempty(principal)?;
                let verbs = decoder.uint()?;
                if verbs > 31 {
                    return Err(Error::InvalidValue);
                }
                grants.push((principal, verbs as u8));
            }
            Value::Grants(grants)
        }
        PropertyName::Quota => {
            if decoder.map(2)? != 2 || decoder.text(65536)? != "bytes-per-root" {
                return Err(Error::InvalidValue);
            }
            let root = decoder.uint()?;
            if decoder.text(65536)? != "bytes-per-principal-unreferenced" {
                return Err(Error::InvalidValue);
            }
            Value::Quota {
                root,
                principal: decoder.uint()?,
            }
        }
        PropertyName::Retain if decoder.peek_major()? == 4 => {
            if decoder.array(2)? != 2 || decoder.text(3)? != "ttl" {
                return Err(Error::InvalidValue);
            }
            Value::Ttl(decoder.uint()?)
        }
        PropertyName::ReflogRetain => {
            if decoder.peek_major()? == 0 {
                Value::Unsigned(decoder.uint()?)
            } else {
                if decoder.array(2)? != 2 || decoder.text(5)? != "count" {
                    return Err(Error::InvalidValue);
                }
                Value::Count(decoder.uint()?)
            }
        }
        PropertyName::Trust if decoder.peek_major()? == 4 => {
            selector(&mut decoder)?;
            Value::Selector(encoded)
        }
        _ => {
            let value = decoder.text(65536)?;
            match name {
                PropertyName::Chunk => choice(value, &["cdc-1m"])?,
                PropertyName::Compression => {
                    if value != "raw" && value != "zstd" {
                        choice(
                            value.strip_prefix("zstd:").ok_or(Error::InvalidValue)?,
                            CLASSIFIERS,
                        )?;
                    }
                }
                PropertyName::Encryption => choice(value, &["none"])?,
                PropertyName::Retain => choice(value, &["gc", "lease", "forever"])?,
                PropertyName::Domain => {
                    Domain::parse(value)?;
                }
                PropertyName::Dedup => choice(value, &["global", "domain", "none"])?,
                PropertyName::Degraded => choice(value, &["allow", "refuse"])?,
                PropertyName::Writers => choice(value, &["one", "many"])?,
                PropertyName::Prefetch => choice(value, &["profile", "rules", "none"])?,
                PropertyName::Reassembly => choice(value, &["never", "smart", "always"])?,
                PropertyName::Passthrough => choice(value, &["auto", "force", "off"])?,
                PropertyName::Wipe => choice(value, &["none", "zero", "discard", "volatile"])?,
                PropertyName::OnRelease => choice(value, &["keep", "commit", "discard"])?,
                PropertyName::Trust => choice(value, PRESETS)?,
                PropertyName::Durability => {
                    if !["local", "zone", "region"].contains(&value) {
                        positive_argument(value, "regions(")?;
                    }
                }
                PropertyName::Replicate => {
                    if !["async", "none"].contains(&value) {
                        positive_argument(value, "sync(")?;
                    }
                }
                PropertyName::Redundancy => redundancy(value)?,
                _ => nonempty(value)?,
            }
            Value::Text(value)
        }
    };
    decoder.finish()?;
    Ok((name, value))
}

fn positive_argument(value: &str, prefix: &str) -> Result<u64, Error> {
    let digits = value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or(Error::InvalidValue)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidValue);
    }
    let number = digits.parse::<u64>().map_err(|_| Error::InvalidValue)?;
    if number == 0 {
        return Err(Error::InvalidValue);
    }
    Ok(number)
}

fn redundancy(value: &str) -> Result<(), Error> {
    if value == "none" {
        return Ok(());
    }
    let (prefix, delimiter) = if value.starts_with("replicated(") {
        ("replicated(", ",ack=")
    } else {
        ("striped(", ",parity=")
    };
    let body = value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or(Error::InvalidValue)?;
    let (first, second) = body.split_once(delimiter).ok_or(Error::InvalidValue)?;
    if !first.bytes().all(|byte| byte.is_ascii_digit())
        || !second.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::InvalidValue);
    }
    let first = first.parse::<u64>().map_err(|_| Error::InvalidValue)?;
    let second = second.parse::<u64>().map_err(|_| Error::InvalidValue)?;
    if first == 0 || second == 0 || (prefix == "replicated(" && second > first) {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

fn selector(decoder: &mut Decoder<'_>) -> Result<(), Error> {
    let mut pending = 1usize;
    while pending != 0 {
        pending -= 1;
        let count = decoder.array(3)?;
        let atom = decoder.text(65536)?;
        if count != if atom == "attr-by" { 3 } else { 2 } {
            return Err(Error::InvalidValue);
        }
        match atom {
            "issuer" | "subject" | "group" | "signed-by-key" => nonempty(decoder.text(65536)?)?,
            "source" => choice(
                decoder.text(65536)?,
                &[
                    "built", "uploaded", "imported", "merged", "derived", "migrated",
                ],
            )?,
            "kind" => choice(decoder.text(65536)?, &["human", "workload", "service"])?,
            "preset" => choice(decoder.text(65536)?, PRESETS)?,
            "not" | "accepted-by" => {
                pending = pending.checked_add(1).ok_or(Error::Limit)?;
            }
            "attr-by" => {
                if !super::registered_attribute(decoder.text(255)?) {
                    return Err(Error::InvalidValue);
                }
                pending = pending.checked_add(1).ok_or(Error::Limit)?;
            }
            "all" | "any" => {
                let count = decoder.array(65536)?;
                if count == 0 {
                    return Err(Error::InvalidValue);
                }
                pending = pending.checked_add(count).ok_or(Error::Limit)?;
            }
            // No attestation claims are registered in v1.
            _ => return Err(Error::InvalidValue),
        }
    }
    Ok(())
}

pub(super) fn defaults(context: Defaults<'_>) -> Result<Vec<(PropertyName, Value<'_>)>, Error> {
    nonempty(context.store)?;
    nonempty(context.home)?;
    let domain = super::Domain::parse(context.private_domain)?;
    if !matches!(domain, super::Domain::Private(_)) {
        return Err(Error::InvalidValue);
    }
    use PropertyName::*;
    Ok(vec![
        (Store, Value::Text(context.store)),
        (Chunk, Value::Text("cdc-1m")),
        (Compression, Value::Text("zstd")),
        (Encryption, Value::Text("none")),
        (Retain, Value::Text("gc")),
        (Domain, Value::Text(context.private_domain)),
        (Dedup, Value::Text("domain")),
        (Redundancy, Value::Text("none")),
        (Degraded, Value::Text("refuse")),
        (Durability, Value::Text("region")),
        (Replicate, Value::Text("async")),
        (Home, Value::Text(context.home)),
        (Warm, Value::Names(Vec::new())),
        (Quota, Value::Unset),
        (CompactionThreshold, Value::Unsigned(5000)),
        (WholePackThreshold, Value::Unsigned(5000)),
        (GapMergeBytes, Value::Unsigned(262144)),
        (SpanMaxBytes, Value::Unsigned(16777216)),
        (Trust, Value::Text("any")),
        (Baseline, Value::Unset),
        (Merge, Value::Names(vec!["prefer-trusted", "keep-conflict"])),
        (Writers, Value::Text("one")),
        (ReflogRetain, Value::Unsigned(7776000)),
        (Prefetch, Value::Text("profile")),
        (Reassembly, Value::Text("smart")),
        (Passthrough, Value::Text("auto")),
        (Wipe, Value::Text("zero")),
        (OnRelease, Value::Text("keep")),
        (Acl, Value::Grants(Vec::new())),
        (Hashes, Value::Names(Vec::new())),
        (Classify, Value::Names(Vec::new())),
        (Index, Value::Names(Vec::new())),
        (StrictAttrs, Value::Boolean(false)),
    ])
}

// A reserved two-key wrapper carries inheritance without changing generic CBOR.
pub(super) fn binding(encoded: &[u8]) -> Result<(&[u8], bool), Error> {
    if encoded.len() > 65536 {
        return Err(Error::Limit);
    }
    let mut decoder = Decoder::new(encoded);
    if decoder.peek_major()? != 5 {
        return Ok((encoded, true));
    }
    let mut probe = decoder.clone();
    if probe.map(65536)? != 2 || probe.peek_major()? != 3 || probe.text(65536)? != "value" {
        return Ok((encoded, true));
    }
    decoder.map(2)?;
    decoder.text(5)?;
    let start = decoder.position();
    super::value::skip_value(&mut decoder, 65536)?;
    let value = decoder.slice(start, decoder.position())?;
    if decoder.text(7)? != "inherit" {
        return Err(Error::InvalidValue);
    }
    let inherit = match decoder.simple()? {
        0xf4 => false,
        0xf5 => true,
        _ => return Err(Error::InvalidValue),
    };
    decoder.finish()?;
    Ok((value, inherit))
}
