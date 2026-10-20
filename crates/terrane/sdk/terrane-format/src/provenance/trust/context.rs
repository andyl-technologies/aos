//! Validates legacy and recorded trust-context tuples and selected evidence.
//!
//! The decoder checks syntax and exact tuple relationships. It creates no
//! verified attribute, history, selector evaluator or repository authority.
//!
//! ```text
//! [1, view, domain, selector-bytes, baseline-or-null, min-chunk-size]
//! [2, view, domain, selector-bytes, baseline-or-null, min-chunk-size,
//!     [[view-location, name, domain, full-path, side-tuple], ...] as bytes]
//! side-tuple = [record, object, name, function, version, value as bytes,
//!               producer, witness-location, [producer-domain, full-path]]
//! [3, view, domain, selector-bytes, baseline-or-null, min-chunk-size,
//!     selected-evidence-bytes-or-null,
//!     [original-view-root, property-revision, behavioral-names, later-names]]
//! ```

use super::{Rejected, Selector};
use crate::{cbor::Decoder, tree_format};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "context/tests_private.rs"]
mod private_tests;

#[cfg(test)]
mod recorded_tests;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Location<'a> {
    commit: &'a [u8],
    root: &'a [u8],
    path: &'a [u8],
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Selection<'a> {
    location: Location<'a>,
    name: &'a str,
    domain: &'a str,
}

/// Retains decoded ordinary fields without establishing a trusted association.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedContext<'a> {
    /// Registered tuple version.
    pub(super) version: u64,
    /// Immutable selected view identity.
    pub(super) view: &'a [u8],
    /// Selected disclosure domain.
    pub(super) domain: &'a str,
    /// Canonical selector bytes.
    pub(super) selector: &'a [u8],
    /// Optional configured baseline.
    pub(super) baseline: Option<&'a str>,
    /// Physical chunk minimum.
    pub(super) minimum: u64,
    /// Nonempty selected evidence, or absence.
    pub(super) selected: Option<&'a [u8]>,
    /// Explicit recorded interpretation claims, when version three is selected.
    pub(super) recorded: Option<RecordedFields<'a>>,
}

/// Retains syntax-checked recorded claims; registration remains external.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RecordedFields<'a> {
    /// Original namespace root before preprocessing.
    pub(super) root: &'a [u8],
    /// Fixed property semantic revision.
    pub(super) revision: u64,
    /// Exact sorted behavioral vocabulary.
    pub(super) behavioral: alloc::vec::Vec<&'a str>,
    /// Sorted disjoint preservation vocabulary.
    pub(super) later: alloc::vec::Vec<&'a str>,
}

/// Checks ordinary context syntax without constructing verified state.
///
/// # Errors
/// Rejects malformed, unsupported or contradictory canonical tuples.
pub(super) fn validate(bytes: &[u8]) -> Result<(), Rejected> {
    decode(bytes).map(|_| ())
}

/// Decodes complete ordinary fields while preserving their interpretation claims.
///
/// # Errors
/// Rejects unsupported versions, noncanonical values, invalid names, mismatched
/// revision vocabularies, oversized fences and inconsistent selected evidence.
pub(super) fn decode(bytes: &[u8]) -> Result<DecodedContext<'_>, Rejected> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array(8).map_err(|_| Rejected)?;
    let version = decoder.uint().map_err(|_| Rejected)?;
    if !matches!((version, count), (1, 6) | (2, 7) | (3, 8)) {
        return Err(Rejected);
    }
    let view = digest(&mut decoder)?;
    let domain = text(&mut decoder)?;
    let selector = decoder
        .bytes(decoder.remaining().len())
        .map_err(|_| Rejected)?;
    Selector::decode(selector).map_err(|_| Rejected)?;
    let baseline = nullable_text(&mut decoder)?;
    let minimum = decoder.uint().map_err(|_| Rejected)?;
    let evidence = if version == 1 {
        None
    } else if version == 3 && decoder.peek_major().map_err(|_| Rejected)? == 7 {
        if decoder.simple().map_err(|_| Rejected)? != 0xf6 {
            return Err(Rejected);
        }
        None
    } else {
        let evidence = decoder
            .bytes(decoder.remaining().len())
            .map_err(|_| Rejected)?;
        selected(evidence, view, domain)?;
        Some(evidence)
    };
    let recorded = if version == 3 {
        Some(recorded(&mut decoder)?)
    } else {
        None
    };
    decoder.finish().map_err(|_| Rejected)?;
    Ok(DecodedContext {
        version,
        view,
        domain,
        selector,
        baseline,
        minimum,
        selected: evidence,
        recorded,
    })
}

fn recorded<'a>(decoder: &mut Decoder<'a>) -> Result<RecordedFields<'a>, Rejected> {
    use crate::properties::semantics::RecordedContext;
    array(decoder, 4)?;
    let root = digest(decoder)?;
    let revision = decoder.uint().map_err(|_| Rejected)?;
    let context = RecordedContext::new(revision, revision, &[]).map_err(|_| Rejected)?;
    // This context validates historical syntax only. Its bytes cannot select
    // the independently supplied runtime current revision or justify names.
    let expected: alloc::vec::Vec<_> = context.behavioral_names().collect();
    let behavioral = names(decoder, 35, 35 * 255)?;
    if behavioral != expected {
        return Err(Rejected);
    }
    let later = names(decoder, 65536, 65536)?;
    if later
        .iter()
        .any(|name| behavioral.binary_search(name).is_ok())
    {
        return Err(Rejected);
    }
    Ok(RecordedFields {
        root,
        revision,
        behavioral,
        later,
    })
}

fn names<'a>(
    decoder: &mut Decoder<'a>,
    limit: usize,
    byte_limit: usize,
) -> Result<alloc::vec::Vec<&'a str>, Rejected> {
    let count = decoder.array(limit).map_err(|_| Rejected)?;
    // Every nonempty text requires a header and a payload byte. Reject claimed
    // counts before allocating, then grow only after each bounded name validates.
    if count > decoder.remaining().len() / 2 {
        return Err(Rejected);
    }
    let mut result = alloc::vec::Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let value = name(decoder)?;
        total = total.checked_add(value.len()).ok_or(Rejected)?;
        if total > byte_limit
            || result
                .last()
                .is_some_and(|previous: &&str| previous.as_bytes() >= value.as_bytes())
        {
            return Err(Rejected);
        }
        result.push(value);
    }
    Ok(result)
}

fn selected(bytes: &[u8], view: &[u8], domain: &str) -> Result<(), Rejected> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array(bytes.len()).map_err(|_| Rejected)?;
    if count == 0 {
        return Err(Rejected);
    }
    let mut previous = None;
    for _ in 0..count {
        array(&mut decoder, 5)?;
        let selection = Selection {
            location: location(&mut decoder)?,
            name: name(&mut decoder)?,
            domain: text(&mut decoder)?,
        };
        if selection.location.commit != view
            || selection.domain != domain
            || previous.is_some_and(|previous| previous >= selection)
        {
            return Err(Rejected);
        }
        path(&mut decoder)?;
        side(&mut decoder, selection.name)?;
        previous = Some(selection);
    }
    decoder.finish().map_err(|_| Rejected)
}

fn side(decoder: &mut Decoder<'_>, selected_name: &str) -> Result<(), Rejected> {
    array(decoder, 9)?;
    digest(decoder)?;
    digest(decoder)?;
    if name(decoder)? != selected_name {
        return Err(Rejected);
    }
    text(decoder)?;
    text(decoder)?;
    let value = decoder
        .bytes(decoder.remaining().len())
        .map_err(|_| Rejected)?;
    let mut value_decoder = Decoder::new(value);
    value_decoder
        .skip_value(value.len())
        .map_err(|_| Rejected)?;
    value_decoder.finish().map_err(|_| Rejected)?;

    digest(decoder)?;
    // Signed records name the producer itself. Unsigned legacy records may
    // carry a checked inline witness whose origin resolves a different producer;
    // syntax validation must not replace that independent verification.
    location(decoder)?;
    array(decoder, 2)?;
    text(decoder)?;
    path(decoder)?;
    Ok(())
}

fn location<'a>(decoder: &mut Decoder<'a>) -> Result<Location<'a>, Rejected> {
    array(decoder, 3)?;
    Ok(Location {
        commit: digest(decoder)?,
        root: digest(decoder)?,
        path: path(decoder)?,
    })
}

fn array(decoder: &mut Decoder<'_>, count: usize) -> Result<(), Rejected> {
    if decoder.array(count).map_err(|_| Rejected)? != count {
        return Err(Rejected);
    }
    Ok(())
}

fn digest<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], Rejected> {
    let bytes = decoder.bytes(32).map_err(|_| Rejected)?;
    if bytes.len() != 32 {
        return Err(Rejected);
    }
    Ok(bytes)
}

fn path<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], Rejected> {
    let bytes = decoder.bytes(tree_format::MAX_KEY).map_err(|_| Rejected)?;
    tree_format::validate_key(bytes).map_err(|_| Rejected)?;
    Ok(bytes)
}

fn name<'a>(decoder: &mut Decoder<'a>) -> Result<&'a str, Rejected> {
    let name = decoder.text(255).map_err(|_| Rejected)?;
    if name.is_empty() {
        return Err(Rejected);
    }
    Ok(name)
}

fn text<'a>(decoder: &mut Decoder<'a>) -> Result<&'a str, Rejected> {
    decoder
        .text(decoder.remaining().len())
        .map_err(|_| Rejected)
}

fn nullable_text<'a>(decoder: &mut Decoder<'a>) -> Result<Option<&'a str>, Rejected> {
    if decoder.peek_major().map_err(|_| Rejected)? == 7 {
        if decoder.simple().map_err(|_| Rejected)? != 0xf6 {
            return Err(Rejected);
        }
        Ok(None)
    } else {
        text(decoder).map(Some)
    }
}
