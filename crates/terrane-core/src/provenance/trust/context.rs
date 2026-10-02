//! Validates borrowed trust-context tuples and selected side-evidence schemas.
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
//! ```

use super::{Rejected, Selector};
use crate::{cbor::Decoder, tree_format};

#[cfg(test)]
mod tests;

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

pub(super) fn validate(bytes: &[u8]) -> Result<(), Rejected> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.array(7).map_err(|_| Rejected)?;
    let version = decoder.uint().map_err(|_| Rejected)?;
    if !matches!((version, count), (1, 6) | (2, 7)) {
        return Err(Rejected);
    }
    let view = digest(&mut decoder)?;
    let domain = text(&mut decoder)?;
    let selector = decoder
        .bytes(decoder.remaining().len())
        .map_err(|_| Rejected)?;
    Selector::decode(selector).map_err(|_| Rejected)?;
    nullable_text(&mut decoder)?;
    decoder.uint().map_err(|_| Rejected)?;
    if version == 2 {
        let evidence = decoder
            .bytes(decoder.remaining().len())
            .map_err(|_| Rejected)?;
        selected(evidence, view, domain)?;
    }
    decoder.finish().map_err(|_| Rejected)
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
