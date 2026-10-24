//! Retains current Control tree layouts rather than substituting vector layouts.
//!
//! ```text
//! originals = [[request,identity,response_body,evidence], ...]
//! content = [[ContentRef,[byte,...]], ...]
//! ```

use super::*;
use serde::ser::SerializeSeq;
use std::cmp::Ordering;

pub(super) struct CurrentOriginals17Data(pub(super) BTreeMap<Id, (HashRef, PacketControlReply)>);

impl HistoricalType for CurrentOriginals17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut attempt = retained::CurrentOriginals17ReadAttempt::default();
        attempt.read_into(input, ledger, build)?;
        Ok(attempt.take_completed_data())
    }
}

impl Serialize for CurrentOriginals17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for (id, (hash, reply)) in &self.0 {
            rows.serialize_element(&(id, hash, &reply.body, &reply.evidence))?;
        }
        rows.end()
    }
}

impl ObserveMetadata for CurrentOriginals17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.tree::<Id, (HashRef, PacketControlReply)>(self.0.len())?;
        for (id, (hash, reply)) in &self.0 {
            observer.observe(id)?;
            observer.observe(hash)?;
            observer.observe(&reply.body)?;
            observer.observe(&reply.evidence)?;
        }
        Ok(())
    }
}

pub(super) struct CurrentContent17Data(pub(super) BTreeMap<ContentRef, Vec<u8>>);

impl HistoricalType for CurrentContent17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut attempt = retained::CurrentContent17ReadAttempt::default();
        attempt.read_into(input, ledger, build)?;
        Ok(attempt.take_completed_data())
    }
}

impl Serialize for CurrentContent17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for row in &self.0 {
            rows.serialize_element(&row)?;
        }
        rows.end()
    }
}

impl ObserveMetadata for CurrentContent17Data {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.observe(&self.0)
    }
}

#[derive(Clone, Copy)]
struct ContentKey<'a> {
    algorithm: &'a [u8],
    domain: &'a [u8],
    digest: &'a [u8],
    length: u64,
    media_type: &'a [u8],
}

impl<'a> ContentKey<'a> {
    fn read(input: &'a [u8]) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        let mut hash = Fields::object(fields.named("hash")?)?;
        let algorithm = hash.named("algorithm")?;
        let domain = hash.named("domain")?;
        let digest = hash.named("digest")?;
        hash.finish()?;
        let length = crate::protocol_snapshot::owned11::typed::unsigned(
            plain_string(fields.named("length")?)?.as_bytes(),
        )?;
        let media_type = fields.named("media_type")?;
        fields.finish()?;
        Ok(Self {
            algorithm,
            domain,
            digest,
            length,
            media_type,
        })
    }

    fn compare(self, other: Self) -> Result<Ordering, ProviderError> {
        for (left, right) in [
            (self.algorithm, other.algorithm),
            (self.domain, other.domain),
            (self.digest, other.digest),
        ] {
            let order = compare_strings(left, right)?;
            if order != Ordering::Equal {
                return Ok(order);
            }
        }
        let order = self.length.cmp(&other.length);
        if order != Ordering::Equal {
            return Ok(order);
        }
        compare_strings(self.media_type, other.media_type)
    }
}

fn compare_strings(left: &[u8], right: &[u8]) -> Result<Ordering, ProviderError> {
    let mut left = StringCharacters::new(left)?;
    let mut right = StringCharacters::new(right)?;
    loop {
        match (left.next()?, right.next()?) {
            (None, None) => return Ok(Ordering::Equal),
            (None, Some(_)) => return Ok(Ordering::Less),
            (Some(_), None) => return Ok(Ordering::Greater),
            (Some(left), Some(right)) => {
                let order = left.cmp(&right);
                if order != Ordering::Equal {
                    return Ok(order);
                }
            }
        }
    }
}

// Ordering decoded scalars also orders valid UTF-8 String bytes. This borrowed
// comparison preserves printable ASCII media types containing quote/backslash
// escapes without allocating a temporary ContentRef during the borrowed pass.
struct StringCharacters<'a>(&'a [u8]);

impl<'a> StringCharacters<'a> {
    fn new(input: &'a [u8]) -> Result<Self, ProviderError> {
        if input.len() < 2 || input.first() != Some(&b'"') || input.last() != Some(&b'"') {
            return Err(invalid());
        }
        Ok(Self(&input[1..input.len() - 1]))
    }

    fn next(&mut self) -> Result<Option<char>, ProviderError> {
        let Some((&first, tail)) = self.0.split_first() else {
            return Ok(None);
        };
        if first == b'\\' {
            let (&escaped, rest) = tail.split_first().ok_or_else(invalid)?;
            self.0 = rest;
            let character = match escaped {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let first = self.hex_quad()?;
                    let scalar = if (0xd800..=0xdbff).contains(&first) {
                        if !self.0.starts_with(b"\\u") {
                            return Err(invalid());
                        }
                        self.0 = &self.0[2..];
                        let second = self.hex_quad()?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(invalid());
                        }
                        0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                    } else {
                        first
                    };
                    char::from_u32(scalar).ok_or_else(invalid)?
                }
                _ => return Err(invalid()),
            };
            return Ok(Some(character));
        }
        if first < 32 || first == b'"' {
            return Err(invalid());
        }
        let width = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(invalid()),
        };
        let scalar = self.0.get(..width).ok_or_else(invalid)?;
        let text = std::str::from_utf8(scalar).map_err(|_| invalid())?;
        let character = text.chars().next().ok_or_else(invalid)?;
        self.0 = &self.0[character.len_utf8()..];
        Ok(Some(character))
    }

    fn hex_quad(&mut self) -> Result<u32, ProviderError> {
        let digits = self.0.get(..4).ok_or_else(invalid)?;
        let mut value = 0u32;
        for digit in digits {
            value = value.checked_mul(16).ok_or_else(invalid)?;
            value += match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a' + 10),
                b'A'..=b'F' => u32::from(digit - b'A' + 10),
                _ => return Err(invalid()),
            };
        }
        self.0 = &self.0[4..];
        Ok(value)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    macro_rules! field_views {
        ($($ty:ty),+ $(,)?) => { 0usize $(
            + size_of::<Option<$ty>>()
            + size_of::<Result<Option<$ty>, ProviderError>>()
            + size_of::<&$ty>()
        )+ };
    }
    field_views!(Id, HashRef, Map<String, Value>, Vec<(ContentRef, Vec<u8>)>, ContentRef, Vec<u8>)
        + size_of::<CurrentOriginals17Data>()
        + size_of::<CurrentContent17Data>()
        + size_of::<ContentKey<'static>>()
        + size_of::<Option<ContentKey<'static>>>()
        + 2 * size_of::<StringCharacters<'static>>()
        + 3 * size_of::<Fields<'static>>()
        + 8 * size_of::<&[u8]>()
        + 4 * size_of::<usize>()
        + size_of::<Result<Ordering, ProviderError>>()
        + size_of::<Result<Option<char>, ProviderError>>()
}

#[cfg(test)]
mod target_tests;

pub(super) mod retained;
