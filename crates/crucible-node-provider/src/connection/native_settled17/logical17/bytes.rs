//! Compares borrowed source fields with compact original bytes without a heap.
//!
//! These helpers perform correspondence only. The enclosing native17 grammar
//! validates every source field, capacity row and alias before publishing a plan.

use crate::ProviderError;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid, plain_string, unsigned};
use std::{cmp::Ordering, io::Write};

/// Counts explicit borrowed comparison workspaces, excluding compiler frames.
pub(crate) const fn comparison_scratch_data() -> usize {
    64 * (std::mem::size_of::<Fields<'static>>()
        + 2 * std::mem::size_of::<JsonUnits<'static>>()
        + std::mem::size_of::<[u8; 128]>()
        + std::mem::size_of::<serde_json::Number>()
        + std::mem::size_of::<ExactBytes17<'static>>())
        + 3 * std::mem::size_of::<[u8; 256]>()
        + std::mem::size_of::<blake3::Hasher>()
        + std::mem::size_of::<[u8; 132]>()
}

pub(crate) fn field<'a>(input: &'a [u8], name: &str) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut found = None;
    while let Some((key, value)) = fields.pair()? {
        if plain_string(key)? == name {
            if found.replace(value).is_some() {
                return Err(invalid());
            }
        }
    }
    fields.finish()?;
    found.ok_or_else(invalid)
}

pub(crate) fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

pub(crate) fn quantity(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| invalid())
}

pub(crate) fn quoted(input: &[u8]) -> Result<u64, ProviderError> {
    unsigned(plain_string(input)?.as_bytes())
}

pub(crate) fn boolean(input: &[u8]) -> Result<bool, ProviderError> {
    match input {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(invalid()),
    }
}

pub(crate) fn count(input: &[u8]) -> Result<usize, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut count = 0usize;
    while fields.next()?.is_some() {
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(count)
}

pub(crate) fn item(input: &[u8], index: usize) -> Result<&[u8], ProviderError> {
    let mut fields = Fields::array(input)?;
    for _ in 0..index {
        next(&mut fields)?;
    }
    next(&mut fields)
}

pub(crate) fn digest(input: &[u8]) -> Result<[u8; 32], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut digest = [0; 32];
    for byte in &mut digest {
        *byte = u8::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    }
    fields.finish()?;
    Ok(digest)
}

pub(crate) fn authenticate_content(
    reference: &[u8],
    bytes: Bytes17<'_>,
) -> Result<(), ProviderError> {
    let hash = field(reference, "hash")?;
    let mut media = JsonUnits::new(field(reference, "media_type")?)?;
    let mut media_length = 0usize;
    while let Some(unit) = media.next()? {
        if !(0x20..=0x7e).contains(&unit) {
            return Err(invalid());
        }
        media_length = media_length.checked_add(1).ok_or_else(invalid)?;
    }
    if !(1..=128).contains(&media_length) {
        return Err(invalid());
    }
    if plain_string(field(hash, "algorithm")?)? != "blake3-256"
        || plain_string(field(hash, "domain")?)? != "cnp.blob.v1"
        || quoted(field(reference, "length")?)?
            != u64::try_from(bytes.len()).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let expected = plain_string(field(hash, "digest")?)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(
        &u64::try_from(bytes.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    bytes.update_hash(&mut hasher)?;
    if expected.as_bytes() != hasher.finalize().to_hex().as_bytes() {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn canonical_domain_digest(
    input: &[u8],
    domain: &'static str,
) -> Result<[u8; 32], ProviderError> {
    struct HashWriter(blake3::Hasher);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(blake3::Hasher::new_derive_key(domain));
    canonical_to_writer(input, &mut writer)?;
    Ok(*writer.0.finalize().as_bytes())
}

pub(crate) fn canonical_digest(input: &[u8]) -> Result<[u8; 32], ProviderError> {
    struct HashWriter(blake3::Hasher);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(blake3::Hasher::new());
    canonical_to_writer(input, &mut writer)?;
    Ok(*writer.0.finalize().as_bytes())
}

pub(crate) fn base64_digest(input: &[u8]) -> Result<[u8; 32], ProviderError> {
    use base64::Engine;
    let mut digest = [0; 32];
    if base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(plain_string(input)?.as_bytes(), &mut digest)
        .map_err(|_| invalid())?
        != digest.len()
    {
        return Err(invalid());
    }
    Ok(digest)
}

pub(crate) fn matches_response(request: &[u8], response: &[u8]) -> Result<(), ProviderError> {
    if field(request, "message")? != b"\"request\""
        || field(response, "message")? != b"\"response\""
    {
        return Err(invalid());
    }
    for name in [
        "method",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        if field(request, name)? != field(response, name)? {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Borrows a named source byte representation, never a reconstructed bank.
#[derive(Clone, Copy)]
pub(crate) enum Bytes17<'a> {
    Slice(&'a [u8]),
    Compact {
        plan: ValidatedCompactBytes<'a>,
        offset: usize,
        length: usize,
    },
    Array {
        encoded: &'a [u8],
        length: usize,
    },
}

impl<'a> Bytes17<'a> {
    pub(crate) fn compact(encoded: &'a [u8]) -> Result<Self, ProviderError> {
        let plan = ValidatedCompactBytes::validate(encoded, encoded.len(), usize::MAX)?;
        Ok(Self::Compact {
            plan,
            offset: 0,
            length: plan.decoded_length(),
        })
    }

    pub(crate) fn array(encoded: &'a [u8]) -> Result<Self, ProviderError> {
        let length = count(encoded)?;
        let mut fields = Fields::array(encoded)?;
        while let Some(byte) = fields.next()? {
            u8::try_from(unsigned(byte)?).map_err(|_| invalid())?;
        }
        fields.finish()?;
        Ok(Self::Array { encoded, length })
    }

    pub(crate) fn bank(input: &'a [u8], reversed: bool) -> Result<(Self, usize), ProviderError> {
        let mut fields = Fields::array(input)?;
        let first = next(&mut fields)?;
        let second = next(&mut fields)?;
        fields.finish()?;
        let (raw, capacity) = if reversed {
            (first, quantity(second)?)
        } else {
            (second, quantity(first)?)
        };
        let bytes = Self::compact(raw)?;
        if bytes.len() > capacity {
            return Err(invalid());
        }
        Ok((bytes, capacity))
    }

    pub(crate) const fn len(self) -> usize {
        match self {
            Self::Slice(bytes) => bytes.len(),
            Self::Compact { length, .. } | Self::Array { length, .. } => length,
        }
    }

    pub(crate) fn range(self, start: usize, length: usize) -> Result<Self, ProviderError> {
        let end = start.checked_add(length).ok_or_else(invalid)?;
        if end > self.len() {
            return Err(invalid());
        }
        match self {
            Self::Slice(bytes) => Ok(Self::Slice(bytes.get(start..end).ok_or_else(invalid)?)),
            Self::Compact { plan, offset, .. } => Ok(Self::Compact {
                plan,
                offset: offset.checked_add(start).ok_or_else(invalid)?,
                length,
            }),
            Self::Array { .. } => Err(invalid()),
        }
    }

    pub(crate) fn copy(self, start: usize, output: &mut [u8]) -> Result<(), ProviderError> {
        if start
            .checked_add(output.len())
            .is_none_or(|end| end > self.len())
        {
            return Err(invalid());
        }
        match self {
            Self::Slice(bytes) => {
                output.copy_from_slice(bytes.get(start..start + output.len()).ok_or_else(invalid)?);
                Ok(())
            }
            Self::Compact { plan, offset, .. } => {
                plan.copy_range(offset.checked_add(start).ok_or_else(invalid)?, output)
            }
            Self::Array { encoded, .. } => {
                let mut fields = Fields::array(encoded)?;
                for _ in 0..start {
                    next(&mut fields)?;
                }
                for byte in output {
                    *byte = u8::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
                }
                Ok(())
            }
        }
    }

    pub(crate) fn update_hash(self, hasher: &mut blake3::Hasher) -> Result<(), ProviderError> {
        if let Self::Array { encoded, .. } = self {
            let mut fields = Fields::array(encoded)?;
            while let Some(byte) = fields.next()? {
                hasher.update(&[u8::try_from(unsigned(byte)?).map_err(|_| invalid())?]);
            }
            return fields.finish();
        }
        let mut scratch = [0; 256];
        let mut offset = 0;
        while offset < self.len() {
            let length = (self.len() - offset).min(scratch.len());
            self.copy(offset, &mut scratch[..length])?;
            hasher.update(&scratch[..length]);
            offset += length;
        }
        Ok(())
    }

    pub(crate) fn hash(self) -> Result<[u8; 32], ProviderError> {
        let mut hasher = blake3::Hasher::new();
        self.update_hash(&mut hasher)?;
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn equal(self, other: Self) -> Result<(), ProviderError> {
        if self.len() != other.len() {
            return Err(invalid());
        }
        if let Self::Array { encoded, .. } = self {
            let mut fields = Fields::array(encoded)?;
            let mut sink = ExactBytes17::new(other)?;
            while let Some(byte) = fields.next()? {
                sink.write_all(&[u8::try_from(unsigned(byte)?).map_err(|_| invalid())?])?;
            }
            fields.finish()?;
            return sink.finish();
        }
        if matches!(other, Self::Array { .. }) {
            return other.equal(self);
        }
        let mut left = [0; 256];
        let mut right = [0; 256];
        let mut offset = 0;
        while offset < self.len() {
            let length = (self.len() - offset).min(left.len());
            self.copy(offset, &mut left[..length])?;
            other.copy(offset, &mut right[..length])?;
            if left[..length] != right[..length] {
                return Err(invalid());
            }
            offset += length;
        }
        Ok(())
    }

    pub(crate) fn canonical(self, source: &[u8]) -> Result<(), ProviderError> {
        let mut sink = ExactBytes17::new(self)?;
        canonical_to_writer(source, &mut sink)?;
        sink.finish()
    }
}

pub(crate) struct ExactBytes17<'a> {
    expected: Bytes17<'a>,
    position: usize,
    array: Option<Fields<'a>>,
}

impl<'a> ExactBytes17<'a> {
    pub(crate) fn new(expected: Bytes17<'a>) -> Result<Self, ProviderError> {
        let array = if let Bytes17::Array { encoded, .. } = expected {
            Some(Fields::array(encoded)?)
        } else {
            None
        };
        Ok(Self {
            expected,
            position: 0,
            array,
        })
    }

    pub(crate) fn finish(self) -> Result<(), ProviderError> {
        if self.position != self.expected.len() {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Write for ExactBytes17<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(fields) = &mut self.array {
            for byte in bytes {
                let encoded = next(fields).map_err(|_| std::io::ErrorKind::InvalidData)?;
                if unsigned(encoded).map_err(|_| std::io::ErrorKind::InvalidData)?
                    != u64::from(*byte)
                {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
            }
            self.position = self
                .position
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::InvalidData)?;
            return Ok(bytes.len());
        }
        let mut scratch = [0; 256];
        for chunk in bytes.chunks(scratch.len()) {
            self.expected
                .copy(self.position, &mut scratch[..chunk.len()])
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
            if scratch[..chunk.len()] != *chunk {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            self.position = self
                .position
                .checked_add(chunk.len())
                .ok_or(std::io::ErrorKind::InvalidData)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Streams canonical correspondence for already grammar-checked source DATA.
/// This is not a JSON validator or an acceptance entrypoint.
pub(crate) fn canonical_to_writer(
    input: &[u8],
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    let mut work = 64usize * 1024 * 1024;
    canonical(input, output, 0, &mut work)
}

fn charge(work: &mut usize, amount: usize) -> Result<(), ProviderError> {
    *work = work
        .checked_sub(amount)
        .ok_or(ProviderError::ResourceExhausted(
            "native17 borrowed comparison work",
        ))?;
    Ok(())
}

fn canonical(
    input: &[u8],
    output: &mut impl Write,
    depth: usize,
    work: &mut usize,
) -> Result<(), ProviderError> {
    charge(work, input.len())?;
    if depth >= 64 && matches!(input.first(), Some(b'{' | b'[')) {
        return Err(invalid());
    }
    match input.first() {
        Some(b'{') => {
            output.write_all(b"{")?;
            let mut previous: Option<&[u8]> = None;
            let mut emitted = 0usize;
            loop {
                charge(work, input.len())?;
                let mut fields = Fields::object(input)?;
                let mut selected: Option<(&[u8], &[u8])> = None;
                let mut total = 0usize;
                while let Some((key, value)) = fields.pair()? {
                    total = total.checked_add(1).ok_or_else(invalid)?;
                    charge(work, key.len())?;
                    if let Some(previous) = previous {
                        if string_order(key, previous)? != Ordering::Greater {
                            continue;
                        }
                    }
                    let replace = match selected {
                        None => true,
                        Some((prior, _)) => string_order(key, prior)? == Ordering::Less,
                    };
                    if replace {
                        selected = Some((key, value));
                    }
                }
                fields.finish()?;
                let Some((key, value)) = selected else {
                    if total != emitted {
                        return Err(invalid());
                    }
                    break;
                };
                if emitted != 0 {
                    output.write_all(b",")?;
                }
                output.write_all(key)?;
                output.write_all(b":")?;
                canonical(value, output, depth + 1, work)?;
                previous = Some(key);
                emitted += 1;
            }
            output.write_all(b"}")?;
        }
        Some(b'[') => {
            output.write_all(b"[")?;
            let mut fields = Fields::array(input)?;
            let mut count = 0usize;
            while let Some(value) = fields.next()? {
                if count != 0 {
                    output.write_all(b",")?;
                }
                canonical(value, output, depth + 1, work)?;
                count = count.checked_add(1).ok_or_else(invalid)?;
                if count > 65536 {
                    return Err(invalid());
                }
            }
            fields.finish()?;
            output.write_all(b"]")?;
        }
        Some(b'"') | Some(b't' | b'f' | b'n') => output.write_all(input)?,
        Some(b'-' | b'0'..=b'9') => {
            // Only a fixed Number leaf enters the authoritative JCS writer.
            // There is no Value map, owned string, sorting bank or parser DOM.
            let text = std::str::from_utf8(input).map_err(|_| invalid())?;
            let numeric: f64 = text.parse().map_err(|_| invalid())?;
            let number = serde_json::Number::from_f64(numeric).ok_or_else(invalid)?;
            crucible_node_contract::canonical::canonical_json_to_writer(
                &serde_json::Value::Number(number),
                output,
            )?;
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

fn string_order(left: &[u8], right: &[u8]) -> Result<Ordering, ProviderError> {
    let mut left = JsonUnits::new(left)?;
    let mut right = JsonUnits::new(right)?;
    loop {
        match (left.next()?, right.next()?) {
            (None, None) => return Ok(Ordering::Equal),
            (None, Some(_)) => return Ok(Ordering::Less),
            (Some(_), None) => return Ok(Ordering::Greater),
            (Some(left), Some(right)) if left != right => return Ok(left.cmp(&right)),
            _ => {}
        }
    }
}

struct JsonUnits<'a> {
    input: &'a [u8],
    position: usize,
    pending: Option<u16>,
}

impl<'a> JsonUnits<'a> {
    fn new(input: &'a [u8]) -> Result<Self, ProviderError> {
        if input.first() != Some(&b'"') || input.last() != Some(&b'"') {
            return Err(invalid());
        }
        Ok(Self {
            input: &input[1..input.len() - 1],
            position: 0,
            pending: None,
        })
    }
    fn next(&mut self) -> Result<Option<u16>, ProviderError> {
        if let Some(unit) = self.pending.take() {
            return Ok(Some(unit));
        }
        let Some(byte) = self.input.get(self.position).copied() else {
            return Ok(None);
        };
        self.position += 1;
        if byte == b'\\' {
            let escaped = *self.input.get(self.position).ok_or_else(invalid)?;
            self.position += 1;
            return Ok(Some(match escaped {
                b'"' => 34,
                b'\\' => 92,
                b'/' => 47,
                b'b' => 8,
                b'f' => 12,
                b'n' => 10,
                b'r' => 13,
                b't' => 9,
                b'u' => {
                    let end = self.position.checked_add(4).ok_or_else(invalid)?;
                    let digits = self.input.get(self.position..end).ok_or_else(invalid)?;
                    self.position = end;
                    let text = std::str::from_utf8(digits).map_err(|_| invalid())?;
                    u16::from_str_radix(text, 16).map_err(|_| invalid())?
                }
                _ => return Err(invalid()),
            }));
        }
        if byte < 128 {
            return Ok(Some(u16::from(byte)));
        }
        self.position -= 1;
        let text = std::str::from_utf8(&self.input[self.position..]).map_err(|_| invalid())?;
        let character = text.chars().next().ok_or_else(invalid)?;
        self.position += character.len_utf8();
        let mut units = [0; 2];
        let encoded = character.encode_utf16(&mut units);
        if encoded.len() == 2 {
            self.pending = Some(encoded[1]);
        }
        Ok(Some(encoded[0]))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Frame17<'a> {
    pub(crate) bytes: Bytes17<'a>,
    pub(crate) incoming: bool,
    pub(crate) transferred: usize,
    pub(crate) complete: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Frames17<'a> {
    pub(crate) bytes: Bytes17<'a>,
    slots: &'a [u8],
    pub(crate) incoming: usize,
    pub(crate) outgoing: usize,
}

impl<'a> Frames17<'a> {
    pub(crate) fn read(input: &'a [u8]) -> Result<Self, ProviderError> {
        // The exact complete compact grammar and source capacities were checked
        // by the enclosing Ledger pass; validation here also guards every range.
        let mut fields = Fields::array(input)?;
        next(&mut fields)?;
        next(&mut fields)?;
        let incoming = quantity(next(&mut fields)?)?;
        let outgoing = quantity(next(&mut fields)?)?;
        next(&mut fields)?;
        next(&mut fields)?;
        let bytes = Bytes17::compact(next(&mut fields)?)?;
        let slots = next(&mut fields)?;
        fields.finish()?;
        Ok(Self {
            bytes,
            slots,
            incoming,
            outgoing,
        })
    }

    pub(crate) fn count(self) -> Result<usize, ProviderError> {
        count(self.slots)
    }

    pub(crate) fn authenticate_incoming(self, envelope: &[u8]) -> Result<(), ProviderError> {
        let digest = canonical_digest(envelope)?;
        for index in 0..self.count()? {
            let frame = self.frame(index)?;
            if frame.incoming
                && frame.complete
                && frame.transferred == frame.bytes.len()
                && frame.bytes.len() >= 4
            {
                let body = frame.bytes.range(4, frame.bytes.len() - 4)?;
                if body.hash()? == digest {
                    return body.canonical(envelope);
                }
            }
        }
        Err(invalid())
    }

    pub(crate) fn single_literal(self, incoming: bool) -> Result<Bytes17<'a>, ProviderError> {
        let mut found = None;
        for index in 0..self.count()? {
            let frame = self.frame(index)?;
            if frame.incoming == incoming {
                if !frame.complete || frame.transferred != frame.bytes.len() || found.is_some() {
                    return Err(invalid());
                }
                found = Some(frame.bytes);
            }
        }
        found.ok_or_else(invalid)
    }

    pub(crate) fn single_body(self, incoming: bool) -> Result<Bytes17<'a>, ProviderError> {
        let literal = self.single_literal(incoming)?;
        literal.range(4, literal.len().checked_sub(4).ok_or_else(invalid)?)
    }

    pub(crate) fn frame(self, index: usize) -> Result<Frame17<'a>, ProviderError> {
        let mut fields = Fields::array(item(self.slots, index)?)?;
        let incoming = match plain_string(next(&mut fields)?)? {
            "incoming" => true,
            "outgoing" => false,
            _ => return Err(invalid()),
        };
        let start = quantity(next(&mut fields)?)?;
        let length = quantity(next(&mut fields)?)?;
        let transferred = quantity(next(&mut fields)?)?;
        let complete = boolean(next(&mut fields)?)?;
        next(&mut fields)?;
        fields.finish()?;
        Ok(Frame17 {
            bytes: self.bytes.range(start, length)?,
            incoming,
            transferred,
            complete,
        })
    }

    pub(crate) fn held_prefix_digest(self, count: usize) -> Result<[u8; 32], ProviderError> {
        if count > self.count()? {
            return Err(invalid());
        }
        let mut hasher = blake3::Hasher::new_derive_key(
            "source-private.complete-restore-held-proof-literals/12",
        );
        for index in 0..count {
            let frame = self.frame(index)?;
            if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
                return Err(invalid());
            }
            hasher.update(&[if frame.incoming { 0 } else { 1 }]);
            hasher.update(
                &u64::try_from(frame.bytes.len())
                    .map_err(|_| invalid())?
                    .to_le_bytes(),
            );
            frame.bytes.update_hash(&mut hasher)?;
        }
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn require_complete(self) -> Result<(), ProviderError> {
        for index in 0..self.count()? {
            let frame = self.frame(index)?;
            if !frame.complete || frame.transferred != frame.bytes.len() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
