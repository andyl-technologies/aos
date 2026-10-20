//! Assembles streamed literal Values under preinstalled iterative destruction.

use super::*;
use serde_json::{Map, Number, Value};
use std::{
    fmt,
    io::{self, Read},
};

/// Owns one completed literal Value and its allocation-free teardown workspace.
///
/// The immutable view remains tied to this owner. Recursive operations on that
/// view need their own depth/resource proof; ordinary Value cloning or serde
/// conversion is not made safe merely by successful stream decoding.
pub struct DecodedValue {
    state: Assembly,
    statistics: StreamStatistics,
}

impl DecodedValue {
    /// Borrows the completed literal Value without transferring its destructor.
    ///
    /// # Errors
    /// Refuses an absent completed root if an internal construction invariant
    /// is violated; it never substitutes a different Value.
    pub fn value(&self) -> Result<&Value, StreamError> {
        self.state.root.as_ref().ok_or(StreamError::Format(
            StreamFormatReason::MissingCompletedRoot,
        ))
    }

    /// Returns validated actual wire, node and nesting counts.
    pub fn statistics(&self) -> StreamStatistics {
        self.statistics
    }
}

impl fmt::Debug for DecodedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedValue")
            .field("statistics", &self.statistics)
            .finish_non_exhaustive()
    }
}

/// Retains the actual refusal and every partially assembled owning child.
///
/// Dropping this owner drains all Values iteratively. It does not discard deep
/// partial containers through ordinary recursive Value destruction.
pub struct ReadFailure {
    error: StreamError,
    state: Assembly,
}

impl ReadFailure {
    /// Borrows the original refusal.
    pub fn error(&self) -> &StreamError {
        &self.error
    }

    /// Counts actual Value-producing tokens read before refusal.
    pub fn values_read(&self) -> usize {
        self.state.values
    }

    /// Counts containers still open at refusal.
    pub fn open_containers(&self) -> usize {
        self.state.frames.len()
    }

    /// Borrows the actual prefix of the most recent incomplete text token.
    pub fn partial_text(&self) -> &[u8] {
        &self.state.text[..self.state.text_read]
    }

    /// Counts bytes actually consumed, including a partially read header/token.
    pub fn wire_bytes_read(&self) -> usize {
        self.state.wire_read
    }
}

impl fmt::Debug for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadFailure")
            .field("error", &self.error)
            .field("values_read", &self.values_read())
            .field("open_containers", &self.open_containers())
            .field("wire_bytes_read", &self.wire_bytes_read())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for ReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Reads exactly one literal frame, leaving subsequent framed data unread.
///
/// The header's declared counts are checked against the operation's bounds and
/// then verified against the actual tokens. Workspace is reserved before the
/// first owning Value; no policy maximum is allocated by default. The reader
/// invokes no JSON parser, serde visitor or RawValue normalization.
///
/// # Errors
/// Returns an owning failure for short I/O, malformed tags/UTF8/chronology,
/// duplicate keys, invalid numbers/counts, arithmetic, allocation or limits.
/// Allocator abort and process termination cannot produce a Rust error result.
pub fn read_value(
    input: &mut impl Read,
    limits: StreamLimits,
) -> Result<DecodedValue, ReadFailure> {
    let mut state = Assembly::new();
    match state.read(input, limits) {
        Ok(statistics) => Ok(DecodedValue { state, statistics }),
        Err(error) => Err(ReadFailure { error, state }),
    }
}

enum Frame {
    Array(Vec<Value>),
    Object {
        values: Map<String, Value>,
        key: Option<String>,
    },
}

struct Assembly {
    frames: Vec<Frame>,
    retirement: Vec<Value>,
    pending: Option<Value>,
    root: Option<Value>,
    header: [u8; HEADER_BYTES],
    header_read: usize,
    word: [u8; 8],
    word_read: usize,
    text: Vec<u8>,
    text_read: usize,
    remaining: usize,
    wire_read: usize,
    values: usize,
    maximum_depth: usize,
    declared_values: usize,
    declared_depth: usize,
}

impl Assembly {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            retirement: Vec::new(),
            pending: None,
            root: None,
            header: [0; HEADER_BYTES],
            header_read: 0,
            word: [0; 8],
            word_read: 0,
            text: Vec::new(),
            text_read: 0,
            remaining: 0,
            wire_read: 0,
            values: 0,
            maximum_depth: 0,
            declared_values: 0,
            declared_depth: 0,
        }
    }

    fn read(
        &mut self,
        input: &mut impl Read,
        limits: StreamLimits,
    ) -> Result<StreamStatistics, StreamError> {
        if limits.maximum_wire_bytes < HEADER_BYTES {
            return Err(StreamError::Limit(StreamLimitReason::WireBytes));
        }
        fill(
            input,
            &mut self.header,
            &mut self.header_read,
            &mut self.wire_read,
        )?;
        if &self.header[..8] != MAGIC {
            return Err(StreamError::Format(StreamFormatReason::MagicOrVersion));
        }
        self.remaining = host_integer(header_word(&self.header, 8))?;
        self.declared_values = host_integer(header_word(&self.header, 16))?;
        self.declared_depth = host_integer(header_word(&self.header, 24))?;
        let wire_bytes = checked_add(HEADER_BYTES, self.remaining)?;
        if wire_bytes > limits.maximum_wire_bytes {
            return Err(StreamError::Limit(StreamLimitReason::WireBytes));
        }
        if self.declared_values == 0 || self.declared_values > self.remaining {
            return Err(StreamError::Format(
                StreamFormatReason::ImpossibleValueCount,
            ));
        }
        if self.declared_values > limits.maximum_values {
            return Err(StreamError::Limit(StreamLimitReason::ValueCount));
        }
        if self.declared_depth > self.declared_values {
            return Err(StreamError::Format(StreamFormatReason::ImpossibleDepth));
        }
        // A placeholder may coexist with its completed pending child. Each is
        // associated with one declared node; 2*N+1 covers their entire disjoint
        // retirement frontier. This is reserved before constructing any Value.
        let retirement = self
            .declared_values
            .checked_mul(2)
            .and_then(|nodes| nodes.checked_add(1))
            .ok_or(StreamError::Limit(
                StreamLimitReason::RetirementSizeOverflow,
            ))?;
        self.retirement.try_reserve_exact(retirement)?;
        self.frames.try_reserve_exact(self.declared_depth)?;

        while self.remaining != 0 {
            if self.root.is_some() && self.frames.is_empty() {
                return Err(StreamError::Format(StreamFormatReason::TrailingPayload));
            }
            let tag = self.read_byte(input)?;
            match tag {
                0..=7 | 9 => {
                    self.accepts_value()?;
                    self.values = checked_add(self.values, 1)?;
                    if self.values > self.declared_values {
                        return Err(StreamError::Format(StreamFormatReason::ValueCountExceeded));
                    }
                    match tag {
                        7 | 9 => self.open(tag)?,
                        0 => self.pending = Some(Value::Null),
                        1 | 2 => self.pending = Some(Value::Bool(tag == 2)),
                        3 => self.pending = Some(Value::from(self.read_word(input)?)),
                        4 => {
                            let value = i64::from_be_bytes(self.read_word(input)?.to_be_bytes());
                            if value >= 0 {
                                return Err(StreamError::Format(
                                    StreamFormatReason::SignedTokenNotNegative,
                                ));
                            }
                            self.pending = Some(Value::from(value));
                        }
                        5 => {
                            let value = f64::from_bits(self.read_word(input)?);
                            let number = Number::from_f64(value)
                                .ok_or(StreamError::Format(StreamFormatReason::NonFiniteFloat))?;
                            self.pending = Some(Value::Number(number));
                        }
                        6 => self.pending = Some(Value::String(self.read_text(input)?)),
                        _ => return Err(StreamError::Format(StreamFormatReason::ValueTag)),
                    }
                    if self.pending.is_some() {
                        self.attach()?;
                    }
                }
                8 | 11 => self.close(tag)?,
                10 => self.key(input)?,
                _ => return Err(StreamError::Format(StreamFormatReason::UnknownToken)),
            }
        }
        if !self.frames.is_empty() || self.pending.is_some() || self.root.is_none() {
            return Err(StreamError::Format(StreamFormatReason::IncompleteValue));
        }
        if self.values != self.declared_values || self.maximum_depth != self.declared_depth {
            return Err(StreamError::Format(StreamFormatReason::HeaderCountsDiffer));
        }
        Ok(StreamStatistics {
            wire_bytes,
            values: self.values,
            depth: self.maximum_depth,
        })
    }

    fn accepts_value(&self) -> Result<(), StreamError> {
        match self.frames.last() {
            Some(Frame::Array(_)) | Some(Frame::Object { key: Some(_), .. }) => Ok(()),
            None if self.root.is_none() => Ok(()),
            _ => Err(StreamError::Format(
                StreamFormatReason::ValueWithoutDestination,
            )),
        }
    }

    fn open(&mut self, tag: u8) -> Result<(), StreamError> {
        if self.frames.len() == self.declared_depth {
            return Err(StreamError::Format(StreamFormatReason::DepthExceeded));
        }
        // The actual empty container enters owner custody before child work.
        self.frames.push(if tag == 7 {
            Frame::Array(Vec::new())
        } else {
            Frame::Object {
                values: Map::new(),
                key: None,
            }
        });
        self.maximum_depth = self.maximum_depth.max(self.frames.len());
        Ok(())
    }

    fn close(&mut self, tag: u8) -> Result<(), StreamError> {
        match (tag, self.frames.last()) {
            (8, Some(Frame::Array(_))) | (11, Some(Frame::Object { key: None, .. })) => {}
            _ => {
                return Err(StreamError::Format(
                    StreamFormatReason::MismatchedCloseOrMissingObjectValue,
                ));
            }
        }
        // No fallible work occurs between removing the deep frame and rooting
        // it in pending; attach keeps pending installed until its destination
        // has a reserved slot or a preinstalled shallow map placeholder.
        self.pending = match self.frames.pop() {
            Some(Frame::Array(values)) => Some(Value::Array(values)),
            Some(Frame::Object { values, .. }) => Some(Value::Object(values)),
            None => return Err(StreamError::Format(StreamFormatReason::MissingContainer)),
        };
        self.attach()
    }

    fn key(&mut self, input: &mut impl Read) -> Result<(), StreamError> {
        if !matches!(self.frames.last(), Some(Frame::Object { key: None, .. })) {
            return Err(StreamError::Format(
                StreamFormatReason::KeyWithoutObjectDestination,
            ));
        }
        let text = self.read_text(input)?;
        let Some(Frame::Object { values, key }) = self.frames.last_mut() else {
            return Err(StreamError::Format(StreamFormatReason::MissingObject));
        };
        *key = Some(text);
        let actual = key
            .as_ref()
            .ok_or(StreamError::Format(StreamFormatReason::MissingKey))?;
        if values.contains_key(actual) {
            return Err(StreamError::Format(StreamFormatReason::DuplicateKey));
        }
        // Install the map slot while its value is shallow. Deep children later
        // move through get_mut/replace, never through an allocating map insert.
        let mut stored_key = String::new();
        stored_key.try_reserve_exact(actual.len())?;
        stored_key.push_str(actual);
        values.insert(stored_key, Value::Null);
        Ok(())
    }

    fn attach(&mut self) -> Result<(), StreamError> {
        match self.frames.last_mut() {
            Some(Frame::Array(values)) => {
                values.try_reserve(1)?;
                let value = self
                    .pending
                    .take()
                    .ok_or(StreamError::Format(StreamFormatReason::MissingPendingValue))?;
                values.push(value);
            }
            Some(Frame::Object { values, key }) => {
                let actual = key
                    .as_ref()
                    .ok_or(StreamError::Format(StreamFormatReason::MissingObjectKey))?;
                let slot = values
                    .get_mut(actual)
                    .ok_or(StreamError::Format(StreamFormatReason::MissingObjectSlot))?;
                if !slot.is_null() {
                    return Err(StreamError::Format(StreamFormatReason::OccupiedObjectSlot));
                }
                let value = self
                    .pending
                    .take()
                    .ok_or(StreamError::Format(StreamFormatReason::MissingPendingValue))?;
                let shallow = std::mem::replace(slot, value);
                drop(shallow);
                *key = None;
            }
            None => self.root = self.pending.take(),
        }
        Ok(())
    }

    fn read_byte(&mut self, input: &mut impl Read) -> Result<u8, StreamError> {
        if self.remaining == 0 {
            return Err(StreamError::Format(StreamFormatReason::TokenBeyondPayload));
        }
        self.word_read = 0;
        fill(
            input,
            &mut self.word[..1],
            &mut self.word_read,
            &mut self.wire_read,
        )?;
        self.remaining -= 1;
        Ok(self.word[0])
    }

    fn read_word(&mut self, input: &mut impl Read) -> Result<u64, StreamError> {
        if self.remaining < 8 {
            return Err(StreamError::Format(StreamFormatReason::WordBeyondPayload));
        }
        self.word_read = 0;
        let result = fill(
            input,
            &mut self.word,
            &mut self.word_read,
            &mut self.wire_read,
        );
        self.remaining -= self.word_read;
        result?;
        Ok(u64::from_be_bytes(self.word))
    }

    fn read_text(&mut self, input: &mut impl Read) -> Result<String, StreamError> {
        let length = host_integer(self.read_word(input)?)?;
        if length > self.remaining {
            return Err(StreamError::Format(StreamFormatReason::TextBeyondPayload));
        }
        self.text.clear();
        self.text_read = 0;
        self.text.try_reserve_exact(length)?;
        self.text.resize(length, 0);
        let result = fill(
            input,
            &mut self.text,
            &mut self.text_read,
            &mut self.wire_read,
        );
        self.remaining -= self.text_read;
        result?;
        match String::from_utf8(std::mem::take(&mut self.text)) {
            Ok(text) => {
                self.text_read = 0;
                Ok(text)
            }
            Err(error) => {
                self.text = error.into_bytes();
                Err(StreamError::Format(StreamFormatReason::InvalidUtf8))
            }
        }
    }
}

fn header_word(header: &[u8; HEADER_BYTES], offset: usize) -> u64 {
    u64::from_be_bytes([
        header[offset],
        header[offset + 1],
        header[offset + 2],
        header[offset + 3],
        header[offset + 4],
        header[offset + 5],
        header[offset + 6],
        header[offset + 7],
    ])
}

fn fill(
    input: &mut impl Read,
    bytes: &mut [u8],
    filled: &mut usize,
    consumed: &mut usize,
) -> Result<(), StreamError> {
    while *filled < bytes.len() {
        match input.read(&mut bytes[*filled..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(length) if length <= bytes.len() - *filled => {
                *filled += length;
                *consumed = checked_add(*consumed, length)?;
            }
            Ok(_) => {
                return Err(StreamError::Format(
                    StreamFormatReason::ReaderReturnedInvalidLength,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl Drop for Assembly {
    fn drop(&mut self) {
        if let Some(value) = self.root.take() {
            retire(value, &mut self.retirement);
        }
        if let Some(value) = self.pending.take() {
            retire(value, &mut self.retirement);
        }
        while let Some(frame) = self.frames.pop() {
            match frame {
                Frame::Array(values) => retire(Value::Array(values), &mut self.retirement),
                Frame::Object { values, key } => {
                    drop(key);
                    retire(Value::Object(values), &mut self.retirement);
                }
            }
        }
    }
}

fn retire(value: Value, workspace: &mut Vec<Value>) {
    // Every actual/placeholder Value is bounded by the validated node count.
    // Only this private owner mutates the graph; the reserved bank cannot need
    // to grow, even when the input fails after creating a deep partial prefix.
    workspace.push(value);
    while let Some(value) = workspace.pop() {
        match value {
            Value::Array(values) => {
                for child in values {
                    workspace.push(child);
                }
            }
            Value::Object(values) => {
                for (key, child) in values {
                    drop(key);
                    workspace.push(child);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}
