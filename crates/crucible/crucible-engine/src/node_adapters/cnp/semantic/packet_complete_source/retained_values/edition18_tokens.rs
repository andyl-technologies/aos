//! Preserves literal Source18 JSON through a shallow, closed token document.
//!
//! A retained Value can be deeper than ordinary JCS permits after the selected
//! SDK decoder expands a RawValue string. These DATA constructors never ask the
//! ordinary writer to recurse through that Value. They preserve its literal
//! keys and numeric representation, including floating-point negative zero.
//!
//! ```json
//! {"schema":"crucible/private-literal-value/18","chunks":[[
//!   {"type":"arrayStart"},{"type":"unsigned","value":"1"},
//!   {"type":"floatBits","value":"4607182418800017408"},{"type":"arrayEnd"}
//! ]]}
//! ```
//!
//! Each chunk respects the existing portable array bound. Source/SDK custody,
//! complete observations and constructor admission remain the caller's job.
//! No returned number, token document or successful assembly grants a native
//! operation or supplies a completed Source/native witness.

#[path = "edition18_tokens/correspondence.rs"]
mod correspondence;
#[path = "edition18_tokens/decode.rs"]
mod decode;
#[path = "edition18_tokens/encode.rs"]
mod encode;
#[path = "edition18_tokens/geometry.rs"]
mod geometry;
#[path = "edition18_tokens/index.rs"]
mod index;
#[path = "edition18_tokens/partials.rs"]
mod partials;
#[path = "edition18_tokens/read.rs"]
mod read;
#[path = "edition18_tokens/walk.rs"]
mod walk;

#[cfg(test)]
#[path = "edition18_tokens/tests.rs"]
mod tests;

pub(crate) use decode::{
    LiteralValue18DecodeAttempt, LiteralValue18DecodeQuote, decode_into_data, quote_decode_data,
    retained_decode_prewalk_data,
};
pub(crate) use encode::{
    LiteralValue18EncodeQuote, encode_into_data, quote_encode_data, traversal_prewalk_data,
};
pub(crate) use geometry::{
    decode_counter_scratch_data, encode_counter_scratch_data, read_counter_scratch_data,
};
pub(crate) use partials::LiteralValue18TokenAttemptPartialData;
pub(crate) use read::{LiteralValue18ReadQuote, quote_read_data, read_into_data};

use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_format::{MAX_ARRAY_ELEMENTS, U64};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};
use std::mem::{align_of, size_of};

const SCHEMA: &str = "crucible/private-literal-value/18";

/// Keeps one literal token without a recursively serialized Value payload.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub(crate) enum LiteralToken18 {
    /// Represents JSON null.
    Null,
    /// Represents a JSON boolean.
    Bool(bool),
    /// Represents the pinned Number positive-integer variant.
    Unsigned(U64),
    /// Represents a negative integer's two's-complement bits.
    Signed(U64),
    /// Represents the bits of the pinned Number finite-float variant.
    FloatBits(U64),
    /// Preserves a literal JSON string.
    String(String),
    /// Begins an array.
    ArrayStart,
    /// Ends an array.
    ArrayEnd,
    /// Begins an object.
    ObjectStart,
    /// Preserves a literal object key.
    Key(String),
    /// Ends an object.
    ObjectEnd,
}

/// Owns the closed shallow representation independently of its source Value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LiteralValue18Data {
    chunks: Vec<Vec<LiteralToken18>>,
    // Rebuilt from the actual token chronology; never serialized as authority.
    container_children: Vec<usize>,
}

impl LiteralValue18Data {
    /// Counts the token document's actual cache, chunk, token and String banks.
    ///
    /// An enclosing inline owner subtracts only this actual root header when
    /// its containing allocation already includes it. No Value traversal or
    /// serializer is invoked by this flat owning-data walk.
    ///
    /// # Errors
    /// Refuses checked layout overflow or the independent requested bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        checked_sum(
            [size_of::<Self>(), self.backing_storage_data(maximum)?],
            maximum,
        )
    }

    fn backing_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut bytes = checked_sum(
            [
                self.container_children
                    .capacity()
                    .checked_mul(size_of::<usize>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                self.chunks
                    .capacity()
                    .checked_mul(size_of::<Vec<LiteralToken18>>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        for chunk in &self.chunks {
            bytes = checked_sum(
                [
                    bytes,
                    chunk
                        .capacity()
                        .checked_mul(size_of::<LiteralToken18>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                ],
                maximum,
            )?;
            for token in chunk {
                if let LiteralToken18::String(text) | LiteralToken18::Key(text) = token {
                    bytes = checked_sum([bytes, text.capacity()], maximum)?;
                }
            }
        }
        Ok(bytes)
    }

    /// Names the actual flat document-census controls, without a deep walk.
    pub(crate) fn retained_counter_scratch_data() -> usize {
        geometry::token_owner_counter_scratch_data()
    }
}

impl Serialize for LiteralValue18Data {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut object = serializer.serialize_struct("LiteralValue18Data", 2)?;
        object.serialize_field("schema", SCHEMA)?;
        object.serialize_field("chunks", &self.chunks)?;
        object.end()
    }
}

/// Quotes requested constructor storage without granting an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiteralValue18Storage {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl LiteralValue18Storage {
    /// Returns independent retained, transient and fixed-control requirements.
    pub(crate) fn requested_storage_data(self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    fn new(
        retained: usize,
        transient: usize,
        scratch: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        checked_sum([retained, transient, scratch], maximum)?;
        Ok(Self {
            retained,
            transient,
            scratch,
        })
    }
}

/// Keeps a failed or incomplete token construction in its original output slot.
pub(crate) struct LiteralValue18TokenAttempt {
    started: bool,
    failed: bool,
    complete: bool,
    data: LiteralValue18Data,
}

impl LiteralValue18TokenAttempt {
    /// Creates only empty inline custody, before the first constructor allocation.
    pub(crate) const fn new() -> Self {
        Self {
            started: false,
            failed: false,
            complete: false,
            data: LiteralValue18Data {
                chunks: Vec::new(),
                container_children: Vec::new(),
            },
        }
    }

    /// Returns the actual attempted, failed and complete DATA-construction flags.
    pub(crate) fn state_data(&self) -> (bool, bool, bool) {
        (self.started, self.failed, self.complete)
    }

    /// Borrows the assembled DATA after its actual token constructor finished.
    ///
    /// # Errors
    /// Refuses incomplete or failed attempts; it grants no native completion.
    pub(crate) fn data(&self) -> Result<&LiteralValue18Data, RuntimeError> {
        if !self.complete || self.failed {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(&self.data)
    }

    /// Counts every retained token/string bank, including failed spare capacity.
    ///
    /// # Errors
    /// Refuses checked layout overflow or the independently supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        checked_sum(
            [size_of::<Self>(), self.data.backing_storage_data(maximum)?],
            maximum,
        )
    }

    /// Moves actual completed token banks into one still-empty retained output.
    ///
    /// The original attempt stays once-started and cannot be reused. Every
    /// refusal happens before taking the banks, so failed/occupied-output
    /// paths retain their exact original owners. This moves DATA only.
    ///
    /// # Errors
    /// Refuses an occupied destination or failed/incomplete token construction.
    pub(crate) fn take_data_into(
        &mut self,
        output: &mut Option<LiteralValue18Data>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.data()?;
        *output = Some(std::mem::replace(
            &mut self.data,
            LiteralValue18Data {
                chunks: Vec::new(),
                container_children: Vec::new(),
            },
        ));
        self.complete = false;
        Ok(())
    }

    fn begin(&mut self) -> Result<(), RuntimeError> {
        if self.started
            || self.failed
            || self.complete
            || !self.data.chunks.is_empty()
            || !self.data.container_children.is_empty()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.started = true;
        // Refusal and unwinding keep this true without a fallible Drop callback.
        self.failed = true;
        Ok(())
    }

    fn finish(&mut self) {
        self.complete = true;
        self.failed = false;
    }

    fn prepare_chunks(&mut self, tokens: usize) -> Result<(), RuntimeError> {
        let chunks = chunks_for(tokens)?;
        self.data
            .chunks
            .try_reserve_exact(chunks)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.data
            .container_children
            .try_reserve_exact(tokens)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.data.container_children.resize(tokens, 0);
        let mut remaining = tokens;
        for _ in 0..chunks {
            // The outer owner exists before allocating this child token bank.
            self.data.chunks.push(Vec::new());
            let child = self
                .data
                .chunks
                .last_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let slots = remaining.min(MAX_ARRAY_ELEMENTS);
            child
                .try_reserve_exact(slots)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            remaining -= slots;
        }
        Ok(())
    }

    fn push(&mut self, index: usize, token: walk::BorrowedToken18<'_>) -> Result<(), RuntimeError> {
        let chunk = self
            .data
            .chunks
            .get_mut(index / MAX_ARRAY_ELEMENTS)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if chunk.len() != index % MAX_ARRAY_ELEMENTS || chunk.len() == chunk.capacity() {
            return Err(RuntimeError::ResourceLimit);
        }
        let owned = match token {
            walk::BorrowedToken18::Null => LiteralToken18::Null,
            walk::BorrowedToken18::Bool(value) => LiteralToken18::Bool(value),
            walk::BorrowedToken18::Unsigned(value) => LiteralToken18::Unsigned(U64::new(value)),
            walk::BorrowedToken18::Signed(value) => LiteralToken18::Signed(U64::new(value)),
            walk::BorrowedToken18::FloatBits(value) => LiteralToken18::FloatBits(U64::new(value)),
            walk::BorrowedToken18::String(_) => LiteralToken18::String(String::new()),
            walk::BorrowedToken18::Key(_) => LiteralToken18::Key(String::new()),
            walk::BorrowedToken18::ArrayStart => LiteralToken18::ArrayStart,
            walk::BorrowedToken18::ArrayEnd => LiteralToken18::ArrayEnd,
            walk::BorrowedToken18::ObjectStart => LiteralToken18::ObjectStart,
            walk::BorrowedToken18::ObjectEnd => LiteralToken18::ObjectEnd,
        };
        chunk.push(owned);
        if let walk::BorrowedToken18::String(input) | walk::BorrowedToken18::Key(input) = token {
            let Some(LiteralToken18::String(output) | LiteralToken18::Key(output)) =
                chunk.last_mut()
            else {
                return Err(RuntimeError::OwnerUnavailable);
            };
            // The failed attempt owns this exact String before it can grow.
            output
                .try_reserve_exact(input.len())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            output.push_str(input);
        }
        Ok(())
    }
}

fn chunks_for(tokens: usize) -> Result<usize, RuntimeError> {
    if tokens == 0 {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let chunks = tokens
        .checked_add(MAX_ARRAY_ELEMENTS - 1)
        .ok_or(RuntimeError::ResourceLimit)?
        / MAX_ARRAY_ELEMENTS;
    if chunks > MAX_ARRAY_ELEMENTS {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(chunks)
}

fn checked_sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    terms.into_iter().try_fold(0usize, |sum, term| {
        sum.checked_add(term)
            .filter(|sum| *sum <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

fn map_storage(entries: usize, maximum: usize) -> Result<usize, RuntimeError> {
    NodeRuntime::capture_protocol_tree_storage(
        1,
        entries,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
        maximum,
    )
}
