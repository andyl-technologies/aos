//! Shares literal traversal between the retained token codec and worker streams.

use crate::errors::RuntimeError;
use serde_json::Value;

/// Borrows one literal token without cloning its source string or key.
#[derive(Clone, Copy)]
pub enum BorrowedToken18<'a> {
    /// Borrows a literal JSON null.
    Null,
    /// Copies a literal JSON boolean.
    Bool(bool),
    /// Copies an unsigned integer selected before signed or floating forms.
    Unsigned(u64),
    /// Copies a negative signed integer as its original two's-complement bits.
    Signed(u64),
    /// Copies the exact bits of a supported finite floating-point number.
    FloatBits(u64),
    /// Borrows literal string text without serde marker interpretation.
    String(&'a str),
    /// Starts an array whose children remain owned by the original Value.
    ArrayStart,
    /// Ends the current array.
    ArrayEnd,
    /// Starts an object in its original immutable map order.
    ObjectStart,
    /// Borrows a literal object key, including reserved serde spellings.
    Key(&'a str),
    /// Ends the current object.
    ObjectEnd,
}

/// Retains only borrowed child iterators in the independently funded workspace.
pub enum Frame<'a> {
    /// Retains only an iterator borrowing the original array children.
    Array(std::slice::Iter<'a, Value>),
    /// Retains only an iterator borrowing the original map entries.
    Object(serde_json::map::Iter<'a>),
}

/// Visits one immutable Value with a bounded disposable iterator bank.
///
/// `GROW = false` preserves the retained codec's preallocated no-growth bank.
/// The contained worker uses `GROW = true` for its disposable prewalk. Both
/// modes borrow the original tree and expose no mutable or owning Value.
pub struct Walker<'a, const GROW: bool> {
    frames: Vec<Frame<'a>>,
    pending: Option<&'a Value>,
    current: Option<&'a Value>,
    population: usize,
    visited: usize,
}

impl<'a, const GROW: bool> Walker<'a, GROW> {
    /// Creates a disposable bank after its caller admits the traversal prewalk.
    ///
    /// No borrowed frame or Source reference survives this owner's disposal.
    ///
    /// # Errors
    /// Refuses allocation failure; later iteration checks the actual population.
    pub fn new(value: &'a Value, population: usize) -> Result<Self, RuntimeError> {
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(population)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(Self {
            frames,
            pending: Some(value),
            current: None,
            population,
            visited: 0,
        })
    }

    pub(super) fn from_bank(value: &'a Value, population: usize, frames: Vec<Frame<'a>>) -> Self {
        Self {
            frames,
            pending: Some(value),
            current: None,
            population,
            visited: 0,
        }
    }

    pub(super) fn into_bank(mut self) -> Vec<Frame<'a>> {
        self.frames.clear();
        self.frames
    }

    /// Borrows the actual value visited by the immediately preceding token.
    pub fn current_value(&self) -> Option<&'a Value> {
        self.current
    }

    /// Visits the next literal token in the selected workspace-growth mode.
    ///
    /// Retained traversal (`GROW = false`) refuses before growing its original
    /// bank. The contained worker prewalk may grow only its disposable bank.
    ///
    /// # Errors
    /// Refuses insufficient population/bank capacity or unsupported numbers.
    pub fn next_token(&mut self) -> Result<Option<BorrowedToken18<'a>>, RuntimeError> {
        self.current = None;
        loop {
            if let Some(value) = self.pending.take() {
                self.current = Some(value);
                self.visited = self
                    .visited
                    .checked_add(1)
                    .ok_or(RuntimeError::ResourceLimit)?;
                if self.visited > self.population {
                    return Err(RuntimeError::ResourceLimit);
                }
                let token = match value {
                    Value::Null => BorrowedToken18::Null,
                    Value::Bool(value) => BorrowedToken18::Bool(*value),
                    Value::Number(value) if value.is_u64() => BorrowedToken18::Unsigned(
                        value.as_u64().ok_or(RuntimeError::UnsupportedFacet)?,
                    ),
                    Value::Number(value) if value.is_i64() => {
                        let value = value.as_i64().ok_or(RuntimeError::UnsupportedFacet)?;
                        BorrowedToken18::Signed(u64::from_ne_bytes(value.to_ne_bytes()))
                    }
                    Value::Number(value) => BorrowedToken18::FloatBits(
                        value
                            .as_f64()
                            .filter(|value| value.is_finite())
                            .ok_or(RuntimeError::UnsupportedFacet)?
                            .to_bits(),
                    ),
                    Value::String(value) => BorrowedToken18::String(value),
                    Value::Array(values) => {
                        // Only the worker stream prewalk grows a disposable borrowed bank.
                        // The original retained codec instantiates GROW=false and keeps
                        // its exact preadmitted no-growth constructor and refusal.
                        if GROW && self.frames.len() == self.frames.capacity() {
                            self.frames
                                .try_reserve(1)
                                .map_err(|_| RuntimeError::ResourceLimit)?;
                        }
                        if self.frames.len() == self.frames.capacity() {
                            return Err(RuntimeError::ResourceLimit);
                        }
                        self.frames.push(Frame::Array(values.iter()));
                        BorrowedToken18::ArrayStart
                    }
                    Value::Object(values) => {
                        // Only the worker stream prewalk grows a disposable borrowed bank.
                        // The original retained codec instantiates GROW=false and keeps
                        // its exact preadmitted no-growth constructor and refusal.
                        if GROW && self.frames.len() == self.frames.capacity() {
                            self.frames
                                .try_reserve(1)
                                .map_err(|_| RuntimeError::ResourceLimit)?;
                        }
                        if self.frames.len() == self.frames.capacity() {
                            return Err(RuntimeError::ResourceLimit);
                        }
                        self.frames.push(Frame::Object(values.iter()));
                        BorrowedToken18::ObjectStart
                    }
                };
                return Ok(Some(token));
            }
            match self.frames.last_mut() {
                Some(Frame::Array(values)) => match values.next() {
                    Some(value) => self.pending = Some(value),
                    None => {
                        self.frames.pop();
                        return Ok(Some(BorrowedToken18::ArrayEnd));
                    }
                },
                Some(Frame::Object(values)) => match values.next() {
                    Some((key, value)) => {
                        self.pending = Some(value);
                        return Ok(Some(BorrowedToken18::Key(key)));
                    }
                    None => {
                        self.frames.pop();
                        return Ok(Some(BorrowedToken18::ObjectEnd));
                    }
                },
                None => return Ok(None),
            }
        }
    }
}

impl<'a> Walker<'a, true> {
    /// Starts a bounded streaming prewalk without allocating a policy maximum.
    pub(crate) fn streaming(value: &'a Value, maximum_nodes: usize) -> Self {
        Self {
            frames: Vec::new(),
            pending: Some(value),
            current: None,
            population: maximum_nodes,
            visited: 0,
        }
    }
}
