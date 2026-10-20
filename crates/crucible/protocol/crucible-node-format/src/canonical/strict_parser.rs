//! Shares the strict parser's cursor, scalar grammar and container transitions.
//!
//! The ordinary public parser executes these same decisions. This private seam
//! supplies no retained attempt, dynamic constructor demand, admission or new
//! accepted form. Quoted strings still delegate one exact token to serde; CNP
//! numbers still use Rust's correctly rounded conversion before local Ryu
//! integral normalization. No serde feature or RawValue pass is introduced.

use crate::{ContractError, MAX_ARRAY_ELEMENTS, invalid};
use serde_json::{Map, Number, Value};

/// Checks the original depth restriction before the original byte restriction.
///
/// # Errors
/// Returns the original depth error before checking oversized input.
pub(super) fn check_limits(
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_depth: usize,
) -> Result<(), ContractError> {
    if maximum_depth == 0 || maximum_depth > 64 {
        return Err(invalid(
            "json_depth",
            "require a nesting limit between 1 and 64",
        ));
    }
    if bytes.len() > maximum_bytes {
        return Err(invalid("json", "frame exceeds admitted byte limit"));
    }
    Ok(())
}

/// Keeps only borrowed bytes and the original numeric cursor/depth controls.
pub(super) struct Parser<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) cursor: usize,
    pub(super) maximum_depth: usize,
}

/// Distinguishes a scalar return from a container whose construction follows.
pub(super) enum ValueStart {
    Scalar(Value),
    Array,
    Object,
}

/// Chooses the original matching delimiter and refusal for a real container.
pub(super) enum ContainerKind {
    Array,
    Object,
}

impl Parser<'_> {
    /// Builds an ordinary value using the same scalar and container decisions.
    ///
    /// # Errors
    /// Preserves strict parsing errors and their original visit order.
    pub(super) fn value(&mut self, depth: usize) -> Result<Value, ContractError> {
        match self.value_start()? {
            ValueStart::Scalar(value) => Ok(value),
            ValueStart::Array => self.array(depth),
            ValueStart::Object => self.object(depth),
        }
    }

    /// Performs the same whitespace, scalar and container-token classification.
    ///
    /// A container is not opened or constructed here. Its original depth check
    /// precedes consuming its delimiter and initializing its Vec or Map.
    ///
    /// # Errors
    /// Returns the original scalar/token error at the current cursor.
    pub(super) fn value_start(&mut self) -> Result<ValueStart, ContractError> {
        self.whitespace();
        match self.bytes.get(self.cursor).copied() {
            Some(b'"') => self.string().map(Value::String).map(ValueStart::Scalar),
            Some(b'[') => Ok(ValueStart::Array),
            Some(b'{') => Ok(ValueStart::Object),
            Some(b't') => self
                .literal(b"true", Value::Bool(true))
                .map(ValueStart::Scalar),
            Some(b'f') => self
                .literal(b"false", Value::Bool(false))
                .map(ValueStart::Scalar),
            Some(b'n') => self.literal(b"null", Value::Null).map(ValueStart::Scalar),
            Some(b'-' | b'0'..=b'9') => self.number().map(ValueStart::Scalar),
            _ => Err(self.error("expected JSON value")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ContractError> {
        self.begin_container(depth)?;
        let mut values = Vec::new();
        if self.take(b']') {
            return Ok(Value::Array(values));
        }
        loop {
            self.array_before_child(values.len())?;
            values.push(self.value(depth + 1)?);
            if self.container_after_child(ContainerKind::Array)? {
                return Ok(Value::Array(values));
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ContractError> {
        self.begin_container(depth)?;
        let mut values = Map::new();
        if self.take(b'}') {
            return Ok(Value::Object(values));
        }
        loop {
            let key = self.object_key()?;
            self.object_before_child(&values, &key)?;
            values.insert(key, self.value(depth + 1)?);
            if self.container_after_child(ContainerKind::Object)? {
                return Ok(Value::Object(values));
            }
        }
    }

    /// Preserves depth refusal before delimiter consumption and empty-bank new.
    ///
    /// # Errors
    /// Refuses a container at the original maximum nesting depth.
    pub(super) fn begin_container(&mut self, depth: usize) -> Result<(), ContractError> {
        if depth >= self.maximum_depth {
            return Err(self.error("JSON nesting limit exceeded"));
        }
        self.cursor += 1;
        self.whitespace();
        Ok(())
    }

    /// Preserves the element bound before the next child's whitespace or token.
    ///
    /// # Errors
    /// Refuses the next element after 65536 actual initialized elements.
    pub(super) fn array_before_child(&self, length: usize) -> Result<(), ContractError> {
        if length == MAX_ARRAY_ELEMENTS {
            return Err(self.error("array exceeds 65536 elements"));
        }
        Ok(())
    }

    /// Returns the actual decoded key before duplicate/colon/child decisions.
    ///
    /// A future retained caller can install this String before the next shared
    /// transition. This method itself supplies no constructor or custody proof.
    ///
    /// # Errors
    /// Returns the original quoted-key parser or serde Unicode error.
    pub(super) fn object_key(&mut self) -> Result<String, ContractError> {
        self.whitespace();
        self.string()
    }

    /// Preserves decoded-key membership refusal before colon and child work.
    ///
    /// # Errors
    /// Refuses a duplicate key before checking a missing object colon.
    pub(super) fn object_before_child(
        &mut self,
        values: &Map<String, Value>,
        key: &String,
    ) -> Result<(), ContractError> {
        if values.contains_key(key) {
            return Err(self.error("duplicate object key"));
        }
        self.whitespace();
        if !self.take(b':') {
            return Err(self.error("expected object colon"));
        }
        Ok(())
    }

    /// Shares close/comma decisions without visiting the next child early.
    ///
    /// # Errors
    /// Returns the original array/object punctuation error at the same cursor.
    pub(super) fn container_after_child(
        &mut self,
        kind: ContainerKind,
    ) -> Result<bool, ContractError> {
        let (close, refusal) = match kind {
            ContainerKind::Array => (b']', "expected array comma or close"),
            ContainerKind::Object => (b'}', "expected object comma or close"),
        };
        self.whitespace();
        if self.take(close) {
            return Ok(true);
        }
        if !self.take(b',') {
            return Err(self.error(refusal));
        }
        Ok(false)
    }

    /// Constructs the unchanged strict diagnostic at the current byte cursor.
    pub(super) fn error(&self, reason: &str) -> ContractError {
        invalid("json", format!("{reason} at byte {}", self.cursor))
    }

    /// Advances across the same four JSON whitespace bytes.
    pub(super) fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| b" \n\r\t".contains(byte))
        {
            self.cursor += 1;
        }
    }

    /// Consumes one exact delimiter only when it is the current byte.
    pub(super) fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.cursor) == Some(&byte) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, literal: &[u8], value: Value) -> Result<Value, ContractError> {
        if !self.bytes[self.cursor..].starts_with(literal) {
            return Err(self.error("invalid JSON literal"));
        }
        self.cursor += literal.len();
        Ok(value)
    }

    fn string(&mut self) -> Result<String, ContractError> {
        let start = self.cursor;
        if !self.take(b'"') {
            return Err(self.error("expected JSON string"));
        }
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            self.cursor += 1;
            match byte {
                b'"' => return Ok(serde_json::from_slice(&self.bytes[start..self.cursor])?),
                b'\\' => {
                    // Skip the escaped byte when finding the closing quote;
                    // serde validates escapes, UTF-8, and surrogate pairing.
                    if self.cursor == self.bytes.len() {
                        break;
                    }
                    self.cursor += 1;
                }
                _ => {}
            }
        }
        Err(self.error("unterminated JSON string"))
    }

    fn digits(&mut self) -> bool {
        let start = self.cursor;
        while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
            self.cursor += 1;
        }
        self.cursor != start
    }

    fn number(&mut self) -> Result<Value, ContractError> {
        let start = self.cursor;
        let negative = self.take(b'-');
        match self.bytes.get(self.cursor).copied() {
            Some(b'0') => {
                self.cursor += 1;
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error("invalid integer part")),
        }
        let mut fractional = false;
        if self.take(b'.') {
            fractional = true;
            if !self.digits() {
                return Err(self.error("missing fractional digits"));
            }
        }
        if self.take(b'e') || self.take(b'E') {
            fractional = true;
            if !self.take(b'+') {
                self.take(b'-');
            }
            if !self.digits() {
                return Err(self.error("missing exponent digits"));
            }
        }
        let token = std::str::from_utf8(&self.bytes[start..self.cursor])
            .map_err(|_| self.error("invalid number encoding"))?;
        if !fractional {
            if negative {
                if let Ok(value) = token.parse::<i64>() {
                    return Ok(Value::Number(value.into()));
                }
            } else if let Ok(value) = token.parse::<u64>() {
                return Ok(Value::Number(value.into()));
            }
        }
        let float = token
            .parse::<f64>()
            .map_err(|_| self.error("invalid finite number"))?;
        // JSON Schema integer fields accept integral decimal/exponent tokens.
        // Normalize their correctly rounded value locally; enabling a global
        // serde feature would change legacy formats outside the CNP boundary.
        if float.is_finite() {
            let mut buffer = ryu_js::Buffer::new();
            let integral = buffer.format(float);
            if let Ok(value) = integral.parse::<u64>() {
                return Ok(Value::Number(value.into()));
            }
            if let Ok(value) = integral.parse::<i64>() {
                return Ok(Value::Number(value.into()));
            }
        }
        Number::from_f64(float)
            .map(Value::Number)
            .ok_or_else(|| self.error("nonfinite number"))
    }
}

#[path = "strict_parser/controls.rs"]
mod controls;
pub(super) use controls::TRANSITION_COUNTER_SCRATCH_BYTES;

#[cfg(test)]
#[path = "strict_parser/tests.rs"]
mod tests;

#[path = "strict_parser/lookup.rs"]
mod lookup;
pub use lookup::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA;
