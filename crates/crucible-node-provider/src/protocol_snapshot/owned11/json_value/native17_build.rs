//! Keeps every partially reconstructed JSON owner in its caller's once slot.

use super::*;
use crate::retained_metadata::MetadataObserver;
use crucible_node_contract::Extensions;

enum RetainedFrame17 {
    Array(Vec<Value>),
    Object(Map<String, Value>, Option<String>),
    Extensions(Extensions, Option<String>),
}

impl RetainedFrame17 {
    fn closing(&self) -> u8 {
        if matches!(self, Self::Array(_)) {
            b']'
        } else {
            b'}'
        }
    }
}

/// Owns completed children, the active container stack and unfinished text.
///
/// The fixed stack is part of the enclosing admitted attempt header. Only actual
/// String, Vec and map backing is included by the retained metadata walk.
pub(crate) struct HistoricalJsonBuildAttempt {
    frames: [Option<RetainedFrame17>; MAXIMUM_DEPTH],
    depth: usize,
    current: Option<Value>,
    text: Option<String>,
    completed: Option<Value>,
    extensions: Option<Extensions>,
    extension_root: bool,
    started: bool,
    failed: bool,
    position: usize,
}

impl Default for HistoricalJsonBuildAttempt {
    fn default() -> Self {
        Self {
            frames: std::array::from_fn(|_| None),
            depth: 0,
            current: None,
            text: None,
            completed: None,
            extensions: None,
            extension_root: false,
            started: false,
            failed: false,
            position: 0,
        }
    }
}

impl HistoricalJsonBuildAttempt {
    /// Poisons the same slot without discarding any previously owned backing.
    pub(crate) fn interrupt_data(&mut self) {
        self.started = true;
        self.failed = true;
    }

    pub(crate) fn completed_data(&self) -> Option<&Value> {
        if self.failed {
            None
        } else {
            self.completed.as_ref()
        }
    }

    pub(crate) fn take_completed_data(&mut self) -> Option<Value> {
        if self.failed {
            None
        } else {
            self.completed.take()
        }
    }

    /// Walks all initialized heap owners, including incomplete keys and values.
    ///
    /// # Errors
    /// Refuses requested-layout arithmetic overflow or invalid child metadata.
    pub(crate) fn observe_retained_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.current)?;
        observer.observe(&self.text)?;
        observer.observe(&self.completed)?;
        observer.observe(&self.extensions)?;
        for frame in self.frames.iter().flatten() {
            match frame {
                RetainedFrame17::Array(values) => observer.observe(values)?,
                RetainedFrame17::Object(values, pending) => {
                    observer.observe(values)?;
                    observer.observe(pending)?;
                }
                RetainedFrame17::Extensions(values, pending) => {
                    observer.observe(values)?;
                    observer.observe(pending)?;
                }
            }
        }
        Ok(())
    }

    fn text_into_data(
        &mut self,
        cursor: &mut Cursor<'_>,
        records: &mut MetadataRecordRows<'_>,
    ) -> Result<(), ProviderError> {
        if self.text.is_some() {
            return Err(invalid());
        }
        let token = cursor.string()?;
        let row = next_row(records)?;
        self.text = Some(String::new());
        let text = self.text.as_mut().ok_or_else(invalid)?;
        text.try_reserve_exact(row.extent).map_err(|_| credit())?;
        if text.capacity() != row.extent {
            return Err(credit());
        }
        let mut decoder = Cursor::new(token.encoded);
        while decoder.position < token.encoded.len() {
            let character = decoder.character()?;
            if text
                .len()
                .checked_add(character.len_utf8())
                .ok_or_else(credit)?
                > text.capacity()
            {
                return Err(invalid());
            }
            text.push(character);
        }
        Ok(())
    }

    fn key_into_data(
        &mut self,
        cursor: &mut Cursor<'_>,
        records: &mut MetadataRecordRows<'_>,
    ) -> Result<(), ProviderError> {
        let index = self.depth.checked_sub(1).ok_or_else(invalid)?;
        match self.frames[index].as_ref().ok_or_else(invalid)? {
            RetainedFrame17::Array(_) => return Ok(()),
            RetainedFrame17::Object(_, Some(_)) | RetainedFrame17::Extensions(_, Some(_)) => {
                return Err(invalid());
            }
            RetainedFrame17::Object(_, None) | RetainedFrame17::Extensions(_, None) => {}
        }
        cursor.whitespace();
        self.text_into_data(cursor, records)?;
        let frame = self.frames[index].as_mut().ok_or_else(invalid)?;
        if let RetainedFrame17::Object(_, pending) | RetainedFrame17::Extensions(_, pending) = frame
        {
            *pending = self.text.take();
        }
        cursor.whitespace();
        cursor.literal(b":")
    }

    fn append_into_data(&mut self) -> Result<(), ProviderError> {
        let index = self.depth.checked_sub(1).ok_or_else(invalid)?;
        let frame = self.frames[index].as_mut().ok_or_else(invalid)?;
        match frame {
            RetainedFrame17::Array(values) => {
                if values.len() == values.capacity() || self.current.is_none() {
                    return Err(invalid());
                }
                if let Some(value) = self.current.take() {
                    values.push(value);
                }
            }
            RetainedFrame17::Object(values, pending) => {
                let key = pending.as_ref().ok_or_else(invalid)?;
                if values.contains_key(key) || self.current.is_none() {
                    return Err(invalid());
                }
                match (pending.take(), self.current.take()) {
                    (Some(key), Some(value)) => {
                        values.insert(key, value);
                    }
                    (key, value) => {
                        *pending = key;
                        self.current = value;
                        return Err(invalid());
                    }
                }
            }
            RetainedFrame17::Extensions(values, pending) => {
                let key = pending.as_ref().ok_or_else(invalid)?;
                if values.contains_key(key) || self.current.is_none() {
                    return Err(invalid());
                }
                match (pending.take(), self.current.take()) {
                    (Some(key), Some(value)) => {
                        values.insert(key, value);
                    }
                    (key, value) => {
                        *pending = key;
                        self.current = value;
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }

    fn close_frame_data(&mut self) -> Result<(), ProviderError> {
        let frame = self.frames[self.depth].take().ok_or_else(invalid)?;
        match frame {
            RetainedFrame17::Array(values) => self.current = Some(Value::Array(values)),
            RetainedFrame17::Object(values, pending) => {
                if pending.is_some() {
                    self.frames[self.depth] = Some(RetainedFrame17::Object(values, pending));
                    return Err(invalid());
                }
                self.current = Some(Value::Object(values));
            }
            RetainedFrame17::Extensions(values, pending) => {
                if self.depth != 0 || pending.is_some() || self.extensions.is_some() {
                    self.frames[self.depth] = Some(RetainedFrame17::Extensions(values, pending));
                    return Err(invalid());
                }
                self.extensions = Some(values);
            }
        }
        Ok(())
    }

    pub(crate) fn completed_object_data(&self) -> Option<&Map<String, Value>> {
        match self.completed_data() {
            Some(Value::Object(values)) => Some(values),
            _ => None,
        }
    }

    pub(crate) fn take_completed_object_data(&mut self) -> Option<Map<String, Value>> {
        if self.failed || !matches!(self.completed, Some(Value::Object(_))) {
            return None;
        }
        match self.completed.take() {
            Some(Value::Object(values)) => Some(values),
            other => {
                self.completed = other;
                None
            }
        }
    }

    pub(crate) fn completed_extensions_data(&self) -> Option<&Extensions> {
        if self.failed {
            None
        } else {
            self.extensions.as_ref()
        }
    }

    pub(crate) fn take_completed_extensions_data(&mut self) -> Option<Extensions> {
        if self.failed {
            None
        } else {
            self.extensions.take()
        }
    }

    fn reconstruct_data(
        &mut self,
        cursor: &mut Cursor<'_>,
        records: &mut MetadataRecordRows<'_>,
    ) -> Result<(), ProviderError> {
        loop {
            cursor.whitespace();
            match cursor.peek() {
                Some(b'[') | Some(b'{') => {
                    if self.depth >= MAXIMUM_DEPTH || self.frames[self.depth].is_some() {
                        return Err(invalid());
                    }
                    let object = cursor.advance()? == b'{';
                    let row = next_row(records)?;
                    self.frames[self.depth] = Some(if object {
                        if self.extension_root && self.depth == 0 {
                            RetainedFrame17::Extensions(Extensions::new(), None)
                        } else {
                            RetainedFrame17::Object(Map::new(), None)
                        }
                    } else {
                        RetainedFrame17::Array(Vec::new())
                    });
                    self.depth += 1;
                    if let Some(RetainedFrame17::Array(values)) = &mut self.frames[self.depth - 1] {
                        values.try_reserve_exact(row.extent).map_err(|_| credit())?;
                        if values.capacity() != row.extent {
                            return Err(credit());
                        }
                    }
                    cursor.whitespace();
                    let closing = self.frames[self.depth - 1]
                        .as_ref()
                        .ok_or_else(invalid)?
                        .closing();
                    if cursor.peek() == Some(closing) {
                        cursor.advance()?;
                        self.depth -= 1;
                        self.close_frame_data()?;
                    } else {
                        self.key_into_data(cursor, records)?;
                        continue;
                    }
                }
                Some(b'"') => {
                    self.text_into_data(cursor, records)?;
                    self.current = self.text.take().map(Value::String);
                }
                Some(b'n') => {
                    cursor.literal(b"null")?;
                    self.current = Some(Value::Null);
                }
                Some(b't') => {
                    cursor.literal(b"true")?;
                    self.current = Some(Value::Bool(true));
                }
                Some(b'f') => {
                    cursor.literal(b"false")?;
                    self.current = Some(Value::Bool(false));
                }
                Some(b'-' | b'0'..=b'9') => {
                    self.current = Some(Value::Number(cursor.number()?));
                }
                _ => return Err(invalid()),
            }

            loop {
                cursor.whitespace();
                if self.depth == 0 {
                    if cursor.position != cursor.input.len()
                        || (self.current.is_none() && self.extensions.is_none())
                    {
                        return Err(invalid());
                    }
                    self.completed = self.current.take();
                    return Ok(());
                }
                self.append_into_data()?;
                let closing = self.frames[self.depth - 1]
                    .as_ref()
                    .ok_or_else(invalid)?
                    .closing();
                if cursor.peek() == Some(closing) {
                    cursor.advance()?;
                    self.depth -= 1;
                    self.close_frame_data()?;
                    continue;
                }
                cursor.literal(b",")?;
                self.key_into_data(cursor, records)?;
                break;
            }
        }
    }
}

impl ValidatedHistoricalJson<'_, '_> {
    /// Reconstructs checked JSON into a retained, non-reusable owner.
    ///
    /// # Errors
    /// Refuses an already started slot, reservation or capacity disagreement,
    /// or changed input geometry. Every allocated child remains in `attempt`.
    pub(crate) fn reconstruct_into_data(
        &self,
        attempt: &mut HistoricalJsonBuildAttempt,
    ) -> Result<(), ProviderError> {
        self.reconstruct_selected_into_data(attempt, false)
    }

    pub(crate) fn reconstruct_extensions_into_data(
        &self,
        attempt: &mut HistoricalJsonBuildAttempt,
    ) -> Result<(), ProviderError> {
        self.reconstruct_selected_into_data(attempt, true)
    }

    fn reconstruct_selected_into_data(
        &self,
        attempt: &mut HistoricalJsonBuildAttempt,
        extensions: bool,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        attempt.extension_root = extensions;
        if repeated {
            return Err(invalid());
        }
        let mut cursor = Cursor::new(self.input);
        let mut records = self.original_records.clone();
        let result = attempt.reconstruct_data(&mut cursor, &mut records);
        attempt.position = cursor.position;
        if result.is_ok() {
            attempt.failed = false;
        }
        result
    }
}

/// Retains a scalar String without allocating a JSON container stack per field.
#[derive(Default)]
pub(crate) struct HistoricalStringBuildAttempt {
    value: Option<String>,
    started: bool,
    failed: bool,
}

impl HistoricalStringBuildAttempt {
    pub(crate) fn interrupt_data(&mut self) {
        self.started = true;
        self.failed = true;
    }
    pub(crate) fn completed_string_data(&self) -> Option<&String> {
        if self.failed {
            None
        } else {
            self.value.as_ref()
        }
    }
    pub(crate) fn take_completed_string_data(&mut self) -> Option<String> {
        if self.failed { None } else { self.value.take() }
    }
    pub(crate) fn observe_retained_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.value)
    }
}

impl ValidatedHistoricalJson<'_, '_> {
    /// Retains the actual scalar backing before reservation or decoding.
    ///
    /// # Errors
    /// Refuses repeated attempts, non-string roots, reservation failure or
    /// changed row geometry. The allocated String remains in the same slot.
    pub(crate) fn reconstruct_string_into_data(
        &self,
        attempt: &mut HistoricalStringBuildAttempt,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        if repeated {
            return Err(invalid());
        }
        let mut cursor = Cursor::new(self.input);
        let token = cursor.string()?;
        cursor.whitespace();
        if cursor.position != self.input.len() {
            return Err(invalid());
        }
        let mut records = self.original_records.clone();
        let row = next_row(&mut records)?;
        attempt.value = Some(String::new());
        let value = attempt.value.as_mut().ok_or_else(invalid)?;
        value.try_reserve_exact(row.extent).map_err(|_| credit())?;
        if value.capacity() != row.extent {
            return Err(credit());
        }
        let mut decoder = Cursor::new(token.encoded);
        while decoder.position < token.encoded.len() {
            let character = decoder.character()?;
            if value
                .len()
                .checked_add(character.len_utf8())
                .ok_or_else(credit)?
                > value.capacity()
            {
                return Err(invalid());
            }
            value.push(character);
        }
        attempt.failed = false;
        Ok(())
    }
}
