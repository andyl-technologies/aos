//! Length-delimited cached expression payload reader.

use super::*;

pub(in crate::cache::runtime) struct PayloadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadCursor<'a> {
    pub(in crate::cache::runtime) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(in crate::cache::runtime) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    pub(in crate::cache::runtime) fn finish(
        &self,
    ) -> Result<(), CachedExpressionValuePayloadError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining == 0 {
            Ok(())
        } else {
            Err(CachedExpressionValuePayloadError::TrailingBytes { remaining })
        }
    }

    pub(in crate::cache::runtime) fn take_marker(
        &mut self,
        marker: &'static [u8],
        name: &'static str,
    ) -> Result<(), CachedExpressionValuePayloadError> {
        let actual = self.take_bytes(marker.len())?;
        if actual == marker {
            Ok(())
        } else {
            Err(CachedExpressionValuePayloadError::MissingMarker { marker: name })
        }
    }

    pub(in crate::cache::runtime) fn take_byte(
        &mut self,
    ) -> Result<u8, CachedExpressionValuePayloadError> {
        Ok(self.take_bytes(1)?[0])
    }

    pub(in crate::cache::runtime) fn take_i64(
        &mut self,
    ) -> Result<i64, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(8)?;
        let mut out = [0; 8];
        out.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(out))
    }

    pub(in crate::cache::runtime) fn take_u64(
        &mut self,
    ) -> Result<u64, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(8)?;
        let mut out = [0; 8];
        out.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(out))
    }

    pub(in crate::cache::runtime) fn take_u32(
        &mut self,
    ) -> Result<u32, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(4)?;
        let mut out = [0; 4];
        out.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(out))
    }

    pub(in crate::cache::runtime) fn take_u128(
        &mut self,
    ) -> Result<u128, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(16)?;
        let mut out = [0; 16];
        out.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(out))
    }

    pub(in crate::cache::runtime) fn take_digest(
        &mut self,
    ) -> Result<[u8; 32], CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(32)?;
        let mut out = [0; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub(in crate::cache::runtime) fn take_len(
        &mut self,
    ) -> Result<usize, CachedExpressionValuePayloadError> {
        let len = self.take_u128()?;
        usize::try_from(len).map_err(|_| CachedExpressionValuePayloadError::LengthOverflow { len })
    }

    pub(in crate::cache::runtime) fn take_length_prefixed_bytes(
        &mut self,
    ) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        let len = self.take_len()?;
        let bytes = self.take_bytes(len)?;
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len()).map_err(|_| {
            CachedExpressionValuePayloadError::PayloadAllocationFailed { len: bytes.len() }
        })?;
        out.extend_from_slice(bytes);
        Ok(out)
    }

    pub(in crate::cache::runtime) fn take_string_context(
        &mut self,
    ) -> Result<StringContext, CachedExpressionValuePayloadError> {
        self.take_marker(b"context", "string context tag")?;
        let len = self.take_len()?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(len)
            .map_err(|_| CachedExpressionValuePayloadError::ContextAllocationFailed { len })?;
        for index in 0..len {
            let tag = self.take_byte()?;
            let path = self.take_length_prefixed_bytes()?;
            let element = match tag {
                0 => ContextElement::opaque_path(path),
                1 => {
                    let output = self.take_length_prefixed_bytes()?;
                    ContextElement::single_output(path, output)
                }
                2 => ContextElement::deep_derivation(path),
                tag => {
                    return Err(CachedExpressionValuePayloadError::InvalidTag {
                        section: "string context",
                        tag,
                    });
                }
            }
            .map_err(|source| CachedExpressionValuePayloadError::Context { source })?;
            if let Some(previous) = elements.last()
                && previous >= &element
            {
                return Err(CachedExpressionValuePayloadError::NonCanonicalStringContext { index });
            }
            elements.push(element);
        }
        Ok(StringContext::new(elements))
    }

    pub(in crate::cache::runtime) fn take_attr_position(
        &mut self,
    ) -> Result<Option<AttrPosition>, CachedExpressionValuePayloadError> {
        match self.take_byte()? {
            0 => Ok(None),
            1 => {
                let module = self.take_u32()?;
                let start = self.take_u32()?;
                let end = self.take_u32()?;
                Ok(Some(AttrPosition::new(module, Span::new(start, end))))
            }
            tag => Err(CachedExpressionValuePayloadError::InvalidTag {
                section: "attr position",
                tag,
            }),
        }
    }

    pub(in crate::cache::runtime) fn take_bytes(
        &mut self,
        len: usize,
    ) -> Result<&'a [u8], CachedExpressionValuePayloadError> {
        let end = self.offset.checked_add(len).ok_or(
            CachedExpressionValuePayloadError::PayloadLengthOverflow {
                current: self.offset,
                additional: len,
            },
        )?;
        if end > self.bytes.len() {
            return Err(CachedExpressionValuePayloadError::ShortPayload {
                expected: end,
                actual: self.bytes.len(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}
