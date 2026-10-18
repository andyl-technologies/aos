//! Bounded root validation reuse after an actual fresh read of identical bytes.
//!
//! One caller-paid image owns its validation for a single pinned snapshot. The
//! arena is still reopened by publication presence and reread for every key;
//! only repeated parsing of an identical authenticated root is avoided.

use super::*;

/// Owns one original-paid root image and its validated immutable layout.
pub(in crate::content_store::packed) struct FreshRoot {
    bytes: Bytes,
    reference: Option<PageReference>,
    layout: Option<wire::NodeLayout>,
    #[cfg(test)]
    pub(in crate::content_store::packed) identical_reads: u64,
}

impl FreshRoot {
    /// Reserves one root image from the same operation as its enclosing owner.
    ///
    /// # Errors
    /// Refuses exhausted or revoked original storage before buffer birth.
    pub(in crate::content_store::packed) fn new(
        operation: &Operation<'_>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            bytes: operation.buffer(wire::PAGE_BYTES)?,
            reference: None,
            layout: None,
            #[cfg(test)]
            identical_reads: 0,
        })
    }

    /// Returns a fresh root read with validation reused only for identical bytes.
    ///
    /// # Errors
    /// Preserves original, IO, reference, checksum and page-layout refusals.
    pub(super) fn load<'buffer>(
        &mut self,
        reader: &Reader<'_>,
        reference: PageReference,
        buffer: &'buffer mut Bytes,
        operation: &mut Operation<'_>,
    ) -> Result<Node<'buffer>, StoreError> {
        reader.read_page(reference, buffer, operation)?;
        if self.reference == Some(reference)
            && let Some(node) = self
                .layout
                .as_ref()
                .and_then(|layout| layout.identical_view(&self.bytes.value, &buffer.value))
        {
            #[cfg(test)]
            {
                self.identical_reads += 1;
            }
            return Ok(node);
        }
        let node = reader.parse_loaded(reference, true, None, None, &buffer.value)?;
        // Invalidate before writing: neither a partial copy nor a refused
        // replacement can retain a layout for overwritten storage.
        self.reference = None;
        self.layout = None;
        self.bytes.value.clear();
        self.bytes.value.extend_from_slice(&buffer.value);
        self.layout = Some(node.copied_layout(&self.bytes.value)?);
        self.reference = Some(reference);
        Ok(node)
    }
}
