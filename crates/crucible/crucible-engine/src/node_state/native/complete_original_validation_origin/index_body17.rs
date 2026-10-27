//! Borrows only the actual immutable Index3 and its declared external rows.
//!
//! These DATA views create no signature, selected load or restoration authority.
//! The caller separately retains its genuine Source/ticket and funds encoding.

use super::*;

impl NativeArchiveRecord {
    /// Borrows the private actual Index3 body for an independently funded encoder.
    ///
    /// # Errors
    /// Refuses a different original index grammar.
    pub(crate) fn complete_original_index_body17_data(
        &self,
    ) -> Result<impl serde::Serialize + '_, StateError> {
        if self.index.schema_version != 3 {
            return Err(refused("original Index3 body grammar differs"));
        }
        Ok(self.index.as_ref())
    }

    /// Borrows the exact direct dependencies declared by this actual Index3 body.
    ///
    /// Duplicate occurrences remain visible to preallocation accounting; the
    /// retaining writer sorts and deduplicates only after all clones are owned.
    ///
    /// # Errors
    /// Refuses a different original index grammar.
    pub(crate) fn complete_original_index_dependencies17_data(
        &self,
    ) -> Result<impl Clone + Iterator<Item = &ContentRef>, StateError> {
        if self.index.schema_version != 3 {
            return Err(refused("original Index3 dependency grammar differs"));
        }
        Ok(IndexDependencies17 {
            index: self.index.as_ref(),
            offset: 0,
        })
    }

    /// Borrows the actual signed inventory and its existing adjacency.
    ///
    /// # Errors
    /// Refuses a different original index grammar.
    pub(crate) fn complete_original_index_rows17_data(
        &self,
    ) -> Result<impl Iterator<Item = (&ContentRef, &[ContentRef])>, StateError> {
        if self.index.schema_version != 3 {
            return Err(refused("original Index3 inventory grammar differs"));
        }
        Ok(IndexRows17 {
            rows: self.index.objects.iter(),
        })
    }

    /// Names fixed defining Index3 views; none owns a buffer or source authority.
    pub(crate) fn complete_original_index_body17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<IndexDependencies17<'static>>()
            + size_of::<IndexRows17<'static>>()
            + size_of::<&super::super::Index>()
            + size_of::<Result<IndexDependencies17<'static>, StateError>>()
            + size_of::<Result<IndexRows17<'static>, StateError>>()
            + size_of::<Result<Option<&'static [ContentRef]>, StateError>>()
            + size_of::<Result<&'static super::super::Index, StateError>>()
            + size_of::<std::slice::Iter<'static, super::super::Object>>()
    }

    /// Borrows only an exact full-reference row from the actual signed inventory.
    ///
    /// # Errors
    /// Refuses a different original index grammar or ambiguous inventory rows.
    pub(crate) fn complete_original_index_row17_data(
        &self,
        reference: &ContentRef,
    ) -> Result<Option<&[ContentRef]>, StateError> {
        if self.index.schema_version != 3 {
            return Err(refused("original Index3 row grammar differs"));
        }
        let mut rows = self
            .index
            .objects
            .iter()
            .filter(|row| &row.reference == reference);
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(refused("original Index3 row is ambiguous"));
        }
        Ok(Some(row.dependencies.as_slice()))
    }
}

#[derive(Clone)]
struct IndexDependencies17<'a> {
    index: &'a super::super::Index,
    offset: usize,
}

impl<'a> Iterator for IndexDependencies17<'a> {
    type Item = &'a ContentRef;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let offset = self.offset;
            self.offset = self.offset.checked_add(1)?;
            match offset {
                0 => return Some(&self.index.artifact),
                1 => {
                    if let Some(reference) = &self.index.original_capture_journal {
                        return Some(reference);
                    }
                }
                2 => {
                    if let Some(reference) = &self.index.selected_extensions {
                        return Some(reference);
                    }
                }
                _ => return self.index.objects.get(offset - 3).map(|row| &row.reference),
            }
        }
    }
}

struct IndexRows17<'a> {
    rows: std::slice::Iter<'a, super::super::Object>,
}

impl<'a> Iterator for IndexRows17<'a> {
    type Item = (&'a ContentRef, &'a [ContentRef]);

    fn next(&mut self) -> Option<Self::Item> {
        self.rows
            .next()
            .map(|row| (&row.reference, row.dependencies.as_slice()))
    }
}
