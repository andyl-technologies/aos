//! Retains actual flat token-bank layouts without traversing a recursive Value.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind,
};

impl LiteralValue18Data {
    /// Observes independent backing while its header stays in the enclosing owner.
    ///
    /// # Errors
    /// Refuses invalid layout, exhausted selected rows or unavailable physical
    /// backing. Earlier records survive; no completion or allocation is granted.
    pub(crate) fn record_backing_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            chunks,
            container_children,
        } = self;
        vector_capacity_data(census, container_children)?;
        vector_capacity_data(census, chunks)?;

        for chunk in chunks {
            vector_capacity_data(census, chunk)?;
            for token in chunk {
                match token {
                    LiteralToken18::String(text) | LiteralToken18::Key(text) => {
                        census.observe(text)?;
                    }
                    LiteralToken18::Null
                    | LiteralToken18::Bool(_)
                    | LiteralToken18::Unsigned(_)
                    | LiteralToken18::Signed(_)
                    | LiteralToken18::FloatBits(_)
                    | LiteralToken18::ArrayStart
                    | LiteralToken18::ArrayEnd
                    | LiteralToken18::ObjectStart
                    | LiteralToken18::ObjectEnd => {}
                }
            }
        }
        Ok(())
    }
}

impl LiteralValue18TokenAttempt {
    /// Observes every actual failed or incomplete token bank without eligibility.
    ///
    /// # Errors
    /// Refuses invalid layout, exhausted selected rows or unavailable physical
    /// backing. The attempt's flags and retained banks remain unchanged.
    pub(crate) fn record_backing_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started: _,
            failed: _,
            complete: _,
            data,
        } = self;
        data.record_backing_capacity_data(census)
    }
}

/// Records an actual vector allocation without visiting inline scalar elements.
fn vector_capacity_data<T>(
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
    values: &Vec<T>,
) -> Result<(), RuntimeError> {
    census.record(MetadataCapacityRecord {
        kind: MetadataRecordKind::Vector,
        extent: values.capacity(),
        element_bytes: size_of::<T>(),
        alignment: align_of::<T>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_literal_capacity_walk_keeps_spare_banks_without_root_header_credit() {
        let mut text = String::with_capacity(137);
        text.push_str("failed literal");
        let mut key = String::with_capacity(113);
        key.push_str("partial key");
        let strings = text.capacity() + key.capacity();
        let mut chunk = Vec::with_capacity(19);
        chunk.extend([
            LiteralToken18::ObjectStart,
            LiteralToken18::Key(key),
            LiteralToken18::String(text),
        ]);
        let mut chunks = Vec::with_capacity(7);
        chunks.push(chunk);
        chunks.push(Vec::with_capacity(23));
        let attempt = LiteralValue18TokenAttempt {
            started: true,
            failed: true,
            complete: false,
            data: LiteralValue18Data {
                chunks,
                container_children: Vec::with_capacity(29),
            },
        };
        let original = attempt.retained_requested_storage_data(usize::MAX).unwrap();
        let mut census = OriginalOwnerCapacityMetadataData::new(6, None);

        attempt.record_backing_capacity_data(&mut census).unwrap();
        let facts = census.finish();

        assert_eq!(facts.capacity_records, 6);
        assert_eq!(facts.vector_banks, 4);
        assert_eq!(facts.string_banks, 2);
        assert_eq!(facts.string_capacity_bytes, strings);
        assert_eq!(facts.boxed_value_bytes, 0);
        assert_eq!(facts.shared_value_bytes, 0);
        assert_eq!(facts.observed_nodes, 0);
        assert_eq!(
            facts.vector_capacity_bytes,
            attempt.data.chunks.capacity() * size_of::<Vec<LiteralToken18>>()
                + attempt.data.container_children.capacity() * size_of::<usize>()
                + attempt
                    .data
                    .chunks
                    .iter()
                    .map(|chunk| chunk.capacity() * size_of::<LiteralToken18>())
                    .sum::<usize>()
        );
        assert_eq!(
            facts.vector_capacity_bytes + strings,
            original - size_of::<LiteralValue18TokenAttempt>()
        );
        assert!(attempt.data().is_err());
        assert_eq!(attempt.state_data(), (true, true, false));

        let mut short = OriginalOwnerCapacityMetadataData::new(5, None);
        assert!(attempt.record_backing_capacity_data(&mut short).is_err());
        assert_eq!(
            attempt.retained_requested_storage_data(usize::MAX).unwrap(),
            original
        );
        assert_eq!(attempt.state_data(), (true, true, false));
    }
}
