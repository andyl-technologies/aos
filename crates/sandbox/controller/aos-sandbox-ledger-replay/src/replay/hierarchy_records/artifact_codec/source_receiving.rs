//! Measures reached artifact allocation frontiers with the existing cursor.
//!
//! This walk constructs no typed artifact and grants no validation or authority.
//! It retains counts already reached when the ordinary decoder would encounter
//! EOF or invalid syntax. Semantic failures can only shorten the later walk.

use std::mem::size_of;

use super::*;

#[derive(Default)]
struct Shape {
    bytes: usize,
    cells: usize,
    overflowed: bool,
}

impl Shape {
    fn reserve<T>(&mut self, count: usize) -> Result<(), HierarchyArtifactCodecError> {
        let next = count.checked_mul(size_of::<T>())
            .and_then(|bytes| self.bytes.checked_add(bytes))
            .zip(self.cells.checked_add(count));
        let Some((bytes, cells)) = next else {
            self.overflowed = true;
            return Err(HierarchyArtifactCodecError::Capacity);
        };
        self.bytes = bytes;
        self.cells = cells;
        Ok(())
    }
}

/// Counts actual declared reserves, including a reached unfinished vector.
///
/// # Errors
/// Rejects checked representation overflow. Syntax and semantic errors remain
/// with the original decoder, after all already reached reserves are counted.
pub fn allocation_frontier(
    bytes: &[u8],
) -> Result<(usize, usize), aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1> {
    let mut shape = Shape::default();
    let observed = (|| {
        let magic: &[u8; 8] = bytes.get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(HierarchyArtifactCodecError::NonCanonical)?;
        let mut cursor = ArtifactCursor::new(bytes, magic)?;
        match magic {
            REALIZATION_MAGIC => plan(&mut cursor, &mut shape),
            REALIZATION_PROGRESS_MAGIC => {
                cursor.reader.bytes(112)?;
                decode_replacement(&mut cursor)?;
                let count = cursor.bounded_count(super::super::recovery::MAXIMUM_REALIZATION_STAGE_HISTORY)?;
                shape.reserve::<RealizationStageObservationV1>(count)
            }
            DETACH_PROGRESS_MAGIC => {
                cursor.reader.bytes(80)?;
                let count = cursor.bounded_count(super::super::recovery::MAXIMUM_REALIZATION_STAGE_HISTORY)?;
                shape.reserve::<DetachStageObservationV1>(count)
            }
            TRANSACTION_STATE_MAGIC => {
                cursor.reader.bytes(56)?;
                let count = cursor.bounded_count(MAXIMUM_REALIZATION_ACTIONS)?;
                shape.reserve::<TransactionActionObservationV1>(count)
            }
            _ => Ok(()),
        }
    })();
    // Syntactic failure is not a new validation result. Already reached vector
    // reservations must still be funded; the original decoder reports its own
    // exact error in its unchanged position after receiving admission.
    let _ = observed;
    if shape.overflowed {
        return Err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::LimitExceeded(
            "Source artifact receiving geometry",
        ));
    }
    Ok((shape.bytes, shape.cells))
}

fn plan(
    cursor: &mut ArtifactCursor<'_>,
    shape: &mut Shape,
) -> Result<(), HierarchyArtifactCodecError> {
    cursor.reader.bytes(56)?;
    let publications = cursor.bounded_count(MAXIMUM_REALIZATION_ACTIONS)?;
    shape.reserve::<AttachmentRealizationV1>(publications)?;
    for _ in 0..publications {
        publication(cursor, shape)?;
    }

    let detaches = cursor.bounded_count(MAXIMUM_REALIZATION_ACTIONS)?;
    if publications.checked_add(detaches)
        .is_none_or(|count| count > MAXIMUM_REALIZATION_ACTIONS)
    {
        return Err(HierarchyArtifactCodecError::Capacity);
    }
    shape.reserve::<AttachmentDetachV1>(detaches)?;
    for _ in 0..detaches {
        cursor.reader.bytes(296)?;
        attachments(cursor, shape, MAXIMUM_REALIZATION_DEPENDENCIES)?;
        cursor.reader.bytes(32)?;
    }

    attachments(cursor, shape, MAXIMUM_REALIZATION_ACTIONS)?;
    attachments(cursor, shape, MAXIMUM_REALIZATION_ACTIONS)?;
    let execution = cursor.bounded_count(MAXIMUM_REALIZATION_ACTIONS)?;
    shape.reserve::<RealizationTransactionActionV1>(execution)
}

fn publication(
    cursor: &mut ArtifactCursor<'_>,
    shape: &mut Shape,
) -> Result<(), HierarchyArtifactCodecError> {
    // The ordinary intent decoder admits only bytes already present in this
    // borrowed length-prefixed body. Its string/encoding copies are covered by
    // the separate encoded-byte term; no declared absent body is multiplied.
    cursor.length_prefixed(MAXIMUM_HIERARCHY_ARTIFACT_BYTES)?;
    cursor.reader.bytes(128)?;
    cursor.optional_bytes::<16>()?;
    cursor.optional_u64()?;
    cursor.optional_u64()?;
    cursor.reader.bytes(192)?;
    decode_replacement(cursor)?;
    attachments(cursor, shape, MAXIMUM_REALIZATION_DEPENDENCIES)?;
    cursor.reader.bytes(32)?;
    Ok(())
}

fn attachments(
    cursor: &mut ArtifactCursor<'_>,
    shape: &mut Shape,
    maximum: usize,
) -> Result<(), HierarchyArtifactCodecError> {
    let count = cursor.bounded_count(maximum)?;
    shape.reserve::<AttachmentId>(count)?;
    let bytes = count.checked_mul(16).ok_or(HierarchyArtifactCodecError::Capacity)?;
    cursor.reader.bytes(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_prefix(count: usize) -> Vec<u8> {
        let mut writer = ArtifactWriter::new(REALIZATION_MAGIC).unwrap();
        writer.bytes(&[1; 56]).unwrap();
        writer.count(count).unwrap();
        writer.finish()
    }

    #[test]
    fn truncated_plan_pays_its_actual_declared_outer_reservation() {
        let (small_bytes, small_cells) = allocation_frontier(&plan_prefix(3)).unwrap();
        let (large_bytes, large_cells) = allocation_frontier(&plan_prefix(7)).unwrap();

        assert_eq!(small_bytes, 3 * size_of::<AttachmentRealizationV1>());
        assert_eq!(large_bytes, 7 * size_of::<AttachmentRealizationV1>());
        assert_eq!((small_cells, large_cells), (3, 7));
        assert!(decode_realization_plan_v1(&plan_prefix(3)).is_err());
    }

    #[test]
    fn count_over_bound_fails_before_any_outer_reservation() {
        let bytes = plan_prefix(MAXIMUM_REALIZATION_ACTIONS + 1);

        assert_eq!(allocation_frontier(&bytes).unwrap(), (0, 0));
        assert_eq!(decode_realization_plan_v1(&bytes), Err(HierarchyArtifactCodecError::Capacity));
    }

    #[test]
    fn truncated_dependency_pays_only_the_reached_actual_vector() {
        let mut writer = ArtifactWriter::new(REALIZATION_MAGIC).unwrap();
        writer.bytes(&[1; 56]).unwrap();
        writer.count(0).unwrap();
        writer.count(1).unwrap();
        writer.bytes(&[1; 296]).unwrap();
        writer.count(5).unwrap();
        let bytes = writer.finish();

        assert_eq!(allocation_frontier(&bytes).unwrap(),
            (size_of::<AttachmentDetachV1>() + 5 * size_of::<AttachmentId>(), 6));
        assert!(decode_realization_plan_v1(&bytes).is_err());
    }
}
