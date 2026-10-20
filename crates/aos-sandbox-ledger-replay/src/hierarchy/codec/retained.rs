//! Captures the existing tree decoder and graph engine before later refusal.
//!
//! This passive owner grants no writer, Source state, scope or resource account.
//! Its caller pays the actual fixed and encoded-extent geometry before entry.

use super::super::graph::{CaptureOnDropV1, TreeBuildOriginalsV1};
use super::*;
use aos_sandbox_core::source_tree_model::HierarchyModelError;

/// Retains reached tree inputs, graph state, exact failure and completed model.
///
/// Normal errors retain actual allocations without replay or reconstruction.
/// This does not promise custody across panic or allocation abort.
#[derive(Default)]
pub struct TreeDecodeOriginalsV1 {
    records: Option<Vec<SandboxTreeRecordV1>>,
    tombstones: Option<Vec<SandboxId>>,
    graph: TreeBuildOriginalsV1,
    limits: Option<Result<TreeLimitsV1, HierarchyModelError>>,
    record: Option<Result<SandboxTreeRecordV1, HierarchyModelError>>,
    records_allocation: Option<Result<(), std::collections::TryReserveError>>,
    tombstones_allocation: Option<Result<(), std::collections::TryReserveError>>,
    tree: Option<SandboxTreeV1>,
    outcome: Option<Result<(), HierarchyCodecError>>,
    attempted: bool,
    taken: bool,
    closed: Option<HierarchyCodecError>,
}

impl TreeDecodeOriginalsV1 {
    /// Creates inert destinations without allocation or observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the actual first graph or codec cause without decoding again.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.limits.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.records_allocation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.record.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.tombstones_allocation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.graph.failure().map(|cause| cause as _))
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Borrows only the complete tree from a positive, untransferred capture.
    #[must_use]
    pub fn tree(&self) -> Option<&SandboxTreeV1> {
        if self.closed.is_some() || self.taken || !matches!(self.outcome, Some(Ok(()))) {
            return None;
        }
        self.tree.as_ref()
    }

    /// Moves the actual complete tree once while reached validation stays held.
    ///
    /// # Errors
    /// Refuses failed, absent, reentered or previously transferred captures.
    pub fn take_tree_once(&mut self) -> Result<SandboxTreeV1, HierarchyCodecError> {
        if self.tree().is_none() {
            self.closed.get_or_insert(HierarchyCodecError::InvalidTree);
            return Err(HierarchyCodecError::InvalidTree);
        }
        let Some(tree) = self.tree.take() else {
            std::process::abort();
        };
        self.taken = true;
        Ok(tree)
    }

    /// Bounds actual inline construction, return, cursor and guard carriers.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        2usize.checked_mul(std::mem::size_of::<Self>())?
            .checked_add(TreeBuildOriginalsV1::construction_bytes_v1()?)?
            .checked_add(std::mem::size_of::<BoundedReader<'static, HierarchyCodecError>>())?
            .checked_add(2 * std::mem::size_of::<Result<SandboxTreeV1, HierarchyCodecError>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Vec<SandboxTreeRecordV1>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Vec<SandboxId>>>())
    }

    /// Counts fixed parent, nested, guard, scalar and complete-model controls.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        // Decode12 +build6 +validation10 +walk5 +fourteen concrete guards*2
        // +eighteen cursor/header/allocation/iterator/check/return controls
        // +the complete tree's six fields. Nested destinations are counted too.
        Some(12 + 6 + 10 + 5 + 14 * 2 + 18 + 6)
    }

    /// Bounds new graph/decoded backing from the actual held encoded extent.
    ///
    /// This allocation-free DATA recipe is deliberately conservative before
    /// header validation. Record and tombstone cardinalities are separately
    /// bounded by that same input length, never multiplied implementation maxima.
    #[must_use]
    pub fn receiving_dynamic_footprint_v1(encoded_bytes: usize) -> Option<(usize, usize)> {
        let (records, tombstones) = Self::receiving_cardinalities_v2(encoded_bytes);
        TreeBuildOriginalsV1::dynamic_footprint_v1(records, tombstones)
    }

    /// Bounds named graph entries from the actual enclosing encoded extent.
    ///
    /// The sole decoder checks its complete advertised widths before reserve.
    /// This passive pre-entry bound reads no header and accepts no Tree DATA.
    /// Scalar fields, allocation results and Vec backing add no namespace fee.
    #[must_use]
    pub fn receiving_named_entries_v2(encoded_bytes: usize) -> Option<usize> {
        let (records, tombstones) = Self::receiving_cardinalities_v2(encoded_bytes);
        TreeBuildOriginalsV1::named_entries_v2(records, tombstones)
    }

    fn receiving_cardinalities_v2(encoded_bytes: usize) -> (usize, usize) {
        let payload = encoded_bytes.saturating_sub(TREE_HEADER_BYTES);
        let records = (payload / TREE_RECORD_BYTES).min(MAXIMUM_TREE_SANDBOXES);
        let tombstones = (payload / 16).min(MAXIMUM_TREE_TOMBSTONES);
        (records, tombstones)
    }
}

/// Bounds the canonical History record and three keyed lookup planes.
///
/// The actual enclosing extent dominates the log body without parsing it.
/// Individual-record decoding allocates no collection; a full log checks its
/// exact 262-byte record total before growth. Byte buffers are Memory only.
#[must_use]
pub fn history_receiving_named_entries_v2(encoded_bytes: usize) -> Option<usize> {
    let records = encoded_bytes.saturating_sub(HISTORY_LOG_HEADER_BYTES) / HISTORY_RECORD_BYTES;
    records.checked_mul(4)
}

/// Runs the sole tree decoder with once-owned reached destinations.
///
/// # Errors
/// Retains framing, capacity, partial-record or actual graph validation errors.
/// Reentry refuses without replacing the first failure or any reached model.
pub fn decode_tree_retaining_v1(
    bytes: &[u8],
    originals: &mut TreeDecodeOriginalsV1,
) -> Result<(), HierarchyCodecError> {
    if originals.attempted {
        originals.closed.get_or_insert(HierarchyCodecError::InvalidTree);
        return Err(HierarchyCodecError::InvalidTree);
    }
    originals.attempted = true;
    let result = decode_tree_engine(bytes, Some(&mut *originals));
    match result {
        Ok(tree) => {
            originals.tree = Some(tree);
            originals.outcome = Some(Ok(()));
            Ok(())
        }
        Err(cause) => {
            originals.outcome = Some(Err(cause));
            Err(HierarchyCodecError::InvalidTree)
        }
    }
}

pub(super) fn decode_tree_engine(
    bytes: &[u8],
    originals: Option<&mut TreeDecodeOriginalsV1>,
) -> Result<SandboxTreeV1, HierarchyCodecError> {
    let (records_slot, tombstones_slot, graph, limits_slot, record_slot,
        records_allocation, tombstones_allocation) = match originals {
        Some(originals) => (
            Some(&mut originals.records),
            Some(&mut originals.tombstones),
            Some(&mut originals.graph),
            Some(&mut originals.limits),
            Some(&mut originals.record),
            Some(&mut originals.records_allocation),
            Some(&mut originals.tombstones_allocation),
        ),
        None => (None, None, None, None, None, None, None),
    };
    let mut record_slot = record_slot;

    if bytes.len() < TREE_HEADER_BYTES || bytes.len() > MAXIMUM_HIERARCHY_SNAPSHOT_BYTES {
        return Err(HierarchyCodecError::InvalidLength);
    }
    let mut cursor = BoundedReader::new(bytes, hierarchy_read_error);
    if cursor.array::<8>()? != *TREE_MAGIC
        || u16::from_be_bytes(cursor.array::<2>()?) != FORMAT_VERSION
        || cursor.array::<2>()? != [0; 2]
    {
        return Err(HierarchyCodecError::InvalidHeader);
    }
    let project = ProjectId::from_bytes(cursor.array::<16>()?);
    let tree_generation = Revision::new(u64::from_be_bytes(cursor.array::<8>()?));
    let limits = retain_model_result(TreeLimitsV1::new(
        cursor.u32()? as usize,
        cursor.u32()? as usize,
        cursor.u32()? as usize,
        cursor.u32()? as usize,
        cursor.u32()? as usize,
        cursor.u32()? as usize,
        cursor.u32()? as usize,
    ), limits_slot)?;
    let count = cursor.u32()? as usize;
    let tombstone_count = cursor.u32()? as usize;
    if count > MAXIMUM_TREE_SANDBOXES {
        return Err(HierarchyCodecError::Capacity);
    }
    if tombstone_count > MAXIMUM_TREE_TOMBSTONES {
        return Err(HierarchyCodecError::Capacity);
    }
    let expected = TREE_RECORD_BYTES
        .checked_mul(count)
        .and_then(|bytes| {
            16_usize
                .checked_mul(tombstone_count)
                .and_then(|tombstone_bytes| bytes.checked_add(tombstone_bytes))
        })
        .and_then(|size| size.checked_add(TREE_HEADER_BYTES))
        .ok_or(HierarchyCodecError::Capacity)?;
    if expected != bytes.len() {
        return Err(HierarchyCodecError::InvalidLength);
    }

    let mut records = CaptureOnDropV1::new(Vec::new(), records_slot);
    reserve_decoded(&mut records, count, records_allocation)?;
    for _ in 0..count {
        let sandbox = SandboxId::from_bytes(cursor.array::<16>()?);
        let parent_present = cursor.array::<1>()?[0];
        let parent_bytes = cursor.array::<16>()?;
        let parent = match parent_present {
            0 if parent_bytes == [0; 16] => None,
            1 if parent_bytes != [0; 16] => Some(SandboxId::from_bytes(parent_bytes)),
            _ => return Err(HierarchyCodecError::CorruptEncoding),
        };
        let desired_generation = DesiredGeneration::new(u64::from_be_bytes(cursor.array::<8>()?));
        let incarnation_present = cursor.array::<1>()?[0];
        let incarnation_bytes = cursor.array::<16>()?;
        let incarnation = match incarnation_present {
            0 if incarnation_bytes == [0; 16] => None,
            1 if incarnation_bytes != [0; 16] => Some(IncarnationId::from_bytes(incarnation_bytes)),
            _ => return Err(HierarchyCodecError::CorruptEncoding),
        };
        records.push(
            retain_model_result(SandboxTreeRecordV1::new(
                project, sandbox, parent, desired_generation, incarnation), record_slot.as_deref_mut())?,
        );
    }
    let mut tombstones = CaptureOnDropV1::new(Vec::new(), tombstones_slot);
    reserve_decoded(&mut tombstones, tombstone_count, tombstones_allocation)?;
    for _ in 0..tombstone_count {
        tombstones.push(SandboxId::from_bytes(cursor.array::<16>()?));
    }
    if !cursor.is_empty() {
        return Err(HierarchyCodecError::InvalidLength);
    }
    match graph {
        None => SandboxTreeV1::from_records_and_tombstones(project, tree_generation, limits,
            records.into_inner(), tombstones.into_inner()),
        Some(graph) => SandboxTreeV1::from_records_retaining_v1(project, tree_generation, limits,
            records.into_inner(), tombstones.into_inner(), graph),
    }.map_err(|_| HierarchyCodecError::InvalidTree)
}

fn retain_model_result<T: Copy>(
    result: Result<T, HierarchyModelError>,
    slot: Option<&mut Option<Result<T, HierarchyModelError>>>,
) -> Result<T, HierarchyCodecError> {
    match slot {
        None => result.map_err(|_| HierarchyCodecError::InvalidTree),
        Some(slot) => {
            *slot = Some(result);
            match slot.as_ref() {
                Some(Ok(value)) => Ok(*value),
                _ => Err(HierarchyCodecError::InvalidTree),
            }
        }
    }
}

fn reserve_decoded<T>(
    values: &mut Vec<T>,
    count: usize,
    slot: Option<&mut Option<Result<(), std::collections::TryReserveError>>>,
) -> Result<(), HierarchyCodecError> {
    let result = values.try_reserve_exact(count);
    match slot {
        None => result.map_err(|_| HierarchyCodecError::Capacity),
        Some(slot) => {
            *slot = Some(result);
            if matches!(slot, Some(Ok(()))) {
                Ok(())
            } else {
                Err(HierarchyCodecError::Capacity)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::graph::SandboxTreeError;

    fn project() -> ProjectId { ProjectId::from_bytes([7; 16]) }

    fn sandbox(value: u8) -> SandboxId { SandboxId::from_bytes([value; 16]) }

    fn ordinary_forest(count: u8) -> SandboxTreeV1 {
        let limits = TreeLimitsV1::new(3, 3, 3, 2, 2, 2, 2).unwrap();
        let records = (1..=count).map(|id| SandboxTreeRecordV1::new(
            project(), sandbox(id), None, DesiredGeneration::new(1), None,
        ).unwrap()).collect();
        SandboxTreeV1::from_records(project(), Revision::new(1), limits, records).unwrap()
    }

    fn set_parent(bytes: &mut [u8], row: usize, parent: u8) {
        let start = TREE_HEADER_BYTES + row * TREE_RECORD_BYTES;
        bytes[start + 16] = 1;
        bytes[start + 17..start + 33].copy_from_slice(sandbox(parent).as_bytes());
    }

    #[test]
    fn malformed_late_record_keeps_actual_decoded_prefix_and_first_cause() {
        let mut bytes = encode_tree_v1(&ordinary_forest(3)).unwrap();
        bytes[TREE_HEADER_BYTES + 2 * TREE_RECORD_BYTES + 16] = 2;
        assert!(matches!(decode_tree_v1(&bytes), Err(HierarchyCodecError::CorruptEncoding)));
        let mut originals = TreeDecodeOriginalsV1::new();

        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());

        let records = originals.records.as_ref().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].sandbox(), sandbox(2));
        let pointer = records.as_ptr();
        let cause = originals.failure().unwrap().downcast_ref::<HierarchyCodecError>().unwrap()
            as *const HierarchyCodecError;
        assert!(matches!(originals.failure().unwrap().downcast_ref::<HierarchyCodecError>(),
            Some(HierarchyCodecError::CorruptEncoding)));
        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());
        assert_eq!(originals.records.as_ref().unwrap().as_ptr(), pointer);
        assert_eq!(originals.failure().unwrap().downcast_ref::<HierarchyCodecError>().unwrap()
            as *const HierarchyCodecError, cause);
        assert!(originals.take_tree_once().is_err());
    }

    #[test]
    fn actual_cycle_keeps_walk_set_and_original_path_on_reentry() {
        let mut bytes = encode_tree_v1(&ordinary_forest(3)).unwrap();
        set_parent(&mut bytes, 0, 2);
        set_parent(&mut bytes, 1, 1);
        assert!(matches!(decode_tree_v1(&bytes), Err(HierarchyCodecError::InvalidTree)));
        let mut originals = TreeDecodeOriginalsV1::new();

        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());

        assert_eq!(originals.graph.retained_path_v1().unwrap(), &[sandbox(1), sandbox(2)]);
        assert!(matches!(originals.failure().unwrap().downcast_ref::<SandboxTreeError>(),
            Some(SandboxTreeError::Cycle)));
        let pointer = originals.graph.retained_path_v1().unwrap().as_ptr();
        let cause = originals.failure().unwrap().downcast_ref::<SandboxTreeError>().unwrap()
            as *const SandboxTreeError;
        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());
        assert_eq!(originals.graph.retained_path_v1().unwrap().as_ptr(), pointer);
        assert_eq!(originals.failure().unwrap().downcast_ref::<SandboxTreeError>().unwrap()
            as *const SandboxTreeError, cause);
    }

    #[test]
    fn depth_refusal_keeps_prior_depths_and_unconsumed_current_path() {
        let mut bytes = encode_tree_v1(&ordinary_forest(3)).unwrap();
        set_parent(&mut bytes, 1, 1);
        set_parent(&mut bytes, 2, 2);
        // The fourth configured limit is maximum_depth; all framing stays real.
        bytes[48..52].copy_from_slice(&1u32.to_be_bytes());
        let mut originals = TreeDecodeOriginalsV1::new();

        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());

        assert!(matches!(originals.failure().unwrap().downcast_ref::<SandboxTreeError>(),
            Some(SandboxTreeError::TooDeep)));
        assert_eq!(originals.graph.retained_depth_count_v1(), 2);
        assert_eq!(originals.graph.retained_path_v1().unwrap(), &[sandbox(3)]);
        assert!(matches!(decode_tree_v1(&bytes), Err(HierarchyCodecError::InvalidTree)));
    }

    #[test]
    fn descendant_refusal_keeps_the_actual_sorted_work_and_built_depths() {
        let mut bytes = encode_tree_v1(&ordinary_forest(3)).unwrap();
        set_parent(&mut bytes, 1, 1);
        set_parent(&mut bytes, 2, 2);
        bytes[56..60].copy_from_slice(&1u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&1u32.to_be_bytes());
        let mut originals = TreeDecodeOriginalsV1::new();

        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());

        assert!(matches!(originals.failure().unwrap().downcast_ref::<SandboxTreeError>(),
            Some(SandboxTreeError::TooManyDescendants)));
        assert_eq!(originals.graph.retained_depth_count_v1(), 3);
        let work = originals.graph.retained_descendant_work_v1().unwrap();
        assert_eq!(work, &[(2, sandbox(3)), (1, sandbox(2)), (0, sandbox(1))]);
        let pointer = work.as_ptr();
        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());
        assert_eq!(originals.graph.retained_descendant_work_v1().unwrap().as_ptr(), pointer);
    }

    #[test]
    fn invalid_tombstone_order_keeps_decoded_input_before_map_build() {
        let tree = SandboxTreeV1::from_records_and_tombstones(project(), Revision::new(1),
            ordinary_forest(0).limits(), Vec::new(), vec![sandbox(3), sandbox(4)]).unwrap();
        let mut bytes = encode_tree_v1(&tree).unwrap();
        bytes[TREE_HEADER_BYTES + 16..TREE_HEADER_BYTES + 32]
            .copy_from_slice(sandbox(2).as_bytes());
        let mut originals = TreeDecodeOriginalsV1::new();

        assert!(decode_tree_retaining_v1(&bytes, &mut originals).is_err());

        assert!(matches!(originals.failure().unwrap().downcast_ref::<SandboxTreeError>(),
            Some(SandboxTreeError::TombstonesNotCanonical)));
        assert_eq!(originals.graph.retained_tombstone_input_v1().unwrap(), &[sandbox(3), sandbox(2)]);
    }

    #[test]
    fn successful_tree_moves_once_without_rebuilding_its_records() {
        let tree = ordinary_forest(3);
        let bytes = encode_tree_v1(&tree).unwrap();
        let mut originals = TreeDecodeOriginalsV1::new();

        decode_tree_retaining_v1(&bytes, &mut originals).unwrap();

        let pointer = originals.tree().unwrap().record(sandbox(2)).unwrap() as *const SandboxTreeRecordV1;
        assert_eq!(originals.tree().unwrap(), &decode_tree_v1(&bytes).unwrap());
        let moved = originals.take_tree_once().unwrap();
        assert_eq!(moved.record(sandbox(2)).unwrap() as *const SandboxTreeRecordV1, pointer);
        assert_eq!(encode_tree_v1(&moved).unwrap(), bytes);
        assert!(originals.tree().is_none());
        assert!(originals.take_tree_once().is_err());
        assert_eq!(tree_commitment_v1(&tree).unwrap(), tree_commitment_from_bytes_v1(bytes.as_slice()));
        assert_eq!(tree_commitment_v1(&tree).unwrap(), tree_commitment_from_bytes_v1(bytes));
    }
}
