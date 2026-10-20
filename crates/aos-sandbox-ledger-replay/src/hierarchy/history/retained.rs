//! Owns the actual inputs and indexes reached by the shared history constructor.

use super::*;

pub(crate) struct HistoryBuildOriginalsV1 {
    pub(super) records: Option<Vec<HierarchyHistoryRecordV1>>,
    pub(super) idempotency: Option<BTreeMap<ObjectDigest, usize>>,
    pub(super) resource_states: Option<BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>>,
    pub(super) resource_heads: Option<BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>>,
    history: Option<HierarchyHistoryV1>,
    outcome: Option<Result<(), HierarchyHistoryError>>,
    closed: Option<HierarchyHistoryError>,
    entered: bool,
}

impl HistoryBuildOriginalsV1 {
    pub(crate) const fn new() -> Self {
        Self {
            records: None,
            idempotency: None,
            resource_states: None,
            resource_heads: None,
            history: None,
            outcome: None,
            closed: None,
            entered: false,
        }
    }

    pub(crate) fn observe_once(
        &mut self,
        project: ProjectId,
        records: Vec<HierarchyHistoryRecordV1>,
    ) -> Result<(), HierarchyHistoryError> {
        if self.entered {
            // A duplicate call must not replace any negative constructor work.
            // The actual selected caller enters once with this one records Vec.
            self.closed.get_or_insert(HierarchyHistoryError::CorruptHistory);
            return Err(HierarchyHistoryError::CorruptHistory);
        }
        self.entered = true;
        self.outcome = Some(match HierarchyHistoryV1::from_records_with_originals(
            project, records, Some(self),
        ) {
            Ok(history) => { self.history = Some(history); Ok(()) }
            Err(cause) => Err(cause),
        });
        match &self.outcome {
            Some(Ok(())) => Ok(()),
            _ => Err(HierarchyHistoryError::CorruptHistory),
        }
    }

    pub(crate) fn take_history_once(&mut self) -> Result<HierarchyHistoryV1, HierarchyHistoryError> {
        if self.failure().is_some() {
            return Err(HierarchyHistoryError::CorruptHistory);
        }
        match self.history.take() {
            Some(history) => Ok(history),
            None => {
                self.closed.get_or_insert(HierarchyHistoryError::CorruptHistory);
                Err(HierarchyHistoryError::CorruptHistory)
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&HierarchyHistoryError> {
        self.outcome.as_ref().and_then(|outcome| outcome.as_ref().err())
            .or(self.closed.as_ref())
    }

    pub(crate) fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_core::bounded_codec::CaptureOnDropV1;
        use std::mem::size_of;

        let guards = size_of::<CaptureOnDropV1<'static, Vec<HierarchyHistoryRecordV1>>>()
            .checked_add(size_of::<CaptureOnDropV1<'static, BTreeMap<ObjectDigest, usize>>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>>>())?;
        // 8 original fields, 4 two-field guards and 4 returned history roots.
        Some((size_of::<Self>().checked_mul(2)?.checked_add(guards)?, 8 + 8 + 4))
    }
}

#[cfg(test)]
impl HistoryBuildOriginalsV1 {
    pub(crate) fn retained_counts_v1(&self) -> (Option<usize>, Option<usize>, Option<usize>, Option<usize>) {
        (self.records.as_ref().map(Vec::len), self.idempotency.as_ref().map(BTreeMap::len),
            self.resource_states.as_ref().map(BTreeMap::len), self.resource_heads.as_ref().map(BTreeMap::len))
    }
}
