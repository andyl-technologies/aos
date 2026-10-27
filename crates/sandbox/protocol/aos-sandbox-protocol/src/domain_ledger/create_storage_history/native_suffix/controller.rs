//! Compares fixed Controller and Cache suffix chains as passive historical DATA.
//!
//! The native role owns the actual file, paid replay and independent posts. This
//! aggregate only routes validated COMMIT coordinates to the same pair observer;
//! it cannot open a file, establish currentness or authorize a transition.

use super::{HistoryPairNativeSuffixProgressV1, HistoryPairNativeSuffixV1, HistoryPairSuffixErrorV1};
use super::super::{KeyV1, OwnerV1};
use crate::domain_ledger::transaction::JournalTransaction;

/// Classifies an unrepresentable passive suffix header quote.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControllerSuffixGeometryErrorV1 {
    /// Identifies a checked header multiplication or integer conversion overflow.
    #[error("Controller suffix header extent is too large")]
    TooLarge,
}

/// Names the new canonical and immediate caller-projection result planes.
///
/// The receiving role pays these Memory-only interfaces before calling the
/// canonical quote. This function does not issue a receiving permission.
pub fn receiving_interface_control_bytes_v1<E>() -> Option<usize> {
    use aos_sandbox_model::ResourceVector;
    use std::mem::size_of;

    let canonical = size_of::<Result<ResourceVector, ControllerSuffixGeometryErrorV1>>()
        .checked_mul(3)?;
    let projected = size_of::<Result<ResourceVector, E>>().checked_mul(3)?;
    let forwarding = size_of::<Option<usize>>().checked_mul(3)?;
    let locals = size_of::<usize>().checked_mul(4)?;

    canonical.checked_add(projected)?.checked_add(forwarding)?.checked_add(locals)
}

/// Borrows a fixed original transaction chain and its retained comparison progress.
///
/// Only the final segment joins the captured whole-file end. These private
/// borrowed fields are comparison DATA, with no native file or role custody.
pub struct ControllerHistoryNativeSuffixV1<'expected, 'progress, const N: usize = 3> {
    pairs: [HistoryPairNativeSuffixV1<'expected, 'progress>; N],
    active: &'progress mut usize,
}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 3> {
    /// Borrows the original three ordered Controller comparison recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new(
        expected: [&'expected JournalTransaction; 3],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 3],
        active: &'progress mut usize,
        positions: [(u64, u64); 4],
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if *active != 0 { return Err(E::Incomplete); }
        let lane = KeyV1::decode(expected[0].records().first().ok_or(E::Recipe)?.key())
            .map_err(|_| E::Recipe)?.lane();
        for (index, transaction) in expected.iter().enumerate() {
            let [record, _] = transaction.records() else { return Err(E::Recipe); };
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            if key.owner() != OwnerV1::Controller || key.lane() != lane
                || key.revision() != (index + 1) as u64
            {
                return Err(E::Recipe);
            }
        }
        let [first, second, third] = progress;
        let pairs = [
            HistoryPairNativeSuffixV1::new(expected[0], first,
                positions[0].0, positions[0].1, positions[1].0, positions[1].1)?,
            HistoryPairNativeSuffixV1::new(expected[1], second,
                positions[1].0, positions[1].1, positions[2].0, positions[2].1)?,
            HistoryPairNativeSuffixV1::new(expected[2], third,
                positions[2].0, positions[2].1, positions[3].0, positions[3].1)?,
        ];
        Ok(Self { pairs, active })
    }

}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 2> {
    /// Borrows the original Cache Held and Released comparison recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new_cache_released_v1(
        expected: [&'expected JournalTransaction; 2],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 2],
        active: &'progress mut usize,
        positions: [(u64, u64); 3],
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if *active != 0 { return Err(E::Incomplete); }
        let first = expected[0].records().first().ok_or(E::Recipe)?;
        let lane = KeyV1::decode(first.key()).map_err(|_| E::Recipe)?.lane();
        for (index, transaction) in expected.iter().enumerate() {
            let [record, _] = transaction.records() else { return Err(E::Recipe); };
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            if key.owner() != OwnerV1::Cache || key.lane() != lane
                || key.revision() != (index + 1) as u64 {
                return Err(E::Recipe);
            }
        }
        let [held, released] = progress;
        let pairs = [
            HistoryPairNativeSuffixV1::new(expected[0], held,
                positions[0].0, positions[0].1, positions[1].0, positions[1].1)?,
            HistoryPairNativeSuffixV1::new(expected[1], released,
                positions[1].0, positions[1].1, positions[2].0, positions[2].1)?,
        ];
        Ok(Self { pairs, active })
    }
}

impl<'expected, 'progress, const N: usize> ControllerHistoryNativeSuffixV1<'expected, 'progress, N> {
    /// Borrows the first retained pair-comparison cause.
    pub fn failure_v1(&self) -> Option<&HistoryPairSuffixErrorV1> {
        self.pairs.iter().find_map(|pair| pair.failure())
    }

    /// Calculates the two original aggregate header planes.
    ///
    /// # Errors
    /// Rejects a header extent that cannot be represented.
    pub fn receiving_frame_demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, ControllerSuffixGeometryErrorV1>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .ok_or(ControllerSuffixGeometryErrorV1::TooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ControllerSuffixGeometryErrorV1::TooLarge)?))
    }

    /// Compares one validated COMMIT at its actual native coordinates.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        let pair = self.pairs.get_mut(*self.active)
            .ok_or(HistoryPairSuffixErrorV1::Incomplete)?;
        pair.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)?;
        if pair.has_seen_v1() && *self.active < N - 1 {
            let next = commit_sequence.checked_add(1)
                .ok_or(HistoryPairSuffixErrorV1::Coordinates)?;
            pair.finish_segment(next, end_offset)?;
            *self.active += 1;
        }
        Ok(())
    }

    /// Joins the completed segments to the actual captured file end.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn finish(
        &mut self,
        next: u64,
        end: u64,
        captured_end: u64,
    ) -> Result<(), HistoryPairSuffixErrorV1> {
        if let Some(first) = self.pairs.iter().find_map(|pair| pair.failure()).copied() {
            return Err(first);
        }
        if *self.active != N - 1 || !self.pairs[..N - 1].iter().all(|pair| pair.is_complete_v1()) {
            return Err(HistoryPairSuffixErrorV1::Incomplete);
        }
        self.pairs[N - 1].finish(next, end, captured_end)
    }
}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 6> {
    /// Borrows the original reserved Controller and bank recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new_reserved(
        expected: [&'expected JournalTransaction; 6],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 6],
        active: &'progress mut usize,
        positions: [(u64, u64); 7],
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if *active != 0 { return Err(E::Incomplete); }
        let lane = KeyV1::decode(expected[0].records().first().ok_or(E::Recipe)?.key())
            .map_err(|_| E::Recipe)?.lane();
        for (index, revision) in [(0, 1), (1, 2), (2, 3), (3, 4), (5, 5)] {
            let [record, _] = expected[index].records() else { return Err(E::Recipe); };
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            if key.owner() != OwnerV1::Controller || key.lane() != lane
                || key.revision() != revision
            { return Err(E::Recipe); }
        }
        let [first, second, third, fourth, bank, sixth] = progress;
        let pairs = [
            HistoryPairNativeSuffixV1::new(expected[0], first,
                positions[0].0, positions[0].1, positions[1].0, positions[1].1)?,
            HistoryPairNativeSuffixV1::new(expected[1], second,
                positions[1].0, positions[1].1, positions[2].0, positions[2].1)?,
            HistoryPairNativeSuffixV1::new(expected[2], third,
                positions[2].0, positions[2].1, positions[3].0, positions[3].1)?,
            HistoryPairNativeSuffixV1::new(expected[3], fourth,
                positions[3].0, positions[3].1, positions[4].0, positions[4].1)?,
            HistoryPairNativeSuffixV1::new_use_reserve(expected[4], bank,
                positions[4], positions[5])?,
            HistoryPairNativeSuffixV1::new(expected[5], sixth,
                positions[5].0, positions[5].1, positions[6].0, positions[6].1)?,
        ];
        Ok(Self { pairs, active })
    }
}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 7> {
    /// Borrows the original signed Controller and bank recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new_signed(
        expected: [&'expected JournalTransaction; 7],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 7],
        active: &'progress mut usize,
        positions: [(u64, u64); 8],
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if *active != 0 { return Err(E::Incomplete); }
        let lane = KeyV1::decode(expected[0].records().first().ok_or(E::Recipe)?.key())
            .map_err(|_| E::Recipe)?.lane();
        for (index, revision) in [(0, 1), (1, 2), (2, 3), (3, 4), (5, 5), (6, 6)] {
            let [record, _] = expected[index].records() else { return Err(E::Recipe); };
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            if key.owner() != OwnerV1::Controller || key.lane() != lane
                || key.revision() != revision
            { return Err(E::Recipe); }
        }
        let [first, second, third, fourth, bank, sixth, seventh] = progress;
        let pairs = [
            HistoryPairNativeSuffixV1::new(expected[0], first,
                positions[0].0, positions[0].1, positions[1].0, positions[1].1)?,
            HistoryPairNativeSuffixV1::new(expected[1], second,
                positions[1].0, positions[1].1, positions[2].0, positions[2].1)?,
            HistoryPairNativeSuffixV1::new(expected[2], third,
                positions[2].0, positions[2].1, positions[3].0, positions[3].1)?,
            HistoryPairNativeSuffixV1::new(expected[3], fourth,
                positions[3].0, positions[3].1, positions[4].0, positions[4].1)?,
            HistoryPairNativeSuffixV1::new_use_reserve(expected[4], bank,
                positions[4], positions[5])?,
            HistoryPairNativeSuffixV1::new(expected[5], sixth,
                positions[5].0, positions[5].1, positions[6].0, positions[6].1)?,
            HistoryPairNativeSuffixV1::new(expected[6], seventh,
                positions[6].0, positions[6].1, positions[7].0, positions[7].1)?,
        ];
        Ok(Self { pairs, active })
    }
}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 10> {
    /// Borrows the original outcome Controller and bank recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new_outcome(
        expected: [&'expected JournalTransaction; 10],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 10],
        active: &'progress mut usize,
        positions: [(u64, u64); 11],
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        if *active != 0 { return Err(E::Incomplete); }
        let lane = KeyV1::decode(expected[0].records().first().ok_or(E::Recipe)?.key())
            .map_err(|_| E::Recipe)?.lane();
        for (index, revision) in [(0, 1), (1, 2), (2, 3), (3, 4), (5, 5),
            (6, 6), (7, 7), (8, 8), (9, 9)] {
            let [record, _] = expected[index].records() else { return Err(E::Recipe); };
            let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
            if key.owner() != OwnerV1::Controller || key.lane() != lane || key.revision() != revision {
                return Err(E::Recipe);
            }
        }
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9] = progress;
        let pairs = [
            HistoryPairNativeSuffixV1::new(expected[0], p0, positions[0].0, positions[0].1, positions[1].0, positions[1].1)?,
            HistoryPairNativeSuffixV1::new(expected[1], p1, positions[1].0, positions[1].1, positions[2].0, positions[2].1)?,
            HistoryPairNativeSuffixV1::new(expected[2], p2, positions[2].0, positions[2].1, positions[3].0, positions[3].1)?,
            HistoryPairNativeSuffixV1::new(expected[3], p3, positions[3].0, positions[3].1, positions[4].0, positions[4].1)?,
            HistoryPairNativeSuffixV1::new_use_reserve(expected[4], p4, positions[4], positions[5])?,
            HistoryPairNativeSuffixV1::new(expected[5], p5, positions[5].0, positions[5].1, positions[6].0, positions[6].1)?,
            HistoryPairNativeSuffixV1::new(expected[6], p6, positions[6].0, positions[6].1, positions[7].0, positions[7].1)?,
            HistoryPairNativeSuffixV1::new(expected[7], p7, positions[7].0, positions[7].1, positions[8].0, positions[8].1)?,
            HistoryPairNativeSuffixV1::new(expected[8], p8, positions[8].0, positions[8].1, positions[9].0, positions[9].1)?,
            HistoryPairNativeSuffixV1::new(expected[9], p9, positions[9].0, positions[9].1, positions[10].0, positions[10].1)?,
        ];
        Ok(Self { pairs, active })
    }
}

impl<'expected, 'progress> ControllerHistoryNativeSuffixV1<'expected, 'progress, 12> {
    /// Borrows the original closed Controller and bank recipes.
    ///
    /// # Errors
    /// Retains malformed recipes, differing coordinates or incomplete comparison.
    pub fn new_closed(
        expected: [&'expected JournalTransaction; 12],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 12],
        active: &'progress mut usize, positions: [(u64, u64); 13],
        binding: crate::domain_ledger::resource_bank::CreateStorageUseBindingV1,
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11] = progress;
        let preceding = ControllerHistoryNativeSuffixV1::<10>::new_outcome(
            [expected[0],expected[1],expected[2],expected[3],expected[4],expected[5],
                expected[6],expected[7],expected[8],expected[9]],
            [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9], active,
            [positions[0],positions[1],positions[2],positions[3],positions[4],positions[5],
                positions[6],positions[7],positions[8],positions[9],positions[10]])?;
        let [record, _] = expected[11].records() else { return Err(E::Recipe); };
        let key = KeyV1::decode(record.key()).map_err(|_| E::Recipe)?;
        let lane = KeyV1::decode(expected[0].records().first().ok_or(E::Recipe)?.key())
            .map_err(|_| E::Recipe)?.lane();
        if key.owner() != OwnerV1::Controller || key.lane() != lane || key.revision() != 10 {
            return Err(E::Recipe);
        }
        let commit = HistoryPairNativeSuffixV1::new_use_commit(expected[10], p10, binding,
            positions[10], positions[11])?;
        let handoff = HistoryPairNativeSuffixV1::new(expected[11], p11,
            positions[11].0, positions[11].1, positions[12].0, positions[12].1)?;
        let [s0,s1,s2,s3,s4,s5,s6,s7,s8,s9] = preceding.pairs;
        Ok(Self { pairs: [s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,commit,handoff], active: preceding.active })
    }
}

impl<const N: usize> ControllerHistoryNativeSuffixV1<'_, '_, N> {
    /// Borrows the first retained cause in this same ordered comparison chain.
    ///
    /// This diagnostic does not compare, advance or complete any segment.
    #[must_use]
    pub fn failure(&self) -> Option<&HistoryPairSuffixErrorV1> {
        self.pairs.iter().find_map(HistoryPairNativeSuffixV1::failure)
    }
}
