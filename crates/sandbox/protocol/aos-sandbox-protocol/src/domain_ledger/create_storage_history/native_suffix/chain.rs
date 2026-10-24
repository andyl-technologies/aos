//! Composes fixed historical pair recipes through one validated native stream.
//!
//! The actual role retains its reader, replay, accounts and independent posts.
//! This borrowed DATA observer owns no descriptor, journal or effect permission.

use super::{
    HistoryPairNativeSuffixProgressV1, HistoryPairNativeSuffixV1,
    HistoryPairSuffixErrorV1, KeyV1, OwnerV1,
};
use crate::domain_ledger::transaction::JournalTransaction;

/// Compares a fixed Controller transaction chain through one COMMIT observer.
///
/// Expected recipes and progress remain caller-owned comparison DATA. The
/// receiving owner separately authenticates and pays the actual native replay.
/// Only the final segment joins the captured whole-file end.
pub struct HistoryPairNativeChainDataV1<'expected, 'progress, const N: usize = 3> {
    pairs: [HistoryPairNativeSuffixV1<'expected, 'progress>; N],
    active: &'progress mut usize,
}

impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 3> {
    /// Compares the three original Controller Ready pair recipes.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

// Cache's original Held and Released pairs use the same sequential observer.
// Only the final Released segment joins the captured whole-file end.
impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 2> {
    /// Compares the original Cache Held and Released pair recipes.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

impl<'expected, 'progress, const N: usize> HistoryPairNativeChainDataV1<'expected, 'progress, N> {
    /// Borrows the first exact member suffix comparison failure.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&HistoryPairSuffixErrorV1> {
        self.pairs.iter().find_map(|pair| pair.failure())
    }

    /// Bounds the two existing observer call and return representations.
    ///
    /// Returns None when the fixed layout cannot be represented.
    #[must_use]
    pub fn receiving_frame_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Compares one transaction and its actual validated native coordinates.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

    /// Completes every selected member against the captured native file end.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 6> {
    /// Compares the original six-member Controller reserve chain.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 7> {
    /// Compares the original seven-member signed Controller chain.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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

impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 10> {
    /// Compares the original ten-member Controller outcome chain.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
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







impl<'expected, 'progress> HistoryPairNativeChainDataV1<'expected, 'progress, 12> {
    /// Compares the original twelve-member closed Controller chain.
    ///
    /// # Errors
    /// Rejects changed recipes, member order or native suffix coordinates.
    pub fn new_closed(
        expected: [&'expected JournalTransaction; 12],
        progress: [&'progress mut HistoryPairNativeSuffixProgressV1; 12],
        active: &'progress mut usize, positions: [(u64, u64); 13],
        binding: crate::domain_ledger::resource_bank::CreateStorageUseBindingV1,
    ) -> Result<Self, HistoryPairSuffixErrorV1> {
        use HistoryPairSuffixErrorV1 as E;
        let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11] = progress;
        let preceding = HistoryPairNativeChainDataV1::<10>::new_outcome(
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
