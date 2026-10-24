//! Declares the exact fixed controls of completed-collection custody loans.
//!
//! These guard walks inspect retained fields only. The independent prospective
//! checkpoint-authentication and semantic constructors still need their own
//! prewalk and full rows before any allocating validator or serializer runs.

use super::*;

impl RetainedCold17Collection {
    /// Names completed/production/member guard controls without walking owners.
    pub(crate) fn completed_loan_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&NativeArchiveRecord>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<[usize; 3]>()
            + size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 3>>>()
            + size_of::<(usize, usize)>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<std::slice::Iter<'static, Option<parent_index::ParentIndex17Attempt>>>()
            + size_of::<std::slice::Iter<'static, Vec<RetainedCold17Member>>>()
            + size_of::<std::slice::Iter<'static, RetainedCold17Member>>()
            + size_of::<&Vec<RetainedCold17Member>>()
            + size_of::<&RetainedCold17Member>()
            + 2 * size_of::<Option<&RetainedCold17Member>>()
            + size_of::<Result<&RetainedCold17Member, RuntimeError>>()
            + size_of::<Option<&PacketRestoredSettledJournal17Objects>>()
            + size_of::<Result<&PacketRestoredSettledJournal17Objects, RuntimeError>>()
            + size_of::<RetainedCold17MemberView<'static>>()
            + size_of::<Result<RetainedCold17MemberView<'static>, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
