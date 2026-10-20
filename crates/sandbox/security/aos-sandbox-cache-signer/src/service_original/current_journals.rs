//! Arms the fixed five-reader roster inside the genuine matched Cache purpose.
//!
//! Every reader's typed backing is retained. Native descriptor peak is reused
//! only after the preceding reader's actual complete local native disposition;
//! failure prevents advancing this roster. Full family replay remains the
//! private driver's responsibility and cannot be replaced by structural EOF.

use std::error::Error;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    cache_state::fixed_journals::CacheJournalRecipeRoleV1 as Role,
    domain_ledger::create_storage_history::cache_held::CacheHeldBodyDataV1,
};

use super::journal_prefix::CacheCurrentJournalPrefixOriginalV1 as Prefix;
use super::{
    CachePurposeReceivingV1, CacheSignerReceivingClosedV1 as Closed, Common, First, StageOriginals,
    admit_stage, cause, observe_original, sample_pair_demand,
};

const ROLES: [Role; 5] = [
    Role::Bootstrap,
    Role::Hold,
    Role::State,
    Role::Authority,
    Role::Clock,
];

#[derive(Clone, Copy)]
enum JournalFailure {
    Entry,
    Funding,
    Before,
    Reader,
    LocalFunding,
    LocalBefore,
    LocalAfter,
    Retirement,
    LocalDeadline,
    Incomplete,
    After,
}

pub(super) struct CacheCurrentJournalsOriginalV1 {
    stage: StageOriginals,
    local_stages: [StageOriginals; 5],
    retirements: [Option<Result<(), Closed>>; 5],
    local_clocks: [Option<rustix::time::Timespec>; 5],
    local_deadlines: [Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >; 5],
    readers: [Option<Prefix>; 5],
    preparations: [Option<Result<(), Closed>>; 5],
    native_posts: [Option<Result<(), Closed>>; 5],
    replays: [Option<Result<(), Closed>>; 5],
    next: usize,
    after_entered: bool,
    first: Option<JournalFailure>,
}

impl CacheCurrentJournalsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: Default::default(),
            local_stages: std::array::from_fn(|_| Default::default()),
            retirements: std::array::from_fn(|_| None),
            local_clocks: std::array::from_fn(|_| None),
            local_deadlines: std::array::from_fn(|_| None),
            readers: std::array::from_fn(|_| None),
            preparations: std::array::from_fn(|_| None),
            native_posts: std::array::from_fn(|_| None),
            replays: std::array::from_fn(|_| None),
            next: 0,
            after_entered: false,
            first: None,
        }
    }

    fn begin_once(
        &mut self,
        common: &mut Common,
        resident_files: u64,
        expected: CacheHeldBodyDataV1,
        controller_uid: u32,
        controller_gid: u32,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.stage.demand.is_some() {
            return self.refuse(JournalFailure::Entry);
        }
        self.stage.demand = Some((|| {
            let missing = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let mut backing = ResourceVector::ZERO;
            let mut native_files = 0;
            for role in ROLES {
                let fixed = Prefix::fixed_receiving_demand_v1(role).ok_or(missing)?;
                backing = backing.checked_add(fixed.with(D::OpenFiles, 0))?;
                native_files = native_files.max(fixed.get(D::OpenFiles));
            }
            backing
                .with(D::OpenFiles, native_files)
                .checked_add(sample_pair_demand()?)?
                .checked_add(
                    ResourceVector::ZERO.with(
                        D::MemoryBytes,
                        u64::try_from(std::mem::size_of::<Self>().checked_mul(2).ok_or(missing)?)
                            .map_err(|_| missing)?,
                    ),
                )
        })());
        if admit_stage(common, &mut self.stage, resident_files).is_err() {
            return self.refuse(JournalFailure::Funding);
        }
        self.stage.before_result = Some(observe_original(common, &mut self.stage.before));
        if !matches!(self.stage.before_result, Some(Ok(()))) {
            return self.refuse(JournalFailure::Before);
        }
        let expected = [
            expected.bootstrap,
            expected.hold,
            expected.state,
            expected.authority,
            expected.clock,
        ];
        for (index, cut) in expected.into_iter().enumerate() {
            self.read_fixed_once(
                common,
                resident_files,
                index,
                cut,
                controller_uid,
                controller_gid,
                cutoff,
            )?;
        }
        Ok(())
    }

    // Each complete physical/parser leaf has its own same-F before/after.
    // A later family comparison cannot justify disposing a failed local leaf.
    // Parsed maps remain resident for the complete cross-view model driver.
    #[allow(clippy::too_many_arguments)]
    fn read_fixed_once(
        &mut self,
        common: &mut Common,
        resident_files: u64,
        index: usize,
        expected: aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1,
        controller_uid: u32,
        controller_gid: u32,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.first.is_some() || self.next != index || index >= ROLES.len() {
            return self.refuse(JournalFailure::Entry);
        }
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::OpenFiles,
        };
        self.local_stages[index].demand = Some(sample_pair_demand());
        let physical = (|| {
            let prefix = Prefix::fixed_receiving_demand_v1(ROLES[index]).ok_or(overflow)?;
            resident_files
                .checked_add(prefix.get(D::OpenFiles))
                .and_then(|files| files.checked_add(sample_pair_demand().ok()?.get(D::OpenFiles)))
                .ok_or(overflow)
        })();
        let resident = match physical {
            Ok(value) => value,
            Err(error) => {
                self.local_stages[index].physical = Some(Err(error));
                return self.refuse(JournalFailure::LocalFunding);
            }
        };
        if admit_stage(common, &mut self.local_stages[index], resident).is_err() {
            return self.refuse(JournalFailure::LocalFunding);
        }
        self.local_stages[index].before_result = Some(observe_original(
            common,
            &mut self.local_stages[index].before,
        ));
        if !matches!(self.local_stages[index].before_result, Some(Ok(()))) {
            self.first.get_or_insert(JournalFailure::LocalBefore);
        }
        if self.first.is_none() {
            self.readers[index] = Some(Prefix::new(ROLES[index]));
            self.preparations[index] =
                Some(self.readers[index].as_mut().ok_or(Closed)?.prepare_once(
                    expected,
                    controller_uid,
                    controller_gid,
                ));
            if !matches!(self.preparations[index], Some(Ok(()))) {
                self.first.get_or_insert(JournalFailure::Reader);
            }
        }
        if self.first.is_none() {
            self.replays[index] = Some(
                self.readers[index]
                    .as_mut()
                    .ok_or(Closed)?
                    .replay_complete_once(common),
            );
            if !matches!(self.replays[index], Some(Ok(()))) {
                self.first.get_or_insert(JournalFailure::Reader);
            }
        }
        if let Some(reader) = self.readers[index].as_mut() {
            if reader.owes_native_post_v1() {
                self.native_posts[index] = Some(reader.finish_native_once(cutoff));
                if !matches!(self.native_posts[index], Some(Ok(()))) {
                    self.first.get_or_insert(JournalFailure::Reader);
                }
            }
        }
        // This was prepaid before the before sample, including failed before
        // or primary work. Later failure cannot suppress its independent post.
        self.local_stages[index].after_result = Some(observe_original(
            common,
            &mut self.local_stages[index].after,
        ));
        if !matches!(self.local_stages[index].after_result, Some(Ok(()))) {
            self.first.get_or_insert(JournalFailure::LocalAfter);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.local_clocks[index] = Some(now);
        self.local_deadlines[index] =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.local_deadlines[index], Some(Ok(_))) {
            self.first.get_or_insert(JournalFailure::LocalDeadline);
        }
        if self.first.is_none() {
            self.retirements[index] = Some(
                self.readers[index]
                    .as_mut()
                    .ok_or(Closed)?
                    .retire_completed_native_leaf_once(),
            );
            if !matches!(self.retirements[index], Some(Ok(())))
                || self.local_stages[index].retire_positive_samples().is_err()
            {
                self.first.get_or_insert(JournalFailure::Retirement);
            }
        }
        if self.first.is_some() {
            return Err(Closed);
        }
        self.next += 1;
        Ok(())
    }

    /// Borrows only a completely replayed and locally settled fixed map.
    pub(super) fn state_v1(
        &self,
        role: Role,
    ) -> Option<&std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>>
    {
        let index = ROLES.iter().position(|candidate| *candidate == role)?;
        if self.first.is_some()
            || self.next <= index
            || !self.local_stages[index].native_retired
            || !matches!(self.retirements[index], Some(Ok(())))
        {
            return None;
        }
        self.readers[index].as_ref()?.replayed_state_v1()
    }

    pub(super) fn coordinates_v1(
        &self,
        role: Role,
    ) -> Option<
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1,
    > {
        self.reader_v1(role)?.completed_coordinates_v1()
    }

    pub(super) fn raw_views_v1(&self)
        -> Option<aos_sandbox_ledger_replay::cache_current::CacheCurrentRawViewsDataV1<'_>> {
        if !self.native_leaves_are_retired_v1() { return None; }
        Some(aos_sandbox_ledger_replay::cache_current::CacheCurrentRawViewsDataV1 {
            bootstrap: self.reader_v1(Role::Bootstrap)?.raw_view_data_v1()?,
            hold: self.reader_v1(Role::Hold)?.raw_view_data_v1()?,
            state: self.reader_v1(Role::State)?.raw_view_data_v1()?,
            authority: self.reader_v1(Role::Authority)?.raw_view_data_v1()?,
            clock: self.reader_v1(Role::Clock)?.raw_view_data_v1()?,
        })
    }

    pub(super) fn reader_v1(&self, role: Role) -> Option<&Prefix> {
        let index = ROLES.iter().position(|candidate| *candidate == role)?;
        self.state_v1(role)?;
        self.readers[index].as_ref()
    }

    /// Lends the actual current reader only inside the fixed service driver.
    pub(super) fn active_mut(&mut self) -> Result<&mut Prefix, Closed> {
        if self.first.is_some() || self.after_entered || self.next >= ROLES.len() {
            return Err(Closed);
        }
        self.readers[self.next].as_mut().ok_or(Closed)
    }

    fn finish_once(&mut self, common: &mut Common, cutoff: u64) -> Result<(), Closed> {
        if !self.owes_after_v1() {
            return self.refuse(JournalFailure::Entry);
        }
        self.after_entered = true;
        if self.next < ROLES.len() {
            if let Some(active) = self.readers[self.next].as_mut() {
                if active.owes_native_post_v1() {
                    self.native_posts[self.next] = Some(active.finish_native_once(cutoff));
                    if !matches!(self.native_posts[self.next], Some(Ok(()))) {
                        self.first.get_or_insert(JournalFailure::Reader);
                    }
                }
            }
            // A partially driven roster cannot yield a positive purpose even
            // when the reached reader's independently owed native post succeeds.
            self.first.get_or_insert(JournalFailure::Incomplete);
        }
        self.stage.after_result = Some(observe_original(common, &mut self.stage.after));
        if !matches!(self.stage.after_result, Some(Ok(()))) {
            self.first.get_or_insert(JournalFailure::After);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn can_retire_positive_samples_v1(&self) -> bool {
        self.native_leaves_are_retired_v1() && self.stage.can_retire_positive_samples()
    }

    pub(super) fn retire_positive_samples_once_v1(&mut self) -> Result<(), Closed> {
        if !self.can_retire_positive_samples_v1() {
            return Err(Closed);
        }
        self.stage.retire_positive_samples()
    }

    pub(super) fn native_leaves_are_retired_v1(&self) -> bool {
        self.first.is_none()
            && self.next == ROLES.len()
            && self.readers.iter().all(|reader| {
                reader
                    .as_ref()
                    .is_some_and(Prefix::native_leaf_is_retired_v1)
            })
    }

    pub(super) fn owes_after_v1(&self) -> bool {
        self.stage.admitted() && !self.after_entered
    }

    fn refuse(&mut self, first: JournalFailure) -> Result<(), Closed> {
        self.first.get_or_insert(first);
        Err(Closed)
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            JournalFailure::Entry | JournalFailure::Incomplete => Some(&Closed),
            JournalFailure::LocalFunding => {
                self.local_stages.get(self.next)?.funding_failure(common)
            }
            JournalFailure::LocalBefore => self
                .local_stages
                .get(self.next)?
                .before
                .failure()
                .or_else(|| cause(&self.local_stages.get(self.next)?.before_result)),
            JournalFailure::LocalAfter => self
                .local_stages
                .get(self.next)?
                .after
                .failure()
                .or_else(|| cause(&self.local_stages.get(self.next)?.after_result)),
            JournalFailure::LocalDeadline => self.local_deadlines.get(self.next).and_then(cause),
            JournalFailure::Retirement => self
                .retirements
                .get(self.next)
                .and_then(cause)
                .or(Some(&Closed)),
            JournalFailure::Funding => self.stage.funding_failure(common),
            JournalFailure::Before => self
                .stage
                .before
                .failure()
                .or_else(|| cause(&self.stage.before_result)),
            JournalFailure::Reader => self
                .readers
                .get(self.next)
                .and_then(Option::as_ref)
                .and_then(|reader| reader.failure(common))
                .or_else(|| self.preparations.get(self.next).and_then(cause))
                .or_else(|| self.replays.get(self.next).and_then(cause))
                .or_else(|| self.native_posts.get(self.next).and_then(cause)),
            JournalFailure::After => self
                .stage
                .after
                .failure()
                .or_else(|| cause(&self.stage.after_result)),
        }
    }
}

impl CachePurposeReceivingV1<'_> {
    pub(super) fn begin_current_journals_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some()
            || !matches!(self.original.current_clock_before, Some(Ok(())))
            || self.original.current_journals.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        let profile = self.startup.profile.profile().ok_or(Closed)?;
        let controller_uid = profile.identities[0];
        let controller_gid = profile.identities[1];
        let expected = self.original.root_challenge.data()?.expected_current;
        let clock = self
            .original
            .current_clock_stage
            .demand
            .as_ref()
            .and_then(|d| d.as_ref().ok())
            .ok_or(Closed)?;
        let resident = self
            .current_purpose_resident_files_v1()?
            .checked_add(clock.get(D::OpenFiles))
            .ok_or(Closed)?;
        self.original.current_journals = Some(CacheCurrentJournalsOriginalV1::new());
        let result = self
            .original
            .current_journals
            .as_mut()
            .ok_or(Closed)?
            .begin_once(
                &mut self.startup.common,
                resident,
                expected,
                controller_uid,
                controller_gid,
                self.original.root_challenge.data()?.cutoff,
            );
        if result.is_err() {
            self.fail(First::CurrentJournals);
        }
        result
    }

    pub(super) fn finish_current_journals_once(&mut self) -> Result<(), Closed> {
        let cutoff = self.original.root_challenge.data()?.cutoff;
        let result = self
            .original
            .current_journals
            .as_mut()
            .ok_or(Closed)?
            .finish_once(&mut self.startup.common, cutoff);
        if result.is_err() {
            self.fail(First::CurrentJournals);
        }
        result
    }
}
