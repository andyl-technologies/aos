//! Keeps one actual fixed readonly Cache journal prefix under private F.
//!
//! Native preparation stops before parsing. The same owner then admits its
//! actual captured extent and lends the sole shared indexed cursor to the
//! private complete family driver. Structural completion remains comparison
//! DATA; this module cannot complete the signer purpose or manufacture a
//! historical inventory. Every reached file and native cause stays resident
//! until that driver's actual semantic and independent native boundaries.

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1 as _;

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayExtentDataV1, CanonicalReplayOriginalV1, NativeJournalDataErrorV1,
    coordinator::indexed_replay::{
        CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
    },
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{
    FileIdentity, FileIdentityOriginalsV1, ProtectedFailure, ProtectedFileNamesCurrentOriginalsV1,
    ReadOnlyAcquisitionOriginalsV1,
};
use aos_sandbox_linux::signer_mount::{SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1};
use aos_sandbox_protocol::{
    cache_state::fixed_journals::CacheJournalRecipeRoleV1 as Role,
    domain_ledger::{
        create_storage_history::cache_held::CacheJournalDataV1, readonly::IdempotencyDecisionV1,
    },
};

use super::journal_semantic::CacheJournalSemanticOriginalV1;
use super::{CacheSignerReceivingClosedV1 as Closed, Common, cause};
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum CacheJournalPrefixErrorV1 {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    #[error(transparent)]
    Replay(#[from] NativeJournalDataErrorV1),
    #[error(transparent)]
    Indexed(#[from] CanonicalIndexedReplayErrorV1),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    SemanticGeometry(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1),
    #[error("fixed Cache journal boundary differs")]
    Boundary,
    #[error("fixed Cache journal changed")]
    Changed,
    #[error("fixed Cache journal opening is unsupported")]
    Unsupported,
}

impl ProtectedFailure for CacheJournalPrefixErrorV1 {
    const BOUNDARY: Self = Self::Boundary;
    const STALE_NAME: Self = Self::Changed;
    const UNSUPPORTED_OPEN: Self = Self::Unsupported;
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Replay,
    Semantic,
    MountBefore,
    Directory,
    Files,
    Identity,
    Extent,
    Demand,
    Debit,
    Names,
    Metadata,
    MountAfter,
    MountBinding,
    Deadline,
}

pub(super) struct CacheCurrentJournalPrefixOriginalV1 {
    role: Role,
    entered: bool,
    expected: Option<CacheJournalDataV1>,
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    mount_before: SignerMountReadbackAttemptV1,
    mount_before_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    source_owner: Option<Result<(), CacheJournalPrefixErrorV1>>,
    physical: ReadOnlyAcquisitionOriginalsV1<CacheJournalPrefixErrorV1>,
    directory: Option<Result<(), CacheJournalPrefixErrorV1>>,
    files: Option<Result<(), CacheJournalPrefixErrorV1>>,
    identity: Option<Result<(), CacheJournalPrefixErrorV1>>,
    extent: Option<Result<CanonicalReplayExtentDataV1, NativeJournalDataErrorV1>>,
    demand: Option<Result<ResourceVector, CacheJournalPrefixErrorV1>>,
    debit: Option<Result<(), Closed>>,
    replay: CanonicalReplayOriginalV1,
    index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    index_original: CanonicalReplayIndexOriginalsV1,
    replay_entered: bool,
    semantic: CacheJournalSemanticOriginalV1,
    semantic_result: Option<Result<(), Closed>>,
    semantic_remainder: Option<ColdReplayRemainderDataV1>,
    names_after: ProtectedFileNamesCurrentOriginalsV1<CacheJournalPrefixErrorV1>,
    metadata_after: [FileIdentityOriginalsV1<CacheJournalPrefixErrorV1>; 3],
    metadata_results: [Option<Result<(), CacheJournalPrefixErrorV1>>; 3],
    metadata_comparison: Option<Result<(), CacheJournalPrefixErrorV1>>,
    mount_after: SignerMountReadbackAttemptV1,
    mount_after_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_binding: Option<Result<(), CacheJournalPrefixErrorV1>>,
    post_clock: Option<rustix::time::Timespec>,
    post_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    completed_coordinates: Option<Result<CacheJournalDataV1, CacheJournalPrefixErrorV1>>,
    posts_entered: bool,
    native_retired: bool,
    first: Option<First>,
}

impl CacheCurrentJournalPrefixOriginalV1 {
    pub(super) fn new(role: Role) -> Self {
        Self {
            role,
            entered: false,
            expected: None,
            controller_uid: 0,
            controller_gid: 0,
            signer_uid: 0,
            mount_before: SignerMountReadbackAttemptV1::new(),
            mount_before_result: None,
            source_owner: None,
            physical: ReadOnlyAcquisitionOriginalsV1::new(),
            directory: None,
            files: None,
            identity: None,
            extent: None,
            demand: None,
            debit: None,
            replay: CanonicalReplayOriginalV1::new(),
            index: BTreeMap::new(),
            index_original: CanonicalReplayIndexOriginalsV1::new(),
            replay_entered: false,
            semantic: CacheJournalSemanticOriginalV1::new(),
            semantic_result: None,
            semantic_remainder: None,
            names_after: ProtectedFileNamesCurrentOriginalsV1::new(),
            metadata_after: std::array::from_fn(|_| FileIdentityOriginalsV1::new()),
            metadata_results: std::array::from_fn(|_| None),
            metadata_comparison: None,
            mount_after: SignerMountReadbackAttemptV1::new(),
            mount_after_result: None,
            mount_binding: None,
            post_clock: None,
            post_deadline: None,
            completed_coordinates: None,
            posts_entered: false,
            native_retired: false,
            first: None,
        }
    }

    pub(super) fn fixed_receiving_demand_v1(role: Role) -> Option<ResourceVector> {
        let path = role.signer_view_v1();
        let name = role.basename_v1();
        let ancestors = Path::new(path).components().count().checked_add(1)?;
        let semantic = CacheJournalSemanticOriginalV1::fixed_demand_v1().ok()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(usize::try_from(semantic.get(D::MemoryBytes)).ok()?)?
            .checked_add(ReadOnlyAcquisitionOriginalsV1::<CacheJournalPrefixErrorV1>::receiving_construction_bytes_v1()?)?
            .checked_add(SignerMountReadbackAttemptV1::receiving_memory_bound_v1()?.checked_mul(2)?)?
            .checked_add(FileIdentityOriginalsV1::<CacheJournalPrefixErrorV1>::receiving_footprint_v1()?.memory_bytes.checked_mul(3)?)?
            .checked_add(ancestors.checked_mul(std::mem::size_of::<std::fs::File>())?.checked_mul(3)?)?
            .checked_add(path.len().checked_add(name.len())?.checked_add(6)?.checked_mul(3)?)?;
        // Ancestors+actual directory, held journal/lock, two named post files,
        // and independently retained before/after mountinfo files.
        let files = ancestors.checked_add(6)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?),
        )
    }

    /// Enters only from the service's paid, Root-first matched purpose.
    pub(super) fn prepare_once(
        &mut self,
        expected: CacheJournalDataV1,
        controller_uid: u32,
        controller_gid: u32,
    ) -> Result<(), Closed> {
        if self.entered {
            return self.refuse(First::Entry);
        }
        self.entered = true;
        self.expected = Some(expected);
        self.controller_uid = controller_uid;
        self.controller_gid = controller_gid;
        self.signer_uid = rustix::process::geteuid().as_raw();
        self.mount_before_result = Some(observe_mount(
            &mut self.mount_before,
            self.role,
            expected,
            self.signer_uid,
            self.controller_uid,
            self.controller_gid,
        ));
        if !matches!(self.mount_before_result, Some(Ok(()))) {
            return self.refuse(First::MountBefore);
        }
        self.source_owner = Some(
            if self.role == Role::Bootstrap
                || self
                    .mount_before
                    .witness()
                    .is_some_and(|witness| witness.source_uid() == controller_uid)
            {
                Ok(())
            } else {
                Err(CacheJournalPrefixErrorV1::Changed)
            },
        );
        if !matches!(self.source_owner, Some(Ok(()))) {
            return self.refuse(First::MountBefore);
        }
        self.directory = Some(self.physical.prepare_directory_once(
            Path::new(self.role.signer_view_v1()),
            self.signer_uid,
            expected.names.directory(),
        ));
        if !matches!(self.directory, Some(Ok(()))) {
            return self.refuse(First::Directory);
        }
        // These are the original compiled limits; no request chooses them.
        self.files = Some(
            self.physical
                .prepare_files_once(self.role.basename_v1(), self.signer_uid),
        );
        if !matches!(self.files, Some(Ok(()))) {
            return self.refuse(First::Files);
        }
        self.identity = Some((|| {
            let (directory, file, lock) = self
                .physical
                .identities()
                .ok_or(CacheJournalPrefixErrorV1::Boundary)?;
            if directory.physical_pair() != expected.names.directory()
                || file.physical_pair() != expected.names.journal()
                || lock.physical_pair() != expected.names.lock()
                || file.byte_len() != expected.end
            {
                return Err(CacheJournalPrefixErrorV1::Changed);
            }
            Ok(())
        })());
        if !matches!(self.identity, Some(Ok(()))) {
            return self.refuse(First::Identity);
        }
        let (_, file, _) = self.physical.identities().ok_or(Closed)?;
        self.extent = Some(CanonicalReplayExtentDataV1::new(
            self.role.limits_v1(),
            file.byte_len(),
        ));
        if !matches!(self.extent, Some(Ok(_))) {
            return self.refuse(First::Extent);
        }
        Ok(())
    }

    fn prepare_replay_once(
        &mut self,
        common: &mut Common,
    ) -> Result<CanonicalReplayExtentDataV1, Closed> {
        if self.first.is_some() || self.replay_entered || self.posts_entered {
            return Err(Closed);
        }
        self.replay_entered = true;
        let extent = self
            .extent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(Closed)?;
        self.demand = Some((|| {
            extent
                .dominant_native_receiving_demand_v1()?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)?)?
                .checked_add(
                    aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(
                        extent.native_bytes(),
                    )
                    .map_err(CacheJournalPrefixErrorV1::SemanticGeometry)?,
                )
                .map_err(CacheJournalPrefixErrorV1::from)
        })());
        let demand = match self.demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first.get_or_insert(First::Demand);
                return Err(Closed);
            }
        };
        self.debit = Some(
            common
                .representation
                .as_mut()
                .ok_or(Closed)?
                .reserve(demand)
                .map_err(|_| Closed),
        );
        if !matches!(self.debit, Some(Ok(()))) {
            self.first.get_or_insert(First::Debit);
            return Err(Closed);
        }
        Ok(extent)
    }

    /// Drives the shared whole raw-COMMIT semantics under the same captured F.
    pub(super) fn replay_complete_once(&mut self, common: &mut Common) -> Result<(), Closed> {
        let extent = self.prepare_replay_once(common)?;
        let identity = self
            .physical
            .identities()
            .map(|(_, file, _)| file)
            .ok_or(Closed)?;
        let expected = self.expected.ok_or(Closed)?;
        let file = self.physical.file().ok_or(Closed)?;
        let cursor = match self.replay.begin_semantic_cursor_once(
            file,
            extent.limits(),
            extent.native_bytes(),
        ) {
            Ok(cursor) => cursor,
            Err(_) => {
                self.first.get_or_insert(First::Replay);
                return Err(Closed);
            }
        };
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut self.index,
            &mut self.index_original,
        );
        self.semantic_result =
            Some(
                self.semantic
                    .observe_once(&mut indexed, identity, extent.limits(), common),
            );
        if !matches!(self.semantic_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Semantic);
            return Err(Closed);
        }
        self.completed_coordinates = Some((|| {
            let prefix = indexed
                .completed_prefix()
                .ok_or(CacheJournalPrefixErrorV1::Boundary)?;
            let coordinates = prefix.coordinates();
            if coordinates.offset != extent.native_bytes()
                || coordinates.durable_end != expected.end
                || coordinates.expected_sequence != expected.next
                || coordinates.durable_next_sequence != expected.next
            {
                return Err(CacheJournalPrefixErrorV1::Changed);
            }
            let (directory, journal, lock) = self
                .physical
                .identities()
                .ok_or(CacheJournalPrefixErrorV1::Boundary)?;
            let names = aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::from_historical_fields(
                directory.physical_pair(), journal.physical_pair(), lock.physical_pair(),
            );
            Ok(CacheJournalDataV1 {
                names,
                next: coordinates.durable_next_sequence,
                end: coordinates.durable_end,
            })
        })());
        if !matches!(self.completed_coordinates, Some(Ok(_))) {
            self.first.get_or_insert(First::Semantic);
            return Err(Closed);
        }
        self.semantic_remainder = self.semantic.take_remainder_once();
        if self.semantic_remainder.is_none() {
            self.first.get_or_insert(First::Semantic);
            return Err(Closed);
        }
        Ok(())
    }

    /// Borrows the actual complete generic replay; Cache family checks follow.
    pub(super) fn replayed_state_v1(
        &self,
    ) -> Option<&BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>> {
        if self.first.is_some()
            || !matches!(self.completed_coordinates, Some(Ok(_)))
            || self.semantic_remainder.is_none()
        {
            return None;
        }
        self.replay.state()
    }

    pub(super) fn completed_coordinates_v1(&self) -> Option<CacheJournalDataV1> {
        self.replayed_state_v1()?;
        self.completed_coordinates.as_ref()?.as_ref().ok().copied()
    }

    /// Compares the same complete native namespace history without a claim.
    pub(super) fn require_single_namespace_data_v1(
        &self,
        namespace: aos_sandbox_model::RecordNamespace,
    ) -> Result<(), aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1> {
        self.raw_view_data_v1().ok_or(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::ProtectedBoundary,
        )?.require_single_namespace_data_v1(namespace)
    }

    /// Compares only the fixed HOLD group's existing native namespace DATA.
    pub(super) fn require_cache_hold_namespaces_data_v1(
        &self,
    ) -> Result<(), aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1> {
        use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as E;
        if self.role != Role::Hold { return Err(E::ProtectedBoundary); }
        self.raw_view_data_v1().ok_or(E::ProtectedBoundary)?
            .require_cache_hold_namespaces_data_v1()
    }

    /// Borrows the same completed native recovery counts after local settlement.
    pub(super) fn recovery_report_v1(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::RecoveryReport> {
        self.replayed_state_v1()?;
        self.replay.report().map(|(_, report)| report)
    }

    // Only complete same-native replay supplies this borrowed DATA view.
    pub(super) fn raw_view_data_v1(&self)
        -> Option<aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1<'_>> {
        Some(aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1 {
            state: self.replayed_state_v1()?,
            namespaces: self.replay.committed_namespaces()?,
            report: self.replay.report()?.1,
        })
    }

    /// Runs reached name, complete metadata and mount posts without body input.
    pub(super) fn finish_native_once(&mut self, cutoff: u64) -> Result<(), Closed> {
        if !self.entered || self.posts_entered {
            return self.refuse(First::Entry);
        }
        self.posts_entered = true;
        if self.replay_entered
            && (self.replay.failure().is_some() || self.index_original.failure().is_some())
        {
            self.first.get_or_insert(First::Replay);
        }
        if let (Some(directory), Some(file), Some(lock)) = (
            self.physical.directory(),
            self.physical.file(),
            self.physical.lock(),
        ) {
            self.names_after.capture_once(
                directory,
                self.role.basename_v1(),
                self.signer_uid,
                lock,
                file,
            );
            if !self.names_after.is_complete() {
                self.first.get_or_insert(First::Names);
            }
            for (index, actual) in [directory, file, lock].into_iter().enumerate() {
                self.metadata_results[index] = Some(FileIdentity::of_retaining_v1(
                    actual,
                    &mut self.metadata_after[index],
                ));
                if !matches!(self.metadata_results[index], Some(Ok(()))) {
                    self.first.get_or_insert(First::Metadata);
                }
            }
            self.metadata_comparison = Some((|| {
                let (directory, file, lock) = self
                    .physical
                    .identities()
                    .ok_or(CacheJournalPrefixErrorV1::Boundary)?;
                for (original, actual) in [directory, file, lock]
                    .into_iter()
                    .zip(&self.metadata_after)
                {
                    if actual.completed_identity() != Some(&original) {
                        return Err(CacheJournalPrefixErrorV1::Changed);
                    }
                }
                Ok(())
            })());
            if !matches!(self.metadata_comparison, Some(Ok(()))) {
                self.first.get_or_insert(First::Metadata);
            }
        }
        if let Some(expected) = self.expected {
            self.mount_after_result = Some(observe_mount(
                &mut self.mount_after,
                self.role,
                expected,
                self.signer_uid,
                self.controller_uid,
                self.controller_gid,
            ));
            if !matches!(self.mount_after_result, Some(Ok(()))) {
                self.first.get_or_insert(First::MountAfter);
            }
            self.mount_binding = Some(if self.role == Role::Bootstrap {
                if self.mount_before.prepared_witness().is_some()
                    && self.mount_before.prepared_witness() == self.mount_after.prepared_witness()
                {
                    Ok(())
                } else {
                    Err(CacheJournalPrefixErrorV1::Changed)
                }
            } else if self.mount_before.witness().is_some()
                && self.mount_before.witness() == self.mount_after.witness()
            {
                Ok(())
            } else {
                Err(CacheJournalPrefixErrorV1::Changed)
            });
            if !matches!(self.mount_binding, Some(Ok(()))) {
                self.first.get_or_insert(First::MountBinding);
            }
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.post_clock = Some(now);
        self.post_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.post_deadline, Some(Ok(_))) {
            self.first.get_or_insert(First::Deadline);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    /// Disposes only the completed local native leaf, retaining parsed DATA.
    /// Full cross-journal family checks and signer admission remain outstanding.
    pub(super) fn retire_completed_native_leaf_once(&mut self) -> Result<(), Closed> {
        if self.native_retired
            || self.first.is_some()
            || !self.posts_entered
            || !self.names_after.is_complete()
            || !matches!(self.metadata_comparison, Some(Ok(())))
            || !matches!(self.mount_binding, Some(Ok(())))
            || !matches!(self.post_deadline, Some(Ok(_)))
            || !self.index_original.is_complete()
            || self.replay.report().is_none()
            || !matches!(self.completed_coordinates, Some(Ok(_)))
        {
            return Err(Closed);
        }
        drop(std::mem::replace(
            &mut self.physical,
            ReadOnlyAcquisitionOriginalsV1::new(),
        ));
        drop(std::mem::replace(
            &mut self.names_after,
            ProtectedFileNamesCurrentOriginalsV1::new(),
        ));
        drop(std::mem::replace(
            &mut self.mount_before,
            SignerMountReadbackAttemptV1::new(),
        ));
        drop(std::mem::replace(
            &mut self.mount_after,
            SignerMountReadbackAttemptV1::new(),
        ));
        self.native_retired = true;
        Ok(())
    }

    pub(super) fn native_leaf_is_retired_v1(&self) -> bool {
        self.native_retired && self.first.is_none()
    }

    pub(super) fn owes_native_post_v1(&self) -> bool {
        self.entered && !self.posts_entered
    }

    fn refuse(&mut self, first: First) -> Result<(), Closed> {
        self.first.get_or_insert(first);
        Err(Closed)
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            First::Entry => Some(&Closed),
            First::Replay => self
                .replay
                .failure()
                .or_else(|| self.index_original.failure()),
            First::Semantic => {
                if self.semantic.native_failure_is_selected_v1() {
                    self.replay
                        .failure()
                        .or_else(|| self.index_original.failure())
                        .or_else(|| self.semantic.failure(common))
                } else {
                    self.semantic
                        .failure(common)
                        .or_else(|| cause(&self.completed_coordinates))
                        .or_else(|| cause(&self.semantic_result))
                }
            }
            First::MountBefore => self
                .mount_before
                .failure()
                .or_else(|| cause(&self.mount_before_result))
                .or_else(|| cause(&self.source_owner)),
            First::Directory | First::Files => self
                .physical
                .failure()
                .or_else(|| cause(&self.directory))
                .or_else(|| cause(&self.files)),
            First::Identity => cause(&self.identity),
            First::Extent => cause(&self.extent),
            First::Demand => cause(&self.demand),
            First::Debit => common
                .representation
                .as_ref()
                .and_then(|ledger| ledger.failure())
                .map(|cause| cause as _)
                .or_else(|| cause(&self.debit)),
            First::Names => self.names_after.failure().map(|cause| cause as _),
            First::Metadata => self
                .metadata_after
                .iter()
                .find_map(FileIdentityOriginalsV1::failure)
                .or_else(|| cause(&self.metadata_comparison)),
            First::MountAfter => self
                .mount_after
                .failure()
                .or_else(|| cause(&self.mount_after_result)),
            First::MountBinding => cause(&self.mount_binding),
            First::Deadline => cause(&self.post_deadline),
        }
    }
}

fn observe_mount(
    original: &mut SignerMountReadbackAttemptV1,
    role: Role,
    expected: CacheJournalDataV1,
    signer_uid: u32,
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), SignerMountReadbackClosedV1> {
    if role == Role::Bootstrap {
        original.observe_prepared_cache_bootstrap_once(
            signer_uid,
            expected.names.directory(),
            controller_uid,
            controller_gid,
        )
    } else {
        original.observe_once(
            role.signer_view_v1(),
            role.writer_directory_v1(),
            signer_uid,
            "/run/aos",
            &[
                "/var",
                "/var/lib",
                "/var/lib/aos",
                "/var/lib/aos/sandbox",
                "/run",
                "/run/aos",
            ],
        )
    }
}
