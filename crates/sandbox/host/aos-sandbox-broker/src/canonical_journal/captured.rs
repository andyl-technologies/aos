//! Retains captured append DATA and its independently owed native observations.
//!
//! This common mechanical owner issues no receiving loan, fixed-role admission
//! or semantic completion. Its caller keeps the actual writer and pays before
//! construction. Unfinished append stages and failed observations remain on
//! their original sinks after a returned diagnostic is dropped.

use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use aos_sandbox_model::{AccountingError, ResourceDimension, ResourceVector};
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::protected_storage::ProtectedFailure;

use super::CanonicalJournalMechanicalErrorV1;
use super::coordinator::CanonicalWriterReadViewV1;
use super::coordinator::retained_data::RetainedAppendDataCustodyV1;
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

/// Selects the existing caller's mechanical observation order.
#[derive(Clone, Copy)]
pub enum CapturedWriterGuardRecipeV1<'path> {
    /// Observes the same held data and lock names.
    Names,
    /// Reopens the rooted ancestry and compares the same directory original.
    Directory(&'path Path, u32),
}

/// Holds one append sink and the same writer's sticky native guard.
///
/// The names and UID are DATA chosen by the actual role. This type neither
/// opens a writer nor grants permission to append to one.
pub struct CapturedAppendDataOwnerV1<E> {
    custody: RetainedAppendDataCustodyV1,
    directory: &'static str,
    name: &'static str,
    uid: u32,
    guards: Arc<CapturedNativeGuardV1<E>>,
}

impl<E> CapturedAppendDataOwnerV1<E>
where
    E: ProtectedFailure
        + From<FrameError>
        + From<CanonicalJournalMechanicalErrorV1>
        + Error
        + 'static,
{
    /// Constructs inert retained storage after the caller's actual admission.
    #[must_use]
    pub fn new(directory: &'static str, name: &'static str, uid: u32) -> Self {
        Self {
            custody: RetainedAppendDataCustodyV1::new(),
            directory,
            name,
            uid,
            guards: Arc::new(CapturedNativeGuardV1::new()),
        }
    }

    /// Prices this owner and its actual two Arc allocations before construction.
    #[must_use]
    pub fn construction_demand_v1() -> Option<ResourceVector> {
        let bytes = RetainedAppendDataCustodyV1::construction_bytes_v1()?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CapturedNativeGuardV1<E>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<usize>().checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Prices the same failed guard, append-before and owed-after observations.
    ///
    /// The caller adds its actual upper interval/constructor supplier separately.
    ///
    /// # Errors
    /// Preserves native shape and checked representation arithmetic failures.
    pub fn append_demand_for_fixed_v1(
        directory: &'static str,
        name: &'static str,
        encoded: u64,
        upper_interval_bytes: usize,
    ) -> Result<ResourceVector, E>
    where
        E: From<AccountingError>,
    {
        let one = WriterCurrentnessOriginalsV1::<E>::fixed_demand_v1(Path::new(directory), name)?;
        let bytes = RetainedAppendDataCustodyV1::append_bytes_v1(encoded)
            .and_then(|bytes| bytes.checked_add(u64::try_from(upper_interval_bytes).ok()?))
            .ok_or_else(|| E::from(FrameError::LimitExceeded("captured append representation")))?;
        one.checked_add(one)
            .and_then(|demand| demand.checked_add(one))
            .and_then(|demand| {
                demand.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
            })
            .map_err(E::from)
    }

    /// Prices this same owner's original fixed recipe before append growth.
    ///
    /// # Errors
    /// Preserves the actual native-shape or checked-accounting failure.
    pub fn append_demand_v1(
        &self,
        encoded: u64,
        upper_interval_bytes: usize,
    ) -> Result<ResourceVector, E>
    where
        E: From<AccountingError>,
    {
        Self::append_demand_for_fixed_v1(self.directory, self.name, encoded, upper_interval_bytes)
    }

    /// Borrows the actual retained DATA sink without a native or authority port.
    #[must_use]
    pub fn data_custody_v1(&self) -> &RetainedAppendDataCustodyV1 {
        &self.custody
    }

    /// Borrows the original parked native cause before any later DATA failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.guards.failure().or_else(|| self.custody.failure())
    }

    /// Borrows the actual native guard cause for the caller's chronological join.
    #[must_use]
    pub fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.guards.failure()
    }

    /// Reports whether failed actual work permanently closed this owner.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.guards.is_closed() || self.custody.is_closed()
    }

    /// Compares the caller's fixed identity to this owner's original DATA.
    #[must_use]
    pub fn matches_identity_v1(&self, directory: &str, name: &str, uid: u32) -> bool {
        self.directory == directory && self.name == name && self.uid == uid
    }

    /// Observes the original writer without replacing its native fields.
    ///
    /// # Errors
    /// Preserves the first native failure; overlap and reentry cannot reset it.
    pub fn observe_guard_v1<P>(
        &self,
        view: CanonicalWriterReadViewV1<'_, P>,
        recipe: CapturedWriterGuardRecipeV1<'_>,
    ) -> Result<(), E> {
        self.guards.observe(view, recipe, &self.custody)
    }

    /// Prearms the independently owed pair before the actual append body enters.
    #[must_use]
    pub fn arm(&self) -> CapturedAppendPostsV1<E> {
        CapturedAppendPostsV1 {
            directory: self.directory,
            uid: self.uid,
            before: WriterCurrentnessOriginalsV1::new(),
            after: WriterCurrentnessOriginalsV1::new(),
            guard: Arc::clone(&self.guards),
            guard_selected: false,
            before_result: None,
            after_result: None,
        }
    }
}

/// Holds the actual captured before and always-owed after results.
pub struct CapturedAppendPostsV1<E> {
    directory: &'static str,
    uid: u32,
    before: WriterCurrentnessOriginalsV1<E>,
    after: WriterCurrentnessOriginalsV1<E>,
    guard: Arc<CapturedNativeGuardV1<E>>,
    guard_selected: bool,
    before_result: Option<Result<(), E>>,
    after_result: Option<Result<(), E>>,
}

impl<E> CapturedAppendPostsV1<E>
where
    E: ProtectedFailure
        + From<FrameError>
        + From<CanonicalJournalMechanicalErrorV1>
        + Error
        + 'static,
{
    fn observe<P>(
        view: CanonicalWriterReadViewV1<'_, P>,
        directory: &str,
        uid: u32,
        original: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E> {
        original.begin(false)?;
        let result = (|| {
            view.observe_directory_binding_into(Path::new(directory), uid, original)?;
            view.observe_names_into(original)
        })();
        original.finish(result)
    }

    /// Observes the same append-before once at its existing frontier.
    ///
    /// # Errors
    /// Retains the actual traversal/name result and rejects repeated entry.
    pub fn before_once<P>(&mut self, view: CanonicalWriterReadViewV1<'_, P>) -> Result<(), E> {
        if self.before_result.is_some() {
            return Err(E::BOUNDARY);
        }
        self.before_result = Some(Self::observe(
            view,
            self.directory,
            self.uid,
            &mut self.before,
        ));
        if matches!(self.before_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Observes the same owed after without a healthy-entry or fresh-debit gate.
    ///
    /// # Errors
    /// Retains the actual traversal/name result and rejects repeated entry.
    pub fn after_once<P>(&mut self, view: CanonicalWriterReadViewV1<'_, P>) -> Result<(), E> {
        if self.after_result.is_some() {
            return Err(E::BOUNDARY);
        }
        self.after_result = Some(Self::observe(
            view,
            self.directory,
            self.uid,
            &mut self.after,
        ));
        if matches!(self.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Latches whether a guard failure already existed at the body's return.
    pub fn mark_primary_return_v1(&mut self) {
        self.guard_selected = self.guard.failure().is_some();
    }

    /// Borrows only causes that preceded or belonged to the primary body.
    #[must_use]
    pub fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before
            .failure()
            .or_else(|| {
                self.before_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                if self.guard_selected {
                    self.guard.failure()
                } else {
                    None
                }
            })
    }

    /// Borrows the chronological pair cause without replacing the primary.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure()
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.after_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    /// Requires both actual native leaves before upper positive disposition.
    ///
    /// # Errors
    /// Refuses vacant or failed leaves; no error or original is discarded.
    pub fn require_complete_v1(&self) -> Result<(), E> {
        if matches!(self.before_result, Some(Ok(()))) && matches!(self.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Retires positive observation scratch after the actual whole append join.
    ///
    /// # Errors
    /// Refuses incomplete leaves; the caller separately proves its semantic,
    /// native publication and any role-specific completion before calling.
    pub fn dispose(&mut self) -> Result<(), E> {
        self.require_complete_v1()?;
        self.before.settle_positive_once_v1();
        self.after.settle_positive_once_v1();
        Ok(())
    }
}

struct CapturedNativeGuardV1<E> {
    failed: OnceLock<WriterCurrentnessOriginalsV1<E>>,
    active: AtomicBool,
    refused: AtomicBool,
}

impl<E> CapturedNativeGuardV1<E>
where
    E: ProtectedFailure
        + From<FrameError>
        + From<CanonicalJournalMechanicalErrorV1>
        + Error
        + 'static,
{
    fn new() -> Self {
        Self {
            failed: OnceLock::new(),
            active: AtomicBool::new(false),
            refused: AtomicBool::new(false),
        }
    }

    fn is_closed(&self) -> bool {
        self.failed.get().is_some() || self.refused.load(Ordering::SeqCst)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failed.get()?.failure()
    }

    fn observe<P>(
        &self,
        view: CanonicalWriterReadViewV1<'_, P>,
        recipe: CapturedWriterGuardRecipeV1<'_>,
        custody: &RetainedAppendDataCustodyV1,
    ) -> Result<(), E> {
        if self.is_closed()
            || self
                .active
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            self.refused.store(true, Ordering::SeqCst);
            return Err(E::BOUNDARY);
        }

        struct Active<'guard>(&'guard AtomicBool);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _active = Active(&self.active);
        let mut original = WriterCurrentnessOriginalsV1::new();
        original.begin(matches!(recipe, CapturedWriterGuardRecipeV1::Names))?;
        let observed = (|| {
            match recipe {
                CapturedWriterGuardRecipeV1::Names => view.observe_names_into(&mut original)?,
                CapturedWriterGuardRecipeV1::Directory(path, uid) => {
                    view.observe_directory_binding_into(path, uid, &mut original)?;
                    if view.is_poisoned() || custody.is_closed() || self.is_closed() {
                        return Err(E::from(CanonicalJournalMechanicalErrorV1::Poisoned));
                    }
                }
            }
            Ok(())
        })();
        let result = original.finish(observed);
        if result.is_err() {
            if self.failed.set(original).is_err() {
                std::process::abort();
            }
        } else {
            original.settle_positive_once_v1();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::canonical_journal::{CanonicalNativeJournalV1, JournalLimits};
    use aos_sandbox_journal::owner::NativeJournalState;
    use aos_sandbox_journal::protected_storage::{ProtectedJournalLocation, open_protected_file};
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::MetadataExt as _;

    type Cause = CanonicalJournalMechanicalErrorV1;

    struct TestWriter {
        native: CanonicalNativeJournalV1,
        index:
            BTreeMap<Vec<u8>, aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1>,
        location: ProtectedJournalLocation<()>,
    }

    fn native_fixture() -> (tempfile::TempDir, TestWriter) {
        // Like the old Domain test-only UID opener, this fixture validates the
        // actual final directory and names, not /tmp's production ancestry.
        // It supplies no fixed role, financial loan or accepted Journal.
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let held_directory = std::fs::File::open(directory.path()).unwrap();
        let lock = open_protected_file::<Cause>(
            &held_directory,
            "session.journal.lock",
            uid,
            true,
            false,
            false,
        )
        .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let file = open_protected_file::<Cause>(
            &held_directory,
            "session.journal",
            uid,
            true,
            false,
            false,
        )
        .unwrap();
        let native = CanonicalNativeJournalV1::from_owned_parts(
            "session.journal".into(),
            file,
            lock,
            JournalLimits::default(),
            NativeJournalState::from_owned_parts(
                1,
                0,
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeMap::new(),
                0,
            ),
        );
        let writer = TestWriter {
            native,
            index: BTreeMap::new(),
            location: ProtectedJournalLocation::from_original_parts((
                held_directory,
                "session.journal".to_owned(),
                uid,
                (),
            )),
        };
        (directory, writer)
    }

    fn view(writer: &TestWriter) -> CanonicalWriterReadViewV1<'_, ()> {
        CanonicalWriterReadViewV1::from_parts(
            writer.native.native(),
            &writer.index,
            Some(&writer.location),
        )
    }

    #[test]
    fn failed_names_keep_actual_native_original_and_close_guard_reentry() {
        let (directory, writer) = native_fixture();
        let owner = CapturedAppendDataOwnerV1::<Cause>::new(
            "/var/lib/aos/sandboxd/broker-session/host",
            "session.journal",
            rustix::process::geteuid().as_raw(),
        );
        owner
            .observe_guard_v1(view(&writer), CapturedWriterGuardRecipeV1::Names)
            .unwrap();
        assert!(!owner.is_closed());
        assert!(owner.guards.failed.get().is_none());

        std::fs::rename(
            directory.path().join("session.journal"),
            directory.path().join("old.journal"),
        )
        .unwrap();
        assert!(
            owner
                .observe_guard_v1(view(&writer), CapturedWriterGuardRecipeV1::Names)
                .is_err()
        );
        let first = owner.failure().unwrap() as *const dyn Error as *const ();
        assert!(owner.guards.failed.get().unwrap().retained_file_count() > 0);
        assert!(owner.is_closed());

        std::fs::rename(
            directory.path().join("old.journal"),
            directory.path().join("session.journal"),
        )
        .unwrap();
        assert!(
            owner
                .observe_guard_v1(view(&writer), CapturedWriterGuardRecipeV1::Names)
                .is_err()
        );
        assert_eq!(
            owner.failure().unwrap() as *const dyn Error as *const (),
            first
        );
    }

    #[test]
    fn active_guard_refuses_overlap_without_native_entry_or_reset() {
        let (directory, writer) = native_fixture();
        let owner = CapturedAppendDataOwnerV1::<Cause>::new(
            "/var/lib/aos/sandboxd/broker-session/storage",
            "session.journal",
            0,
        );
        owner.guards.active.store(true, Ordering::SeqCst);

        assert!(
            owner
                .observe_guard_v1(view(&writer), CapturedWriterGuardRecipeV1::Names)
                .is_err()
        );
        assert!(owner.guards.failed.get().is_none());
        assert!(owner.is_closed());
        owner.guards.active.store(false, Ordering::SeqCst);
        assert!(
            owner
                .observe_guard_v1(view(&writer), CapturedWriterGuardRecipeV1::Names)
                .is_err()
        );
        assert!(owner.guards.failed.get().is_none());
        assert_eq!(
            std::fs::metadata(directory.path().join("session.journal"))
                .unwrap()
                .len(),
            0
        );
    }
}
