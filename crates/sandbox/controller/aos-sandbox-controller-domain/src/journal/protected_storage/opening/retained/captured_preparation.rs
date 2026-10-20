//! Once-only fixed native preparation before captured semantic replay.
//!
//! The same directory, lock, journal and initial metadata stay in the existing
//! original reservoir. Preparation is custody only. Its enclosing selected
//! receiver must pay fixed traversal first, then admit variable replay from
//! this held prefix before calling the argument-free continuation.

use super::*;

pub(super) struct CapturedWriterPreparationV1 {
    binding: Option<(String, JournalLimits, u32, bool)>,
    native: Option<Result<(), JournalError>>,
    replay_entered: bool,
    closed: bool,
}

impl CapturedWriterPreparationV1 {
    pub(super) const fn new() -> Self {
        Self {
            binding: None,
            native: None,
            replay_entered: false,
            closed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.closed.then_some(
                &READ_ONLY_OPEN_CLOSED as &(dyn std::error::Error + 'static),
            ))
    }
}

impl ProtectedWriterOpenOriginalsV1 {
    /// Holds the existing fixed native recipe and its first metadata only.
    ///
    /// The outer role has already paid this native stage. This method neither
    /// validates a receiving permit nor consumes variable journal records.
    pub(crate) fn prepare_captured_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
    ) {
        self.prepare_captured_for_uid_once(path, name, limits, 0, true);
    }

    /// Prepares one exact-owner native recipe, preserving existing-only mode.
    ///
    /// This crate-private mechanics entry accepts no grant or decoded payer.
    /// The genuine role chooses its fixed names/uid and prepays native custody.
    pub(crate) fn prepare_captured_for_uid_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) {
        if self.attempted || self.captured.native.is_some() {
            self.captured.closed = true;
            return;
        }
        self.attempted = true;
        self.captured.binding = Some((name.to_owned(), limits, uid, allow_create));
        self.captured.native = Some(self.prepare_native_inner(
            path, name, limits, uid, allow_create,
        ));
    }

    /// Borrows actual captured geometry without reconstructing its originals.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepared_extent(
        &self,
    ) -> Option<&crate::journal::ProtectedJournalPreopenReplayExtentV1> {
        if self.captured.closed
            || self.captured.replay_entered
            || !matches!(self.captured.native, Some(Ok(())))
        {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok()
    }

    /// Enters the same prepared replay once with no replacement path or limit.
    ///
    /// The enclosing role must have admitted this exact held extent. A failed
    /// native stage, repeated continuation or earlier complete open cannot be
    /// retried. Later independent name posts remain the outer owner's duty.
    pub(crate) fn replay_prepared_once(&mut self) {
        if self.captured.closed
            || self.captured.replay_entered
            || !matches!(self.captured.native, Some(Ok(())))
            || self.returned.is_some()
        {
            self.captured.closed = true;
            return;
        }
        self.captured.replay_entered = true;
        let Some((_name, limits, _uid, allow_create)) = self.captured.binding.as_ref() else {
            self.captured.closed = true;
            return;
        };
        let (limits, allow_create) = (*limits, *allow_create);
        self.returned = Some(self.finish_open_inner(limits, allow_create));
    }

    pub(crate) fn captured_opened_ready(&self) -> bool {
        !self.captured.closed
            && self.captured.replay_entered
            && self.failure().is_none()
            && matches!(self.returned, Some(Ok(_)))
            && self.journal.is_some()
    }

    // Only a wrapper that retained its complete independent name/currentness
    // bookends moves this positive native tuple. No failure is extracted.
    pub(crate) fn take_captured_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
        if !self.captured_opened_ready() {
            return None;
        }
        let report = *self.returned.as_ref()?.as_ref().ok()?;
        // The actual Journal already owns the moved native/index bundle. All
        // enclosing role bookends precede this call; only here may its original
        // completed traversal retire. Refusal leaves that whole Journal resident.
        self.native.retire_completed_traversal_once_v1().ok()?;
        let journal = self.journal.take()?;
        Some((journal, report))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn positive_captured_handoff_retires_only_traversal_ancestors() {
        // Rooted preparation rejects writable ancestors such as /tmp. The
        // actual Cargo test executable lives in its private writable target
        // tree, including hermetic builds, so keep this real native fixture
        // beneath that ancestry without changing production traversal rules.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("captured-writer-positive-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let limits = JournalLimits::default();
        let mut original = ProtectedWriterOpenOriginalsV1::new();
        original.prepare_captured_for_uid_once(directory.path(), "journal", limits, uid, true);
        assert!(original.failure().is_none(), "{:?}", original.failure());
        assert!(original.native.retained_ancestors_for_fixture_v1().0 > 0);
        original.replay_prepared_once();
        assert!(original.captured_opened_ready());
        let journal = original.journal_mut().unwrap();
        journal.validate_held_owned_at_for_uid(directory.path(), "journal", uid).unwrap();
        journal.require_protected_location(directory.path(), "journal", uid, limits).unwrap();

        let (mut journal, _report) = original.take_captured_opened().unwrap();

        assert!(original.native.retained_ancestors_for_fixture_v1().0 == 0);
        assert!(original.failure().is_none());
        journal.validate_held_owned_at_for_uid(directory.path(), "journal", uid).unwrap();
        journal.require_protected_location(directory.path(), "journal", uid, limits).unwrap();
        assert!(original.take_captured_opened().is_none());
    }

    #[test]
    fn changed_captured_prefix_refuses_before_tail_repair_or_handoff() {
        use std::io::Write as _;

        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("captured-writer-changed-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut original = ProtectedWriterOpenOriginalsV1::new();
        original.prepare_captured_for_uid_once(
            directory.path(), "journal", JournalLimits::default(), uid, true,
        );
        assert!(original.failure().is_none(), "{:?}", original.failure());
        let path = directory.path().join("journal");
        let changed = b"bytes beyond the actual captured prefix";
        let mut expected = std::fs::read(&path).unwrap();
        expected.extend_from_slice(changed);
        let mut external = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        external.write_all(changed).unwrap();
        external.sync_all().unwrap();

        original.replay_prepared_once();

        assert!(original.failure().is_some());
        assert!(!original.captured_opened_ready());
        assert!(original.take_captured_opened().is_none());
        assert!(original.native.retained_ancestors_for_fixture_v1().0 > 0);
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    #[test]
    fn refused_captured_handoff_keeps_its_actual_ancestor_prefix() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut original = ProtectedWriterOpenOriginalsV1::new();
        original.prepare_captured_for_uid_once(
            directory.path(), "missing", JournalLimits::default(), uid, false,
        );
        assert!(original.failure().is_some());
        let ancestors = original.native.retained_ancestors_for_fixture_v1().0;
        assert!(ancestors > 0);
        let first = std::ptr::from_ref(original.failure().unwrap());

        assert!(original.take_captured_opened().is_none());

        assert_eq!(original.native.retained_ancestors_for_fixture_v1().0, ancestors);
        assert!(original.native.retained_ancestors_for_fixture_v1().1);
        assert!(std::ptr::eq(std::ptr::from_ref(original.failure().unwrap()), first));
    }
}
