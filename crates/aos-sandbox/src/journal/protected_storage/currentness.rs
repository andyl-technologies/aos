//! Applies Domain writer gates around shared retained native currentness.

use std::fs::File;
use std::path::Path;
use super::{Journal, JournalError, JournalLimits};

pub type ProtectedJournalCurrentnessOriginalsV1 =
    aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1<JournalError>;

impl Journal {
    /// Measures the names-only recipe of this actual held protected writer.
    pub(crate) fn held_names_receiving_demand_v2(&self)
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        let location = self.native.protected_view().ok_or(JournalError::ProtectedBoundary)?;
        ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(location.name())
    }

    /// Retains the ordinary names-first physical witness in its paid caller.
    ///
    /// This observation runs on the actual held descriptions after earlier
    /// append poison too; it grants no health, currentness or append authority.
    ///
    /// # Errors
    /// Keeps reached name files, metadata and the exact first native failure.
    pub(crate) fn observe_held_physical_names_retaining_v1(&self,
        names: &mut ProtectedJournalCurrentnessOriginalsV1,
        witness: &mut aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    ) -> Result<super::ProtectedJournalNamesV1, JournalError> {
        self.observe_held_names_post_retaining_v1(names)?;
        self.native.read_view().writer_witness_retaining_v1(witness)?;
        let observed = witness.completed_witness().ok_or(JournalError::ProtectedBoundary)?;
        Ok(super::names_from_identities(observed.directory(), observed.file(), observed.lock()))
    }

    /// Observes metadata from this writer's actual held protected directory.
    ///
    /// This is nonauthorizing native DATA, including on an unhealthy writer.
    /// Its caller pays and retains the whole Result, joins its actual other
    /// owner, and independently preserves every ordinary health/name guard.
    /// No pathname is resolved and no descriptor or authority is constructed.
    ///
    /// # Errors
    /// Returns a missing-protected-owner refusal or the original metadata IO
    /// error from the same retained directory descriptor.
    pub fn observe_held_protected_directory_metadata_v1(&self)
        -> Result<aos_sandbox_journal::protected_storage::OriginalFileMetadataV1, JournalError>
    {
        let location = self.native.protected_view().ok_or(JournalError::ProtectedBoundary)?;
        location.directory_metadata::<JournalError>()
    }


    // Same names-first schedule as the ordinary witness post, with its fresh
    // Lock/Journal descriptions retained through the caller's entire interval.
    pub(crate) fn validate_protected_writer_name_witness_retaining_v1(
        &self, witness: &super::ProtectedWriterNameWitness,
        originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        originals.begin(true)?;
        let result = (|| {
            let location = self.native.protected_view().ok_or(JournalError::ProtectedBoundary)?;
            self.require_protected_names_with_originals(Some(originals))?;
            location.require_writer_witness::<JournalError>(witness)
        })();
        originals.finish(result)
    }

    /// Validates the actual held writer's names with retained native outcomes.
    ///
    /// This shares the ordinary protected-authority then Lock/Journal recipe;
    /// it performs no rooted traversal and grants no funding or authority.
    ///
    /// # Errors
    /// Rejects reentry, poisoned/unprotected writers or native/name failures.
    /// The detailed first cause stays in `originals` through the caller's posts.
    pub fn validate_held_protected_names_retaining(
        &self, originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        originals.begin(true)?;
        let result = (|| {
            self.ensure_protected_authority()?;
            self.require_protected_names_with_originals(Some(originals))
        })();
        originals.finish(result)
    }

    /// Observes the same held names into an already prepaid owed-post owner.
    ///
    /// This is nonauthorizing DATA. The caller separately retains ordinary
    /// health/admission errors and the whole enclosing append or domain result.
    /// Poison still rejects admission and commit; this observation cannot clear
    /// either error or establish positive completion. Its original destination
    /// must be paid before the enclosing interval can incur the post obligation.
    ///
    /// # Errors
    /// Returns reentry, absent protected custody or the original physical names
    /// failure. Reached native files/results remain in `originals` on failure.
    pub fn observe_held_names_post_retaining_v1(
        &self, originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        originals.begin(true)?;
        let result = self.require_protected_names_with_originals(Some(originals));
        originals.finish(result)
    }

    pub(crate) fn is_fixed_storage_state_post_v1(&self) -> bool {
        self.native.protected_view().is_some_and(|location|
            location.name() == "storage-state.journal" && location.expected_uid() == 0)
            && self.native.path() == Path::new("/var/lib/aos/sandbox-storage/storage-state.journal")
    }

    /// Validates this exact writer while retaining every reached fresh prefix.
    ///
    /// This shares the ordinary fixed-location then Lock/Journal check order.
    /// It grants no authority or funding; the caller retains its genuine loan.
    ///
    /// # Errors
    /// Refuses reentry, unhealthy or changed writers and native/path failures.
    /// The original detailed failure remains in `originals`.
    pub fn validate_held_owned_at_for_uid_retaining(
        &self, directory: impl AsRef<Path>, name: &str, expected_uid: u32,
        originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        originals.begin(false)?;
        let result = (|| {
            self.require_protected_location_with_originals(directory.as_ref(), name,
                expected_uid, self.native.limits(), Some(originals))?;
            self.require_protected_names_with_originals(Some(originals))
        })();
        originals.finish(result)
    }

    /// Checks this exact writer against a shared same-interval protected ancestry.
    ///
    /// Path, UID, limits, held directory identity, health and both physical names
    /// retain the ordinary order. Only duplicate ancestry resolution is shared.
    ///
    /// # Errors
    /// Retains each writer's binding/name failure; the caller also retains the
    /// original shared ancestry and its first native error through all posts.
    pub fn validate_held_owned_at_with_directory_retaining_v6(&self, directory: &Path,
        name: &str, expected_uid: u32, originals: &mut ProtectedJournalCurrentnessOriginalsV1,
        shared: &ProtectedJournalCurrentnessOriginalsV1) -> Result<(), JournalError> {
        originals.begin(false)?;
        let observed = (|| {
            self.require_protected_location_engine_v6(directory, name, expected_uid,
                self.native.limits(), Some(originals), Some(shared))?;
            self.require_protected_names_with_originals(Some(originals))
        })();
        originals.finish(observed)
    }

    pub(crate) fn require_protected_location_retaining(
        &self, directory: &Path, name: &str, uid: u32, limits: JournalLimits,
        originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        originals.begin(false)?;
        let result = self.require_protected_location_with_originals(directory, name, uid,
            limits, Some(originals));
        originals.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_journal::protected_storage::ProtectedJournalLocation;

    use super::*;

    #[test]
    fn actual_session_position_supplier_selects_its_real_receipt_boundary() {
        use std::io::Write as _;
        use aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1;
        use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
        use aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3;
        use aos_sandbox_protocol::authenticated_session::stored_history::canonical_protocol_key_v1;
        use aos_sandbox_protocol::domain_ledger::{protected_names::{
            ProtectedJournalNamesV1, SessionCompletionPositionDataV4},
            transaction::{JournalRecord, JournalTransaction, encode_transaction}};
        use crate::RecordNamespace;

        // Use the existing protected-writer fixture's real executable ancestry.
        // Opaque row bodies exercise only native receipt selection; they mint
        // no authenticated Session or successful historical method original.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new().prefix("session-boundary-contract-")
            .tempdir_in(executable.parent().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("session.journal");
        let mut file = File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
        let mut next = 1;
        for (id, value) in [(7, b"prior".as_slice()), (8, b"terminal".as_slice())] {
            let transaction = JournalTransaction::new([id; 16], vec![
                JournalRecord::put(RecordNamespace::BrokerSessionTraffic, key.clone(), value.to_vec()),
            ]).unwrap();
            let frames = encode_transaction(&transaction, next).unwrap();
            next += frames.len() as u64;
            for frame in frames { file.write_all(&frame).unwrap(); }
        }
        file.sync_all().unwrap();
        drop(file);
        let uid = directory.path().metadata().unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(directory.path(), "session.journal",
            JournalLimits::default(), uid).unwrap();
        let mut names = ProtectedJournalCurrentnessOriginalsV1::new();
        let mut witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::default();
        let supplied = journal.observe_session_completion_position_retaining_v2(&mut names, &mut witness).unwrap();

        // Independently read the same actual names and full held file, as the
        // Root reader does. The supplier's first48 bytes are never a COMMIT ID.
        let directory_metadata = File::open(directory.path()).unwrap().metadata().unwrap();
        let held = File::open(&path).unwrap();
        let metadata = held.metadata().unwrap();
        let lock = File::open(directory.path().join("session.journal.lock")).unwrap().metadata().unwrap();
        let actual_names = ProtectedJournalNamesV1::from_historical_fields(
            (directory_metadata.dev(), directory_metadata.ino()), (metadata.dev(), metadata.ino()),
            (lock.dev(), lock.ino()));
        assert_eq!(supplied, SessionCompletionPositionDataV4::from_native_data_v4(
            actual_names, next, metadata.len()).unwrap().encode_v4());
        let mut selected = DeleteSelectedCommitReplayDataV3::new_session_boundary_v4(supplied).unwrap();
        let mut wrong_contract = DeleteSelectedCommitReplayDataV3::new_storage_v3(supplied);
        let mut changed = supplied;
        changed[55] ^= 1;
        let mut wrong_boundary = DeleteSelectedCommitReplayDataV3::new_session_boundary_v4(changed).unwrap();
        let mut replay = CanonicalReplayOriginalV1::new();
        let mut cursor = replay.begin_semantic_cursor_once(&held, JournalLimits::default(), metadata.len()).unwrap();
        while cursor.advance_once().unwrap() {
            let commit = cursor.current_commit().unwrap();
            // This is the actual encoder/parser contract: the first four
            // native payload bytes are a little-endian record count, whereas
            // native64 embeds only the remaining ordered-payload digest32.
            assert_eq!(commit.commit_payload().len(), 36);
            assert_eq!(&commit.commit_payload()[..4], &1_u32.to_le_bytes());
            let digest = commit.commit_digest_data_v4().unwrap();
            assert_eq!(digest.len(), 32);
            assert_eq!(digest.as_slice(), &commit.commit_payload()[4..]);
            selected.observe_commit_v3(&commit).unwrap();
            wrong_contract.observe_commit_v3(&commit).unwrap();
            wrong_boundary.observe_commit_v3(&commit).unwrap();
            cursor.validate_compaction_once().unwrap();
            cursor.register_transaction_once().unwrap();
            cursor.prepare_change_once().unwrap();
            cursor.apply_commit_once().unwrap();
        }
        selected.finish_prefix_v3(cursor.completed_prefix().unwrap(), metadata.len()).unwrap();
        assert_eq!(selected.session_boundary_data_v4(actual_names, next, metadata.len()).unwrap(), supplied);
        assert_eq!(selected.storage_history_rows_v3().unwrap(), (key.as_slice(), b"prior".as_slice(), b"terminal".as_slice()));
        assert!(wrong_contract.finish_prefix_v3(cursor.completed_prefix().unwrap(), metadata.len()).is_err());
        assert!(wrong_boundary.finish_prefix_v3(cursor.completed_prefix().unwrap(), metadata.len()).is_err());
        let first = wrong_boundary.failure_v3().unwrap() as *const dyn Error;
        assert!(wrong_boundary.finish_prefix_v3(cursor.completed_prefix().unwrap(), metadata.len()).is_err());
        assert!(std::ptr::eq(first, wrong_boundary.failure_v3().unwrap() as *const dyn Error));
        assert!(selected.session_boundary_data_v4(actual_names, next + 1, metadata.len()).is_err());
        assert!(selected.session_boundary_data_v4(actual_names, next, metadata.len() + 1).is_err());
        let changed_names = ProtectedJournalNamesV1::from_historical_fields(
            actual_names.directory(), (metadata.dev(), metadata.ino() + 1), actual_names.lock());
        assert!(selected.session_boundary_data_v4(changed_names, next, metadata.len()).is_err());
        assert!(SessionCompletionPositionDataV4::decode_v4(&supplied[..63]).is_err());
        assert!(SessionCompletionPositionDataV4::decode_v4(&[0; 64]).is_err());
    }

    fn cause_identity(error: &(dyn Error + 'static)) -> (
        Option<*const rustix::io::Errno>, Option<*const JournalError>,
    ) {
        let native = error.downcast_ref::<rustix::io::Errno>()
            .map(|error| error as *const rustix::io::Errno);
        let protected = error.downcast_ref::<JournalError>()
            .map(|error| error as *const JournalError);
        assert!(native.is_some() || protected.is_some());
        (native, protected)
    }

    #[test]
    fn rooted_failure_keeps_reached_ancestors_through_reentry_and_independent_posts() {
        let path = format!("/rfc21-missing-protected-directory-{}", std::process::id());
        let mut first = ProtectedJournalCurrentnessOriginalsV1::new();
        first.begin(false).unwrap();
        let entered = first.observe_directory(Path::new(&path), 0).map(|_| ());
        assert!(first.finish(entered).is_err());
        let files = first.retained_file_count();
        assert!(files >= 1);
        let cause = cause_identity(first.failure().unwrap());

        let mut post = ProtectedJournalCurrentnessOriginalsV1::new();
        post.begin(false).unwrap();
        let entered = post.observe_directory(Path::new(&path), 0).map(|_| ());
        assert!(post.finish(entered).is_err());
        first.settle_positive_once_v1();
        assert!(first.begin(false).is_err());

        assert_eq!(first.retained_file_count(), files);
        assert_eq!(cause_identity(first.failure().unwrap()), cause);
        assert!(post.retained_file_count() >= 1);
    }

    #[test]
    fn missing_main_name_retains_the_fresh_lock_after_negative_disposal_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        std::fs::write(path.join("history.journal"), []).unwrap();
        std::fs::write(path.join("history.journal.lock"), []).unwrap();
        for name in ["history.journal", "history.journal.lock"] {
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let uid = path.metadata().unwrap().uid();
        let lock = File::open(path.join("history.journal.lock")).unwrap();
        let file = File::open(path.join("history.journal")).unwrap();
        let location = ProtectedJournalLocation::from_original_parts((
            File::open(path).unwrap(), "history.journal".to_owned(), uid, (),
        ));
        std::fs::remove_file(path.join("history.journal")).unwrap();
        let mut first = ProtectedJournalCurrentnessOriginalsV1::new();
        first.begin(false).unwrap();
        let entered = first.observe_names(&location, "history.journal", uid, &lock, &file);
        assert!(first.finish(entered).is_err());
        assert_eq!(first.retained_file_count(), 1);
        let cause = cause_identity(first.failure().unwrap());

        std::fs::remove_file(path.join("history.journal.lock")).unwrap();
        let mut post = ProtectedJournalCurrentnessOriginalsV1::new();
        post.begin(false).unwrap();
        let entered = post.observe_names(&location, "history.journal", uid, &lock, &file);
        assert!(post.finish(entered).is_err());
        first.settle_positive_once_v1();

        assert_eq!(first.retained_file_count(), 1);
        assert_eq!(post.retained_file_count(), 0);
        assert_eq!(cause_identity(first.failure().unwrap()), cause);
    }

    #[test]
    fn completed_native_boundary_is_the_retained_sample_and_ends_before_name_disposal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        std::fs::write(path.join("history.journal"), b"old").unwrap();
        std::fs::write(path.join("history.journal.lock"), []).unwrap();
        for name in ["history.journal", "history.journal.lock"] {
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let uid = path.metadata().unwrap().uid();
        let lock = File::open(path.join("history.journal.lock")).unwrap();
        let file = File::open(path.join("history.journal")).unwrap();
        let metadata = file.metadata().unwrap();
        let location = ProtectedJournalLocation::from_original_parts((
            File::open(path).unwrap(), "history.journal".to_owned(), uid, (),
        ));
        let mut original = ProtectedJournalCurrentnessOriginalsV1::new();
        original.begin(false).unwrap();
        let observed = original.observe_names(&location, "history.journal", uid, &lock, &file);
        original.finish(observed).unwrap();

        assert_eq!(original.completed_held_file_boundary_data_v1(),
            Some((metadata.dev(), metadata.ino(), 3)));
        // A getter must not silently recapture currentness or turn historical
        // DATA into a fresh proof after the actual file changes.
        std::fs::write(path.join("history.journal"), b"different length").unwrap();
        assert_eq!(original.completed_held_file_boundary_data_v1(),
            Some((metadata.dev(), metadata.ino(), 3)));

        original.settle_positive_once_v1();
        assert_eq!(original.completed_held_file_boundary_data_v1(), None);
    }

    #[test]
    fn failed_shared_ancestry_keeps_one_native_prefix_and_cannot_bind_another_writer() {
        let mut shared = ProtectedJournalCurrentnessOriginalsV1::new();
        let missing = format!("/rfc21-shared-directory-missing-{}", std::process::id());
        assert!(shared.capture_directory_once_v6(Path::new(&missing), 0).is_err());
        let files = shared.retained_file_count();
        assert!(files >= 1);
        let cause = cause_identity(shared.failure().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let location = ProtectedJournalLocation::from_original_parts((
            File::open(directory.path()).unwrap(), "history.journal".to_owned(),
            directory.path().metadata().unwrap().uid(), (),
        ));
        let mut writer = ProtectedJournalCurrentnessOriginalsV1::new();
        writer.begin(false).unwrap();
        let bound = writer.bind_shared_location_v6(&shared, Path::new(&missing), 0, &location);
        assert!(writer.finish(bound).is_err());
        assert_eq!(writer.retained_file_count(), 0);

        shared.settle_positive_once_v1();
        assert_eq!(shared.retained_file_count(), files);
        assert_eq!(cause_identity(shared.failure().unwrap()), cause);
        assert!(shared.capture_directory_once_v6(Path::new(&missing), 0).is_err());
        assert_eq!(shared.retained_file_count(), files);
        assert_eq!(cause_identity(shared.failure().unwrap()), cause);
    }

    #[test]
    fn common_ancestry_geometry_counts_real_directory_and_name_entries_once() {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        type Original = ProtectedJournalCurrentnessOriginalsV1;
        for path in ["/protected", "/var/lib/aos/sandbox-host"] {
            let path = Path::new(path);
            let root = Original::directory_demand_v6(path).unwrap();
            let mut shared = root;
            let mut repeated = ResourceVector::ZERO;
            for name in ["peer.journal", "execution.journal", "agent.journal", "lifecycle.journal", "argument.journal"] {
                shared = shared.checked_add(Original::named_demand_v1(name).unwrap()).unwrap();
                repeated = repeated.checked_add(Original::fixed_demand_v1(path, name).unwrap()).unwrap();
            }
            // The source roster still contains ten distinct physical names;
            // only four duplicate ancestry traversals have been removed.
            assert_eq!(shared.get(D::OpenFiles), root.get(D::OpenFiles) + 10);
            assert_eq!(shared.get(D::MetadataEntries), root.get(D::MetadataEntries) + 10);
            assert_eq!(repeated.get(D::OpenFiles) - shared.get(D::OpenFiles),
                4 * root.get(D::OpenFiles));
        }
    }

    #[test]
    fn one_native_ancestry_binds_actual_writers_and_rejects_different_directory_uid_or_path() {
        // Reuse the existing protected-writer fixture's private executable
        // ancestry; /tmp is intentionally rejected by the production resolver.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new().prefix("host-shared-root-")
            .tempdir_in(executable.parent().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let mut shared = ProtectedJournalCurrentnessOriginalsV1::new();
        shared.capture_directory_once_v6(directory.path(), uid).unwrap();
        let root_files = shared.retained_file_count();
        assert!(root_files > 0);
        let location = ProtectedJournalLocation::from_original_parts((
            File::open(directory.path()).unwrap(), "first.journal".to_owned(), uid, (),
        ));
        let mut first = ProtectedJournalCurrentnessOriginalsV1::new();
        first.begin(false).unwrap();
        let bound = first.bind_shared_location_v6(&shared, directory.path(), uid, &location);
        first.finish(bound).unwrap();
        assert_eq!(first.retained_file_count(), 0);
        assert_eq!(shared.retained_file_count(), root_files);

        let other = tempfile::tempdir().unwrap();
        let different = ProtectedJournalLocation::from_original_parts((
            File::open(other.path()).unwrap(), "second.journal".to_owned(), uid, (),
        ));
        for (path, selected_uid, selected_location) in [
            (directory.path(), uid, &different),
            (other.path(), uid, &location),
            (directory.path(), uid.wrapping_add(1), &location),
        ] {
            let mut writer = ProtectedJournalCurrentnessOriginalsV1::new();
            writer.begin(false).unwrap();
            let bound = writer.bind_shared_location_v6(&shared, path, selected_uid, selected_location);
            assert!(writer.finish(bound).is_err());
            assert!(writer.failure().is_some());
        }
        shared.settle_positive_once_v1();
        assert_eq!(shared.retained_file_count(), 0);
        let mut after = ProtectedJournalCurrentnessOriginalsV1::new();
        after.begin(false).unwrap();
        let bound = after.bind_shared_location_v6(&shared, directory.path(), uid, &location);
        assert!(after.finish(bound).is_err());
        assert!(shared.capture_directory_once_v6(directory.path(), uid).is_err());
    }

}

impl Journal {
    pub(crate) fn observe_session_completion_position_retaining_v2(&self,
        names: &mut ProtectedJournalCurrentnessOriginalsV1,
        witness: &mut aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    ) -> Result<[u8; 64], JournalError> {
        let actual = self.observe_held_physical_names_retaining_v1(names, witness)?;
        let held = witness.completed_witness().ok_or(JournalError::ProtectedBoundary)?;
        // The established wire ABI is names48 + next-sequence8 + held-length8.
        // The same passive codec serves Root's independent native reader;
        // no transaction identity or COMMIT digest is present in these bytes.
        aos_sandbox_protocol::domain_ledger::protected_names::SessionCompletionPositionDataV4::
            from_native_data_v4(actual, self.snapshot_sequence(), held.file().byte_len())
            .map(|position| position.encode_v4()).map_err(|_| JournalError::ProtectedBoundary)
    }
}
