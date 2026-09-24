//! Nonmutating inventory for an offline Cache journal migration.
//!
//! The old cache root also contains object storage. Only the three journal
//! basenames and their lock and compaction siblings belong to this inventory.
//! A complete inventory is a prerequisite for replay, not migration authority.

use std::{fs::File, io, path::Path, sync::Arc};

use aos_sandbox_core::ObjectDigest;
use rustix::fs::{statat, AtFlags, FileType, Mode};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::super::protected_journal::{
    CacheResidencyCurrentTimeAuthorityV1, EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX,
};
use super::super::{
    CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedOpenReportV1, CacheResidencyReplayValidatorV1,
};
use super::{
    cache_authority_journal_limits, cache_clock_journal_limits, cache_state_journal_limits,
    decode_cache_clock_floor, recover_cache_replay_evidence, sample_wall_clock, CacheClockFloorV1,
    CACHE_AUTHORITY_JOURNAL, CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY, CACHE_MANIFEST_KEY_PREFIX,
    CACHE_STATE_JOURNAL, LEGACY_CACHE_ROOT, MAXIMUM_AUTHORITY_RECORD_BYTES,
};

// Each three-name group is the journal, its lock, then its compaction remainder.
const LEGACY_JOURNAL_NAMES: [&str; 9] = [
    "state.journal",
    "state.journal.lock",
    "state.journal.compact.tmp",
    "authority.journal",
    "authority.journal.lock",
    "authority.journal.compact.tmp",
    "clock.journal",
    "clock.journal.lock",
    "clock.journal.compact.tmp",
];

/// Classifies the exact old Cache journal names before any replay or migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyCacheJournalInventoryV1 {
    /// None of the nine old journal names exists.
    Absent,
    /// All three journals and their locks exist, with no compaction remainder.
    Complete,
    /// At least one journal or lock is missing from a nonempty inventory.
    Incomplete,
    /// A compaction remainder exists and needs separate offline recovery.
    InterruptedCompaction,
}

/// Summarizes existing old journals that passed an offline, nonmutating replay.
///
/// This value is diagnostic evidence only. It neither migrates bytes nor
/// authorizes Cache effects under the new journal path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyCacheJournalPreflightReportV1 {
    /// Reports structural replay of the three old journals.
    pub journals: CacheResidencyProtectedOpenReportV1,
    /// Counts partitions whose protected Replay authority and history verified.
    pub partitions: usize,
}

struct LegacyReadOnlyCacheClockV1 {
    floor: CacheClockFloorV1,
    owner_scope: ObjectDigest,
}

impl CacheResidencyCurrentTimeAuthorityV1 for LegacyReadOnlyCacheClockV1 {
    fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        let now = sample_wall_clock()?;
        if self.floor.owner_scope != self.owner_scope || now < self.floor.observed_unix_seconds {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(now)
    }
}

/// Classifies exact old names beneath an already verified and retained directory.
///
/// Every present entry must be a single-link, mode-0600 regular file owned by
/// `expected_uid`. This scan alone is not an authority proof: the caller must
/// also verify the directory and names through protected existing-only opens.
///
/// # Errors
///
/// Returns a protected-boundary error for an unsafe entry or an I/O error if
/// an exact-name lookup fails for a reason other than absence.
pub(crate) fn classify_legacy_cache_journals_at(
    directory: &File,
    expected_uid: u32,
) -> Result<LegacyCacheJournalInventoryV1, JournalError> {
    let mut present = [false; LEGACY_JOURNAL_NAMES.len()];

    for (index, name) in LEGACY_JOURNAL_NAMES.iter().enumerate() {
        match statat(directory, *name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || Mode::from_raw_mode(stat.st_mode) != (Mode::RUSR | Mode::WUSR)
                    || stat.st_uid != expected_uid
                    || stat.st_nlink != 1
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                present[index] = true;
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(JournalError::Io(io::Error::from_raw_os_error(
                    error.raw_os_error(),
                )));
            }
        }
    }

    if present.iter().all(|found| !found) {
        return Ok(LegacyCacheJournalInventoryV1::Absent);
    }
    if present.chunks_exact(3).any(|group| group[2]) {
        return Ok(LegacyCacheJournalInventoryV1::InterruptedCompaction);
    }
    if present.chunks_exact(3).all(|group| group[0] && group[1]) {
        return Ok(LegacyCacheJournalInventoryV1::Complete);
    }
    Ok(LegacyCacheJournalInventoryV1::Incomplete)
}

/// Preflights the fixed old Cache journals while the old Controller is offline.
///
/// All nine exact legacy names are classified first. The three existing lock
/// files are exclusively locked without creation, and journal replay rejects
/// an uncommitted tail rather than repairing it. Scope checks use the old
/// compiled-in directory path. The result does not survive release of the
/// locks and cannot authorize a move, authority reissue, or public Q04.
///
/// # Errors
///
/// Returns an error for absent or incomplete old names, unsafe ownership or
/// modes, a concurrent writer, stale protected time, foreign owner scope, or
/// malformed structural or typed Cache replay.
pub fn preflight_fixed_legacy_cache_journals_for_uid(
    owner_uid: u32,
) -> Result<LegacyCacheJournalPreflightReportV1, CacheResidencyProtectedJournalErrorV1> {
    let root = Path::new(LEGACY_CACHE_ROOT);
    let directory = File::open(root).map_err(JournalError::Io)?;
    if classify_legacy_cache_journals_at(&directory, owner_uid)?
        != LegacyCacheJournalInventoryV1::Complete
    {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let owner_scope = legacy_cache_owner_scope();

    // Opening in the same order as the old owner avoids a lock-order cycle.
    let (mut clock, clock_report) = Journal::open_existing_locked_read_only_protected_at_for_uid(
        root,
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
        owner_uid,
    )?;
    let floor = {
        let authority = clock
            .journal_mut()
            .claim_protected_authority(RecordNamespace::DesiredState)?;
        let mut records = authority.records()?;
        let (key, value) = records
            .next()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if key != CACHE_CLOCK_KEY || records.next().is_some() {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        decode_cache_clock_floor(value)?
    };
    if floor.owner_scope != owner_scope {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    let current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> =
        Arc::new(LegacyReadOnlyCacheClockV1 { floor, owner_scope });

    let (mut authority, authority_report) =
        Journal::open_existing_locked_read_only_protected_at_for_uid(
            root,
            CACHE_AUTHORITY_JOURNAL,
            cache_authority_journal_limits(),
            owner_uid,
        )?;
    {
        let records = authority
            .journal_mut()
            .claim_protected_authority(RecordNamespace::DesiredState)?;
        require_legacy_authority_record_scopes(records.records()?, owner_scope)?;
    }
    let evidence = recover_cache_replay_evidence(
        authority.journal_mut(),
        owner_scope,
        CacheRecoveryLimitsV1::default(),
    )?;
    let partitions = evidence.len();
    let (authority_journal, authority_witness) = authority.into_parts();
    let (_validator, replay_authority) = CacheResidencyReplayValidatorV1::from_protected_authority(
        authority_journal,
        owner_scope,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        evidence,
        CacheRecoveryLimitsV1::default(),
        current_time,
    )?;

    let (mut state, state_report) = Journal::open_existing_locked_read_only_protected_at_for_uid(
        root,
        CACHE_STATE_JOURNAL,
        cache_state_journal_limits(),
        owner_uid,
    )?;
    replay_authority.while_authority_current(
        &[],
        |_owner, _capabilities, _now, validator, refresh| {
            CacheResidencyProtectedJournalV1::claim(state.journal_mut(), validator)?.replay()?;
            refresh()?;
            Ok(())
        },
    )?;

    let directory = File::open(root).map_err(JournalError::Io)?;
    if classify_legacy_cache_journals_at(&directory, owner_uid)?
        != LegacyCacheJournalInventoryV1::Complete
    {
        return Err(JournalError::ProtectedBoundary.into());
    }
    state.check_named_currentness()?;
    authority_witness.check_named_currentness()?;
    clock.check_named_currentness()?;

    Ok(LegacyCacheJournalPreflightReportV1 {
        journals: CacheResidencyProtectedOpenReportV1 {
            state: state_report,
            authority: authority_report,
            clock: clock_report,
        },
        partitions,
    })
}

// Protected Cache authority was bound to the old path, not to its new sibling.
fn legacy_cache_owner_scope() -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache-residency.fixed-owner.v1\0")
            .chain_update(LEGACY_CACHE_ROOT.as_bytes())
            .finalize()
            .into(),
    )
}

// A replay manifest verifies its referenced Replay authority record, but the
// migration inventory must also reject stale or foreign unreferenced rows.
fn require_legacy_authority_record_scopes<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    owner_scope: ObjectDigest,
) -> Result<(), JournalError> {
    for (key, value) in records {
        if key.starts_with(CACHE_MANIFEST_KEY_PREFIX) {
            if key.len() != CACHE_MANIFEST_KEY_PREFIX.len() + 32 || !value.starts_with(b"AOSCRM01")
            {
                return Err(JournalError::ProtectedBoundary);
            }
            continue;
        }

        if key.starts_with(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX) {
            if key.len() != EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX.len() + 16
                || value.len() != 192
                || &value[..8] != b"AOSCOA01"
                || value[8..10] != 1_u16.to_be_bytes()
                || value[10..16] != [0; 6]
                || value[16..48] != *owner_scope.as_bytes()
                || key[EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX.len()..] != value[48..64]
                || value[48..64] == [0; 16]
                || value[64..96] == [0; 32]
                || value[96..128] == [0; 32]
                || value[128..160] == [0; 32]
                || value[160..192]
                    != Sha256::new()
                        .chain_update(b"aos.sandbox.cache.effect-observation-authority.v1\0")
                        .chain_update(&value[..160])
                        .finalize()[..]
            {
                return Err(JournalError::ProtectedBoundary);
            }
            continue;
        }

        if value.len() != 208
            || &value[..8] != b"AOSCAR01"
            || value[8..10] != 1_u16.to_be_bytes()
            || !(1..=13).contains(&value[10])
            || value[11..16] != [0; 5]
            || value[16..48] != *owner_scope.as_bytes()
            || value[48..80] == [0; 32]
            || value[80..112] == [0; 32]
            || value[128..160] == [0; 32]
            || value[160..192] == [0; 32]
            || value[192..200] == [0; 8]
            || value[200..208] == [0; 8]
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _},
    };

    use super::*;

    fn create_legacy_file(directory: &std::path::Path, name: &str) {
        let path = directory.join(name);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create legacy entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set exact mode");
    }

    #[test]
    fn all_nine_names_are_classified_without_touching_disk() {
        let directory = tempfile::tempdir().expect("directory");
        let held = File::open(directory.path()).expect("open directory");
        let uid = rustix::process::geteuid().as_raw();
        assert_eq!(
            classify_legacy_cache_journals_at(&held, uid).expect("empty inventory"),
            LegacyCacheJournalInventoryV1::Absent
        );
        fs::create_dir(directory.path().join("objects")).expect("unrelated object root");

        for name in LEGACY_JOURNAL_NAMES {
            create_legacy_file(directory.path(), name);
        }
        assert_eq!(
            classify_legacy_cache_journals_at(&held, uid).expect("compaction inventory"),
            LegacyCacheJournalInventoryV1::InterruptedCompaction
        );

        for name in [
            "state.journal.compact.tmp",
            "authority.journal.compact.tmp",
            "clock.journal.compact.tmp",
        ] {
            fs::remove_file(directory.path().join(name)).expect("remove fixture");
        }
        assert_eq!(
            classify_legacy_cache_journals_at(&held, uid).expect("complete inventory"),
            LegacyCacheJournalInventoryV1::Complete
        );
        assert!(matches!(
            classify_legacy_cache_journals_at(&held, uid.wrapping_add(1)),
            Err(JournalError::ProtectedBoundary)
        ));

        fs::remove_file(directory.path().join("authority.journal.lock")).expect("remove fixture");
        assert_eq!(
            classify_legacy_cache_journals_at(&held, uid).expect("partial inventory"),
            LegacyCacheJournalInventoryV1::Incomplete
        );
    }

    #[test]
    fn exact_names_reject_symlinks_and_bad_modes() {
        let directory = tempfile::tempdir().expect("directory");
        let held = File::open(directory.path()).expect("open directory");
        let uid = rustix::process::geteuid().as_raw();

        for name in LEGACY_JOURNAL_NAMES {
            symlink("missing", directory.path().join(name)).expect("create symlink");
            assert!(matches!(
                classify_legacy_cache_journals_at(&held, uid),
                Err(JournalError::ProtectedBoundary)
            ));
            fs::remove_file(directory.path().join(name)).expect("remove fixture");

            create_legacy_file(directory.path(), name);
            fs::set_permissions(
                directory.path().join(name),
                fs::Permissions::from_mode(0o644),
            )
            .expect("widen fixture mode");
            assert!(matches!(
                classify_legacy_cache_journals_at(&held, uid),
                Err(JournalError::ProtectedBoundary)
            ));
            fs::remove_file(directory.path().join(name)).expect("remove fixture");
        }
    }

    #[test]
    fn old_scope_uses_the_old_journal_directory_name() {
        let old = legacy_cache_owner_scope();
        let new = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.cache-residency.fixed-owner.v1\0")
                .chain_update(b"/var/lib/aos/sandbox/cache-residency-journals")
                .finalize()
                .into(),
        );
        assert_ne!(old, new);
    }

    #[test]
    fn unreferenced_authority_record_with_new_scope_is_rejected() {
        let old = legacy_cache_owner_scope();
        let mut record = [0_u8; 208];
        record[..8].copy_from_slice(b"AOSCAR01");
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[10] = 10;
        record[16..48].copy_from_slice(old.as_bytes());
        record[48..80].copy_from_slice(&[1; 32]);
        record[80..112].copy_from_slice(&[2; 32]);
        record[128..160].copy_from_slice(&[3; 32]);
        record[160..192].copy_from_slice(&[4; 32]);
        record[192..200].copy_from_slice(&1_u64.to_be_bytes());
        record[200..208].copy_from_slice(&u64::MAX.to_be_bytes());
        let rows = [(b"unreferenced".as_slice(), record.as_slice())];
        assert!(require_legacy_authority_record_scopes(rows, old).is_ok());

        record[16..48].copy_from_slice(&[8; 32]);
        let rows = [(b"unreferenced".as_slice(), record.as_slice())];
        assert!(matches!(
            require_legacy_authority_record_scopes(rows, old),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn unreferenced_observation_with_new_scope_is_rejected() {
        let old = legacy_cache_owner_scope();
        let mut key = EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX.to_vec();
        key.extend_from_slice(&[1; 16]);
        let mut record = [0_u8; 192];
        record[..8].copy_from_slice(b"AOSCOA01");
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[16..48].copy_from_slice(old.as_bytes());
        record[48..64].copy_from_slice(&[1; 16]);
        record[64..96].copy_from_slice(&[2; 32]);
        record[96..128].copy_from_slice(&[3; 32]);
        record[128..160].copy_from_slice(&[4; 32]);
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache.effect-observation-authority.v1\0")
            .chain_update(&record[..160])
            .finalize();
        record[160..192].copy_from_slice(&digest);
        let rows = [(key.as_slice(), record.as_slice())];
        assert!(require_legacy_authority_record_scopes(rows, old).is_ok());

        record[16..48].copy_from_slice(&[8; 32]);
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.cache.effect-observation-authority.v1\0")
            .chain_update(&record[..160])
            .finalize();
        record[160..192].copy_from_slice(&digest);
        let rows = [(key.as_slice(), record.as_slice())];
        assert!(matches!(
            require_legacy_authority_record_scopes(rows, old),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn hard_linked_legacy_journal_is_not_a_protected_entry() {
        let directory = tempfile::tempdir().expect("directory");
        let held = File::open(directory.path()).expect("open directory");
        let uid = rustix::process::geteuid().as_raw();
        create_legacy_file(directory.path(), "state.journal");
        fs::hard_link(
            directory.path().join("state.journal"),
            directory.path().join("elsewhere"),
        )
        .expect("link fixture");

        assert!(matches!(
            classify_legacy_cache_journals_at(&held, uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }
}
