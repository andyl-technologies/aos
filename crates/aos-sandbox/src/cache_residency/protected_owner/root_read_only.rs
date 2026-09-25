//! Nonauthorizing root replay of the fixed, read-only Cache journal view.
//!
//! The physical names, limits, and owner scope come from Cache code. Root
//! obtains no writer lock, cannot advance the clock, and cannot use this
//! observation to publish policy or hand off an effect.

use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{AtFlags, CWD, StatVfsMountFlags, StatxAttributes, StatxFlags, statvfs, statx};

#[cfg(target_os = "linux")]
use crate::cache_residency::CacheOwnerLimitsV1;
#[cfg(target_os = "linux")]
use crate::cache_residency::signer_mount::require_signer_mount;
use crate::journal::{
    CACHE_POLICY_HOLD_JOURNAL, CachePolicyHoldV1, Journal, JournalError, JournalLimits,
    ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal, RecordNamespace, RecoveryReport,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use aos_sandbox_core::ObjectDigest;

use super::super::{
    CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayValidatorV1,
};
use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY, CACHE_STATE_JOURNAL,
    CacheClockFloorV1, CacheResidencyCurrentTimeAuthorityV1, CacheResidencyProtectedOpenReportV1,
    CacheResidencyProtectedOwnerV1, MAXIMUM_AUTHORITY_RECORD_BYTES, cache_authority_journal_limits,
    cache_clock_journal_limits, cache_owner_scope, cache_state_journal_limits,
    complete_node_quota_digest_v2, decode_cache_clock_floor, recover_cache_replay_evidence,
    reject_legacy_cache_journals, sample_wall_clock, select_project_physical_cache_head,
};

const ROOT_READ_ONLY_CACHE_VIEW: &str = "/run/aos/sandbox-policy-cache-journals";
#[cfg(target_os = "linux")]
pub(crate) const SIGNER_READ_ONLY_CACHE_VIEW: &str = "/run/aos/sandbox-cache-signer-journals";

/// Reports a fully verified but nonauthorizing root Cache readback.
///
/// This diagnostic has no held Controller cut, effect capability, or policy
/// publication authority. Its count is useful only for health and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheResidencyRootReadOnlyReplayV1 {
    /// Reports structural replay of the three exact physical journals.
    pub journals: CacheResidencyProtectedOpenReportV1,
    /// Counts partitions whose manifest, authority, and typed history verified.
    pub partitions: usize,
    /// Commits the complete typed node quota envelope in partition order.
    pub quota_digest: ObjectDigest,
}

/// Reports an exact active Cache hold together with independently replayed state.
///
/// This observation cannot authorize Q04. A future root-owned CAS must compare
/// `hold.binding()` and `hold.epoch()` with root-owned expected values while
/// retaining every required owner cut and performing the effect handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheResidencyRootReadOnlyPolicyHoldV1 {
    /// Reports the verified Cache state, authority, and clock replay.
    pub replay: CacheResidencyRootReadOnlyReplayV1,
    /// Reports structural replay of the fourth exact protected journal.
    pub hold_journal: RecoveryReport,
    /// Names the canonical active hold observed from that journal.
    pub hold: CachePolicyHoldV1,
}

pub(super) struct ReadOnlyCacheClockV1 {
    pub(super) floor: CacheClockFloorV1,
}

impl CacheResidencyCurrentTimeAuthorityV1 for ReadOnlyCacheClockV1 {
    fn current_unix_seconds(&self) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        let now = sample_wall_clock()?;
        if self.floor.owner_scope != cache_owner_scope() || now < self.floor.observed_unix_seconds {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(now)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FixedCacheMountIdentity {
    mount_id: u64,
    inode: u64,
    device_major: u32,
    device_minor: u32,
}

fn mountinfo_has_fixed_read_only_view(mountinfo: &str, mount_id: u64) -> bool {
    mountinfo
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let id = fields.next().and_then(|value| value.parse::<u64>().ok());
            let _parent = fields.next();
            let _device = fields.next();
            let _root = fields.next();
            let path = fields.next();
            let options = fields.next();
            id == Some(mount_id)
                && path == Some(ROOT_READ_ONLY_CACHE_VIEW)
                && options.is_some_and(|options| {
                    ["ro", "nosuid", "nodev", "noexec", "nosymfollow"]
                        .into_iter()
                        .all(|required| options.split(',').any(|option| option == required))
                })
        })
        .count()
        == 1
}

fn require_fixed_read_only_cache_mount()
-> Result<FixedCacheMountIdentity, CacheResidencyProtectedJournalErrorV1> {
    let view = statx(
        CWD,
        ROOT_READ_ONLY_CACHE_VIEW,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let parent = statx(
        CWD,
        "/run/aos",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let options = statvfs(ROOT_READ_ONLY_CACHE_VIEW)
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let required = StatVfsMountFlags::RDONLY
        | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NODEV
        | StatVfsMountFlags::NOEXEC;
    let mut mountinfo = String::new();
    fs::File::open("/proc/self/mountinfo")
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut mountinfo)
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if view.stx_mask & StatxFlags::MNT_ID.bits() != 0
        && parent.stx_mask & StatxFlags::MNT_ID.bits() != 0
        && view.stx_mnt_id != parent.stx_mnt_id
        && view
            .stx_attributes_mask
            .contains(StatxAttributes::MOUNT_ROOT)
        && view.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)
        && options.f_flag.contains(required)
        && mountinfo.len() <= 1024 * 1024
        && mountinfo_has_fixed_read_only_view(&mountinfo, view.stx_mnt_id)
    {
        Ok(FixedCacheMountIdentity {
            mount_id: view.stx_mnt_id,
            inode: view.stx_ino,
            device_major: view.stx_dev_major,
            device_minor: view.stx_dev_minor,
        })
    } else {
        Err(ProtectedDomainJournalErrorV1::StaleAuthority)
    }
}

fn hold_matches_replayed_head(
    hold: CachePolicyHoldV1,
    partition: ObjectDigest,
    head: ObjectDigest,
) -> bool {
    hold.partition() == partition && hold.cache_head() == head
}

/// Replays the fixed root Cache view without touching Controller writer state.
///
/// The three journals are reopened by their compiled-in names and checked
/// again after complete Cache authority and typed-history verification. This
/// cannot prove that their observations occurred at one Controller cut, so the
/// result must never authorize Q04, public Create, or an effect.
///
/// # Errors
///
/// Rejects an absent or changed read-only mount, unsafe names or metadata,
/// incomplete tails, stale clock, malformed authority, or invalid Cache replay.
pub fn replay_fixed_root_read_only_cache_journals_v1()
-> Result<CacheResidencyRootReadOnlyReplayV1, CacheResidencyProtectedJournalErrorV1> {
    let (replay, _) = replay_fixed_root_read_only_cache_journals_inner(false)?;
    Ok(replay)
}

/// Replays the exact active Cache hold under the fixed root read-only view.
///
/// The hold's project, physical partition, and replay head must equal one
/// unique healthy protected Cache partition. Binding and epoch are returned as
/// observed data; the caller must not treat them as root-owned expectations.
/// The four names and mount are checked again after complete replay. This is
/// still not a simultaneous Controller cut or Q04 publication authority.
///
/// # Errors
///
/// Rejects an absent, released, malformed, substituted, or mismatched hold,
/// unsafe mount or name, stale clock, or invalid protected Cache replay.
pub fn replay_fixed_root_read_only_cache_policy_hold_v1()
-> Result<CacheResidencyRootReadOnlyPolicyHoldV1, CacheResidencyProtectedJournalErrorV1> {
    let (replay, hold) = replay_fixed_root_read_only_cache_journals_inner(true)?;
    let (hold, hold_journal) = hold.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    Ok(CacheResidencyRootReadOnlyPolicyHoldV1 {
        replay,
        hold_journal,
        hold,
    })
}

/// Replays the signer view and derives physical limits from its complete quotas.
///
/// The separate Cache signer must use this checked form before signing a
/// physical and protected receipt. Only the signer-private heap ceiling is
/// supplied; all other physical limits come from complete protected quotas.
///
/// # Errors
///
/// Rejects unsafe or changed mounts and names, invalid typed replay, a stale
/// hold, or protected quotas that cannot form one valid physical envelope.
#[cfg(target_os = "linux")]
pub(crate) fn derive_fixed_signer_cache_policy_hold_and_limits_v1(
    maximum_memory_bytes: u64,
) -> Result<
    (CacheResidencyRootReadOnlyPolicyHoldV1, CacheOwnerLimitsV1),
    CacheResidencyProtectedJournalErrorV1,
> {
    let signer_uid = rustix::process::geteuid().as_raw();
    let mount = require_signer_mount(
        SIGNER_READ_ONLY_CACHE_VIEW,
        super::PROTECTED_CACHE_ROOT,
        signer_uid,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    reject_legacy_cache_journals()?;
    let mut derived_limits = None;
    let (replay, hold) = replay_cache_journals_at(
        Path::new(SIGNER_READ_ONLY_CACHE_VIEW),
        signer_uid,
        true,
        |view, name, limits| {
            Journal::open_read_only_protected_at_for_uid_bound(
                view,
                name,
                limits,
                signer_uid,
                mount.root_identity(),
            )
        },
        ReadOnlyJournalNameWitness::check_named_currentness,
        ReadOnlyProtectedJournal::check_named_currentness,
        |quotas| {
            derived_limits = Some(
                CacheOwnerLimitsV1::from_node_quotas(maximum_memory_bytes, quotas.iter().copied())
                    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?,
            );
            Ok(())
        },
    )?;
    reject_legacy_cache_journals()?;
    if require_signer_mount(
        SIGNER_READ_ONLY_CACHE_VIEW,
        super::PROTECTED_CACHE_ROOT,
        signer_uid,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?
        != mount
    {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    let (hold, hold_journal) = hold.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let limits = derived_limits.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    Ok((
        CacheResidencyRootReadOnlyPolicyHoldV1 {
            replay,
            hold_journal,
            hold,
        },
        limits,
    ))
}

fn replay_fixed_root_read_only_cache_journals_inner(
    require_hold: bool,
) -> Result<
    (
        CacheResidencyRootReadOnlyReplayV1,
        Option<(CachePolicyHoldV1, RecoveryReport)>,
    ),
    CacheResidencyProtectedJournalErrorV1,
> {
    let mount = require_fixed_read_only_cache_mount()?;
    reject_legacy_cache_journals()?;
    let view = Path::new(ROOT_READ_ONLY_CACHE_VIEW);
    let replay = replay_cache_journals_at(
        view,
        0,
        require_hold,
        Journal::open_read_only_protected_at,
        ReadOnlyJournalNameWitness::check_named_currentness,
        ReadOnlyProtectedJournal::check_named_currentness,
        |_| Ok(()),
    )?;
    reject_legacy_cache_journals()?;
    if require_fixed_read_only_cache_mount()? != mount {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    Ok(replay)
}

fn replay_cache_journals_at(
    view: &Path,
    owner_uid: u32,
    require_hold: bool,
    open: impl Fn(
        &Path,
        &str,
        JournalLimits,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError>,
    check_name: impl Fn(&ReadOnlyJournalNameWitness) -> Result<(), JournalError>,
    check_hold: impl Fn(&ReadOnlyProtectedJournal) -> Result<(), JournalError>,
    check_quotas: impl FnOnce(
        &[crate::cache_residency::NodeCacheQuotaV1],
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1>,
) -> Result<
    (
        CacheResidencyRootReadOnlyReplayV1,
        Option<(CachePolicyHoldV1, RecoveryReport)>,
    ),
    CacheResidencyProtectedJournalErrorV1,
> {
    let owner_scope = cache_owner_scope();

    let (mut clock, clock_report) = open(view, CACHE_CLOCK_JOURNAL, cache_clock_journal_limits())?;
    let floor = {
        let authority = clock
            .journal_mut()
            .claim_protected_authority(RecordNamespace::DesiredState)?;
        authority
            .get(CACHE_CLOCK_KEY)?
            .map(decode_cache_clock_floor)
            .transpose()?
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
    };
    if floor.owner_scope != owner_scope {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }
    let current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> =
        Arc::new(ReadOnlyCacheClockV1 { floor });

    let (mut authority, authority_report) = open(
        view,
        CACHE_AUTHORITY_JOURNAL,
        cache_authority_journal_limits(),
    )?;
    let evidence = recover_cache_replay_evidence(
        authority.journal_mut(),
        owner_scope,
        CacheRecoveryLimitsV1::default(),
    )?;
    let (authority_journal, authority_witness) = authority.into_parts();
    let (_validator, replay_authority) = CacheResidencyReplayValidatorV1::from_protected_authority(
        authority_journal,
        owner_scope,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        evidence,
        CacheRecoveryLimitsV1::default(),
        current_time,
    )?;

    let (state, state_report) = open(view, CACHE_STATE_JOURNAL, cache_state_journal_limits())?;
    let (state_journal, state_witness) = state.into_parts();
    let mut owner = CacheResidencyProtectedOwnerV1 {
        state_journal: Some(state_journal),
        authority: replay_authority,
        clock: None,
        owner_uid,
    };
    let inventories = owner.reconstructed_partitions()?;
    let partitions = inventories.len();
    let node_quotas: Vec<_> = inventories
        .iter()
        .map(|inventory| inventory.global.node_quota)
        .collect();
    check_quotas(&node_quotas)?;
    let quota_digest = complete_node_quota_digest_v2(node_quotas)?;
    let mut hold_witness = None;
    let hold = if require_hold {
        let (mut journal, report) = open(
            view,
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
        )?;
        let hold = journal.held_cache_policy_hold()?;
        let current = select_project_physical_cache_head(hold.project(), inventories)?;
        if !hold_matches_replayed_head(hold, current.partition().digest(), current.head()) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        hold_witness = Some(journal);
        Some((hold, report))
    } else {
        None
    };

    if let Some(journal) = hold_witness.as_ref() {
        check_hold(journal)?;
    }
    check_name(&state_witness)?;
    check_name(&authority_witness)?;
    check_hold(&clock)?;

    let replay = CacheResidencyRootReadOnlyReplayV1 {
        journals: CacheResidencyProtectedOpenReportV1 {
            state: state_report,
            authority: authority_report,
            clock: clock_report,
        },
        partitions,
        quota_digest,
    };
    Ok((replay, hold))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    fn replay_live_test_view(
        view: &Path,
        uid: u32,
    ) -> Result<
        (
            CacheResidencyRootReadOnlyReplayV1,
            Option<(CachePolicyHoldV1, RecoveryReport)>,
        ),
        CacheResidencyProtectedJournalErrorV1,
    > {
        replay_cache_journals_at(
            view,
            uid,
            true,
            |view, name, limits| {
                Journal::open_read_only_protected_at_uid_for_test(view, name, limits, uid)
            },
            ReadOnlyJournalNameWitness::check_named_currentness_at_uid_for_test,
            ReadOnlyProtectedJournal::check_named_currentness_at_uid_for_test,
            |_| Ok(()),
        )
    }

    #[test]
    fn active_hold_replays_four_exact_names_without_mutation() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let names = [
            CACHE_CLOCK_JOURNAL,
            CACHE_AUTHORITY_JOURNAL,
            CACHE_STATE_JOURNAL,
            CACHE_POLICY_HOLD_JOURNAL,
        ];
        let before = names.map(|name| {
            std::fs::read(directory.path().join(name)).expect("journal before readback")
        });

        let (replay, observed) =
            replay_live_test_view(directory.path(), uid).expect("four-journal readback");

        assert_eq!(replay.partitions, 1);
        assert!(replay.journals.authority.committed_transactions > 0);
        assert!(replay.journals.clock.committed_transactions > 0);
        let (hold, report) = observed.expect("active canonical hold");
        assert_eq!(hold, expected);
        assert!(report.committed_transactions > 0);
        for (name, expected_bytes) in names.into_iter().zip(before) {
            assert_eq!(
                std::fs::read(directory.path().join(name)).expect("journal after readback"),
                expected_bytes,
            );
        }
    }

    #[test]
    fn active_hold_name_witness_rejects_concurrent_mutation() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            uid,
        )
        .expect("read-only active hold");
        assert_eq!(
            readback.held_cache_policy_hold().expect("held record"),
            expected
        );

        OpenOptions::new()
            .append(true)
            .open(directory.path().join(CACHE_POLICY_HOLD_JOURNAL))
            .expect("test writer")
            .write_all(b"changed")
            .expect("append after readback");

        assert!(readback.check_named_currentness_at_uid_for_test().is_err());
    }

    #[test]
    fn active_hold_name_witness_rejects_identical_new_inode() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            uid,
        )
        .expect("read-only active hold");
        assert_eq!(
            readback.held_cache_policy_hold().expect("held record"),
            expected
        );

        let named = directory.path().join(CACHE_POLICY_HOLD_JOURNAL);
        let retained = directory.path().join("policy-hold.journal.retained");
        let original_inode = std::fs::metadata(&named).expect("held name").ino();
        std::fs::rename(&named, &retained).expect("retain open hold inode");
        std::fs::copy(&retained, &named).expect("replace with identical hold bytes");

        let replacement = std::fs::metadata(&named).expect("replacement hold name");
        assert_ne!(replacement.ino(), original_inode);
        assert_eq!(replacement.mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read(&named).expect("replacement bytes"),
            std::fs::read(&retained).expect("retained bytes")
        );
        assert!(readback.check_named_currentness_at_uid_for_test().is_err());
    }

    #[test]
    fn mountinfo_requires_one_exact_protected_cache_mount() {
        let valid = "42 1 0:2 / /run/aos/sandbox-policy-cache-journals ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/test rw";
        assert!(mountinfo_has_fixed_read_only_view(valid, 42));
        assert!(!mountinfo_has_fixed_read_only_view(valid, 43));
        assert!(!mountinfo_has_fixed_read_only_view(
            &valid.replace("nosymfollow", "symfollow"),
            42,
        ));
        assert!(!mountinfo_has_fixed_read_only_view(
            &format!("{valid}\n{valid}"),
            42,
        ));
        assert!(!mountinfo_has_fixed_read_only_view(
            &valid.replace(ROOT_READ_ONLY_CACHE_VIEW, "/run/aos/other"),
            42,
        ));
    }

    #[test]
    fn read_only_clock_rejects_a_stale_floor() {
        let clock = ReadOnlyCacheClockV1 {
            floor: CacheClockFloorV1 {
                owner_scope: cache_owner_scope(),
                revision: 1,
                observed_unix_seconds: u64::MAX,
                predecessor_unix_seconds: 0,
            },
        };
        assert!(clock.current_unix_seconds().is_err());
    }

    #[test]
    fn active_hold_requires_exact_replayed_partition_and_head() {
        use aos_sandbox_core::ProjectId;

        let partition = ObjectDigest::from_bytes([2; 32]);
        let head = ObjectDigest::from_bytes([3; 32]);
        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            partition,
            head,
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("valid hold");

        assert!(hold_matches_replayed_head(hold, partition, head));
        assert!(!hold_matches_replayed_head(
            hold,
            ObjectDigest::from_bytes([6; 32]),
            head,
        ));
        assert!(!hold_matches_replayed_head(
            hold,
            partition,
            ObjectDigest::from_bytes([7; 32]),
        ));
        assert_eq!(hold.binding(), ObjectDigest::from_bytes([4; 32]));
        assert_eq!(hold.epoch(), 5);
    }
}
