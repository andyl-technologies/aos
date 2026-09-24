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

use crate::journal::{Journal, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::super::{
    CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayValidatorV1,
};
use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY, CACHE_STATE_JOURNAL,
    CacheClockFloorV1, CacheResidencyCurrentTimeAuthorityV1, CacheResidencyProtectedOpenReportV1,
    CacheResidencyProtectedOwnerV1, MAXIMUM_AUTHORITY_RECORD_BYTES, cache_authority_journal_limits,
    cache_clock_journal_limits, cache_owner_scope, cache_state_journal_limits,
    decode_cache_clock_floor, recover_cache_replay_evidence, reject_legacy_cache_journals,
    sample_wall_clock,
};

const ROOT_READ_ONLY_CACHE_VIEW: &str = "/run/aos/sandbox-policy-cache-journals";

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
}

struct ReadOnlyCacheClockV1 {
    floor: CacheClockFloorV1,
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
    let mount = require_fixed_read_only_cache_mount()?;
    reject_legacy_cache_journals()?;
    let view = Path::new(ROOT_READ_ONLY_CACHE_VIEW);
    let owner_scope = cache_owner_scope();

    let (mut clock, clock_report) = Journal::open_read_only_protected_at(
        view,
        CACHE_CLOCK_JOURNAL,
        cache_clock_journal_limits(),
    )?;
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

    let (mut authority, authority_report) = Journal::open_read_only_protected_at(
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

    let (state, state_report) = Journal::open_read_only_protected_at(
        view,
        CACHE_STATE_JOURNAL,
        cache_state_journal_limits(),
    )?;
    let (state_journal, state_witness) = state.into_parts();
    let mut owner = CacheResidencyProtectedOwnerV1 {
        state_journal: Some(state_journal),
        authority: replay_authority,
        owner_uid: 0,
    };
    let partitions = owner.reconstructed_partitions()?.len();

    state_witness.check_named_currentness()?;
    authority_witness.check_named_currentness()?;
    clock.check_named_currentness()?;
    if require_fixed_read_only_cache_mount()? != mount {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
    }

    Ok(CacheResidencyRootReadOnlyReplayV1 {
        journals: CacheResidencyProtectedOpenReportV1 {
            state: state_report,
            authority: authority_report,
            clock: clock_report,
        },
        partitions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
