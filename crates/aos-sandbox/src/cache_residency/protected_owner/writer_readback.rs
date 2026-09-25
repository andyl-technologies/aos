//! Writer-held typed Cache replay for a future joined owner receipt.
//!
//! The four protected journals stay open through the callback. This module
//! samples time without advancing the clock journal: its normal update path
//! drops and reopens that writer, which would break the claimed cut.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
#[cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;

use crate::journal::{
    CACHE_POLICY_HOLD_JOURNAL, CachePolicyHoldV1, Journal, JournalError, JournalLimits,
    RecordNamespace, RecoveryReport,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::root_read_only::ReadOnlyCacheClockV1;
use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY, CACHE_STATE_JOURNAL,
    CacheResidencyProtectedOwnerV1, MAXIMUM_AUTHORITY_RECORD_BYTES, cache_authority_journal_limits,
    cache_clock_journal_limits, cache_owner_scope, cache_state_journal_limits,
    complete_node_quota_digest_v2, decode_cache_clock_floor, recover_cache_replay_evidence,
    reject_legacy_cache_journals, select_project_physical_cache_head,
};
#[cfg(target_os = "linux")]
use crate::cache_residency::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, CacheOwnerLimitsV1, CacheOwnerReadbackChallengeV1,
    DormantCacheOwnerV1,
};
use crate::cache_residency::{
    CacheRecoveryLimitsV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyReplayValidatorV1,
};

/// Identifies the exact protected hold and complete quota envelope under four writers.
///
/// The value is diagnostic after the callback returns. It confers no Q04 or
/// physical Cache authority and cannot keep any journal writer alive itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheResidencyWriterReadbackV2 {
    /// Names the active hold matched to typed Cache replay.
    pub hold: CachePolicyHoldV1,
    /// Commits every validated node quota in canonical partition order.
    pub quota_digest: ObjectDigest,
    node_quotas: Vec<crate::cache_residency::NodeCacheQuotaV1>,
}

impl CacheResidencyWriterReadbackV2 {
    /// Returns every typed node quota used to derive the complete envelope.
    #[must_use]
    pub fn node_quotas(&self) -> &[crate::cache_residency::NodeCacheQuotaV1] {
        &self.node_quotas
    }
}

/// Runs an action while all four fixed Cache journal writers remain held.
///
/// The caller must acquire Controller and Source owners first. A physical
/// Cache owner may be acquired inside `action`, after these protected writers.
/// The action must not release an outer owner's custody or treat this local
/// result as an all-owner policy cut. No clock journal is advanced here.
///
/// # Errors
///
/// Rejects unsafe or changed names, a missing or changed hold, stale clock,
/// malformed authority, invalid typed history, or an action failure.
pub fn with_fixed_cache_writer_readback_v2<R>(
    owner_uid: u32,
    action: impl FnOnce(
        CacheResidencyWriterReadbackV2,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
    reject_legacy_cache_journals()?;
    let result = with_cache_writer_readback_at(
        Path::new(super::PROTECTED_CACHE_ROOT),
        owner_uid,
        |root, name, limits| Journal::open_protected_at_for_uid(root, name, limits, owner_uid),
        |journal, root, name, limits| {
            journal.require_protected_named_location(root, name, owner_uid, limits)
        },
        action,
    )?;
    reject_legacy_cache_journals()?;
    Ok(result)
}

/// Signs one joined Cache receipt while the four writers and physical flock overlap.
///
/// The trusted caller supplies the Cache-only private key, signer generation,
/// owner UID, and independently configured physical limits. This library API
/// does not load deployment credentials, transport the packet, or grant Q04.
/// The physical owner is acquired after the protected writers and retained
/// through their final name and byte-level checks.
///
/// # Errors
///
/// Rejects any protected replay, quota-to-limit, physical custody, manifest,
/// or signature failure. Physical failures are reported as stale authority.
#[cfg(target_os = "linux")]
pub fn sign_fixed_cache_owner_readback_v2(
    owner_uid: u32,
    physical_limits: CacheOwnerLimitsV1,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheResidencyProtectedJournalErrorV1> {
    let (physical_owner, packet) = with_fixed_cache_writer_readback_v2(owner_uid, |readback| {
        let derived = CacheOwnerLimitsV1::from_node_quotas(
            physical_limits.maximum_memory_bytes,
            readback.node_quotas().iter().copied(),
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if derived != physical_limits {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let physical_owner = DormantCacheOwnerV1::open_fixed(physical_limits)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let snapshot = physical_owner
            .held_snapshot()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let packet = snapshot
            .sign_closed_readback_v2(
                readback.hold,
                readback.quota_digest,
                challenge,
                signer_generation,
                signing_key,
            )
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        // Keep the physical owner in the result until the protected post-check.
        Ok((physical_owner, packet))
    })?;
    drop(physical_owner);
    Ok(packet)
}

fn with_cache_writer_readback_at<R>(
    root: &Path,
    owner_uid: u32,
    open: impl Fn(&Path, &str, JournalLimits) -> Result<(Journal, RecoveryReport), JournalError>,
    check: impl Fn(&Journal, &Path, &str, JournalLimits) -> Result<(), JournalError>,
    action: impl FnOnce(
        CacheResidencyWriterReadbackV2,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
    let (mut clock, _) = open(root, CACHE_CLOCK_JOURNAL, cache_clock_journal_limits())?;
    let floor = {
        let authority = clock.claim_protected_authority(RecordNamespace::DesiredState)?;
        authority
            .get(CACHE_CLOCK_KEY)?
            .map(decode_cache_clock_floor)
            .transpose()?
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
    };
    if floor.owner_scope != cache_owner_scope() {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    let time = Arc::new(ReadOnlyCacheClockV1 { floor });

    let (mut authority_journal, _) = open(
        root,
        CACHE_AUTHORITY_JOURNAL,
        cache_authority_journal_limits(),
    )?;
    let (state, _) = open(root, CACHE_STATE_JOURNAL, cache_state_journal_limits())?;
    let (mut hold_journal, _) = open(
        root,
        CACHE_POLICY_HOLD_JOURNAL,
        Journal::cache_policy_hold_limits(),
    )?;
    let clock_witness = clock.protected_writer_name_witness()?;
    let authority_witness = authority_journal.protected_writer_name_witness()?;
    let state_witness = state.protected_writer_name_witness()?;
    let hold_witness = hold_journal.protected_writer_name_witness()?;
    let evidence = recover_cache_replay_evidence(
        &mut authority_journal,
        cache_owner_scope(),
        CacheRecoveryLimitsV1::default(),
    )?;
    let (_validator, authority) = CacheResidencyReplayValidatorV1::from_protected_authority(
        authority_journal,
        cache_owner_scope(),
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        evidence,
        CacheRecoveryLimitsV1::default(),
        time,
    )?;

    let hold = hold_journal.held_cache_policy_hold_for_writer()?;
    let mut owner = CacheResidencyProtectedOwnerV1 {
        state_journal: Some(state),
        authority,
        owner_uid,
    };
    let inventories = owner.reconstructed_partitions()?;
    let node_quotas: Vec<_> = inventories
        .iter()
        .map(|inventory| inventory.global.node_quota)
        .collect();
    let quota_digest = complete_node_quota_digest_v2(node_quotas.clone())?;
    let selected = select_project_physical_cache_head(hold.project(), inventories)?;
    if selected.partition().digest() != hold.partition() || selected.head() != hold.cache_head() {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }

    let check_all = || -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        check(
            &clock,
            root,
            CACHE_CLOCK_JOURNAL,
            cache_clock_journal_limits(),
        )?;
        clock.validate_protected_writer_name_witness(&clock_witness)?;
        owner.authority.check_named_location(|journal| {
            check(
                journal,
                root,
                CACHE_AUTHORITY_JOURNAL,
                cache_authority_journal_limits(),
            )?;
            journal.validate_protected_writer_name_witness(&authority_witness)
        })?;
        let state = owner
            .state_journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        check(
            state,
            root,
            CACHE_STATE_JOURNAL,
            cache_state_journal_limits(),
        )?;
        state.validate_protected_writer_name_witness(&state_witness)?;
        check(
            &hold_journal,
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
        )?;
        hold_journal.validate_protected_writer_name_witness(&hold_witness)?;
        Ok(())
    };
    check_all()?;
    let result = action(CacheResidencyWriterReadbackV2 {
        hold,
        quota_digest,
        node_quotas,
    })?;
    check_all()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn with_fixture<R>(
        root: &Path,
        uid: u32,
        action: impl FnOnce(
            CacheResidencyWriterReadbackV2,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        with_cache_writer_readback_at(
            root,
            uid,
            |root, name, limits| Journal::open_protected_at_uid(root, name, limits, uid),
            |journal, root, name, limits| {
                journal.require_protected_named_location_at_uid_for_test(root, name, uid, limits)
            },
            action,
        )
    }

    #[test]
    fn typed_cut_retains_all_four_writers_and_matches_the_held_head() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let observed = with_fixture(directory.path(), uid, |readback| {
            for (name, limits) in [
                (CACHE_CLOCK_JOURNAL, cache_clock_journal_limits()),
                (CACHE_AUTHORITY_JOURNAL, cache_authority_journal_limits()),
                (CACHE_STATE_JOURNAL, cache_state_journal_limits()),
                (
                    CACHE_POLICY_HOLD_JOURNAL,
                    Journal::cache_policy_hold_limits(),
                ),
            ] {
                assert!(matches!(
                    Journal::open_protected_at_uid(directory.path(), name, limits, uid),
                    Err(JournalError::AlreadyLocked)
                ));
            }
            Ok(readback)
        })
        .expect("writer-held typed replay");
        assert_eq!(observed.hold, expected);
        assert_ne!(observed.quota_digest.as_bytes(), &[0; 32]);
    }

    #[test]
    fn identical_inode_replacements_fail_for_every_journal_and_lock_name() {
        for name in [
            CACHE_CLOCK_JOURNAL,
            CACHE_AUTHORITY_JOURNAL,
            CACHE_STATE_JOURNAL,
            CACHE_POLICY_HOLD_JOURNAL,
        ] {
            for suffix in ["", ".lock"] {
                let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
                let named = directory.path().join(format!("{name}{suffix}"));
                let retained = directory.path().join(format!("{name}{suffix}.retained"));
                let outcome = with_fixture(directory.path(), uid, |_| {
                    fs::rename(&named, &retained).expect("retain locked inode");
                    fs::copy(&retained, &named).expect("replace with identical bytes");
                    Ok(())
                });
                assert!(outcome.is_err(), "accepted replacement of {name}{suffix}");
            }
        }
    }

    #[test]
    fn directory_alias_and_unlocked_writes_fail_after_typed_replay() {
        let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
        let root = directory.path().to_path_buf();
        let retained = root.with_extension("retained");
        let outcome = with_fixture(&root, uid, |_| {
            fs::rename(&root, &retained).expect("move held directory");
            fs::create_dir(&root).expect("replace directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("private replacement directory");
            Ok(())
        });
        assert!(outcome.is_err());
        fs::remove_dir(&root).expect("remove empty replacement directory");
        fs::rename(&retained, &root).expect("restore temporary fixture path");

        for name in [
            CACHE_CLOCK_JOURNAL,
            CACHE_AUTHORITY_JOURNAL,
            CACHE_STATE_JOURNAL,
            CACHE_POLICY_HOLD_JOURNAL,
        ] {
            let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
            let outcome = with_fixture(directory.path(), uid, |_| {
                OpenOptions::new()
                    .append(true)
                    .open(directory.path().join(name))
                    .expect("open journal beside its writer")
                    .write_all(b"foreign append")
                    .expect("change journal bytes");
                Ok(())
            });
            assert!(outcome.is_err(), "accepted changed {name} bytes");
        }
    }
}
