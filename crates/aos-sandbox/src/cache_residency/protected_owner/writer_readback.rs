//! Writer-held typed Cache replay for a future joined owner receipt.
//!
//! The four protected journals stay open through the callback. This module
//! samples time without advancing the clock journal: its normal update path
//! drops and reopens that writer, which would break the claimed cut.

use std::path::Path;
#[cfg(any(test, target_os = "linux"))]
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;

use crate::journal::{
    CACHE_POLICY_HOLD_JOURNAL, CachePolicyHoldV1, Journal, ProtectedWriterNameWitness,
};
#[cfg(test)]
use crate::journal::{JournalError, JournalLimits, RecordNamespace, RecoveryReport};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

#[cfg(test)]
use super::root_read_only::ReadOnlyCacheClockV1;
use super::{
    CACHE_AUTHORITY_JOURNAL, CACHE_STATE_JOURNAL, CacheResidencyProtectedOwnerV1,
    cache_authority_journal_limits, cache_state_journal_limits, complete_node_quota_digest_v2,
    reject_legacy_cache_journals, select_project_physical_cache_head,
};
#[cfg(test)]
use super::{
    CACHE_CLOCK_JOURNAL, CACHE_CLOCK_KEY, MAXIMUM_AUTHORITY_RECORD_BYTES,
    cache_clock_journal_limits, cache_owner_scope, decode_cache_clock_floor,
    recover_cache_replay_evidence,
};
use crate::cache_residency::CacheResidencyProtectedJournalErrorV1;
#[cfg(target_os = "linux")]
use crate::cache_residency::{CacheOwnerLimitsV1, DormantCacheOwnerV1};
#[cfg(test)]
use crate::cache_residency::{CacheRecoveryLimitsV1, CacheResidencyReplayValidatorV1};

/// Identifies the exact protected hold and complete quota envelope under four writers.
///
/// The value is diagnostic after the callback returns. It confers no Q04 or
/// physical Cache authority and cannot keep any journal writer alive itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheResidencyWriterReadbackV2 {
    /// Names the active hold matched to typed Cache replay.
    hold: CachePolicyHoldV1,
    /// Commits every validated node quota in canonical partition order.
    quota_digest: ObjectDigest,
    node_quotas: Vec<crate::cache_residency::NodeCacheQuotaV1>,
}

impl CacheResidencyWriterReadbackV2 {
    /// Returns the exact active hold matched to typed protected Cache replay.
    #[must_use]
    pub const fn hold(&self) -> CachePolicyHoldV1 {
        self.hold
    }

    /// Returns the complete, canonically ordered node quota commitment.
    #[must_use]
    pub const fn quota_digest(&self) -> ObjectDigest {
        self.quota_digest
    }

    /// Returns every typed node quota used to derive the complete envelope.
    #[must_use]
    fn node_quotas(&self) -> &[crate::cache_residency::NodeCacheQuotaV1] {
        &self.node_quotas
    }
}

#[cfg(target_os = "linux")]
fn validate_physical_limits(
    readback: &CacheResidencyWriterReadbackV2,
    physical_limits: CacheOwnerLimitsV1,
) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
    let derived = CacheOwnerLimitsV1::from_node_quotas(
        physical_limits.maximum_memory_bytes,
        readback.node_quotas().iter().copied(),
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if derived != physical_limits {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl CacheResidencyProtectedOwnerV1 {
    /// Runs an action under the resident protected writers and physical flock.
    ///
    /// The caller must already hold the Controller and source-domain owners if
    /// it needs their currentness. This Cache-local callback does not establish
    /// a root CAS, authorize Q04, or return a signed packet. The clock writer
    /// is frozen for the callback, so a time refresh cannot reopen its inode.
    /// The action must remain observational and must not dispatch an effect.
    ///
    /// # Errors
    ///
    /// Rejects changed protected names, a missing or stale hold, invalid typed
    /// replay, a quota mismatch, or changed physical custody or manifest.
    pub fn with_held_cache_owner_readback_v2<R>(
        &mut self,
        physical: &DormantCacheOwnerV1,
        action: impl FnOnce(
            &CacheResidencyWriterReadbackV2,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        reject_legacy_cache_journals()?;
        let clock = Arc::clone(
            self.clock
                .as_ref()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?,
        );
        let clock_guard = clock.hold_writer_for_readback()?;
        let root = Path::new(super::PROTECTED_CACHE_ROOT);
        let (mut hold_journal, _) = Journal::open_protected_at_for_uid(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            self.owner_uid,
        )?;
        let hold_witness = hold_journal.protected_writer_name_witness()?;
        let hold = hold_journal.held_cache_policy_hold_for_writer()?;
        let state_witness = self
            .state_journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
            .protected_writer_name_witness()?;
        let authority_witness = self.authority.writer_name_witness()?;
        let physical_snapshot = physical
            .held_snapshot()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if physical_snapshot.owner_uid() != self.owner_uid {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let physical_limits = physical.limits();
        clock_guard.revalidate()?;
        self.check_held_writer_names(&state_witness, &authority_witness)?;
        hold_journal.require_protected_named_location(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            self.owner_uid,
            Journal::cache_policy_hold_limits(),
        )?;
        hold_journal.validate_protected_writer_name_witness(&hold_witness)?;

        let result = self.with_reconstructed_partitions(|inventories| {
            let node_quotas: Vec<_> = inventories
                .iter()
                .map(|inventory| inventory.global.node_quota)
                .collect();
            let quota_digest = complete_node_quota_digest_v2(node_quotas.clone())?;
            let selected = select_project_physical_cache_head(hold.project(), inventories)?;
            if selected.partition().digest() != hold.partition()
                || selected.head() != hold.cache_head()
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            let readback = CacheResidencyWriterReadbackV2 {
                hold,
                quota_digest,
                node_quotas,
            };
            validate_physical_limits(&readback, physical_limits)?;
            physical_snapshot
                .revalidate()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            action(&readback)
        });

        clock_guard.revalidate()?;
        self.check_held_writer_names(&state_witness, &authority_witness)?;
        hold_journal.require_protected_named_location(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            self.owner_uid,
            Journal::cache_policy_hold_limits(),
        )?;
        hold_journal.validate_protected_writer_name_witness(&hold_witness)?;
        if hold_journal.held_cache_policy_hold_for_writer()? != hold {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        physical_snapshot
            .revalidate()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        reject_legacy_cache_journals()?;
        result
    }

    fn check_held_writer_names(
        &self,
        state_witness: &ProtectedWriterNameWitness,
        authority_witness: &ProtectedWriterNameWitness,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let root = Path::new(super::PROTECTED_CACHE_ROOT);
        let state = self
            .state_journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        state.require_protected_named_location(
            root,
            CACHE_STATE_JOURNAL,
            self.owner_uid,
            cache_state_journal_limits(),
        )?;
        state.validate_protected_writer_name_witness(state_witness)?;
        self.authority.check_named_location(|journal| {
            journal.require_protected_named_location(
                root,
                CACHE_AUTHORITY_JOURNAL,
                self.owner_uid,
                cache_authority_journal_limits(),
            )?;
            journal.validate_protected_writer_name_witness(authority_witness)
        })?;
        Ok(())
    }
}

#[cfg(test)]
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
        clock: None,
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
    fn held_cut_requires_the_complete_physical_envelope() {
        let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
        let readback = with_fixture(directory.path(), uid, Ok).expect("typed Cache cut");
        let limits = CacheOwnerLimitsV1::from_node_quotas(
            1024 * 1024,
            readback.node_quotas().iter().copied(),
        )
        .expect("complete physical limits");
        validate_physical_limits(&readback, limits).expect("same complete envelope");

        let different = CacheOwnerLimitsV1 {
            maximum_disk_bytes: limits.maximum_disk_bytes + 1,
            ..limits
        };
        assert!(validate_physical_limits(&readback, different).is_err());
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
