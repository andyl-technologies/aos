//! Writer-held typed Cache replay, release, and V8 settlement.
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
#[cfg(target_os = "linux")]
use crate::policy_compiler::RootV8SettledGrantV1;

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
use crate::cache_residency::DormantCacheOwnerV1;
#[cfg(test)]
use crate::cache_residency::{
    CacheOwnerLimitsV1, CacheRecoveryLimitsV1, CacheResidencyReplayValidatorV1,
};

/// Identifies the exact protected hold and complete quota envelope under four writers.
///
/// The value is diagnostic after the callback returns. It confers no Q04 or
/// physical Cache authority and cannot keep any journal writer alive itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheResidencyWriterReadbackV2 {
    /// Names the active hold matched to typed Cache replay.
    hold: CachePolicyHoldV1,
    /// Names the uniquely selected project partition under the same writers.
    selected: super::CurrentProjectPhysicalCacheHeadV1,
    /// Commits every validated node quota in canonical partition order.
    quota_digest: ObjectDigest,
    node_quotas: Vec<crate::cache_residency::NodeCacheQuotaV1>,
}

/// Confirms that Cache cleared one exact pending release under retained custody.
///
/// Source may require this token before clearing its own pending marker. The
/// token is minted only after Cache's durable marker deletion and readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "linux")]
pub(crate) struct CacheV8SettledClearV1 {
    predecessor: ObjectDigest,
    epoch: u64,
    cache_released: ObjectDigest,
    settlement: ObjectDigest,
}

#[cfg(target_os = "linux")]
impl CacheV8SettledClearV1 {
    /// Checks that this Cache clear belongs to the same Root settlement.
    #[must_use]
    pub(crate) fn matches_grant(self, grant: RootV8SettledGrantV1) -> bool {
        self.predecessor == grant.predecessor()
            && self.epoch == grant.epoch()
            && self.cache_released == grant.cache_released()
            && self.settlement == grant.settlement()
    }
}

#[derive(Clone, Copy)]
#[cfg(target_os = "linux")]
enum CacheTerminalCutV1 {
    HeldReadback,
    HeldRelease,
    ReleasedReadback,
    ReleasedSettlement(RootV8SettledGrantV1),
}

#[cfg(target_os = "linux")]
impl CacheTerminalCutV1 {
    fn read(
        self,
        journal: &mut Journal,
    ) -> Result<(CachePolicyHoldV1, Option<CachePolicyHoldV1>, bool), crate::journal::JournalError>
    {
        match self {
            Self::HeldReadback | Self::HeldRelease => {
                Ok((journal.held_cache_policy_hold_for_writer()?, None, false))
            }
            Self::ReleasedReadback => {
                let (prior, released) = journal.v8_pending_cache_policy_release_for_writer()?;
                Ok((released, Some(prior), true))
            }
            Self::ReleasedSettlement(grant) => {
                let (prior, released, pending) =
                    journal.v8_cache_policy_settlement_state_for_writer(grant)?;
                Ok((released, Some(prior), pending))
            }
        }
    }
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

    /// Returns the unique project partition retained by this Cache callback.
    #[must_use]
    pub(crate) const fn selected(&self) -> super::CurrentProjectPhysicalCacheHeadV1 {
        self.selected
    }

    /// Returns every typed node quota used to derive the complete envelope.
    #[must_use]
    fn node_quotas(&self) -> &[crate::cache_residency::NodeCacheQuotaV1] {
        &self.node_quotas
    }
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
        self.with_held_cache_owner_readback_after_postflight_v3(physical, |readback| {
            action(readback).map(|value| (value, |value| Ok(value)))
        })
    }

    /// Runs a terminal observation after Cache postflight but before any writer drops.
    ///
    /// The first callback may open a Root-last observational flight and return
    /// a continuation. Cache then validates its clock, all named journals,
    /// hold, physical flock, and complete typed replay before calling that
    /// continuation under the same clock and hold writer guards. A caller
    /// must separately revalidate Controller and Source before sending a
    /// terminal ACK. Neither phase may dispatch effects or release owners.
    ///
    /// # Errors
    ///
    /// Rejects stale Cache custody, an incomplete first callback, or a failed
    /// terminal continuation. No continuation runs after Cache postflight fails.
    pub fn with_held_cache_owner_readback_after_postflight_v3<Prepared, Output, Finish>(
        &mut self,
        physical: &DormantCacheOwnerV1,
        inspect: impl FnOnce(
            &CacheResidencyWriterReadbackV2,
        )
            -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<Output, CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
    {
        self.with_cache_owner_terminal_cut(
            physical,
            |readback, _| {
                let (prepared, finish) = inspect(readback)?;
                Ok((prepared, finish, Ok))
            },
            CacheTerminalCutV1::HeldReadback,
            |value, _| Ok(value),
        )
        .map(|(value, _)| value)
    }

    /// Runs a final continuation and retires the exact Cache hold under its writer.
    ///
    /// The first callback and terminal continuation have the same ordering as
    /// v3. After Cache postflight, `finalize` runs with all four journal writers
    /// and the physical owner still held. A second postflight must pass before
    /// the already-open hold journal durably records the released phase and
    /// pending V8 settlement together. The returned released hold is read back
    /// from that same protected writer. The pending row fences another Cache
    /// hold until a future authenticated Root settlement clears it.
    /// This local primitive does not verify a Root receipt or open public Create.
    ///
    /// # Errors
    ///
    /// Rejects failed callbacks, stale Cache custody, changed physical state,
    /// or an unsuccessful durable release readback. A failed final callback
    /// leaves the hold active.
    pub(crate) fn with_held_cache_owner_terminal_and_release_v4<
        Prepared,
        Output,
        Final,
        Finish,
        Finalize,
    >(
        &mut self,
        physical: &DormantCacheOwnerV1,
        inspect: impl FnOnce(
            &CacheResidencyWriterReadbackV2,
        ) -> Result<
            (Prepared, Finish, Finalize),
            CacheResidencyProtectedJournalErrorV1,
        >,
    ) -> Result<(Final, CachePolicyHoldV1), CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
        Finalize: FnOnce(Output) -> Result<Final, CacheResidencyProtectedJournalErrorV1>,
    {
        self.with_cache_owner_terminal_cut(
            physical,
            |readback, _| inspect(readback),
            CacheTerminalCutV1::HeldRelease,
            |value, _| Ok(value),
        )
    }

    /// Replays an already released Cache hold under the same typed owner cut.
    ///
    /// This recovery path never commits a release. It verifies the released
    /// row, its pending V8 settlement, and complete Cache replay before the
    /// callback, then revalidates writer names, the exact pair, and physical
    /// custody afterward.
    /// Controller and Source are retained externally.
    ///
    /// # Errors
    ///
    /// Rejects a held or changed hold, stale Cache evidence, or failed callback.
    pub(crate) fn with_released_cache_owner_readback_v5<Prepared, Output, Finish>(
        &mut self,
        physical: &DormantCacheOwnerV1,
        inspect: impl FnOnce(
            &CacheResidencyWriterReadbackV2,
            CachePolicyHoldV1,
        )
            -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(Output, CachePolicyHoldV1), CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
    {
        self.with_cache_owner_terminal_cut(
            physical,
            |readback, historical_held| {
                let held = historical_held.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                let (prepared, finish) = inspect(readback, held)?;
                Ok((prepared, finish, Ok))
            },
            CacheTerminalCutV1::ReleasedReadback,
            |value, _| Ok(value),
        )
    }

    /// Clears a pending Cache V8 settlement under full typed and physical replay.
    ///
    /// The Controller must retain its own writer and Source custody while it
    /// couriers the peer-checked Root grant. Cache checks that grant against
    /// its exact released row, revalidates all writer names and physical
    /// custody after postflight, then deletes only AOSCPP08. `after_clear`
    /// runs with that writer still held, so Source can clear its marker without
    /// a new Cache hold appearing in between. An exact replay after a lost
    /// reply invokes the callback without another Cache commit.
    ///
    /// # Errors
    ///
    /// Rejects stale Cache replay or physical custody, a different Root
    /// settlement, a held row, or failed durable deletion and readback.
    pub(crate) fn with_cleared_v8_pending_cache_settlement_v1<R>(
        &mut self,
        physical: &DormantCacheOwnerV1,
        grant: RootV8SettledGrantV1,
        after_clear: impl FnOnce(
            CacheV8SettledClearV1,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        self.with_cache_owner_terminal_cut(
            physical,
            |_, _| Ok(((), Ok, Ok)),
            CacheTerminalCutV1::ReleasedSettlement(grant),
            |_, _| {
                after_clear(CacheV8SettledClearV1 {
                    predecessor: grant.predecessor(),
                    epoch: grant.epoch(),
                    cache_released: grant.cache_released(),
                    settlement: grant.settlement(),
                })
            },
        )
        .map(|(value, _)| value)
    }

    fn with_cache_owner_terminal_cut<Prepared, Output, Final, After, Finish, Finalize>(
        &mut self,
        physical: &DormantCacheOwnerV1,
        inspect: impl FnOnce(
            &CacheResidencyWriterReadbackV2,
            Option<CachePolicyHoldV1>,
        ) -> Result<
            (Prepared, Finish, Finalize),
            CacheResidencyProtectedJournalErrorV1,
        >,
        mode: CacheTerminalCutV1,
        after_commit: impl FnOnce(
            Final,
            CachePolicyHoldV1,
        ) -> Result<After, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(After, CachePolicyHoldV1), CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
        Finalize: FnOnce(Output) -> Result<Final, CacheResidencyProtectedJournalErrorV1>,
    {
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
        let (hold, historical_held, pending) = mode.read(&mut hold_journal)?;
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
            let selected = select_project_physical_cache_head(hold.project(), &inventories)?;
            if selected.partition().digest() != hold.partition()
                || selected.head() != hold.cache_head()
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            let readback = CacheResidencyWriterReadbackV2 {
                hold,
                selected,
                quota_digest,
                node_quotas,
            };
            if !physical_limits.matches_node_quotas(readback.node_quotas()) {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            physical_snapshot
                .revalidate()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            inspect(&readback, historical_held)
        });

        let revalidate = |hold_journal: &mut Journal, expected_pending: bool| {
            clock_guard.revalidate()?;
            self.check_held_writer_names(&state_witness, &authority_witness)?;
            hold_journal.require_protected_named_location(
                root,
                CACHE_POLICY_HOLD_JOURNAL,
                self.owner_uid,
                Journal::cache_policy_hold_limits(),
            )?;
            hold_journal.validate_protected_writer_name_witness(&hold_witness)?;
            let (current, prior, current_pending) = mode.read(hold_journal)?;
            if current != hold || prior != historical_held || current_pending != expected_pending {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            physical_snapshot
                .revalidate()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            reject_legacy_cache_journals()?;
            Ok::<(), CacheResidencyProtectedJournalErrorV1>(())
        };

        revalidate(&mut hold_journal, pending)?;
        let (prepared, finish, finalize) = result?;
        let outcome = finish(prepared);
        revalidate(&mut hold_journal, pending)?;
        let finalized = finalize(outcome?);
        let (value, row) = match mode {
            CacheTerminalCutV1::HeldRelease => {
                revalidate(&mut hold_journal, pending)?;
                let value = finalized?;
                let released = hold_journal.release_v8_held_cache_policy_hold_for_writer(hold)?;
                (value, released)
            }
            CacheTerminalCutV1::ReleasedSettlement(grant) => {
                revalidate(&mut hold_journal, pending)?;
                let value = finalized?;
                let released = hold_journal.clear_v8_pending_cache_settlement_for_writer(grant)?;
                (value, released)
            }
            CacheTerminalCutV1::HeldReadback | CacheTerminalCutV1::ReleasedReadback => {
                (finalized?, hold)
            }
        };
        let result = after_commit(value, row);
        if matches!(mode, CacheTerminalCutV1::ReleasedSettlement(_)) {
            revalidate(&mut hold_journal, false)?;
        }
        Ok((result?, row))
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
    with_cache_writer_readback_after_postflight_at(root, owner_uid, open, check, |readback| {
        action(readback).map(|value| (value, |value| Ok(value)))
    })
}

#[cfg(test)]
fn with_cache_writer_readback_after_postflight_at<Prepared, Output, Finish>(
    root: &Path,
    owner_uid: u32,
    open: impl Fn(&Path, &str, JournalLimits) -> Result<(Journal, RecoveryReport), JournalError>,
    check: impl Fn(&Journal, &Path, &str, JournalLimits) -> Result<(), JournalError>,
    action: impl FnOnce(
        CacheResidencyWriterReadbackV2,
    ) -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
) -> Result<Output, CacheResidencyProtectedJournalErrorV1>
where
    Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
{
    with_cache_writer_terminal_cut_at(root, owner_uid, open, check, action, Ok, false)
        .map(|(value, _)| value)
}

#[cfg(test)]
fn with_cache_writer_terminal_cut_at<Prepared, Output, Final, Finish>(
    root: &Path,
    owner_uid: u32,
    open: impl Fn(&Path, &str, JournalLimits) -> Result<(Journal, RecoveryReport), JournalError>,
    check: impl Fn(&Journal, &Path, &str, JournalLimits) -> Result<(), JournalError>,
    action: impl FnOnce(
        CacheResidencyWriterReadbackV2,
    ) -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
    finalize: impl FnOnce(Output) -> Result<Final, CacheResidencyProtectedJournalErrorV1>,
    retire_hold: bool,
) -> Result<(Final, Option<CachePolicyHoldV1>), CacheResidencyProtectedJournalErrorV1>
where
    Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
{
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
        project_usage: super::project_usage::CacheProjectUsageProgressV1::default(),
    };
    let inventories = owner.reconstructed_partitions()?;
    let node_quotas: Vec<_> = inventories
        .iter()
        .map(|inventory| inventory.global.node_quota)
        .collect();
    let quota_digest = complete_node_quota_digest_v2(node_quotas.clone())?;
    let selected = select_project_physical_cache_head(hold.project(), &inventories)?;
    if selected.partition().digest() != hold.partition() || selected.head() != hold.cache_head() {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }

    let check_all = |hold_journal: &Journal| -> Result<(), CacheResidencyProtectedJournalErrorV1> {
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
            hold_journal,
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
        )?;
        hold_journal.validate_protected_writer_name_witness(&hold_witness)?;
        Ok(())
    };
    check_all(&hold_journal)?;
    let result = action(CacheResidencyWriterReadbackV2 {
        hold,
        selected,
        quota_digest,
        node_quotas,
    });
    check_all(&hold_journal)?;
    let (prepared, finish) = result?;
    let outcome = finish(prepared);
    check_all(&hold_journal)?;
    let finalized = finalize(outcome?);
    if retire_hold {
        check_all(&hold_journal)?;
        if hold_journal.held_cache_policy_hold_for_writer()? != hold {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let value = finalized?;
        let released = hold_journal.release_v8_held_cache_policy_hold_for_writer(hold)?;
        Ok((value, Some(released)))
    } else {
        finalized.map(|value| (value, None))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
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

    fn with_fixture_after_postflight<Prepared, Output, Finish>(
        root: &Path,
        uid: u32,
        action: impl FnOnce(
            CacheResidencyWriterReadbackV2,
        )
            -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<Output, CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
    {
        with_cache_writer_readback_after_postflight_at(
            root,
            uid,
            |root, name, limits| Journal::open_protected_at_uid(root, name, limits, uid),
            |journal, root, name, limits| {
                journal.require_protected_named_location_at_uid_for_test(root, name, uid, limits)
            },
            action,
        )
    }

    fn with_fixture_after_final<Prepared, Output, Final, Finish>(
        root: &Path,
        uid: u32,
        action: impl FnOnce(
            CacheResidencyWriterReadbackV2,
        )
            -> Result<(Prepared, Finish), CacheResidencyProtectedJournalErrorV1>,
        finalize: impl FnOnce(Output) -> Result<Final, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(Final, CachePolicyHoldV1), CacheResidencyProtectedJournalErrorV1>
    where
        Finish: FnOnce(Prepared) -> Result<Output, CacheResidencyProtectedJournalErrorV1>,
    {
        let (value, released) = with_cache_writer_terminal_cut_at(
            root,
            uid,
            |root, name, limits| Journal::open_protected_at_uid(root, name, limits, uid),
            |journal, root, name, limits| {
                journal.require_protected_named_location_at_uid_for_test(root, name, uid, limits)
            },
            action,
            finalize,
            true,
        )?;
        Ok((
            value,
            released.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?,
        ))
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
        assert_eq!(observed.selected.project(), expected.project());
        assert_eq!(observed.selected.partition().digest(), expected.partition());
        assert_eq!(observed.selected.head(), expected.cache_head());
        assert_ne!(observed.quota_digest.as_bytes(), &[0; 32]);
    }

    #[test]
    fn root_writer_can_be_acquired_after_all_cache_writers() {
        let (cache_root, uid, _) = super::super::tests::live_cache_hold_fixture();
        let root = tempfile::tempdir().expect("Root journal fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private Root directory");

        with_fixture(cache_root.path(), uid, |_| {
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
                    Journal::open_protected_at_uid(cache_root.path(), name, limits, uid),
                    Err(JournalError::AlreadyLocked)
                ));
            }
            let (_root_writer, _) = Journal::open_protected_at_uid(
                root.path(),
                "root.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("Root writer acquired last");
            Ok(())
        })
        .expect("Root-last nested callback");
    }

    #[test]
    fn terminal_continuation_keeps_all_cache_writers_after_postflight() {
        let (cache_root, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let root = tempfile::tempdir().expect("Root journal fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private Root directory");

        let observed = with_fixture_after_postflight(cache_root.path(), uid, |readback| {
            Ok((readback, |readback: CacheResidencyWriterReadbackV2| {
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
                        Journal::open_protected_at_uid(cache_root.path(), name, limits, uid),
                        Err(JournalError::AlreadyLocked)
                    ));
                }
                let (_root_writer, _) = Journal::open_protected_at_uid(
                    root.path(),
                    "root.journal",
                    JournalLimits::default(),
                    uid,
                )
                .expect("Root acquired last under Cache postflight guards");
                Ok(readback)
            }))
        })
        .expect("terminal Cache continuation");
        assert_eq!(observed.hold(), expected);
    }

    #[test]
    fn final_continuation_retires_exact_hold_after_cache_postflight() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let stage = Cell::new(0);

        let (observed, released) = with_fixture_after_final(
            directory.path(),
            uid,
            |readback| {
                assert_eq!(stage.get(), 0);
                stage.set(1);
                Ok((readback, |readback: CacheResidencyWriterReadbackV2| {
                    assert_eq!(stage.get(), 1);
                    stage.set(2);
                    Ok(readback)
                }))
            },
            |readback| {
                assert_eq!(stage.get(), 2);
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
                assert!(matches!(
                    Journal::read_cache_policy_hold_at(directory.path(), uid),
                    Err(JournalError::AlreadyLocked)
                ));
                stage.set(3);
                Ok(readback)
            },
        )
        .expect("final Cache continuation and release");

        assert_eq!(stage.get(), 3);
        assert_eq!(observed.hold(), expected);
        assert!(!released.is_held());
        assert_eq!(released.project(), expected.project());
        assert_eq!(released.partition(), expected.partition());
        assert_eq!(released.cache_head(), expected.cache_head());
        assert_eq!(released.binding(), expected.binding());
        assert_eq!(released.epoch(), expected.epoch());

        let replayed = Journal::read_cache_policy_hold_at(directory.path(), uid)
            .expect("cold replay of released hold")
            .expect("released phase retained");
        assert_eq!(released, replayed);
        assert_eq!(
            released.record_digest().unwrap(),
            replayed.record_digest().unwrap()
        );
        assert_eq!(
            Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid)
                .expect("V8 pending Cache settlement"),
            (expected, released)
        );
    }

    #[test]
    fn failed_cache_postflight_suppresses_final_continuation_and_release() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let named = directory.path().join(format!("{CACHE_STATE_JOURNAL}.lock"));
        let retained = directory
            .path()
            .join(format!("{CACHE_STATE_JOURNAL}.lock.retained"));
        let finished = Cell::new(false);
        let finalized = Cell::new(false);

        let result = with_fixture_after_final(
            directory.path(),
            uid,
            |_| {
                fs::rename(&named, &retained).expect("retain state lock inode");
                fs::copy(&retained, &named).expect("replace state lock name");
                Ok(((), |_| {
                    finished.set(true);
                    Ok(())
                }))
            },
            |_| {
                finalized.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!finished.get());
        assert!(!finalized.get());
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("hold replay after failed postflight"),
            Some(expected),
        );
    }

    #[test]
    fn failed_final_continuation_preserves_the_held_phase() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();

        let result = with_fixture_after_final(
            directory.path(),
            uid,
            |_| Ok(((), |_| Ok(()))),
            |_| -> Result<(), _> { Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord) },
        );

        assert!(matches!(
            result,
            Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        ));
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("hold replay after failed final continuation"),
            Some(expected),
        );
    }

    #[test]
    fn ambiguous_controller_floor_after_root_release_keeps_cache_held() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let root_released = Cell::new(false);

        let result = with_fixture_after_final(
            directory.path(),
            uid,
            |_| {
                Ok(((), |_| {
                    root_released.set(true);
                    Ok(())
                }))
            },
            |_| -> Result<(), _> {
                assert!(root_released.get());
                Err(JournalError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Controller floor reply lost",
                ))
                .into())
            },
        );

        assert!(result.is_err());
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("hold replay after ambiguous floor"),
            Some(expected),
        );
        assert!(Journal::read_v8_pending_cache_policy_release_at(directory.path(), uid).is_err());
    }

    #[test]
    fn timed_out_root_final_continuation_keeps_cache_held() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();

        let result = with_fixture_after_final(
            directory.path(),
            uid,
            |_| Ok(((), |_| Ok(()))),
            |_| -> Result<(), _> {
                Err(JournalError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Root final command timed out",
                ))
                .into())
            },
        );

        assert!(result.is_err());
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("hold replay after Root timeout"),
            Some(expected),
        );
    }

    #[test]
    fn changed_writer_during_final_continuation_blocks_release() {
        let (directory, uid, expected) = super::super::tests::live_cache_hold_fixture();
        let named = directory.path().join(format!("{CACHE_STATE_JOURNAL}.lock"));
        let retained = directory
            .path()
            .join(format!("{CACHE_STATE_JOURNAL}.lock.retained"));

        let result = with_fixture_after_final(
            directory.path(),
            uid,
            |_| Ok(((), |_| Ok(()))),
            |_| {
                fs::rename(&named, &retained).expect("retain state lock inode");
                fs::copy(&retained, &named).expect("replace state lock name");
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid)
                .expect("hold replay after final postflight failure"),
            Some(expected),
        );
    }

    #[test]
    fn changed_cache_writer_name_suppresses_terminal_continuation() {
        let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
        let named = directory
            .path()
            .join(format!("{CACHE_POLICY_HOLD_JOURNAL}.lock"));
        let retained = directory
            .path()
            .join(format!("{CACHE_POLICY_HOLD_JOURNAL}.lock.retained"));
        let invoked = Cell::new(false);

        let outcome = with_fixture_after_postflight(directory.path(), uid, |_| {
            fs::rename(&named, &retained).expect("retain locked inode");
            fs::copy(&retained, &named).expect("replace with identical lock bytes");
            Ok(((), |_| {
                invoked.set(true);
                Ok(())
            }))
        });
        assert!(outcome.is_err());
        assert!(!invoked.get());
    }

    #[test]
    fn terminal_error_still_checks_all_cache_writer_names() {
        let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
        let named = directory.path().join(format!("{CACHE_CLOCK_JOURNAL}.lock"));
        let retained = directory
            .path()
            .join(format!("{CACHE_CLOCK_JOURNAL}.lock.retained"));

        let outcome = with_fixture_after_postflight(directory.path(), uid, |_| {
            Ok(((), |_| -> Result<(), _> {
                fs::rename(&named, &retained).expect("retain locked inode");
                fs::copy(&retained, &named).expect("replace with identical lock bytes");
                Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
            }))
        });
        assert!(matches!(
            outcome,
            Err(CacheResidencyProtectedJournalErrorV1::Journal(_))
        ));
    }

    #[test]
    fn writer_names_are_postchecked_when_the_nested_action_fails() {
        let (directory, uid, _) = super::super::tests::live_cache_hold_fixture();
        let named = directory.path().join(format!("{CACHE_STATE_JOURNAL}.lock"));
        let retained = directory
            .path()
            .join(format!("{CACHE_STATE_JOURNAL}.lock.retained"));
        let outcome = with_fixture(directory.path(), uid, |_| -> Result<(), _> {
            fs::rename(&named, &retained).expect("retain locked inode");
            fs::copy(&retained, &named).expect("replace with identical lock bytes");
            Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        });
        assert!(matches!(
            outcome,
            Err(CacheResidencyProtectedJournalErrorV1::Journal(_))
        ));
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
        assert!(limits.matches_node_quotas(readback.node_quotas()));

        let different = CacheOwnerLimitsV1 {
            maximum_disk_bytes: limits.maximum_disk_bytes + 1,
            ..limits
        };
        assert!(!different.matches_node_quotas(readback.node_quotas()));
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
