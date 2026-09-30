//! Prospective genuine Session custody kept outside the mutable Ready ledger.
//!
//! The public surface reports observations only. The private original bridge
//! can authenticate retained archive cuts and append exact metadata through the
//! same held writer; it cannot lend Ready, sign, send or run a backend. Native3
//! intermediate associations remain unsupported.

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1;

use super::{
    FixedProviderOwnerStateV1, FixedProviderOwnerV1, ProviderSourceProviderOwnerV1,
    configured_ledger,
};
use crate::{
    ProviderLedgerError,
    recovery::native_profile::{self, RecoveredNativeProfileV1, UnresolvedNativeProofV1},
    state::ProtectedProviderConfigurationV1,
};

/// Reports only counts from an exact currently held mixed structural snapshot.
///
/// A named original observation additionally checks its archive/current bridge.
/// Counts still grant no effect, signing, send, FD, cleanup, floor credit or
/// Storage retirement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedProviderHeldReadOnlyObservationV1 {
    /// Counts complete retained owner rows, including exact archive-bearing rows.
    pub owner_records: usize,
    /// Counts full typed held8 completions, never projected legacy outers.
    pub held_completions: usize,
    /// Counts all canonical associated physical legacy/native floors.
    ///
    /// This count does not prove original admission or remaining funded geometry.
    pub capacity_floors: usize,
}

pub(super) struct HeldReadOnlyV1 {
    pub(super) session: CurrentProviderIngressSessionV1,
    pub(super) publication: Vec<u8>,
    configuration: Option<ProtectedProviderConfigurationV1>,
    profile: Option<RecoveredNativeProfileV1>,
    snapshot: Option<ProtectedJournalSnapshot>,
    pub(super) original: Option<super::original_journal::OriginalJournalV5>,
}

impl HeldReadOnlyV1 {
    /// Retains the same genuine Session after a first-birth runtime is parked.
    pub(super) fn retain_original_v5(
        session: CurrentProviderIngressSessionV1,
        publication: Vec<u8>,
        original: super::original_journal::OriginalJournalV5,
    ) -> Self {
        Self {
            session,
            publication,
            configuration: None,
            profile: None,
            snapshot: None,
            original: Some(original),
        }
    }
}

impl FixedProviderOwnerV1 {
    pub(super) fn select_held_readonly(
        &mut self,
        security: ProviderSourceProviderOwnerV1,
        publication: Vec<u8>,
    ) -> Result<Option<(ProviderSourceProviderOwnerV1, Vec<u8>)>, ProviderLedgerError> {
        let claim = self
            .journal
            .as_mut()
            .ok_or(ProviderLedgerError::RuntimePoisoned)
            .and_then(|journal| {
                journal
                    .claim_source_provider_held_readonly_v1()
                    .map_err(Into::into)
            });
        let journal = match claim {
            Ok(journal) => journal,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: publication,
                });
                return Err(error);
            }
        };
        let selected = (|| {
            let held = journal
                .security_view()?
                .records()?
                .any(|(_, value)| native_profile::is_held(value)
                    || value.get(8..10) == Some(&9_u16.to_be_bytes()));
            let native = journal.capacity_records()?.iter().any(|row| {
                row.value()
                    .is_some_and(|value| matches!(value.get(8..10), Some([0, 3]) | Some([0, 5])))
            });
            Ok::<_, ProviderLedgerError>(held || native)
        })();
        match selected {
            Ok(false) => return Ok(Some((security, publication))),
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: publication,
                });
                return Err(error);
            }
            Ok(true) => {}
        }
        let handoff = match journal.session_handoff() {
            Ok(handoff) => handoff,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: publication,
                });
                return Err(error.into());
            }
        };
        let session = match security.try_into_fixed_ledger_session(handoff) {
            Ok(session) => session,
            Err((security, error)) => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: publication,
                });
                return Err(error.into());
            }
        };
        self.state = Some(FixedProviderOwnerStateV1::HeldReadOnly(Box::new(
            HeldReadOnlyV1 {
                session,
                publication,
                configuration: None,
                profile: None,
                snapshot: None,
                original: None,
            },
        )));
        self.observe_held_readonly()?;
        Ok(None)
    }

    /// Revalidates real prospective custody and reports only mixed structural DATA.
    ///
    /// The same Journal, current Session/configuration, scoped physical snapshot,
    /// complete graph and complete floor identity association are checked before
    /// and after the observation. Funded geometry remains unresolved. Failures
    /// retain owning objects and never enter Ready.
    ///
    /// # Errors
    ///
    /// Rejects non-read-only state, changed physical/current custody or snapshot,
    /// malformed/ineligible legacy history, unsupported held associations,
    /// missing/orphan debt, or a changed complete readback.
    pub fn observe_held_readonly(
        &mut self,
    ) -> Result<FixedProviderHeldReadOnlyObservationV1, ProviderLedgerError> {
        let retained_original = matches!(self.state.as_ref(),
            Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) if held.original.is_some());
        if retained_original
            || self.journal.as_ref().is_some_and(|journal| journal.source_original_replay_required_v5())
        {
            return self.observe_original_journal_v5();
        }
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::InvalidTransition(
                "owner is not held read-only",
            ));
        };
        let journal = self
            .journal
            .as_mut()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_provider_held_readonly_v1()?;
        if let Some(snapshot) = &held.snapshot {
            journal.validate_snapshot(snapshot)?;
        } else {
            held.snapshot = Some(journal.snapshot()?);
        }
        // Store the genuine projection before fallible replay so no recovery
        // failure drops the captured configuration or prospective Session.
        held.configuration = Some(configured_ledger(&mut held.session, &held.publication)?);
        let configuration = held
            .configuration
            .as_ref()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let before = native_profile::recover(&journal, configuration)?;
        if held.profile.as_ref().is_some_and(|profile| {
            profile.records != before.records || profile.floor_ids != before.floor_ids
        }) {
            return Err(ProviderLedgerError::Equivocation);
        }
        held.profile = Some(before);
        held.configuration = Some(configured_ledger(&mut held.session, &held.publication)?);
        let after = native_profile::recover(
            &journal,
            held.configuration
                .as_ref()
                .ok_or(ProviderLedgerError::RuntimePoisoned)?,
        )?;
        let before = held
            .profile
            .as_ref()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if before.records != after.records
            || before.floor_ids != after.floor_ids
            || before.archive_eligibility != UnresolvedNativeProofV1::Unresolved
            || before.remaining_geometry != UnresolvedNativeProofV1::Unresolved
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        journal.validate_snapshot(
            held.snapshot
                .as_ref()
                .ok_or(ProviderLedgerError::RuntimePoisoned)?,
        )?;
        let observation = FixedProviderHeldReadOnlyObservationV1 {
            owner_records: after.records.len(),
            held_completions: after.held.len(),
            capacity_floors: after.floor_ids.len(),
        };
        held.profile = Some(after);
        Ok(observation)
    }
}
