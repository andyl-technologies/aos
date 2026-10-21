//! Keeps startup's native authority checks between sole canonical chain stages.

use super::super::credential_authority::StartupCredentialAuthorityV1;
use crate::native::PolicyNativeJournalErrorV1;
use aos_sandbox_protocol::policy_data::binding_v2::{
    BindingDataErrorV1, HOLD_KEY, RETIRED_EFFECT_ACK_KEY, ROOT_BINDING_HEAD_KEY,
    RootBindingChainDataV2, RootBindingHoldV1, current_hold_v1,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum StartupBindingGuardErrorV1 {
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    #[error(transparent)]
    Data(#[from] BindingDataErrorV1),
}

pub(super) fn ensure_root_binding_unheld_v1(
    authority: &StartupCredentialAuthorityV1<'_, '_, '_>,
) -> Result<(), StartupBindingGuardErrorV1> {
    if current_binding_hold_data_v1(authority)?.is_some_and(|hold| hold.held)
        || authority.get(RETIRED_EFFECT_ACK_KEY)?.is_some()
    {
        return Err(BindingDataErrorV1::UnauthenticatedCandidate.into());
    }
    Ok(())
}

// Both old callers finish the same inner chain before the independent outer
// hold read. Only the mutation caller subsequently checks the retired ACK.
fn current_binding_hold_data_v1(
    authority: &StartupCredentialAuthorityV1<'_, '_, '_>,
) -> Result<Option<RootBindingHoldV1>, StartupBindingGuardErrorV1> {
    let mut chain = RootBindingChainDataV2::from_records_v2(authority.records()?)?;
    chain.require_proof_records_v2(authority.records()?)?;
    chain.require_ordered_v2()?;
    let (head, next, count) = chain.require_head_v2(authority.get(ROOT_BINDING_HEAD_KEY)?)?;
    let held = current_hold_v1(authority.get(HOLD_KEY)?, head, next, count)?;
    chain.require_hold_issuer_v2(held)?;
    // The former inner chain helper ended before the outer hold/ACK reads.
    drop(chain);
    Ok(current_hold_v1(
        authority.get(HOLD_KEY)?,
        head,
        next,
        count,
    )?)
}

/// Preserves one startup binding read's actual entry, native or DATA refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootStartupBindingReadErrorV1 {
    /// Retains the actual startup entry or its same-owner names marker.
    #[error(transparent)]
    Startup(#[from] super::super::RootStartupJournalErrorV1),
    /// Owns the original native namespace or historical-state refusal.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Rejects a malformed canonical binding chain or hold.
    #[error(transparent)]
    Data(#[from] BindingDataErrorV1),
}

impl super::super::RootStartupJournalOriginalV1 {
    /// Reads this held startup writer's unresolved binding before credentials.
    ///
    /// The same entry, DesiredState namespace claim and staged canonical chain
    /// checks precede the independent outer hold read. This read cannot issue
    /// an append gate or interpret missing selected finance as ordinary purpose.
    ///
    /// # Errors
    /// Preserves native entry, namespace and canonical binding-history refusal.
    /// Names or absent custody remain boundary markers on this resident owner.
    pub fn read_binding_hold_data_v1(
        &mut self,
    ) -> Result<Option<RootBindingHoldV1>, RootStartupBindingReadErrorV1> {
        self.journal_mut_v1()?;
        let authority = self.binding_read_authority_after_entry_v1()?;
        let held = current_binding_hold_data_v1(&authority).map_err(|error| match error {
            StartupBindingGuardErrorV1::Native(error) => {
                RootStartupBindingReadErrorV1::Native(error)
            }
            StartupBindingGuardErrorV1::Data(error) => RootStartupBindingReadErrorV1::Data(error),
        })?;
        Ok(held.filter(|hold| hold.held))
    }
}

pub(super) fn read_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<&mut super::super::RootStartupJournalOriginalV1>()
        .checked_mul(3)?
        .checked_add(size_of::<&StartupCredentialAuthorityV1<'_, '_, '_>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<Option<RootBindingHoldV1>, StartupBindingGuardErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Result<Option<RootBindingHoldV1>, RootStartupBindingReadErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<super::super::RootStartupJournalErrorV1>().checked_mul(3)?)?
        .checked_add(size_of::<StartupBindingGuardErrorV1>().checked_mul(3)?)?
        .checked_add(size_of::<RootStartupBindingReadErrorV1>().checked_mul(6)?)?
        .checked_add(size_of::<Option<RootBindingHoldV1>>().checked_mul(3)?)?
        .checked_add(size_of::<&RootBindingHoldV1>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(6)?)
}
