//! Keeps roster storage funded through every strong and weak allocation owner.
//!
//! Normal rosters retain an independent real Main charge for the entire Arc
//! allocation. A closed upgrade gate and actual strong uniqueness permit native
//! body retirement while weak observers retain that separate charge. Legacy
//! component/private rosters have no such payer and still require Arc uniqueness
//! across both strong and weak owners before returning native credit.

use super::{Mutex, NativeRoster, OriginalActorAccountError};
use crucible_host_resources::host_services::process_birth::NativeRosterAllocationFunding;
use std::ops::Deref;
use std::sync::{Arc, Weak};

/// Owns a real roster body with its independent allocation payer after the Arc.
pub(super) struct RosterOwner {
    shared: Arc<Mutex<NativeRoster>>,
    funding: Option<NativeRosterAllocationFunding>,
}

/// Retains the same complete allocation charge after its weak field closes.
#[derive(Clone)]
pub(super) struct RosterWeak {
    shared: Weak<Mutex<NativeRoster>>,
    funding: Option<NativeRosterAllocationFunding>,
}

impl RosterOwner {
    pub(super) fn new(
        value: Mutex<NativeRoster>,
        funding: Option<NativeRosterAllocationFunding>,
    ) -> Self {
        Self {
            shared: Arc::new(value),
            funding,
        }
    }

    pub(super) fn downgrade(&self) -> RosterWeak {
        RosterWeak {
            shared: Arc::downgrade(&self.shared),
            funding: self.funding.clone(),
        }
    }

    /// Validates closure before irreversibly excluding new strong borrowers.
    ///
    /// All fallible work precedes sealing. The final callback only moves the
    /// already checked credits into their prepaid external retirement slots.
    pub(super) fn retire_body(
        &mut self,
        verify: impl FnOnce(&NativeRoster) -> Result<(), OriginalActorAccountError>,
        consume: impl FnOnce(&mut NativeRoster),
    ) -> Result<(), OriginalActorAccountError> {
        let Some(funding) = self.funding.as_ref() else {
            let state = Arc::get_mut(&mut self.shared)
                .ok_or(OriginalActorAccountError::Unavailable)?
                .get_mut()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            verify(state)?;
            consume(state);
            return Ok(());
        };

        let mut state = self
            .shared
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        verify(&state)?;
        let gate = funding
            .try_open()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        if Arc::strong_count(&self.shared) != 1 {
            return Err(OriginalActorAccountError::Unavailable);
        }

        // Every upgrade holds this same gate through actual Arc acquisition.
        // No raw Arc or independently clonable strong handle escapes. Once
        // sealed, this observed sole strong owner therefore remains exclusive.
        // Existing Weak owners keep the whole allocation funded by Main.
        gate.seal();
        consume(&mut state);
        Ok(())
    }
}

impl Deref for RosterOwner {
    type Target = Mutex<NativeRoster>;

    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

impl RosterWeak {
    pub(super) fn upgrade(&self) -> Option<RosterOwner> {
        let gate = self
            .funding
            .as_ref()
            .map(NativeRosterAllocationFunding::try_open)
            .transpose()
            .ok()?;
        let shared = self.shared.upgrade()?;
        let funding = self.funding.clone();
        drop(gate);
        Some(RosterOwner { shared, funding })
    }

    pub(super) fn ptr_eq(left: &Self, right: &Self) -> bool {
        Weak::ptr_eq(&left.shared, &right.shared)
    }

    pub(super) fn matches_owner(&self, owner: &RosterOwner) -> bool {
        self.shared.as_ptr() == Arc::as_ptr(&owner.shared)
    }

    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self {
            shared: Weak::new(),
            funding: None,
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- component controls panic only on failed real allocation, paired-charge or upgrade-exclusion assertions; they issue no native authority.
#[allow(clippy::unwrap_used)]
mod tests;
