//! Borrows the real main and sidecar at each physical primitive.
//!
//! Only sealed actual traffic/store owners supply these borrows. Identity
//! links remain comparison DATA; this owner never substitutes them for files.
//! No references escape their real owners or overlap mutable store validation.

use aos_sandbox::Journal;

use super::*;

pub(in crate::recovery::journal::tpm_floor) struct HeldControllerFloorPairV1<'held> {
    main: &'held Journal,
    sidecar: &'held Journal,
}

impl<'held> HeldControllerFloorPairV1<'held> {
    pub(super) fn from_actual_attachment_v1(main: &'held Journal, store: &'held FloorStoreV1) -> Self {
        Self { main, sidecar: store.original_controller_pair_journal_v1() }
    }

    fn borrow<Traffic: HeldTrafficWriterV1>(traffic: &'held Traffic, store: &'held FloorStoreV1)
        -> Option<Self>
    {
        Some(Self {
            main: traffic.original_controller_pair_journal_v1()?,
            sidecar: store.original_controller_pair_journal_v1(),
        })
    }

    pub(in crate::recovery::journal::tpm_floor) fn main(&self) -> &Journal { self.main }

    pub(in crate::recovery::journal::tpm_floor) fn sidecar(&self) -> &Journal { self.sidecar }
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1>
    BorrowedDurableFloorV1<'_, '_, Traffic, Io>
{
    pub(super) fn require_storage_programme_originals_v3(&mut self) -> Result<(), FloorErrorV1> {
        let Some(receiving) = self.storage_receiving.as_mut() else { return Ok(()); };
        self.traffic.require_storage_main_programme_v3()?;
        self.store.require_storage_floor_programme_v3()?;
        let pair = HeldControllerFloorPairV1::borrow(&*self.traffic, &*self.store)
            .ok_or(FloorErrorV1::Unavailable)?;
        // These zero-growth admissions validate the real same-main/taken-sidecar
        // source association without resetting either charged component. Every
        // following primitive still prepays its full actual demand separately.
        receiving.reserve_main_v3(pair.main(), aos_sandbox_core::ResourceVector::ZERO)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        receiving.reserve_sidecar_v2(pair.main(), pair.sidecar(), aos_sandbox_core::ResourceVector::ZERO)
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(super) fn read_backend_with_pair_v1(&mut self) -> Result<[u8; 32], FloorErrorV1> {
        let pair = HeldControllerFloorPairV1::borrow(&*self.traffic, &*self.store);
        match self.storage_receiving.as_mut() {
            Some(source) => self.backend.read_with_storage_receiving_v2(pair.as_ref(), Some(&mut **source)),
            None => self.backend.read_with_pair_v1(pair.as_ref()),
        }
    }

    fn extend_backend_with_pair_v1(&mut self, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        let pair = HeldControllerFloorPairV1::borrow(&*self.traffic, &*self.store);
        match self.storage_receiving.as_mut() {
            Some(source) => self.backend.extend_with_storage_receiving_v2(input, pair.as_ref(), Some(&mut **source)),
            None => self.backend.extend_with_pair_v1(input, pair.as_ref()),
        }
    }

    pub(super) fn advance_backend_with_pair_v1(
        &mut self,
        prepared: FloorIntentDataV1,
        suffix: &BorrowedFinalSuffixV2,
        stored: &StoredFloorDataV1,
        transaction: &JournalTransaction,
    ) -> Result<FloorAdvanceV1, FloorErrorV1> {
        let profile = self.backend.profile_data_v1();
        super::super::backend::advance_held_recipe_v1!(profile, prepared, old, target,
            self.read_backend_with_pair_v1(),
            {
                self.check_cold_deadline()?;
                self.require_prospective_cut_v2(prepared, transaction)?;
                self.validate_sidecar_preflight_v2(suffix, stored)?;
                self.check_cold_deadline()
            },
            self.extend_backend_with_pair_v1(&target.extend_input()))
    }
}
