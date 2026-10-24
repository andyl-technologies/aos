//! Owns the four original Reserved P/I/Q/J observer origins.
//!
//! The same fixed Controller writer validates its actual initial launch,
//! profile and protected purpose claim. Upper coordinators still own CPU,
//! clock, exclusive archive attachment, semantic append and independent posts.
//! This prerequisite creates no native peer, stream, Cache loan or paid ledger.

use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, Claim};

use super::identity::ControllerWriterIdentityV1;
use super::{
    ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1, ControllerCoordinatorWriterV1,
};
use crate::controller_receiving::{
    ControllerReceivingOriginalV1, profile::ControllerSelfProfileOriginalV1,
};
use crate::receiving::{FixedPropertyArchiveV1, ObservationLifetimeV1};

/// Names only the four genuine native producer entrances in this subtree.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum OriginalObserverPurposeV1 {
    FirstGlobal,
    NixIntake,
    Q04Intake,
    CreateIntake,
}

/// Retains an actual native P/I/Q/J claim and its original observer lifetime.
///
/// Only the same Controller writer constructs this non-Clone owner. Its
/// capacity and lifetime are comparison/closure DATA, not a financial loan or
/// authority to perform native work. Upper admission, CPU and semantic currentness checks remain mandatory.
#[must_use]
pub struct ControllerReservedObserverOriginalV1 {
    pub(super) original: Arc<ControllerReceivingOriginalV1>,
    pub(super) identity: Arc<ControllerWriterIdentityV1>,
    pub(super) reserved: Claim,
    pub(super) capacity: usize,
    pub(super) lifetime: ObservationLifetimeV1,
    pub(super) purpose: OriginalObserverPurposeV1,
}

impl ControllerReservedObserverOriginalV1 {
    /// Bounds the existing original Q entrance through HELLO.
    pub const Q04_ENTRANCE_OBSERVER_ROWS: usize = 3 + 4 + 1 + 5 + 2 + 10 + 2;

    /// Prices factory locals and its returned controls before construction.
    ///
    /// The retained owner is already part of the upper intake's compiled Self.
    /// This adds only simultaneous factory/return/codec planes, not another
    /// copy of that resident owner or a second native resource account.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Result<Self, ControllerBankLaunchErrorV1>>())?
            .checked_add(std::mem::size_of::<(
                crate::receiving::OriginalEnrollment,
                bank::ImageBootstrapPolicy,
                bank::BootstrapProvisions,
                Claim,
                bank::ClaimFields,
                ResourceVector,
                ResourceVector,
                ResourceVector,
                Result<usize, crate::receiving::RootObservationErrorV1>,
                Option<bank::RecipientIncarnation>,
                Result<Option<bank::RecipientIncarnation>, bank::ResourceBankDataError>,
                Result<Vec<u8>, bank::ResourceBankDataError>,
                Result<[u8; bank::CLAIM_BYTES_V1], bank::ResourceBankDataError>,
                [u8; 96],
                [u8; 176],
                sha2::Sha256,
            )>())?
            .checked_add(bank::RECIPIENT_RANGE_INCARNATION_BYTES.checked_mul(2)?)?
            .checked_add(bank::CLAIM_BYTES_V1)?
            .checked_add(Self::attachment_construction_bytes_v1()?)
    }

    /// Returns the count funded by this exact native purpose claim.
    #[must_use]
    pub const fn capacity_data_v1(&self) -> usize {
        self.capacity
    }

    /// Clones this original's monotone closure handle for the upper archive.
    ///
    /// This handle cannot construct a native peer or a financial borrower.
    #[must_use]
    pub fn lifetime_v1(&self) -> ObservationLifetimeV1 {
        self.lifetime.clone()
    }

    pub(in crate::controller_receiving) fn lifetime_is_open_v1(&self) -> bool {
        self.lifetime.is_open()
    }

    pub(in crate::controller_receiving) fn same_lifetime_v1(
        &self,
        lifetime: &ObservationLifetimeV1,
    ) -> bool {
        self.lifetime.same_original(lifetime)
    }

    pub(in crate::controller_receiving) fn close_lifetime_v1(&self) {
        self.lifetime.close();
    }

    pub(in crate::controller_receiving) fn require_attachment_profile_v1(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: OriginalObserverPurposeV1,
    ) -> Result<(), crate::controller_receiving::profile::ControllerProfileErrorV1> {
        use crate::controller_receiving::profile::ControllerProfileErrorV1 as Error;

        if purpose != self.purpose || !self.lifetime.is_open() {
            return Err(Error::Service);
        }
        let compared = match self.purpose {
            OriginalObserverPurposeV1::CreateIntake => self
                .original
                .require_create_continuation_profile_v1(profile),
            _ => self
                .original
                .require_original_observer_profile_v1(profile, self.purpose),
        };
        compared.map_err(|_| Error::Service)
    }

    /// Prices the actual by-value attachment and native archive controls.
    #[must_use]
    pub fn attachment_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<(Self, FixedPropertyArchiveV1)>().checked_add(std::mem::size_of::<
            Result<(), crate::controller_receiving::profile::ControllerProfileErrorV1>,
        >())
    }

    /// Rejoins the same origin, fixed writer, profile and Reserved claim.
    ///
    /// # Errors
    /// Rejects closed or foreign originals, a changed writer or a changed claim.
    pub fn require_same_reserved_original_v1<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&self.original, writer.fixed.original())
            || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match self.purpose {
            OriginalObserverPurposeV1::CreateIntake => {
                self.original
                    .require_create_continuation_profile_v1(profile)?;
            }
            _ => self
                .original
                .require_original_observer_profile_v1(profile, self.purpose)?,
        }
        bank::require_exact_claim_record_v1(writer.fixed.bank_state_v1()?, self.reserved)?;
        Ok(())
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Starts this initial Controller's Reserved FirstGlobal observer origin.
    ///
    /// # Errors
    /// Rejects foreign/closed originals, reentry, a changed Reserved P claim
    /// or insufficient fixed/observer capacity. No lifetime or capacity is supplied.
    pub fn begin_first_global_reserved_observers_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_original_reserved_observers_once_v1(
            launch,
            profile,
            fixed,
            OriginalObserverPurposeV1::FirstGlobal,
        )
    }

    /// Starts this initial Controller's Reserved original Nix observer origin.
    ///
    /// # Errors
    /// Rejects foreign/closed originals, reentry, a changed Reserved I claim
    /// or insufficient fixed/observer capacity. No lifetime or capacity is supplied.
    pub fn begin_nix_reserved_observers_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_original_reserved_observers_once_v1(
            launch,
            profile,
            fixed,
            OriginalObserverPurposeV1::NixIntake,
        )
    }

    /// Starts this initial Controller's Reserved Q observer origin.
    ///
    /// # Errors
    /// Rejects foreign/closed originals, reentry, a changed Reserved Q claim
    /// or insufficient fixed/observer capacity. No lifetime or capacity is supplied.
    pub fn begin_q04_reserved_observers_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_original_reserved_observers_once_v1(
            launch,
            profile,
            fixed,
            OriginalObserverPurposeV1::Q04Intake,
        )
    }

    // Only the three named native producer methods select this closed role.
    // Requirements are DATA; actual claim/once/profile custody admits the origin.
    fn begin_original_reserved_observers_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        fixed: ResourceVector,
        purpose: OriginalObserverPurposeV1,
    ) -> Result<ControllerReservedObserverOriginalV1, ControllerBankLaunchErrorV1> {
        if matches!(purpose, OriginalObserverPurposeV1::CreateIntake) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let controls = ControllerReservedObserverOriginalV1::receiving_construction_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        fixed.checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, controls))?;
        if !launch.is_initial_enrollment() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_current_controller_v1(self)?;
        let original = self.fixed.original();
        let observed = original.claim_original_observers_once_v1(profile, purpose)?;
        let provisions = observed.policy.bootstrap_provisions();
        let (provision, role, claim_purpose): (_, &[u8], _) = match purpose {
            OriginalObserverPurposeV1::FirstGlobal => (
                provisions.first_global_prefix,
                b"controller-first-global-prefix-v1",
                bank::ClaimPurpose::ControllerFirstGlobalPrefix,
            ),
            OriginalObserverPurposeV1::NixIntake => (
                provisions.nix_original_start_intake,
                b"controller-nix-original-start-intake-v1",
                bank::ClaimPurpose::NixOriginalStartIntake,
            ),
            OriginalObserverPurposeV1::CreateIntake => {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            OriginalObserverPurposeV1::Q04Intake => (
                provisions.q04_original_intake,
                b"controller-q04-original-intake-v1",
                bank::ClaimPurpose::Q04OriginalIntake,
            ),
        };
        let provision = provision.ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let state = self.fixed.bank_state_v1()?;
        let claim = Claim::decode(
            bank::claim_bytes(state, observed.identity.account_id(role))
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?,
        )?;
        let fields = claim.native_fields();
        if fields.enrollment != observed.identity
            || fields.account != observed.identity.account_id(b"controller")
            || fields.purpose != claim_purpose
            || fields.state != bank::ClaimState::Reserved
            || fields.cut != bank::ClaimCut::BootLifetime
            || fields.amount != provision
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        bank::require_exact_claim_record_v1(state, claim)?;
        let row = FixedPropertyArchiveV1::controller_observer_row_demand_v1()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let whole =
            FixedPropertyArchiveV1::receiving_capacity_data_v1(provision.checked_sub(fixed)?, row)
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let capacity = if matches!(purpose, OriginalObserverPurposeV1::FirstGlobal) {
            whole / 2
        } else {
            whole
        };
        let minimum = if matches!(purpose, OriginalObserverPurposeV1::Q04Intake) {
            ControllerReservedObserverOriginalV1::Q04_ENTRANCE_OBSERVER_ROWS
        } else {
            1
        };
        if capacity < minimum {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let rows = FixedPropertyArchiveV1::multiply_receiving_demand_data_v1(row, capacity)
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        provision.checked_sub(fixed.checked_add(rows)?)?;

        Ok(ControllerReservedObserverOriginalV1 {
            original: Arc::clone(original),
            identity: Arc::clone(self.fixed.identity()),
            reserved: claim,
            capacity,
            lifetime: ObservationLifetimeV1::begin(),
            purpose,
        })
    }
}

impl Drop for ControllerReservedObserverOriginalV1 {
    fn drop(&mut self) {
        self.lifetime.close();
    }
}
