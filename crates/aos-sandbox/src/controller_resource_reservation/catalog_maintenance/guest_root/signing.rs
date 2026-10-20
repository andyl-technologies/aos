//! Lends the same Maintenance original to its actual fixed plan signer.
//!
//! The constructor moves only the actual resident Root child into this short
//! borrower. Source, current C, completed Storage Session and signed18 stay
//! borrowed together. Drop restores custody and records unfinished debt; it
//! never executes replacement IO or disposes an entered failed phase.

use super::*;
use aos_sandbox_core::RevocationScopeId;
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::authorization_artifact::{
    BrokerPlanPreparation, SignedBrokerPlan, SigningAuthority,
};

/// Borrows the actual Maintenance signing continuation under the same held F.
///
/// It cannot be constructed from decoded Root bytes, a budget, a lease, or a
/// signed plan. Every entered call requires `finish_once_v3`, including a
/// failed preparation or key/message construction.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceSigningBorrowV3<'owner, 'session> {
    controller: &'owner Journal,
    loan: root_loan::ControllerCatalogMaintenanceRootLoanV3<'owner, 'session>,
    root: Option<crate::normal_root::RootMaintenanceStorageClientOriginalV3>,
    finished: bool,
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Enters the prepaid native signing interval of this actual Root child.
    ///
    /// # Errors
    /// Retains changed M/Source/C/Session/query association, missing opening,
    /// reentry, geometry or payment refusal. An entered native before is
    /// returned as a borrower even when refused, so its posts remain reachable.
    #[doc(hidden)]
    pub fn begin_refresh_guest_root_signing_once_v3<'borrow>(
        &'borrow mut self,
        receiving: &'borrow crate::ControllerInitialBrokerSessionReceivingV1,
        session: &'borrow Journal,
        inventory: &'borrow AuthenticatedBrokerMethodOutcomeV1,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<
        ControllerCatalogMaintenanceSigningBorrowV3<'borrow, 'borrow>,
        ResourceReservationErrorV1,
    > {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, session, 2)?;
        let Some(mut root) = self.owner.guest_root.root.take() else {
            self.owner
                .guest_root
                .repeated
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let mut loan = root_loan::ControllerCatalogMaintenanceRootLoanV3::new_v3(
            self.owner,
            self.source,
            receiving,
            session,
            inventory,
        );
        if root
            .begin_construction_once_v3(&mut loan, self.controller, verifier)
            .is_err()
        {
            loan.owner.guest_root.root = Some(root);
            loan.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(ControllerCatalogMaintenanceSigningBorrowV3 {
            controller: self.controller,
            loan,
            root: Some(root),
            finished: false,
        })
    }
}

impl ControllerCatalogMaintenanceSigningBorrowV3<'_, '_> {
    /// Verifies the current quartet and rebuilds exactly the admitted method31.
    ///
    /// # Errors
    /// Retains currentness, full crypto, fixed authority, Root comparison or
    /// unchanged deadline refusal. Independent native posts remain owed.
    pub fn prepare_once_v3(
        &mut self,
        verifier: &OwnershipAuthorityVerifier,
        authority: &SigningAuthority,
        scope: RevocationScopeId,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .prepare_construction_once_v3(
                &mut self.loan,
                self.controller,
                verifier,
                authority,
                scope,
            )?;
        Ok(())
    }

    /// Borrows only the actual prepared plan while its original is current.
    ///
    /// # Errors
    /// Refuses an unprepared, changed, failed or already finished continuation.
    pub fn signing_preparation_v3(
        &mut self,
    ) -> Result<&BrokerPlanPreparation, Box<dyn Error + Send + Sync>> {
        self.loan.require_current_v3(self.controller)?;
        Ok(self
            .root
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .signing_preparation_v3()?)
    }

    /// Samples the final actual paired clock immediately before the signature.
    ///
    /// # Errors
    /// Retains a changed original, repeated sample, clock, lease or original
    /// cutoff refusal, without extending either authority's expiry.
    pub fn final_signing_clock_once_v3(
        &mut self,
    ) -> Result<RawPairedClockSample, Box<dyn Error + Send + Sync>> {
        Ok(self
            .root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .final_signing_clock_once_v3(&mut self.loan, self.controller)?)
    }

    /// Retains and compares the actual fixed signer's completed plan once.
    ///
    /// # Errors
    /// Retains substituted plan semantics or missing actual presign clock.
    pub fn retain_signed_once_v3(
        &mut self,
        signed: SignedBrokerPlan,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.loan.require_current_v3(self.controller)?;
        self.root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .retain_signed_once_v3(signed)?;
        Ok(())
    }

    /// Runs every independently paid signing post and restores actual custody.
    ///
    /// `body_succeeded` classifies the caller's actual retained key/message
    /// result. It cannot close this phase without the exact stored signed plan,
    /// original presign clock and successful independent native posts.
    ///
    /// # Errors
    /// Retains the first body/native failure and every reached later post.
    pub fn finish_once_v3(
        &mut self,
        body_succeeded: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.finished {
            self.loan.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.finished = true;
        let result = self
            .root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .finish_construction_once_v3(&mut self.loan, self.controller, body_succeeded);
        if result.is_err() {
            if self
                .root
                .as_ref()
                .is_some_and(|root| root.construction_external_failure_selected_v3())
            {
                self.loan.owner.first.get_or_insert(First::Sdk);
            } else {
                self.loan.owner.first.get_or_insert(First::GuestRoot);
            }
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl Drop for ControllerCatalogMaintenanceSigningBorrowV3<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.loan
                .owner
                .guest_root
                .pending_root
                .get_or_insert(JournalError::ProtectedBoundary);
            self.loan.owner.first.get_or_insert(First::GuestRoot);
        }
        self.loan.owner.guest_root.root = self.root.take();
    }
}
