//! Retains the same Runtime Session shell around either closed Client turn.
//!
//! The old Runtime owner and completed informational/effect originals stay
//! resident while Security consumes the same actual Session. Pending, ambiguous
//! or failed custody cannot be discarded to open a new protected writer.

use super::*;
use aos_sandbox::OriginalCreateStorageReadyV1;
use aos_sandbox_broker_session_security::controller_composition::{
    OriginalStorageClientSessionTransitionV1, OriginalStorageClientTransitionClosedV1,
};

#[derive(Debug, thiserror::Error)]
#[error("the original Storage Client transition is closed with actual custody retained")]
pub(crate) struct StoragePreparationClientClosedV1;

struct RetiredRuntimeOriginalsV1 {
    capture_candidate: Option<crate::controller_service::capture_candidate_exchange::ControllerStorageCaptureCandidateExchangeV1>,
    capture_admission: Option<crate::controller_service::execution_output_storage_capture::OriginalControllerStorageCaptureV3>,
    capture_admission_construction: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    pending: Option<DormantLifecycleInventoryQueryRecoveryV1>,
    authority_effects: ControllerAuthorityEffectExchangeV1,
    output_registration: Option<crate::controller_service::execution_output_storage_registration::OriginalControllerOutputRegistrationV1>,
    #[cfg(feature = "online-nix")]
    nix_generation: Option<crate::controller_service::nix_generation::NixGenerationAttemptV1>,
    git_coverage: Option<GitCoverageQueryCustodyV1>,
}

pub(crate) struct OriginalStoragePreparationClientV1 {
    old: Option<DormantStorageLifecycleInventoryOwnerV1>,
    retired: Option<RetiredRuntimeOriginalsV1>,
    security: Option<OriginalStorageClientSessionTransitionV1>,
    idle: Option<Result<(), StoragePreparationClientClosedV1>>,
    borrowed: Option<Result<(), aos_sandbox::CreateStorageClientSessionClosedV1>>,
    provisioning_geometry: Option<Result<aos_sandbox_core::ResourceVector, aos_sandbox::ResourceReservationErrorV1>>,
    returned: Option<Result<(), OriginalStorageClientTransitionClosedV1>>,
    closed: Option<StoragePreparationClientClosedV1>,
    transferred: bool,
}

impl OriginalStoragePreparationClientV1 {
    fn retain(old: Option<DormantStorageLifecycleInventoryOwnerV1>) -> Self {
        Self { old, retired: None, security: None, idle: None, borrowed: None,
            returned: None, closed: None, transferred: false, provisioning_geometry: None }
    }

    fn close<T>(&mut self) -> Result<T, StoragePreparationClientClosedV1> {
        self.closed.get_or_insert(StoragePreparationClientClosedV1);
        Err(StoragePreparationClientClosedV1)
    }

    pub(super) fn require_idle(old: &DormantLifecycleInventorySessionV1)
        -> Result<(), StoragePreparationClientClosedV1>
    {
        if old.pending.is_some() || old.authority_effects.has_pending()
            || old.authority_effects.requires_reconnect()
            || old.capture_candidate.as_ref().is_some_and(|candidate|
                candidate.has_pending() || candidate.failure(&old.session).is_some()
                    || candidate.postcheck_debt(&old.session).is_some())
            || old.output_registration.as_ref().is_some_and(|registration|
                registration.has_pending() || registration.failure(&old.session).is_some()
                    || registration.postcheck_debt(&old.session).is_some())
            || old.git_coverage.as_ref().is_some_and(|query|
                query.first_failure.is_some() || query.postcheck_debt.is_some() || query.completed.is_none())
        {
            return Err(StoragePreparationClientClosedV1);
        }
        // The existing real Nix owner has no positive disposal loan in this
        // flow. Its presence remains unfinished; DATA cannot manufacture one.
        #[cfg(feature = "online-nix")]
        if old.nix_generation.is_some() { return Err(StoragePreparationClientClosedV1); }
        Ok(())
    }

    fn run_once(&mut self, ready: &mut OriginalCreateStorageReadyV1<'_, '_>)
        -> Result<DormantStorageLifecycleInventoryOwnerV1, StoragePreparationClientClosedV1>
    {
        if self.idle.is_some() || self.closed.is_some() { return self.close(); }
        self.require_idle_once_v1()?;
        let mut original = match ready.borrow_client_session_once() {
            Ok(original) => {
                self.borrowed = Some(Ok(()));
                original
            }
            Err(error) => {
                self.borrowed = Some(Err(error));
                return self.close();
            }
        };
        self.retain_security_once_v1()?;
        let security = match self.security.as_mut() { Some(security) => security, None => std::process::abort() };
        self.returned = Some(security.run_once(&mut original, std::mem::size_of::<Self>()));
        if !matches!(self.returned, Some(Ok(()))) { return self.close(); }
        let session = match security.take_completed_once() {
            Ok(session) => session,
            Err(error) => {
                self.returned = Some(Err(error));
                return self.close();
            }
        };
        // The native purpose is Complete and ends before Inventory borrows
        // this SAME joined Ready again. No resident Session debt is refunded.
        drop(original);
        self.finish_positive_transfer_v1(session)
    }

    fn require_idle_once_v1(&mut self) -> Result<(), StoragePreparationClientClosedV1> {
        let old = match self.old.as_ref() { Some(old) => &old.0, None => return self.close() };
        self.idle = Some(Self::require_idle(old));
        if !matches!(self.idle, Some(Ok(()))) { return self.close(); }
        Ok(())
    }

    fn retain_security_once_v1(&mut self) -> Result<(), StoragePreparationClientClosedV1> {
        let DormantStorageLifecycleInventoryOwnerV1(old) = match self.old.take() {
            Some(old) => old,
            None => std::process::abort(),
        };
        let DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        } = old;
        self.retired = Some(RetiredRuntimeOriginalsV1 {
            capture_candidate, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        });
        self.security = Some(OriginalStorageClientSessionTransitionV1::retain(session));
        Ok(())
    }

    fn finish_positive_transfer_v1(
        &mut self,
        session: aos_sandbox_broker_session_security::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<DormantStorageLifecycleInventoryOwnerV1, StoragePreparationClientClosedV1> {
        let retired = match self.retired.take() {
            Some(retired) => retired,
            None => return self.close(),
        };
        // Move the actual Capture owner and its first construction Result into
        // the successor shell. Session rollover cannot dispose or recreate it.
        let RetiredRuntimeOriginalsV1 {
            capture_admission, capture_admission_construction, ..
        } = retired;
        self.transferred = true;
        Ok(DormantStorageLifecycleInventoryOwnerV1(DormantLifecycleInventorySessionV1 {
            capture_candidate: None, session, pending: None,
            capture_admission, capture_admission_construction,
            authority_effects: ControllerAuthorityEffectExchangeV1::default(),
            output_registration: None,
            #[cfg(feature = "online-nix")]
            nix_generation: None,
            git_coverage: None,
        }))
    }

    fn completed_predecessor_v1(&mut self)
        -> Result<&mut OriginalStorageClientSessionTransitionV1, StoragePreparationClientClosedV1>
    {
        if !self.transferred || self.closed.is_some() || self.old.is_some() || self.retired.is_some()
            || !matches!(self.idle, Some(Ok(()))) || !matches!(self.borrowed, Some(Ok(())))
            || !matches!(self.returned, Some(Ok(())))
        {
            return self.close();
        }
        self.security.as_mut().ok_or(StoragePreparationClientClosedV1)
    }

    fn run_provisioning_once_v1(
        &mut self,
        predecessor: &mut OriginalStoragePreparationClientV1,
        capture: &aos_sandbox_broker_session_security::DormantControllerInitialSessionOpenV1,
        receiving: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        co_resident: aos_sandbox_core::ResourceVector,
    ) -> Result<DormantStorageLifecycleInventoryOwnerV1, StoragePreparationClientClosedV1> {
        if self.idle.is_some() || self.closed.is_some() || self.provisioning_geometry.is_some() {
            return self.close();
        }
        self.require_idle_once_v1()?;
        self.provisioning_geometry = Some((|| {
            let bytes = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
            co_resident.checked_add(aos_sandbox_core::ResourceVector::ZERO
                .with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
                .map_err(Into::into)
        })());
        let complete = match self.provisioning_geometry.as_ref() {
            Some(Ok(complete)) => *complete,
            _ => return self.close(),
        };
        let predecessor = match predecessor.completed_predecessor_v1() {
            Ok(predecessor) => predecessor,
            Err(_) => return self.close(),
        };
        self.retain_security_once_v1()?;
        let security = match self.security.as_mut() {
            Some(security) => security,
            None => std::process::abort(),
        };
        self.returned = Some(security.run_provisioning_once_v1(
            predecessor, capture, receiving, controller, complete, std::mem::size_of::<Self>(),
        ));
        if !matches!(self.returned, Some(Ok(()))) { return self.close(); }
        let session = match security.take_completed_once() {
            Ok(session) => session,
            Err(cause) => {
                self.returned = Some(Err(cause));
                return self.close();
            }
        };
        self.finish_positive_transfer_v1(session)
    }

    fn retained_input_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.old.as_ref().and_then(|old| {
            old.0.capture_candidate.as_ref().and_then(|candidate| candidate.failure(&old.0.session)
                .or_else(|| candidate.postcheck_debt(&old.0.session)))
                .or_else(|| old.0.output_registration.as_ref().and_then(|registration|
                    registration.failure(&old.0.session).or_else(|| registration.postcheck_debt(&old.0.session))))
                .or_else(|| old.0.git_coverage.as_ref().and_then(|query| query.first_failure.as_ref()
                    .or(query.postcheck_debt.as_ref())).map(|cause| cause as _))
        }).or_else(|| self.idle.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    pub(crate) fn failure_with_provisioning_v1<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.retained_input_failure_v1()
            .or_else(|| self.provisioning_geometry.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.security.as_ref().and_then(|security| security.failure_with_provisioning_v1(receiving)))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn failure_with_ready<'cause>(&'cause self, ready: &'cause OriginalCreateStorageReadyV1<'_, '_>)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        self.retained_input_failure_v1()
            .or_else(|| self.borrowed.as_ref().and_then(|result| result.as_ref().err())
                .map(|marker| ready.failure().unwrap_or(marker)))
            .or_else(|| self.security.as_ref().and_then(|security| security.failure_with_ready(ready)))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Drop for OriginalStoragePreparationClientV1 {
    fn drop(&mut self) {
        if !self.transferred {
            // The resident Controller worker is the owner of this failure.
            // Process termination is the only way unfinished custody releases.
            std::process::abort();
        }
    }
}

impl crate::controller_service::ControllerBrokerSessions {
    pub(in crate::controller_service) fn run_original_storage_preparation_client_once(
        &mut self, ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Result<(), StoragePreparationClientClosedV1> {
        if self.storage_preparation_client.is_some() { return Err(StoragePreparationClientClosedV1); }
        // A failed cold prefix or Root exchange stays beside the exact old
        // Session. No reconnect/default replacement can overtake either.
        let parent_closed = self.storage_cold.as_ref().is_some_and(|cold| cold.is_failed())
            || self.storage_root.has_pending() || self.storage_root.requires_reconnect();
        self.storage_preparation_client = Some(OriginalStoragePreparationClientV1::retain(
            if parent_closed { None } else { self.storage.take() },
        ));
        let attempt = match self.storage_preparation_client.as_mut() { Some(attempt) => attempt, None => std::process::abort() };
        if parent_closed { return attempt.close(); }
        let session = attempt.run_once(ready)?;
        self.storage = Some(session);
        // Only whole joint success releases the positive old cold shell. The
        // Root exchange's complete DATA stays on its original parent field.
        drop(self.storage_cold.take());
        // Keep the SAME completed Security rollover in its original inline
        // destination. Its native positives are already disposed; the next
        // genuine purpose must borrow this actual provenance, not a new token.
        Ok(())
    }
}

impl crate::controller_service::ControllerBrokerSessions {
    pub(in crate::controller_service) fn run_original_storage_apply_client_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        co_resident: aos_sandbox_core::ResourceVector,
    ) -> Result<(), StoragePreparationClientClosedV1> {
        if let Some(attempt) = self.storage_apply_client.as_mut() {
            return attempt.close();
        }
        let parent_closed = self.storage_cold.as_ref().is_some_and(|cold| cold.is_failed())
            || self.storage_root.has_pending() || self.storage_root.requires_reconnect();
        self.storage_apply_client = Some(OriginalStoragePreparationClientV1::retain(
            if parent_closed { None } else { self.storage.take() },
        ));
        let attempt = match self.storage_apply_client.as_mut() {
            Some(attempt) => attempt,
            None => std::process::abort(),
        };
        if parent_closed { return attempt.close(); }
        // This private getter lends the actual original Storage slot; the
        // Security+Native borrower rejoins its same C/role/native ownership.
        let capture = match self.initial_slots[2].completed_capture_v1() {
            Some(capture) => capture,
            None => return attempt.close(),
        };
        let predecessor = match self.storage_preparation_client.as_mut() {
            Some(predecessor) => predecessor,
            None => return attempt.close(),
        };
        let session = attempt.run_provisioning_once_v1(
            predecessor, capture, receiving, controller, co_resident,
        )?;
        self.storage = Some(session);
        // Keep this positive actual rollover for a later separately admitted
        // Start purpose. This does not fund or authorize another request.
        Ok(())
    }
}
