//! Issues native input admission only from the same source-authenticated Prepare.
//!
//! The mandatory Source writer association checks its opaque current SDK lease
//! before signing this selected Prepare. Native boot validation binds the full
//! immutable selection and private key to that same original proof. Selection
//! data alone never constructs this owner or changes a reader/bank limit.

use super::*;
use crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection;

pub(crate) struct VerifiedCanonicalRestoreInputAdmission {
    identity: OriginalNativeRestorationConnectionIdentity,
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    authority: ConnectionAuthority,
    attempt: Rc<RefCell<NativeCompleteRestorePrepareAttempt>>,
}

impl VerifiedCompleteRestorePrepare {
    pub(crate) fn retain_original_restore_input_admission<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        completed: &mut Option<VerifiedCanonicalRestoreInputAdmission>,
    ) -> Result<(), ProviderError> {
        self.authenticate_installation(connection)?;
        if completed.is_some()
            || self.policy.restore_input_emitter_selection()
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
            || self.policy.restore_input_emitter_definition().is_none()
        {
            return Err(refused());
        }
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if flight.input_segment_issued || flight.input_segment_started {
            return Err(refused());
        }
        // Issuance is nonrenewing even if a later identity/currentness check or
        // owner construction refuses. The retained original attempt survives.
        flight.input_segment_issued = true;
        let identity = connection.retain_original_native_restore_identity(
            flight.original.as_ref().ok_or_else(refused)?,
            &self.policy,
        )?;
        identity
            .authenticate_installation(connection, flight.original.as_ref().ok_or_else(refused)?)?;
        *completed = Some(VerifiedCanonicalRestoreInputAdmission {
            identity,
            boot: Rc::clone(&self.boot),
            policy: Rc::clone(&self.policy),
            authority: self.authority.clone(),
            attempt: Rc::clone(&self.attempt),
        });
        Ok(())
    }
}

impl VerifiedCanonicalRestoreInputAdmission {
    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.identity.authenticate_current(connection)?;
        self.authority.ensure_live()?;
        let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
        boot.ensure_origin()?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !boot.verified
            || !flight.verified
            || !flight.input_segment_issued
            || boot
                .transfer
                .as_ref()
                .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
            || boot
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
            || self.policy.restore_input_emitter_selection()
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
            || self.policy.restore_input_emitter_definition().is_none()
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_installation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        if flight.input_segment_started {
            return Err(refused());
        }
        self.identity
            .authenticate_installation(connection, flight.original.as_ref().ok_or_else(refused)?)
    }

    pub(crate) fn authenticate_original_prepare<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &VerifiedCompleteRestorePrepare,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        original.authenticate_current(connection)?;
        if !Rc::ptr_eq(&self.attempt, &original.attempt)
            || !Rc::ptr_eq(&self.boot, &original.boot)
            || !Rc::ptr_eq(&self.policy, &original.policy)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Spends this admission before the SDK's first segment ownership effect.
    pub(crate) fn begin_installation<S: ProviderStream>(
        &mut self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_installation(connection)?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        if flight.input_segment_started {
            return Err(refused());
        }
        flight.input_segment_started = true;
        Ok(())
    }

    pub(crate) fn request<'a, S: ProviderStream>(
        &'a self,
        connection: &Connection<S>,
    ) -> Result<std::cell::Ref<'a, PacketCompleteRestorePrepareRequest>, ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        std::cell::Ref::filter_map(flight, |flight| flight.request.as_ref()).map_err(|_| refused())
    }

    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Original actor PID/thread checks precede registrar/gate access in a
        // copied process. The identity walk owns those original checks.
        self.identity.observe_retained_metadata(observer)?;
        self.authority.ensure_live()?;
        self.authority.observe_retained_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeBoot,
            self.boot.as_ref(),
        )?;
        self.boot
            .try_borrow()
            .map_err(|_| borrowed())?
            .observe_admitted_boot_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            self.policy.as_ref(),
        )?;
        self.policy.observe_owned11_metadata(observer)?;
        observer.shared_value(self.attempt.as_ref())?;
        self.attempt
            .try_borrow()
            .map_err(|_| borrowed())?
            .observe_actual_retained_metadata(observer)
    }
}
