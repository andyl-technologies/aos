//! Borrows the complete original negotiation issuer while holding its live gate.
//!
//! This view preserves private installation secrets, complete negotiation policy
//! and actual phase/counters. It is data for a source's bounded complete snapshot,
//! not a decoded authority, fresh registration or native restoration permission.

use super::*;
use serde::ser::SerializeStruct;
use std::sync::MutexGuard;

/// Borrows complete private issuer data under the same original registration gate.
///
/// The source retains this view through its bounded count and encoding passes.
/// The view contains private launch/resume secrets and must stay in source-owned
/// custody. Serialization must not reenter registration, resumption or another
/// callback that locks this gate. No verifier callback is retained or serialized.
pub struct OriginalNegotiationView<'a> {
    original: &'a Handshake,
    authority: &'a ConnectionAuthority,
    _registration: MutexGuard<'a, ()>,
}

impl Handshake {
    /// Borrows every original issuer fact under its authenticated live registrar.
    ///
    /// Source process/currentness and complete semantic/native ownership remain
    /// mandatory external checks. This view supplies no capture or Ready token.
    /// Its lock keeps shared revocation fixed through bounded serialization;
    /// ordinary Rust borrowing prevents the issuer's phase/policy mutation.
    ///
    /// # Errors
    /// Refuses a foreign registration, contained/superseded lease or poisoned
    /// original gate. The actual issuer and journals remain unchanged.
    pub fn original_negotiation_view<'a>(
        &'a self,
        authority: &'a ConnectionAuthority,
    ) -> Result<OriginalNegotiationView<'a>, ProviderError> {
        let registration = self
            .registration_gate
            .lock()
            .map_err(|_| ProviderError::Correlation("original negotiation gate poisoned"))?;
        self.verify_current_authority(authority)?;
        Ok(OriginalNegotiationView {
            original: self,
            authority,
            _registration: registration,
        })
    }
}

impl Serialize for OriginalNegotiationView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.original
            .verify_current_authority(self.authority)
            .map_err(serde::ser::Error::custom)?;
        let original = self.original;
        let installation = &original.installation;
        let policy = &original.policy;
        let mut state = serializer.serialize_struct("OriginalNegotiation", 11)?;
        state.serialize_field("schema", "source-private.original-negotiation/5")?;
        state.serialize_field(
            "installation",
            &(
                &installation.session_id,
                &installation.incarnation_id,
                &installation.measured_implementation,
                &installation.launch_receipt,
                &installation.admission_token,
            ),
        )?;
        state.serialize_field(
            "policy",
            &(
                &policy.supported_features,
                &policy.required_features,
                &policy.provider_limits,
                &policy.required_schemas,
                &policy.required_guarantees,
                &policy.envelope_extension_features,
            ),
        )?;
        state.serialize_field("epoch", &U64::new(original.epoch))?;
        state.serialize_field("current_connection", &original.current_connection)?;
        state.serialize_field("selected_features", &original.selected_features)?;
        state.serialize_field("resume_token", &original.resume_token)?;
        state.serialize_field("contained", &original.contained)?;
        state.serialize_field("hello_request_ids", &original.hello_request_ids)?;
        state.serialize_field(
            "shared_epoch",
            &U64::new(original.shared_epoch.load(Ordering::Acquire)),
        )?;
        state.serialize_field(
            "registration_gate_poisoned",
            &original.registration_gate.is_poisoned(),
        )?;
        state.end()
    }
}

impl OriginalNegotiationView<'_> {
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.original.verify_current_authority(self.authority)?;
        self.original.observe_retained_metadata_data(observer)
    }
}

impl Handshake {
    /// Reports actual retained negotiation allocations as historical data.
    ///
    /// The owning process capsule must check its original creator/thread before
    /// this borrow. A plain Handshake has no process-origin field. This method
    /// invokes no callback, registration, serializer or native I/O and grants no
    /// current authority; inline issuer fields remain the caller's layout term.
    ///
    /// # Errors
    /// Reports checked layout overflow or finite metadata traversal exhaustion.
    pub fn retained_metadata_facts_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_retained_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    pub(in crate::handshake) fn observe_retained_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Handshake {
            installation,
            policy,
            shared_epoch,
            registration_gate,
            epoch,
            current_connection,
            selected_features,
            resume_token,
            contained,
            hello_request_ids,
        } = self;
        let TrustedInstallation {
            session_id,
            incarnation_id,
            measured_implementation,
            launch_receipt,
            admission_token: _,
        } = installation;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(measured_implementation)?;
        observer.observe(launch_receipt)?;
        let NegotiationPolicy {
            supported_features,
            required_features,
            provider_limits,
            required_schemas,
            required_guarantees,
            envelope_extension_features,
        } = policy;
        observer.observe(supported_features)?;
        observer.observe(required_features)?;
        observer.observe(provider_limits)?;
        observer.observe(required_schemas)?;
        observer.observe(required_guarantees)?;
        observer.observe(envelope_extension_features)?;
        observer.observe(epoch)?;
        observer.observe(current_connection)?;
        observer.observe(selected_features)?;
        // Both private secrets are fixed inline arrays, never Vec allocations.
        observer.observe(&resume_token.is_some())?;
        observer.observe(contained)?;
        observer.observe(hello_request_ids)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarEpoch,
            shared_epoch.as_ref(),
        )?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarGate,
            registration_gate.as_ref(),
        )?;
        Ok(())
    }
}

impl Handshake {
    pub(in crate::handshake) fn observe_unique_capture_metadata_data(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Handshake {
            installation,
            policy,
            shared_epoch,
            registration_gate,
            epoch,
            current_connection,
            selected_features,
            resume_token,
            contained,
            hello_request_ids,
        } = self;
        let TrustedInstallation {
            session_id,
            incarnation_id,
            measured_implementation,
            launch_receipt,
            admission_token: _,
        } = installation;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(measured_implementation)?;
        observer.observe(launch_receipt)?;
        let NegotiationPolicy {
            supported_features,
            required_features,
            provider_limits,
            required_schemas,
            required_guarantees,
            envelope_extension_features,
        } = policy;
        observer.observe(supported_features)?;
        observer.observe(required_features)?;
        observer.observe(provider_limits)?;
        observer.observe(required_schemas)?;
        observer.observe(required_guarantees)?;
        observer.observe(envelope_extension_features)?;
        observer.observe(epoch)?;
        observer.observe(current_connection)?;
        observer.observe(selected_features)?;
        // Both private secrets are fixed inline arrays, never Vec allocations.
        observer.observe(&resume_token.is_some())?;
        observer.observe(contained)?;
        observer.observe(hello_request_ids)?;
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarEpoch,
            shared_epoch.as_ref(),
        )?;
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarGate,
            registration_gate.as_ref(),
        )?;
        Ok(())
    }
}
