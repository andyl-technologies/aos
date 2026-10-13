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
