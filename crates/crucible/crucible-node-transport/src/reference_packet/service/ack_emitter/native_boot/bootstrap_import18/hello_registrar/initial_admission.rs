//! Retains actual initial SDK admission before any fallible terminal guard.
//!
//! The enclosing Native18 transition must admit complete SDK construction,
//! authenticate all original request/response operands and supply its genuine
//! verifier. This primitive owns the resulting SDK lease and failure; it grants
//! no Native18 policy, publication, ACK, model adoption or readiness.

use super::super::InitialHelloInputs;
use super::{Attempt, Stage, refused};
use crate::ProviderError;
use crate::envelope::Envelope;
use crate::handshake::{
    ConnectionAuthority, ExtensionHandshake, HelloRequest, HelloResult, TrustedHandshakeVerifier,
};
use crate::operational_time::OperationalDeadline;
use crucible_node_format::Id;

impl Attempt {
    /// Names this custody wrapper's controls, excluding SDK and callback work.
    pub(in super::super::super) fn initial_admission_wrapper_counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&Envelope>() * 2
            + size_of::<&HelloRequest>()
            + size_of::<&HelloResult>()
            + size_of::<&mut dyn TrustedHandshakeVerifier>()
            + size_of::<&mut ExtensionHandshake>()
            + size_of::<&ConnectionAuthority>()
            + size_of::<Id>()
            + size_of::<ConnectionAuthority>()
            + size_of::<Option<ConnectionAuthority>>()
            + size_of::<Result<ConnectionAuthority, ProviderError>>()
            + size_of::<ProviderError>() * 2
            + size_of::<Option<ProviderError>>()
            + size_of::<OperationalDeadline>() * 2
            + size_of::<Stage>()
            + size_of::<Result<(), ProviderError>>() * 4
            // Keep earlier field views beside the caller and forwarded records.
            + size_of::<InitialHelloInputs<'static>>() * 3
    }

    /// Spends initial admission and retains its actual lease or SDK failure.
    ///
    /// The caller must first admit the entire SDK constructor, including its
    /// internal decoding, comparison, tree and callback windows. This method's
    /// inline destinations already exist in the pre-read registrar attempt.
    /// Failed or expired admission contains the issuer without dropping owners.
    ///
    /// # Errors
    /// Refuses foreign custody, retry, incomplete fresh construction, original
    /// cut mismatch, actual SDK/verifier refusal or a failed terminal lease check.
    pub(in super::super::super) fn admit_initial_data(
        &mut self,
        inputs: InitialHelloInputs<'_>,
        verifier: &mut impl TrustedHandshakeVerifier,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.admission_started {
            return Err(refused());
        }
        self.admission_started = true;

        let outcome = self.admit_current_initial(inputs, verifier, cut);
        let terminal = self.guard(cut);
        if let Err(error) = outcome.and(terminal) {
            self.admission_failure = Some(error);
            if let Some(wrapper) = &mut self.wrapper {
                wrapper.contain();
            }
            return Err(refused());
        }
        Ok(())
    }

    fn admit_current_initial(
        &mut self,
        inputs: InitialHelloInputs<'_>,
        verifier: &mut impl TrustedHandshakeVerifier,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        let InitialHelloInputs {
            request,
            response,
            hello,
            result,
            connection,
        } = inputs;

        if self.stage != Stage::Complete
            || self.failure.is_some()
            || self.admission_failure.is_some()
            || self.authority.is_some()
            || hello.resume_session.is_some()
            || !result.resumed_operations.is_empty()
            || result.resume_token.0.is_some()
        {
            return Err(refused());
        }
        let wrapper = self.wrapper.as_mut().ok_or_else(refused)?;
        let authority = wrapper
            .admit_original_envelopes(request, response, hello, result, connection, verifier)?;
        // This move must precede the cut and lease checks. Their refusal revokes
        // the lease while its actual independent fields remain in this slot.
        self.authority = Some(authority);
        self.guard(cut)?;
        self.wrapper
            .as_ref()
            .ok_or_else(refused)?
            .verify_authority(self.authority.as_ref().ok_or_else(refused)?)
    }

    /// Borrows the same completed issuer through initial selection.
    ///
    /// This immutable view supplies no lease. The enclosing owner continues to
    /// authenticate complete original DATA and its nonrenewing physical cut.
    ///
    /// # Errors
    /// Refuses incomplete/refused custody, an expired/substituted cut or a
    /// missing, foreign, superseded or contained selected lease.
    pub(in super::super) fn state_data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<&ExtensionHandshake, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete
            || self.failure.is_some()
            || self.admission_failure.is_some()
        {
            return Err(refused());
        }
        let wrapper = self.wrapper.as_ref().ok_or_else(refused)?;
        match (self.admission_started, self.authority.as_ref()) {
            (false, None) => {}
            (true, Some(authority)) => wrapper.verify_authority(authority)?,
            _ => return Err(refused()),
        }
        Ok(wrapper)
    }

    /// Borrows the real selected lease without moving or cloning it.
    ///
    /// # Errors
    /// Refuses original state/cut guards or absent initial SDK admission.
    pub(in super::super::super) fn authority_data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<&ConnectionAuthority, ProviderError> {
        self.state_data(cut)?;
        self.authority.as_ref().ok_or_else(refused)
    }

    #[cfg(test)]
    pub(in super::super::super) fn retained_authority_fixture_data(
        &self,
    ) -> Option<&ConnectionAuthority> {
        self.authority.as_ref()
    }

    #[cfg(test)]
    pub(in super::super::super) fn admission_failure_fixture_data(&self) -> Option<&ProviderError> {
        self.admission_failure.as_ref()
    }

    /// Revokes selected registration while retaining every initialized owner.
    ///
    /// # Errors
    /// Refuses foreign creator custody or an absent original wrapper.
    pub(in super::super::super) fn contain_admission_data(&mut self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        self.wrapper.as_mut().ok_or_else(refused)?.contain();
        Ok(())
    }
}

#[cfg(test)]
#[path = "initial_admission_tests.rs"]
mod tests;
