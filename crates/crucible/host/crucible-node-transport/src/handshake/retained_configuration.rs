//! Constructs an unadmitted issuer while preserving inputs on validation failure.
//!
//! The enclosing owner independently funds configuration cloning, validation,
//! actual shared allocations and controls before calling this constructor. This
//! module performs no peer I/O and issues no connection or native authority.

use super::*;

impl Handshake {
    /// Constructs a fresh issuer from retained configuration after validation.
    ///
    /// Installation and policy stay in their original slots on every error. The
    /// caller retains the returned validation error before its terminal census.
    /// Success moves both configurations once and installs the actual issuer in
    /// `output`; its new epoch and registration gate are not shared with an old
    /// handshake. The caller's original funding and custody remain mandatory.
    ///
    /// # Errors
    /// Refuses occupied output, missing inputs or any installation/policy
    /// validation error. Existing inputs and output are preserved on refusal.
    pub(crate) fn from_retained_configuration_data(
        installation: &mut Option<TrustedInstallation>,
        policy: &mut Option<NegotiationPolicy>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(absent());
        }
        Self::validate_configuration_data(
            installation.as_ref().ok_or_else(absent)?,
            policy.as_ref().ok_or_else(absent)?,
        )?;

        match (installation.take(), policy.take()) {
            (Some(installation), Some(policy)) => {
                *output = Some(Self::from_validated_configuration_data(
                    installation,
                    policy,
                ));
                Ok(())
            }
            (original_installation, original_policy) => {
                // No callback occurs between validation and these moves. Keep
                // the refusal preserving even if this control flow changes.
                *installation = original_installation;
                *policy = original_policy;
                Err(absent())
            }
        }
    }

    pub(super) fn validate_configuration_data(
        installation: &TrustedInstallation,
        policy: &NegotiationPolicy,
    ) -> Result<(), ProviderError> {
        installation.measured_implementation.validate()?;
        installation.launch_receipt.validate()?;
        policy.validate()?;
        Ok(())
    }

    pub(super) fn from_validated_configuration_data(
        installation: TrustedInstallation,
        policy: NegotiationPolicy,
    ) -> Self {
        Self {
            installation,
            policy,
            shared_epoch: Arc::new(AtomicU64::new(0)),
            registration_gate: Arc::new(Mutex::new(())),
            epoch: 0,
            current_connection: None,
            selected_features: None,
            resume_token: None,
            contained: false,
            hello_request_ids: BTreeSet::new(),
        }
    }

    /// Reports actual moved allocation addresses for in-crate ownership controls.
    #[cfg(test)]
    pub(crate) fn retained_configuration_addresses_data(&self) -> (*const u8, *const Id) {
        (
            self.installation.session_id.as_str().as_ptr(),
            self.policy.supported_features.as_ptr(),
        )
    }
}

fn absent() -> ProviderError {
    ProviderError::Correlation("original retained handshake configuration differs")
}
