//! Retains actual Broker configuration parts across fallible Storage key setup.
//!
//! This private result custody supplies no receiver or configuration factory.
//! The original Broker loader has already authenticated these parts; the
//! enclosing selected startup keeps its actual public descriptor pins through
//! the independent original posts before disposing any positive proof custody.

use super::*;
use aos_sandbox_broker::ProtectedBrokerPublicCredentials;
use zeroize::Zeroizing;

pub(crate) struct StorageProtectedConfigurationConversionV1 {
    authority: Option<BrokerAuthority>,
    key_id: Option<[u8; 16]>,
    secret: Option<Zeroizing<[u8; 32]>>,
    public_credentials: Option<ProtectedBrokerPublicCredentials>,
    binding: Option<ObjectDigest>,
    state_key: Option<Result<StorageStateKey, crate::StorageStateError>>,
    entered: bool,
    taken: bool,
}

impl StorageProtectedConfigurationConversionV1 {
    pub(crate) const fn new() -> Self {
        Self {
            authority: None,
            key_id: None,
            secret: None,
            public_credentials: None,
            binding: None,
            state_key: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn capture_once_v1(
        &mut self,
        configuration: &mut Option<ProtectedBrokerAuthorityConfiguration>,
    ) -> Result<(), StorageAuthorityConfigError> {
        if self.entered {
            // An offered actual configuration stays in the caller's resident
            // slot; repeat entry neither consumes it nor replaces old parts.
            return Err(StorageAuthorityConfigError::Invalid("journal-mac-key"));
        }
        self.entered = true;
        let configuration = configuration.take()
            .ok_or(StorageAuthorityConfigError::Invalid("journal-mac-key"))?;
        self.binding = Some(configuration.public_binding());
        let (authority, key_id, secret, public_credentials) =
            configuration.into_parts_with_public_credentials();
        self.authority = Some(authority);
        self.key_id = Some(key_id);
        self.secret = Some(secret);
        self.public_credentials = Some(public_credentials);
        let secret = self.secret.as_ref()
            .ok_or(StorageAuthorityConfigError::Invalid("journal-mac-key"))?;
        // Every normal part, including the six actual public original FDs,
        // is already resident before this existing fallible constructor.
        self.state_key = Some(StorageStateKey::new(key_id, **secret));
        if matches!(self.state_key, Some(Ok(_))) {
            Ok(())
        } else {
            Err(StorageAuthorityConfigError::Invalid("journal-mac-key"))
        }
    }

    pub(crate) fn take_configuration_once_v1(&mut self) -> Option<StorageProtectedConfigurationV1> {
        if !self.entered || self.taken || self.authority.is_none()
            || self.binding.is_none() || !matches!(self.state_key, Some(Ok(_)))
        {
            return None;
        }
        let (Some(authority), Some(binding), Some(Ok(state_key))) = (
            self.authority.take(), self.binding.take(), self.state_key.take(),
        ) else {
            std::process::abort();
        };
        self.taken = true;
        Some(StorageProtectedConfigurationV1 {
            authority: StorageAuthorityV1(authority), state_key, public_binding: binding,
        })
    }

    // Called only after the actual enclosing capture/conversion and fresh
    // original post are positive and both normal outputs are already parked.
    // This disposes real positive pins, without changing financial accounting.
    pub(crate) fn dispose_positive_pins_v1(&mut self) {
        if self.taken {
            drop(self.public_credentials.take());
            drop(self.secret.take());
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.state_key.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
    }
}
