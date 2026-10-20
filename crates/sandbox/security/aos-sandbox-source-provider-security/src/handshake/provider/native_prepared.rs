//! Owned zero-descriptor RootPrepared reception, without admission authority.
//!
//! Root witness sequences and socket cookies are diagnostic claims. This
//! carrier brand never supplies an ordinary request sequence or Source nonce.

use aos_sandbox_source_provider_protocol::{
    native_held_completion::frame::SignedNativeHeldControlV1, verify_current_root_prepared_v1,
};

use super::{
    CurrentProviderIngressSessionV1, CurrentProviderSessionProjectionV1, poison_and_close,
};
use crate::SourceProviderSecurityError;

/// Retains a Root preparation received and verified by genuine current custody.
///
/// Its private constructor supplies no journal funding, native qualification,
/// effect or signing grant. Later pairing must revalidate the owning Session.
pub struct CurrentRootPreparedCarrierV1 {
    control: SignedNativeHeldControlV1,
    peer: CurrentProviderSessionProjectionV1,
}

impl core::fmt::Debug for CurrentRootPreparedCarrierV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentRootPreparedCarrierV1([retained carrier])")
    }
}

impl CurrentRootPreparedCarrierV1 {
    /// Borrows the exact signed carrier as nonauthorizing comparison data.
    #[must_use]
    pub const fn control(&self) -> &SignedNativeHeldControlV1 {
        &self.control
    }
}

/// Classifies exact owned-carrier bytes without permitting a Source effect.
#[derive(Debug)]
pub enum CurrentProviderOriginalCarrierPacketV1 {
    /// Retains a current Root1 carrier with no independently drawn sequence.
    RootPrepared(CurrentRootPreparedCarrierV1),
    /// Preserves an ordinary carrier packet for the existing Source classifier.
    Source(Vec<u8>),
    /// Retains malformed or ineligible Root bytes after closing actual custody.
    Rejected {
        /// Preserves the exact received packet, not authenticated authority.
        packet: Vec<u8>,
        /// Reports the verification/currentness failure that poisoned custody.
        error: SourceProviderSecurityError,
    },
}

impl CurrentProviderIngressSessionV1 {
    /// Receives an ordinary packet or a current original Root preparation.
    ///
    /// Root1 is decoded and verified only after this Session's actual zero-FD
    /// receive. Rejected Root bytes remain in the returned owning container.
    ///
    /// # Errors
    ///
    /// Returns a fatal carrier/currentness failure with this Session poisoned;
    /// retryable reception returns `None` and retains genuine custody.
    #[doc(hidden)]
    pub fn receive_current_original_packet_v1(
        &mut self,
    ) -> Result<Option<CurrentProviderOriginalCarrierPacketV1>, SourceProviderSecurityError> {
        let received = match self.receive_current_request_packet_owned() {
            Ok(received) => received,
            Err((Some(packet), error)) => {
                return Ok(Some(CurrentProviderOriginalCarrierPacketV1::Rejected {
                    packet,
                    error,
                }));
            }
            Err((None, error)) => return Err(error),
        };
        let Some(packet) = received else {
            return Ok(None);
        };
        if !packet.starts_with(b"AOSNHC01") {
            return Ok(Some(CurrentProviderOriginalCarrierPacketV1::Source(packet)));
        }

        let checked = (|| {
            let control = SignedNativeHeldControlV1::from_canonical_bytes(&packet)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            self.verify_root_prepared_current(&control)?;
            let peer = self.current_projection()?;
            Ok(CurrentRootPreparedCarrierV1 { control, peer })
        })();
        Ok(Some(match checked {
            Ok(root) => CurrentProviderOriginalCarrierPacketV1::RootPrepared(root),
            Err(error) => CurrentProviderOriginalCarrierPacketV1::Rejected {
                packet,
                error: poison_and_close(&mut self.custody, &mut self.carrier, error),
            },
        }))
    }

    /// Rechecks the same live peer and exact currently eligible retained Root1.
    ///
    /// # Errors
    ///
    /// Rejects changed current custody, original Session/process instances,
    /// authority tuples, role eligibility or signature without replacing Root1.
    #[doc(hidden)]
    pub fn revalidate_root_prepared_carrier_v1(
        &mut self,
        root: &CurrentRootPreparedCarrierV1,
    ) -> Result<(), SourceProviderSecurityError> {
        self.verify_root_prepared_current(&root.control)?;
        let current = self.current_projection()?;
        if current.provider() != root.peer.provider()
            || current.holder() != root.peer.holder()
            || current.session_binding() != root.peer.session_binding()
            || current.root_process_instance() != root.peer.root_process_instance()
            || current.provider_process_instance() != root.peer.provider_process_instance()
        {
            return Err(self.fail_current_custody_v5(
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        self.revalidate()
    }

    fn verify_root_prepared_current(
        &mut self,
        control: &SignedNativeHeldControlV1,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        let checked = super::current_unix_seconds().and_then(|now| {
            let inner = self.custody.inner();
            verify_current_root_prepared_v1(
                control,
                &self.session,
                inner.trust(),
                inner.root_authority(),
                now,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)
        });
        if let Err(error) = checked {
            return Err(self.fail_current_custody_v5(error));
        }
        self.revalidate()
    }
}
