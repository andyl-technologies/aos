//! Canonical DATA for the versioned Host argument preparation.
//!
//! A preparation creates no Guest nonce and carries no transferable execution
//! authority. Host accepts it only by comparing its own retained preparation,
//! live Agent, protected source and authenticated Controller Session.
//!
//! ```text
//! AOSHAP02 || proposed-AOSCIA02:336 || Controller-session:32
//!          || live-Agent-session:32 || runtime-handle:32
//!          || signed-Prepare-request:32 || Host-cut:32
//!          || Host-effect-epoch:u64be || checksum:32
//! ```

use sha2::{Digest as _, Sha256};

use crate::semantics::host_execution_argument::canonical_attempt_request_id_v1;
use crate::ProtocolValidationError;

/// Exact encoded width of one non-consuming Host preparation.
pub const HOST_ARGUMENT_PREPARATION_BYTES_V2: usize = 544;

const MAGIC: &[u8; 8] = b"AOSHAP02";
const DOMAIN: &[u8] = b"aos.sandbox.host-argument-preparation.v2\0";
const CONTENT_BYTES: usize = HOST_ARGUMENT_PREPARATION_BYTES_V2 - 32;

/// Stores canonical preparation coordinates without conferring their authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostArgumentPreparationV2 {
    bytes: [u8; HOST_ARGUMENT_PREPARATION_BYTES_V2],
}

impl HostArgumentPreparationV2 {
    /// Encodes structurally valid observed coordinates.
    ///
    /// The caller supplies DATA. Only the Host's real native preparation owner
    /// can use an exact match to enter the Accept transition.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical source or a zero Session, runtime, request, cut
    /// or effect epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn from_observed_fields(
        source: &[u8],
        controller_session: [u8; 32],
        agent_session: [u8; 32],
        runtime_handle: [u8; 32],
        signed_prepare_request: [u8; 32],
        host_cut: [u8; 32],
        host_effect_epoch: u64,
    ) -> Result<Self, ProtocolValidationError> {
        canonical_attempt_request_id_v1(source).map_err(|_| invalid())?;
        let mut bytes = [0; HOST_ARGUMENT_PREPARATION_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..344].copy_from_slice(source);
        for (range, field) in [
            (344..376, controller_session),
            (376..408, agent_session),
            (408..440, runtime_handle),
            (440..472, signed_prepare_request),
            (472..504, host_cut),
        ] {
            bytes[range].copy_from_slice(&field);
        }
        bytes[504..512].copy_from_slice(&host_effect_epoch.to_be_bytes());
        let checksum = checksum(&bytes[..CONTENT_BYTES]);
        bytes[CONTENT_BYTES..].copy_from_slice(&checksum);
        Self::decode(&bytes)
    }

    /// Decodes exact preparation DATA and checks its canonical checksum.
    ///
    /// # Errors
    ///
    /// Rejects incorrect width, magic, source, required identities or checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; HOST_ARGUMENT_PREPARATION_BYTES_V2] =
            bytes.try_into().map_err(|_| invalid())?;
        canonical_attempt_request_id_v1(&bytes[8..344]).map_err(|_| invalid())?;
        if &bytes[..8] != MAGIC
            || bytes[CONTENT_BYTES..] != checksum(&bytes[..CONTENT_BYTES])
            || [344..376, 376..408, 408..440, 440..472, 472..504, 504..512]
                .iter()
                .any(|range| bytes[range.clone()].iter().all(|byte| *byte == 0))
        {
            return Err(invalid());
        }
        Ok(Self { bytes })
    }

    /// Borrows the complete canonical DATA.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; HOST_ARGUMENT_PREPARATION_BYTES_V2] {
        &self.bytes
    }

    /// Borrows the original proposed source, whose request names Prepare.
    #[must_use]
    pub fn proposed_source(&self) -> &[u8] {
        &self.bytes[8..344]
    }

    /// Returns the digest bound by the separate Accept grant.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// Returns the exact observed controller session DATA.
    #[must_use]
    pub fn controller_session(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[344..376]);
        bytes
    }

    /// Returns the exact observed agent session DATA.
    #[must_use]
    pub fn agent_session(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[376..408]);
        bytes
    }

    /// Returns the exact observed runtime handle DATA.
    #[must_use]
    pub fn runtime_handle(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[408..440]);
        bytes
    }

    /// Returns the exact observed host cut DATA.
    #[must_use]
    pub fn host_cut(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[472..504]);
        bytes
    }

    /// Returns the exact epoch read under the protected Host Effect writer.
    #[must_use]
    pub fn host_effect_epoch(&self) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.bytes[504..512]);
        u64::from_be_bytes(bytes)
    }

    /// Returns the protected Prepare request's signed ClientRecord digest.
    #[must_use]
    pub fn signed_prepare_request(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[440..472]);
        bytes
    }

    /// Checks an Accept source against the unchanged proposed source fields.
    ///
    /// The two authenticated requests have distinct IDs. Every other source
    /// byte, including the original nonrenewable deadline, must agree. Both
    /// sources pass the sole existing canonical source validator first.
    ///
    /// # Errors
    ///
    /// Rejects malformed sources, reused request IDs or any changed field.
    pub fn require_accept_source(&self, source: &[u8]) -> Result<(), ProtocolValidationError> {
        let accepted = canonical_attempt_request_id_v1(source).map_err(|_| invalid())?;
        let proposed = canonical_attempt_request_id_v1(self.proposed_source())
            .map_err(|_| invalid())?;
        if accepted == proposed
            || source[..40] != self.proposed_source()[..40]
            || source[56..304] != self.proposed_source()[56..304]
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares exact independently observed Session, Agent, runtime and cut DATA.
    #[must_use]
    pub fn matches_observed(
        &self,
        controller_session: &[u8; 32],
        agent_session: &[u8; 32],
        runtime_handle: &[u8; 32],
        host_cut: &[u8; 32],
    ) -> bool {
        self.bytes[344..376] == *controller_session
            && self.bytes[376..408] == *agent_session
            && self.bytes[408..440] == *runtime_handle
            && self.bytes[472..504] == *host_cut
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host argument preparation")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(request: u8) -> [u8; 336] {
        let mut source = [3; 336];
        source[..8].copy_from_slice(b"AOSCIA02");
        source[40..56].fill(request);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&source[..304]).finalize().into();
        source[304..].copy_from_slice(&digest);
        source
    }

    fn preparation() -> HostArgumentPreparationV2 {
        HostArgumentPreparationV2::from_observed_fields(
            &source(4), [5; 32], [6; 32], [7; 32], [8; 32], [9; 32], 10,
        ).unwrap()
    }

    #[test]
    fn accept_changes_only_the_actual_request_identity() {
        let preparation = preparation();
        assert!(preparation.require_accept_source(&source(11)).is_ok());
        assert!(preparation.require_accept_source(&source(4)).is_err());

        let mut changed = source(11);
        changed[296] ^= 1;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&changed[..304]).finalize().into();
        changed[304..].copy_from_slice(&digest);
        assert!(preparation.require_accept_source(&changed).is_err());
    }

    #[test]
    fn preparation_requires_all_observed_bindings_and_exact_bytes() {
        let preparation = preparation();
        assert!(preparation.matches_observed(&[5; 32], &[6; 32], &[7; 32], &[9; 32]));
        assert!(!preparation.matches_observed(&[5; 32], &[0; 32], &[7; 32], &[9; 32]));
        assert_eq!(HostArgumentPreparationV2::decode(preparation.canonical_bytes()).unwrap(), preparation);

        let mut changed = *preparation.canonical_bytes();
        changed[376] ^= 1;
        assert!(HostArgumentPreparationV2::decode(&changed).is_err());
    }
}
