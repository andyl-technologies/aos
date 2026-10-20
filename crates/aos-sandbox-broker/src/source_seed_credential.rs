//! Verifies signed seed DATA using the one compiled native issuer recipe.
//!
//! Original pin/read/recheck mechanics are shared with all other fixed native
//! credentials. This ordinary adapter confers no Controller/Source admission,
//! current head, paid original, epoch spend, or append capability.

use crate::systemd_credentials::PinnedSystemdCredential;
use aos_sandbox_protocol::controller_source_seed::{
    ControllerSourceTreeSeedErrorV1, ControllerSourceTreeSeedExpectedV1,
    PinnedControllerSourceTreeSeedIssuerV1, VerifiedControllerSourceTreeSeedV1,
    verify_controller_source_tree_seed_v1,
};

/// Retains the fixed systemd issuer pin and its protected file identity.
///
/// Only the Controller's fixed credential name can supply the trust root for
/// this path. Verification still grants no Source append authority.
struct ProtectedControllerSourceTreeSeedIssuerV1 {
    credential: PinnedSystemdCredential,
    pin: PinnedControllerSourceTreeSeedIssuerV1,
}

impl ProtectedControllerSourceTreeSeedIssuerV1 {
    fn from_systemd_credentials() -> Result<Self, ControllerSourceTreeSeedErrorV1> {
        let credential = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let pin = PinnedControllerSourceTreeSeedIssuerV1::decode(credential.bytes())?;
        credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        Ok(Self { credential, pin })
    }

    fn verify(
        &self,
        bytes: &[u8],
        expected: ControllerSourceTreeSeedExpectedV1,
    ) -> Result<VerifiedControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1> {
        self.credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let verified = verify_controller_source_tree_seed_v1(bytes, &self.pin, expected);
        self.credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        verified
    }
}

/// Verifies a proposal using the Controller's fixed privileged issuer pin.
///
/// The Controller must derive `expected` under protected current custody.
/// Even then, the verified packet is nonauthorizing until a future owner
/// retains the Controller writer through the Source append and durably spends
/// the issuer epoch. This check performs none of those effects.
///
/// # Errors
///
/// Rejects absent, malformed, or replaced credential custody, malformed or
/// stale packet claims, and invalid signatures.
pub fn verify_controller_source_tree_seed_from_fixed_issuer_v1(
    bytes: &[u8],
    expected: ControllerSourceTreeSeedExpectedV1,
) -> Result<VerifiedControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1> {
    ProtectedControllerSourceTreeSeedIssuerV1::from_systemd_credentials()?.verify(bytes, expected)
}
