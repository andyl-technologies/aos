//! Commits exact Create Storage V1 Ready bytes as passive correlation DATA.
//!
//! The borrowed bundle codec frames every required original input and checks
//! their shared history associations. Genuine producers must derive every
//! field from live originals, and receivers must independently validate all
//! nested schemas and their own current cut before a positive transition.
//! Hashing inert bytes establishes neither canonical B nor current authority.
//!
//! ```text
//! Ready = SHA256("aos.sandbox.create-storage.ready.v1\0" || exact_encoded_B)
//! ReadyIndex.digest = Open.ready = Ready
//! ```

mod bundle;
mod inputs_ready;

pub use inputs_ready::{
    InputsReadyBodyDataV1, InputsReadyNativeReceiptDataV1,
    INPUTS_READY_BODY_BYTES_V1, INPUTS_READY_RECORD_BYTES_V1, INPUTS_READY_RECEIPT_BYTES_V1,
};

pub use bundle::{ControllerAdmissionDataV1, IntentNativeReceiptDataV1, ReadyBundleDataV1};

use sha2::{Digest as _, Sha256};

const READY_DOMAIN_V1: &[u8] = b"aos.sandbox.create-storage.ready.v1\0";

/// Commits the exact complete encoded Ready bundle as inert correlation DATA.
///
/// This allocation-free hash does not parse, canonicalize or authenticate the
/// bundle, issue a receiving budget, or establish a held current cut. The same
/// helper binds the original producer's Open, transfer index and actual bytes.
#[must_use]
pub fn ready_commitment_v1(exact_encoded_b: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(READY_DOMAIN_V1)
        .chain_update(exact_encoded_b).finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_matches_independent_fixed_domain_vector() {
        assert_eq!(
            ready_commitment_v1(b"ready-v1-golden"),
            [
                0x10, 0x0c, 0x54, 0x29, 0x47, 0x9c, 0x09, 0xfb,
                0x7d, 0x3d, 0xbb, 0xc6, 0xde, 0x7f, 0x3e, 0x64,
                0xfb, 0x03, 0xbc, 0xea, 0x6a, 0xe4, 0x51, 0x09,
                0xed, 0x04, 0x4b, 0xb7, 0xc3, 0x25, 0x78, 0x2a,
            ],
        );
        let raw: [u8; 32] = Sha256::digest(b"ready-v1-golden").into();
        assert_ne!(ready_commitment_v1(b"ready-v1-golden"), raw);
        assert_ne!(ready_commitment_v1(b"ready-v1-golden"), ready_commitment_v1(b"ready-v1-golden\0"));
    }
}
