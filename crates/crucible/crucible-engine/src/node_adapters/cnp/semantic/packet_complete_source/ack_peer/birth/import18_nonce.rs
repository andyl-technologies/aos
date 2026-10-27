//! Derives a mapping challenge from the same unstarted private Birth.
//!
//! The challenge is stable for this Birth and domain separated from its boot
//! and SDK challenges. It supplies no generation, lease, escrow or phase claim.

use super::OriginalAckPeerBirth;
use crate::node_contract::RuntimeError;
use std::mem::size_of;

const MAPPING_NONCE_DOMAIN: &str = "source-owned.packet-native-import-mapping-nonce/18";

impl OriginalAckPeerBirth {
    /// Returns the mapping challenge without lending or copying the private key.
    ///
    /// # Errors
    /// Refuses foreign, failed, unavailable or already started private custody.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn import18_mapping_nonce_data(
        &self,
    ) -> Result<[u8; 32], RuntimeError> {
        self.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
        let nonce = mapping_nonce(&self.key);
        self.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
        Ok(nonce)
    }

    /// Names the fixed hash and original-guard controls before inspecting Birth.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn import18_mapping_nonce_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<&[u8; 32]>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>()
            + size_of::<Result<[u8; 32], RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>() * 2
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}

fn mapping_nonce(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(MAPPING_NONCE_DOMAIN);
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_challenge_is_stable_and_separate_from_boot_and_sdk_challenges() {
        let key = [42; 32];
        let nonce = mapping_nonce(&key);

        assert_eq!(nonce, mapping_nonce(&key));
        assert_eq!(nonce, blake3::derive_key(MAPPING_NONCE_DOMAIN, &key));
        assert_ne!(nonce, mapping_nonce(&[43; 32]));
        assert_ne!(nonce, [0; 32]);
        assert_ne!(nonce, key);
        for domain in [
            "source-owned.packet-canonical-ack-birth/5",
            "source-owned.packet-native-host-sdk-challenge/1",
        ] {
            assert_ne!(nonce, blake3::derive_key(domain, &key));
        }
    }
}
