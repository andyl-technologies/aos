//! Lends a stable mapping nonce under the actual Source and private Birth guards.
//!
//! The nonce binds a future mapping to this occurrence. Repeating this DATA
//! query neither creates nor renews a lease, generation, escrow or phase claim.

use super::*;

impl PacketCompleteSemanticSource {
    /// Derives this occurrence's mapping nonce from its genuine private Birth.
    ///
    /// The caller first admits
    /// [`Self::native_import18_original_mapping_nonce_counter_data`]. The fixed
    /// output has no backing. The original Source, accepted worker banks, launch
    /// and private Birth remain guarded through every outcome. No key is exposed,
    /// worker response parsed or mapping authority reconstructed from DATA.
    ///
    /// # Errors
    /// Refuses unavailable, foreign, changed, busy or started original custody.
    pub fn native_import18_original_mapping_nonce_data(&self) -> Result<[u8; 32], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = loan.birth.import18_mapping_nonce_data();
        let current = loan.authenticate();
        result.and_then(|nonce| current.map(|()| nonce))
    }

    /// Names original-loan and fixed hash controls before deriving the nonce.
    ///
    /// The returned retained/transient/control row prices the DATA query only;
    /// every existing owner and the eventual mapping admission remain separate.
    pub fn native_import18_original_mapping_nonce_counter_data() -> [usize; 3] {
        let [retained, transient, scratch] =
            Self::native_import18_source_declaration_construction_data();
        [
            retained,
            transient,
            scratch
                + birth::OriginalAckPeerBirth::import18_mapping_nonce_counter_scratch_data()
                + size_of::<&Self>()
                + size_of::<[u8; 32]>()
                + size_of::<Result<[u8; 32], RuntimeError>>() * 2
                + size_of::<Result<(), RuntimeError>>(),
        ]
    }
}
