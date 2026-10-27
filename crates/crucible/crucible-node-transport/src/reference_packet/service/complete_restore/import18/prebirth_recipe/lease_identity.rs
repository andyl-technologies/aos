//! Commits the fixed original mapping occurrence without issuing live custody.
//!
//! ```text
//! BLAKE3 derive-key(mapping-lease-identity/18,
//!   selected_launch[32] || private_launch[32] || nonce[32] || generation_be[8])
//! ```
//!
//! Fixed field widths make the framing unambiguous. Source and native producers
//! independently authenticate their original operands; this commitment is DATA.

use super::*;

const LEASE_IDENTITY_DOMAIN: &str = "source-owned.packet-native-import-mapping-lease-identity/18";
const MAPPING_NONCE_DOMAIN: &str = "source-owned.packet-native-import-mapping-nonce/18";

/// Derives the stable mapping challenge from an original private Birth key.
///
/// The Source authenticates its unstarted Birth before and after this calculation.
/// Native independently authenticates the private bootstrap key before comparing
/// the same challenge. The key remains borrowed; neither the challenge nor this
/// helper supplies live Birth custody, a generation, escrow or phase permission.
pub fn native_import18_mapping_nonce_data(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(MAPPING_NONCE_DOMAIN);
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

/// Names the borrowed key, fixed hash state and challenge output controls.
pub fn native_import18_mapping_nonce_counter_scratch_data() -> usize {
    size_of::<&[u8; 32]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
}

impl PacketNativeImport18PrebirthRecipeWireData {
    /// Checks the announced occurrence against independently authenticated operands.
    ///
    /// Callers first admit the defining fixed counter. Native derives the nonce
    /// from its authenticated private bootstrap key and supplies the generation
    /// of the original Source-local once occurrence. The launch identity comes
    /// from the actual typed launch and private-launch Id. This checks mapping
    /// DATA only; complete recipe reconstruction and native admission are separate.
    ///
    /// # Errors
    /// Refuses an absent occurrence or any changed launch identity, nonce,
    /// generation or mapping commitment.
    pub fn authenticate_mapping_occurrence_data(
        &self,
        launch: &PacketNativeImport18LaunchIdentityData,
        nonce: &[u8; 32],
        generation: U64,
    ) -> Result<(), ProviderError> {
        authenticate_mapping_fields(
            &self.fields,
            nonce,
            generation,
            &launch.selected_launch_identity_data(),
            &launch.private_launch_identity_data(),
        )
    }
}

/// Names the fixed field comparison and independent mapping hash controls.
pub fn native_import18_mapping_occurrence_counter_scratch_data() -> usize {
    native_import18_mapping_lease_identity_counter_scratch_data()
        + size_of::<&PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<&RecipeFields>()
        + size_of::<&[u8; 32]>() * 3
        + size_of::<U64>()
        + size_of::<Result<(), ProviderError>>()
}

/// Joins both opaque and inert recipe views to the same fixed mapping operands.
pub(super) fn authenticate_mapping_fields(
    fields: &RecipeFields,
    nonce: &[u8; 32],
    generation: U64,
    selected: &[u8; 32],
    private: &[u8; 32],
) -> Result<(), ProviderError> {
    validate_occurrence(nonce, generation).map_err(|_| mapping_mismatch())?;
    if fields.nonce != *nonce
        || fields.generation != generation
        || fields.selected_launch_identity != *selected
        || fields.private_launch_identity != *private
        || fields.lease_identity != commit_identity(selected, private, nonce, generation)
    {
        return Err(mapping_mismatch());
    }
    Ok(())
}

fn mapping_mismatch() -> ProviderError {
    ProviderError::Correlation("original import18 mapping occurrence DATA")
}

/// Commits the actual launch identities and original mapping occurrence as DATA.
///
/// The Source independently owns its once-only mapping attempt and genuine
/// private Birth. Native independently authenticates the private bootstrap and
/// reconstructed recipe. Neither this digest nor the generation creates that
/// custody, an escrow reservation, a phase claim or allocation permission.
///
/// # Errors
/// Refuses an absent mapping nonce or a zero occurrence generation.
pub fn native_import18_mapping_lease_identity_data(
    launch: &PacketNativeImport18LaunchIdentityData,
    nonce: &[u8; 32],
    generation: U64,
) -> Result<[u8; 32], ProviderError> {
    validate_occurrence(nonce, generation)?;
    Ok(commit_identity(
        &launch.selected_launch_identity_data(),
        &launch.private_launch_identity_data(),
        nonce,
        generation,
    ))
}

/// Names the fixed commitment operands, hash state and validation controls.
pub fn native_import18_mapping_lease_identity_counter_scratch_data() -> usize {
    size_of::<&PacketNativeImport18LaunchIdentityData>()
        + size_of::<&[u8; 32]>() * 4
        + size_of::<[u8; 32]>() * 3
        + size_of::<[u8; 8]>()
        + size_of::<U64>() * 2
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

fn validate_occurrence(nonce: &[u8; 32], generation: U64) -> Result<(), ProviderError> {
    if *nonce == [0; 32] || generation.get() == 0 {
        return Err(invalid());
    }
    Ok(())
}

fn commit_identity(
    selected: &[u8; 32],
    private: &[u8; 32],
    nonce: &[u8; 32],
    generation: U64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(LEASE_IDENTITY_DOMAIN);
    hasher.update(selected);
    hasher.update(private);
    hasher.update(nonce);
    hasher.update(&generation.get().to_be_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_birth_mapping_nonce_is_stable_and_domain_separated() {
        let key = [42; 32];
        let nonce = native_import18_mapping_nonce_data(&key);

        assert_eq!(nonce, blake3::derive_key(MAPPING_NONCE_DOMAIN, &key));
        assert_eq!(nonce, native_import18_mapping_nonce_data(&key));
        assert_ne!(nonce, native_import18_mapping_nonce_data(&[43; 32]));
        assert_ne!(nonce, key);
        assert_ne!(nonce, [0; 32]);
        for domain in [
            "source-owned.packet-canonical-ack-birth/5",
            "source-owned.packet-native-host-sdk-challenge/1",
        ] {
            assert_ne!(nonce, blake3::derive_key(domain, &key));
        }
    }

    #[test]
    fn mapping_commitment_binds_every_fixed_occurrence_operand() {
        let selected = [11; 32];
        let private = [22; 32];
        let nonce = [33; 32];
        let generation = U64::new(1);
        let original = commit_identity(&selected, &private, &nonce, generation);

        assert_eq!(
            original,
            commit_identity(&selected, &private, &nonce, generation)
        );
        assert_ne!(
            original,
            commit_identity(&[12; 32], &private, &nonce, generation)
        );
        assert_ne!(
            original,
            commit_identity(&selected, &[23; 32], &nonce, generation)
        );
        assert_ne!(
            original,
            commit_identity(&selected, &private, &[34; 32], generation)
        );
        assert_ne!(
            original,
            commit_identity(&selected, &private, &nonce, U64::new(2))
        );
        assert_ne!(
            original,
            commit_identity(&private, &selected, &nonce, generation)
        );
    }

    #[test]
    fn missing_nonce_and_zero_generation_cannot_name_an_occurrence() {
        assert!(validate_occurrence(&[1; 32], U64::new(1)).is_ok());
        assert!(validate_occurrence(&[0; 32], U64::new(1)).is_err());
        assert!(validate_occurrence(&[1; 32], U64::new(0)).is_err());
    }
}
