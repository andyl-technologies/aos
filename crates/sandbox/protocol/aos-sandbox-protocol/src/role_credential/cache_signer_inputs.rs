//! Checks the fixed Cache signer seed/memory input DATA grammar.
//!
//! Native credential capture, private key ownership and financial admission
//! remain in each actual role/application owner. These borrowed pure checks
//! neither read a credential nor adopt supplied bytes as a role original.
//!
//! ```text
//! seed[32] ; memory = AOSCSM01 | maximum_memory_bytes:u64be
//! ```

use ed25519_dalek::VerifyingKey;

/// Names the existing fixed Cache memory-ceiling DATA framing.
pub const MEMORY_MAGIC: &[u8; 8] = b"AOSCSM01";

/// Reports a noncanonical Cache seed, memory ceiling or public-key comparison.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Cache signer input DATA is malformed or mismatched")]
pub struct CacheSignerInputDataErrorV1;

/// Borrows the exact nonzero seed array and decodes the existing memory ceiling.
///
/// This comparison DATA establishes no custody, key installation or permission.
///
/// # Errors
/// Rejects a nonexact/zero seed, wrong memory framing, short ceiling or zero
/// ceiling in the same established seed-to-memory validation order.
pub fn validate_seed_and_memory<'seed>(
    seed: &'seed [u8],
    memory: &[u8],
) -> Result<(&'seed [u8; 32], u64), CacheSignerInputDataErrorV1> {
    let seed_bytes: &[u8; 32] = seed.try_into().map_err(|_| CacheSignerInputDataErrorV1)?;
    if *seed_bytes == [0; 32] {
        return Err(CacheSignerInputDataErrorV1);
    }
    let maximum_memory_bytes = decode_memory_ceiling_data_v1(memory)?;
    Ok((seed_bytes, maximum_memory_bytes))
}

/// Compares the actual public verifier with the key derived by its owning caller.
///
/// # Errors
/// Rejects unequal public keys without installing either as a trust pin.
pub fn require_key_matches(
    pinned: &VerifyingKey,
    derived: &VerifyingKey,
) -> Result<(), CacheSignerInputDataErrorV1> {
    if pinned != derived {
        return Err(CacheSignerInputDataErrorV1);
    }
    Ok(())
}

/// Decodes the existing public physical Cache memory-ceiling DATA.
///
/// The actual F and R roles must independently capture the SAME deployed
/// artifact through their fixed native owners. This number creates no budget.
///
/// # Errors
/// Rejects wrong framing, a short ceiling or zero in the established grammar.
pub fn decode_memory_ceiling_data_v1(memory: &[u8]) -> Result<u64, CacheSignerInputDataErrorV1> {
    if memory.get(..8) != Some(MEMORY_MAGIC.as_slice()) { return Err(CacheSignerInputDataErrorV1); }
    let maximum_memory_bytes = u64::from_be_bytes(
        memory
            .get(8..16)
            .ok_or(CacheSignerInputDataErrorV1)?
            .try_into()
            .map_err(|_| CacheSignerInputDataErrorV1)?,
    );
    if maximum_memory_bytes == 0 {
        return Err(CacheSignerInputDataErrorV1);
    }
    Ok(maximum_memory_bytes)
}
