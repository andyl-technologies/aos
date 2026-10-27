//! Encodes the fixed import18 prefix on the original private bootstrap channel.
//!
//! ```text
//! offsets: 0 magic[8]; 8 version:u64; 16 recipe_len:u64; 24 launch_len:u64;
//! 32 boot_len:u64; 40 recipe_raw_hash[32]; 72 launch_raw_hash[32];
//! 104 boot_raw_hash[32]; 136 recipe_identity[32]; 168 initial_R:u64;
//! 176 initial_T:u64; 184 initial_S:u64; 192 source_key[32]; 224 mac[32].
//! Integers are big endian. Bodies follow: exact recipe JSON, selected launch
//! JSON, then new Boot18 JSON. MAC covers the preceding224 header bytes.
//! ```
//!
//! This fixed DATA codec is not a Source signer or native admission issuer.
//! The key retains the existing inherited private-stdin treatment. Native must
//! match it to the genuine new Boot18 owner, preserve original channel/cut/
//! Source lease/member guards, independently derive and admit initial funding,
//! check all three exact body lengths/hashes before typed parse, and recompute
//! the complete recipe before model/Hold/stage effects. An embedded key and
//! matching MAC alone establish none of those facts.

use super::super::import17::{
    NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC,
    NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION,
};
use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use std::mem::size_of;

/// Names the exact fixed field widths; the original prefix568 stays unchanged.
pub const NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES: usize =
    8 + 8 + 3 * 8 + 3 * 32 + 32 + 3 * 8 + 32 + 32;
const MAC_OFFSET: usize = NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES - 32;

/// Retains a fixed authenticated-header DATA copy, never a native permission.
///
/// The private key is intentionally neither Debug-formatted nor publicly lent.
/// Every source/native owner independently counts and retains its actual bank.
pub struct PacketNativeImport18PrivatePrefixData {
    bytes: [u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
}

/// Encodes actual body identities and separately derived initial funding DATA.
///
/// The producer supplies a genuine complete opaque recipe and the actual same
/// bodies. Its caller separately owns the Source lease, member, private key and
/// constructor admission; this codec cannot establish them. The initial row is
/// independently derived, not substituted from announced complete phase rows.
///
/// # Errors
/// Refuses zero/overflowing lengths, invalid initial row or body width overflow.
pub fn encode_native_import18_private_prefix_data(
    recipe: &PacketNativeImport18PrebirthRecipeData,
    recipe_body: &[u8],
    launch_body: &[u8],
    boot_body: &[u8],
    initial: &PacketNativeStartupAllocationRow,
    key: &[u8; 32],
) -> Result<PacketNativeImport18PrivatePrefixData, ProviderError> {
    initial.requested_peak_data()?;
    let mut bytes = [0u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES];
    bytes[..8].copy_from_slice(&NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC);
    put_u64(&mut bytes, 8, NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION);
    for (index, body) in [recipe_body, launch_body, boot_body]
        .into_iter()
        .enumerate()
    {
        let length = u64::try_from(body.len()).map_err(|_| invalid())?;
        if length == 0 {
            return Err(invalid());
        }
        put_u64(&mut bytes, 16 + index * 8, length);
        bytes[40 + index * 32..72 + index * 32].copy_from_slice(blake3::hash(body).as_bytes());
    }
    bytes[136..168].copy_from_slice(&recipe.identity_data());
    for (index, value) in [
        initial.retained_requested_bytes,
        initial.maximum_simultaneous_transient_bytes,
        initial.declared_counter_scratch_bytes,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(&mut bytes, 168 + index * 8, value.get());
    }
    bytes[192..224].copy_from_slice(key);
    let mac = mac_data(&bytes, key);
    bytes[MAC_OFFSET..].copy_from_slice(&mac);
    Ok(PacketNativeImport18PrivatePrefixData { bytes })
}

/// Decodes only exact fixed DATA under three independent immutable byte bounds.
///
/// All lengths and their complete sum are checked before any caller reads or
/// allocates a body. The row is only announced DATA until independently matched
/// to the real initial producer; this method issues no scope or credit.
///
/// # Errors
/// Refuses size/magic/version/MAC, zero/overflowing or over-bound body lengths,
/// an overflowing complete private input, or an invalid positive initial row.
pub fn decode_native_import18_private_prefix_data(
    input: &[u8],
    maximum_bodies: [usize; 3],
    maximum_complete_private_bytes: usize,
) -> Result<PacketNativeImport18PrivatePrefixData, ProviderError> {
    let bytes: &[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES] =
        input.try_into().map_err(|_| invalid())?;
    if bytes[..8] != NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC
        || read_u64(bytes, 8)? != NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION
    {
        return Err(invalid());
    }
    let mut total = NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES;
    for (index, maximum) in maximum_bodies.into_iter().enumerate() {
        let length = usize::try_from(read_u64(bytes, 16 + index * 8)?).map_err(|_| invalid())?;
        if length == 0 || length > maximum {
            return Err(invalid());
        }
        total = total.checked_add(length).ok_or_else(invalid)?;
    }
    if total > maximum_complete_private_bytes {
        return Err(invalid());
    }
    let key: &[u8; 32] = bytes[192..224].try_into().map_err(|_| invalid())?;
    if bytes[MAC_OFFSET..] != mac_data(bytes, key) {
        return Err(invalid());
    }
    let result = PacketNativeImport18PrivatePrefixData { bytes: *bytes };
    result.initial_funding_data()?.requested_peak_data()?;
    Ok(result)
}

impl PacketNativeImport18PrivatePrefixData {
    /// Borrows the exact fixed header without copying or exposing a parsed key.
    pub const fn encoded_data(&self) -> &[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES] {
        &self.bytes
    }

    /// Returns the already bounded body extents in exact receive order.
    ///
    /// # Errors
    /// Refuses an unsupported scalar width in an unverified source-side header.
    pub fn body_lengths_data(&self) -> Result<[usize; 3], ProviderError> {
        Ok([
            extent(read_u64(&self.bytes, 16)?)?,
            extent(read_u64(&self.bytes, 24)?)?,
            extent(read_u64(&self.bytes, 32)?)?,
        ])
    }

    /// Checks exact lengths and complete raw bytes before typed body parsing.
    ///
    /// # Errors
    /// Refuses a missing, reordered, truncated or changed recipe/launch/Boot body.
    pub fn authenticate_body_slices_data(
        &self,
        recipe: &[u8],
        launch: &[u8],
        boot: &[u8],
    ) -> Result<(), ProviderError> {
        for (index, body) in [recipe, launch, boot].into_iter().enumerate() {
            if u64::try_from(body.len()).map_err(|_| invalid())?
                != read_u64(&self.bytes, 16 + index * 8)?
                || self.bytes[40 + index * 32..72 + index * 32] != *blake3::hash(body).as_bytes()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Compares the header identity with an independently derived opaque recipe.
    ///
    /// Native full model effects require the recomputed complete recipe and
    /// genuine admission; this equality is never a conversion from wire DATA.
    ///
    /// # Errors
    /// Refuses another complete immutable recipe identity.
    pub fn authenticate_recipe_data(
        &self,
        recipe: &PacketNativeImport18PrebirthRecipeData,
    ) -> Result<(), ProviderError> {
        if self.bytes[136..168] != recipe.identity_data() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares the inert announcement identity without validating its derivation.
    ///
    /// # Errors
    /// Refuses a prefix bound to a different announced identity.
    pub(in crate::reference_packet) fn authenticate_announced_recipe_identity_data(
        &self,
        identity: &[u8; 32],
    ) -> Result<(), ProviderError> {
        if self.bytes[136..168] != *identity {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares the embedded key to the genuine separately guarded Boot18 owner.
    ///
    /// # Errors
    /// Refuses a different private Birth key; equality alone supplies no owner.
    pub fn authenticate_private_boot_key_data(
        &self,
        expected: &[u8; 32],
    ) -> Result<(), ProviderError> {
        if self.bytes[192..224] != *expected {
            return Err(invalid());
        }
        Ok(())
    }

    /// Reads the announced initial DATA row without issuing funding or a claim.
    ///
    /// # Errors
    /// Refuses malformed fixed row coordinates.
    pub fn initial_funding_data(&self) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        Ok(PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(read_u64(&self.bytes, 168)?),
            maximum_simultaneous_transient_bytes: U64::new(read_u64(&self.bytes, 176)?),
            declared_counter_scratch_bytes: U64::new(read_u64(&self.bytes, 184)?),
        })
    }

    /// Joins all axes to the independently derived actual initial constructor row.
    ///
    /// # Errors
    /// Refuses a changed row, zero axis or overflowing requested sum.
    pub fn authenticate_initial_funding_data(
        &self,
        expected: &PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        expected.requested_peak_data()?;
        if &self.initial_funding_data()? != expected {
            return Err(invalid());
        }
        Ok(())
    }
}

fn put_u64(output: &mut [u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
fn read_u64(
    input: &[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
    offset: usize,
) -> Result<u64, ProviderError> {
    Ok(u64::from_be_bytes(
        input
            .get(offset..offset + 8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn extent(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| invalid())
}
fn mac_data(bytes: &[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES], key: &[u8; 32]) -> [u8; 32] {
    let derived = blake3::derive_key(NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, key);
    *blake3::keyed_hash(&derived, &bytes[..MAC_OFFSET]).as_bytes()
}

/// Names the actual fixed header construction/output windows before allocation.
///
/// These explicit arrays and returned DATA are temporary constructor values.
/// The caller's separately retained raw prefix bank and enclosing owner header
/// remain distinct; this declaration cannot issue either allocation.
pub const fn native_import18_private_prefix_construction_transient_data() -> usize {
    size_of::<[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES]>()
        + size_of::<PacketNativeImport18PrivatePrefixData>()
        + size_of::<Result<PacketNativeImport18PrivatePrefixData, ProviderError>>()
}

/// Names this fixed prefix codec's actual borrowed controls and hash scratch.
///
/// Complete body banks, recipe parser/field staging and parent channel/cut guards
/// remain separate constructor terms; this counter never prices or admits them.
pub fn native_import18_private_prefix_counter_scratch_data() -> usize {
    size_of::<&PacketNativeImport18PrivatePrefixData>()
        + size_of::<&[u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES]>()
        + size_of::<[&[u8]; 3]>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&'static [u8], 3>>>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 3>>>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<U64, 3>>>()
        + size_of::<[U64; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 8]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_short_and_overbound_headers_refuse_without_body_allocation() {
        let mut bytes = [0u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES];
        bytes[..8].copy_from_slice(&NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC);
        put_u64(&mut bytes, 8, 9);
        for offset in [16, 24, 32, 168, 176, 184] {
            put_u64(&mut bytes, offset, 1);
        }
        let key = [7; 32];
        bytes[192..224].copy_from_slice(&key);
        let mac = mac_data(&bytes, &key);
        bytes[MAC_OFFSET..].copy_from_slice(&mac);

        assert!(decode_native_import18_private_prefix_data(&bytes[..255], [1; 3], 259).is_err());
        assert!(decode_native_import18_private_prefix_data(&bytes, [0, 1, 1], 259).is_err());
        assert!(decode_native_import18_private_prefix_data(&bytes, [1; 3], 258).is_err());
        let decoded = decode_native_import18_private_prefix_data(&bytes, [1; 3], 259).unwrap();
        assert!(
            decoded
                .authenticate_private_boot_key_data(&[8; 32])
                .is_err()
        );
        assert!(
            decoded
                .authenticate_body_slices_data(b"x", b"y", b"z")
                .is_err()
        );
        assert_eq!(decoded.encoded_data(), &bytes);

        bytes[..8].copy_from_slice(b"CNPNS17\0");
        assert!(decode_native_import18_private_prefix_data(&bytes, [1; 3], 259).is_err());
    }
}
