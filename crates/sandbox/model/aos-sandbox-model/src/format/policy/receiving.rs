//! Prices the existing portable Policy/Optimization decoder models as DATA.
//!
//! Decoder::new validates the complete canonical object before any schema Vec
//! allocation. Every eventual item/path/string therefore consumes actual input
//! bytes, including a schema-invalid but canonically complete negative prefix.
//! No parser, decoder mode, limits change or authority is introduced here.

use super::*;
use crate::model::Limit;
use crate::{FeatureRef, ObjectDescriptor, PathName};
use std::mem::size_of;

// Four slots per encoded cell cover Vec's nonzero first capacity and the old
// plus new allocations at a growth frontier. This is a source allocation bound,
// not four simultaneously decoded Policy objects.
fn vector_cells<T>(encoded_bytes: usize) -> Option<usize> {
    encoded_bytes.checked_mul(4)?.checked_mul(size_of::<T>())
}

// These are the exact finite Display/to_owned messages reached from the
// Policy/Optimization codec, including nested Grant/ResourceProfile/path values.
// Registry text is separately bounded from the actual encoded string extent;
// integer formatting uses the decimal width of the real u64/usize types.
fn semantic_error_receiving_bytes_v1(encoded_bytes: usize) -> Option<usize> {
    let fixed = [
        "set-valued policy collection must be strictly ordered and unique",
        "effective grants contain a duplicate identity or semantic grant",
        "delegable grants must be an exact delegable subset of effective grants",
        "resolved policy resource limits cannot retain inheritance",
        "policy explanation source must occur in input commitments",
        "optimization entries must be unique",
        "Git upload policy profile is incomplete or inconsistent",
        "capability grant operation set must not be empty",
        "resource limits must be strictly ordered by closed dimension",
        "media type must be 1..=255 bytes of lowercase ASCII type/subtype syntax",
        "feature namespace must be 1..=255 normalized lowercase ASCII bytes",
        "path name must be 1..=255 bytes and exclude NUL, slash, dot, and dot-dot",
        "relative path exceeds the absolute 4096-component decoder ceiling",
        "base v1 registers no profile-selector body schema",
    ]
    .into_iter()
    .map(str::len)
    .max()
    .unwrap_or_default();
    let digits = usize::try_from(u64::MAX.ilog10()).ok()?.checked_add(1)?;
    let exact_digits = usize::try_from(32_usize.ilog10()).ok()?.checked_add(1)?;
    let version_digits = usize::try_from(u32::MAX.ilog10()).ok()?.checked_add(1)?;
    let integer = "integer value "
        .len()
        .checked_add(digits)?
        .checked_add(" is outside its schema width".len())?;
    let exact = "expected exactly "
        .len()
        .checked_add(exact_digits)?
        .checked_add(" bytes, found ".len())?
        .checked_add(exact_digits)?;
    let registry_context = "unknown required feature  version ."
        .len()
        .checked_add(version_digits.checked_mul(2)?)?
        .max(
            "media type  is invalid for descriptor role "
                .len()
                .checked_add(stringify!(OptimizationCommitment).len())?,
        )
        .max("unregistered portable media type ".len());
    // Unknown feature/media errors retain a separate clone before converting
    // the exact original Display into CanonicalCborError::InvalidSemantics.
    let registry_text = encoded_bytes.min(255);
    let message = fixed
        .max(integer)
        .max(exact)
        .max(registry_context.checked_add(registry_text)?);
    message
        .max(8)
        .checked_mul(4)?
        .checked_add(registry_text)?
        .checked_add(size_of::<String>().checked_mul(2)?)?
        .checked_add(size_of::<crate::RegistryError>().checked_mul(2)?)?
        .checked_add(size_of::<super::super::decode_attempt::DecodeFailure>().checked_mul(2)?)
}

/// Bounds one existing Policy or Optimization decode and exact re-encoding.
///
/// The two output kinds are alternatives in the same schema body loop. Model
/// backing, parser/encoder controls and canonical validation are included;
/// outer envelope/projection copies belong to the schema's own supplier.
///
/// # Errors
/// The passive calculation returns `None` on checked arithmetic overflow.
#[doc(hidden)]
#[must_use]
pub fn decoding_receiving_bytes_v1(encoded_bytes: usize, limits: DecodeLimits) -> Option<usize> {
    let policy = vector_cells::<FeatureRef>(encoded_bytes)?
        .checked_add(vector_cells::<ObjectDescriptor>(encoded_bytes)?)?
        .checked_add(vector_cells::<Grant>(encoded_bytes)?.checked_mul(2)?)?
        .checked_add(vector_cells::<Limit>(encoded_bytes)?)?
        .checked_add(vector_cells::<PolicyViewAction>(encoded_bytes)?)?
        .checked_add(vector_cells::<ExplanationReason>(encoded_bytes)?)?
        .checked_add(size_of::<Policy>().checked_mul(2)?)?
        .checked_add(size_of::<Result<Policy, CanonicalCborError>>())?;
    let optimization = vector_cells::<Optimization>(encoded_bytes)?
        .checked_add(size_of::<OptimizationProfile>().checked_mul(2)?)?
        .checked_add(size_of::<Result<OptimizationProfile, CanonicalCborError>>())?;
    // PathName lists and their bytes, feature namespaces and descriptor media
    // strings share the original encoded extent per model plane. Exact set
    // re-encoding additionally holds prior/item buffers and Vec<Vec<u8>>.
    let nested =
        vector_cells::<PathName>(encoded_bytes)?.checked_add(encoded_bytes.checked_mul(4)?)?;
    let encoding =
        vector_cells::<Vec<u8>>(encoded_bytes)?.checked_add(encoded_bytes.checked_mul(8)?)?;
    let controls = size_of::<Decoder<'_>>()
        .checked_mul(2)?
        .checked_add(size_of::<Encoder>().checked_mul(2)?)?
        .checked_add(size_of::<Result<Vec<u8>, CanonicalCborError>>().checked_mul(2)?)?
        .checked_add(size_of::<Option<Vec<u8>>>())?;
    policy
        .max(optimization)
        .checked_add(nested)?
        .checked_add(encoding)?
        .checked_add(controls)?
        .checked_add(semantic_error_receiving_bytes_v1(encoded_bytes)?)?
        .checked_add(super::super::canonical_cbor_validation_receiving_bytes_v1(
            encoded_bytes,
            limits,
        )?)
}
