//! Stable envelopes for persistent, address-free compiled-body artifacts.
//!
//! The payload is verified CLIF, not executable memory. Decoding verifies both
//! functions again before returning a lowering that a fresh [`crate::JitModuleContext`]
//! may compile and finalize.

use cranelift_codegen::ir::Function;
use ratchet_core::IrId;
use serde::{Deserialize, Serialize};

use crate::{JitTier2LambdaLowering, lower::verify_clif_function};

const TIER2_LAMBDA_CODEC_VERSION: u32 = 1;

/// Returns the exact target triple that scopes persistent CLIF records.
pub fn compiled_body_target_triple() -> String {
    target_lexicon::HOST.to_string()
}

#[derive(Serialize, Deserialize)]
struct CachedTier2LambdaLowering {
    version: u32,
    source: u32,
    self_upval: (u32, u32),
    self_call_count: u32,
    entry: Function,
    inner: Function,
}

/// Reports an invalid or unreadable persistent compiled-body payload.
#[derive(Debug, thiserror::Error)]
pub enum JitCompiledBodyCodecError {
    /// Binary encoding or decoding failed.
    #[error("compiled-body binary codec failed: {0}")]
    Binary(#[from] Box<bincode::ErrorKind>),
    /// The payload uses an unsupported schema version.
    #[error("compiled-body schema {found} does not match {expected}")]
    Schema {
        /// Version required by this evaluator.
        expected: u32,
        /// Version found in the payload.
        found: u32,
    },
    /// The payload names a different IR body than the cache key.
    #[error("compiled-body source {found} does not match expected {expected}")]
    Source {
        /// Body ID required by the cache key.
        expected: u32,
        /// Body ID found in the payload.
        found: u32,
    },
    /// A decoded CLIF function failed Cranelift verification.
    #[error("compiled-body {function} CLIF failed verification: {detail}")]
    Verification {
        /// Function role in the paired lowering.
        function: &'static str,
        /// Cranelift verifier diagnostic.
        detail: String,
    },
}

/// Encodes a verified unary tier-2 lowering without executable addresses.
///
/// # Errors
///
/// Returns [`JitCompiledBodyCodecError::Binary`] when serde cannot encode the
/// Cranelift functions.
pub fn encode_tier2_lambda_lowering(
    lowering: &JitTier2LambdaLowering,
) -> Result<Vec<u8>, JitCompiledBodyCodecError> {
    let cached = CachedTier2LambdaLowering {
        version: TIER2_LAMBDA_CODEC_VERSION,
        source: lowering.source().as_u32(),
        self_upval: lowering.self_upval(),
        self_call_count: lowering.self_call_count(),
        entry: lowering.entry().clone(),
        inner: lowering.inner().clone(),
    };
    Ok(bincode::serialize(&cached)?)
}

/// Decodes and re-verifies an address-free unary tier-2 lowering.
///
/// # Errors
///
/// Returns an error for malformed bytes, a schema or source mismatch, or CLIF
/// rejected by the active Cranelift verifier.
pub fn decode_tier2_lambda_lowering(
    bytes: &[u8],
    expected_source: IrId,
) -> Result<JitTier2LambdaLowering, JitCompiledBodyCodecError> {
    let cached: CachedTier2LambdaLowering = bincode::deserialize(bytes)?;
    if cached.version != TIER2_LAMBDA_CODEC_VERSION {
        return Err(JitCompiledBodyCodecError::Schema {
            expected: TIER2_LAMBDA_CODEC_VERSION,
            found: cached.version,
        });
    }
    if cached.source != expected_source.as_u32() {
        return Err(JitCompiledBodyCodecError::Source {
            expected: expected_source.as_u32(),
            found: cached.source,
        });
    }
    verify("entry", &cached.entry)?;
    verify("inner", &cached.inner)?;
    Ok(JitTier2LambdaLowering::from_cached_parts(
        cached.entry,
        cached.inner,
        expected_source,
        cached.self_upval,
        cached.self_call_count,
    ))
}

fn verify(
    function_name: &'static str,
    function: &Function,
) -> Result<(), JitCompiledBodyCodecError> {
    verify_clif_function(function).map_err(|error| JitCompiledBodyCodecError::Verification {
        function: function_name,
        detail: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use ratchet_core::{lower, resolve};

    use super::*;
    use crate::{TIER2_NATIVE_DEPTH_BUDGET, lower_tier2_self_recursive_lambda};

    fn fib_lowering() -> JitTier2LambdaLowering {
        let ir = lower(
            resolve(
                ratchet_core::syntax::parse_str(
                    "let fib = n: if n < 2 then n else fib (n - 1) + fib (n - 2); in fib 8",
                )
                .expect("fib parses"),
            )
            .expect("fib resolves"),
        )
        .expect("fib lowers");
        let lambda = ir
            .arena
            .nodes()
            .iter()
            .find_map(|node| match node.data {
                ratchet_core::IrData::Lambda { pattern, body, .. } => Some((pattern, body)),
                _ => None,
            })
            .expect("fib lambda exists");
        lower_tier2_self_recursive_lambda(&ir.arena, lambda.0, lambda.1, TIER2_NATIVE_DEPTH_BUDGET)
            .expect("fib lowers to tier 2")
    }

    #[test]
    fn unary_tier2_lowering_round_trips_as_verified_clif() {
        let lowering = fib_lowering();
        let encoded = encode_tier2_lambda_lowering(&lowering).expect("lowering encodes");
        let decoded =
            decode_tier2_lambda_lowering(&encoded, lowering.source()).expect("lowering decodes");

        assert_eq!(decoded.source(), lowering.source());
        assert_eq!(decoded.self_upval(), lowering.self_upval());
        assert_eq!(decoded.self_call_count(), lowering.self_call_count());
        assert_eq!(
            decoded.entry().display().to_string(),
            lowering.entry().display().to_string()
        );
        assert_eq!(
            decoded.inner().display().to_string(),
            lowering.inner().display().to_string()
        );
    }

    #[test]
    fn unary_tier2_lowering_rejects_wrong_source() {
        let lowering = fib_lowering();
        let encoded = encode_tier2_lambda_lowering(&lowering).expect("lowering encodes");
        let wrong = IrId::new(lowering.source().as_u32().saturating_add(1));

        assert!(matches!(
            decode_tier2_lambda_lowering(&encoded, wrong),
            Err(JitCompiledBodyCodecError::Source { .. })
        ));
    }
}
