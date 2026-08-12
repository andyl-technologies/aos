//! Heap-owned construction and decoding for active scalar values.
//!
//! The current 16-byte ABI stores every scalar inline, but Candidate C boxes
//! wide integers and every float in the evaluator reservation. Production
//! evaluation therefore crosses this seam instead of depending directly on
//! context-free [`Value`] scalar accessors. The implementation remains a
//! zero-allocation baseline until the active ABI selects the compressed word.
//!
//! # Candidate-C scalar shadow (FV-4 stage S0)
//!
//! Setting `AOS_NIX_CANDIDATE_C_SHADOW=1` turns this seam into a *shadow
//! exerciser* for the inactive Candidate-C boxed-scalar store: every integer
//! and float constructed through it is additionally boxed into the reservation
//! and read back, proving the encode/decode + reservation-membership +
//! hash-cons path survives a real evaluation corpus ahead of the value-ABI
//! carrier flip. The active 16-byte carrier is unchanged — the seam still
//! returns the inline [`Value`] — so the shadow is observationally identical
//! and the flag can be enabled under the byte-parity battery. The flag is off
//! by default (a single cached bool read; no allocation on the hot path).
//! Round-trip failures are a `debug_assert` (caught by `cargo test`) and, in
//! release, a one-line `stderr` diagnostic; they never fail the evaluation.

use std::sync::OnceLock;

use crate::value::compressed::CandidateCScalarError;
use crate::{cache::runtime::CachedScalarValue, value::Value};

use super::super::{EvalHeap, EvalHeapError};

/// Returns whether the Candidate-C scalar shadow (stage S0) is enabled.
///
/// Reads `AOS_NIX_CANDIDATE_C_SHADOW` once and caches the result. `1` or
/// `true` (case-insensitive) enable the shadow; anything else leaves it off.
fn candidate_c_scalar_shadow_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("AOS_NIX_CANDIDATE_C_SHADOW")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

impl EvalHeap {
    /// Rehydrates one canonical cached scalar in this evaluator's runtime domain.
    ///
    /// # Errors
    ///
    /// Returns an allocation or publication error when the selected active ABI
    /// must box the scalar and cannot publish it in this heap.
    #[inline(always)]
    pub(crate) fn alloc_cached_scalar_value(
        &mut self,
        value: CachedScalarValue,
    ) -> Result<Value, EvalHeapError> {
        match value {
            CachedScalarValue::Int(value) => self.alloc_int_value(value),
            CachedScalarValue::FloatBits(bits) => self.alloc_float_value(f64::from_bits(bits)),
            CachedScalarValue::Bool(value) => Ok(Value::bool(value)),
            CachedScalarValue::Null => Ok(Value::null()),
        }
    }

    /// Constructs an integer in the active runtime representation.
    ///
    /// The active ABI currently carries the full `i64` inline. Candidate C can
    /// replace this implementation with its typed scalar store without
    /// changing evaluator call sites.
    ///
    /// # Errors
    ///
    /// The baseline implementation is infallible. The result remains fallible
    /// because the Candidate-C implementation may fail to publish a boxed
    /// scalar in the reservation.
    #[inline(always)]
    pub fn alloc_int_value(&mut self, value: i64) -> Result<Value, EvalHeapError> {
        #[cfg(not(feature = "candidate_c_value"))]
        {
            if candidate_c_scalar_shadow_enabled() {
                self.shadow_exercise_candidate_c_int(value);
            }
            Ok(Value::int(value))
        }
        // On the Candidate-C carrier this seam IS the boxing funnel: inline `i32`
        // stays immediate and wider integers box into the reservation scalar
        // store, returning the compressed word as a `Value`.
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.candidate_c_encode_int(value).map_err(|error| {
                EvalHeapError::CandidateCScalar {
                    message: error.to_string(),
                }
            })?;
            Ok(Value::from_word(word))
        }
    }

    /// Constructs a float in the active runtime representation.
    ///
    /// # Errors
    ///
    /// The baseline implementation is infallible. The result remains fallible
    /// because Candidate C stores the exact float bits in a typed arena cell.
    #[inline(always)]
    pub fn alloc_float_value(&mut self, value: f64) -> Result<Value, EvalHeapError> {
        #[cfg(not(feature = "candidate_c_value"))]
        {
            if candidate_c_scalar_shadow_enabled() {
                self.shadow_exercise_candidate_c_float(value);
            }
            Ok(Value::float(value))
        }
        // Every float boxes into the reservation scalar store on the Candidate-C
        // carrier (a 64-bit float does not fit the 32-bit inline payload).
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.candidate_c_encode_float(value).map_err(|error| {
                EvalHeapError::CandidateCScalar {
                    message: error.to_string(),
                }
            })?;
            Ok(Value::from_word(word))
        }
    }

    /// Boxes `value` through the Candidate-C integer store and verifies the
    /// round-trip (stage S0 shadow; never fails the evaluation).
    ///
    /// A heap without a Candidate-C reservation (explicit chunk geometry or an
    /// unsupported platform mapping) legitimately has nothing to exercise and
    /// is skipped. Any other anomaly is a `debug_assert` and a release `stderr`
    /// diagnostic.
    #[cold]
    fn shadow_exercise_candidate_c_int(&mut self, value: i64) {
        let word = match self.candidate_c_encode_int(value) {
            Ok(word) => word,
            Err(CandidateCScalarError::ReservationUnavailable) => return,
            Err(error) => return candidate_c_shadow_anomaly("int", "encode", &error),
        };
        match self.candidate_c_decode_int(word) {
            Ok(decoded) if decoded == value => {}
            Ok(_) => candidate_c_shadow_mismatch("int"),
            Err(error) => candidate_c_shadow_anomaly("int", "decode", &error),
        }
    }

    /// Boxes `value` through the Candidate-C float store and verifies the exact
    /// bit round-trip (stage S0 shadow; never fails the evaluation).
    ///
    /// Skips heaps without a Candidate-C reservation; any other anomaly is a
    /// `debug_assert` and a release `stderr` diagnostic.
    #[cold]
    fn shadow_exercise_candidate_c_float(&mut self, value: f64) {
        let word = match self.candidate_c_encode_float(value) {
            Ok(word) => word,
            Err(CandidateCScalarError::ReservationUnavailable) => return,
            Err(error) => return candidate_c_shadow_anomaly("float", "encode", &error),
        };
        match self.candidate_c_decode_float(word) {
            Ok(decoded) if decoded.to_bits() == value.to_bits() => {}
            Ok(_) => candidate_c_shadow_mismatch("float"),
            Err(error) => candidate_c_shadow_anomaly("float", "decode", &error),
        }
    }

    /// Decodes an integer from the active runtime representation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] when `value` is not an integer. A
    /// Candidate-C implementation may additionally reject a foreign or stale
    /// boxed scalar word.
    #[inline(always)]
    pub fn decode_int_value(&self, value: Value) -> Result<i64, EvalHeapError> {
        #[cfg(not(feature = "candidate_c_value"))]
        {
            value.as_int().map_err(EvalHeapError::from)
        }
        // The scalar store decodes both the inline `i32` and the boxed-`i64`
        // words, so the whole int seam funnels through it.
        #[cfg(feature = "candidate_c_value")]
        {
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            if let Some(generation) = self.packed_generation()
                && let Some(payload) = generation.integer(value)
            {
                return payload.map_err(EvalHeapError::from);
            }
            self.candidate_c_decode_int(value.word()).map_err(|error| {
                EvalHeapError::CandidateCScalar {
                    message: error.to_string(),
                }
            })
        }
    }

    /// Decodes a float from the active runtime representation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] when `value` is not a float. A
    /// Candidate-C implementation may additionally reject a foreign or stale
    /// boxed scalar word.
    #[inline(always)]
    pub fn decode_float_value(&self, value: Value) -> Result<f64, EvalHeapError> {
        #[cfg(not(feature = "candidate_c_value"))]
        {
            value.as_float().map_err(EvalHeapError::from)
        }
        #[cfg(feature = "candidate_c_value")]
        {
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            if let Some(generation) = self.packed_generation()
                && let Some(payload) = generation.float(value)
            {
                return payload.map_err(EvalHeapError::from);
            }
            self.candidate_c_decode_float(value.word())
                .map_err(|error| EvalHeapError::CandidateCScalar {
                    message: error.to_string(),
                })
        }
    }
}

/// Reports a Candidate-C scalar shadow encode/decode failure.
///
/// Fails a `debug_assert` (caught by `cargo test`) and, in release, prints one
/// `stderr` line so an `AOS_NIX_CANDIDATE_C_SHADOW=1` corpus run surfaces the
/// anomaly without changing evaluation output.
#[cold]
fn candidate_c_shadow_anomaly(kind: &str, phase: &str, error: &CandidateCScalarError) {
    debug_assert!(
        false,
        "AOS_NIX_CANDIDATE_C_SHADOW: {kind} {phase} failed: {error}"
    );
    if !cfg!(debug_assertions) {
        eprintln!("AOS_NIX_CANDIDATE_C_SHADOW: {kind} {phase} failed: {error}");
    }
}

/// Reports a Candidate-C scalar shadow round-trip that decoded a wrong value.
#[cold]
fn candidate_c_shadow_mismatch(kind: &str) {
    debug_assert!(
        false,
        "AOS_NIX_CANDIDATE_C_SHADOW: {kind} round-trip mismatch"
    );
    if !cfg!(debug_assertions) {
        eprintln!("AOS_NIX_CANDIDATE_C_SHADOW: {kind} round-trip mismatch");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{ValueError, ValueTag};

    #[test]
    fn active_scalar_boundary_preserves_full_width_values_and_float_bits() {
        let mut heap = EvalHeap::new();
        let integer = heap
            .alloc_int_value(i64::MIN)
            .expect("active integer constructs");
        let float_bits = 0xfff8_0000_0000_0042;
        let float = heap
            .alloc_float_value(f64::from_bits(float_bits))
            .expect("active float constructs");

        assert_eq!(heap.decode_int_value(integer), Ok(i64::MIN));
        assert_eq!(
            heap.decode_float_value(float).map(f64::to_bits),
            Ok(float_bits)
        );
    }

    #[test]
    fn active_scalar_boundary_preserves_checked_type_errors() {
        let heap = EvalHeap::new();

        // Both carriers reject a non-scalar handed to a scalar decoder; the error
        // kind differs by construction. The baseline decodes the tag inline and
        // reports `ValueError::Type`; the Candidate-C carrier routes the decode
        // through the compressed scalar store, which reports `CandidateCScalar`.
        let int_err = heap.decode_int_value(Value::bool(false));
        let float_err = heap.decode_float_value(Value::null());
        #[cfg(not(feature = "candidate_c_value"))]
        {
            assert_eq!(
                int_err,
                Err(EvalHeapError::Value(ValueError::Type {
                    expected: "int",
                    actual: ValueTag::Bool,
                }))
            );
            assert_eq!(
                float_err,
                Err(EvalHeapError::Value(ValueError::Type {
                    expected: "float",
                    actual: ValueTag::Null,
                }))
            );
        }
        #[cfg(feature = "candidate_c_value")]
        {
            assert!(matches!(
                int_err,
                Err(EvalHeapError::CandidateCScalar { .. })
            ));
            assert!(matches!(
                float_err,
                Err(EvalHeapError::CandidateCScalar { .. })
            ));
        }
    }

    #[test]
    fn cached_scalar_rehydration_preserves_runtime_domain_and_exact_bits() {
        let mut heap = EvalHeap::new();
        let int = heap
            .alloc_cached_scalar_value(CachedScalarValue::Int(i64::MAX))
            .expect("cached integer rehydrates");
        let float_bits = 0xfff8_0000_0000_0042;
        let float = heap
            .alloc_cached_scalar_value(CachedScalarValue::FloatBits(float_bits))
            .expect("cached float rehydrates");
        let boolean = heap
            .alloc_cached_scalar_value(CachedScalarValue::Bool(true))
            .expect("cached boolean rehydrates");
        let null = heap
            .alloc_cached_scalar_value(CachedScalarValue::Null)
            .expect("cached null rehydrates");

        assert_eq!(heap.decode_int_value(int), Ok(i64::MAX));
        assert_eq!(
            heap.decode_float_value(float).map(f64::to_bits),
            Ok(float_bits)
        );
        assert_eq!(boolean.as_bool(), Ok(true));
        assert_eq!(null.as_null(), Ok(()));
    }

    #[test]
    fn candidate_c_scalar_shadow_roundtrips_and_preserves_active_output() {
        let mut heap = EvalHeap::new();
        // Spans inline `i32`, wide `i64`, signed zero, a NaN payload, and a
        // subnormal. The shadow's internal `debug_assert` fires on any
        // round-trip failure, so a clean return in this debug test is the
        // assertion; the active seam must still yield the inline value.
        for value in [0_i64, 1, -1, i64::from(i32::MAX) + 1, i64::MIN, i64::MAX] {
            heap.shadow_exercise_candidate_c_int(value);
            let active = heap.alloc_int_value(value).expect("active int constructs");
            assert_eq!(heap.decode_int_value(active), Ok(value));
        }
        for bits in [
            0x0000_0000_0000_0000_u64,
            0x8000_0000_0000_0000,
            0xfff8_0000_0000_0042,
            0x0000_0000_0000_0001,
        ] {
            let value = f64::from_bits(bits);
            heap.shadow_exercise_candidate_c_float(value);
            let active = heap
                .alloc_float_value(value)
                .expect("active float constructs");
            assert_eq!(heap.decode_float_value(active).map(f64::to_bits), Ok(bits));
        }
    }

    // Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
    // reservation heap geometry (GC-stress record placement / chunked / fake
    // pointer) or reads a boxed wide scalar context-free — both unavailable under
    // the single-reservation Candidate-C carrier. Real eval is covered by the
    // byte-parity battery (cutover plan sections 2, 3.6).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn candidate_c_scalar_shadow_skips_reservationless_heaps() {
        // A chunked-geometry heap has no Candidate-C reservation; the shadow
        // must skip it silently rather than trip its failure diagnostics.
        let mut heap = EvalHeap::with_initial_chunk_bytes(4096).expect("chunked heap builds");
        heap.shadow_exercise_candidate_c_int(i64::MAX);
        heap.shadow_exercise_candidate_c_float(-0.0);
        let active = heap.alloc_int_value(7).expect("active int constructs");
        assert_eq!(heap.decode_int_value(active), Ok(7));
    }
}
