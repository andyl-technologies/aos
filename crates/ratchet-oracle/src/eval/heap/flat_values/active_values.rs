//! Heap-owned construction and decoding for active scalar values.
//!
//! The current 16-byte ABI stores every scalar inline, but Candidate C boxes
//! wide integers and every float in the evaluator reservation. Production
//! evaluation therefore crosses this seam instead of depending directly on
//! context-free [`Value`] scalar accessors. The implementation remains a
//! zero-allocation baseline until the active ABI selects the compressed word.

use crate::value::Value;

use super::super::{EvalHeap, EvalHeapError};

impl EvalHeap {
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
        Ok(Value::int(value))
    }

    /// Constructs a float in the active runtime representation.
    ///
    /// # Errors
    ///
    /// The baseline implementation is infallible. The result remains fallible
    /// because Candidate C stores the exact float bits in a typed arena cell.
    #[inline(always)]
    pub fn alloc_float_value(&mut self, value: f64) -> Result<Value, EvalHeapError> {
        Ok(Value::float(value))
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
        value.as_int().map_err(EvalHeapError::from)
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
        value.as_float().map_err(EvalHeapError::from)
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

        assert_eq!(
            heap.decode_int_value(Value::bool(false)),
            Err(EvalHeapError::Value(ValueError::Type {
                expected: "int",
                actual: ValueTag::Bool,
            }))
        );
        assert_eq!(
            heap.decode_float_value(Value::null()),
            Err(EvalHeapError::Value(ValueError::Type {
                expected: "float",
                actual: ValueTag::Null,
            }))
        );
    }
}
