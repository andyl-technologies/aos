//! Candidate-C boxed scalar storage in the evaluator's serial reservation.
//!
//! The active 16-byte [`Value`] keeps full-width integers and floats inline.
//! Candidate C instead inlines only `i32` and places every wider integer and
//! float in hash-consed cells addressed by the same reservation-relative
//! indices as the permanent flat-object stores. This module owns the evaluator
//! seam for exercising that storage before the value/FFI/JIT ABI switches.

use crate::value::compressed::{CandidateCScalarError, CandidateCScalarStore, CompressedValueWord};

use super::*;

impl EvalHeap {
    /// Encodes an integer through the Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateCScalarError::ReservationUnavailable`] when this
    /// heap uses explicit chunk geometry or its platform could not create the
    /// Candidate-C reservation. Allocation failures are also returned.
    pub fn candidate_c_encode_int(
        &mut self,
        value: i64,
    ) -> Result<CompressedValueWord, CandidateCScalarError> {
        candidate_c_scalars_mut(&mut self.compressed_scalars)?.encode_int(value)
    }

    /// Encodes a float through the Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateCScalarError::ReservationUnavailable`] when this
    /// heap has no Candidate-C reservation. Allocation failures are also
    /// returned.
    pub fn candidate_c_encode_float(
        &mut self,
        value: f64,
    ) -> Result<CompressedValueWord, CandidateCScalarError> {
        candidate_c_scalars_mut(&mut self.compressed_scalars)?.encode_float(value)
    }

    /// Decodes an integer from the Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unavailable, the word has the
    /// wrong kind, or its boxed index is not live in this heap.
    pub fn candidate_c_decode_int(
        &self,
        word: CompressedValueWord,
    ) -> Result<i64, CandidateCScalarError> {
        candidate_c_scalars(&self.compressed_scalars)?.decode_int(word)
    }

    /// Decodes a float from the Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unavailable, the word has the
    /// wrong kind, or its boxed index is not live in this heap.
    pub fn candidate_c_decode_float(
        &self,
        word: CompressedValueWord,
    ) -> Result<f64, CandidateCScalarError> {
        candidate_c_scalars(&self.compressed_scalars)?.decode_float(word)
    }
}

fn candidate_c_scalars(
    store: &Option<CandidateCScalarStore>,
) -> Result<&CandidateCScalarStore, CandidateCScalarError> {
    store
        .as_ref()
        .ok_or(CandidateCScalarError::ReservationUnavailable)
}

fn candidate_c_scalars_mut(
    store: &mut Option<CandidateCScalarStore>,
) -> Result<&mut CandidateCScalarStore, CandidateCScalarError> {
    store
        .as_mut()
        .ok_or(CandidateCScalarError::ReservationUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluator_candidate_c_scalar_seam_roundtrips_full_width_values() {
        let mut heap = EvalHeap::new();
        let wide = i64::from(i32::MAX) + 1;
        let int = heap
            .candidate_c_encode_int(wide)
            .expect("wide integer encodes");
        let float = heap.candidate_c_encode_float(-0.0).expect("float encodes");

        assert_eq!(
            heap.candidate_c_decode_int(int).expect("integer decodes"),
            wide
        );
        assert_eq!(
            heap.candidate_c_decode_float(float)
                .expect("float decodes")
                .to_bits(),
            (-0.0f64).to_bits()
        );
    }

    #[test]
    fn explicit_chunk_geometry_declines_candidate_c_scalars() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(4096).expect("chunked heap builds");
        assert!(matches!(
            heap.candidate_c_encode_int(i64::MAX),
            Err(CandidateCScalarError::ReservationUnavailable)
        ));
    }
}
