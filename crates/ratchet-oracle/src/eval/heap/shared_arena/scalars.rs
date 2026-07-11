//! Candidate-C boxed scalars shared across parallel evaluator workers.
//!
//! One [`SharedHeapArena`](super::SharedHeapArena) owns the typed scalar
//! stores in the same reservation as every shard's flat objects. This module
//! keeps the public encode/decode seam out of the shared-arena ownership and
//! resolution implementation.

use crate::value::compressed::{CandidateCScalarError, CompressedValueWord};

use super::SharedHeapArena;

impl SharedHeapArena {
    /// Encodes an integer in the shared Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared reservation is unavailable, its scalar
    /// store is full, or scalar publication fails.
    pub fn candidate_c_encode_int(
        &self,
        value: i64,
    ) -> Result<CompressedValueWord, CandidateCScalarError> {
        self.compressed_scalars
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .encode_int(value)
    }

    /// Encodes a float in the shared Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared reservation is unavailable, its scalar
    /// store is full, or scalar publication fails.
    pub fn candidate_c_encode_float(
        &self,
        value: f64,
    ) -> Result<CompressedValueWord, CandidateCScalarError> {
        self.compressed_scalars
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .encode_float(value)
    }

    /// Decodes an integer from the shared Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unavailable or `word` does not
    /// name an integer cell published in this shared arena.
    pub fn candidate_c_decode_int(
        &self,
        word: CompressedValueWord,
    ) -> Result<i64, CandidateCScalarError> {
        self.compressed_scalars
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .decode_int(word)
    }

    /// Decodes a float from the shared Candidate-C scalar store.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unavailable or `word` does not
    /// name a float cell published in this shared arena.
    pub fn candidate_c_decode_float(
        &self,
        word: CompressedValueWord,
    ) -> Result<f64, CandidateCScalarError> {
        self.compressed_scalars
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .decode_float(word)
    }
}
