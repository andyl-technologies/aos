//! Candidate-C boxed scalars shared across parallel evaluator workers.
//!
//! One [`SharedHeapArena`](super::SharedHeapArena) owns the typed scalar
//! stores in the same reservation as every shard's flat objects. This module
//! keeps the public encode/decode seam out of the shared-arena ownership and
//! resolution implementation.

use crate::heap::flat::FlatObjectKind;
use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::HeapObject;
use crate::value::compressed::{CandidateCScalarError, CompressedValueWord};

use super::SharedHeapArena;

impl SharedHeapArena {
    /// Returns the shared hash-consed boxed integer cell for Candidate B.
    pub(in crate::eval::heap) fn candidate_b_box_int_pointer(
        &self,
        value: i64,
    ) -> Result<std::ptr::NonNull<HeapObject>, CandidateCScalarError> {
        self.compressed_scalars.box_int_pointer(value)
    }

    /// Returns the shared hash-consed boxed float cell for Candidate B.
    pub(in crate::eval::heap) fn candidate_b_box_float_pointer(
        &self,
        value: f64,
    ) -> Result<std::ptr::NonNull<HeapObject>, CandidateCScalarError> {
        self.compressed_scalars.box_float_pointer(value)
    }

    /// Decodes a Candidate-B boxed integer pointer owned by this arena.
    pub(in crate::eval::heap) fn candidate_b_decode_int_pointer(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Result<i64, CandidateCScalarError> {
        self.compressed_scalars.decode_int_pointer(ptr)
    }

    /// Decodes a Candidate-B boxed float pointer owned by this arena.
    pub(in crate::eval::heap) fn candidate_b_decode_float_pointer(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Result<f64, CandidateCScalarError> {
        self.compressed_scalars.decode_float_pointer(ptr)
    }

    /// Returns the boxed scalar kind published at `ptr`, if any.
    pub(in crate::eval::heap) fn candidate_b_scalar_kind(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Option<FlatObjectKind> {
        self.compressed_scalars.kind_of_pointer(ptr)
    }

    /// Returns the reservation identity used by Candidate-C indexed words.
    pub(in crate::eval::heap) fn candidate_c_domain_id(&self) -> Option<ArenaDomainId> {
        self.flat_reservation
            .as_ref()
            .map(|arena| arena.domain_id())
    }

    /// Returns the compressed offset for a live address in the reservation.
    pub(in crate::eval::heap) fn candidate_c_index_for_pointer(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Option<ArenaIndex> {
        self.flat_reservation.as_ref()?.index_for_pointer(ptr).ok()
    }

    /// Returns the native address represented by a live compressed offset.
    pub(in crate::eval::heap) fn candidate_c_pointer_for_index(
        &self,
        index: ArenaIndex,
    ) -> Option<std::ptr::NonNull<HeapObject>> {
        self.flat_reservation
            .as_ref()?
            .pointer_for_index(index)
            .ok()
    }

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
        self.compressed_scalars.encode_int(value)
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
        self.compressed_scalars.encode_float(value)
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
        self.compressed_scalars.decode_int(word)
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
        self.compressed_scalars.decode_float(word)
    }
}
