//! Candidate-C boxed scalar storage in the evaluator's serial reservation.
//!
//! The active 16-byte [`Value`] keeps full-width integers and floats inline.
//! Candidate C instead inlines only `i32` and places every wider integer and
//! float in hash-consed cells addressed by the same reservation-relative
//! indices as the permanent flat-object stores. This module owns the evaluator
//! seam for exercising that storage before the value/FFI/JIT ABI switches.

use crate::value::compressed::{
    CandidateCScalarError, CandidateCScalarRetirementReport, CompressedValueWord,
};

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
        if let Some(shared) = &self.shared {
            return shared.arena().candidate_c_encode_int(value);
        }
        self.compressed_scalars.encode_int(value)
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
        if let Some(shared) = &self.shared {
            return shared.arena().candidate_c_encode_float(value);
        }
        self.compressed_scalars.encode_float(value)
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
        if let Some(shared) = &self.shared {
            return shared.arena().candidate_c_decode_int(word);
        }
        self.compressed_scalars.decode_int(word)
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
        if let Some(shared) = &self.shared {
            return shared.arena().candidate_c_decode_float(word);
        }
        self.compressed_scalars.decode_float(word)
    }

    /// Retires all boxed Candidate-C scalars owned by this serial heap.
    ///
    /// The replacement scalar stores retain the heap's existing flat arena and
    /// reservation domain. Shared worker heaps must coordinate retirement at
    /// their common arena owner and are therefore rejected here.
    ///
    /// # Errors
    ///
    /// Returns an error without mutation if the heap is shared or the scalar
    /// store's pre-retirement inventory is inconsistent.
    pub fn retire_candidate_c_scalar_store(
        &mut self,
    ) -> Result<CandidateCScalarRetirementReport, CandidateCScalarError> {
        if self.shared.is_some() {
            return Err(CandidateCScalarError::SerialRetirementRequiresExclusiveHeap);
        }
        self.compressed_scalars.retire_all_boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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

    #[test]
    fn evaluator_rejects_compressed_scalar_from_another_live_heap() {
        let mut source = EvalHeap::new();
        let receiver = EvalHeap::new();
        let word = source
            .candidate_c_encode_int(i64::MAX)
            .expect("source scalar encodes");

        assert!(matches!(
            receiver.candidate_c_decode_int(word),
            Err(CandidateCScalarError::ArenaDomainMismatch { .. })
        ));
    }

    #[test]
    fn evaluator_retires_and_reopens_its_serial_scalar_store() {
        let mut heap = EvalHeap::new();
        let wide = i64::MAX;
        let old = heap
            .candidate_c_encode_int(wide)
            .expect("wide integer boxes");
        let domain = old.arena_domain();

        let report = heap
            .retire_candidate_c_scalar_store()
            .expect("serial store retires");

        assert_eq!(report.retired_ints(), 1);
        assert_eq!(report.retired_floats(), 0);
        assert_eq!(report.arena_domain(), domain);
        assert!(heap.candidate_c_decode_int(old).is_err());

        let new = heap
            .candidate_c_encode_int(wide)
            .expect("wide integer boxes after reset");
        assert_ne!(new, old);
        assert_eq!(new.arena_domain(), domain);
        assert_eq!(
            heap.candidate_c_decode_int(new)
                .expect("replacement cell decodes"),
            wide
        );
    }

    #[test]
    fn parallel_workers_share_candidate_c_scalar_cells() {
        let arena = Arc::new(SharedHeapArena::new(2, 32));
        let mut first = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(0).expect("first shard exists")),
        );
        let mut second = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(1).expect("second shard exists")),
        );

        let first_int = first
            .candidate_c_encode_int(i64::MAX)
            .expect("first worker boxes integer");
        let second_int = second
            .candidate_c_encode_int(i64::MAX)
            .expect("second worker reuses integer");
        let float = first
            .candidate_c_encode_float(-0.0)
            .expect("first worker boxes float");

        assert_eq!(first_int, second_int);
        assert_eq!(
            second
                .candidate_c_decode_int(first_int)
                .expect("second worker decodes first worker integer"),
            i64::MAX
        );
        assert!(matches!(
            first.retire_candidate_c_scalar_store(),
            Err(CandidateCScalarError::SerialRetirementRequiresExclusiveHeap)
        ));
        assert_eq!(
            second
                .candidate_c_decode_int(first_int)
                .expect("refused retirement leaves shared cell live"),
            i64::MAX
        );
        assert_eq!(
            second
                .candidate_c_decode_float(float)
                .expect("second worker decodes first worker float")
                .to_bits(),
            (-0.0f64).to_bits()
        );
        assert_eq!(arena.published_len(), 2);
        assert_eq!(arena.published_payload_bytes(), 16);
    }

    #[test]
    fn parallel_heap_rejects_scalar_from_another_shared_arena() {
        let left_arena = Arc::new(SharedHeapArena::new(1, 16));
        let right_arena = Arc::new(SharedHeapArena::new(1, 16));
        let mut left = EvalHeap::with_shared_shard(
            Arc::clone(&left_arena),
            Arc::clone(left_arena.shard(0).expect("left shard exists")),
        );
        let right = EvalHeap::with_shared_shard(
            Arc::clone(&right_arena),
            Arc::clone(right_arena.shard(0).expect("right shard exists")),
        );
        let word = left
            .candidate_c_encode_float(1.5)
            .expect("left float boxes");

        assert!(matches!(
            right.candidate_c_decode_float(word),
            Err(CandidateCScalarError::ArenaDomainMismatch { .. })
        ));
    }
}
