//! Literal source-owned native retirement readback before local publication.
//!
//! This pointer-bearing GPL-local ABI never crosses a public process boundary.
//! A callback argument or a balanced local ring token cannot construct this
//! proof. The source getter verifies its actual RETIRED slot and stopped cut in
//! the literal publication window before returning immutable original bodies.

use std::ffi::{c_int, c_void};

use crucible_qemu_protocol::whole_control::{WHOLE_BODY_MAX_BYTES, body::WholeResult};

use super::whole_journals::OriginalComputeJournal;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NativeRetirementTuple {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) allocation: *mut c_void,
    pub(crate) source_cut: u64,
    pub(crate) stopped_ps: u64,
    pub(crate) stopped_raw: u64,
    pub(crate) request: *const u8,
    pub(crate) request_extent: usize,
    pub(crate) result: *const u8,
    pub(crate) result_extent: usize,
    pub(crate) consumed_ack: *const u8,
    pub(crate) ack_extent: usize,
}

impl Default for NativeRetirementTuple {
    fn default() -> Self {
        Self {
            version: 1,
            size: std::mem::size_of::<Self>() as u32,
            epoch: 0,
            sequence: 0,
            allocation: std::ptr::null_mut(),
            source_cut: 0,
            stopped_ps: 0,
            stopped_raw: 0,
            request: std::ptr::null(),
            request_extent: 0,
            result: std::ptr::null(),
            result_extent: 0,
            consumed_ack: std::ptr::null(),
            ack_extent: 0,
        }
    }
}

type ReadNativeRetirement = extern "C" fn(*mut NativeRetirementTuple) -> c_int;

/// Resolves the exact native getter without exposing a replaceable function field.
pub(crate) struct NativeRetirementApi {
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    getter: ReadNativeRetirement,
}

impl NativeRetirementApi {
    pub(crate) fn resolve() -> Option<Self> {
        // SAFETY: The exact source SDK names this literal retirement getter.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_retirement_v1".as_ptr(),
            )
        };
        if symbol.is_null() {
            return None;
        }
        Some(Self {
            // SAFETY: The matching GPL-local SDK declares this104-byte ABI.
            getter: unsafe { std::mem::transmute::<*mut c_void, ReadNativeRetirement>(symbol) },
        })
    }

    #[cfg(test)]
    pub(super) fn unavailable_for_test() -> Self {
        extern "C" fn unavailable(_destination: *mut NativeRetirementTuple) -> c_int {
            -libc::ENOTSUP
        }
        Self {
            getter: unavailable,
        }
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn read_proof(&self) -> Result<NativeRetirementProof, c_int> {
        NativeRetirementProof::read(self.getter)
    }
}

/// Retains one getter-authenticated native publication tuple without cloning it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(crate) struct NativeRetirementProof {
    original: NativeRetirementTuple,
    process: u32,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
impl NativeRetirementProof {
    /// Reads only the literal source-owned post-retirement publication context.
    ///
    /// This occurs before any mapping or device guard. The native source checks
    /// original PID/thread/BQL, the current RETIRED slot, stopped CPUs, empty work
    /// and the full postcallback cut. No provider-supplied tuple is accepted.
    fn read(getter: ReadNativeRetirement) -> Result<Self, c_int> {
        let mut original = NativeRetirementTuple::default();
        let status = getter(&mut original);
        if status != 0 {
            return Err(if status < 0 { status } else { -libc::EPROTO });
        }
        if original.version != 1
            || original.size as usize != std::mem::size_of::<NativeRetirementTuple>()
            || original.epoch == 0
            || original.sequence == 0
            || original.allocation.is_null()
            || original.source_cut == 0
            || original.request.is_null()
            || original.result.is_null()
            || original.consumed_ack.is_null()
            || !(264..=WHOLE_BODY_MAX_BYTES as usize).contains(&original.request_extent)
            || !(344..=WHOLE_BODY_MAX_BYTES as usize).contains(&original.result_extent)
            || original.ack_extent != 128
        {
            return Err(-libc::EPROTO);
        }
        Ok(Self {
            original,
            process: std::process::id(),
        })
    }

    /// Compares every actual source tuple field with the literal callback claim.
    ///
    /// Pointer comparison occurs before dereferencing any callback body. The
    /// callback tuple alone supplies no permission; only this getter-created
    /// proof can bind it to the same retained native journal and source cut.
    pub(crate) fn validate_callback(&self, callback: &NativeRetirementTuple) -> Result<(), c_int> {
        if self.process != std::process::id() {
            return Err(-libc::ESTALE);
        }
        let original = &self.original;
        if callback.version != original.version
            || callback.size != original.size
            || callback.epoch != original.epoch
            || callback.sequence != original.sequence
            || callback.allocation != original.allocation
            || callback.source_cut != original.source_cut
            || callback.stopped_ps != original.stopped_ps
            || callback.stopped_raw != original.stopped_raw
            || callback.request != original.request
            || callback.request_extent != original.request_extent
            || callback.result != original.result
            || callback.result_extent != original.result_extent
            || callback.consumed_ack != original.consumed_ack
            || callback.ack_extent != original.ack_extent
        {
            return Err(-libc::EPROTO);
        }
        Ok(())
    }

    /// Matches the complete authentic native bodies to the original Rust journal.
    ///
    /// The caller first obtains this journal through the current-process
    /// sequence/index lookup and exact original allocation-pointer comparison.
    /// Only after this check may it consume its retained local ring completion
    /// for cell retirement and publish the exact consumed ACK on its actor.
    pub(crate) fn validate_journal(&self, journal: &OriginalComputeJournal) -> Result<(), c_int> {
        if self.process != std::process::id()
            || std::ptr::from_ref(journal).cast_mut().cast::<c_void>() != self.original.allocation
        {
            return Err(-libc::ESTALE);
        }
        let original = &self.original;
        let request = unsafe {
            // SAFETY: the genuine SDK getter alone supplies this original,
            // initialized immutable request in never-recycled native backing.
            // The current-process check and bounded nonnull extent precede this
            // byte slice; no callback-supplied pointer is dereferenced.
            std::slice::from_raw_parts(original.request, original.request_extent)
        };
        // SAFETY: The same source-owned immutable lifetime and bounds apply.
        let result = unsafe { std::slice::from_raw_parts(original.result, original.result_extent) };
        let consumed = unsafe {
            // SAFETY: the genuine getter supplies the initialized immutable ACK
            // in the same never-recycled native slot. The current-process check,
            // nonnull pointer and exact 128-byte extent precede this byte slice.
            std::slice::from_raw_parts(original.consumed_ack, original.ack_extent)
        };
        journal
            .validate_native_retirement(request, result, consumed)
            .map_err(|_| -libc::EPROTO)?;
        let result = WholeResult::decode(result).map_err(|_| -libc::EPROTO)?;
        if result.epoch != original.epoch
            || result.sequence != original.sequence
            || result.stopped_ps != original.stopped_ps
            || result.raw_after != original.stopped_raw
            || result.cut != original.source_cut
        {
            return Err(-libc::EPROTO);
        }
        Ok(())
    }

    pub(crate) fn source_cut(&self) -> u64 {
        self.original.source_cut
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeRetirementTuple>() == 104);
    assert!(std::mem::offset_of!(NativeRetirementTuple, allocation) == 24);
    assert!(std::mem::offset_of!(NativeRetirementTuple, request) == 56);
    assert!(std::mem::offset_of!(NativeRetirementTuple, consumed_ack) == 88);
};

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Modeled getter controls assert exact retained native bytes.
    #![allow(clippy::unwrap_used)]

    use super::super::whole_journals::WholeJournals;
    use super::*;
    use crucible_qemu_protocol::whole_control::{
        WholeControlProfile, staged::StagedControlProfile,
    };
    use std::cell::Cell;

    const REQUEST: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crucible-qemu-protocol/src/whole_control/testdata/native-zero-request.bin"
    ));
    const RESULT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crucible-qemu-protocol/src/whole_control/testdata/native-zero-result.bin"
    ));
    const ACK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crucible-qemu-protocol/src/whole_control/testdata/native-zero-ack.bin"
    ));

    thread_local! {
        // This models only the private getter response. No native callback,
        // stopped-cut predicate or real source-retirement permission executes.
        static MODEL: Cell<(c_int, NativeRetirementTuple)> = Cell::new((0, NativeRetirementTuple::default()));
    }

    extern "C" fn modeled_getter(destination: *mut NativeRetirementTuple) -> c_int {
        MODEL.with(|model| {
            let (status, body) = model.get();
            if status == 0 {
                // SAFETY: The private read helper supplied its live local104-byte destination.
                unsafe { destination.write(body) };
            }
            status
        })
    }

    fn journals() -> WholeJournals {
        WholeJournals::new(
            &StagedControlProfile {
                compute: WholeControlProfile {
                    scope: [9; 32],
                    operation_capacity: 2,
                    body_byte_limit: 1024,
                    native_history_byte_limit: 1_000_000,
                    provider_history_byte_limit: 1_000_000,
                    administrative_read_attempt_limit: 100,
                    administrative_read_byte_limit: 100_000,
                    administrative_write_attempt_limit: 100,
                    administrative_write_byte_limit: 100_000,
                    deadline_monotonic_ns: 1000,
                    cpu_retirement_limit: 100,
                    event_step_limit: 100,
                    input_byte_limit: 100,
                    input_record_limit: 10,
                    output_byte_limit: 100,
                    output_record_limit: 10,
                },
                input_stage_limit: 3,
                stage_body_byte_limit: 1024,
            },
            0,
        )
        .unwrap()
    }

    fn native_tuple(journal: &OriginalComputeJournal) -> NativeRetirementTuple {
        let result = WholeResult::decode(RESULT).unwrap();
        NativeRetirementTuple {
            epoch: result.epoch,
            sequence: result.sequence,
            allocation: std::ptr::from_ref(journal).cast_mut().cast(),
            source_cut: result.cut,
            stopped_ps: result.stopped_ps,
            stopped_raw: result.raw_after,
            request: REQUEST.as_ptr(),
            request_extent: REQUEST.len(),
            result: RESULT.as_ptr(),
            result_extent: RESULT.len(),
            consumed_ack: ACK.as_ptr(),
            ack_extent: ACK.len(),
            ..NativeRetirementTuple::default()
        }
    }

    fn retain(journal: &OriginalComputeJournal) {
        journal.retain_request(REQUEST).unwrap();
        journal.retain_result(RESULT).unwrap();
        journal.retain_acknowledgement(ACK).unwrap();
        journal.retain_consumed_acknowledgement(ACK).unwrap();
    }

    #[test]
    fn modeled_retirement_getter_refuses_error_and_malformed_shape_before_body_reads() {
        MODEL.set((-libc::ESTALE, NativeRetirementTuple::default()));
        assert!(
            matches!(NativeRetirementProof::read(modeled_getter),Err(error) if error == -libc::ESTALE)
        );
        MODEL.set((1, NativeRetirementTuple::default()));
        assert!(
            matches!(NativeRetirementProof::read(modeled_getter),Err(error) if error == -libc::EPROTO)
        );
        MODEL.set((0, NativeRetirementTuple::default()));
        assert!(NativeRetirementProof::read(modeled_getter).is_err());
    }

    #[test]
    fn modeled_native_tuple_compares_every_callback_field_before_original_body_validation() {
        let journals = journals();
        let journal = journals.compute(1).unwrap();
        retain(journal);
        let original = native_tuple(journal);
        MODEL.set((0, original));
        let proof = NativeRetirementProof::read(modeled_getter).unwrap();

        proof.validate_callback(&original).unwrap();
        let same = journals
            .compute_allocation(original.sequence, original.allocation)
            .unwrap();
        proof.validate_journal(same).unwrap();
        assert_eq!(proof.source_cut(), 1);
        assert!(!journal.is_uncertain());

        for index in 0..14 {
            let mut changed = original;
            match index {
                0 => changed.version += 1,
                1 => changed.size += 1,
                2 => changed.epoch += 1,
                3 => changed.sequence += 1,
                4 => changed.allocation = std::ptr::null_mut(),
                5 => changed.source_cut += 1,
                6 => changed.stopped_ps += 1,
                7 => changed.stopped_raw += 1,
                8 => changed.request = changed.request.wrapping_add(1),
                9 => changed.request_extent -= 1,
                10 => changed.result = changed.result.wrapping_add(1),
                11 => changed.result_extent -= 1,
                12 => changed.consumed_ack = changed.consumed_ack.wrapping_add(1),
                _ => changed.ack_extent -= 1,
            }
            assert!(proof.validate_callback(&changed).is_err());
        }
        assert_eq!(journal.request_body().unwrap(), REQUEST);
        assert_eq!(journal.result_body().unwrap(), RESULT);
    }

    #[test]
    fn modeled_readback_cannot_retire_changed_or_uncertain_original_journal() {
        let journals = journals();
        let journal = journals.compute(1).unwrap();
        retain(journal);
        let mut changed = RESULT.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let mut original = native_tuple(journal);
        original.result = changed.as_ptr();
        MODEL.set((0, original));
        let proof = NativeRetirementProof::read(modeled_getter).unwrap();
        assert!(proof.validate_journal(journal).is_err());
        assert!(!journal.is_uncertain());
        assert_eq!(journal.result_body().unwrap(), RESULT);

        MODEL.set((0, native_tuple(journal)));
        let proof = NativeRetirementProof::read(modeled_getter).unwrap();
        journal.refuse();
        assert!(proof.validate_journal(journal).is_err());
        assert_eq!(journal.acknowledgement_body().unwrap(), ACK);
    }
}
