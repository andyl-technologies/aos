//! Native-console storage primitives for the coordinated ABI-31 boundary.
//!
//! ABI-31 geometry reserves one disjoint bounded segment per VM. These
//! primitives stage immutable records and validate complete accepted prefixes;
//! they do not authenticate native phase authority or manufacture an odd ACK.
//! Frontier atomics must join the original NodeSlot publication interval.
//! Independent frontier reads are never completed-boundary acceptance.

mod c_header;
mod clamp;
#[cfg(test)]
mod clamp_tests;
mod operation_stop;
mod ring;
mod tables;
#[cfg(test)]
mod tests;

pub use c_header::generated_native_console_c_header;
pub use clamp::*;
pub use operation_stop::*;
pub use ring::*;
pub use tables::*;

use std::sync::atomic::{AtomicU64, Ordering};

use crucible_protocol::native_console::{
    NATIVE_CONSOLE_CAPACITY, NATIVE_CONSOLE_CLAMP_BYTES, NATIVE_CONSOLE_OPERATION_STOP_BYTES,
    NATIVE_CONSOLE_RECORD_BYTES, NativeConsoleError,
};

/// Fixed bytes in one ABI-31 per-VM console segment.
pub const NATIVE_CONSOLE_SEGMENT_BYTES: usize = 128
    + 128
    + crate::RING_HEADER_SIZE
    + NATIVE_CONSOLE_CAPACITY as usize * NATIVE_CONSOLE_RECORD_BYTES
    + 128
    + NATIVE_CONSOLE_CLAMP_BYTES
    + NATIVE_CONSOLE_OPERATION_STOP_BYTES;

/// Exact immutable native-console ring entry; scalar atomics prevent data races.
///
/// Each atomic word represents eight little-endian encoded bytes. The complete
/// entry becomes visible only through the ring's release/acquire publication,
/// then through an independently authenticated sealed frontier. A staging write
/// is not a canonical evidence commit.
#[repr(C, align(64))]
pub struct NativeConsoleEntry {
    words: [AtomicU64; 16],
}

impl Default for NativeConsoleEntry {
    fn default() -> Self {
        Self {
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleEntry {
    fn store(&self, bytes: &[u8; 128]) {
        for (word, chunk) in self.words.iter().zip(bytes.as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
    }

    fn load(&self) -> [u8; 128] {
        let mut bytes = [0; 128];
        for (word, chunk) in self.words.iter().zip(bytes.as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        bytes
    }
}

const _: () = assert!(core::mem::size_of::<NativeConsoleEntry>() == NATIVE_CONSOLE_RECORD_BYTES);
const _: () = assert!(core::mem::align_of::<NativeConsoleEntry>() == 64);

/// Checked offsets for one ABI-31 per-VM console segment.
///
/// RegionLayout derives each base from the validated ABI-31 region header.
/// An arbitrary local layout is not setup admission or native authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleSegmentLayout {
    /// Native observed capability table offset.
    pub capability: usize,
    /// Host authorization table offset.
    pub authorization: usize,
    /// Existing SPSC ring header offset.
    pub ring_header: usize,
    /// First immutable record offset.
    pub records: usize,
    /// Frontier offset; original node publication and odd ACK still govern it.
    pub frontier: usize,
    /// Host paired-clamp custody, published before the original even request.
    pub clamp: usize,
    /// Accounted operation-stop framing, before later control acceptance.
    pub operation_stop: usize,
    /// First byte after all allocated storage.
    pub end: usize,
}

impl NativeConsoleSegmentLayout {
    /// Computes checked, aligned console segment offsets within owned storage.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an unaligned base, overlap with the
    /// region header, arithmetic overflow or a short mapping.
    pub fn new(base: usize, mapping_len: usize) -> Result<Self, NativeConsoleError> {
        if base < crate::REGION_HEADER_SIZE || !base.is_multiple_of(128) {
            return Err(NativeConsoleError::Length);
        }
        let authorization = base.checked_add(128).ok_or(NativeConsoleError::Length)?;
        let ring_header = authorization
            .checked_add(128)
            .ok_or(NativeConsoleError::Length)?;
        let records = ring_header
            .checked_add(crate::RING_HEADER_SIZE)
            .ok_or(NativeConsoleError::Length)?;
        let frontier = records
            .checked_add(NATIVE_CONSOLE_CAPACITY as usize * NATIVE_CONSOLE_RECORD_BYTES)
            .ok_or(NativeConsoleError::Length)?;
        let clamp = frontier
            .checked_add(128)
            .ok_or(NativeConsoleError::Length)?;
        let operation_stop = clamp
            .checked_add(NATIVE_CONSOLE_CLAMP_BYTES)
            .ok_or(NativeConsoleError::Length)?;
        let end = operation_stop
            .checked_add(NATIVE_CONSOLE_OPERATION_STOP_BYTES)
            .ok_or(NativeConsoleError::Length)?;
        if end > mapping_len {
            return Err(NativeConsoleError::Length);
        }
        Ok(Self {
            capability: base,
            authorization,
            ring_header,
            records,
            frontier,
            clamp,
            operation_stop,
            end,
        })
    }
}

/// Borrowed console segment whose storage remains owned by one validated mapping.
pub struct MappedNativeConsoleSegment<'a> {
    /// Native capability fields; setup acknowledgement is external authority.
    pub capability: &'a NativeConsoleCapabilityTable,
    /// Original host authorization fields; no new phase owner is invented.
    pub authorization: &'a NativeConsoleAuthorizationTable,
    /// Original shared SPSC admission and cursor state.
    pub ring: &'a crate::RingHeader,
    /// Immutable staged records, published through the ring write index.
    pub records: &'a [NativeConsoleEntry],
    /// Frontier fields; original NodeSlot publication and ACK remain mandatory.
    pub frontier: &'a NativeConsoleFrontierTable,
    /// Paired full-body custody; it is never an accepted native frontier.
    pub clamp: &'a NativeConsoleClampTable,
    /// Accounted native stop; this table cannot authorize byte consumption.
    pub operation_stop: &'a NativeConsoleOperationStopTable,
}
