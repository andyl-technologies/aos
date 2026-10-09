//! Bounded storage framing for an original accounted UART stop.
//!
//! Publication occurs inside the genuine node writer. Readers must separately
//! join its exact closed generation, original advance/ACK and retained emitting
//! AUTH. Neither this table nor a UART seal permits byte consumption.

use super::*;
use crucible_protocol::native_console::NativeConsoleOperationStop;

/// Single-native-writer accounted stop table with fixed scalar atomic words.
#[repr(C, align(128))]
pub struct NativeConsoleOperationStopTable {
    publication: AtomicU64,
    words: [AtomicU64; 15],
}

impl Default for NativeConsoleOperationStopTable {
    fn default() -> Self {
        Self {
            publication: AtomicU64::new(0),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleOperationStopTable {
    /// Stores exact shape after all fallible checks, inside the node writer.
    ///
    /// The caller retains the genuine stopped native occurrence. Its closed
    /// generation belongs to that same writer, not an independently predicted
    /// publication. No accepted-prefix or retired-AUTH state changes here.
    ///
    /// # Errors
    ///
    /// Refuses malformed shape, stale publication or a conflicting writer
    /// before changing any table body. After the claim, the suffix only stores
    /// complete words and the final even publication.
    pub fn store(&self, stop: NativeConsoleOperationStop) -> Result<(), NativeConsoleError> {
        let bytes = stop.encode()?;
        let previous = self.publication.load(Ordering::Acquire);
        if previous & 1 != 0 || stop.publication <= previous {
            return Err(NativeConsoleError::Sequence);
        }
        self.publication
            .compare_exchange(
                previous,
                stop.publication - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| NativeConsoleError::Sequence)?;

        for (word, chunk) in self.words.iter().zip(bytes[8..].as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
        self.publication.store(stop.publication, Ordering::Release);
        Ok(())
    }

    /// Copies one coherent table without spinning or authorizing completion.
    ///
    /// # Errors
    ///
    /// Refuses absent, in-progress, changing or malformed table publications.
    /// The host must also join exact live node framing and launch custody.
    pub fn snapshot(&self) -> Result<NativeConsoleOperationStop, NativeConsoleError> {
        self.try_snapshot()?.ok_or(NativeConsoleError::Sequence)
    }

    /// Copies a published table, distinguishing the original empty installation.
    ///
    /// # Errors
    ///
    /// Refuses in-progress, changing or malformed framing without spinning.
    /// An absent table supplies no stopped-operation evidence.
    pub fn try_snapshot(&self) -> Result<Option<NativeConsoleOperationStop>, NativeConsoleError> {
        let before = self.publication.load(Ordering::Acquire);
        if before == 0 {
            return Ok(None);
        }
        if before & 1 != 0 {
            return Err(NativeConsoleError::Sequence);
        }
        let mut bytes = [0; NATIVE_CONSOLE_OPERATION_STOP_BYTES];
        bytes[..8].copy_from_slice(&before.to_le_bytes());
        for (word, chunk) in self.words.iter().zip(bytes[8..].as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        std::sync::atomic::fence(Ordering::Acquire);
        if self.publication.load(Ordering::Acquire) != before {
            return Err(NativeConsoleError::Sequence);
        }
        NativeConsoleOperationStop::decode(&bytes).map(Some)
    }
}

const _: () = assert!(core::mem::size_of::<NativeConsoleOperationStopTable>() == 128);
const _: () = assert!(core::mem::align_of::<NativeConsoleOperationStopTable>() == 128);
