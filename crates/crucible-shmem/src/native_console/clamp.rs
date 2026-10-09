//! Bounded coherent custody published before its original control request.

use crucible_protocol::native_console::{
    NATIVE_CONSOLE_CLAMP_BYTES, NativeConsoleClamp, NativeConsoleError,
};

use super::*;

/// Single-host-writer paired-clamp fields; no native phase proof is encoded.
#[repr(C, align(128))]
pub struct NativeConsoleClampTable {
    publication: AtomicU64,
    words: [AtomicU64; 31],
}

impl Default for NativeConsoleClampTable {
    fn default() -> Self {
        Self {
            publication: AtomicU64::new(0),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleClampTable {
    /// Reserves all fallible shape and writer checks before request effects.
    ///
    /// # Errors
    ///
    /// Refuses invalid shape, an in-progress writer, or a stale publication.
    /// The caller must separately hold the original host request owner.
    pub fn prepare(
        &self,
        clamp: NativeConsoleClamp,
    ) -> Result<PreparedNativeConsoleClamp<'_>, NativeConsoleError> {
        let bytes = clamp.encode()?;
        let previous = self.publication.load(Ordering::Acquire);
        if previous & 1 != 0 || clamp.publication <= previous {
            return Err(NativeConsoleError::Sequence);
        }
        self.publication
            .compare_exchange(
                previous,
                clamp.publication - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| NativeConsoleError::Sequence)?;
        Ok(PreparedNativeConsoleClamp {
            table: self,
            previous,
            publication: clamp.publication,
            bytes,
            committed: false,
        })
    }

    /// Copies one coherent table, without spinning or authorizing acceptance.
    ///
    /// # Errors
    ///
    /// Refuses absent, in-progress, changing, or malformed custody. The native
    /// reader must also join the exact subsequently observed request/advance.
    pub fn snapshot(&self) -> Result<NativeConsoleClamp, NativeConsoleError> {
        let before = self.publication.load(Ordering::Acquire);
        if before == 0 || before & 1 != 0 {
            return Err(NativeConsoleError::Sequence);
        }
        let mut bytes = [0; NATIVE_CONSOLE_CLAMP_BYTES];
        bytes[..8].copy_from_slice(&before.to_le_bytes());
        for (word, chunk) in self.words.iter().zip(bytes[8..].as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        std::sync::atomic::fence(Ordering::Acquire);
        if self.publication.load(Ordering::Acquire) != before {
            return Err(NativeConsoleError::Sequence);
        }
        NativeConsoleClamp::decode(&bytes)
    }
}

/// Process-local prepared storage, never placed in the shared region.
pub struct PreparedNativeConsoleClamp<'a> {
    table: &'a NativeConsoleClampTable,
    previous: u64,
    publication: u64,
    bytes: [u8; NATIVE_CONSOLE_CLAMP_BYTES],
    committed: bool,
}

impl PreparedNativeConsoleClamp<'_> {
    /// Commits the complete prepared body before the original request Release.
    ///
    /// The original request owner supplies its proposed even successor. The
    /// native reader must refuse until that same request is actually visible;
    /// this table's publication alone cannot authorize a control invocation.
    pub fn commit_before_request(mut self, request: crate::PreparedControlBoundaryRequest) {
        self.bytes[24..28].copy_from_slice(&request.get().to_le_bytes());
        self.commit_bytes();
    }

    /// Pairs the prepared Restore body with its same original advance writer.
    ///
    /// The caller reserved a full Restore body before entering the stopped
    /// transaction. These supplied local receipts patch only its physical
    /// transaction identifiers; they confer no loaded-state permission.
    pub fn commit_restore_before_request(
        mut self,
        request: crate::PreparedControlBoundaryRequest,
        advance: crate::SchedulerAdvanceSequence,
        generation: u32,
    ) {
        self.bytes[16..24].copy_from_slice(&advance.get().to_le_bytes());
        self.bytes[24..28].copy_from_slice(&request.get().to_le_bytes());
        self.bytes[112..120].copy_from_slice(&advance.get().to_le_bytes());
        self.bytes[144..152].copy_from_slice(&u64::from(generation).to_le_bytes());
        self.commit_bytes();
    }

    fn commit_bytes(mut self) {
        for (word, chunk) in self
            .table
            .words
            .iter()
            .zip(self.bytes[8..].as_chunks::<8>().0)
        {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
        self.table
            .publication
            .store(self.publication, Ordering::Release);
        self.committed = true;
    }
}

impl Drop for PreparedNativeConsoleClamp<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.table
                .publication
                .store(self.previous, Ordering::Release);
        }
    }
}

const _: () =
    assert!(core::mem::size_of::<NativeConsoleClampTable>() == NATIVE_CONSOLE_CLAMP_BYTES);
