//! Atomic authorization publication and frontier fields, without phase authority.

use crucible_protocol::native_console::{
    NativeConsoleAuthorization, NativeConsoleCapability, NativeConsoleFrontier,
};

use super::*;

/// Native observed capability fields, published before original setup acknowledgement.
#[repr(C, align(128))]
pub struct NativeConsoleCapabilityTable {
    words: [AtomicU64; 16],
}

impl Default for NativeConsoleCapabilityTable {
    fn default() -> Self {
        Self {
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleCapabilityTable {
    /// Publishes the native-resolved shape before the original setup ACK release.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for invalid capability shape or a prior
    /// installation. Framing is released last; the table stays immutable for
    /// that installed lifetime. Native resolution and setup ownership must
    /// already be authenticated by the adapter.
    pub fn publish(&self, capability: NativeConsoleCapability) -> Result<(), NativeConsoleError> {
        let bytes = capability.encode()?;
        let framing = u64::from_le_bytes(bytes.as_chunks::<8>().0[0]);
        self.words[0]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NativeConsoleError::Sequence)?;
        for (word, chunk) in self.words[1..].iter().zip(bytes[8..].as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
        self.words[0].store(framing, Ordering::Release);
        Ok(())
    }

    /// Copies fields only after the original caller has acquired setup acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for absent or malformed capability fields.
    /// Successful decoding does not prove actual native device resolution.
    pub fn copy(&self) -> Result<NativeConsoleCapability, NativeConsoleError> {
        let mut bytes = [0; 128];
        bytes[..8].copy_from_slice(&self.words[0].load(Ordering::Acquire).to_le_bytes());
        for (word, chunk) in self.words[1..]
            .iter()
            .zip(bytes[8..].as_chunks_mut::<8>().0)
        {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        NativeConsoleCapability::decode(&bytes)
    }
}

/// Atomic authorization table with a single original host writer.
#[repr(C, align(128))]
pub struct NativeConsoleAuthorizationTable {
    publication: AtomicU64,
    words: [AtomicU64; 15],
}

impl Default for NativeConsoleAuthorizationTable {
    fn default() -> Self {
        Self {
            publication: AtomicU64::new(0),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleAuthorizationTable {
    /// Publishes a shape-valid table through its original single-writer seqlock.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for invalid shape, stale publication,
    /// exhausted generation or a conflicting writer. No phase authority is granted.
    pub fn publish(
        &self,
        authorization: NativeConsoleAuthorization,
    ) -> Result<(), NativeConsoleError> {
        let bytes = authorization.encode()?;
        let previous = self.publication.load(Ordering::Acquire);
        if previous & 1 != 0 || authorization.publication <= previous {
            return Err(NativeConsoleError::Sequence);
        }
        self.publication
            .compare_exchange(
                previous,
                authorization.publication - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| NativeConsoleError::Sequence)?;
        for (word, chunk) in self.words.iter().zip(bytes[8..].as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
        self.publication
            .store(authorization.publication, Ordering::Release);
        Ok(())
    }

    /// Reserves the original single writer for a prepared advance transaction.
    ///
    /// Shape and writer conflict checks occur before the caller changes an
    /// inbox. Dropping this reservation leaves the previous body untouched and
    /// restores its publication. Committing supplies the exact advance from the
    /// original scheduler writer; neither operation establishes phase authority.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for invalid shape, stale publication or a
    /// conflicting writer. The caller must separately reserve its owned ledger.
    pub fn prepare_for_advance(
        &self,
        authorization: NativeConsoleAuthorization,
    ) -> Result<PreparedNativeConsoleAuthorization<'_>, NativeConsoleError> {
        let bytes = authorization.encode()?;
        let previous = self.publication.load(Ordering::Acquire);
        if previous & 1 != 0 || authorization.publication <= previous {
            return Err(NativeConsoleError::Sequence);
        }
        self.publication
            .compare_exchange(
                previous,
                authorization.publication - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| NativeConsoleError::Sequence)?;
        Ok(PreparedNativeConsoleAuthorization {
            table: self,
            previous,
            authorization,
            bytes,
            committed: false,
        })
    }

    /// Reserves a full Restore body before the stopped request transaction.
    ///
    /// The original advance writer and physical request supply its transaction
    /// fields at commit. The native loaded-state owner remains independent.
    ///
    /// # Errors
    ///
    /// Refuses a non-Restore phase, an already assigned restore token, invalid
    /// shape, a stale publication, or a competing authorization writer.
    pub fn prepare_for_restore(
        &self,
        authorization: NativeConsoleAuthorization,
    ) -> Result<PreparedNativeConsoleRestoreAuthorization<'_>, NativeConsoleError> {
        if authorization.phase != crucible_protocol::native_console::NativeConsolePhase::Restore
            || authorization.phase_token != 0
        {
            return Err(NativeConsoleError::Field);
        }
        Ok(PreparedNativeConsoleRestoreAuthorization(
            self.prepare_for_advance(authorization)?,
        ))
    }

    /// Takes one bounded coherent snapshot; contention is unavailable, not a grant.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an unpublished, in-progress, changing
    /// or malformed snapshot. The adapter must separately authenticate its phase.
    pub fn snapshot(&self) -> Result<NativeConsoleAuthorization, NativeConsoleError> {
        let before = self.publication.load(Ordering::Acquire);
        if before == 0 || before & 1 != 0 {
            return Err(NativeConsoleError::Sequence);
        }
        let mut bytes = [0; 128];
        bytes[..8].copy_from_slice(&before.to_le_bytes());
        for (word, chunk) in self.words.iter().zip(bytes[8..].as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        std::sync::atomic::fence(Ordering::Acquire);
        if self.publication.load(Ordering::Acquire) != before {
            return Err(NativeConsoleError::Sequence);
        }
        NativeConsoleAuthorization::decode(&bytes)
    }
}

/// Local reserved table writer, never a shared-memory object or phase proof.
///
/// The original host publication owner holds this reservation before inbox
/// effects. A dropped reservation restores the unchanged old body; a committed
/// reservation retains the new body even if the later futex wake fails.
pub struct PreparedNativeConsoleAuthorization<'a> {
    table: &'a NativeConsoleAuthorizationTable,
    previous: u64,
    authorization: NativeConsoleAuthorization,
    bytes: [u8; 128],
    committed: bool,
}

impl PreparedNativeConsoleAuthorization<'_> {
    /// Commits the prepared body inside its original scheduler advance writer.
    ///
    /// All shape and ownership checks must precede this infallible operation.
    /// The supplied local sequence comes from that writer, not a predicted or
    /// subsequently sampled header. This method grants no execution authority.
    pub fn commit_for_advance(
        mut self,
        advance: crate::SchedulerAdvanceSequence,
    ) -> NativeConsoleAuthorization {
        self.authorization.advance = advance.get();
        self.bytes[48..56].copy_from_slice(&advance.get().to_le_bytes());
        self.commit_bytes()
    }

    /// Commits a Restore body in the stopped transaction's original writer.
    ///
    /// The physical restore generation names the request only; the native
    /// whole-loader and closed owner must still authenticate this body. The
    /// caller prevalidated the Restore phase and captured canonical prefix.
    fn commit_for_restore(
        mut self,
        advance: crate::SchedulerAdvanceSequence,
        generation: u32,
    ) -> NativeConsoleAuthorization {
        self.authorization.advance = advance.get();
        self.authorization.phase_token = u64::from(generation);
        self.bytes[48..56].copy_from_slice(&advance.get().to_le_bytes());
        self.bytes[80..88].copy_from_slice(&u64::from(generation).to_le_bytes());
        self.commit_bytes()
    }

    fn commit_bytes(mut self) -> NativeConsoleAuthorization {
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
            .store(self.authorization.publication, Ordering::Release);
        self.committed = true;
        self.authorization
    }
}

/// Local Restore reservation, containing no loaded-state execution permission.
pub struct PreparedNativeConsoleRestoreAuthorization<'a>(PreparedNativeConsoleAuthorization<'a>);

impl PreparedNativeConsoleRestoreAuthorization<'_> {
    /// Commits exact fields from the stopped transaction's original writer.
    ///
    /// These local identifiers name its physical requests. Actual whole-load,
    /// installed-resource and closed native phase checks are still required.
    pub fn commit(
        self,
        advance: crate::SchedulerAdvanceSequence,
        generation: u32,
    ) -> NativeConsoleAuthorization {
        self.0.commit_for_restore(advance, generation)
    }
}

impl Drop for PreparedNativeConsoleAuthorization<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.table
                .publication
                .store(self.previous, Ordering::Release);
        }
    }
}

/// Atomic frontier fields stored only inside the original NodeSlot writer interval.
///
/// The original publication generation and odd ACK are external to this
/// table. Neither `store` nor `copy` supplies a completed-boundary proof.
#[repr(C, align(128))]
pub struct NativeConsoleFrontierTable {
    words: [AtomicU64; 16],
}

impl Default for NativeConsoleFrontierTable {
    fn default() -> Self {
        Self {
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NativeConsoleFrontierTable {
    /// Stores fields within an externally owned original publication interval.
    ///
    /// The native adapter must already hold its original single-writer authority,
    /// finish operation/control settlement, publish these fields before releasing
    /// the generation, and release the original odd ACK last. This primitive does
    /// not implement or waive those obligations.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an invalid frontier shape.
    pub fn store(&self, frontier: NativeConsoleFrontier) -> Result<(), NativeConsoleError> {
        self.prepare_store(frontier)?.commit();
        Ok(())
    }

    /// Prepares all shape checks before opening the original publication writer.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an invalid frontier shape. Preparation
    /// does not mutate the table or authenticate native permission.
    pub fn prepare_store(
        &self,
        frontier: NativeConsoleFrontier,
    ) -> Result<PreparedNativeConsoleFrontier<'_>, NativeConsoleError> {
        Ok(PreparedNativeConsoleFrontier {
            table: self,
            bytes: frontier.encode()?,
        })
    }

    /// Copies fields between the original caller's acquire/generation checks.
    ///
    /// The caller must acquire the exact odd ACK before copying and reject a
    /// changed publication generation afterward. A successful decode alone is
    /// shape validation and must never authorize consumption.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an unsealed or malformed copied value.
    pub fn copy(&self) -> Result<NativeConsoleFrontier, NativeConsoleError> {
        let mut bytes = [0; 128];
        for (word, chunk) in self.words.iter().zip(bytes.as_chunks_mut::<8>().0) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        std::sync::atomic::fence(Ordering::Acquire);
        NativeConsoleFrontier::decode(&bytes)
    }
}

/// Prepared words committed only within the original externally owned interval.
///
/// This process-local value is not stored in shared memory and provides no
/// native owner proof. The caller must finish every authority check before commit.
pub struct PreparedNativeConsoleFrontier<'a> {
    table: &'a NativeConsoleFrontierTable,
    bytes: [u8; 128],
}

impl PreparedNativeConsoleFrontier<'_> {
    /// Stores the complete already-validated frontier without fallible work.
    pub fn commit(self) {
        for (word, chunk) in self.table.words.iter().zip(self.bytes.as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
    }
}

const _: () = assert!(core::mem::size_of::<NativeConsoleAuthorizationTable>() == 128);
const _: () = assert!(core::mem::size_of::<NativeConsoleCapabilityTable>() == 128);
const _: () = assert!(core::mem::align_of::<NativeConsoleAuthorizationTable>() == 128);
const _: () = assert!(core::mem::size_of::<NativeConsoleFrontierTable>() == 128);
const _: () = assert!(core::mem::align_of::<NativeConsoleFrontierTable>() == 128);

#[cfg(test)]
mod capability_tests {
    use super::*;

    fn capability() -> NativeConsoleCapability {
        NativeConsoleCapability {
            slot: 0,
            region: [4; 16],
            process: 8,
            plan_hash: [1; 32],
            resolved_streams: [2; 32],
        }
    }

    #[test]
    fn capability_release_is_one_time_and_refuses_unpublished_partial_rows()
    -> Result<(), NativeConsoleError> {
        let table = NativeConsoleCapabilityTable::default();
        assert!(table.copy().is_err());
        let mut invalid = capability();
        invalid.process = 0;
        assert!(table.publish(invalid).is_err());
        assert_eq!(table.words[0].load(Ordering::Acquire), 0);

        // A modeled pre-release writer has not made installed framing visible.
        let partial = NativeConsoleCapabilityTable::default();
        partial.words[0].store(1, Ordering::Release);
        partial.words[3].store(8, Ordering::Relaxed);
        assert!(partial.copy().is_err());
        assert_eq!(
            partial.publish(capability()),
            Err(NativeConsoleError::Sequence)
        );

        table.publish(capability())?;
        assert_eq!(table.copy()?, capability());
        let mut replacement = capability();
        replacement.process += 1;
        assert_eq!(
            table.publish(replacement),
            Err(NativeConsoleError::Sequence)
        );
        assert_eq!(table.copy()?, capability());
        Ok(())
    }
}
