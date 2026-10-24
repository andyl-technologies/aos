//! Lends the Source's retained native read without creating another read owner.
//!
//! The scoped loan preserves the actual association through its callback. It
//! performs no native currentness check and grants no permission; an armed read
//! may stay busy while the owning dispatcher performs its separately admitted
//! operation. The dispatcher independently compares this read with its actual
//! native custody before splitting mutable Controller and runtime loans.

use crate::{
    node_adapters::cnp::{
        CnpSemanticSourceRead, PacketCompleteSemanticSource,
        semantic::packet_complete_source::ack_peer::association::OriginalAckPeerAssociation,
    },
    node_contract::RuntimeError,
};
use std::{cell::Ref, mem::size_of};

impl PacketCompleteSemanticSource {
    /// Lends only the native read already retained by this exact Source.
    ///
    /// The original association borrow survives callback refusal and the late
    /// owner check. This method never creates a source read, checks idle currency
    /// or acquires another native call; live validation remains caller-owned.
    ///
    /// # Errors
    /// Refuses a foreign Source origin, busy or absent association, absent native
    /// read, a changed retained owner, or a callback failure. The late origin and
    /// owner checks run even when the callback returns an error.
    pub(in crate::node_adapters::cnp::semantic) fn with_original_retained_capture17_read_data<R>(
        &self,
        inspect: impl FnOnce(&CnpSemanticSourceRead) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let original_identity = std::ptr::from_ref(original);
        let native_identity = std::ptr::from_ref(native);

        let result = inspect(native);

        self.storage_origin_with_error::<RuntimeError>()?;
        let retained = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let retained_native = retained
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(original_identity, retained)
            || !std::ptr::eq(native_identity, retained_native)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        result
    }

    /// Prices the exact retained read's eventual fresh-current link bank.
    ///
    /// This pre-effect getter uses actual executable custody without allocation,
    /// hashing, syscalls or registrar callbacks. Its returned bytes are separate
    /// from the fixed FreshCurrentScratch/stream views and create no credit.
    ///
    /// # Errors
    /// Refuses a foreign or absent retained read, busy/revoked read custody,
    /// unsupported executable lease state, or checked executable-link overflow.
    pub(crate) fn original_retained_capture17_fresh_link_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.with_original_retained_capture17_read_data(|read| {
            read.original_fresh_current_storage_data()
        })
    }

    /// Counts the scoped borrower and an actual concrete callback-result header.
    ///
    /// The caller separately counts its closure's captures and implementation
    /// frames. No generic callback heap or return backing is inferred here.
    pub(crate) fn original_retained_capture17_read_counter_scratch_data<R>() -> usize {
        size_of::<&Self>()
            + size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<
                Result<Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>,
            >()
            + 2 * size_of::<&OriginalAckPeerAssociation>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Result<&OriginalAckPeerAssociation, RuntimeError>>()
            + 2 * size_of::<&CnpSemanticSourceRead>()
            + size_of::<Option<&CnpSemanticSourceRead>>()
            + size_of::<Result<&CnpSemanticSourceRead, RuntimeError>>()
            + size_of::<*const OriginalAckPeerAssociation>()
            + size_of::<*const CnpSemanticSourceRead>()
            + size_of::<Result<R, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
