//! Keeps the actual returned receipt or validation error for its Source caller.
//!
//! Fixed Seed/PSC validation uses the bounded consuming protocol engines. Its
//! temporary models are byte-priced, rather than separate metadata reservoirs.

use super::*;

/// Retains the consuming receipt decoder's caller-projected returned cause.
///
/// The error parameter changes only the representation of the same returned
/// DATA refusal. It cannot authorize a read, writer, payment or publication.
#[doc(hidden)]
pub struct SourceGenesisReceiptDecodeOriginalsV1<E = SourceGenesisReceiptDataErrorV1> {
    receipt: Option<SourceTreeGenesisReceiptV1>,
    result: Option<Result<(), E>>,
    closed: Option<E>,
    entered: bool,
    taken: bool,
}

impl<E: From<SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceGenesisReceiptDecodeOriginalsV1<E> {
    /// Prearms an inert returned-receipt destination without decoding.
    pub const fn new() -> Self {
        Self { receipt: None, result: None, closed: None, entered: false, taken: false }
    }

    /// Runs the same bounded consuming receipt decoder exactly once.
    ///
    /// # Errors
    /// Rejects reentry or the original fixed receipt grammar/join failure.
    pub fn observe_once(&mut self, bytes: &[u8]) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(SourceGenesisErrorV1::NonCanonical));
            return Err(E::from(SourceGenesisErrorV1::NonCanonical));
        }
        self.entered = true;
        self.result = Some(match SourceTreeGenesisReceiptV1::decode(bytes) {
            Ok(receipt) => { self.receipt = Some(receipt); Ok(()) }
            Err(cause) => Err(E::from(cause)),
        });
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(E::from(SourceGenesisErrorV1::NonCanonical)) }
    }

    /// Moves only this destination's actual successfully decoded receipt.
    pub fn take_receipt_once(&mut self) -> Option<SourceTreeGenesisReceiptV1> {
        if self.taken || self.failure().is_some() || !matches!(self.result, Some(Ok(()))) {
            self.closed.get_or_insert(E::from(SourceGenesisErrorV1::NonCanonical));
            return None;
        }
        self.taken = true;
        self.receipt.take()
    }

    /// Borrows the first retained DATA error without replacing it.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Returns the existing conservative compiled byte permit and namespace count.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use std::mem::size_of;
        use aos_sandbox_protocol::controller_source_seed::{ControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1};
        use aos_sandbox_protocol::source_project_authorization::{UnverifiedProjectAuthorizationClaimsV2, ProjectAuthorizationSourceDataErrorV2};
        use aos_sandbox_core::source_tree_model::TreeLimitsV1;

        // The receipt has one of two exact widths. Four fixed model planes and
        // two byte copies dominate the consuming parser/constructor workspace;
        // actual Source row/index cardinality is paid by the enclosing supplier.
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<Result<(), E>>())?
            .checked_add(size_of::<E>())?
            .checked_add(SOURCE_TREE_GENESIS_RECEIPT_BYTES_V2.checked_mul(2)?)?
            .checked_add(size_of::<SourceTreeGenesisReceiptV1>().checked_mul(2)?)?
            .checked_add(size_of::<Result<SourceTreeGenesisReceiptV1, SourceGenesisErrorV1>>())?
            .checked_add(size_of::<ControllerSourceTreeSeedV1>().checked_mul(4)?)?
            .checked_add(size_of::<UnverifiedProjectAuthorizationClaimsV2>().checked_mul(4)?)?
            .checked_add(size_of::<Result<ControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1>>())?
            .checked_add(size_of::<Result<UnverifiedProjectAuthorizationClaimsV2, ProjectAuthorizationSourceDataErrorV2>>())?
            .checked_add(size_of::<TreeLimitsV1>().checked_mul(4)?)?
            .checked_add(size_of::<[u64; aos_sandbox_core::ResourceDimension::COUNT]>().checked_mul(2)?)?
            .checked_add(size_of::<[usize; 32]>())?
            .checked_add(size_of::<[&'static [u8]; 8]>())?;
        // No resident namespace entry is created by these fixed controls.
        Some((bytes, 0))
    }
}
