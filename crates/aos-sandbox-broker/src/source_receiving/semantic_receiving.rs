//! Lends only the same fixed Source original's monotone representation debit.
//!
//! The actual opening/role owner selects the native work. This private-field
//! loan returns neither capacity, a native handle nor semantic readiness.
//! Its resident result and high-water remain in that same opening after the
//! canonical cursor and borrowed loan end.

use aos_sandbox_core::{ResourceDimension, ResourceVector};
use crate::controller_receiving::ControllerSourceOriginalRefV1;
use super::SourceNativeErrorV1;

/// Restricts actual semantic representation on the same C-funded Source owner.
///
/// Its constructor is private to the actual fixed opening. A numeric shape
/// provides no work selection, authority, parser completion or native custody.
pub struct SourceSemanticReceivingLoanV1<'owner> {
    pub(super) original: &'owner ControllerSourceOriginalRefV1,
    pub(super) base: ResourceVector,
    pub(super) peak: &'owner mut ResourceVector,
    pub(super) result: &'owner mut Option<Result<ResourceVector, SourceNativeErrorV1>>,
}

impl SourceSemanticReceivingLoanV1<'_> {
    /// Admits the complete actual reached-model bound before semantic growth.
    ///
    /// # Errors
    /// Retains the actual first arithmetic or original-ledger refusal and
    /// refuses later use after that failure without retrying the debit.
    pub fn require_dynamic_complete_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), SourceNativeErrorV1> {
        if matches!(self.result, Some(Err(_))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        let mut peak = ResourceVector::ZERO;
        for dimension in ResourceDimension::ALL {
            peak = peak.with(dimension, self.peak.get(dimension).max(demand.get(dimension)));
        }
        *self.result = Some((|| {
            self.original.debit_complete_representation_v1(self.base.checked_add(peak)?)?;
            Ok(peak)
        })());
        if matches!(self.result, Some(Ok(_))) {
            *self.peak = peak;
            Ok(())
        } else {
            Err(SourceNativeErrorV1::Closed)
        }
    }
}
