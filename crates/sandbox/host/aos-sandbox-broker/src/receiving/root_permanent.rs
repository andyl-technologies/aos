//! Shares the actual permanent Root originals after their one-way handoff.
//!
//! The enrollment, original policy/delivery files and invocation fence MOVE
//! into this private owner once. Native writers keep this SAME allocation;
//! no parsed table, vector, account, observer result or unit identity link can
//! reconstruct it. Upper semantic stages remain upper; the same original
//! cumulative representation liability moves here with the native originals.

use std::sync::{Arc, Mutex};

use super::{RootEnrollmentOriginalsV1, RootObservationErrorV1};
use super::root_invocation::{RootInvocationOriginalV1, RootNativeInvocationGuardV1};

pub(super) struct RootPermanentNativeOriginalV1 {
    // Refused original destruction aborts before physical enrollment release.
    invocation: RootInvocationOriginalV1,
    enrollment: RootEnrollmentOriginalsV1,
    initial_identity: Arc<()>,
    writer_claims: Mutex<[bool; 3]>,
    pub(in crate::receiving) financial: super::root_initial::financial::RootFinancialCustodyV1,
    pub(super) service: super::root_selected_currentness::RootSelectedServiceOriginalV1,
}

impl RootPermanentNativeOriginalV1 {
    pub(super) fn from_serving_originals(
        invocation: RootInvocationOriginalV1,
        enrollment: RootEnrollmentOriginalsV1,
        initial_identity: Arc<()>,
        financial: super::root_initial::financial::RootFinancialCustodyV1,
        kernel: super::RootKernelOriginalCaptureV1,
        sampler: super::RootServiceCurrentnessOriginalV1,
    ) -> Self {
        Self {
            invocation, enrollment, initial_identity, writer_claims: Mutex::new([false; 3]), financial,
            service: super::root_selected_currentness::RootSelectedServiceOriginalV1::from_settled_originals(kernel, sampler),
        }
    }

    pub(super) fn construction_bytes_v1() -> Option<usize> {
        // Actual new Arc allocation, possible construction move, allocator
        // alignment and its strong/weak header; no optimized placement assumed.
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<Self>())?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<(), Arc<Self>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<RootInvocationOriginalV1, RootObservationErrorV1>>())?
            .checked_add(std::mem::size_of::<Result<RootEnrollmentOriginalsV1, RootObservationErrorV1>>())?
            .checked_add(RootInvocationOriginalV1::construction_bytes_v1()?)?
            .checked_add(super::root_selected_currentness::RootSelectedServiceOriginalV1::construction_bytes_v1()?)
    }

    pub(super) fn claim_writer_once(&self, index: usize) -> Result<(), RootObservationErrorV1> {
        // The same invocation lock closes the check/claim interval. The closed
        // recipe index is internal; neither a caller path nor a counter mints it.
        let mut invocation = self.enter_native()?;
        let mut claims = self.writer_claims.lock().map_err(|_| {
            invocation.refuse();
            RootObservationErrorV1::Service
        })?;
        let slot = match claims.get_mut(index) {
            Some(slot) if !*slot => slot,
            _ => {
                invocation.refuse();
                return Err(RootObservationErrorV1::Service);
            }
        };
        *slot = true;
        Ok(())
    }

    pub(super) fn enrollment(&self) -> &RootEnrollmentOriginalsV1 {
        &self.enrollment
    }

    pub(super) fn invocation(&self) -> &RootInvocationOriginalV1 {
        &self.invocation
    }

    pub(super) fn has_identity(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.initial_identity, identity)
    }

    pub(super) fn enter_native(&self)
        -> Result<RootNativeInvocationGuardV1<'_>, RootObservationErrorV1>
    {
        self.invocation.enter_native()
    }

    pub(super) fn enter_observation(&self)
        -> Result<RootNativeInvocationGuardV1<'_>, RootObservationErrorV1>
    {
        self.invocation.enter_observation()
    }

    pub(super) fn end_initial(&self) {
        self.financial.abort_if_unfinished_v1();
        self.invocation.end_initial();
    }
}
