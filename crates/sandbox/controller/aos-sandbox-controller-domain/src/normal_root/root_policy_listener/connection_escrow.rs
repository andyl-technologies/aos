//! Keeps the listener's prepaid connection alive until transient D is positive.
//!
//! Its fixed listener reservoir pays the same accepted socket, duplicate and
//! peer pidfd before accept. No duplication, IO or new financial owner occurs
//! at transfer. A separately prepaid fixed response follows genuine D disposal;
//! EOF itself cannot distinguish positive disposal from process exit.

use super::*;

pub(super) struct RootPolicyConnectionEscrowV1 {
    native_financial: Option<aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1>,
    native: Option<RetainedUnixStream>,
    completion: super::permanent_completion::RootPermanentCompletionOriginalV2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read as _};
    use std::os::fd::AsFd as _;

    #[test]
    fn same_endpoint_stays_open_until_the_last_escrow_owner_drops() {
        let (original, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let native = RetainedUnixStream::from_owned(original.try_clone().unwrap().into()).unwrap();
        native.require_same_endpoint_v1(original.as_fd()).unwrap();
        let mut escrow = RootPolicyConnectionEscrowV1 {
            native_financial: None,
            native: None,
            completion: Default::default(),
        };
        // Socket custody alone cannot lend a positive financial association.
        assert!(escrow.require_same_empty_v1(None).is_err());

        escrow.retain_same_native_v1(native);
        drop(original);

        assert!(escrow.require_same_empty_v1(None).is_err());
        let mut byte = [0];
        assert_eq!(
            peer.read(&mut byte).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        drop(escrow);
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }
}

impl RootPolicyConnectionEscrowV1 {
    pub(super) fn arm_before_body_once_v2(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_financial_association_v1(startup)?;
        let mut original = startup.lock_receiving_v1()?;
        let returned = self.completion
            .arm_before_body_once_v2(original.original_mut_v1(), startup);
        original.finish_returned_v1(returned)
    }

    pub(super) fn install_completed_plan_v2(&mut self, plan: RootPolicyPositiveCompletionPlanV2) {
        self.completion.install_completed_plan_v2(plan);
    }

    pub(super) fn require_completion_armed_v2(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.completion.require_armed_empty_v2()
    }

    pub(super) fn send_after_positive_disposition_once_v2(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_financial_association_v1(startup)?;
        let mut original = startup.lock_receiving_v1()?;
        let returned = match self.native.as_mut() {
            Some(native) => self.completion.send_after_positive_disposition_once_v2(
                original.original_mut_v1(), startup, native,
            ),
            None => Err(NormalRootStartupErrorV1::Service),
        };
        original.finish_returned_v1(returned)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.completion.failure()
    }

    pub(super) fn claim_before_body_v1(
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<Self, NormalRootStartupErrorV1> {
        let native_financial = {
            let receiving = startup.lock_receiving_v1()?;
            let original = receiving.original_v1();
            let returned = original.require_policy_connection_escrow_v1().and_then(|()| {
                original.native_journal_financial_original_v1()
                    .map_err(|_| NormalRootStartupErrorV1::Service)
            });
            receiving.finish_returned_v1(returned)?
        };
        Ok(Self {
            native_financial: Some(native_financial),
            native: None,
            completion: Default::default(),
        })
    }

    pub(super) fn require_same_empty_v1(
        &self,
        financial: Option<&aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.native.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let expected = financial.ok_or(NormalRootStartupErrorV1::Service)?;
        self.native_financial.as_ref().ok_or(NormalRootStartupErrorV1::Service)?
            .require_same_v1(expected).map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(())
    }

    fn require_financial_association_v1(
        &self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let expected = startup.receiving_financial.as_ref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let actual = self.native_financial.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        if !actual.same_original_data_v1(expected) {
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(())
    }

    // The caller already checked the whole body and original socket cookie,
    // peer and endpoint against this exact retained native stream. Its private
    // empty slot has no competing writer under the exclusive listener borrow.
    pub(super) fn retain_same_native_v1(&mut self, native: RetainedUnixStream) {
        if self.native.is_some() {
            std::process::abort();
        }
        self.native = Some(native);
    }
}
