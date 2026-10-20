//! Fixed selected Mode-file prepayment on the actual Storage original.
//!
//! Mode is a protected floor policy observation, not resource authority. The
//! same genuine installed receiving original must admit its actual upper
//! capture geometry before the closed reader opens any Mode file.

use super::*;

impl StoragePrepareReceivingLoanV1<'_> {
    /// Pays the selected initial Mode capture and its retained local post.
    ///
    /// The upper supplies the concrete shared reader's DATA geometry, including
    /// its actual capture owner and every simultaneously held comparison. No
    /// caller path, mode value, floor policy or new resource account is accepted.
    ///
    /// # Errors
    /// Refuses changed original custody, Runtime configuration already entered,
    /// a repeated Mode attempt or a sticky same-ledger capacity refusal.
    pub fn reserve_initial_mode_prefix_once_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if receiving.initial_mode_payment.is_some()
            || !receiving.startup.before_runtime_configuration_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.initial_mode_payment = Some(receiving.reserve(demand));
        if matches!(receiving.initial_mode_payment, Some(Ok(()))) {
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        }
    }
}
