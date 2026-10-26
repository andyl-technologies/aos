//! Lends original main-map DATA without exposing a Journal, File or writer.
//!
//! The genuine Source prepays the bounded canonical hash carrier before its
//! sole loan exists. Native readback bookends remain with the actual opening.

use std::cell::Ref;

use super::*;

/// Bounds the co-live original main-cut hash state, key scratch and carriers.
///
/// The canonical Security implementation checks its compiled layout and the
/// actual opened key limit against this separately prepaid allowance.
pub const METHOD46_INITIAL_MAIN_CUT_BYTES_V1: usize = 8192;

/// Borrows DATA from the same Source-funded protected main opening.
///
/// Only the actual startup constructs this loan after native admission and
/// payment. Neither this loan nor its map yields writer, schema or TPM rights.
#[must_use = "retain the genuine original loan beside the canonical hash result"]
pub struct Method46InitialMainReadbackLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
    after_attempted: Cell<bool>,
}

/// Holds a temporary immutable borrow of the original complete native map.
///
/// No Journal or descriptor is exposed. Holding this view through an owed
/// writer post makes that post refuse; other posts and Source after remain owed.
pub struct Method46InitialMainMapReadbackV1<'owner> {
    journal: Ref<'owner, crate::Journal>,
}

impl Method46InitialMainMapReadbackV1<'_> {
    /// Returns the same held main's next native sequence as DATA.
    pub fn next_sequence_data_v1(&self) -> u64 {
        self.journal.snapshot_sequence()
    }

    /// Returns the actual opened key-width ceiling as DATA for hash pricing.
    pub fn maximum_key_bytes_data_v1(&self) -> usize {
        self.journal.configured_limits_data_v1().maximum_key_bytes
    }

    /// Iterates the whole current map, including foreign namespace DATA.
    pub fn all_records_data_v1(
        &self,
    ) -> impl Iterator<Item = (crate::RecordNamespace, &[u8], &[u8])> {
        self.journal.all_records()
    }

    /// Iterates every current Broker row in the original bytewise order.
    ///
    /// Foreign namespaces, historical schema and capacity ownership require
    /// independent admission; this range never grants namespace authority.
    pub fn broker_records_data_v1(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.journal
            .records(crate::RecordNamespace::BrokerSessionTraffic)
    }
}

impl Method46InitialMainReadbackLoanV1<'_> {
    /// Copies comparison identity from this same current Source original.
    ///
    /// # Errors
    /// Refuses a failed or ended Source, busy original or missing identity.
    pub fn origin_data_v1(
        &self,
    ) -> Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1> {
        if self.startup.first.get().is_some() || self.startup.after_attempted.get() {
            return Err(self.startup.closed);
        }
        self.startup
            .source
            .try_borrow()
            .map_err(|_| self.startup.closed)?
            .require_current_v1()
            .map_err(|_| self.startup.closed)?;
        self.startup.origin.ok_or(self.startup.closed)
    }

    /// Borrows the same admitted main map without copying or performing IO.
    ///
    /// # Errors
    /// Refuses an ended Source, busy owner, failed native before or entered
    /// after. The caller drops this temporary view before finishing readback.
    pub fn read_map_data_v1(
        &self,
    ) -> Result<Method46InitialMainMapReadbackV1<'_>, Method46InitialStartupClosedV1> {
        self.origin_data_v1()?;
        let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
        let writer = body
            .main_writer
            .try_borrow()
            .map_err(|_| self.startup.closed)?;
        let journal = Ref::filter_map(writer, |writer| writer.readback_journal_data())
            .map_err(|_| self.startup.closed)?;
        Ok(Method46InitialMainMapReadbackV1 { journal })
    }

    /// Attempts the prepaid independent native readback after even on refusal.
    ///
    /// # Errors
    /// Refuses a busy/ended owner or the retained original name failure. The
    /// enclosing startup still attempts all its other independently owed posts.
    pub fn finish_readback_after_owed_once_v1(&self) -> Result<(), Method46InitialStartupClosedV1> {
        if self.after_attempted.replace(true)
            || self.startup.after_attempted.get()
            || self.startup.origin.is_none()
        {
            return Err(self.startup.fail(First::MainWriter));
        }
        let result = (|| {
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            body.main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .finish_readback_after_owed()
                .map_err(|_| self.startup.closed)
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }

    /// Fences this same startup after a canonical map/hash refusal.
    pub fn refuse_readback_v1(&self) {
        self.startup.fail(First::MainWriter);
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Prepays and lends the original existing main-map readback once.
    ///
    /// The same Source pays the finite hash allowance before the result owner
    /// exists. Native before/after work was prepaid with this opening's fixed
    /// acquisition. No supplied map, amount, path or Journal enters this gate.
    ///
    /// # Errors
    /// Refuses missing original writer admission, reentry, a closed Source,
    /// insufficient actual funding or a failed original native name bookend.
    pub fn lend_initial_main_readback_once_v1(
        &self,
    ) -> Result<Method46InitialMainReadbackLoanV1<'_>, Method46InitialStartupClosedV1> {
        let result = (|| {
            if self.first.get().is_some() || self.after_attempted.get() {
                return Err(self.closed);
            }
            self.source
                .try_borrow()
                .map_err(|_| self.closed)?
                .require_current_v1()
                .map_err(|_| self.closed)?;
            let body = self.body.as_ref().ok_or(self.closed)?;
            let mut writer = body.main_writer.try_borrow_mut().map_err(|_| self.closed)?;
            if !writer.readback_available_data() {
                return Err(self.closed);
            }
            self.fund_additional(Some(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, METHOD46_INITIAL_MAIN_CUT_BYTES_V1 as u64),
            ))?;
            writer.begin_readback_once().map_err(|_| self.closed)?;
            Ok(Method46InitialMainReadbackLoanV1 {
                startup: self,
                after_attempted: Cell::new(false),
            })
        })();
        result.map_err(|_| self.fail(First::MainWriter))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn method46_initial_main_readback_requires_original_writer_before_payment() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));

        assert!(startup.lend_initial_main_readback_once_v1().is_err());
        assert!(startup.capture_before_arguments_once_v1().is_err());

        assert!(startup.body.is_none());
        assert!(!startup.capture_attempted);
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        assert!(matches!(startup.first.get(), Some(First::MainWriter)));
    }

    #[test]
    fn method46_initial_main_readback_refusal_keeps_source_after_owed() {
        let startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        // Negative dispatch only: this has no actual Source or native writer.
        let loan = Method46InitialMainReadbackLoanV1 {
            startup: &startup,
            after_attempted: Cell::new(false),
        };

        assert!(loan.origin_data_v1().is_err());
        assert!(loan.read_map_data_v1().is_err());
        loan.refuse_readback_v1();
        assert!(loan.finish_readback_after_owed_once_v1().is_err());
        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::MainWriter)));
    }
}
