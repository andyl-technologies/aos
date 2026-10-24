//! Drives genuine native startup phases inside the same original L/U interval.
//!
//! Policy owns phase results and the same independently owed native posts.
//! These finite callers lend actual Initial and real exclusion, never snapshots.

use super::RootReceivingGuardV1;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::RootPolicyStartupJournalV1;

impl RootReceivingGuardV1<'_> {
    pub(crate) fn receive_startup_journal_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &mut RootPolicyStartupJournalV1,
    ) -> Result<(), Error> {
        let startup = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        let (prior, initial, exclusion) = self.native_startup_prior_parts_mut_v1()?;
        {
            let provision = initial.borrow_selected_provision_v1()?;
            journal.initialize_selected_once_v1(&provision)?;
        }
        prior
            .receive_selected_journal_once_v1(
                journal.native_mut_v1()?,
                initial,
                &startup,
                exclusion,
            )
            .map_err(|()| Error::Service)
    }

    pub(crate) fn begin_startup_credentials_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &mut RootPolicyStartupJournalV1,
    ) -> Result<(), Error> {
        let startup = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        let (prior, initial, exclusion) = self.native_startup_prior_parts_mut_v1()?;
        prior
            .begin_selected_credentials_once_v1(
                journal.native_mut_v1()?,
                initial,
                &startup,
                exclusion,
            )
            .map_err(|()| Error::Service)
    }

    pub(crate) fn finish_startup_credentials_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &mut RootPolicyStartupJournalV1,
    ) -> Result<(), Error> {
        // This is the owed path. Do not construct a new healthy selected loan:
        // the native startup method below lends the original without rechecking.
        let startup = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()?;
        let (prior, initial, exclusion) = self.native_startup_prior_parts_mut_v1()?;
        prior
            .finish_selected_credentials_once_v1(
                journal.native_mut_v1()?,
                initial,
                &startup,
                exclusion,
            )
            .map_err(|()| Error::Service)
    }

    pub(crate) fn prepay_policy_listener_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        {
            let startup = startup
                .native_startup_original_v1()
                .borrow_selected_original_v1()?;
            let (prior, initial, exclusion) = self.native_startup_prior_parts_mut_v1()?;
            prior
                .begin_selected_listener_once_v1(initial, &startup, exclusion)
                .map_err(|()| Error::Service)?;
        }
        self.original_mut_v1().complete_native_listener_once_v1()
    }
}

impl RootReceivingGuardV1<'_> {
    // The same actual profile adapter pays these four reached upper forwarding
    // interfaces before any native journal or credential interval is entered.
    pub(crate) fn startup_driver_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &mut RootPolicyStartupJournalV1,
        )>()
        .checked_mul(9)?
        .checked_add(size_of::<(&mut Self, &ProductionNormalRootStartupV1)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), Error>>().checked_mul(12)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
