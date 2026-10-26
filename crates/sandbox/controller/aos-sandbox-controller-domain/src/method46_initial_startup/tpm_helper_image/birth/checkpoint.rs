//! Captures Source-paid checkpoint staging before the first native NV request.
//!
//! Security derives the canonical checkpoint from its resident approved request.
//! The same Source owns the native prefix and fixed journal encoder; comparison
//! DATA grants no publication or TPM authority.

use super::*;

impl Method46InitialTpmHelperDrivingLoanV1<'_> {
    /// Captures the fixed checkpoint stage as an exact canonical prefix once.
    ///
    /// The Source prepays before encoding or opening the existing stage. This
    /// read-only step must complete before any NV request; a conflicting prefix
    /// cannot be discovered only after the first Extend. No file is created,
    /// written, truncated, renamed or removed by this method.
    ///
    /// # Errors
    /// Refuses failed/ended Source, reentry, missing original locks, insufficient
    /// funding, changed native main, unsafe stage or a nonmatching prefix. Every
    /// reached native failure and the independent main post remain resident.
    pub fn capture_initial_checkpoint_stage_once_v1(
        &mut self,
        checkpoint: [u8; 156],
    ) -> Result<(), Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = (|| {
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let mut writer = body
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?;
            let demand = writer.quote_initial_checkpoint_once();
            self.startup.fund_additional(demand)?;
            writer
                .capture_initial_checkpoint_once(checkpoint)
                .map_err(|_| self.startup.closed)
        })();
        let after = require_current(self.startup);
        if action.is_err() || after.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }
}

enum PublicationStep {
    Prepare,
    Validate,
    Exchange,
    Sync,
    Finish,
}

impl Method46InitialTpmHelperDrivingLoanV1<'_> {
    /// Publishes the captured canonical checkpoint after actual helper retirement.
    ///
    /// The same original child must have closed its TPM context and completed
    /// clean reaping. Security must already have compared the final target with
    /// its resident approval. Source prepays publication, retires the original
    /// empty-floor intervals without releasing either lock, writes/fsyncs the
    /// bounded stage and checks currentness again before exchanging both names.
    /// Directory sync and independent native posts remain owed after failure.
    /// Both files survive; this method never unlinks or truncates a conflict.
    ///
    /// # Errors
    /// Refuses unretired helper, failed Source, absent capture/funding, reentry,
    /// changed main/floor/stage, native write/ownership/sync/exchange failure or
    /// an uncertain postcheck. Failed prefixes remain in the original Source.
    pub fn publish_initial_checkpoint_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let action = (|| {
            require_current(self.startup)?;
            if !self.helper_retired {
                return Err(self.startup.closed);
            }
            {
                let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
                let mut writer = body
                    .main_writer
                    .try_borrow_mut()
                    .map_err(|_| self.startup.closed)?;
                let demand = writer.quote_initial_checkpoint_publication_once();
                self.startup.fund_additional(demand)?;
            }
            let prepared = self.checkpoint_step(PublicationStep::Prepare);
            self.observe_checkpoint_after(prepared)?;
            let validated = self.checkpoint_step(PublicationStep::Validate);
            self.observe_checkpoint_after(validated)?;
            let exchanged = self.checkpoint_step(PublicationStep::Exchange);
            self.observe_checkpoint_after(exchanged)
        })();
        // No successful Source or primary-action prerequisite suppresses debt.
        let synced = self.checkpoint_step(PublicationStep::Sync);
        let synced = self.observe_checkpoint_after(synced);
        let posted = self.checkpoint_step(PublicationStep::Finish);
        let posted = self.observe_checkpoint_after(posted);
        if action.is_err() || synced.is_err() || posted.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }

    fn observe_checkpoint_after(
        &self,
        result: Result<(), Method46InitialStartupClosedV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let after = require_current(self.startup);
        if result.is_err() || after.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }

    fn checkpoint_step(&self, step: PublicationStep) -> Result<(), Method46InitialStartupClosedV1> {
        let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
        let mut writer = body
            .main_writer
            .try_borrow_mut()
            .map_err(|_| self.startup.closed)?;
        match step {
            PublicationStep::Prepare => writer.prepare_initial_checkpoint_publication_once(),
            PublicationStep::Validate => writer.validate_initial_checkpoint_publication_once(),
            PublicationStep::Exchange => writer.exchange_initial_checkpoint_once(),
            PublicationStep::Sync => writer.sync_initial_checkpoint_after_owed(),
            PublicationStep::Finish => writer.finish_initial_checkpoint_after_owed(),
        }
        .map_err(|_| self.startup.closed)
    }
}
