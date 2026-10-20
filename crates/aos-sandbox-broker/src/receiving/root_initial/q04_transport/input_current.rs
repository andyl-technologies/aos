//! Borrows the same paid Root crossing around one upper target-name operation.
//!
//! The ordinary and split purposes share all native prefix, clock and post
//! recipes. The split ends N before the target and never accepts a target
//! callback, replacement clock, payment marker or successful semantic Result.

use aos_sandbox_core::RawPairedClockSample;

use super::{
    RootJournalFinancialOriginalV1, RootObservationErrorV1, RootQ04TransportOriginalV1, positive,
};

/// Borrows one paid prefix while its actual target-name check runs above.
///
/// The native invocation fence has ended before this loan is returned. Its
/// owner must retain a target failure or unwind and explicitly finish the
/// original-clock and independent-post frontier before propagating it.
#[must_use = "finish the same native current prefix before returning or unwinding"]
pub struct RootQ04InputCurrentLoanV1<'origin, 'startup> {
    origin: &'origin mut RootQ04TransportOriginalV1<'startup>,
    finished: bool,
}

impl RootQ04InputCurrentLoanV1<'_, '_> {
    /// Completes the original clock and all independently owed native posts.
    ///
    /// # Errors
    /// Retains the same prefix, original clock, Root-post or settlement refusal.
    pub fn finish_once_v1(mut self) -> Result<RawPairedClockSample, RootObservationErrorV1> {
        self.finished = true;
        self.origin.finish_input_prefix_once_v1(false)
    }

    /// Finishes independently owed native posts after an upper target refusal.
    ///
    /// This negative-only entry skips the failed body's primary clock just as
    /// the original ordered target check did; the final clock post is owed.
    /// It cannot return a successful sample or complete a native crossing.
    ///
    /// # Errors
    /// Always refuses while retaining every actual independently owed result.
    pub fn finish_refused_once_v1(mut self) -> Result<(), RootObservationErrorV1> {
        self.finished = true;
        let _owed = self.origin.finish_input_prefix_once_v1(true);
        Err(RootObservationErrorV1::Service)
    }
}

impl Drop for RootQ04InputCurrentLoanV1<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.origin
                .closed
                .get_or_insert(RootObservationErrorV1::Service);
            if let Some(lifetime) = &self.origin.lifetime {
                lifetime.close();
            }
        }
    }
}

impl<'startup> RootQ04TransportOriginalV1<'startup> {
    /// Begins the same current prefix before the real target's named check.
    ///
    /// Startup, qualified Controller and queue checks use the existing native
    /// crossing. Its invocation guard ends before the genuine target operation.
    /// Prefix refusal still attempts the independent Root and final clock posts.
    ///
    /// # Errors
    /// Retains payment, prefix, native-unwind or independently owed post failure.
    pub fn begin_input_current_once_v1(
        &mut self,
    ) -> Result<RootQ04InputCurrentLoanV1<'_, 'startup>, RootObservationErrorV1> {
        self.prepare_crossing_once_v1(false, true)?;
        self.input_prefix_pending = true;
        let prefix = self
            .crossings
            .last_mut()
            .ok_or(RootObservationErrorV1::Service)?
            .observe_input_prefix_once_v1(
                self.startup,
                self.financial
                    .as_ref()
                    .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                    .ok_or(RootObservationErrorV1::Service)?,
                self.qualifier
                    .as_ref()
                    .ok_or(RootObservationErrorV1::Service)?,
                self.stream
                    .as_ref()
                    .ok_or(RootObservationErrorV1::Service)?,
            );
        if prefix.is_err() {
            let _owed = self.finish_input_prefix_once_v1(false);
            return Err(RootObservationErrorV1::Service);
        }
        Ok(RootQ04InputCurrentLoanV1 {
            origin: self,
            finished: false,
        })
    }

    fn finish_input_prefix_once_v1(
        &mut self,
        refused: bool,
    ) -> Result<RawPairedClockSample, RootObservationErrorV1> {
        if !self.input_prefix_pending {
            self.closed.get_or_insert(RootObservationErrorV1::Service);
            return Err(RootObservationErrorV1::Service);
        }
        self.input_prefix_pending = false;
        let returned = self
            .crossings
            .last_mut()
            .ok_or(RootObservationErrorV1::Service)?
            .finish_input_prefix_once_v1(
                self.startup,
                self.financial
                    .as_ref()
                    .map(RootJournalFinancialOriginalV1::q04_permanent_v1)
                    .ok_or(RootObservationErrorV1::Service)?,
                *positive(&self.original_pair)?,
                self.started.ok_or(RootObservationErrorV1::Service)?,
                refused,
            );
        if returned.is_err() {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            self.closed.get_or_insert(RootObservationErrorV1::Service);
        }
        returned
    }
}
