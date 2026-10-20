//! Lends the fixed Controller writer only through its actual Bank/launch join.
//!
//! Cache receives the same live profile-construction interval beside the real
//! writer and confirmed launch. No profile/Arc pair, decoded Bank, success
//! scalar or published coordinates can construct this loan. Failed entry and
//! independent owed observations remain in this original until termination.

use std::io;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use crate::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::HistoricalRuntimeLedgerReadV1;

use crate::controller_receiving::construction::{
    ControllerCacheConstructionReceivingV1, ControllerPublisherReadReceivingV1,
};
use crate::controller_receiving::profile::ControllerSelfProfileOriginalV1;

use super::coordinator::ControllerCoordinatorWriterV1;
use super::launch::ControllerBankLaunchOriginalV1;
use super::writer::ControllerWriterNameSampleV1;
use super::ControllerBankLaunchErrorV1;

trait ReadReceiving<'profile>: Sized {
    fn begin(profile: &'profile ControllerSelfProfileOriginalV1,
        original: &std::sync::Arc<crate::controller_receiving::ControllerReceivingOriginalV1>) -> Self;
    fn outer_inline_bytes<P>() -> Option<usize>;
    fn require_active(&self) -> Result<(), crate::controller_receiving::ControllerReceivingErrorV1>;
    fn finish_native_once(&mut self) -> Result<(), crate::controller_receiving::profile::ControllerProfileErrorV1>;
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)>;
}

macro_rules! receiving_recipe {
    ($receiver:ident, $outer:ident) => {
        impl<'profile> ReadReceiving<'profile> for $receiver<'profile> {
            fn begin(profile: &'profile ControllerSelfProfileOriginalV1,
                original: &std::sync::Arc<crate::controller_receiving::ControllerReceivingOriginalV1>) -> Self
            {
                Self::begin_from_conjunction(profile, original)
            }

            fn outer_inline_bytes<P>() -> Option<usize> {
                std::mem::size_of::<$outer<'_, '_, 'profile, P>>().checked_mul(2)
            }

            fn require_active(&self) -> Result<(), crate::controller_receiving::ControllerReceivingErrorV1> {
                self.require_active()
            }

            fn finish_native_once(&mut self) -> Result<(), crate::controller_receiving::profile::ControllerProfileErrorV1> {
                self.finish_native_once()
            }

            fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.failure()
            }
        }
    };
}

receiving_recipe!(ControllerCacheConstructionReceivingV1, ControllerCacheConstructionLoanV1);
receiving_recipe!(ControllerPublisherReadReceivingV1, PublisherControllerLoanV1);

#[derive(Clone, Copy)]
enum FailureStage {
    Entry,
    Before,
    Receiving,
    After,
    Profile,
    Launch,
}

/// Keeps the actual fixed writer/Bank/launch/profile conjunction continuously.
///
/// Entry is a retained operation, so the caller must check `require_active`
/// before its body. The role retains its own complete body result and calls
/// `finish_native_once` even after an entered body failed. Native completion
/// certifies no Cache semantic success. An unsuccessful or abandoned loan
/// fences the same writer and cannot free reached owners through field Drop.
#[must_use]
struct ControllerReadInterval<'writer, 'launch, 'profile, P, R: ReadReceiving<'profile>> {
    writer: &'writer mut ControllerCoordinatorWriterV1<P>,
    launch: &'launch ControllerBankLaunchOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
    entry: Result<(), ControllerBankLaunchErrorV1>,
    before: ControllerWriterNameSampleV1,
    after: ControllerWriterNameSampleV1,
    before_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    receiving: Option<R>,
    after_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_result: Option<Result<(), crate::controller_receiving::profile::ControllerProfileErrorV1>>,
    launch_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    first: Option<FailureStage>,
    finished: bool,
}

impl<'writer, 'launch, 'profile, P, R: ReadReceiving<'profile>>
    ControllerReadInterval<'writer, 'launch, 'profile, P, R>
{
    fn begin(
        writer: &'writer mut ControllerCoordinatorWriterV1<P>,
        launch: &'launch ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Self {
        let entry = (|| {
            launch.require_current_recipient(&writer.fixed)?;
            if !profile.has_same_baseline_original(writer.fixed.original()) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let demand = Self::fixed_demand()?;
            writer.fixed.require_role_borrow_representation(demand)
        })();
        let mut loan = Self {
            writer,
            launch,
            profile,
            entry,
            before: ControllerWriterNameSampleV1::new(),
            after: ControllerWriterNameSampleV1::new(),
            before_result: None,
            receiving: None,
            after_result: None,
            profile_result: None,
            launch_result: None,
            first: None,
            finished: false,
        };
        if loan.entry.is_ok() {
            // Arm the independent held-name post before any constructor body.
            // The same prearmed sample remains owed after later native poison.
            loan.entry = loan.writer.fixed.begin_name_sample(&mut loan.after);
            if loan.entry.is_ok() {
                loan.before_result = Some((|| {
                    loan.writer.fixed.begin_name_sample(&mut loan.before)?;
                    loan.writer.fixed.finish_owed_name_sample(&mut loan.before)
                })());
                if matches!(loan.before_result, Some(Ok(()))) {
                    loan.receiving = Some(R::begin(
                        loan.profile, loan.writer.fixed.original(),
                    ));
                }
            }
        }
        if loan.entry.is_err() {
            loan.first = Some(FailureStage::Entry);
        } else if !matches!(loan.before_result, Some(Ok(()))) {
            loan.first = Some(FailureStage::Before);
        } else if loan.receiving.as_ref().is_none_or(|receiving| receiving.failure().is_some()) {
            loan.first = Some(FailureStage::Receiving);
        }
        loan
    }
}

impl<'writer, 'launch, 'profile, P, R: ReadReceiving<'profile>>
    ControllerReadInterval<'writer, 'launch, 'profile, P, R>
{
    fn fixed_demand() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let invalid = || ControllerBankLaunchErrorV1::Conflict;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(R::outer_inline_bytes::<P>()?))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<super::identity::CacheControllerOriginalRefV1>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<super::identity::PublisherControllerOriginalRefV1>()))
            .and_then(|bytes| bytes.checked_add(crate::canonical_journal::coordinator::CanonicalWriterReadViewV1::<P>
                ::receiving_construction_bytes_v1()?))
            .ok_or_else(invalid)?;
        let inline = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?);
        Ok(inline
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?)
    }

    /// Checks actual positive entry while the same conjunction remains borrowed.
    ///
    /// # Errors
    /// Refuses failed entry, incomplete names/profile, or completed interval.
    pub fn require_active(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.entry.is_err() || !matches!(self.before_result, Some(Ok(())))
            || self.after_result.is_some() || self.finished
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.receiving.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_active()?;
        Ok(())
    }

    /// Borrows Controller history under the same continuously held conjunction.
    ///
    /// # Errors
    /// Refuses failed or ended entry before lending any history view.
    pub fn historical_view(&self) -> Result<HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1> {
        self.require_active()?;
        Ok(self.writer.fixed.historical_view())
    }

    /// Borrows Runtime's existing read engine without exposing the location.
    ///
    /// # Errors
    /// Refuses failed or ended entry before lending the read engine.
    pub fn runtime_history(&self) -> Result<HistoricalRuntimeLedgerReadV1<'_, aos_sandbox_journal::protected_storage::ProtectedJournalLocation<P>>, ControllerBankLaunchErrorV1> {
        self.require_active()?;
        Ok(self.writer.fixed.runtime_history())
    }

    /// Returns the same writer's next sequence as comparison DATA.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn next_sequence(&self) -> Result<u64, ControllerBankLaunchErrorV1> {
        self.require_active()?;
        Ok(self.writer.fixed.next_sequence())
    }

    /// Lends a bounded cursor over the actual original file without another open.
    ///
    /// # Errors
    /// Refuses failed or ended entry. The actual extent remains caller DATA.
    pub fn captured_reader(&self, length: u64) -> Result<CanonicalCoordinatorReadCursorV1<'_>, ControllerBankLaunchErrorV1> {
        self.require_active()?;
        Ok(self.writer.fixed.captured_reader(length))
    }

    /// Samples the same held data file at the role's native read frontier.
    ///
    /// # Errors
    /// Returns the actual metadata failure, or closed-entry refusal.
    pub fn metadata(&self) -> Result<std::fs::Metadata, ControllerBankLaunchErrorV1> {
        self.require_active()?;
        self.writer.fixed.metadata().map_err(|cause: io::Error| {
            crate::canonical_journal::NativeJournalDataErrorV1::from(cause).into()
        })
    }

    /// Performs every already-owed native/profile post before native settlement.
    ///
    /// The upper owner calls this independently of its body result. Completion
    /// neither accepts a success flag nor proves the role's semantic outcome.
    ///
    /// # Errors
    /// Retains first entry/name/profile/launch failure and fences actual writer.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.after_result.is_some() || self.finished {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // A role debit refusal already held by the receiving owner precedes
        // these independent posts. Record that position before the post adds
        // another result to the same receiving owner.
        if self.receiving.as_ref().is_some_and(|receiving| receiving.failure().is_some()) {
            self.first.get_or_insert(FailureStage::Receiving);
        }
        self.after_result = Some(self.writer.fixed.finish_owed_name_sample(&mut self.after));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::After);
        }
        // Profile completion remains independent of the held-name result.
        if let Some(receiving) = self.receiving.as_mut() {
            self.profile_result = Some(receiving.finish_native_once());
            if !matches!(self.profile_result, Some(Ok(()))) {
                self.first.get_or_insert(FailureStage::Profile);
            }
        }
        self.launch_result = Some(self.launch.require_current_recipient(&self.writer.fixed));
        if !matches!(self.launch_result, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::Launch);
        }
        if self.failure().is_some() || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.profile_result, Some(Ok(())))
            || !matches!(self.launch_result, Some(Ok(())))
        {
            self.writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.before.dispose_after_complete_interval();
        self.after.dispose_after_complete_interval();
        self.finished = true;
        Ok(())
    }

    /// Borrows the earliest reached conjunction or native-post cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FailureStage::Entry => self.writer.fixed.borrow_debit_failure.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.entry.as_ref().err().map(|cause| cause as _)),
            FailureStage::Before => self.before.failure().or_else(|| {
                self.before_result.as_ref()?.as_ref().err().map(|cause| cause as _)
            }),
            FailureStage::Receiving => self.receiving.as_ref().and_then(|receiving| receiving.failure()),
            FailureStage::After => self.after.failure().or_else(|| {
                self.after_result.as_ref()?.as_ref().err().map(|cause| cause as _)
            }),
            FailureStage::Profile => self.receiving.as_ref().and_then(|receiving| receiving.failure())
                .or_else(|| self.profile_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FailureStage::Launch => self.launch_result.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

impl<'profile, P, R: ReadReceiving<'profile>> Drop for ControllerReadInterval<'_, '_, 'profile, P, R> {
    fn drop(&mut self) {
        if !self.finished {
            self.writer.fixed.fence();
            // This borrow cannot move its actual role/body failure into an
            // unrelated owner. The coordinator retains the loan on failure;
            // abandonment must terminate before any partial owner is freed.
            std::process::abort();
        }
    }
}

/// Keeps the continuous actual C conjunction around one private Cache constructor.
#[must_use]
pub struct ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P> {
    interval: ControllerReadInterval<'writer, 'launch, 'profile, P, ControllerCacheConstructionReceivingV1<'profile>>,
}

/// Keeps a short actual Controller read interval for Publisher/Runtime/Local.
///
/// It cannot append or yield a mutable coordinator, file, descriptor or account.
#[must_use]
pub struct PublisherControllerLoanV1<'writer, 'launch, 'profile, P> {
    interval: ControllerReadInterval<'writer, 'launch, 'profile, P, ControllerPublisherReadReceivingV1<'profile>>,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Borrows the same confirmed writer/Bank/launch/profile for Cache construction.
    #[must_use]
    pub fn borrow_cache_construction<'writer, 'launch, 'profile>(
        &'writer mut self,
        launch: &'launch ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P> {
        ControllerCacheConstructionLoanV1 {
            interval: ControllerReadInterval::begin(self, launch, profile),
        }
    }

    /// Borrows the same confirmed Controller conjunction for a short Publisher read.
    #[must_use]
    pub fn borrow_publisher<'writer, 'launch, 'profile>(
        &'writer mut self,
        launch: &'launch ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> PublisherControllerLoanV1<'writer, 'launch, 'profile, P> {
        PublisherControllerLoanV1 {
            interval: ControllerReadInterval::begin(self, launch, profile),
        }
    }
}

impl<'writer, 'launch, 'profile, P> ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P> {
    /// Lends the inert original association after the whole interval completes.
    ///
    /// # Errors
    /// Refuses unfinished or failed posts; the result cannot start any work.
    pub fn completed_original_ref(&self)
        -> Result<super::identity::CacheControllerOriginalRefV1, ControllerBankLaunchErrorV1>
    {
        if !self.interval.finished || self.interval.failure().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(super::identity::CacheControllerOriginalRefV1::from_completed_loan(
            self.interval.writer.fixed.identity(),
        ))
    }

    /// Rejoins a completed inert association to this fresh actual interval.
    ///
    /// # Errors
    /// Refuses a foreign original or an inactive interval.
    pub fn require_same_original_ref(&self, held: &super::identity::CacheControllerOriginalRefV1)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_active()?;
        if !held.matches_actual_original(self.interval.writer.fixed.identity(), self.interval.writer.fixed.original()) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Checks the same live native/profile interval before role work.
    ///
    /// # Errors
    /// Refuses failed or ended entry without a new observation.
    pub fn require_active(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()
    }

    /// Lends the original historical ledger through the same live interval.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn historical_view(&self) -> Result<HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1> {
        self.interval.historical_view()
    }

    /// Lends Runtime's original read-only crosslink engine.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn runtime_history(&self) -> Result<HistoricalRuntimeLedgerReadV1<'_, aos_sandbox_journal::protected_storage::ProtectedJournalLocation<P>>, ControllerBankLaunchErrorV1> {
        self.interval.runtime_history()
    }

    /// Returns the original next sequence as comparison DATA.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn next_sequence(&self) -> Result<u64, ControllerBankLaunchErrorV1> {
        self.interval.next_sequence()
    }

    /// Lends the same bounded positional cursor without a File projection.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn captured_reader(&self, length: u64) -> Result<CanonicalCoordinatorReadCursorV1<'_>, ControllerBankLaunchErrorV1> {
        self.interval.captured_reader(length)
    }

    /// Borrows the actual completed entry witness as passive comparison DATA.
    ///
    /// # Errors
    /// Refuses failed or ended entry; this witness cannot construct a role loan.
    pub fn held_writer_witness(&self) -> Result<&aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness, ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.before.witness().ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    /// Samples the actual original file at the caller's metadata frontier.
    ///
    /// # Errors
    /// Preserves native metadata failure or closed-entry refusal.
    pub fn metadata(&self) -> Result<std::fs::Metadata, ControllerBankLaunchErrorV1> {
        self.interval.metadata()
    }

    /// Completes all already-owed name/profile/current-recipient posts once.
    ///
    /// # Errors
    /// Retains actual first cause and fences a failed or unfinished writer.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.finish_native_once()
    }

    /// Borrows the first actual retained interval refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.interval.failure()
    }

    /// Restricts the same Cache Bootstrap native journal representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_bootstrap_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_bootstrap_native_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache HOLD native journal representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_hold_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_hold_native_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache clock native journal representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_clock_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_clock_native_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache Authority native journal representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_authority_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_authority_native_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache STATE native journal representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_state_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_state_native_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache import models representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_import_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_import_models_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache Source models representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_source_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_source_models_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache Authority models representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_authority_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_authority_models_complete(complete)?;
        Ok(())
    }

    /// Restricts the same Cache physical owners representation before growth.
    ///
    /// This monotone debit returns no account, permit, writer or completion.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or inactive original-interval refusal.
    pub fn require_physical_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.receiving.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_physical_complete(complete)?;
        Ok(())
    }

}

impl<'writer, 'launch, 'profile, P> PublisherControllerLoanV1<'writer, 'launch, 'profile, P> {
    /// Checks the same live native/profile interval before role work.
    ///
    /// # Errors
    /// Refuses failed or ended entry without a new observation.
    pub fn require_active(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.require_active()
    }

    /// Lends the original historical ledger through the same live interval.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn historical_view(&self) -> Result<HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1> {
        self.interval.historical_view()
    }

    /// Lends Runtime's original read-only crosslink engine.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn runtime_history(&self) -> Result<HistoricalRuntimeLedgerReadV1<'_, aos_sandbox_journal::protected_storage::ProtectedJournalLocation<P>>, ControllerBankLaunchErrorV1> {
        self.interval.runtime_history()
    }

    /// Returns the original next sequence as comparison DATA.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn next_sequence(&self) -> Result<u64, ControllerBankLaunchErrorV1> {
        self.interval.next_sequence()
    }

    /// Lends the same bounded positional cursor without a File projection.
    ///
    /// # Errors
    /// Refuses failed or ended entry.
    pub fn captured_reader(&self, length: u64) -> Result<CanonicalCoordinatorReadCursorV1<'_>, ControllerBankLaunchErrorV1> {
        self.interval.captured_reader(length)
    }

    /// Borrows the actual completed entry witness as passive comparison DATA.
    ///
    /// # Errors
    /// Refuses failed or ended entry; this witness cannot construct a role loan.
    pub fn held_writer_witness(&self) -> Result<&aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness, ControllerBankLaunchErrorV1> {
        self.interval.require_active()?;
        self.interval.before.witness().ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    /// Samples the actual original file at the caller's metadata frontier.
    ///
    /// # Errors
    /// Preserves native metadata failure or closed-entry refusal.
    pub fn metadata(&self) -> Result<std::fs::Metadata, ControllerBankLaunchErrorV1> {
        self.interval.metadata()
    }

    /// Completes all already-owed name/profile/current-recipient posts once.
    ///
    /// # Errors
    /// Retains actual first cause and fences a failed or unfinished writer.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.interval.finish_native_once()
    }

    /// Borrows the first actual retained interval refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.interval.failure()
    }

    /// Lends only an inert original association after this whole native interval.
    ///
    /// # Errors
    /// Refuses unfinished or failed posts; the result cannot start another loan.
    pub fn completed_original_ref(&self) -> Result<super::identity::PublisherControllerOriginalRefV1, ControllerBankLaunchErrorV1> {
        if !self.interval.finished || self.interval.failure().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(super::identity::PublisherControllerOriginalRefV1::from_completed_loan(
            self.interval.writer.fixed.identity(),
        ))
    }

    /// Rejoins a held inert association to this actual newly entered interval.
    ///
    /// # Errors
    /// Refuses a different original or inactive current interval.
    pub fn require_same_original_ref(&self, held: &super::identity::PublisherControllerOriginalRefV1)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_active()?;
        if !held.matches_actual_original(self.interval.writer.fixed.identity(), self.interval.writer.fixed.original()) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }
}
