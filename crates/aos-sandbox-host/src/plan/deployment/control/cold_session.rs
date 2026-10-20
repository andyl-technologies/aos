//! Funds finite pre-Session cleanup reads on the actual startup Control.
//!
//! The caller holds the original mutex guard throughout the shared cold
//! engine. Async Source observations surround that same synchronous engine;
//! no runtime, thread, Source account, enrollment or effect authority is made.
//! Failed clock/body/prefix originals remain on this captured Control. A
//! successful temporary-prefix drop never refunds the retained Session graph.

use super::*;
use super::terminal_inventory::HostControlPreparationReceivingV5;
use aos_sandbox_broker::receiving::HostControlColdClockOriginalV1;
use aos_sandbox_core::{RawPairedClockSample, component_receiving::complete_bound_delta_v1};
use std::sync::{Arc, Mutex, MutexGuard};

/// Names the closed pre-Session history being financed, without permitting it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostControlColdSessionPurposeV1 {
    /// Funds the shared cold prefix before the signed client HELLO is verified.
    ///
    /// The caller prepays a bound dominating the existing ordinary profile,
    /// Stop1/3 and NoApply42/43. Only the authenticated transport may select a
    /// profile, preserving its existing history gates; this financial identity
    /// neither selects a profile nor authorizes a method.
    Bootstrap,
    /// Funds the finite Stop cleanup Session without authorizing Stop1/3.
    StopCleanup,
    /// Funds the live NoApply42/43 Session, without access to old64/39 history.
    NoApplyRecovery,
}

/// Reports refusal while the actual current-Control originals remain retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Host cold cleanup Session is closed; its original cause remains retained")]
pub struct HostControlColdSessionClosedV1;

struct ColdIdentityV1 { purpose: HostControlColdSessionPurposeV1 }

/// Retains the actual captured Host startup owner before authentication exists.
///
/// Construction is sealed to the real broker. This is financial custody only;
/// neither the selected history nor a decoded transcript grants cleanup effects.
pub struct HostControlColdSessionOwnerV1 {
    original: Arc<Mutex<HostComponentControlStartupV2>>,
    resident: Option<crate::broker::HostLiveCleanupOwnerV1>,
}

impl HostControlColdSessionOwnerV1 {
    pub(crate) fn from_original_v1(
        original: Arc<Mutex<HostComponentControlStartupV2>>,
        resident: Option<crate::broker::HostLiveCleanupOwnerV1>,
    ) -> Self {
        Self { original, resident }
    }

    /// Locks the same actual owner through its finite cold Session interval.
    ///
    /// # Errors
    /// Refuses poisoned custody without replacing or reconstructing the owner.
    pub fn lock_original_v1(
        &self,
    ) -> std::result::Result<HostControlColdSessionAccessV1<'_>, HostControlColdSessionClosedV1>
    {
        Ok(HostControlColdSessionAccessV1 {
            original: self
                .original
                .lock()
                .map_err(|_| HostControlColdSessionClosedV1)?,
            resident: self.resident.as_ref(),
        })
    }
}

/// Holds the actual startup mutex guard, permitting no parallel sibling entry.
pub struct HostControlColdSessionAccessV1<'owner> {
    original: MutexGuard<'owner, HostComponentControlStartupV2>,
    resident: Option<&'owner crate::broker::HostLiveCleanupOwnerV1>,
}

#[derive(Clone, Copy)]
enum First { Financial, Before, Clock, Body, After, NativeAfter, Disposal, Node }

pub(super) struct ColdSessionOriginalV1 {
    identity: Arc<ColdIdentityV1>,
    complete: ResourceVector,
    clock: HostControlColdClockOriginalV1,
    body: Option<std::result::Result<(), HostControlColdSessionClosedV1>>,
    native_after: Option<std::result::Result<(), aos_sandbox_broker::receiving::FixedServiceOperationClosedV4>>,
    first: Option<First>,
    retention_issued: bool,
}

/// Pins the temporary native cold-prefix graph until its actual physical drop.
///
/// The private constructor belongs to the paid loan. Security parks this
/// non-Clone token beside its actual completed-prefix graph, drops that graph
/// after all native/TPM/Source posts, then drops the token. The live Session
/// journal/endpoint/floor/transcript stay separately retained and fully charged.
#[must_use = "retain this token beside the actual cold native-prefix graph"]
pub struct HostControlColdSessionNativeRetentionV1 { identity: Arc<ColdIdentityV1> }

/// Borrows only the same paid current-Control preparation and native clock.
pub struct HostControlColdSessionLoanV1<'original> {
    source: HostControlPreparationReceivingV5<'original>,
    identity: Arc<ColdIdentityV1>,
}

impl HostControlColdSessionAccessV1<'_> {
    /// Pays the actual cold carrier and native clock before their construction.
    ///
    /// `complete` is the caller's initial native/model demand. Later additional
    /// representations raise the same cumulative bound on the same residual.
    ///
    /// # Errors
    /// Refuses occupied/unhealthy original custody, overflow or insufficient
    /// current Control; no ordinary enrollment or lost Launch is reconstructed.
    pub fn begin_cold_session_v1(&mut self, purpose: HostControlColdSessionPurposeV1,
        complete: ResourceVector,
    ) -> std::result::Result<HostControlColdSessionLoanV1<'_>, HostControlColdSessionClosedV1> {
        self.original.require_admitted_original().map_err(|_| HostControlColdSessionClosedV1)?;
        if self.original.cold_session_original.is_some() { return Err(HostControlColdSessionClosedV1); }
        let intrinsic = cold_intrinsic_demand_v1().ok_or(HostControlColdSessionClosedV1)?;
        let quote = complete
            .checked_add(intrinsic)
            .map_err(|_| HostControlColdSessionClosedV1)?;
        let mut selected = false;
        let mut source = match self.resident {
            Some(resident) => resident.begin_inventory_v1(&mut self.original, quote, &mut selected),
            None => self
                .original
                .begin_native_inventory_entry_v5(quote, &mut selected),
        }
        .map_err(|_| HostControlColdSessionClosedV1)?;
        let identity = Arc::new(ColdIdentityV1 { purpose });
        source.original.cold_session_original = Some(Box::new(ColdSessionOriginalV1 {
            identity: Arc::clone(&identity), complete,
            clock: HostControlColdClockOriginalV1::default(), body: None, native_after: None,
            first: None, retention_issued: false,
        }));
        Ok(HostControlColdSessionLoanV1 { source, identity })
    }

    /// Borrows the retained native/financial cause after a refused cold entry.
    #[must_use]
    pub fn failure_v1(&self) -> &(dyn std::error::Error + '_) {
        cold_failure_v1(&self.original)
    }
}

fn cold_intrinsic_demand_v1() -> Option<ResourceVector> {
    // The clock supplier includes two full native-clock carrier planes.
    // Add only the surrounding original's remaining fields to avoid counting
    // those same inline carriers again. Loan/token/access have construction
    // and live-return planes; the single Arc allocation includes its counters.
    let original_extra = std::mem::size_of::<ColdSessionOriginalV1>()
        .checked_sub(std::mem::size_of::<HostControlColdClockOriginalV1>())?;
    let bytes = original_extra.checked_mul(2)?
        .checked_add(std::mem::size_of::<HostControlColdSessionLoanV1<'_>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<HostControlColdSessionNativeRetentionV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<HostControlColdSessionAccessV1<'_>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<HostControlColdSessionOwnerV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<ColdIdentityV1>())?
        .checked_add(3 * std::mem::size_of::<usize>())?;
    HostControlColdClockOriginalV1::receiving_demand_v1().ok()?
        .checked_add(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes,
            u64::try_from(bytes).ok()?)).ok()
}

impl HostControlColdSessionLoanV1<'_> {
    fn original(&self) -> std::result::Result<&ColdSessionOriginalV1, HostControlColdSessionClosedV1> {
        let original = self.source.original.cold_session_original.as_deref().ok_or(HostControlColdSessionClosedV1)?;
        if !Arc::ptr_eq(&original.identity, &self.identity) { return Err(HostControlColdSessionClosedV1); }
        Ok(original)
    }

    fn original_mut(&mut self) -> std::result::Result<&mut ColdSessionOriginalV1, HostControlColdSessionClosedV1> {
        self.original()?;
        self.source.original.cold_session_original.as_deref_mut().ok_or(HostControlColdSessionClosedV1)
    }

    fn select(&mut self, first: First) { if let Ok(original) = self.original_mut() { original.first.get_or_insert(first); } }

    /// Borrows the closed financial purpose without conferring history access.
    #[must_use]
    pub fn purpose_v1(&self) -> HostControlColdSessionPurposeV1 { self.identity.purpose }

    /// Compares the endpoint's node with the same protected Control profile.
    ///
    /// # Errors
    /// Refuses an unhealthy loan, missing protected profile or another node.
    /// No caller DATA can replace the actual Source-bound profile identity.
    pub fn require_node_data_v1(&mut self, node: [u8; 16])
        -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.require_current_v1()?;
        if self.source.original.profile.as_ref().is_none_or(|profile| profile.node != node) {
            self.select(First::Node);
            return Err(HostControlColdSessionClosedV1);
        }
        Ok(())
    }

    /// Checks the same actual current-Control body interval without new IO.
    ///
    /// # Errors
    /// Refuses changed identity, prior native/financial failure or completed IO.
    pub fn require_current_v1(&mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.source.original.require_admitted_original().map_err(|_| HostControlColdSessionClosedV1)?;
        let original = self.original()?;
        if original.first.is_some() || original.native_after.is_some() { return Err(HostControlColdSessionClosedV1); }
        if original.clock.retained_interval_data_v1().is_ok() {
            let result = self.original_mut()?.clock.require_current_v1();
            if result.is_err() { self.select(First::Clock); return Err(HostControlColdSessionClosedV1); }
        }
        Ok(())
    }

    /// Raises the absolute native/model bound without resetting spent planes.
    ///
    /// # Errors
    /// Refuses overflow, mismatched/closed original or insufficient same Control.
    pub fn raise_complete_v1(&mut self, complete: ResourceVector)
        -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.require_current_v1()?;
        let previous = self.original()?.complete;
        let (reached, delta) = complete_bound_delta_v1(previous, complete).map_err(|_| HostControlColdSessionClosedV1)?;
        let result = self.source.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed).and_then(|owner| owner.account_control_preparation_v5(delta));
        if result.is_err() {
            self.select(First::Financial);
            self.source.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostControlColdSessionClosedV1);
        }
        self.original_mut()?.complete = reached;
        Ok(())
    }

    /// Adds a newly reached representation to the same cumulative bound.
    ///
    /// # Errors
    /// Refuses checked overflow or the same current-Control boundary failure.
    pub fn require_additional_representation_v1(&mut self, additional: ResourceVector)
        -> std::result::Result<(), HostControlColdSessionClosedV1> {
        let complete = self.original()?.complete.checked_add(additional).map_err(|_| HostControlColdSessionClosedV1)?;
        self.raise_complete_v1(complete)
    }

    /// Issues the single private token before constructing the native prefix.
    ///
    /// # Errors
    /// Refuses reentry or a closed/foreign original; no decoded DATA can mint it.
    pub fn retain_native_prefix_once_v1(&mut self)
        -> std::result::Result<HostControlColdSessionNativeRetentionV1, HostControlColdSessionClosedV1> {
        self.require_current_v1()?;
        if self.original()?.retention_issued { return Err(HostControlColdSessionClosedV1); }
        self.original_mut()?.retention_issued = true;
        Ok(HostControlColdSessionNativeRetentionV1 { identity: Arc::clone(&self.identity) })
    }

    /// Reaches the actual paid async Source before using the existing observer.
    ///
    /// # Errors
    /// Retains failed native/property/Source observations and their first cause.
    pub async fn observe_before_once_v1(&mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.require_current_v1()?;
        let result = self.source.observe_before_once_v5().await;
        if result.is_err() { self.select(First::Before); }
        result.map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Confirms that the sync cold engine borrows the real completed before.
    ///
    /// # Errors
    /// Refuses unentered/failed actual Source native leaves, without another read.
    pub fn require_before_entered_v1(&mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.require_current_v1()?;
        if !self.source.before || self.source.after || !self.original()?.retention_issued {
            return Err(HostControlColdSessionClosedV1);
        }
        self.source.original.attempts[self.source.destinations.round_start].require_positive_leaf_v2()
            .map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Captures the shared native opening after its actual Source before.
    ///
    /// # Errors
    /// Retains native failure, wrong actual boot or repeated opening entry.
    pub fn actual_before_clock_v1(&mut self) -> std::result::Result<RawPairedClockSample, HostControlColdSessionClosedV1> {
        self.require_before_entered_v1()?;
        let result = self.original_mut()?.clock.actual_before_clock_v1();
        self.select_clock_result_v1(result)
    }

    fn select_clock_result_v1(&mut self, result: std::result::Result<RawPairedClockSample,
        aos_sandbox_broker::receiving::FixedServiceOperationClosedV4>)
        -> std::result::Result<RawPairedClockSample, HostControlColdSessionClosedV1> {
        let result = result.map_err(|_| HostControlColdSessionClosedV1).and_then(|sample| {
            self.source.original.require_argument_boot_v2(sample.host_boot_id())
                .map_err(|_| HostControlColdSessionClosedV1)?;
            Ok(sample)
        });
        if result.is_err() { self.select(First::Clock); }
        result
    }

    /// Borrows the paid original opening without observing or renewing it.
    ///
    /// # Errors
    /// Refuses absent/failed or already-finished native clock custody.
    pub fn retained_opening_clock_data_v1(&self) -> std::result::Result<RawPairedClockSample, HostControlColdSessionClosedV1> {
        self.original()?.clock.retained_opening_clock_data_v1().map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Narrows the same native cutoff and optional wall ceiling without renewal.
    ///
    /// # Errors
    /// Retains invalid/expired bounds or same-clock native failure.
    pub fn narrow_deadline_data_v1(&mut self, cutoff: u64, wall_expiry: Option<i64>)
        -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.require_before_entered_v1()?;
        let result = self.original_mut()?.clock.narrow_deadline_data_v1(cutoff, wall_expiry);
        if result.is_err() { self.select(First::Clock); }
        result.map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Borrows the actual opening's narrowed cutoff without taking a new sample.
    ///
    /// # Errors
    /// Refuses missing/failed clock or an already completed independent after.
    pub fn original_cutoff_data_v1(&self) -> std::result::Result<u64, HostControlColdSessionClosedV1> {
        self.original()?.clock.retained_interval_data_v1().map(|(_, cutoff)| cutoff)
            .map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Samples the finite shared clock immediately before one actual HELLO send.
    ///
    /// # Errors
    /// Retains expiry/provenance/native failure or exhausted two-send schedule.
    pub fn fresh_before_effect_clock_v1(&mut self) -> std::result::Result<RawPairedClockSample, HostControlColdSessionClosedV1> {
        self.require_before_entered_v1()?;
        let result = self.original_mut()?.clock.fresh_before_effect_clock_v1();
        self.select_clock_result_v1(result)
    }

    /// Records the sole sync body's classification while its native graph stays held.
    ///
    /// This financial marker grants no Session or effect. The actual native
    /// graph/token and all independent posts still require physical retirement.
    ///
    /// # Errors
    /// Refuses repeated body classification or a foreign cold original.
    pub fn record_body_result_v1(&mut self, result: std::result::Result<(), HostControlColdSessionClosedV1>)
        -> std::result::Result<(), HostControlColdSessionClosedV1> {
        let original = self.original_mut()?;
        if original.body.is_some() { return Err(HostControlColdSessionClosedV1); }
        if result.is_err() { original.first.get_or_insert(First::Body); }
        original.body = Some(result);
        result
    }

    /// Reaches the independently owed async Source after despite body failure.
    ///
    /// # Errors
    /// Retains the actual Source/native after failure without healthy reentry.
    pub async fn observe_after_once_v1(&mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        self.original()?;
        let result = self.source.observe_after_once_v5().await;
        if result.is_err() { self.select(First::After); }
        result.map_err(|_| HostControlColdSessionClosedV1)
    }

    /// Reaches the shared independently owed clock after even after refusal.
    ///
    /// # Errors
    /// Retains native/continuity/expiry failure or refuses repeated after entry.
    pub fn finish_native_once_v1(&mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        let original = self.original_mut()?;
        if original.native_after.is_some() { return Err(HostControlColdSessionClosedV1); }
        original.native_after = Some(original.clock.finish_native_once_v1());
        if !matches!(original.native_after, Some(Ok(()))) {
            original.first.get_or_insert(First::NativeAfter);
            return Err(HostControlColdSessionClosedV1);
        }
        Ok(())
    }

    /// Retires Source samples only after the actual temporary native graph drops.
    ///
    /// The same live Session graph remains separately held and fully charged.
    /// No negative/ambiguous prefix can drop its retention token to create this
    /// positive boundary; its actual caller first checks the finite native graph.
    ///
    /// # Errors
    /// Refuses pending token owners, any missing body/native/Source post or
    /// manager disposal failure. Cancellation retains the original and its debt.
    pub fn complete_after_native_drop_v1(mut self) -> std::result::Result<(), HostControlColdSessionClosedV1> {
        let original = self.original()?;
        if original.first.is_some() || !original.retention_issued
            || !matches!(original.body, Some(Ok(())))
            || !matches!(original.native_after, Some(Ok(()))) || !original.clock.completed_native_v1()
            || !self.source.before || !self.source.after || Arc::strong_count(&self.identity) != 2
        { return Err(HostControlColdSessionClosedV1); }
        for round in self.source.destinations.round_start .. self.source.destinations.round_start + 2 {
            self.source.original.attempts[round].require_positive_leaf_v2()
                .map_err(|_| HostControlColdSessionClosedV1)?;
        }
        let result = self.source.dispose_positive_once_v5();
        if result.is_err() { self.select(First::Disposal); return Err(HostControlColdSessionClosedV1); }
        self.source.original.cold_session_original = None;
        Ok(())
    }

    /// Borrows the actual chronological native/financial cause without cloning.
    #[must_use]
    pub fn failure_v1(&self) -> &(dyn std::error::Error + '_) { cold_failure_v1(self.source.original) }
}

fn cold_failure_v1(original: &HostComponentControlStartupV2) -> &(dyn std::error::Error + '_) {
    if let Some(cold) = original.cold_session_original.as_deref() {
        match cold.first {
            Some(First::Node) => return &HostControlColdSessionClosedV1,
            Some(First::Clock | First::NativeAfter) => if let Some(cause) = cold.clock.failure_v1() { return cause; },
            Some(First::Body) => if let Some(Err(cause)) = cold.body.as_ref() { return cause; },
            _ => {}
        }
    }
    original.failure()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_huge_caller_quote_cannot_adopt_uncaptured_control_or_create_native_clock() {
        use std::os::unix::process::ExitStatusExt as _;

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "plan::deployment::control::cold_session::tests::uncaptured_control_refusal_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AOS_TEST_UNCAPTURED_CONTROL_REFUSAL", "1")
            .output()
            .unwrap();

        assert_eq!(child.status.signal(), Some(6));
        assert!(
            child.stdout.windows(b"uncaptured-control-refusals-verified".len())
                .any(|window| window == b"uncaptured-control-refusals-verified"),
            "child aborted before verifying refusals: {}",
            String::from_utf8_lossy(&child.stderr),
        );
    }

    #[test]
    fn uncaptured_control_refusal_fixture() {
        use std::io::Write as _;

        if std::env::var_os("AOS_TEST_UNCAPTURED_CONTROL_REFUSAL").is_none() {
            return;
        }

        let owner = HostControlColdSessionOwnerV1::from_original_v1(
            Arc::new(Mutex::new(HostComponentControlStartupV2::new())),
            None,
        );
        let mut access = owner.lock_original_v1().unwrap();

        for purpose in [HostControlColdSessionPurposeV1::Bootstrap,
            HostControlColdSessionPurposeV1::StopCleanup,
            HostControlColdSessionPurposeV1::NoApplyRecovery] {
            assert!(access.begin_cold_session_v1(purpose, ResourceVector::new([u64::MAX; 22])).is_err());
            assert!(access.original.cold_session_original.is_none());
            assert!(access.original.execution_receiving.is_none());
            assert!(!access.original.admitted);
            assert!(!access.original.armed);
        }

        // The nested fixed activation table is intentionally armed even before
        // capture. Verify the refusals before exercising its real Drop fence;
        // neither the test nor production may discard that resident original.
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "uncaptured-control-refusals-verified").unwrap();
        stdout.flush().unwrap();
        drop(stdout);
        drop(access);
        drop(owner);
        panic!("uncaptured native activation table unexpectedly allowed Drop");
    }

    #[test]
    fn same_purpose_data_does_not_replace_the_actual_native_retention_owner() {
        // Identity fixtures have no Source, native clock or positive disposer.
        let first = Arc::new(ColdIdentityV1 { purpose: HostControlColdSessionPurposeV1::StopCleanup });
        let second = Arc::new(ColdIdentityV1 { purpose: HostControlColdSessionPurposeV1::StopCleanup });
        let native = HostControlColdSessionNativeRetentionV1 { identity: Arc::clone(&first) };
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(Arc::strong_count(&second), 1);

        drop(native);

        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(Arc::strong_count(&second), 1);
    }
}
