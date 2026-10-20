//! Owns the one selected Root opening before any purpose-specific admission.
//!
//! The selected listener prepays this fixed owner before accepting its socket.
//! Classification is DATA: every closed transfer carries the whole accepted
//! stream, exclusive flight, actual native prefix and original absolute clock.
//! No prefix bytes, purpose tag or constructor supplies a Root signing grant.

mod opening_clock;

use std::error::Error as StdError;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1};
use super::create_storage_current::OriginalRootCreateStorageCurrentAttemptV1;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};

/// Classifies a successfully received fixed Root opening prefix as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPolicyPurposeV1 {
    /// Selects the existing Create Storage current protocol.
    CreateStorage,
    /// Selects the distinct Delete opening protocol.
    Delete,
    /// Selects authorized-before-Planned Transfer/Ownership comparison only.
    DeletePlanning,
    /// Selects the immutable Environment provisioning protocol.
    Environment,
    /// Selects fresh workspace Apply verification.
    Apply,
    /// Selects the distinct current Maintenance Storage31 purpose.
    MaintenanceStorage,
    /// Selects fresh Host launch verification.
    HostLaunch,
    /// Selects new authorized metadata-only Create finality reconciliation.
    FinalityRecover,
    /// Selects accepted Start current signed-input comparison only.
    StartAssignmentInputs,
    /// Selects the distinct paid Execution NoApply floor-to-ACK protocol.
    ExecutionNoApply,
    /// Selects current-capability Stop cleanup on one held exchange.
    StopCleanup,
}

/// Reports a failed Root opening while its actual native cause remains held.
#[derive(Debug, thiserror::Error)]
pub enum RootPolicyPreludeErrorV1 {
    /// The actual selected stream or retained listener is unavailable.
    #[error("original Root policy connection is unavailable")]
    Original,
    /// The original clock, fixed prefix or absolute cutoff failed.
    #[error("Root policy opening is unavailable")]
    Opening,
    /// The fixed discriminator does not name a supported versioned purpose.
    #[error("Root policy opening purpose is unavailable")]
    Purpose,
    /// The one original opening was entered again.
    #[error("Root policy opening was already entered")]
    Reentry,
}

// The first field of every whole owning transfer preserves failed native
// custody before any later field can unwind. Only Create's actual terminal
// writer-pair producer currently has a positive retirement path.
#[derive(Default)]
pub(super) struct RootPolicyDispositionGuardV1 {
    pub(super) entered: bool,
    pub(super) handed_off: bool,
}

impl Drop for RootPolicyDispositionGuardV1 {
    fn drop(&mut self) {
        if self.entered && !self.handed_off {
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Clock,
    EndpointAccess,
    Endpoint,
    WriteTimeout,
    Prefix,
    Purpose,
}

pub(super) struct RootPolicyPreludeNativeOriginalV1 {
    clock: opening_clock::RootPolicyOpeningClockV1,
    endpoint_access: Option<Result<(), NormalRootStartupErrorV1>>,
    endpoint: Option<Result<(), aos_sandbox_linux::Error>>,
    write_timeout: Option<std::io::Result<()>>,
    prefix_io: FixedDeadlineStreamIoV1<32>,
    prefix_bytes: [u8; 32],
    prefix: Option<Result<(), RootPolicyPreludeErrorV1>>,
    purpose: Option<Result<RootPolicyPurposeV1, RootPolicyPreludeErrorV1>>,
    first: Option<First>,
    entered: bool,
    closed: Option<RootPolicyPreludeErrorV1>,
}

impl Default for RootPolicyPreludeNativeOriginalV1 {
    fn default() -> Self {
        Self {
            clock: Default::default(),
            endpoint_access: None,
            endpoint: None,
            write_timeout: None,
            prefix_io: Default::default(),
            prefix_bytes: [0; 32],
            prefix: None,
            purpose: None,
            first: None,
            entered: false,
            closed: None,
        }
    }
}

impl RootPolicyPreludeNativeOriginalV1 {
    fn receive_once_v1(
        &mut self,
        original: &mut UnixStream,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootPolicyPreludeErrorV1> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(RootPolicyPreludeErrorV1::Reentry);
            return Err(RootPolicyPreludeErrorV1::Reentry);
        }
        self.entered = true;
        let result = self.receive_inner(original, flight);
        // A failed prefix still owes the independent prepaid native clock.
        // Successful purpose transfers finish it after their fixed remainder.
        if result.is_err() {
            let _owed = self.finish_opening_once_v1();
        }
        result
    }

    fn receive_inner(
        &mut self,
        original: &mut UnixStream,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootPolicyPreludeErrorV1> {
        let cutoff = self.clock.begin_once_v1().map_err(|cause| {
            self.first.get_or_insert(First::Clock);
            cause
        })?;
        match flight.current_cut_native() {
            Ok(native) => {
                self.endpoint_access = Some(Ok(()));
                self.endpoint = Some(native.require_same_endpoint_v1(original.as_fd()));
            }
            Err(cause) => {
                self.endpoint_access = Some(Err(cause));
                self.first.get_or_insert(First::EndpointAccess);
                return Err(RootPolicyPreludeErrorV1::Original);
            }
        }
        if !matches!(self.endpoint, Some(Ok(()))) {
            self.first.get_or_insert(First::Endpoint);
            return Err(RootPolicyPreludeErrorV1::Original);
        }
        // Preserve the selected Create stream's existing send-timeout setup.
        // Purpose-specific opening IO still uses the one absolute cutoff;
        // transferring this owner never installs a fresh relative deadline.
        self.write_timeout = Some(original.set_write_timeout(Some(Duration::from_secs(5))));
        if !matches!(self.write_timeout, Some(Ok(()))) {
            self.first.get_or_insert(First::WriteTimeout);
            return Err(RootPolicyPreludeErrorV1::Opening);
        }
        self.prefix = Some(
            self.prefix_io
                .run_once(
                    original,
                    &mut self.prefix_bytes,
                    cutoff,
                    DeadlineStreamDirectionV1::Read,
                )
                .map_err(|_| RootPolicyPreludeErrorV1::Opening),
        );
        if !matches!(self.prefix, Some(Ok(()))) {
            self.first.get_or_insert(First::Prefix);
            return Err(RootPolicyPreludeErrorV1::Opening);
        }
        self.purpose = Some(classify(&self.prefix_bytes));
        if !matches!(self.purpose, Some(Ok(_))) {
            self.first.get_or_insert(First::Purpose);
            return Err(RootPolicyPreludeErrorV1::Purpose);
        }
        Ok(())
    }

    pub(super) fn purpose_v1(&self) -> Option<RootPolicyPurposeV1> {
        if self.first.is_some() || self.closed.is_some() {
            return None;
        }
        self.purpose.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn prefix_bytes_v1(&self) -> &[u8; 32] {
        &self.prefix_bytes
    }

    pub(super) fn cutoff_v1(&self) -> Result<u64, RootPolicyPreludeErrorV1> {
        self.clock.cutoff_v1()
    }

    pub(super) fn finish_opening_once_v1(&mut self) -> Result<(), RootPolicyPreludeErrorV1> {
        self.clock.finish_once_v1()
    }

    // New continuations may converge their positive/negative finalizers. This
    // checks the existing original; it never rearms or clears a failed sample.
    pub(super) fn finish_opening_if_owed_v1(&mut self) -> Result<(), RootPolicyPreludeErrorV1> {
        if self.clock.is_finished_v1() {
            return Ok(());
        }
        self.finish_opening_once_v1()
    }

    pub(super) fn failure_before_v1(&self) -> Option<&(dyn StdError + 'static)> {
        let selected = match self.first {
            Some(First::Clock) => self.clock.failure(),
            Some(First::EndpointAccess) => cause(&self.endpoint_access),
            Some(First::Endpoint) => cause(&self.endpoint),
            Some(First::WriteTimeout) => cause(&self.write_timeout),
            Some(First::Prefix) => self.prefix_io.failure().or_else(|| cause(&self.prefix)),
            Some(First::Purpose) => cause(&self.purpose),
            None => None,
        };
        selected.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn failure_after_v1(&self) -> Option<&(dyn StdError + 'static)> {
        if self.clock.is_finished_v1() {
            self.clock.failure()
        } else {
            None
        }
    }
}

/// Retains the whole selected Root socket before its fixed discriminator read.
///
/// Construction performs no IO and grants no purpose admission. Only the
/// genuine selected listener supplies the exclusively borrowed accepted flight.
/// A failed or unconsumed entered owner remains resident until intentional
/// process termination; dropping it aborts before native originals can unwind.
pub struct RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    pub(super) disposition: RootPolicyDispositionGuardV1,
    pub(super) original: UnixStream,
    pub(super) flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    pub(super) native: RootPolicyPreludeNativeOriginalV1,
    negative_post: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Parks the same accepted stream and its exclusive original flight.
    #[must_use]
    pub fn new(
        original: UnixStream,
        flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    ) -> Self {
        Self {
            disposition: Default::default(),
            original,
            flight,
            native: Default::default(),
            negative_post: None,
        }
    }

    pub(crate) fn opening_clock_demand_v1() -> aos_sandbox_model::ResourceVector {
        opening_clock::RootPolicyOpeningClockV1::fixed_demand_v1()
    }

    /// Transfers the whole accepted Apply socket to its distinct fresh owner.
    ///
    /// # Errors
    /// Returns the unchanged whole original if its actual fixed prefix does
    /// not name Apply. No native stream can be supplied through this method.
    pub fn into_storage_apply_v1(
        self,
    ) -> Result<
        super::storage_apply_root::RootStorageApplyReceivingV1<'flight, 'listener, 'startup>,
        Self,
    > {
        self.into_apply_v1()
            .map(super::storage_apply_root::RootStorageApplyReceivingV1::from_prelude_v1)
    }

    /// Receives the fixed 32-byte prefix under one original absolute cutoff.
    ///
    /// # Errors
    /// Retains the first native clock, endpoint, partial IO or purpose error.
    /// The independently prepaid opening-clock post runs on every refusal.
    pub fn receive_prefix_once_v1(&mut self) -> Result<(), RootPolicyPreludeErrorV1> {
        self.disposition.entered = true;
        let result = self.native.receive_once_v1(&mut self.original, self.flight);
        if result.is_err() && !self.native.clock.is_finished_v1() {
            let _owed = self.native.finish_opening_once_v1();
        }
        result
    }

    /// Borrows purpose DATA only after the complete original prefix succeeds.
    #[must_use]
    pub fn purpose_v1(&self) -> Option<RootPolicyPurposeV1> {
        if self.negative_post.is_some() || self.native.clock.is_finished_v1() {
            return None;
        }
        self.native.purpose_v1()
    }

    /// Moves the complete original opening into the existing Create receiver.
    ///
    /// # Errors
    /// Returns this whole resident owner when the prefix did not select Create.
    /// No failed native field or socket is dropped by a rejected transfer.
    pub fn into_create_v1(
        self,
    ) -> Result<OriginalRootCreateStorageCurrentAttemptV1<'flight, 'listener, 'startup>, Self> {
        if self.purpose_v1() != Some(RootPolicyPurposeV1::CreateStorage) {
            return Err(self);
        }
        Ok(OriginalRootCreateStorageCurrentAttemptV1::from_prelude_v1(
            self,
        ))
    }

    pub(crate) fn into_delete_v1(
        self,
    ) -> Result<super::delete_root::RootDeletePendingReceivingV1<'flight, 'listener, 'startup>, Self>
    {
        if self.purpose_v1() != Some(RootPolicyPurposeV1::Delete) {
            return Err(self);
        }
        Ok(super::delete_root::RootDeletePendingReceivingV1::from_prelude_v1(self))
    }

    /// Runs the genuine Delete sequence through terminal evidence and Root disposal.
    ///
    /// This retains the same original stream and current policy owner through
    /// all native readers, exact final response and independently owed posts.
    /// Only the actual completed graph reaches positive financial disposal;
    /// the listener's prepaid connection remains alive until that boundary.
    ///
    /// # Errors
    /// Retains the whole offered Delete prefix on native, financial, policy,
    /// terminal evidence, response, peer or disposal refusal.
    pub fn serve_delete_once_v4(
        self,
        policy: &super::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = match self.into_delete_v1() {
            Ok(receiving) => receiving,
            Err(mut original) => {
                let _owed = original.finish_negative_once_v1();
                return Err(NormalRootStartupErrorV1::Service);
            }
        };
        let _primary = (|| {
            receiving.receive_opening_once_v1()?;
            receiving.receive_canonical_batch_once_v1()?;
            receiving.verify_controller_current_once_v1()?;
            receiving.verify_authorization_once_v2()?;
            receiving.capture_broker_trust_once_v2()?;
            receiving.verify_initial_sessions_once_v2()?;
            receiving.verify_source_current_once_v1()?;
            receiving.compare_saved_floor_once_v1()?;
            receiving.begin_transfer_namespace_once_v1()?;
            receiving.verify_cache_current_once_v2()?;
            receiving.verify_initial_inventory_once_v2()?;
            receiving.verify_post_ack_inventory_once_v2(policy)
        })();
        receiving.finish_positive_once_v4()
    }

    /// Completes the authorized pre-Planned namespace comparison purpose.
    ///
    /// Consumes the same accepted socket, original opening deadline and native
    /// owners. A positive return disposes only this comparison flight; it does
    /// not accept Delete or install a pending, floor or six-owner proof.
    ///
    /// # Errors
    /// Retains the original opening, native comparison, response or independent
    /// post failure in the same owning accepted flight before returning.
    pub fn serve_delete_planning_once_v1(self) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = match self.into_delete_planning_v1() {
            Ok(receiving) => receiving,
            Err(mut original) => {
                let _owed = original.finish_negative_once_v1();
                return Err(NormalRootStartupErrorV1::Service);
            }
        };
        if receiving.receive_opening_once_v1().is_ok() {
            let _primary = receiving.compare_originals_once_v1();
        }
        // The consuming finisher parks the whole owner before any projection,
        // and posts/ends the same flight even after an unsuccessful body.
        receiving.finish_once_v1()
    }

    // This closed transfer retains the SAME whole Prelude and absolute
    // opening clock; it cannot adopt pending bytes or create a new flight.
    pub(crate) fn into_delete_planning_v1(
        self,
    ) -> Result<super::delete_root::RootDeletePlanningReceivingV1<'flight, 'listener, 'startup>, Self>
    {
        if self.purpose_v1() != Some(RootPolicyPurposeV1::DeletePlanning) {
            return Err(self);
        }
        Ok(super::delete_root::RootDeletePlanningReceivingV1::from_prelude_v1(self))
    }

    /// Ends only a rejected opening while retaining every native original.
    ///
    /// # Errors
    /// Retains repeated negative disposition or the actual same-socket shutdown
    /// and independent Root/financial post failure. This never rearms a flight.
    pub fn finish_negative_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.negative_post.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        if self.native.entered && !self.native.clock.is_finished_v1() {
            let _owed = self.native.finish_opening_once_v1();
        }
        self.negative_post = Some(
            self.flight
                .finish_dispatch_once(Err(Box::new(RootPolicyPreludeErrorV1::Opening))),
        );
        self.negative_post
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|_| ())
            .ok_or(NormalRootStartupErrorV1::Service)
    }

    pub(super) fn negative_disposition_entered_v1(&self) -> bool {
        self.negative_post.is_some()
    }

    /// Borrows the first original error without observation or retry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.native
            .failure_before_v1()
            .or_else(|| self.native.failure_after_v1())
            .or_else(|| cause(&self.negative_post))
            .or_else(|| self.flight.failure())
    }
}

// Each wrapper owns the whole original, including its armed first-field guard.
// Its private field cannot be populated from purpose bytes or an arbitrary FD.
macro_rules! purpose_transfer {
    ($owner:ident, $method:ident, $purpose:ident) => {
        pub(crate) struct $owner<'flight, 'listener, 'startup> {
            pub(super) original: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>,
        }

        impl<'flight, 'listener, 'startup>
            RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>
        {
            pub(crate) fn $method(self) -> Result<$owner<'flight, 'listener, 'startup>, Self> {
                if self.purpose_v1() != Some(RootPolicyPurposeV1::$purpose) {
                    return Err(self);
                }
                Ok($owner { original: self })
            }
        }
    };
}

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Moves the whole native opening to the fixed Environment receiver.
    ///
    /// # Errors
    /// Returns this whole owner when the actual prefix selected another purpose.
    pub fn into_environment_v1(
        self,
    ) -> Result<super::RootEnvironmentPolicyAttemptV1<'flight, 'listener, 'startup>, Self> {
        if self.purpose_v1() != Some(RootPolicyPurposeV1::Environment) {
            return Err(self);
        }
        Ok(super::RootEnvironmentPolicyAttemptV1::from_prelude_v1(self))
    }
}
purpose_transfer!(
    RootExecutionNoApplyPreludeV2,
    into_execution_no_apply_v2,
    ExecutionNoApply
);

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Serves the actual Execution floor-to-ACK and post-disposal confirmation.
    ///
    /// # Errors
    /// Retains the actual failed native graph and all independently owed posts.
    /// Only a completed native ACK and genuine financial disposal can send the
    /// private final confirmation; a failed body cannot grant completion.
    pub fn serve_execution_no_apply_once_v2(
        self,
        policy: &super::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let prelude = match self.into_execution_no_apply_v2() {
            Ok(prelude) => prelude,
            Err(mut original) => {
                let _owed = original.finish_negative_once_v1();
                return Err(NormalRootStartupErrorV1::Service);
            }
        };
        super::execution_no_apply_root::transport::RootExecutionNoApplyReceivingV2::from_prelude_v2(
            prelude,
        )
        .serve_once_v2(policy)
    }
}

purpose_transfer!(RootApplyPreludeV1, into_apply_v1, Apply);
purpose_transfer!(RootStopCleanupPreludeV1, into_stop_cleanup_v1, StopCleanup);

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Serves Stop verification, its real final inventory and causal disposal.
    ///
    /// # Errors
    /// Retains the failed whole graph and runs independently owed posts. Only
    /// actual native completion and genuine financial disposal unlock Root48.
    pub fn serve_stop_cleanup_once_v1(
        self,
        policy: &super::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let prelude = match self.into_stop_cleanup_v1() {
            Ok(prelude) => prelude,
            Err(mut original) => {
                let _owed = original.finish_negative_once_v1();
                return Err(NormalRootStartupErrorV1::Service);
            }
        };
        super::stop_cleanup_root::transport::RootStopCleanupReceivingV1::from_prelude(prelude)
            .serve_once_v1(policy)
    }
}
purpose_transfer!(RootHostLaunchPreludeV1, into_host_launch_v1, HostLaunch);
purpose_transfer!(
    RootMaintenanceStoragePreludeV3,
    into_maintenance_storage_v3,
    MaintenanceStorage
);
purpose_transfer!(
    RootFinalityRecoverPreludeV1,
    into_finality_recover_v1,
    FinalityRecover
);
purpose_transfer!(
    RootStartAssignmentInputsPreludeV2,
    into_start_assignment_inputs_v2,
    StartAssignmentInputs
);

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Transfers the complete actual opening to the metadata-only Recover handler.
    ///
    /// # Errors
    /// Returns this whole owner when its real prefix selected another purpose.
    pub fn into_finality_recover_receiving_v1(
        self,
    ) -> Result<super::RootFinalityRecoverReceivingV1<'flight, 'listener, 'startup>, Self> {
        self.into_finality_recover_v1()
            .map(super::RootFinalityRecoverReceivingV1::from_prelude_v1)
    }
}

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Transfers the whole actual opening to the read-only Start input receiver.
    ///
    /// # Errors
    /// Returns this whole original when its prefix names another purpose.
    pub fn into_start_assignment_inputs_receiving_v2(
        self,
    ) -> Result<super::RootStartAssignmentInputsReceivingV2<'flight, 'listener, 'startup>, Self>
    {
        self.into_start_assignment_inputs_v2()
            .map(super::RootStartAssignmentInputsReceivingV2::from_prelude_v2)
    }
}

fn classify(prefix: &[u8; 32]) -> Result<RootPolicyPurposeV1, RootPolicyPreludeErrorV1> {
    match &prefix[..8] {
        b"AOSXPQ01" => Ok(RootPolicyPurposeV1::CreateStorage),
        b"AOSDRQ02" => Ok(RootPolicyPurposeV1::Delete),
        b"AOSDRP03" => Ok(RootPolicyPurposeV1::DeletePlanning),
        b"AOSENQ02" | b"AOSANQ02" => Ok(RootPolicyPurposeV1::ExecutionNoApply),
        b"AOSHSQ02" => Ok(RootPolicyPurposeV1::StopCleanup),
        b"AOSENQ01" => Ok(RootPolicyPurposeV1::Environment),
        b"AOSAPQ01" => Ok(RootPolicyPurposeV1::Apply),
        b"AOSHLQ01" => Ok(RootPolicyPurposeV1::HostLaunch),
        b"AOSMSQ02" => Ok(RootPolicyPurposeV1::MaintenanceStorage),
        b"AOSFRQ01" => Ok(RootPolicyPurposeV1::FinalityRecover),
        b"AOSSIQ02" => Ok(RootPolicyPurposeV1::StartAssignmentInputs),
        _ => Err(RootPolicyPreludeErrorV1::Purpose),
    }
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn pending_delete_requires_the_explicit_authorization_bearing_version() {
        let mut prefix = [0; 32];
        prefix[..8].copy_from_slice(b"AOSDRQ01");
        assert!(classify(&prefix).is_err());
        prefix[..8].copy_from_slice(b"AOSDRQ02");
        assert_eq!(classify(&prefix).unwrap(), RootPolicyPurposeV1::Delete);
    }

    #[test]
    fn planning_requires_the_explicit_funding_bearing_version() {
        let mut prefix = [0; 32];
        prefix[..8].copy_from_slice(b"AOSDRP01");
        assert!(classify(&prefix).is_err());
        prefix[..8].copy_from_slice(b"AOSDRP02");
        assert!(classify(&prefix).is_err());
        prefix[..8].copy_from_slice(b"AOSDRP03");
        assert_eq!(
            classify(&prefix).unwrap(),
            RootPolicyPurposeV1::DeletePlanning
        );
    }

    #[test]
    fn fixed_remainder_keeps_the_actual_partial_native_cause_and_same_prefix() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut sent = [0u8; 32];
        sent[..8].copy_from_slice(b"AOSXPQ01");
        sender.write_all(&sent).unwrap();
        sender.write_all(b"partial").unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        let mut prefix = [0; 32];
        let mut prefix_io = FixedDeadlineStreamIoV1::<32>::default();
        prefix_io
            .run_once(
                &mut receiver,
                &mut prefix,
                u64::MAX,
                DeadlineStreamDirectionV1::Read,
            )
            .unwrap();
        assert_eq!(
            classify(&prefix).unwrap(),
            RootPolicyPurposeV1::CreateStorage
        );

        let mut remainder = [0; 80];
        let mut remainder_io = FixedDeadlineStreamIoV1::<80>::default();
        assert!(
            remainder_io
                .run_once(
                    &mut receiver,
                    &mut remainder,
                    u64::MAX,
                    DeadlineStreamDirectionV1::Read
                )
                .is_err()
        );
        let first = remainder_io.failure().unwrap() as *const dyn StdError as *const ();
        assert_eq!(&remainder[..7], b"partial");
        assert_eq!(prefix, sent);
        assert!(!remainder_io.completed_exact());

        assert!(
            remainder_io
                .run_once(
                    &mut receiver,
                    &mut remainder,
                    u64::MAX,
                    DeadlineStreamDirectionV1::Read
                )
                .is_err()
        );
        assert_eq!(
            first,
            remainder_io.failure().unwrap() as *const dyn StdError as *const ()
        );
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(receiver.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn expired_original_cutoff_leaves_queued_remainder_unconsumed() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"still queued").unwrap();
        let mut original = FixedDeadlineStreamIoV1::<12>::default();
        let mut bytes = [0; 12];

        assert!(
            original
                .run_once(
                    &mut receiver,
                    &mut bytes,
                    0,
                    DeadlineStreamDirectionV1::Read
                )
                .is_err()
        );

        assert!(original.failure().is_some());
        assert_eq!(bytes, [0; 12]);
        receiver.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"still queued");
    }
}

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Moves the whole native Host-purpose opening to the Network resource server.
    ///
    /// # Errors
    /// Returns this same whole owner if the authenticated opening chose another purpose.
    pub fn into_start_resource_receiving_v2(
        self,
    ) -> Result<
        super::host_launch_root::RootStartResourceReceivingV2<'flight, 'listener, 'startup>,
        Self,
    > {
        self.into_host_launch_v1()
            .map(super::host_launch_root::RootStartResourceReceivingV2::from_prelude_v2)
    }
}

impl<'flight, 'listener, 'startup> RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup> {
    /// Transfers the whole actual opening into the distinct Maintenance receiver.
    ///
    /// # Errors
    /// Returns the same held owner if its real prefix selected another purpose.
    pub fn into_maintenance_storage_receiving_v3(
        self,
    ) -> Result<super::RootMaintenanceStorageReceivingV3<'flight, 'listener, 'startup>, Self> {
        self.into_maintenance_storage_v3()
            .map(super::RootMaintenanceStorageReceivingV3::from_prelude_v3)
    }
}
