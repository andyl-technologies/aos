//! Lends only the genuine inherited Root input to Source's closed receiver.
//!
//! The same Source original remains the sole ledger spender. This private loan
//! cannot be built from a File, tuple, resource vector or request challenge.

use std::error::Error;
use std::fs::File;
use std::os::fd::OwnedFd;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::PidFdInfo;

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1;
use crate::signer::SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1;
use super::currentness::SourceCurrentnessSampleV1;
use super::{CLOSED, SourceReceivingClosedV1, SourceSignerServiceOriginalV1};
use aos_sandbox_broker::receiving::RootProfileOriginalCaptureV1 as RootProfileOriginalReceivingV1;
use crate::signer::root_observation::SourceRootPeerInputsV1;

#[derive(Default)]
pub(super) struct SourceRootInputsReceivingV1 {
    entered: bool,
    resident: Option<Result<ResourceVector, AccountingError>>,
    samples_physical: Option<Result<(), AccountingError>>,
    fixed_physical: Option<Result<(), AccountingError>>,
    selected_physical: Option<Result<(), AccountingError>>,
    samples: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    selected: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed_result: Option<Result<(), SourceReceivingClosedV1>>,
    selected_result: Option<Result<(), SourceReceivingClosedV1>>,
    before: SourceCurrentnessSampleV1,
    before_result: Option<Result<(), SourceReceivingClosedV1>>,
    after: SourceCurrentnessSampleV1,
    after_result: Option<Result<(), SourceReceivingClosedV1>>,
    input_result: Option<Result<(), SourceReceivingClosedV1>>,
    closed: Option<SourceReceivingClosedV1>,
}

pub(crate) struct SourceRootPeerInputsLoanV1<'source> {
    original: &'source mut Option<File>,
    ledger: &'source mut dyn RepresentationDemandDebitV1,
    stages: &'source mut SourceRootInputsReceivingV1,
    identity: PidFdInfo,
    resident_files: u64,
    permanent_files: u64,
}

impl SourceRootPeerInputsLoanV1<'_> {
    fn physical_shape(&self, additional: ResourceVector) -> Result<(), AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::OpenFiles };
        let samples = self.stages.samples.as_ref().and_then(|result| result.as_ref().ok())
            .map_or(0, |demand| demand.get(D::OpenFiles));
        let fixed = if matches!(self.stages.fixed_result, Some(Ok(()))) {
            self.stages.fixed.as_ref().and_then(|result| result.as_ref().ok())
                .map_or(0, |demand| demand.get(D::OpenFiles))
        } else { 0 };
        let attempted = self.resident_files.checked_add(samples)
            .and_then(|files| files.checked_add(fixed))
            .and_then(|files| files.checked_add(additional.get(D::OpenFiles))).ok_or(overflow)?;
        super::require_descriptor_shape(attempted, self.permanent_files)
    }

    pub(crate) fn reserve_profile_once(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.stages.fixed.is_some() { return Err(CLOSED); }
        self.stages.fixed = Some(SourceRootPeerInputsV1::profile_demand());
        let demand = self.stages.fixed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        self.stages.fixed_physical = Some(self.physical_shape(demand));
        if !matches!(self.stages.fixed_physical, Some(Ok(()))) { return Err(CLOSED); }
        // The Original checked its actual complete F3 and fixed hard limit
        // immediately before lending these same ledger/profile fields.
        self.stages.fixed_result = Some(self.ledger.reserve(demand.with(D::OpenFiles, 0))
            .map_err(|_| CLOSED));
        if matches!(self.stages.fixed_result, Some(Ok(()))) { Ok(()) } else { Err(CLOSED) }
    }

    pub(crate) fn move_profile_into(
        &mut self,
        destination: &mut RootProfileOriginalReceivingV1,
    ) -> Result<(), SourceReceivingClosedV1> {
        if !matches!(self.stages.fixed_result, Some(Ok(()))) || self.original.is_none() {
            return Err(CLOSED);
        }
        // Infallibly move the original, without opening a replacement name.
        // The shared receiver parks it before any measurement or JSON decode.
        let mut original = self.original.take().map(OwnedFd::from);
        let outcome = destination.receive_original_once(&mut original);
        if let Some(file) = original { *self.original = Some(File::from(file)); }
        outcome.map_err(|_| CLOSED)
    }

    pub(crate) fn require_source_identity(&self, identities: &[u32; 4]) -> Result<(), SourceReceivingClosedV1> {
        let credentials = self.identity.credentials().ok_or(CLOSED)?;
        let source = identities[3];
        if source == 0 || identities[0] == source
            || credentials.real_user_id() != source
            || credentials.effective_user_id() != source
            || credentials.saved_user_id() != source
            || credentials.filesystem_user_id() != source
            || rustix::process::getuid().as_raw() != source
            || rustix::process::geteuid().as_raw() != source
        {
            return Err(CLOSED);
        }
        // Root's shared profile contains Source UID, not an independent Source
        // GID pin. The actual fixed Source unit/initial process owns that GID.
        Ok(())
    }

    pub(crate) fn reserve_selected_once(
        &mut self,
        inputs: &SourceRootPeerInputsV1,
    ) -> Result<(), SourceReceivingClosedV1> {
        if !matches!(self.stages.fixed_result, Some(Ok(()))) || self.stages.selected.is_some() {
            return Err(CLOSED);
        }
        self.stages.selected = Some(inputs.selected_demand());
        let demand = self.stages.selected.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        self.stages.selected_physical = Some(self.physical_shape(demand));
        if !matches!(self.stages.selected_physical, Some(Ok(()))) { return Err(CLOSED); }
        self.stages.selected_result = Some(self.ledger.reserve(demand.with(D::OpenFiles, 0))
            .map_err(|_| CLOSED));
        if matches!(self.stages.selected_result, Some(Ok(()))) { Ok(()) } else { Err(CLOSED) }
    }
}

impl SourceSignerServiceOriginalV1 {
    /// Captures the same image-delivered Root inputs after the private key pins.
    ///
    /// This accepts no pathname, profile, descriptor, tuple or caller budget.
    /// All native, schema and live-policy owners remain on this same original.
    ///
    /// # Errors
    /// Retains first accounting, input, process or containment failure. Reentry
    /// cannot replace an original or recover a previously refused prefix.
    pub fn prepare_source_readonly_peer_inputs_once_v1(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.require_permanent_fd_coverage_v1().is_err()
            || !self.credential_receiving.complete() || self.root_inputs_receiving.entered
        {
            self.root_inputs_receiving.closed.get_or_insert(CLOSED);
            return Err(self.fail(super::Failure::RootInputs));
        }
        self.root_inputs_receiving.entered = true;
        // The two whole process samples have dynamic buffers beyond Source's
        // fixed representation. Price both before entering the first one.
        self.root_inputs_receiving.samples = Some(SourceCurrentnessSampleV1::dynamic_demand()
            .and_then(|sample| sample.checked_add(sample))
            .map_err(ResourceReservationErrorV1::from));
        let samples = match self.root_inputs_receiving.samples.as_ref()
            .and_then(|result| result.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => return Err(self.fail(super::Failure::RootInputs)),
        };
        let permanent_files = self.common.permanent_open_files()?;
        self.root_inputs_receiving.resident = Some(self.common.fixed_startup_demand().and_then(|native| {
            native.checked_add(self.credential_receiving.physical_demand()
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?)
        }));
        let resident = match self.root_inputs_receiving.resident.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(self.fail(super::Failure::RootInputs)),
        };
        self.root_inputs_receiving.samples_physical = Some(resident.checked_add(samples)
            .and_then(|total| super::require_descriptor_shape(total.get(D::OpenFiles), permanent_files)));
        if !matches!(self.root_inputs_receiving.samples_physical, Some(Ok(()))) {
            return Err(self.fail(super::Failure::RootInputs));
        }
        if self.common.representation.as_mut().ok_or(CLOSED)?.reserve(samples.with(D::OpenFiles, 0)).is_err() {
            return Err(self.fail(super::Failure::Accounting));
        }
        let anchor = self.common.cgroup.as_ref().ok_or(CLOSED)?;
        let identity = self.common.membership.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        let startup = self.common.process_before.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        self.root_inputs_receiving.before_result = Some(self.root_inputs_receiving.before.observe_once(
            &mut self.common.process, anchor, &self.common.limits, identity, startup,
        ));
        if !matches!(self.root_inputs_receiving.before_result, Some(Ok(()))) {
            self.first.get_or_insert(super::Failure::RootInputs);
        } else {
            let mut loan = SourceRootPeerInputsLoanV1 {
                original: &mut self.common.root_profile,
                ledger: self.common.representation.as_mut().ok_or(CLOSED)?,
                stages: &mut self.root_inputs_receiving,
                identity, resident_files: resident.get(D::OpenFiles), permanent_files,
            };
            let returned = self.root_inputs.receive_once(&mut loan);
            self.root_inputs_receiving.input_result = Some(returned);
            if !matches!(self.root_inputs_receiving.input_result, Some(Ok(()))) {
                self.first.get_or_insert(super::Failure::RootInputs);
            }
        }
        // Independent posts run after either reached SourceBefore/input outcome;
        // a refused before-sample never moves or observes the Root inputs.
        self.root_inputs_receiving.after_result = Some(self.root_inputs_receiving.after.observe_once(
            &mut self.common.process, anchor, &self.common.limits, identity, startup,
        ));
        if !matches!(self.root_inputs_receiving.after_result, Some(Ok(()))) {
            self.fail(super::Failure::RootInputs);
        }
        if self.first.is_some() { Err(CLOSED) } else { Ok(()) }
    }
}

impl SourceRootInputsReceivingV1 {
    pub(super) fn physical_demand(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let mut demand = ResourceVector::ZERO;
        for stored in [&self.samples, &self.fixed, &self.selected] {
            demand = demand.checked_add(stored.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?)?;
        }
        Ok(demand)
    }

    pub(super) fn debit_refused(&self) -> bool {
        matches!(self.fixed_result, Some(Err(_))) || matches!(self.selected_result, Some(Err(_)))
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.samples).or_else(|| failure(&self.resident))
            .or_else(|| failure(&self.samples_physical)).or_else(|| self.before.failure())
            .or_else(|| failure(&self.before_result)).or_else(|| failure(&self.fixed))
            .or_else(|| failure(&self.fixed_physical)).or_else(|| failure(&self.selected))
            .or_else(|| failure(&self.selected_physical))
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.after.failure().or_else(|| failure(&self.after_result))
            .or_else(|| failure(&self.input_result))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
