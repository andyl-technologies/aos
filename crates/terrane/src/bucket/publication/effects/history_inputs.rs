//! Closes actual selected, administrative and payload read inputs together.
//!
//! The owning Guard producer must extend its genuine control receipts with all
//! late consumed Original records before invoking this physical observation.
//! This helper supplies neither semantic history completion nor current ACL
//! permission; the owning caller retains those independent checks.

use super::{BucketBinding, LocalFs, SelectedObservation, StoreFailure, contextual_frame};
use super::{corrupt, io_failure, unsupported};
use crate::bucket::held::NodeReads;
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::HistoryObservation;
use crate::selected_bridge::native_guard::GuardEffectContext;
use crate::store::{NativeOrdinaryRead, OrdinaryReadOutcome};
use terrane_core::gc::publication::evidence::{PhysicalRegistration, RequiredControlPin};

/// Retains one actual operation's successful complete physical closing check.
///
/// Only the native closing factory constructs this value. It cannot certify
/// semantic history or authorize publication; the owning Guard consumes it with
/// the same pending candidate and operation before promoting any view.
pub(crate) struct CheckedHistoryInputs<'scope, 'history, 'held> {
    observed: &'scope SelectedObservation<'held>,
    history: HistoryObservation<'history>,
    scope: &'scope dyn NodeReads,
    controls: Vec<crate::guard::RetainedControls>,
    pins: Vec<RequiredControlPin>,
    artifacts: Vec<RecordRead>,
    current: crate::selected_bridge::OwnedFinalCheck,
}

impl CheckedHistoryInputs<'_, '_, '_> {
    /// Checks the sealed reader against this actual closing operation.
    ///
    /// # Errors
    /// Refuses a substituted reader, changed actual inputs or expired requests.
    pub(crate) fn check_reader_scope(&self, scope: &dyn NodeReads) -> Result<(), StoreFailure> {
        self.check_candidate_scope(self.history, scope)
    }

    /// Checks the exact candidate operation and sealed reader before promotion.
    ///
    /// # Errors
    /// Refuses substituted observations, readers, holders or late control pins,
    /// and expired genuine current request checks.
    pub(crate) fn check_candidate_scope(
        &self,
        history: HistoryObservation<'_>,
        scope: &dyn NodeReads,
    ) -> Result<(), StoreFailure> {
        self.current.recheck()?;
        self.history.same_candidate_scope(history)?;
        if !std::ptr::addr_eq(self.scope, scope) {
            return Err(corrupt());
        }
        scope.check_holder(history.identity().ok_or_else(unsupported)?)?;
        scope.check_selection(self.observed)?;
        let pins = history.resolver().ok_or_else(unsupported)?.control_pins()?;
        if pins != self.pins {
            return Err(corrupt());
        }
        Ok(())
    }

    /// Borrows the same original payload recipes for subsequent native frames.
    pub(crate) fn artifacts(&self) -> &[RecordRead] {
        &self.artifacts
    }

    /// Borrows the actual extended controls retained by the closing worker.
    pub(crate) fn controls(&self) -> &[crate::guard::RetainedControls] {
        &self.controls
    }
}

/// Checks one complete original physical input set in the native read lane.
///
/// The actual namespace and administrative exclusions remain owned by the
/// worker through all checks, including when its waiter is canceled. Successful
/// completion reports a fresh physical observation, without a mutation ACK.
///
/// # Errors
/// Refuses missing original recipes, changed selected/control/artifact preimages,
/// expired genuine request checks, unavailable native reads or an unsupported
/// binding. A declined native lane never produces a successful closing claim.
pub(crate) async fn close_history_inputs<'scope, 'history, 'held, F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &'scope SelectedObservation<'held>,
    context: &GuardEffectContext,
    history: HistoryObservation<'history>,
    scope: &'scope dyn NodeReads,
) -> Result<CheckedHistoryInputs<'scope, 'history, 'held>, StoreFailure> {
    let current = context.final_check();
    current.recheck()?;
    history.same_candidate_scope(history)?;
    scope.check_holder(history.identity().ok_or_else(unsupported)?)?;
    scope.check_selection(observed)?;
    if observed
        .physical_reads()
        .iter()
        .any(|read| read.retained_payload().is_none())
    {
        return Err(unsupported());
    }

    let pins = history.resolver().ok_or_else(unsupported)?.control_pins()?;
    for pin in &pins {
        let PhysicalRegistration::Local(owner) = &pin.owner else {
            return Err(unsupported());
        };
        let retained = context
            .controls()
            .iter()
            .find(|retained| {
                retained.directory().as_os_str().as_encoded_bytes() == owner.control.as_slice()
            })
            .ok_or_else(unsupported)?;
        let record = retained
            .records()
            .iter()
            .find(|record| record.path() == retained.directory().join(&pin.key))
            .ok_or_else(unsupported)?;
        pin.check_record(record.bytes()).map_err(|_| corrupt())?;
    }

    let artifacts = scope.begin_closing()?;
    let (mut frame, _) = contextual_frame(fs, observed, &[], context).await?;
    for artifact in &artifacts {
        frame.retained_payload_read(artifact.retained_payload().ok_or_else(unsupported)?)?;
    }

    current.recheck()?;
    let read = NativeOrdinaryRead::for_projection(frame.read_projection()?);
    let record = fs
        .read_ordinary_record(read)
        .await
        .map_err(io_failure)?
        .ok_or_else(unsupported)?;
    current.recheck()?;

    match record.into_outcome() {
        OrdinaryReadOutcome::ProjectionChecked => {}
        OrdinaryReadOutcome::Absent
        | OrdinaryReadOutcome::Present(_, _)
        | OrdinaryReadOutcome::InvalidLayout => return Err(corrupt()),
    }

    let checked = CheckedHistoryInputs {
        observed,
        history,
        scope,
        controls: context.controls().to_vec(),
        pins,
        artifacts,
        current,
    };
    checked.check_candidate_scope(history, scope)?;
    scope.complete_closing(&checked)?;
    Ok(checked)
}
