//! Shares actual SDK26/7 refusal, independent posts and physical retirement.

use super::*;
use aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1;

#[derive(Clone, Copy)]
pub(super) enum First {
    Entry,
    Sdk,
    After,
    Retirement,
    Completion,
    Catalog,
    Current,
    Acknowledgement,
    Reentry,
}

#[derive(Default)]
pub(super) struct FlightState {
    pub(super) entry: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) run: Option<Result<(), OutputPreparationClosedV1>>,
    pub(super) after: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) retirement: Option<Result<(), OutputPreparationClosedV1>>,
    pub(super) complete: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) first: Option<First>,
    pub(super) started: bool,
}

// Only the two lexical adapters over actual held Session/SDK/upper owners
// implement this interface. It accepts no callback, grant DATA or payer.
pub(super) trait ActualFlight {
    fn run(&mut self) -> Result<(), OutputPreparationClosedV1>;
    fn refuse_sdk(&mut self);
    fn after(&mut self) -> Result<(), ResourceReservationErrorV1>;
    fn retire(&mut self) -> Result<(), OutputPreparationClosedV1>;
    fn complete(&mut self) -> Result<(), ResourceReservationErrorV1>;
}

impl FlightState {
    pub(super) fn run_once(&mut self, flight: &mut impl ActualFlight) {
        self.run = Some(flight.run());
        if !matches!(self.run, Some(Ok(()))) {
            self.first.get_or_insert(First::Sdk);
            flight.refuse_sdk();
        }
        // No SDK/native refusal can bypass these independently prepaid posts.
        self.after = Some(flight.after());
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_none() {
            self.retirement = Some(flight.retire());
            if !matches!(self.retirement, Some(Ok(()))) {
                self.first = Some(First::Retirement);
            }
        }
        if self.first.is_none() {
            self.complete = Some(flight.complete());
            if !matches!(self.complete, Some(Ok(()))) {
                self.first = Some(First::Completion);
            }
        }
    }

    pub(super) fn original_selected(&self, sdk_selected: bool) -> bool {
        matches!(self.first, Some(First::Entry | First::After | First::Completion | First::Current))
            || matches!(self.first, Some(First::Sdk | First::Retirement)) && sdk_selected
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::After => self.after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Completion => self.complete.as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => None,
        }
    }
}
