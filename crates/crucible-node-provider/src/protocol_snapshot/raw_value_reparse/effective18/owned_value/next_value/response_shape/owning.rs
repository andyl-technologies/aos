//! Owns the actual ResponseShape cursor, FIRST transfers and every NEXT prefix.
//!
//! Each effect has a distinct actual quote and admission boundary. Whole-parent
//! census includes the current returned error before any dependent action.
//! This is DATA deserialization custody, not a live header/correlation grant.

use super::super::super::NativeImport18OwningEnvelopeAttemptData;
use super::*;

mod storage;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

struct BankSlot {
    custody: Option<NativeImport18FirstBankCustodyData>,
}

struct Pending {
    cut: schedule::SelectedCut,
    selection: Option<NativeImport18FirstSelectionData>,
    next: Option<NativeImport18OwningNextAttemptData>,
}

struct OwnedSource<'a> {
    envelope: &'a NativeImport18OwningEnvelopeAttemptData,
    banks: &'a [BankSlot],
}

impl Source for OwnedSource<'_> {
    fn body_name_data(&self, index: usize) -> Result<Option<&str>, ProviderError> {
        Ok(self
            .envelope
            .body_data()?
            .iter()
            .nth(index)
            .map(|(name, _)| name.as_str()))
    }

    fn value_data(
        &self,
        route: Route,
    ) -> Result<NativeImport18FirstFlatViewData<'_>, ProviderError> {
        OwnedSource::value_data(self, route)
    }
}

impl<'a> OwnedSource<'a> {
    fn value_data(
        &self,
        route: Route,
    ) -> Result<NativeImport18FirstFlatViewData<'a>, ProviderError> {
        let first = match self
            .banks
            .get(route.body)
            .and_then(|slot| slot.custody.as_ref())
        {
            Some(custody) => custody.retained_first_data()?,
            None => self
                .envelope
                .cut_first_data(EnvelopeField18Data::Body, route.body)?,
        };
        schedule::resolve_data(first.completed_data()?, route)
    }
}

/// Names the next real constructor effect, not an authorization or route grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18OwningResponseActionData {
    /// Reserves retained bank slots and selects status after actual canonical completion.
    Start,
    /// Advances the one shared exact field schedule without normalization.
    Advance,
    /// Moves the actual body FIRST into a rooted immutable-bank transfer.
    TakeFirst,
    /// Quotes its separately funded immutable allocation.
    QuoteFirst,
    /// Freezes that same FIRST into its private immutable allocation.
    FreezeFirst,
    /// Constructs the checked actual selected FIRST descendant handle.
    Select,
    /// Roots that selection in the existing owning NEXT attempt.
    TakeNext,
    /// Quotes structural prewalk before logical-spine allocation.
    PrewalkNext,
    /// Quotes the one actual next pass after its prewalk admission.
    QuoteNext,
    /// Runs the sole existing next engine after full admission.
    RunNext,
    /// Retains the complete actual output before acknowledging the pending cut.
    Commit,
}
use NativeImport18OwningResponseActionData as Action;

#[derive(Clone, Copy)]
struct Plan {
    action: Action,
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

/// Records actual current parent, input, flat histories and then-live error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18OwningResponseCensusData {
    /// Marks rooted transfer before observation.
    Pending,
    /// Counts actual capacities; no stored snapshot renews admission.
    Observed {
        /// Includes current actual external error backing.
        requested_bytes: usize,
        /// Compares with this same actual action's prospective row, when present.
        within_row: Option<bool>,
    },
    /// Records checked actual census refusal.
    Refused,
}

/// Retains a canonical-completed Envelope and the exact response cut history.
///
/// This owns no recursive ResponseBody, receipt, mutable bank recovery or Source
/// permission. Live Connection header/session/correlation checks must precede
/// body canonical routing in their eventual defining parent.
pub(crate) struct NativeImport18OwningResponseAttemptData {
    envelope: Option<NativeImport18OwningEnvelopeAttemptData>,
    banks: Vec<BankSlot>,
    history: Vec<Pending>,
    pending: Option<Pending>,
    schedule: Schedule,
    action: Option<Action>,
    row: Option<Plan>,
    quoted: bool,
    failed: bool,
    finished: bool,
    census: NativeImport18OwningResponseCensusData,
}

impl NativeImport18OwningResponseAttemptData {
    /// Names actual additional root/initializer and complete prequote controls.
    ///
    /// Original Envelope backing remains independently charged before transfer.
    pub(crate) fn take_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            storage::initializer_data(),
            storage::counter_data(),
        )
    }

    /// Roots the actual Envelope before checking canonical completion or census.
    ///
    /// # Errors
    /// Refuses reuse, absent/failed/incomplete Envelope or actual observation.
    /// All installed refusals retain the exact original input and bytes.
    pub(crate) fn take_into_data(
        input: &mut Option<NativeImport18OwningEnvelopeAttemptData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            envelope: None,
            banks: Vec::new(),
            history: Vec::new(),
            pending: None,
            schedule: Schedule::new_data(),
            action: None,
            row: None,
            quoted: false,
            failed: true,
            finished: false,
            census: NativeImport18OwningResponseCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.envelope = input.take();
        let result = (|| {
            owner
                .envelope
                .as_ref()
                .ok_or_else(invalid)?
                .completed_canonical_bytes_data()?;
            owner.action = Some(Action::Start);
            owner.failed = false;
            Ok(())
        })();
        owner.observe_data(result)
    }

    /// Quotes only the next real action from its actual rooted predecessor.
    ///
    /// Keep fixed take S admitted before quotation. Independently admit the
    /// complete returned row beside other actual parent/error owners before run.
    /// No numeric row authorizes later actions, grants or failed-error reuse.
    ///
    /// # Errors
    /// Refuses failed/finished/requoted state, actual predecessor or the bound.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.failed || self.finished || self.quoted {
            return Err(invalid());
        }
        self.row = None;
        let result = (|| {
            self.row = Some(storage::quote_data(self, maximum)?);
            self.quoted = true;
            Ok(())
        })();
        self.observe_data(result)
    }

    /// Returns this actual action and complete demand for independent admission.
    ///
    /// # Errors
    /// Refuses missing or failed quotation.
    pub(crate) fn requested_storage_data(
        &self,
    ) -> Result<(Action, (usize, usize, usize)), ProviderError> {
        if self.failed || !self.quoted {
            return Err(invalid());
        }
        let row = self.row.as_ref().ok_or_else(invalid)?;
        Ok((row.action, (row.retained, row.transient, row.scratch)))
    }

    /// Rechecks every axis before this one real effect, then whole-observes it.
    ///
    /// # Errors
    /// Refuses short row, actual schema/pass error, allocation or census. Original
    /// failures and every moved/partial child remain rooted at the exact prefix.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.failed || self.finished || !self.quoted {
            return Err(invalid());
        }
        let result = (|| {
            let row = self.row.as_ref().ok_or_else(invalid)?;
            let current = storage::quote_data(self, row.maximum)?;
            if row.action != current.action
                || row.retained < current.retained
                || row.transient < current.transient
                || row.scratch < current.scratch
            {
                return Err(exhausted());
            }
            let action = row.action;
            let maximum = row.maximum;
            self.failed = true;
            self.run_action_data(action, maximum)
        })();
        self.observe_data(result)?;
        self.quoted = false;
        self.failed = false;
        Ok(())
    }

    fn run_action_data(&mut self, action: Action, maximum: usize) -> Result<(), ProviderError> {
        match action {
            Action::Start => {
                let envelope = self.envelope.as_ref().ok_or_else(invalid)?;
                let count = envelope.body_data()?.len();
                self.banks
                    .try_reserve_exact(count)
                    .map_err(|_| exhausted())?;
                storage::observe_capacity_data(self)?;
                while self.banks.len() < count {
                    self.banks.push(BankSlot { custody: None });
                }
                self.schedule.start_data(&OwnedSource {
                    envelope,
                    banks: &self.banks,
                })?;
                self.action = Some(Action::Advance);
            }
            Action::Advance => {
                let source = OwnedSource {
                    envelope: self.envelope.as_ref().ok_or_else(invalid)?,
                    banks: &self.banks,
                };
                match self.schedule.next_data(&source)? {
                    Some(cut) => {
                        let present = self
                            .banks
                            .get(cut.route.body)
                            .ok_or_else(invalid)?
                            .custody
                            .is_some();
                        self.pending = Some(Pending {
                            cut,
                            selection: None,
                            next: None,
                        });
                        self.action = Some(if present {
                            Action::Select
                        } else {
                            Action::TakeFirst
                        });
                    }
                    None => {
                        self.finished = true;
                        self.action = None;
                    }
                }
            }
            Action::TakeFirst => {
                let body = self.pending.as_ref().ok_or_else(invalid)?.cut.route.body;
                let slot = self.banks.get_mut(body).ok_or_else(invalid)?;
                self.envelope
                    .as_mut()
                    .ok_or_else(invalid)?
                    .transfer_body_first_into_data(body, &mut slot.custody)?;
                self.action = Some(Action::QuoteFirst);
            }
            Action::QuoteFirst => {
                self.custody_mut_data()?.quote_into_data(maximum)?;
                self.action = Some(Action::FreezeFirst);
            }
            Action::FreezeFirst => {
                self.custody_mut_data()?.freeze_data()?;
                self.action = Some(Action::Select);
            }
            Action::Select => {
                let pending = self.pending.as_mut().ok_or_else(invalid)?;
                let bank = self
                    .banks
                    .get(pending.cut.route.body)
                    .and_then(|slot| slot.custody.as_ref())
                    .ok_or_else(invalid)?
                    .completed_bank_data()?;
                let row = selection_row_data(bank, pending.cut.route, maximum)?;
                NativeImport18FirstSelectionData::read_into_data(&row, &mut pending.selection)?;
                self.action = Some(Action::TakeNext);
            }
            Action::TakeNext => {
                let pending = self.pending.as_mut().ok_or_else(invalid)?;
                NativeImport18OwningNextAttemptData::take_into_data(
                    &mut pending.selection,
                    &mut pending.next,
                )?;
                self.action = Some(Action::PrewalkNext);
            }
            Action::PrewalkNext => {
                self.next_mut_data()?.prewalk_into_data(maximum)?;
                self.action = Some(Action::QuoteNext);
            }
            Action::QuoteNext => {
                self.next_mut_data()?.quote_into_data()?;
                self.action = Some(Action::RunNext);
            }
            Action::RunNext => {
                self.next_mut_data()?.run_data()?;
                self.action = Some(Action::Commit);
            }
            Action::Commit => {
                if self.schedule.pending_data()?
                    != self.pending.as_ref().ok_or_else(invalid)?.cut.route
                {
                    return Err(invalid());
                }
                self.pending
                    .as_ref()
                    .and_then(|pending| pending.next.as_ref())
                    .ok_or_else(invalid)?
                    .completed_data()?
                    .kind_data()?;
                // The exact private NEXT input came only from this pending route;
                // no caller-supplied owner or Boolean can acknowledge the cut.
                self.history.try_reserve_exact(1).map_err(|_| exhausted())?;
                storage::observe_capacity_data(self)?;
                let pending = self.pending.take().ok_or_else(invalid)?;
                self.history.push(pending);
                self.schedule.complete_data();
                self.action = Some(Action::Advance);
            }
        }
        Ok(())
    }

    fn custody_mut_data(
        &mut self,
    ) -> Result<&mut NativeImport18FirstBankCustodyData, ProviderError> {
        let body = self.pending.as_ref().ok_or_else(invalid)?.cut.route.body;
        self.banks
            .get_mut(body)
            .and_then(|slot| slot.custody.as_mut())
            .ok_or_else(invalid)
    }
    fn next_mut_data(&mut self) -> Result<&mut NativeImport18OwningNextAttemptData, ProviderError> {
        self.pending
            .as_mut()
            .and_then(|pending| pending.next.as_mut())
            .ok_or_else(invalid)
    }

    /// Borrows the actual immutable received frame after success or refusal.
    ///
    /// # Errors
    /// Refuses a transfer that never received an Envelope source.
    pub(crate) fn retained_frame_data(&self) -> Result<&RetainedFrame, ProviderError> {
        self.envelope
            .as_ref()
            .ok_or_else(invalid)?
            .retained_frame_data()
    }

    /// Lends one actual completed cut, its structural key and immutable output.
    ///
    /// No typed DTO validation or additional Value pass occurs. Callers retain
    /// this owner and independently fund the defining typed consumer's work.
    ///
    /// # Errors
    /// Refuses failed/incomplete schedules or inconsistent private projections.
    pub(crate) fn completed_cut_data(
        &self,
        index: usize,
    ) -> Result<
        Option<(
            NativeImport18ResponseValueCutLocationData,
            &str,
            NativeImport18NextValuePassViewData<'_>,
        )>,
        ProviderError,
    > {
        if self.failed || !self.finished {
            return Err(invalid());
        }
        let Some(pending) = self.history.get(index) else {
            return Ok(None);
        };
        let route = pending.cut.route;
        let (path, member) = match route.path {
            [Some(member), None] => ([None; 2], member),
            [Some(field), Some(member)] => ([Some(field), None], member),
            _ => return Err(invalid()),
        };
        let source = OwnedSource {
            envelope: self.envelope.as_ref().ok_or_else(invalid)?,
            banks: &self.banks,
        };
        let NativeImport18FirstFlatKindData::Object(mut values) = source
            .value_data(Route {
                body: route.body,
                path,
            })?
            .kind_data()?
        else {
            return Err(invalid());
        };
        let (key, _) = values.nth(member).ok_or_else(invalid)?;
        let value = pending
            .next
            .as_ref()
            .ok_or_else(invalid)?
            .completed_data()?;
        Ok(Some((pending.cut.location, key, value)))
    }

    /// Reports failed, exhausted and pending custody without renewing credit.
    pub(crate) const fn state_data(&self) -> (bool, bool, bool) {
        (self.failed, self.finished, self.pending.is_some())
    }
    /// Returns actual current output/error observation; snapshots are no grants.
    pub(crate) const fn census_data(&self) -> NativeImport18OwningResponseCensusData {
        self.census
    }
    /// Returns the actual pending structural cut location, without a source getter.
    pub(crate) fn pending_location_data(
        &self,
    ) -> Option<NativeImport18ResponseValueCutLocationData> {
        self.pending.as_ref().map(|pending| pending.cut.location)
    }
    /// Counts actual current output; callers separately count their current errors.
    ///
    /// # Errors
    /// Refuses current source/flat census, checked layout or supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        storage::retained_data(self, maximum)
    }

    fn observe_data(&mut self, result: Result<(), ProviderError>) -> Result<(), ProviderError> {
        let census = (|| {
            let bytes = storage::retained_data(self, usize::MAX)?;
            add(
                bytes,
                super::super::super::envelope_fields::error_retained_requested_data(&result)?,
            )
        })();
        self.census = match &census {
            Ok(bytes) => NativeImport18OwningResponseCensusData::Observed {
                requested_bytes: *bytes,
                within_row: self.row.as_ref().map(|row| *bytes <= row.retained),
            },
            Err(_) => NativeImport18OwningResponseCensusData::Refused,
        };
        if result.is_err() {
            self.failed = true;
            self.schedule.fail_data();
        }
        result?;
        let bytes = match census {
            Ok(bytes) => bytes,
            Err(error) => {
                self.failed = true;
                self.schedule.fail_data();
                return Err(error);
            }
        };
        if self.row.as_ref().is_some_and(|row| bytes > row.retained) {
            self.failed = true;
            self.schedule.fail_data();
            return Err(exhausted());
        }
        Ok(())
    }
}

fn selection_row_data(
    bank: &NativeImport18FirstBankData,
    route: Route,
    maximum: usize,
) -> Result<NativeImport18FirstSelectionConstructionData<'_>, ProviderError> {
    let mut value = bank.root_input_data()?.selected;
    for position in route.path.into_iter().flatten() {
        value = match value.kind_data()? {
            SourceKind::Object(mut fields) => fields
                .nth(position)
                .map(|(_, value)| value)
                .ok_or_else(invalid)?,
            SourceKind::Array(mut fields) => fields.nth(position).ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
    }
    bank.response_row_data(value, maximum)
}
