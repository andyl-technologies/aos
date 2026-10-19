//! Selects actual ResponseShape second-pass fields after the body JCS precheck.
//!
//! This borrowed DATA cursor is an upcoming typed receiver dependency, not a
//! ResponseShape owner or validation/native grant. Every yielded Value cut must
//! finish through the actual next-pass owner before the cursor can advance.
//! Callers retain those actual owners, failed prefixes, rows and observations.

use super::*;
use crate::bodies::{EffectCertainty, OperationState};

pub(in super::super) mod canonical;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Accepted,
    Completed,
    Error,
}

/// Names the actual structural Value field being normalized once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18ResponseValueCutLocationData {
    /// Selects one result-map member in final preceding BTreeMap order.
    Result(usize),
    /// Selects one ErrorRecord.details member in that same map order.
    ErrorDetail(usize),
    /// Selects one common response Extensions member in that same map order.
    Extension(usize),
}

/// Borrows an actual selected first-to-second ResponseShape field cut.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18ResponseValueCutData<'a> {
    location: NativeImport18ResponseValueCutLocationData,
    input: NativeImport18NextValueInputData<'a>,
}

impl<'a> NativeImport18ResponseValueCutData<'a> {
    /// Returns the actual structural member location.
    pub(crate) const fn location_data(self) -> NativeImport18ResponseValueCutLocationData {
        self.location
    }

    /// Quotes this exact selected node's separate borrowed prewalk workspace.
    ///
    /// # Errors
    /// Refuses changed actual banks, overflow or the unchanged supplied maximum.
    pub(crate) fn prewalk_data(
        self,
        maximum: usize,
    ) -> Result<NativeImport18NextValuePrewalkData<'a>, ProviderError> {
        NativeImport18NextValuePrewalkData::quote_data(self.input, maximum)
    }

    /// Quotes the actual next pass after independent prewalk admission.
    ///
    /// # Errors
    /// Refuses foreign prewalk rows, changed node/banks, storage or layout.
    pub(crate) fn quote_data(
        self,
        prewalk: &NativeImport18NextValuePrewalkData<'a>,
        maximum: usize,
    ) -> Result<NativeImport18NextValuePassConstructionData<'a>, ProviderError> {
        NativeImport18NextValuePassConstructionData::quote_data(self.input, prewalk, maximum)
    }

    /// Runs this one actual cut after independent complete R/T/S admission.
    ///
    /// # Errors
    /// Retains spent output, actual flat failures and census on any refusal.
    pub(crate) fn read_into_data(
        self,
        row: &NativeImport18NextValuePassConstructionData<'a>,
        output: &mut Option<NativeImport18NextValuePassAttemptData<'a>>,
    ) -> Result<(), ProviderError> {
        NativeImport18NextValuePassAttemptData::read_into_data(self.input, row, output)
    }

    /// Borrows the same actual completed cut result without another pass.
    ///
    /// # Errors
    /// Refuses a foreign, failed or incomplete next-pass owner.
    pub(crate) fn completed_data(
        self,
        owner: &'a NativeImport18NextValuePassAttemptData<'a>,
    ) -> Result<NativeImport18NextValuePassViewData<'a>, ProviderError> {
        owner.completed_data(self.input)
    }
}

/// Quotes the actual borrowed cursor and scalar JCS precheck controls.
///
/// Its real raw and completed Envelope loans persist even for an empty body,
/// preventing same-slot replacement between quotation and cursor construction.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18ResponseShapeCutsPreludeData<'a> {
    raw: &'a RetainedFrame,
    envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl<'a> NativeImport18ResponseShapeCutsPreludeData<'a> {
    /// Quotes fixed borrowed constructors without traversing or normalizing.
    ///
    /// Admit counter_scratch_data before quotation, then independently admit
    /// this returned T/S beside all actual prior owners before read_into_data.
    /// This is no future whole-owner admission or scalar cap donation.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete envelope/body loan, checked size or bound.
    pub(crate) fn quote_data(
        raw: &'a RetainedFrame,
        envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        envelope.body_data(raw)?;
        let retained = size_of::<Option<NativeImport18ResponseShapeCutsData<'static>>>();
        let initializer = sum(&[
            size_of::<NativeImport18ResponseShapeCutsData<'static>>(),
            size_of::<Option<NativeImport18ResponseShapeCutsData<'static>>>(),
        ])?;
        let group = size_of::<Group<'static>>() + size_of::<Option<Group<'static>>>();
        let error = size_of::<ErrorFields<'static>>() + size_of::<Option<ErrorFields<'static>>>();
        let pending = size_of::<NativeImport18ResponseValueCutData<'static>>()
            + size_of::<Option<NativeImport18ResponseValueCutData<'static>>>();
        let transient = initializer
            .max(group)
            .max(error)
            .max(pending)
            .max(canonical::transient_data()?);
        let scratch = Self::counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            raw,
            envelope,
            maximum,
            retained,
            transient,
            scratch,
        })
    }

    /// Returns the independently admitted borrowed prelude axes.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual cursor, canonical64, direct-schema and borrow controls.
    pub(crate) fn counter_scratch_data() -> usize {
        type CutResult = Result<Option<NativeImport18ResponseValueCutData<'static>>, ProviderError>;
        type ErrorFieldResult = Result<
            Option<(&'static str, NativeImport18OwnedValuePassViewData<'static>)>,
            ProviderError,
        >;

        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 2
            + size_of::<NativeImport18ResponseShapeCutsData<'static>>()
            + size_of::<Option<NativeImport18ResponseShapeCutsData<'static>>>()
            + size_of::<&mut Option<NativeImport18ResponseShapeCutsData<'static>>>()
            + size_of::<&mut NativeImport18ResponseShapeCutsData<'static>>()
            + size_of::<NativeImport18ResponseValueCutData<'static>>() * 2
            + size_of::<Option<NativeImport18ResponseValueCutData<'static>>>()
            + size_of::<CutResult>()
            + size_of::<NativeImport18ResponseValueCutLocationData>()
            + size_of::<Option<Status>>()
            + size_of::<Status>()
            + size_of::<GroupKind>()
            + size_of::<(bool, bool, bool)>()
            + size_of::<Group<'static>>()
            + size_of::<Option<Group<'static>>>()
            + size_of::<&mut Group<'static>>()
            + size_of::<ErrorFields<'static>>()
            + size_of::<Option<ErrorFields<'static>>>()
            + size_of::<&mut ErrorFields<'static>>()
            + size_of::<ErrorIter<'static>>()
            + size_of::<Result<ErrorFields<'static>, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassViewData<'static>>() * 2
            + size_of::<NativeImport18OwnedValuePassKindData<'static>>()
            + size_of::<Result<NativeImport18OwnedValuePassKindData<'static>, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassObjectData<'static>>()
            + size_of::<NativeImport18OwnedValuePassArrayData<'static>>()
            + size_of::<Option<(&str, NativeImport18OwnedValuePassViewData<'static>)>>()
            + size_of::<Option<(usize, NativeImport18OwnedValuePassViewData<'static>)>>()
            + size_of::<std::iter::Enumerate<NativeImport18OwnedValuePassArrayData<'static>>>()
            + size_of::<std::iter::Enumerate<NativeImport18OwnedValuePassObjectData<'static>>>()
            + size_of::<std::iter::Enumerate<serde_json::map::Iter<'static>>>()
            + size_of::<Option<std::iter::Enumerate<serde_json::map::Iter<'static>>>>()
            + size_of::<ErrorFieldResult>()
            + size_of::<OperationState>()
            + size_of::<EffectCertainty>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<&RetainedFrame>() * 3
            + size_of::<&NativeImport18EnvelopeFieldsAttemptData<'static>>() * 3
            + size_of::<&NativeImport18NextValuePassAttemptData<'static>>()
            + size_of::<&serde_json::Map<String, Value>>()
            + size_of::<Result<&serde_json::Map<String, Value>, ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<&Value>()
            + size_of::<&str>() * 3
            + size_of::<usize>() * 10
            + size_of::<u8>() * 3
            + size_of::<[bool; 5]>()
            + size_of::<bool>() * 3
            + canonical::counter_scratch_data()
            + input::counter_scratch_data()
            + super::super::view::counter_scratch_data()
    }
}

#[derive(Clone, Copy)]
enum GroupKind {
    Result,
    ErrorDetail,
    Extension,
}

struct Group<'a> {
    kind: GroupKind,
    values: std::iter::Enumerate<NativeImport18OwnedValuePassObjectData<'a>>,
}

enum ErrorIter<'a> {
    Map(NativeImport18OwnedValuePassObjectData<'a>),
    Sequence(std::iter::Enumerate<NativeImport18OwnedValuePassArrayData<'a>>),
}
struct ErrorFields<'a> {
    fields: ErrorIter<'a>,
    present: [bool; 5],
}

impl<'a> ErrorFields<'a> {
    fn new_data(value: NativeImport18OwnedValuePassViewData<'a>) -> Result<Self, ProviderError> {
        let fields = match value.kind_data()? {
            NativeImport18OwnedValuePassKindData::Object(values) => ErrorIter::Map(values),
            NativeImport18OwnedValuePassKindData::Array(values) => {
                ErrorIter::Sequence(values.enumerate())
            }
            _ => return Err(invalid()),
        };
        Ok(Self {
            fields,
            present: [false; 5],
        })
    }

    fn next_data(
        &mut self,
    ) -> Result<Option<(&'a str, NativeImport18OwnedValuePassViewData<'a>)>, ProviderError> {
        let next = match &mut self.fields {
            ErrorIter::Map(values) => values.next(),
            ErrorIter::Sequence(values) => values.next().map(|(index, value)| {
                (
                    match index {
                        0 => "code",
                        1 => "message",
                        2 => "effect",
                        3 => "retryable",
                        4 => "details",
                        _ => "unknown",
                    },
                    value,
                )
            }),
        };
        let Some((name, value)) = next else {
            if self.present.iter().any(|present| !present) {
                return Err(invalid());
            }
            return Ok(None);
        };
        let index = match name {
            "code" => 0,
            "message" => 1,
            "effect" => 2,
            "retryable" => 3,
            "details" => 4,
            _ => return Err(invalid()),
        };
        if self.present[index] {
            return Err(invalid());
        }
        self.present[index] = true;
        Ok(Some((name, value)))
    }
}

/// Borrows the actual second-pass field schedule after canonical body acceptance.
///
/// This owns no user tree. Callers retain every actual yielded next-pass owner
/// and error, and must whole-observe them before further effects. None means
/// only that field deserialization cuts are exhausted: ResponseShape::validate,
/// typed results, receipts, safe materialization and native grants remain closed.
pub(crate) struct NativeImport18ResponseShapeCutsData<'a> {
    raw: &'a RetainedFrame,
    envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
    body: Option<std::iter::Enumerate<serde_json::map::Iter<'a>>>,
    status: Option<Status>,
    present: u8,
    error: Option<ErrorFields<'a>>,
    group: Option<Group<'a>>,
    pending: Option<NativeImport18ResponseValueCutData<'a>>,
    failed: bool,
    finished: bool,
    canonical_bytes: Option<usize>,
}

impl<'a> NativeImport18ResponseShapeCutsData<'a> {
    /// Installs a spent cursor before precheck and status/field selection.
    ///
    /// The actual Envelope.body cut is a map; although locked TaggedContentVisitor
    /// also accepts a sequence tag/rest, body::object supplies Value::Object in
    /// this SDK path. ErrorRecord's reachable five-position sequence is retained.
    ///
    /// # Errors
    /// Refuses reuse, changed loans/row, canonical64/array/number/16MiB, or status.
    /// No subsequent Value normalization occurs before all prechecks succeed.
    pub(crate) fn read_into_data(
        raw: &'a RetainedFrame,
        envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
        row: &NativeImport18ResponseShapeCutsPreludeData<'a>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            raw,
            envelope,
            body: None,
            status: None,
            present: 0,
            error: None,
            group: None,
            pending: None,
            failed: true,
            finished: false,
            canonical_bytes: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        // The cursor owns borrowed headers only; observe its actual installed
        // header on every return, including failed precheck/prefix outputs.
        if owner.retained_requested_storage_data() > row.retained {
            return Err(exhausted());
        }
        if !std::ptr::eq(row.raw, raw) || !std::ptr::eq(row.envelope, envelope) {
            return Err(invalid());
        }
        let current =
            NativeImport18ResponseShapeCutsPreludeData::quote_data(raw, envelope, row.maximum)?;
        if current.retained > row.retained
            || current.transient > row.transient
            || current.scratch > row.scratch
        {
            return Err(exhausted());
        }
        owner.canonical_bytes = Some(canonical::body_extent_data(raw, envelope)?);
        let body = envelope.body_data(raw)?;
        let (member, (_, input)) = body
            .iter()
            .enumerate()
            .find(|(_, (key, _))| *key == "status")
            .ok_or_else(invalid)?;
        let tag = envelope.completed_cut_data(raw, EnvelopeField18Data::Body, member, input)?;
        let NativeImport18OwnedValuePassKindData::String(tag) = tag.kind_data()? else {
            return Err(invalid());
        };
        owner.status = Some(match tag {
            "accepted" => Status::Accepted,
            "completed" => Status::Completed,
            "error" => Status::Error,
            _ => return Err(invalid()),
        });
        owner.body = Some(body.iter().enumerate());
        owner.failed = false;
        Ok(())
    }

    /// Counts this installed borrowed cursor without counting its loaned banks.
    pub(crate) fn retained_requested_storage_data(&self) -> usize {
        let Self {
            raw: _,
            envelope: _,
            body: _,
            status: _,
            present: _,
            error: _,
            group: _,
            pending: _,
            failed: _,
            finished: _,
            canonical_bytes: _,
        } = self;
        size_of::<Option<Self>>()
    }

    /// Returns the checked actual canonical body byte extent.
    pub(crate) const fn canonical_bytes_data(&self) -> Option<usize> {
        self.canonical_bytes
    }

    /// Reports failed, exhausted-schedule and pending-cut DATA state.
    pub(crate) const fn state_data(&self) -> (bool, bool, bool) {
        (self.failed, self.finished, self.pending.is_some())
    }

    /// Selects the next actual structural member requiring one next Value pass.
    ///
    /// # Errors
    /// Refuses pending/unacknowledged cuts, earlier failure, unknown/missing/type
    /// fields or inconsistent prior loans. The cursor stops at that exact prefix.
    pub(crate) fn next_cut_data(
        &mut self,
    ) -> Result<Option<NativeImport18ResponseValueCutData<'a>>, ProviderError> {
        if self.failed || self.pending.is_some() {
            self.failed = true;
            return Err(invalid());
        }
        if self.finished {
            return Ok(None);
        }
        self.failed = true;
        let result = self.advance_data();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    /// Acknowledges this exact pending cut using its actual completed owner.
    ///
    /// # Errors
    /// Refuses a failed/incomplete/foreign owner or missing pending cut. A caller
    /// Boolean, equal bytes or another selected node cannot advance this cursor.
    pub(crate) fn complete_cut_data(
        &mut self,
        owner: &NativeImport18NextValuePassAttemptData<'a>,
    ) -> Result<(), ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        self.failed = true;
        let pending = self.pending.ok_or_else(invalid)?;
        owner.completed_data(pending.input)?.kind_data()?;
        self.pending = None;
        self.failed = false;
        Ok(())
    }

    fn advance_data(
        &mut self,
    ) -> Result<Option<NativeImport18ResponseValueCutData<'a>>, ProviderError> {
        loop {
            if let Some(group) = &mut self.group {
                if let Some((member, (_, value))) = group.values.next() {
                    let location = match group.kind {
                        GroupKind::Result => {
                            NativeImport18ResponseValueCutLocationData::Result(member)
                        }
                        GroupKind::ErrorDetail => {
                            NativeImport18ResponseValueCutLocationData::ErrorDetail(member)
                        }
                        GroupKind::Extension => {
                            NativeImport18ResponseValueCutLocationData::Extension(member)
                        }
                    };
                    let input = NativeImport18NextValueInputData::selected_data(
                        self.raw,
                        value.boundary_data(),
                        value,
                    )?;
                    let cut = NativeImport18ResponseValueCutData { location, input };
                    self.pending = Some(cut);
                    return Ok(Some(cut));
                }
                self.group = None;
            }
            if let Some(error) = &mut self.error {
                if let Some((name, value)) = error.next_data()? {
                    match name {
                        "details" => self.start_group_data(value, GroupKind::ErrorDetail)?,
                        "effect" => {
                            effect_data(value)?;
                        }
                        "retryable" => {
                            if !matches!(
                                value.kind_data()?,
                                NativeImport18OwnedValuePassKindData::Bool(_)
                            ) {
                                return Err(invalid());
                            }
                        }
                        _ => {
                            if !matches!(
                                value.kind_data()?,
                                NativeImport18OwnedValuePassKindData::String(_)
                            ) {
                                return Err(invalid());
                            }
                        }
                    }
                    continue;
                }
                self.error = None;
            }
            let next = self.body.as_mut().ok_or_else(invalid)?.next();
            let Some((member, (name, input))) = next else {
                if self.present != 7 {
                    return Err(invalid());
                }
                self.finished = true;
                return Ok(None);
            };
            if name == "status" {
                continue;
            }
            let value = self.envelope.completed_cut_data(
                self.raw,
                EnvelopeField18Data::Body,
                member,
                input,
            )?;
            let mask = match name.as_str() {
                "operation_state" => 1,
                "extensions" => 2,
                "result" if self.status != Some(Status::Error) => 4,
                "error" if self.status == Some(Status::Error) => 4,
                _ => return Err(invalid()),
            };
            if self.present & mask != 0 {
                return Err(invalid());
            }
            self.present |= mask;
            match name.as_str() {
                "operation_state" => {
                    operation_data(value)?;
                }
                "extensions" => self.start_group_data(value, GroupKind::Extension)?,
                "result" => self.start_group_data(value, GroupKind::Result)?,
                "error" => self.error = Some(ErrorFields::new_data(value)?),
                _ => return Err(invalid()),
            }
        }
    }

    fn start_group_data(
        &mut self,
        value: NativeImport18OwnedValuePassViewData<'a>,
        kind: GroupKind,
    ) -> Result<(), ProviderError> {
        let NativeImport18OwnedValuePassKindData::Object(values) = value.kind_data()? else {
            return Err(invalid());
        };
        self.group = Some(Group {
            kind,
            values: values.enumerate(),
        });
        Ok(())
    }
}

fn unit_variant_data<'a>(
    value: NativeImport18OwnedValuePassViewData<'a>,
) -> Result<&'a str, ProviderError> {
    match value.kind_data()? {
        NativeImport18OwnedValuePassKindData::String(value) => Ok(value),
        NativeImport18OwnedValuePassKindData::Object(mut values) => {
            let (key, value) = values.next().ok_or_else(invalid)?;
            if values.next().is_some()
                || !matches!(
                    value.kind_data()?,
                    NativeImport18OwnedValuePassKindData::Null
                )
            {
                return Err(invalid());
            }
            Ok(key)
        }
        _ => Err(invalid()),
    }
}

fn operation_data(
    value: NativeImport18OwnedValuePassViewData<'_>,
) -> Result<OperationState, ProviderError> {
    Ok(match unit_variant_data(value)? {
        "not_started" => OperationState::NotStarted,
        "running" => OperationState::Running,
        "completed" => OperationState::Completed,
        "unknown" => OperationState::Unknown,
        _ => return Err(invalid()),
    })
}

fn effect_data(
    value: NativeImport18OwnedValuePassViewData<'_>,
) -> Result<EffectCertainty, ProviderError> {
    Ok(match unit_variant_data(value)? {
        "not_started" => EffectCertainty::NotStarted,
        "in_progress" => EffectCertainty::InProgress,
        "completed" => EffectCertainty::Completed,
        "unknown" => EffectCertainty::Unknown,
        _ => return Err(invalid()),
    })
}
