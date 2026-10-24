//! Drives the shared actual ResponseShape cut schedule through borrowed inputs.
//!
//! Owning and borrowed adapters share source-free ordinal state. Views are short
//! immutable loans; no new Value pass or Source/native permission is implied.

use super::*;

pub(in super::super) mod canonical;
pub(super) mod owning;
mod schedule;
mod shape_validate;
use schedule::{Route, Schedule, Source};
pub(crate) use shape_validate::{
    NativeImport18ShapeValidateAttemptData, NativeImport18ShapeValidateCensusData,
};

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

/// Quotes the borrowed cursor, canonical precheck and shared schedule controls.
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
    /// Quotes real fixed demand before canonical or schedule work.
    ///
    /// Admit counter S before entry and the complete returned row before read.
    ///
    /// # Errors
    /// Refuses incomplete/foreign source, checked overflow or the supplied bound.
    pub(crate) fn quote_data(
        raw: &'a RetainedFrame,
        envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        envelope.body_data(raw)?;
        let retained = size_of::<Option<NativeImport18ResponseShapeCutsData<'static>>>();
        let initializer = sum(&[
            size_of::<NativeImport18ResponseShapeCutsData<'static>>(),
            retained,
            schedule::initializer_data(),
        ])?;
        let cut = size_of::<NativeImport18ResponseValueCutData<'static>>()
            + size_of::<Option<NativeImport18ResponseValueCutData<'static>>>();
        let transient = initializer.max(cut).max(canonical::transient_data()?);
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

    /// Returns real fixed cursor axes for independent admission.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual borrowed controls beside the shared schedule and checker.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 2
            + size_of::<NativeImport18ResponseShapeCutsData<'static>>()
            + size_of::<Option<NativeImport18ResponseShapeCutsData<'static>>>()
            + size_of::<&mut Option<NativeImport18ResponseShapeCutsData<'static>>>()
            + size_of::<&mut NativeImport18ResponseShapeCutsData<'static>>() * 2
            + size_of::<BorrowedSource<'static>>() * 2
            + size_of::<&BorrowedSource<'static>>() * 3
            + size_of::<NativeImport18ResponseValueCutData<'static>>() * 2
            + size_of::<Option<NativeImport18ResponseValueCutData<'static>>>()
            + size_of::<Result<Option<NativeImport18ResponseValueCutData<'static>>, ProviderError>>(
            )
            + size_of::<NativeImport18OwnedValuePassViewData<'static>>() * 3
            + size_of::<Result<NativeImport18OwnedValuePassViewData<'static>, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassKindData<'static>>() * 2
            + size_of::<NativeImport18OwnedValuePassObjectData<'static>>()
            + size_of::<NativeImport18OwnedValuePassArrayData<'static>>()
            + size_of::<Option<(&str, NativeImport18OwnedValuePassViewData<'static>)>>()
            + size_of::<Option<NativeImport18OwnedValuePassViewData<'static>>>()
            + size_of::<&RetainedFrame>() * 4
            + size_of::<&NativeImport18EnvelopeFieldsAttemptData<'static>>() * 4
            + size_of::<&NativeImport18NextValuePassAttemptData<'static>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Route>() * 2
            + size_of::<Option<Route>>()
            + size_of::<Result<Route, ProviderError>>()
            + size_of::<serde_json::map::Iter<'static>>() * 2
            + size_of::<Option<(&String, &Value)>>() * 2
            // Raw body-name callback, raw value binding and normalized object
            // child callback are direct adapter controls, not delegated credit.
            + size_of::<(&String, &Value)>() * 2
            + size_of::<Result<(&String, &Value), ProviderError>>()
            + size_of::<(&str, NativeImport18OwnedValuePassViewData<'static>)>()
            + size_of::<Option<&str>>()
            + size_of::<Result<Option<&str>, ProviderError>>()
            + size_of::<std::array::IntoIter<Option<usize>, 2>>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<usize>, 2>>>()
            + size_of::<[Option<usize>; 2]>()
            // Initializer, complete bound and canonical::transient_data each
            // execute their own three-term sum before the returned admission.
            + size_of::<[usize; 3]>() * 3
            + size_of::<&[usize]>() * 3
            + size_of::<std::slice::Iter<'static, usize>>() * 3
            + size_of::<&mut std::slice::Iter<'static, usize>>() * 3
            + size_of::<&usize>() * 3
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<[usize; 8]>()
            + size_of::<bool>() * 3
            + canonical::counter_scratch_data()
            + schedule::counter_data()
            + input::counter_scratch_data()
            + super::super::view::counter_scratch_data()
    }
}

struct BorrowedSource<'a> {
    raw: &'a RetainedFrame,
    envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
}

impl<'a> BorrowedSource<'a> {
    fn value_data(
        &self,
        route: Route,
    ) -> Result<NativeImport18OwnedValuePassViewData<'a>, ProviderError> {
        let (_, input) = self
            .envelope
            .body_data(self.raw)?
            .iter()
            .nth(route.body)
            .ok_or_else(invalid)?;
        let mut value = self.envelope.completed_cut_data(
            self.raw,
            EnvelopeField18Data::Body,
            route.body,
            input,
        )?;
        for position in route.path.into_iter().flatten() {
            value = match value.kind_data()? {
                NativeImport18OwnedValuePassKindData::Object(mut fields) => {
                    fields.nth(position).map(|(_, v)| v).ok_or_else(invalid)?
                }
                NativeImport18OwnedValuePassKindData::Array(mut fields) => {
                    fields.nth(position).ok_or_else(invalid)?
                }
                _ => return Err(invalid()),
            };
        }
        Ok(value)
    }
}

impl Source for BorrowedSource<'_> {
    fn body_name_data(&self, index: usize) -> Result<Option<&str>, ProviderError> {
        Ok(self
            .envelope
            .body_data(self.raw)?
            .iter()
            .nth(index)
            .map(|(key, _)| key.as_str()))
    }
    fn value_data(
        &self,
        route: Route,
    ) -> Result<NativeImport18FirstFlatViewData<'_>, ProviderError> {
        Ok(BorrowedSource::value_data(self, route)?.flat_data())
    }
}

/// Retains actual immutable boundary loans and the shared source-free schedule.
///
/// Exhausting this DATA schedule does not materialize or validate a typed DTO.
pub(crate) struct NativeImport18ResponseShapeCutsData<'a> {
    raw: &'a RetainedFrame,
    envelope: &'a NativeImport18EnvelopeFieldsAttemptData<'a>,
    schedule: Schedule,
    canonical_bytes: Option<usize>,
}

impl<'a> NativeImport18ResponseShapeCutsData<'a> {
    /// Roots the spent cursor before canonical precheck and actual tag selection.
    ///
    /// # Errors
    /// Refuses reuse, foreign/short row, canonical body or exact status decoding.
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
            schedule: Schedule::new_data(),
            canonical_bytes: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
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
        owner.schedule.start_data(&BorrowedSource { raw, envelope })
    }

    /// Counts the installed borrowed header; all borrowed banks remain separate.
    pub(crate) fn retained_requested_storage_data(&self) -> usize {
        size_of::<Option<Self>>()
    }
    /// Returns actual canonical body bytes after the check completed.
    pub(crate) const fn canonical_bytes_data(&self) -> Option<usize> {
        self.canonical_bytes
    }
    /// Reports failed, exhausted and pending schedule state.
    pub(crate) const fn state_data(&self) -> (bool, bool, bool) {
        self.schedule.state_data()
    }

    /// Selects one exact scheduled next-pass member with actual boundary loans.
    ///
    /// # Errors
    /// Refuses prior failure, pending cuts or exact schema/order violations.
    pub(crate) fn next_cut_data(
        &mut self,
    ) -> Result<Option<NativeImport18ResponseValueCutData<'a>>, ProviderError> {
        let source = BorrowedSource {
            raw: self.raw,
            envelope: self.envelope,
        };
        let Some(selected) = self.schedule.next_data(&source)? else {
            return Ok(None);
        };
        self.schedule.fail_data();
        let value = source.value_data(selected.route)?;
        let input = NativeImport18NextValueInputData::selected_data(
            self.raw,
            value.boundary_data(),
            value,
        )?;
        self.schedule.resume_data();
        Ok(Some(NativeImport18ResponseValueCutData {
            location: selected.location,
            input,
        }))
    }

    /// Acknowledges only the actual complete next owner for this pending node.
    ///
    /// # Errors
    /// Refuses failed/incomplete/foreign output; every refusal spends the cursor.
    pub(crate) fn complete_cut_data(
        &mut self,
        owner: &NativeImport18NextValuePassAttemptData<'a>,
    ) -> Result<(), ProviderError> {
        let pending = self.schedule.pending_data();
        self.schedule.fail_data();
        let route = pending?;
        let source = BorrowedSource {
            raw: self.raw,
            envelope: self.envelope,
        };
        let value = source.value_data(route)?;
        let input = NativeImport18NextValueInputData::selected_data(
            self.raw,
            value.boundary_data(),
            value,
        )?;
        owner.completed_data(input)?.kind_data()?;
        self.schedule.complete_data();
        Ok(())
    }
}
