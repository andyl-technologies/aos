//! Constructs actual owning Envelope fields with the shared locked field schedule.
//!
//! Strict raw custody, scalar headers, member keys and every flat FIRST prefix
//! stay rooted together. Body and Extensions remain structural maps; no root
//! Value pass or ordinary recursive Envelope is materialized.

use super::*;

mod storage;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

struct Header {
    protocol: Option<String>,
    message: Option<MessageKind>,
    nullable: [Option<Option<Id>>; 7],
    sequence: Option<U64>,
    method: Option<Method>,
}

impl Header {
    fn new_data() -> Self {
        Self {
            protocol: None,
            message: None,
            nullable: std::array::from_fn(|_| None),
            sequence: None,
            method: None,
        }
    }
}

struct OwnedCut {
    field: EnvelopeField18Data,
    member: usize,
    key: Option<String>,
    selected: Option<NativeImport18RawSelectionData>,
    first: Option<NativeImport18OwningFirstAttemptData>,
}

struct Data {
    header: Header,
    cuts: Vec<OwnedCut>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Selected,
    Quoted,
    FieldsComplete,
    CanonicalQuoted,
    CanonicalComplete,
    Failed,
}

#[derive(Clone, Copy)]
struct Plan {
    maximum: usize,
    cuts: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

#[derive(Clone, Copy)]
struct CanonicalPlan {
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

/// Records actual whole output plus the then-live external returned error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18OwningEnvelopeCensusData {
    /// Marks rooted custody before actual observation.
    Pending,
    /// Counts actual capacities and compares with this same owner's full row.
    Observed {
        /// Includes current root, shared raw, typed headers, keys and flat states.
        requested_bytes: usize,
        /// Compares with the same private prospective row when one exists.
        within_row: Option<bool>,
    },
    /// Records refusal of actual checked source/state/error counting.
    Refused,
}

/// Owns one actual structural Envelope decode and all failed field prefixes.
///
/// This component contains no recursive Envelope, Source currentness or native
/// permission. Canonical body qualification is a separate actual stage.
pub(crate) struct NativeImport18OwningEnvelopeAttemptData {
    stage: Stage,
    source: Option<NativeImport18RawSelectionData>,
    row: Option<Plan>,
    data: Data,
    canonical: Option<CanonicalPlan>,
    canonical_bytes: Option<usize>,
    census: NativeImport18OwningEnvelopeCensusData,
}

impl NativeImport18OwningEnvelopeAttemptData {
    /// Names additional root, initializer and complete prequote controls.
    ///
    /// Original immutable input backing stays independently charged. Keep fixed
    /// S admitted through quote; no returned row funds its own quotation.
    pub(crate) fn take_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            storage::initializer_data(),
            storage::counter_data(),
        )
    }

    /// Roots the actual immutable raw root before any fallible field check.
    ///
    /// # Errors
    /// Refuses reuse, missing/failed selection, a non-root selection or census.
    /// The exact moved selection and bytes remain under any installed refusal.
    pub(crate) fn take_into_data(
        source: &mut Option<NativeImport18RawSelectionData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Taking,
            source: None,
            row: None,
            data: Data {
                header: Header::new_data(),
                cuts: Vec::new(),
            },
            canonical: None,
            canonical_bytes: None,
            census: NativeImport18OwningEnvelopeCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.source = source.take();
        let result = (|| {
            let source = owner.source.as_ref().ok_or_else(invalid)?;
            if !std::ptr::eq(source.value_data()?, &source.retained_frame_data()?.value) {
                return Err(invalid());
            }
            owner.stage = Stage::Selected;
            Ok(())
        })();
        owner.observe_result_data(result)
    }

    /// Quotes actual field cuts, retained scalar/key owners and constructors.
    ///
    /// # Errors
    /// Refuses reuse, source, strict depth/layout or the supplied bound. This
    /// quote performs no normalization or typed-header allocation.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Selected {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            self.row = Some(storage::quote_data(
                self.source.as_ref().ok_or_else(invalid)?,
                maximum,
            )?);
            self.stage = Stage::Quoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns the complete structural row for independent parent admission.
    ///
    /// # Errors
    /// Refuses absent or failed quotation.
    pub(crate) fn requested_storage_data(&self) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        let row = self.row.as_ref().ok_or_else(invalid)?;
        Ok((row.retained, row.transient, row.scratch))
    }

    /// Executes the shared field schedule with actual owning FIRST constructors.
    ///
    /// # Errors
    /// Refuses reuse, short actual row, reserve, exact field/Nullable/pass error
    /// or current whole-owner census. Original errors and partial owners survive.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let Self {
                source,
                row,
                data,
                census,
                ..
            } = self;
            let source = source.as_ref().ok_or_else(invalid)?;
            let row = row.as_ref().ok_or_else(invalid)?;
            let current = storage::quote_data(source, row.maximum)?;
            if row.cuts < current.cuts
                || row.retained < current.retained
                || row.transient < current.transient
                || row.scratch < current.scratch
            {
                return Err(exhausted());
            }
            data.cuts
                .try_reserve_exact(row.cuts)
                .map_err(|_| exhausted())?;
            // Census actual reserve capacity before dependent field effects.
            observe_data(Some(source), data, Some(row), census, Ok(()))?;
            let mut sink = OwningFields {
                source,
                data,
                row,
                census,
            };
            visit_fields_data(&source.retained_frame_data()?.value, &mut sink)
        })();
        self.observe_result_data(result)?;
        self.stage = Stage::FieldsComplete;
        Ok(())
    }

    /// Quotes the real canonical-body controls after all first field cuts finish.
    ///
    /// Admit returned R/T/S before check_body_canonical_data. The quote contains
    /// no user serializer output bank or later Value adapter work.
    ///
    /// # Errors
    /// Refuses reuse, failed/incomplete fields, actual census or the bound.
    pub(crate) fn quote_body_canonical_into_data(
        &mut self,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if self.stage != Stage::FieldsComplete {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            self.canonical = Some(storage::canonical_quote_data(self, maximum)?);
            self.stage = Stage::CanonicalQuoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns this actual canonical check's separate row for parent admission.
    ///
    /// # Errors
    /// Refuses an absent or failed canonical quotation.
    pub(crate) fn canonical_requested_storage_data(
        &self,
    ) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::CanonicalQuoted {
            return Err(invalid());
        }
        let row = self.canonical.as_ref().ok_or_else(invalid)?;
        Ok((row.retained, row.transient, row.scratch))
    }

    /// Checks actual body canonical64/array/finite/16MiB before later cuts.
    ///
    /// This invokes the existing exact checker over the actual member FIRST
    /// outputs. A failed body stays flat and no ResponseShape pass is started.
    ///
    /// # Errors
    /// Refuses reuse, short row, actual canonical body checks or output census.
    pub(crate) fn check_body_canonical_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::CanonicalQuoted {
            return Err(invalid());
        }
        let result = (|| {
            let row = self.canonical.as_ref().ok_or_else(invalid)?;
            let current = storage::canonical_quote_data(self, row.maximum)?;
            if row.retained < current.retained
                || row.transient < current.transient
                || row.scratch < current.scratch
            {
                return Err(exhausted());
            }
            let bytes =
                super::super::next_value::response_shape::canonical::owned_body_extent_data(self)?;
            self.canonical_bytes = Some(bytes);
            Ok(())
        })();
        self.observe_result_data(result)?;
        self.stage = Stage::CanonicalComplete;
        Ok(())
    }

    /// Reports completed actual canonical extent without granting later admission.
    ///
    /// # Errors
    /// Refuses a failed or incomplete body check.
    pub(crate) fn completed_canonical_bytes_data(&self) -> Result<usize, ProviderError> {
        if self.stage != Stage::CanonicalComplete {
            return Err(invalid());
        }
        self.canonical_bytes.ok_or_else(invalid)
    }

    pub(in super::super) fn body_data(
        &self,
    ) -> Result<&serde_json::Map<String, Value>, ProviderError> {
        if !matches!(
            self.stage,
            Stage::FieldsComplete | Stage::CanonicalQuoted | Stage::CanonicalComplete
        ) {
            return Err(invalid());
        }
        let raw = self
            .source
            .as_ref()
            .ok_or_else(invalid)?
            .retained_frame_data()?;
        let body = match &raw.value {
            Value::Object(fields) => fields.get("body"),
            Value::Array(fields) => fields.get(11),
            _ => None,
        }
        .ok_or_else(invalid)?;
        body.as_object().ok_or_else(invalid)
    }

    pub(in super::super) fn cut_first_data(
        &self,
        field: EnvelopeField18Data,
        member: usize,
    ) -> Result<&NativeImport18OwningFirstAttemptData, ProviderError> {
        if !matches!(
            self.stage,
            Stage::FieldsComplete | Stage::CanonicalQuoted | Stage::CanonicalComplete
        ) {
            return Err(invalid());
        }
        self.data
            .cuts
            .iter()
            .find(|cut| cut.field == field && cut.member == member)
            .and_then(|cut| cut.first.as_ref())
            .ok_or_else(invalid)
    }

    pub(in super::super) fn transfer_counter_data() -> usize {
        storage::transfer_counter_data()
    }

    // Only the owning ResponseShape parent can move a body FIRST into its
    // already rooted transfer slot. The parent then observes both halves.
    pub(in super::super) fn transfer_body_first_into_data(
        &mut self,
        member: usize,
        output: &mut Option<super::super::next_value::NativeImport18FirstBankCustodyData>,
    ) -> Result<(), ProviderError> {
        if self.stage != Stage::CanonicalComplete {
            return Err(invalid());
        }
        let cut = self
            .data
            .cuts
            .iter_mut()
            .find(|cut| cut.field == EnvelopeField18Data::Body && cut.member == member)
            .ok_or_else(invalid)?;
        super::super::next_value::NativeImport18FirstBankCustodyData::take_into_data(
            &mut cut.first,
            output,
        )
    }

    /// Borrows the original immutable raw frame even after a field refusal.
    ///
    /// # Errors
    /// Refuses a take that never received a selection.
    pub(crate) fn retained_frame_data(&self) -> Result<&RetainedFrame, ProviderError> {
        self.source
            .as_ref()
            .ok_or_else(invalid)?
            .retained_frame_data()
    }

    /// Returns the actual last output/error census without renewing credit.
    pub(crate) const fn census_data(&self) -> NativeImport18OwningEnvelopeCensusData {
        self.census
    }

    /// Counts actual current root/raw/header/key/flat backing without an old error.
    ///
    /// The caller separately includes its actual current externally held error.
    /// The snapshot on return includes the then-live error, never future credit.
    ///
    /// # Errors
    /// Refuses source/flat observation, checked layout or the supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        retained_data(self.source.as_ref(), &self.data, maximum)
    }

    fn observe_result_data(
        &mut self,
        result: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let returned = observe_data(
            self.source.as_ref(),
            &self.data,
            self.row.as_ref(),
            &mut self.census,
            result,
        );
        if returned.is_err() {
            self.stage = Stage::Failed;
        }
        returned
    }
}

struct OwningFields<'owner> {
    source: &'owner NativeImport18RawSelectionData,
    data: &'owner mut Data,
    row: &'owner Plan,
    census: &'owner mut NativeImport18OwningEnvelopeCensusData,
}

impl<'raw> FieldSink<'raw> for OwningFields<'_> {
    fn read_cut_data(
        &mut self,
        field: EnvelopeField18Data,
        member: usize,
        key: Option<&'raw str>,
        input: &'raw Value,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            if self.data.cuts.len() >= self.row.cuts {
                return Err(exhausted());
            }
            self.data.cuts.push(OwnedCut {
                field,
                member,
                key: key.map(String::from),
                selected: None,
                first: None,
            });
            observe_data(
                Some(self.source),
                self.data,
                Some(self.row),
                self.census,
                Ok(()),
            )?;
            {
                let selected_row = self.source.member_row_data(input, self.row.maximum)?;
                let child = self.data.cuts.last_mut().ok_or_else(invalid)?;
                NativeImport18RawSelectionData::read_into_data(&selected_row, &mut child.selected)?;
            }
            observe_data(
                Some(self.source),
                self.data,
                Some(self.row),
                self.census,
                Ok(()),
            )?;
            {
                let child = self.data.cuts.last_mut().ok_or_else(invalid)?;
                NativeImport18OwningFirstAttemptData::take_into_data(
                    &mut child.selected,
                    &mut child.first,
                )?;
            }
            observe_data(
                Some(self.source),
                self.data,
                Some(self.row),
                self.census,
                Ok(()),
            )?;
            self.data
                .cuts
                .last_mut()
                .and_then(|cut| cut.first.as_mut())
                .ok_or_else(invalid)?
                .quote_into_data(self.row.maximum)?;
            observe_data(
                Some(self.source),
                self.data,
                Some(self.row),
                self.census,
                Ok(()),
            )?;
            self.data
                .cuts
                .last_mut()
                .and_then(|cut| cut.first.as_mut())
                .ok_or_else(invalid)?
                .run_data()
        })();
        observe_data(
            Some(self.source),
            self.data,
            Some(self.row),
            self.census,
            result,
        )
    }

    fn nullable_data(
        &mut self,
        field: EnvelopeField18Data,
        _input: &'raw Value,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            let first = self
                .data
                .cuts
                .last()
                .and_then(|cut| cut.first.as_ref())
                .ok_or_else(invalid)?;
            let value = match first.completed_data()?.kind_data()? {
                NativeImport18FirstFlatKindData::Null => None,
                NativeImport18FirstFlatKindData::String(value) => Some(Id::new(value)?),
                _ => return Err(invalid()),
            };
            let index = match field {
                EnvelopeField18Data::SessionId => 0,
                EnvelopeField18Data::IncarnationId => 1,
                EnvelopeField18Data::NodeId => 2,
                EnvelopeField18Data::ExecutionOwnerId => 3,
                EnvelopeField18Data::CaptureOwnerId => 4,
                EnvelopeField18Data::RequestId => 5,
                EnvelopeField18Data::OperationId => 6,
                _ => return Err(invalid()),
            };
            self.data.header.nullable[index] = Some(value);
            Ok(())
        })();
        observe_data(
            Some(self.source),
            self.data,
            Some(self.row),
            self.census,
            result,
        )
    }

    fn direct_data(
        &mut self,
        field: EnvelopeField18Data,
        input: &'raw Value,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            match field {
                EnvelopeField18Data::Protocol => {
                    self.data.header.protocol = Some(input.as_str().ok_or_else(invalid)?.into())
                }
                EnvelopeField18Data::Message => {
                    self.data.header.message = Some(message_data(input)?)
                }
                EnvelopeField18Data::Sequence => {
                    self.data.header.sequence =
                        Some(input.as_str().ok_or_else(invalid)?.parse::<U64>()?)
                }
                EnvelopeField18Data::Method => self.data.header.method = Some(method_data(input)?),
                _ => return Err(invalid()),
            }
            Ok(())
        })();
        observe_data(
            Some(self.source),
            self.data,
            Some(self.row),
            self.census,
            result,
        )
    }
}

fn retained_data(
    source: Option<&NativeImport18RawSelectionData>,
    data: &Data,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let Data { header, cuts } = data;
    let Header {
        protocol,
        message: _,
        nullable,
        sequence: _,
        method: _,
    } = header;
    let mut retained = size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>();
    if let Some(source) = source {
        retained = super::super::storage::add(
            retained,
            source
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18RawSelectionData>>())
                .ok_or_else(invalid)?,
        )?;
    }
    retained = super::super::storage::add(
        retained,
        super::super::storage::mul(cuts.capacity(), size_of::<OwnedCut>())?,
    )?;
    if let Some(value) = protocol {
        retained = super::super::storage::add(retained, value.capacity())?;
    }
    for value in nullable.iter().flatten().flatten() {
        retained = super::super::storage::add(retained, value.allocated_capacity())?;
    }
    for OwnedCut {
        field: _,
        member: _,
        key,
        selected: _,
        first,
    } in cuts
    {
        if let Some(key) = key {
            retained = super::super::storage::add(retained, key.capacity())?;
        }
        if let Some(first) = first {
            retained = super::super::storage::add(
                retained,
                first.state_data().retained_backing_data(maximum)?,
            )?;
        }
    }
    // All raw handles above are created only from the same private source's
    // checked member rows. Its one immutable allocation is counted once here;
    // the inline handle/owner headers already belong to Self and each Cut slot.
    if retained > maximum {
        return Err(exhausted());
    }
    Ok(retained)
}

fn observe_data(
    source: Option<&NativeImport18RawSelectionData>,
    data: &Data,
    row: Option<&Plan>,
    census: &mut NativeImport18OwningEnvelopeCensusData,
    result: Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let actual = retained_data(source, data, usize::MAX).and_then(|bytes| {
        super::super::storage::add(bytes, error_retained_requested_data(&result)?)
    });
    *census = match &actual {
        Ok(bytes) => NativeImport18OwningEnvelopeCensusData::Observed {
            requested_bytes: *bytes,
            within_row: row.map(|row| *bytes <= row.retained),
        },
        Err(_) => NativeImport18OwningEnvelopeCensusData::Refused,
    };
    result?;
    if let Some(row) = row {
        if actual? > row.retained {
            return Err(exhausted());
        }
    } else {
        actual?;
    }
    Ok(())
}
