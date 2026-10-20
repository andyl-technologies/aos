//! Retains the actual first Envelope field adapter cuts as flat DATA.
//!
//! Envelope's body and Extensions are structural maps: only their member values
//! invoke Value::deserialize. Nullable<Id> invokes it once before its scalar Id
//! decoder. Struct sequences use declaration order; object fields use the
//! locked serde_json BTreeMap order. No Envelope, ResponseShape or native grant
//! is constructed here. Later response/result/receipt cuts remain independent.

use super::*;
use crate::envelope::{MessageKind, Method};
use crate::transport::RetainedFrame;
use crucible_node_format::{Id, U64};

/// Identifies one actual Envelope field without an allocated path string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeField18Data {
    /// Selects the direct protocol String.
    Protocol,
    /// Selects the direct message-kind unit enum.
    Message,
    /// Selects the nullable session identifier Value pass.
    SessionId,
    /// Selects the nullable incarnation identifier Value pass.
    IncarnationId,
    /// Selects the nullable node identifier Value pass.
    NodeId,
    /// Selects the nullable execution-owner identifier Value pass.
    ExecutionOwnerId,
    /// Selects the nullable capture-owner identifier Value pass.
    CaptureOwnerId,
    /// Selects the nullable request identifier Value pass.
    RequestId,
    /// Selects the nullable operation identifier Value pass.
    OperationId,
    /// Selects the direct canonical-decimal sequence.
    Sequence,
    /// Selects the direct method unit enum.
    Method,
    /// Selects the body structural map's individual member passes.
    Body,
    /// Selects the Extensions structural map's individual member passes.
    Extensions,
}

const FIELDS: [EnvelopeField18Data; 13] = [
    EnvelopeField18Data::Protocol,
    EnvelopeField18Data::Message,
    EnvelopeField18Data::SessionId,
    EnvelopeField18Data::IncarnationId,
    EnvelopeField18Data::NodeId,
    EnvelopeField18Data::ExecutionOwnerId,
    EnvelopeField18Data::CaptureOwnerId,
    EnvelopeField18Data::RequestId,
    EnvelopeField18Data::OperationId,
    EnvelopeField18Data::Sequence,
    EnvelopeField18Data::Method,
    EnvelopeField18Data::Body,
    EnvelopeField18Data::Extensions,
];

impl EnvelopeField18Data {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "protocol" => Self::Protocol,
            "message" => Self::Message,
            "session_id" => Self::SessionId,
            "incarnation_id" => Self::IncarnationId,
            "node_id" => Self::NodeId,
            "execution_owner_id" => Self::ExecutionOwnerId,
            "capture_owner_id" => Self::CaptureOwnerId,
            "request_id" => Self::RequestId,
            "operation_id" => Self::OperationId,
            "sequence" => Self::Sequence,
            "method" => Self::Method,
            "body" => Self::Body,
            "extensions" => Self::Extensions,
            _ => return None,
        })
    }

    fn nullable(self) -> bool {
        matches!(
            self,
            Self::SessionId
                | Self::IncarnationId
                | Self::NodeId
                | Self::ExecutionOwnerId
                | Self::CaptureOwnerId
                | Self::RequestId
                | Self::OperationId
        )
    }

    fn structural(self) -> bool {
        matches!(self, Self::Body | Self::Extensions)
    }
}

enum Fields<'a> {
    Object(serde_json::map::Iter<'a>),
    Sequence(std::iter::Enumerate<std::slice::Iter<'a, Value>>),
}

impl<'a> Fields<'a> {
    fn new(value: &'a Value) -> Result<Self, ProviderError> {
        match value {
            Value::Object(fields) => Ok(Self::Object(fields.iter())),
            Value::Array(fields) => Ok(Self::Sequence(fields.iter().enumerate())),
            _ => Err(invalid()),
        }
    }

    fn next(&mut self) -> Option<Result<(EnvelopeField18Data, &'a Value), ProviderError>> {
        match self {
            Self::Object(fields) => fields.next().map(|(name, value)| {
                EnvelopeField18Data::from_name(name)
                    .map(|field| (field, value))
                    .ok_or_else(invalid)
            }),
            Self::Sequence(fields) => fields.next().map(|(index, value)| {
                FIELDS
                    .get(index)
                    .copied()
                    .map(|field| (field, value))
                    .ok_or_else(invalid)
            }),
        }
    }
}

mod owning;
pub(crate) use owning::{
    NativeImport18OwningEnvelopeAttemptData, NativeImport18OwningEnvelopeCensusData,
};

// Both actual adapters execute this single declaration/map schedule. A sink
// roots each field pass before its nullable decoder or next member can run.
trait FieldSink<'raw> {
    fn read_cut_data(
        &mut self,
        field: EnvelopeField18Data,
        member: usize,
        key: Option<&'raw str>,
        input: &'raw Value,
    ) -> Result<(), ProviderError>;
    fn nullable_data(
        &mut self,
        field: EnvelopeField18Data,
        input: &'raw Value,
    ) -> Result<(), ProviderError>;
    fn direct_data(
        &mut self,
        field: EnvelopeField18Data,
        input: &'raw Value,
    ) -> Result<(), ProviderError>;
}

fn visit_fields_data<'raw>(
    root: &'raw Value,
    sink: &mut impl FieldSink<'raw>,
) -> Result<(), ProviderError> {
    let mut present = [false; 13];
    let mut fields = Fields::new(root)?;
    while let Some(field) = fields.next() {
        let (field, input) = field?;
        let index = FIELDS
            .iter()
            .position(|candidate| *candidate == field)
            .ok_or_else(invalid)?;
        if present[index] {
            return Err(invalid());
        }
        present[index] = true;
        if field.nullable() {
            sink.read_cut_data(field, 0, None, input)?;
            sink.nullable_data(field, input)?;
        } else if field.structural() {
            for (member, (key, input)) in input.as_object().ok_or_else(invalid)?.iter().enumerate()
            {
                sink.read_cut_data(field, member, Some(key), input)?;
            }
        } else {
            sink.direct_data(field, input)?;
        }
    }
    if present.iter().any(|present| !present) {
        return Err(invalid());
    }
    Ok(())
}

struct BorrowedFields<'owner, 'raw> {
    owner: &'owner mut NativeImport18EnvelopeFieldsAttemptData<'raw>,
    raw: &'raw RetainedFrame,
}

impl<'raw> FieldSink<'raw> for BorrowedFields<'_, 'raw> {
    fn read_cut_data(
        &mut self,
        field: EnvelopeField18Data,
        member: usize,
        _key: Option<&'raw str>,
        input: &'raw Value,
    ) -> Result<(), ProviderError> {
        self.owner.read_cut(self.raw, field, member, input)
    }

    fn nullable_data(
        &mut self,
        _field: EnvelopeField18Data,
        input: &'raw Value,
    ) -> Result<(), ProviderError> {
        let child = self
            .owner
            .cuts
            .last()
            .and_then(|cut| cut.attempt.as_ref())
            .ok_or_else(invalid)?;
        match child.completed_data(self.raw, input)?.kind_data()? {
            NativeImport18OwnedValuePassKindData::Null => {}
            NativeImport18OwnedValuePassKindData::String(value) => {
                Id::new(value)?;
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }

    fn direct_data(
        &mut self,
        field: EnvelopeField18Data,
        input: &'raw Value,
    ) -> Result<(), ProviderError> {
        match field {
            EnvelopeField18Data::Protocol => {
                input.as_str().ok_or_else(invalid)?;
            }
            EnvelopeField18Data::Message => {
                message_data(input)?;
            }
            EnvelopeField18Data::Sequence => {
                input.as_str().ok_or_else(invalid)?.parse::<U64>()?;
            }
            EnvelopeField18Data::Method => {
                method_data(input)?;
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

struct Cut<'bank> {
    field: EnvelopeField18Data,
    member: usize,
    attempt: Option<NativeImport18OwnedValuePassAttemptData<'bank>>,
}

/// Reports the same output owner's actual post-attempt retained census.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeFieldsCensus18Data {
    /// Indicates that construction has not reached its final census yet.
    Pending,
    /// Retains an actual capacity count and its comparison with the quoted row.
    Observed {
        /// Counts the actual output, flat children and returned scalar error backing.
        requested_bytes: usize,
        /// Reports whether that actual count fits this same owner's quoted R.
        within_row: bool,
    },
    /// Indicates that checked layout/counting refused; completion remains closed.
    Refused,
}

/// Quotes the exact selected strict-raw fields and their flat backing.
///
/// The row retains an immutable loan to the actual raw frame, including bytes.
/// Copying it cannot detach its content identity or permit same-slot mutation.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18EnvelopeFieldsConstructionData<'bank> {
    raw: &'bank RetainedFrame,
    root: &'bank Value,
    maximum: usize,
    cuts: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl<'bank> NativeImport18EnvelopeFieldsConstructionData<'bank> {
    /// Quotes actual fields without normalizing or constructing user Values.
    ///
    /// This conservative quote continues past direct scalar failures, because
    /// it prices potential construction rather than executing the field visitor.
    /// Construction itself stops at the first actual failed field or member.
    /// The original raw owner and enclosing Source rows remain separately live.
    ///
    /// # Errors
    /// Refuses checked layout overflow, strict raw depth, or demand beyond the
    /// supplied maximum. Semantic errors are executed by the actual attempt,
    /// after retaining all earlier initialized field passes.
    pub(crate) fn quote_data(
        raw: &'bank RetainedFrame,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let mut row = Self {
            raw,
            root: &raw.value,
            maximum,
            cuts: 0,
            retained: size_of::<Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>(),
            transient: Self::outer_initializer_transient_data()?,
            scratch: Self::counter_scratch_data(),
        };
        let mut scalar_error_possible = false;
        if let Ok(mut fields) = Fields::new(&raw.value) {
            while let Some(field) = fields.next() {
                let Ok((field, value)) = field else {
                    continue;
                };
                scalar_error_possible |= field.nullable() || field == EnvelopeField18Data::Sequence;
                if field.nullable() {
                    row.add_cut(raw, value)?;
                } else if field.structural() {
                    if let Some(fields) = value.as_object() {
                        for value in fields.values() {
                            row.add_cut(raw, value)?;
                        }
                    }
                }
            }
        }

        // The only scalar owner here is the post-Value nullable Id decoder.
        // Raw parsing and escapes cannot increase UTF-8 length beyond the
        // actual strict source String containing them. Read actual String
        // extents rather than trusting raw.bytes to remain a matching encoding.
        let mut strings = walk::Walk::new_data(&raw.value);
        let mut scalar_bytes = 0;
        while let Some((value, _)) = strings.next_data()? {
            if let Value::String(value) = value {
                scalar_bytes = scalar_bytes.max(value.len());
            }
        }
        // These exact reason Strings are the only error heap produced by the
        // defining Id::new and U64::from_str scalar routines. An invalid owned
        // Id String can coexist with its reason before try_from_owned returns.
        let scalar_error_bytes = "expected 1–128 bounded ASCII identifier bytes"
            .len()
            .max("expected canonical decimal string".len())
            .max("integer outside declared range".len());
        if scalar_error_possible {
            // A failed scalar's reason String is returned alongside this same
            // retained output. It remains in R as well as its construction T;
            // no hypothetical future caller row supplies that owning backing.
            row.retained = storage::add(row.retained, scalar_error_bytes)?;
        }
        row.transient = row
            .transient
            .max(storage::add(scalar_bytes, scalar_error_bytes)?);
        if row.retained > maximum || row.transient > maximum || row.scratch > maximum {
            return Err(exhausted());
        }
        Ok(row)
    }

    fn add_cut(
        &mut self,
        raw: &'bank RetainedFrame,
        input: &'bank Value,
    ) -> Result<(), ProviderError> {
        let child =
            NativeImport18OwnedValuePassConstructionData::quote_data(raw, input, self.maximum)?;
        let (retained, transient, scratch) = child.requested_storage_data();
        self.cuts = storage::add(self.cuts, 1)?;
        self.retained = storage::sum(&[
            self.retained,
            size_of::<Cut<'bank>>(),
            retained
                .checked_sub(size_of::<
                    Option<NativeImport18OwnedValuePassAttemptData<'static>>,
                >())
                .ok_or_else(invalid)?,
        ])?;
        self.transient = self
            .transient
            .max(transient)
            .max(Self::cut_initializer_transient_data()?);
        self.scratch = self
            .scratch
            .max(storage::add(Self::counter_scratch_data(), scratch)?);
        Ok(())
    }

    /// Returns independently admitted retained, transient and scratch demand.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    // These are the actual outer initializer/Some outputs. Their temporary
    // headers are priced independently of the retained destination and of all
    // child rows, including a no-cut/no-String refusal before field iteration.
    fn outer_initializer_transient_data() -> Result<usize, ProviderError> {
        storage::sum(&[
            size_of::<NativeImport18EnvelopeFieldsAttemptData<'static>>(),
            size_of::<Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>(),
            size_of::<Vec<Cut<'bank>>>(),
        ])
    }

    // A reserved Cut is pushed before its child can fail. No backing growth
    // occurs here: construction checks the quoted population and reserves the
    // complete Vec before visiting any field. This prices that real push value
    // and its inline None initializer without borrowing child initializer T.
    fn cut_initializer_transient_data() -> Result<usize, ProviderError> {
        storage::sum(&[
            size_of::<Cut<'bank>>(),
            size_of::<Cut<'bank>>(),
            size_of::<Option<NativeImport18OwnedValuePassAttemptData<'static>>>(),
        ])
    }

    /// Names this defining borrowed schedule and its direct scalar controls.
    pub(crate) fn counter_scratch_data() -> usize {
        let quote = size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 3
            + size_of::<&mut Self>()
            + size_of::<Fields<'static>>()
            + size_of::<Result<Fields<'static>, ProviderError>>()
            + size_of::<&mut Fields<'static>>()
            + size_of::<Option<Result<(EnvelopeField18Data, &Value), ProviderError>>>()
            + size_of::<(EnvelopeField18Data, &Value)>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<serde_json::map::Values<'static>>()
            + size_of::<std::iter::Enumerate<serde_json::map::Values<'static>>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
            + size_of::<Result<(EnvelopeField18Data, &Value), ProviderError>>()
            + size_of::<Option<(usize, &Value)>>()
            + size_of::<(usize, &Value)>()
            + size_of::<Option<(&String, &Value)>>()
            + size_of::<(&String, &Value)>()
            + size_of::<Option<&serde_json::Map<String, Value>>>()
            + size_of::<&serde_json::Map<String, Value>>()
            + size_of::<NativeImport18OwnedValuePassConstructionData<'static>>() * 2
            + size_of::<&NativeImport18OwnedValuePassConstructionData<'static>>()
            + size_of::<Result<NativeImport18OwnedValuePassConstructionData<'static>, ProviderError>>(
            )
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<[usize; 3]>() * 2
            + size_of::<[usize; 2]>()
            + size_of::<&[usize]>() * 3
            + size_of::<(usize, usize, usize)>();

        let construction = size_of::<NativeImport18EnvelopeFieldsAttemptData<'static>>()
            + size_of::<Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>()
            + size_of::<Vec<Cut<'bank>>>()
            + size_of::<Cut<'bank>>()
            + size_of::<Option<NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<&mut Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>()
            + size_of::<&Option<NativeImport18EnvelopeFieldsAttemptData<'static>>>()
            + size_of::<&mut NativeImport18EnvelopeFieldsAttemptData<'static>>() * 2
            + size_of::<&NativeImport18EnvelopeFieldsAttemptData<'static>>() * 2
            + size_of::<&mut Vec<Cut<'bank>>>()
            + size_of::<&Vec<Cut<'bank>>>()
            + size_of::<&mut Cut<'static>>()
            + size_of::<Option<&mut Cut<'static>>>()
            + size_of::<&mut Option<NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<Result<(), ProviderError>>() * 2
            // The census closure capture and its error-observer argument.
            + size_of::<&Result<(), ProviderError>>() * 2
            + size_of::<&ProviderError>()
            + size_of::<&crucible_node_format::ContractError>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<EnvelopeFieldsCensus18Data>()
            + size_of::<[bool; 13]>()
            + size_of::<std::slice::Iter<'static, bool>>()
            + size_of::<&bool>()
            + size_of::<Option<&bool>>()
            + size_of::<std::slice::Iter<'static, EnvelopeField18Data>>()
            + size_of::<&EnvelopeField18Data>() * 2
            + size_of::<Option<&EnvelopeField18Data>>()
            + size_of::<Option<usize>>();

        // find's predicate receives &&Cut and captures the field/member loans.
        // The census and completed lookup borrow this same actual owner; their
        // controls are separate from the frozen child's own view operations.
        let loans = size_of::<std::slice::Iter<'static, Cut<'static>>>() * 2
            + size_of::<&Cut<'static>>() * 2
            + size_of::<&&Cut<'static>>()
            + size_of::<Option<&Cut<'static>>>() * 2
            + size_of::<&EnvelopeField18Data>()
            + size_of::<&usize>()
            + size_of::<Option<&NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>()
            + size_of::<&Option<NativeImport18OwnedValuePassAttemptData<'static>>>()
            + size_of::<NativeImport18OwnedValuePassViewData<'static>>()
            + size_of::<Result<NativeImport18OwnedValuePassViewData<'static>, ProviderError>>()
            + size_of::<NativeImport18OwnedValuePassKindData<'static>>()
            + size_of::<Result<NativeImport18OwnedValuePassKindData<'static>, ProviderError>>();

        let scalars = size_of::<Result<Id, crucible_node_format::ContractError>>()
            + size_of::<EnvelopeField18Data>() * 2
            + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
            + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
            + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
            + size_of::<(String, crucible_node_format::ContractError)>()
            + size_of::<Result<MessageKind, ProviderError>>()
            + size_of::<Result<Method, ProviderError>>()
            + size_of::<Result<U64, crucible_node_format::ContractError>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<std::num::ParseIntError>()
            + size_of::<std::str::Bytes<'static>>() * 2
            + size_of::<Option<u8>>()
            + size_of::<crucible_node_format::ContractError>()
            + size_of::<Result<&str, ProviderError>>()
            + size_of::<Option<&str>>()
            + size_of::<&str>() * 3
            + size_of::<String>()
            + size_of::<&String>()
            + size_of::<Id>()
            + size_of::<ProviderError>()
            + size_of::<usize>() * 19
            + size_of::<bool>() * 4
            + size_of::<&RetainedFrame>() * 3
            + size_of::<&Value>() * 3;

        schedule_counter_scratch_data()
            + quote
            + construction
            + loans
            + scalars
            + size_of::<usize>() * 4
            + walk::counter_scratch_data()
            + NativeImport18OwnedValuePassConstructionData::counter_scratch_data()
    }
}

/// Retains each actual Envelope field pass before any later field can fail.
///
/// Only flat child attempts are owned. The strict raw frame stays independently
/// retained. Completion proves this first adapter schedule only, and does not
/// prove Envelope validation, correlation, canonical64, ResponseShape/result
/// passes, receipts, default-stack DTO materialization or native permission.
pub(crate) struct NativeImport18EnvelopeFieldsAttemptData<'bank> {
    row: NativeImport18EnvelopeFieldsConstructionData<'bank>,
    failed: bool,
    complete: bool,
    census: EnvelopeFieldsCensus18Data,
    cuts: Vec<Cut<'bank>>,
}

impl<'bank> NativeImport18EnvelopeFieldsAttemptData<'bank> {
    pub(super) fn body_data<'a>(
        &'a self,
        raw: &'a RetainedFrame,
    ) -> Result<&'a serde_json::Map<String, Value>, ProviderError> {
        if self.failed || !self.complete || !std::ptr::eq(self.row.raw, raw) {
            return Err(invalid());
        }
        let body = match &raw.value {
            Value::Object(fields) => fields.get("body"),
            Value::Array(fields) => fields.get(11),
            _ => None,
        }
        .ok_or_else(invalid)?;
        body.as_object().ok_or_else(invalid)
    }

    /// Installs spent failure state before rechecking the independently funded row.
    ///
    /// # Errors
    /// Refuses a reused output, changed actual raw/row, reserve failure, missing
    /// or unknown fields, incorrect types, scalar errors or a failed flat pass.
    /// Every initialized pass and spare Cut capacity stays under the output slot.
    /// The same actual owner is censused on every result after installation,
    /// including foreign rows, reserve failures and failed field prefixes. The
    /// original construction error wins over a later census refusal, while
    /// census_data records whether actual retained storage could be bounded.
    /// No failed/refused census permits dependent allocation or progress; a
    /// future whole-owner caller must retain and include this output and its
    /// returned error in its own actual census. This local observation already
    /// includes the actual returned scalar reason capacity in R; no separate
    /// caller admission is assumed or supplied here.
    pub(crate) fn read_into_data(
        raw: &'bank RetainedFrame,
        row: &NativeImport18EnvelopeFieldsConstructionData<'bank>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            row: *row,
            failed: true,
            complete: false,
            census: EnvelopeFieldsCensus18Data::Pending,
            cuts: Vec::new(),
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        let result = owner.read_fields_data(raw, row);
        let census = owner
            .retained_requested_storage_data(usize::MAX)
            .and_then(|retained| storage::add(retained, error_retained_requested_data(&result)?));
        owner.census = match &census {
            Ok(requested_bytes) => EnvelopeFieldsCensus18Data::Observed {
                requested_bytes: *requested_bytes,
                within_row: *requested_bytes <= row.retained,
            },
            Err(_) => EnvelopeFieldsCensus18Data::Refused,
        };

        // Observation never clears an earlier failed child or replaces its
        // original error. Completion additionally requires this actual census.
        result?;
        if census? > row.retained {
            return Err(exhausted());
        }
        owner.failed = false;
        owner.complete = true;
        Ok(())
    }

    fn read_fields_data(
        &mut self,
        raw: &'bank RetainedFrame,
        row: &NativeImport18EnvelopeFieldsConstructionData<'bank>,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(row.raw, raw) || !std::ptr::eq(row.root, &raw.value) {
            return Err(invalid());
        }
        let current = NativeImport18EnvelopeFieldsConstructionData::quote_data(raw, row.maximum)?;
        if current.cuts > row.cuts
            || current.retained > row.retained
            || current.transient > row.transient
            || current.scratch > row.scratch
        {
            return Err(exhausted());
        }
        self.cuts
            .try_reserve_exact(row.cuts)
            .map_err(|_| exhausted())?;

        visit_fields_data(&raw.value, &mut BorrowedFields { owner: self, raw })
    }

    /// Returns the same owner's actual post-attempt census without allocation.
    ///
    /// Observed storage or a refused census grants no caller admission. Failed
    /// output/error owners remain required in the enclosing complete census.
    /// The recorded local count includes their actual scalar reason backing.
    pub(crate) const fn census_data(&self) -> EnvelopeFieldsCensus18Data {
        self.census
    }

    fn read_cut(
        &mut self,
        raw: &'bank RetainedFrame,
        field: EnvelopeField18Data,
        member: usize,
        input: &'bank Value,
    ) -> Result<(), ProviderError> {
        if self.cuts.len() >= self.row.cuts {
            return Err(exhausted());
        }
        self.cuts.push(Cut {
            field,
            member,
            attempt: None,
        });
        let child = self.cuts.last_mut().ok_or_else(invalid)?;
        let row =
            NativeImport18OwnedValuePassConstructionData::quote_data(raw, input, self.row.maximum)?;
        NativeImport18OwnedValuePassAttemptData::read_into_data(
            raw,
            input,
            &row,
            &mut child.attempt,
        )
    }

    /// Lends a completed actual nullable/member pass without another Value pass.
    ///
    /// A body/Extensions member uses its sorted structural-map index; nullable
    /// fields use zero. The caller supplies the exact original subtree loan.
    ///
    /// # Errors
    /// Refuses a failed attempt, absent cut, changed raw, or foreign input.
    pub(crate) fn completed_cut_data<'a>(
        &'a self,
        raw: &'a RetainedFrame,
        field: EnvelopeField18Data,
        member: usize,
        input: &'a Value,
    ) -> Result<NativeImport18OwnedValuePassViewData<'a>, ProviderError> {
        if self.failed || !self.complete || !std::ptr::eq(self.row.raw, raw) {
            return Err(invalid());
        }
        self.cuts
            .iter()
            .find(|cut| cut.field == field && cut.member == member)
            .and_then(|cut| cut.attempt.as_ref())
            .ok_or_else(invalid)?
            .completed_data(raw, input)
    }

    /// Counts actual spare Cut capacity and every completed or failed child.
    ///
    /// # Errors
    /// Refuses checked overflow or a census exceeding the independently admitted bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            row: _,
            failed: _,
            complete: _,
            census: _,
            cuts,
        } = self;
        let mut retained = storage::sum(&[
            size_of::<Option<Self>>(),
            storage::mul(cuts.capacity(), size_of::<Cut<'bank>>())?,
        ])?;
        for Cut {
            field: _,
            member: _,
            attempt,
        } in cuts
        {
            if let Some(attempt) = attempt {
                retained = storage::add(
                    retained,
                    attempt
                        .retained_requested_storage_data(maximum)?
                        .checked_sub(size_of::<
                            Option<NativeImport18OwnedValuePassAttemptData<'static>>,
                        >())
                        .ok_or_else(invalid)?,
                )?;
            }
        }
        if retained > maximum {
            return Err(exhausted());
        }
        Ok(retained)
    }
}

// Only the defining Id/U64 validators allocate returned error backing here.
// Keep this match exhaustive, count actual String capacity, and refuse an
// unexpected allocating error rather than formatting, cloning or discarding it.
pub(super) fn error_retained_requested_data(
    result: &Result<(), ProviderError>,
) -> Result<usize, ProviderError> {
    use crucible_node_format::ContractError;

    match result {
        Ok(()) => Ok(0),
        Err(ProviderError::Contract(ContractError::Invalid { field: _, reason })) => {
            Ok(reason.capacity())
        }
        Err(
            ProviderError::Contract(ContractError::Overflow)
            | ProviderError::Frame(_)
            | ProviderError::Correlation(_)
            | ProviderError::ResourceExhausted(_)
            | ProviderError::Conflict(_),
        ) => Ok(0),
        Err(ProviderError::Io(_) | ProviderError::Contract(ContractError::Json(_))) => {
            Err(invalid())
        }
    }
}

// The locked Value enum adapter accepts both a String unit variant and its
// externally tagged one-member/null object form. It does not invoke the Raw
// Value visitor for either direct enum field.
fn unit_variant_data(input: &Value) -> Result<&str, ProviderError> {
    match input {
        Value::String(value) => Ok(value),
        Value::Object(fields) if fields.len() == 1 => {
            let (key, value) = fields.iter().next().ok_or_else(invalid)?;
            if !value.is_null() {
                return Err(invalid());
            }
            Ok(key)
        }
        _ => Err(invalid()),
    }
}

fn message_data(input: &Value) -> Result<MessageKind, ProviderError> {
    match unit_variant_data(input)? {
        "request" => Ok(MessageKind::Request),
        "response" => Ok(MessageKind::Response),
        "event" => Ok(MessageKind::Event),
        _ => Err(invalid()),
    }
}

fn method_data(input: &Value) -> Result<Method, ProviderError> {
    Ok(match unit_variant_data(input)? {
        "hello" => Method::Hello,
        "discover" => Method::Discover,
        "realize" => Method::Realize,
        "admit" => Method::Admit,
        "native_import18_bootstrap" => Method::NativeImport18Bootstrap,
        "activate" => Method::Activate,
        "input" => Method::Input,
        "observe" => Method::Observe,
        "begin" => Method::Begin,
        "poll" => Method::Poll,
        "cancel" => Method::Cancel,
        "quantum_close" => Method::QuantumClose,
        "world_activate" => Method::WorldActivate,
        "abort" => Method::Abort,
        "retire" => Method::Retire,
        "blob_begin" => Method::BlobBegin,
        "blob_chunk" => Method::BlobChunk,
        "blob_finish" => Method::BlobFinish,
        "release" => Method::Release,
        "operation_update" => Method::OperationUpdate,
        "observation_ready" => Method::ObservationReady,
        "provider_fault" => Method::ProviderFault,
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "envelope_fields/tests.rs"]
mod tests;

fn schedule_counter_scratch_data() -> usize {
    size_of::<BorrowedFields<'static, 'static>>()
        + size_of::<&mut BorrowedFields<'static, 'static>>()
        + size_of::<&Value>()
        + size_of::<Option<&str>>()
        + size_of::<(&String, &Value)>()
        + size_of::<(usize, (&String, &Value))>()
        + size_of::<Option<(usize, (&String, &Value))>>()
        + size_of::<std::iter::Enumerate<serde_json::map::Iter<'static>>>()
}
