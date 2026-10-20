//! Retains actual common Shape.validate effects after the shared cut cursor.
//!
//! The actual cursor stays owned and immutable during short header/NEXT loans.
//! No request selection, extra Value pass, recursive DTO or live grant is added.

use super::owning::NativeImport18OwningResponseAttemptData;
use super::schedule::Status;
use super::*;
use crate::bodies::{EffectCertainty, OperationState};
use crucible_node_format::Id;

mod storage;
mod string_copy;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[derive(Clone, Copy)]
pub(super) enum ErrorScalar {
    Code,
    Message,
    Effect,
    Retryable,
}

pub(super) struct ErrorInput<'a> {
    pub(super) code: &'a str,
    pub(super) message: &'a str,
    pub(super) effect: EffectCertainty,
    pub(super) retryable: bool,
    pub(super) order: [ErrorScalar; 4],
}

pub(super) struct HeaderInput<'a> {
    pub(super) status: Status,
    pub(super) operation: OperationState,
    pub(super) error: Option<ErrorInput<'a>>,
}

enum CodeCheck {
    String(String),
    Valid(Id),
    Invalid(String),
}

struct ErrorFields {
    code: Option<String>,
    message: Option<String>,
    effect: Option<EffectCertainty>,
    retryable: Option<bool>,
    code_check: Option<CodeCheck>,
}

struct Fields {
    status: Option<Status>,
    operation: Option<OperationState>,
    error: Option<ErrorFields>,
    details_bytes: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Taken,
    Quoted,
    Complete,
    Failed,
}

#[derive(Clone, Copy)]
struct Plan {
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

/// Records actual current cursor/scalar backing and the then-live returned error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18ShapeValidateCensusData {
    /// Marks installed input custody before observation.
    Pending,
    /// Counts actual capacities without renewing any admission.
    Observed {
        /// Includes current root/cursor/scalars and the actual current error.
        requested_bytes: usize,
        /// Compares only with this same stored prospective row, when present.
        within_row: Option<bool>,
    },
    /// Records checked actual observation refusal.
    Refused,
}

/// Owns the actual common Shape.validate attempt and all scalar failure prefixes.
///
/// Completion describes common response DATA only. It is no selected-method,
/// request/read-only check, result/receipt DTO, Source or currentness witness.
pub(crate) struct NativeImport18ShapeValidateAttemptData {
    source: Option<NativeImport18OwningResponseAttemptData>,
    fields: Fields,
    row: Option<Plan>,
    stage: Stage,
    census: NativeImport18ShapeValidateCensusData,
}

impl NativeImport18ShapeValidateAttemptData {
    /// Names the additional root, actual initializer and complete prequote S.
    ///
    /// Original cursor backing remains independently charged before transfer.
    pub(crate) fn take_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            storage::initializer_data(),
            storage::counter_data(),
        )
    }

    /// Roots the exact cursor before checking schema completion or census.
    ///
    /// # Errors
    /// Refuses reuse, absent/failed/incomplete cursor or actual observation.
    /// Every installed refusal retains the original input and all prior history.
    pub(crate) fn take_into_data(
        input: &mut Option<NativeImport18OwningResponseAttemptData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            source: None,
            fields: Fields {
                status: None,
                operation: None,
                error: None,
                details_bytes: None,
            },
            row: None,
            stage: Stage::Taking,
            census: NativeImport18ShapeValidateCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.source = input.take();
        let result = (|| {
            owner
                .source
                .as_ref()
                .ok_or_else(invalid)?
                .shape_header_data()?;
            owner.stage = Stage::Taken;
            Ok(())
        })();
        owner.observe_data(result)
    }

    /// Quotes actual scalar copies, Id/result windows and shared canonical S.
    ///
    /// Keep fixed take S admitted before entry. Independently admit the full
    /// returned row beside current parent/error custody before run_data.
    ///
    /// # Errors
    /// Refuses reuse, actual scalar source, checked layout or supplied bound.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Taken {
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
        self.observe_data(result)
    }

    /// Returns complete actual demand, without authorizing this or later stages.
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

    /// Rechecks before effects, then performs the exact common validator order.
    ///
    /// Error code Id precedes message bound, which precedes canonical(details).
    /// All actual NEXT owners stay rooted and immutable during the one checker.
    ///
    /// # Errors
    /// Refuses reuse, short row, actual validator failure or whole-owner census.
    /// The original error and exact invalid owned code backing remain retained.
    pub(crate) fn run_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let Self {
                source,
                fields,
                row,
                census,
                ..
            } = self;
            let source = source.as_ref().ok_or_else(invalid)?;
            let row = row.as_ref().ok_or_else(invalid)?;
            let current = storage::quote_data(source, row.maximum)?;
            if current.retained > row.retained
                || current.transient > row.transient
                || current.scratch > row.scratch
            {
                return Err(exhausted());
            }
            let input = source.shape_header_data()?;
            fields.status = Some(input.status);
            fields.operation = Some(input.operation);
            observe_parts_data(Some(source), fields, Some(row), census, Ok(()))?;
            match input.status {
                Status::Accepted if input.operation != OperationState::Running => {
                    return Err(crate::bodies::invalid(
                        "operation_state",
                        "accepted response requires running custody",
                    )
                    .into());
                }
                Status::Completed if input.operation != OperationState::Completed => {
                    return Err(crate::bodies::invalid(
                        "operation_state",
                        "completed response requires completed custody",
                    )
                    .into());
                }
                Status::Error => {
                    let input = input.error.ok_or_else(invalid)?;
                    fields.error = Some(ErrorFields {
                        code: None,
                        message: None,
                        effect: None,
                        retryable: None,
                        code_check: None,
                    });
                    observe_parts_data(Some(source), fields, Some(row), census, Ok(()))?;
                    for scalar in input.order {
                        let error = fields.error.as_mut().ok_or_else(invalid)?;
                        match scalar {
                            ErrorScalar::Code => error.code = Some(String::from(input.code)),
                            ErrorScalar::Message => {
                                error.message = Some(String::from(input.message))
                            }
                            ErrorScalar::Effect => error.effect = Some(input.effect),
                            ErrorScalar::Retryable => error.retryable = Some(input.retryable),
                        }
                        observe_parts_data(Some(source), fields, Some(row), census, Ok(()))?;
                    }
                    let error = fields.error.as_mut().ok_or_else(invalid)?;
                    error.code_check = Some(CodeCheck::String(
                        error.code.as_ref().ok_or_else(invalid)?.clone(),
                    ));
                    observe_parts_data(Some(source), fields, Some(row), census, Ok(()))?;
                    let error = fields.error.as_mut().ok_or_else(invalid)?;
                    let Some(CodeCheck::String(code)) = error.code_check.take() else {
                        return Err(invalid());
                    };
                    match Id::try_from_owned(code) {
                        Ok(id) => error.code_check = Some(CodeCheck::Valid(id)),
                        Err(refusal) => {
                            let (code, reason) = refusal.into_parts();
                            error.code_check = Some(CodeCheck::Invalid(code));
                            return Err(ProviderError::Contract(reason));
                        }
                    }
                    observe_parts_data(Some(source), fields, Some(row), census, Ok(()))?;
                    if fields
                        .error
                        .as_ref()
                        .and_then(|error| error.message.as_ref())
                        .ok_or_else(invalid)?
                        .len()
                        > 4096
                    {
                        return Err(crate::bodies::invalid(
                            "message",
                            "error message exceeds 4096 UTF-8 bytes",
                        )
                        .into());
                    }
                    fields.details_bytes =
                        Some(canonical::owned_error_details_extent_data(source)?);
                }
                _ => {}
            }
            Ok(())
        })();
        self.observe_data(result)?;
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Reports failed/completed common-validation DATA, never a live route grant.
    pub(crate) const fn state_data(&self) -> (bool, bool) {
        (
            matches!(self.stage, Stage::Failed),
            matches!(self.stage, Stage::Complete),
        )
    }

    /// Returns actual checked details extent only after that validator completed.
    pub(crate) const fn error_details_canonical_bytes_data(&self) -> Option<usize> {
        self.fields.details_bytes
    }

    /// Returns the current actual observation snapshot without renewing credit.
    pub(crate) const fn census_data(&self) -> NativeImport18ShapeValidateCensusData {
        self.census
    }

    /// Lends the original immutable receipt even after a validation refusal.
    ///
    /// # Errors
    /// Refuses a transfer that never received a cursor.
    pub(crate) fn retained_frame_data(&self) -> Result<&RetainedFrame, ProviderError> {
        self.source
            .as_ref()
            .ok_or_else(invalid)?
            .retained_frame_data()
    }

    /// Counts actual current source/scalars; callers add their current held error.
    ///
    /// # Errors
    /// Refuses source/flat observation, checked overflow or supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        storage::retained_data(self.source.as_ref(), &self.fields, maximum)
    }

    fn observe_data(&mut self, result: Result<(), ProviderError>) -> Result<(), ProviderError> {
        let returned = observe_parts_data(
            self.source.as_ref(),
            &self.fields,
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

fn observe_parts_data(
    source: Option<&NativeImport18OwningResponseAttemptData>,
    fields: &Fields,
    row: Option<&Plan>,
    census: &mut NativeImport18ShapeValidateCensusData,
    result: Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let observed = storage::retained_data(source, fields, usize::MAX).and_then(|bytes| {
        add(
            bytes,
            super::super::super::envelope_fields::error_retained_requested_data(&result)?,
        )
    });
    *census = match &observed {
        Ok(bytes) => NativeImport18ShapeValidateCensusData::Observed {
            requested_bytes: *bytes,
            within_row: row.map(|row| *bytes <= row.retained),
        },
        Err(_) => NativeImport18ShapeValidateCensusData::Refused,
    };
    result?;
    if let Some(row) = row {
        if observed? > row.retained {
            return Err(exhausted());
        }
    } else {
        observed?;
    }
    Ok(())
}
