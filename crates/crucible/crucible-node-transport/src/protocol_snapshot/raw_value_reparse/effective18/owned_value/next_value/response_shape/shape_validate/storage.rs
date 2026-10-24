//! Quotes actual scalar ownership, validator windows and complete reader controls.

use super::*;

fn reason_bytes_data() -> usize {
    // Exact current defining Id::try_from_owned and ResponseShape/ErrorRecord
    // validators. These are returned String backing, not an admission cap.
    "expected 1–128 bounded ASCII identifier bytes"
        .len()
        .max("accepted response requires running custody".len())
        .max("completed response requires completed custody".len())
        .max("error message exceeds 4096 UTF-8 bytes".len())
}

pub(super) fn quote_data(
    source: &NativeImport18OwningResponseAttemptData,
    maximum: usize,
) -> Result<Plan, ProviderError> {
    let input = source.shape_header_data()?;
    let mut retained = retained_data(
        Some(source),
        &Fields {
            status: None,
            operation: None,
            error: None,
            details_bytes: None,
        },
        maximum,
    )?;
    let mut scalar_bytes = 0;
    if let Some(error) = &input.error {
        retained = add(
            retained,
            add(
                add(error.code.len(), error.code.len())?,
                error.message.len(),
            )?,
        )?;
        scalar_bytes = error.code.len().max(error.message.len());
    }
    retained = add(retained, reason_bytes_data())?;
    let scalar = add(
        add(scalar_bytes, reason_bytes_data())?,
        scalar_initializer_data(),
    )?;
    let transient = initializer_data()
        .max(scalar)
        .max(canonical::transient_data()?);
    let scratch = counter_data();
    if add(add(retained, transient)?, scratch)? > maximum {
        return Err(exhausted());
    }
    Ok(Plan {
        maximum,
        retained,
        transient,
        scratch,
    })
}

pub(super) fn retained_data(
    source: Option<&NativeImport18OwningResponseAttemptData>,
    fields: &Fields,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut retained = size_of::<Option<NativeImport18ShapeValidateAttemptData>>();
    if let Some(source) = source {
        retained = add(
            retained,
            source
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18OwningResponseAttemptData>>())
                .ok_or_else(invalid)?,
        )?;
    }
    if let Some(error) = &fields.error {
        if let Some(code) = &error.code {
            retained = add(retained, code.capacity())?;
        }
        if let Some(message) = &error.message {
            retained = add(retained, message.capacity())?;
        }
        if let Some(code) = &error.code_check {
            retained = add(
                retained,
                match code {
                    CodeCheck::String(value) | CodeCheck::Invalid(value) => value.capacity(),
                    CodeCheck::Valid(value) => value.allocated_capacity(),
                },
            )?;
        }
    }
    if retained > maximum {
        return Err(exhausted());
    }
    Ok(retained)
}

fn scalar_initializer_data() -> usize {
    size_of::<ErrorFields>() * 2
        + size_of::<Option<ErrorFields>>()
        + size_of::<String>() * 4
        + size_of::<Option<String>>() * 2
        + size_of::<CodeCheck>() * 2
        + size_of::<Option<CodeCheck>>()
        + size_of::<Id>()
        + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
        + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
        + size_of::<(String, crucible_node_format::ContractError)>()
        + size_of::<crucible_node_format::ContractError>()
        + size_of::<ProviderError>()
        + string_copy::transient_data()
}

pub(super) fn initializer_data() -> usize {
    size_of::<NativeImport18ShapeValidateAttemptData>()
        + size_of::<Option<NativeImport18ShapeValidateAttemptData>>()
        + size_of::<Fields>() * 2
        + size_of::<NativeImport18OwningResponseAttemptData>()
        + size_of::<Option<NativeImport18OwningResponseAttemptData>>()
        + size_of::<HeaderInput<'static>>() * 2
        + size_of::<ErrorInput<'static>>() * 2
        + size_of::<Option<ErrorInput<'static>>>()
        + size_of::<Result<ErrorInput<'static>, ProviderError>>()
        + size_of::<[ErrorScalar; 4]>() * 2
        + scalar_initializer_data()
}

pub(super) fn counter_data() -> usize {
    type Owner = NativeImport18ShapeValidateAttemptData;
    type ContractError = crucible_node_format::ContractError;
    size_of::<Owner>()
        + size_of::<Option<Owner>>()
        + size_of::<&Owner>() * 3
        + size_of::<&mut Owner>() * 3
        + size_of::<&mut Option<Owner>>()
        + size_of::<Option<&mut Owner>>()
        + size_of::<Result<&mut Owner, ProviderError>>()
        + size_of::<NativeImport18OwningResponseAttemptData>()
        + size_of::<Option<NativeImport18OwningResponseAttemptData>>()
        + size_of::<&NativeImport18OwningResponseAttemptData>() * 5
        + size_of::<Option<&NativeImport18OwningResponseAttemptData>>() * 3
        + size_of::<Result<&NativeImport18OwningResponseAttemptData, ProviderError>>()
        + size_of::<&mut Option<NativeImport18OwningResponseAttemptData>>()
        + size_of::<Plan>() * 3
        + size_of::<Option<Plan>>()
        + size_of::<Result<Plan,ProviderError>>()
        + size_of::<&Plan>() * 4
        + size_of::<Option<&Plan>>() * 2
        + size_of::<Result<&Plan, ProviderError>>()
        + size_of::<&mut Option<Plan>>()
        + size_of::<Fields>() * 2
        + size_of::<&Fields>() * 3
        + size_of::<&mut Fields>()
        + size_of::<ErrorFields>() * 2
        + size_of::<Option<ErrorFields>>()
        + size_of::<&ErrorFields>() * 3
        + size_of::<&mut ErrorFields>() * 3
        + size_of::<Option<&ErrorFields>>()
        + size_of::<Option<&mut ErrorFields>>()
        + size_of::<Result<&mut ErrorFields, ProviderError>>()
        + size_of::<HeaderInput<'static>>() * 2
        + size_of::<Result<HeaderInput<'static>,ProviderError>>()
        + size_of::<ErrorInput<'static>>()
        + size_of::<Option<ErrorInput<'static>>>()
        + size_of::<Result<ErrorInput<'static>, ProviderError>>()
        + size_of::<&ErrorInput<'static>>()
        + size_of::<[ErrorScalar;4]>() * 2
        + size_of::<std::array::IntoIter<ErrorScalar,4>>()
        + size_of::<ErrorScalar>()
        + size_of::<String>() * 4
        + size_of::<&String>() * 4
        + size_of::<Option<String>>() * 2
        + size_of::<Option<&String>>() * 2
        + size_of::<Result<&String, ProviderError>>()
        + size_of::<CodeCheck>() * 2
        + size_of::<Option<CodeCheck>>() * 2
        + size_of::<&CodeCheck>()
        + size_of::<Option<&CodeCheck>>()
        + size_of::<Id>()
        + size_of::<&Id>()
        // Actual Id::is_valid_str byte iterator and grammar predicate controls.
        + size_of::<std::str::Bytes<'static>>() * 2
        + size_of::<&mut std::str::Bytes<'static>>()
        + size_of::<Option<u8>>()
        + size_of::<u8>() * 2
        + size_of::<&u8>()
        + size_of::<&[u8]>()
        + size_of::<ContractError>() * 2
        + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
        + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
        + size_of::<(String,ContractError)>()
        + size_of::<Status>()
        + size_of::<Option<Status>>()
        + size_of::<OperationState>()
        + size_of::<Option<OperationState>>()
        + size_of::<EffectCertainty>()
        + size_of::<Option<EffectCertainty>>()
        + size_of::<Stage>()
        + size_of::<NativeImport18ShapeValidateCensusData>()
        + size_of::<&mut NativeImport18ShapeValidateCensusData>() * 2
        + size_of::<Option<bool>>() * 2
        + size_of::<bool>() * 4
        + size_of::<Result<(),ProviderError>>() * 4
        + size_of::<&Result<(),ProviderError>>()
        + size_of::<Result<usize,ProviderError>>() * 4
        + size_of::<&Result<usize,ProviderError>>()
        + size_of::<&usize>() * 3
        + size_of::<usize>() * 14
        + size_of::<Option<usize>>()
        + size_of::<&str>() * 4
        + size_of::<(usize,usize,usize)>()
        + size_of::<Result<(usize,usize,usize),ProviderError>>()
        + size_of::<&RetainedFrame>()
        + size_of::<Result<&RetainedFrame,ProviderError>>()
        // canonical::transient_data's sum executes during quote, before its
        // returned demand can be admitted. These are its own direct operands.
        + size_of::<[usize;3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static,usize>>()
        + size_of::<&mut std::slice::Iter<'static,usize>>()
        + size_of::<&usize>()
        + size_of::<Result<usize,ProviderError>>()
        + NativeImport18OwningResponseAttemptData::take_requested_storage_data().2
        + NativeImport18OwningResponseAttemptData::shape_header_counter_data()
        + canonical::error_details_counter_data()
        + string_copy::counter_data()
}
