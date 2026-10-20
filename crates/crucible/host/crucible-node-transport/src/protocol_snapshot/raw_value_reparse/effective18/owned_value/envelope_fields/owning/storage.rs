//! Quotes actual typed headers, member keys, owning FIRST cuts and shared raw.

use super::super::super::storage::{add, mul};
use super::*;

type NullableIter<'a> = std::slice::Iter<'a, Option<Option<Id>>>;
type NullableSlots<'a> = std::iter::Flatten<NullableIter<'a>>;
type NullableValues<'a> = std::iter::Flatten<NullableSlots<'a>>;

pub(super) fn quote_data(
    source: &NativeImport18RawSelectionData,
    maximum: usize,
) -> Result<Plan, ProviderError> {
    let raw = source.retained_frame_data()?;
    if !std::ptr::eq(source.value_data()?, &raw.value) {
        return Err(invalid());
    }
    let borrowed = NativeImport18EnvelopeFieldsConstructionData::quote_data(raw, maximum)?;
    // The existing exact cut quote already contains each flat state's backing
    // and the possible returned scalar reason. Replace only actual root/slots.
    let cut_headers = mul(borrowed.cuts, size_of::<Cut<'static>>())?;
    let flat = borrowed
        .retained
        .checked_sub(size_of::<
            Option<NativeImport18EnvelopeFieldsAttemptData<'static>>,
        >())
        .and_then(|bytes| bytes.checked_sub(cut_headers))
        .ok_or_else(invalid)?;
    let raw_backing = source
        .retained_requested_storage_data(maximum)?
        .checked_sub(size_of::<Option<NativeImport18RawSelectionData>>())
        .ok_or_else(invalid)?;
    let mut retained = add(
        size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>(),
        raw_backing,
    )?;
    retained = add(retained, mul(borrowed.cuts, size_of::<OwnedCut>())?)?;
    retained = add(retained, flat)?;
    let (_, first_t, first_s) = NativeImport18OwningFirstAttemptData::take_requested_storage_data();
    let nullable_initializer = size_of::<Id>()
        + size_of::<Option<Id>>()
        + size_of::<Option<Option<Id>>>()
        + size_of::<String>();
    let mut transient = add(borrowed.transient, nullable_initializer)?
        .max(initializer_data())
        .max(first_t)
        .max(cut_initializer_data());
    let mut scratch = add(counter_data(), borrowed.scratch.max(first_s))?;
    if let Ok(mut fields) = Fields::new(&raw.value) {
        while let Some(field) = fields.next() {
            let Ok((field, input)) = field else {
                continue;
            };
            if field == EnvelopeField18Data::Protocol {
                if let Some(value) = input.as_str() {
                    retained = add(retained, value.len())?;
                    transient = transient.max(add(
                        value.len(),
                        size_of::<String>() * 2 + size_of::<Option<String>>(),
                    )?);
                }
            } else if field.nullable() {
                let maximum_string = {
                    let mut source_strings = walk::Walk::new_data(input);
                    let mut maximum_string = 0;
                    while let Some((value, _)) = source_strings.next_data()? {
                        if let Value::String(value) = value {
                            maximum_string = maximum_string.max(value.len());
                        }
                    }
                    maximum_string
                };
                // A successfully owned Id is constrained by the existing Id
                // decoder to at most 128 bytes; failures retain only its reason.
                // Actual source String extent supplies the other bound.
                retained = add(retained, maximum_string.min(128))?;
                let member = source.member_row_data(input, maximum)?;
                let (_, t, s) = member.requested_storage_data();
                transient = transient.max(t);
                scratch = scratch.max(add(counter_data(), s)?);
            } else if field.structural() {
                if let Some(values) = input.as_object() {
                    for (key, value) in values {
                        retained = add(retained, key.len())?;
                        transient = transient.max(add(
                            cut_initializer_data(),
                            add(
                                key.len(),
                                size_of::<String>() * 2 + size_of::<Option<String>>(),
                            )?,
                        )?);
                        let member = source.member_row_data(value, maximum)?;
                        let (_, t, s) = member.requested_storage_data();
                        transient = transient.max(t);
                        scratch = scratch.max(add(counter_data(), s)?);
                    }
                }
            }
        }
    }
    if add(add(retained, transient)?, scratch)? > maximum {
        return Err(exhausted());
    }
    Ok(Plan {
        maximum,
        cuts: borrowed.cuts,
        retained,
        transient,
        scratch,
    })
}

pub(super) fn initializer_data() -> usize {
    size_of::<NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>()
        + size_of::<Data>() * 2
        + size_of::<Header>() * 2
        + size_of::<[Option<Option<Id>>; 7]>() * 2
        + size_of::<Vec<OwnedCut>>()
        + size_of::<NativeImport18RawSelectionData>()
        + size_of::<Option<NativeImport18RawSelectionData>>()
}

fn cut_initializer_data() -> usize {
    size_of::<OwnedCut>() * 2
        + size_of::<Option<String>>()
        + size_of::<Option<NativeImport18RawSelectionData>>()
        + size_of::<Option<NativeImport18OwningFirstAttemptData>>()
}

pub(super) fn counter_data() -> usize {
    let rows = size_of::<Plan>() * 2
        + size_of::<Result<Plan, ProviderError>>()
        + size_of::<Option<Plan>>()
        + size_of::<&Plan>() * 3
        + size_of::<NativeImport18EnvelopeFieldsConstructionData<'static>>()
        + size_of::<Result<NativeImport18EnvelopeFieldsConstructionData<'static>, ProviderError>>()
        + size_of::<&NativeImport18RawSelectionConstructionData<'static>>()
        + size_of::<NativeImport18RawSelectionConstructionData<'static>>() * 2
        + size_of::<Result<NativeImport18RawSelectionConstructionData<'static>, ProviderError>>()
        + size_of::<CanonicalPlan>() * 2
        + size_of::<Result<CanonicalPlan, ProviderError>>()
        + size_of::<Option<CanonicalPlan>>()
        + size_of::<&CanonicalPlan>()
        + size_of::<(usize, usize, usize)>() * 2
        + size_of::<Result<(usize, usize, usize), ProviderError>>();
    let outer = size_of::<NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>()
        + size_of::<&mut Option<NativeImport18OwningEnvelopeAttemptData>>()
        + size_of::<&mut NativeImport18OwningEnvelopeAttemptData>() * 2
        + size_of::<&NativeImport18OwningEnvelopeAttemptData>() * 2
        + size_of::<Data>() * 2
        + size_of::<&Data>() * 2
        + size_of::<&mut Data>()
        + size_of::<Header>() * 2
        + size_of::<&Header>()
        + size_of::<[Option<Option<Id>>; 7]>() * 2
        + size_of::<Stage>()
        + size_of::<NativeImport18OwningEnvelopeCensusData>()
        + size_of::<&mut NativeImport18OwningEnvelopeCensusData>() * 2;
    let sources = size_of::<NativeImport18RawSelectionData>()
        + size_of::<Option<NativeImport18RawSelectionData>>()
        + size_of::<&mut Option<NativeImport18RawSelectionData>>()
        + size_of::<&NativeImport18RawSelectionData>() * 4
        + size_of::<Option<&NativeImport18RawSelectionData>>()
        + size_of::<&RetainedFrame>() * 2
        + size_of::<Result<&RetainedFrame, ProviderError>>()
        + size_of::<&Value>() * 4
        + size_of::<Result<&Value, ProviderError>>()
        + size_of::<OwningFields<'static>>()
        + size_of::<&mut OwningFields<'static>>()
        + size_of::<Option<&str>>() * 2
        + size_of::<&str>() * 3;
    let cuts = size_of::<Vec<OwnedCut>>()
        + size_of::<OwnedCut>() * 2
        + size_of::<&mut Vec<OwnedCut>>()
        + size_of::<&Vec<OwnedCut>>()
        + size_of::<std::slice::Iter<'static, OwnedCut>>() * 2
        + size_of::<&mut OwnedCut>()
        + size_of::<Option<&mut OwnedCut>>()
        + size_of::<&OwnedCut>() * 2
        + size_of::<&&OwnedCut>()
        + size_of::<Option<&OwnedCut>>()
        + size_of::<&EnvelopeField18Data>()
        + size_of::<&usize>()
        + size_of::<&mut Option<NativeImport18OwningFirstAttemptData>>()
        + size_of::<&mut NativeImport18OwningFirstAttemptData>() * 2
        + size_of::<Option<&mut NativeImport18OwningFirstAttemptData>>() * 2
        + size_of::<&Option<NativeImport18OwningFirstAttemptData>>()
        + size_of::<&NativeImport18OwningFirstAttemptData>() * 2
        + size_of::<Option<&NativeImport18OwningFirstAttemptData>>()
        + size_of::<NativeImport18FirstFlatViewData<'static>>()
        + size_of::<Result<NativeImport18FirstFlatViewData<'static>, ProviderError>>()
        + size_of::<NativeImport18FirstFlatKindData<'static>>()
        + size_of::<Result<NativeImport18FirstFlatKindData<'static>, ProviderError>>()
        + size_of::<Option<String>>()
        + size_of::<String>() * 2
        + size_of::<&String>()
        + size_of::<Option<&String>>();
    let ids = size_of::<NullableIter<'static>>()
        + size_of::<NullableSlots<'static>>()
        + size_of::<NullableValues<'static>>()
        + size_of::<&Option<Option<Id>>>()
        + size_of::<&Option<Id>>()
        + size_of::<&Id>()
        + size_of::<Option<&Option<Id>>>()
        + size_of::<Option<&Id>>()
        + size_of::<&mut NullableValues<'static>>()
        + size_of::<Option<Id>>()
        + size_of::<Option<Option<Id>>>()
        + size_of::<Id>()
        + size_of::<Result<Id, crucible_node_format::ContractError>>()
        + size_of::<Option<MessageKind>>()
        + size_of::<Option<U64>>()
        + size_of::<Option<Method>>();
    rows + outer
        + sources
        + cuts
        + ids
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<&Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<&Result<usize, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 25
        // Actual shared canonical transient-quote sum/fold controls execute
        // before its returned complete checker row can be admitted.
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + NativeImport18EnvelopeFieldsConstructionData::counter_scratch_data()
        + NativeImport18RawSelectionData::member_counter_scratch_data()
        + NativeImport18OwningFirstConstructionData::counter_scratch_data()
}

pub(super) fn canonical_quote_data(
    owner: &NativeImport18OwningEnvelopeAttemptData,
    maximum: usize,
) -> Result<CanonicalPlan, ProviderError> {
    let retained = owner.retained_requested_storage_data(maximum)?;
    let transient = super::super::super::next_value::response_shape::canonical::transient_data()?;
    let scratch = add(
        counter_data(),
        super::super::super::next_value::response_shape::canonical::owned_counter_scratch_data(),
    )?;
    if add(add(retained, transient)?, scratch)? > maximum {
        return Err(exhausted());
    }
    Ok(CanonicalPlan {
        maximum,
        retained,
        transient,
        scratch,
    })
}

// Additional direct controls for the actual scoped body-FIRST transfer. The
// shared upstream transfer counter is independently included by its caller.
pub(super) fn transfer_counter_data() -> usize {
    size_of::<&mut NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<std::slice::IterMut<'static, OwnedCut>>()
        + size_of::<&mut std::slice::IterMut<'static, OwnedCut>>()
        + size_of::<Option<&mut OwnedCut>>()
        + size_of::<&mut OwnedCut>()
        + size_of::<&&mut OwnedCut>()
        + size_of::<&mut Option<NativeImport18OwningFirstAttemptData>>()
        + size_of::<&mut Option<super::super::super::next_value::NativeImport18FirstBankCustodyData>>(
        )
        + size_of::<Stage>()
        + size_of::<usize>() * 2
        + size_of::<&usize>()
        + size_of::<&EnvelopeField18Data>()
        + size_of::<Result<(), ProviderError>>()
}
