//! Prices each actual cursor effect and current complete failure custody.

use super::*;

pub(super) fn quote_data(
    owner: &NativeImport18OwningResponseAttemptData,
    maximum: usize,
) -> Result<Plan, ProviderError> {
    let action = owner.action.ok_or_else(invalid)?;
    let current = retained_data(owner, maximum)?;
    let mut retained = current;
    let mut transient = initializer_data();
    let mut scratch = counter_data();
    let child = match action {
        Action::Start => {
            let count = owner
                .envelope
                .as_ref()
                .ok_or_else(invalid)?
                .body_data()?
                .len();
            retained = add(retained, mul(count, size_of::<BankSlot>())?)?;
            None
        }
        Action::Advance | Action::QuoteFirst => None,
        Action::TakeFirst => {
            let route = owner.pending.as_ref().ok_or_else(invalid)?.cut.route;
            let first = owner
                .envelope
                .as_ref()
                .ok_or_else(invalid)?
                .cut_first_data(EnvelopeField18Data::Body, route.body)?;
            // The transfer observer conservatively charges its complete raw
            // input beside the Envelope's sealed single-raw census. Include
            // that real change of accounting boundary before moving FIRST.
            retained = add(retained, first.retained_requested_storage_data(maximum)?)?;
            Some(NativeImport18FirstBankCustodyData::transfer_requested_storage_data())
        }
        Action::FreezeFirst => Some(custody_data(owner)?.requested_storage_data()?),
        Action::Select => {
            let route = owner.pending.as_ref().ok_or_else(invalid)?.cut.route;
            let bank = custody_data(owner)?.completed_bank_data()?;
            Some(selection_row_data(bank, route, maximum)?.requested_storage_data())
        }
        Action::TakeNext => {
            Some(NativeImport18OwningNextAttemptData::take_requested_storage_data())
        }
        // Quote the actual physical population without constructing a logical
        // spine. This is the existing prewalk primitive, rechecked by the
        // owning NEXT stage before its independently admitted quote.
        Action::PrewalkNext => {
            let next = next_data(owner)?;
            let input = next.retained_selection_data()?.input_data()?;
            let prewalk = NativeImport18NextValuePrewalkData::quote_data(input, maximum)?;
            let (r, t, s) = prewalk.requested_storage_data();
            Some((
                r,
                t,
                add(
                    NativeImport18OwningNextAttemptData::take_requested_storage_data().2,
                    s,
                )?,
            ))
        }
        Action::QuoteNext => Some(next_data(owner)?.prewalk_requested_storage_data()?),
        Action::RunNext => Some(next_data(owner)?.requested_storage_data()?),
        Action::Commit => {
            retained = add(retained, size_of::<Pending>())?;
            // Reserve can relocate all prior headers before the pending move.
            // Every prior dynamic backing remains rooted and separately counted.
            transient = add(
                transient,
                mul(owner.history.capacity(), size_of::<Pending>())?,
            )?;
            None
        }
    };
    if let Some((r, t, s)) = child {
        // Deliberately conservative: full child backing stays charged beside
        // the actual current parent. No generic shared-allocation discount.
        retained = add(retained, r)?;
        transient = transient.max(add(initializer_data(), t)?);
        scratch = add(scratch, s)?;
    }
    if sum(&[retained, transient, scratch])? > maximum {
        return Err(exhausted());
    }
    Ok(Plan {
        action,
        maximum,
        retained,
        transient,
        scratch,
    })
}

fn custody_data(
    owner: &NativeImport18OwningResponseAttemptData,
) -> Result<&NativeImport18FirstBankCustodyData, ProviderError> {
    let body = owner.pending.as_ref().ok_or_else(invalid)?.cut.route.body;
    owner
        .banks
        .get(body)
        .and_then(|slot| slot.custody.as_ref())
        .ok_or_else(invalid)
}

fn next_data(
    owner: &NativeImport18OwningResponseAttemptData,
) -> Result<&NativeImport18OwningNextAttemptData, ProviderError> {
    owner
        .pending
        .as_ref()
        .and_then(|pending| pending.next.as_ref())
        .ok_or_else(invalid)
}

pub(super) fn retained_data(
    owner: &NativeImport18OwningResponseAttemptData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut retained = size_of::<Option<NativeImport18OwningResponseAttemptData>>();
    if let Some(envelope) = &owner.envelope {
        retained = add(
            retained,
            envelope
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>())
                .ok_or_else(invalid)?,
        )?;
    }
    retained = add(
        retained,
        mul(owner.banks.capacity(), size_of::<BankSlot>())?,
    )?;
    retained = add(
        retained,
        mul(owner.history.capacity(), size_of::<Pending>())?,
    )?;
    for bank in &owner.banks {
        if let Some(custody) = &bank.custody {
            retained = add(
                retained,
                custody
                    .retained_requested_storage_data(maximum)?
                    .checked_sub(size_of::<Option<NativeImport18FirstBankCustodyData>>())
                    .ok_or_else(invalid)?,
            )?;
        }
    }
    for pending in owner.history.iter().chain(owner.pending.iter()) {
        if let Some(selection) = &pending.selection {
            retained = add(
                retained,
                selection
                    .retained_requested_storage_data(maximum)?
                    .checked_sub(size_of::<Option<NativeImport18FirstSelectionData>>())
                    .ok_or_else(invalid)?,
            )?;
        }
        if let Some(next) = &pending.next {
            retained = add(
                retained,
                next.retained_requested_storage_data(maximum)?
                    .checked_sub(size_of::<Option<NativeImport18OwningNextAttemptData>>())
                    .ok_or_else(invalid)?,
            )?;
        }
    }
    if retained > maximum {
        return Err(exhausted());
    }
    Ok(retained)
}

pub(super) fn observe_capacity_data(
    owner: &NativeImport18OwningResponseAttemptData,
) -> Result<(), ProviderError> {
    let retained = retained_data(owner, usize::MAX)?;
    if retained > owner.row.as_ref().ok_or_else(invalid)?.retained {
        return Err(exhausted());
    }
    Ok(())
}

pub(super) fn initializer_data() -> usize {
    size_of::<NativeImport18OwningResponseAttemptData>()
        + size_of::<Option<NativeImport18OwningResponseAttemptData>>()
        + size_of::<Vec<BankSlot>>()
        + size_of::<Vec<Pending>>()
        + size_of::<BankSlot>() * 2
        + size_of::<Option<NativeImport18FirstBankCustodyData>>()
        + size_of::<Pending>() * 3
        + size_of::<Option<Pending>>()
        + size_of::<Option<NativeImport18FirstSelectionData>>()
        + size_of::<Option<NativeImport18OwningNextAttemptData>>()
        + size_of::<NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>()
        + schedule::initializer_data()
}

pub(super) fn counter_data() -> usize {
    type Owner = NativeImport18OwningResponseAttemptData;
    type History<'a> =
        std::iter::Chain<std::slice::Iter<'a, Pending>, std::option::Iter<'a, Pending>>;
    size_of::<Owner>()
        + size_of::<Option<Owner>>()
        + size_of::<&Owner>() * 6
        + size_of::<&mut Owner>() * 4
        + size_of::<&mut Option<Owner>>()
        + size_of::<NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<Option<NativeImport18OwningEnvelopeAttemptData>>()
        + size_of::<&NativeImport18OwningEnvelopeAttemptData>() * 3
        + size_of::<&mut NativeImport18OwningEnvelopeAttemptData>()
        + size_of::<&mut Option<NativeImport18OwningEnvelopeAttemptData>>()
        + size_of::<OwnedSource<'static>>() * 2
        + size_of::<&OwnedSource<'static>>() * 3
        + size_of::<&[BankSlot]>() * 2
        + size_of::<&BankSlot>() * 3
        + size_of::<&mut BankSlot>()
        + size_of::<Option<&BankSlot>>() * 2
        + size_of::<Option<&mut BankSlot>>()
        + size_of::<BankSlot>() * 2
        + size_of::<Vec<BankSlot>>()
        + size_of::<std::slice::Iter<'static, BankSlot>>()
        + size_of::<Pending>() * 3
        + size_of::<Option<Pending>>()
        + size_of::<&Pending>() * 4
        + size_of::<&mut Pending>() * 2
        + size_of::<Option<&Pending>>() * 2
        + size_of::<Option<&mut Pending>>()
        + size_of::<Vec<Pending>>()
        + size_of::<std::slice::Iter<'static, Pending>>()
        + size_of::<std::option::Iter<'static, Pending>>()
        + size_of::<History<'static>>()
        + size_of::<Plan>() * 3
        + size_of::<Option<Plan>>()
        + size_of::<&Plan>() * 3
        + size_of::<Result<Plan, ProviderError>>()
        + size_of::<Action>() * 3
        + size_of::<Option<Action>>()
        + size_of::<NativeImport18OwningResponseCensusData>()
        + size_of::<Option<(usize, usize, usize)>>()
        + size_of::<(usize, usize, usize)>() * 3
        + size_of::<Result<(Action, (usize, usize, usize)), ProviderError>>()
        + size_of::<(Action, (usize, usize, usize))>()
        + size_of::<Option<NativeImport18ResponseValueCutLocationData>>()
        + size_of::<NativeImport18FirstBankCustodyData>()
        + size_of::<Option<NativeImport18FirstBankCustodyData>>()
        + size_of::<&NativeImport18FirstBankCustodyData>() * 4
        + size_of::<&mut NativeImport18FirstBankCustodyData>() * 2
        + size_of::<Option<&NativeImport18FirstBankCustodyData>>() * 2
        + size_of::<Option<&mut NativeImport18FirstBankCustodyData>>()
        + size_of::<Result<&NativeImport18FirstBankCustodyData, ProviderError>>()
        + size_of::<Result<&mut NativeImport18FirstBankCustodyData, ProviderError>>()
        + size_of::<&NativeImport18FirstBankData>() * 3
        + size_of::<Result<&NativeImport18FirstBankData, ProviderError>>()
        + size_of::<NativeImport18FirstSelectionConstructionData<'static>>() * 2
        + size_of::<Result<NativeImport18FirstSelectionConstructionData<'static>, ProviderError>>()
        + size_of::<NativeImport18FirstSelectionData>()
        + size_of::<Option<NativeImport18FirstSelectionData>>()
        + size_of::<&NativeImport18FirstSelectionData>()
        + size_of::<&mut Option<NativeImport18FirstSelectionData>>()
        + size_of::<NativeImport18OwningNextAttemptData>()
        + size_of::<Option<NativeImport18OwningNextAttemptData>>()
        + size_of::<&NativeImport18OwningNextAttemptData>() * 4
        + size_of::<&mut NativeImport18OwningNextAttemptData>() * 2
        + size_of::<Option<&NativeImport18OwningNextAttemptData>>() * 2
        + size_of::<Option<&mut NativeImport18OwningNextAttemptData>>()
        + size_of::<Result<&NativeImport18OwningNextAttemptData, ProviderError>>()
        + size_of::<Result<&mut NativeImport18OwningNextAttemptData, ProviderError>>()
        + size_of::<&serde_json::Map<String, Value>>()
        + size_of::<Result<&serde_json::Map<String, Value>, ProviderError>>()
        + size_of::<serde_json::map::Iter<'static>>() * 2
        + size_of::<Option<(&String, &Value)>>()
        // body_name_data's actual raw-map callback tuple and returned name.
        + size_of::<(&String, &Value)>()
        + size_of::<Option<&str>>()
        + size_of::<Result<Option<&str>, ProviderError>>()
        + size_of::<NativeImport18FirstFlatViewData<'static>>() * 3
        + size_of::<Result<NativeImport18FirstFlatViewData<'static>, ProviderError>>()
        + size_of::<NativeImport18NextValueInputData<'static>>() * 2
        + size_of::<Result<NativeImport18NextValueInputData<'static>, ProviderError>>()
        + size_of::<NativeImport18NextValuePrewalkData<'static>>() * 2
        + size_of::<Result<NativeImport18NextValuePrewalkData<'static>, ProviderError>>()
        + size_of::<Result<&NativeImport18FirstSelectionData, ProviderError>>()
        + size_of::<SourceView<'static>>() * 3
        + size_of::<SourceKind<'static>>()
        + size_of::<SourceArray<'static>>()
        + size_of::<SourceObject<'static>>()
        + size_of::<Option<(&str, SourceView<'static>)>>()
        // The selection route's SourceObject callback and fallible child loan.
        + size_of::<(&str, SourceView<'static>)>()
        + size_of::<Result<SourceView<'static>, ProviderError>>()
        + size_of::<Option<SourceView<'static>>>()
        + size_of::<[Option<usize>; 2]>()
        + size_of::<std::array::IntoIter<Option<usize>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<Option<usize>, 2>>>()
        // This own action-bound sum has its own direct helper/fold controls.
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&mut std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<usize>() * 28
        + size_of::<bool>() * 5
        + size_of::<Option<bool>>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<&Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<&Result<usize, ProviderError>>()
        + size_of::<&NativeImport18OwningFirstAttemptData>() * 2
        + size_of::<Result<&NativeImport18OwningFirstAttemptData, ProviderError>>()
        + size_of::<&usize>() * 4
        + size_of::<Result<&RetainedFrame, ProviderError>>()
        + size_of::<&RetainedFrame>()
        + size_of::<(
            NativeImport18ResponseValueCutLocationData,
            &str,
            NativeImport18NextValuePassViewData<'static>,
        )>()
        + size_of::<
            Option<(
                NativeImport18ResponseValueCutLocationData,
                &str,
                NativeImport18NextValuePassViewData<'static>,
            )>,
        >()
        + size_of::<
            Result<
                Option<(
                    NativeImport18ResponseValueCutLocationData,
                    &str,
                    NativeImport18NextValuePassViewData<'static>,
                )>,
                ProviderError,
            >,
        >()
        + size_of::<NativeImport18NextValuePassViewData<'static>>()
        + size_of::<Result<NativeImport18NextValuePassViewData<'static>, ProviderError>>()
        + size_of::<NativeImport18FirstFlatKindData<'static>>()
        + size_of::<NativeImport18FirstFlatObjectData<'static>>()
        + size_of::<Option<(&str, NativeImport18FirstFlatViewData<'static>)>>()
        // completed_cut_data retains the actual key/view binding and its
        // ok_or_else result independently of the schedule's own flat tuples.
        + size_of::<(&str, NativeImport18FirstFlatViewData<'static>)>()
        + size_of::<Result<(&str, NativeImport18FirstFlatViewData<'static>), ProviderError>>()
        + size_of::<([Option<usize>; 2], usize)>()
        + size_of::<Route>() * 2
        + size_of::<&str>() * 2
        + NativeImport18OwningEnvelopeAttemptData::take_requested_storage_data().2
        + NativeImport18OwningEnvelopeAttemptData::transfer_counter_data()
        + NativeImport18FirstBankCustodyData::transfer_requested_storage_data().2
        + NativeImport18FirstSelectionConstructionData::counter_scratch_data()
        + NativeImport18OwningNextAttemptData::take_requested_storage_data().2
        + schedule::counter_data()
}
