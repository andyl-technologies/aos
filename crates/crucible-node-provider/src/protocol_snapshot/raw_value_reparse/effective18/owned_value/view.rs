//! Borrows one exact adapter result without copying or applying another pass.

use super::*;

#[derive(Clone, Copy)]
enum NodeData<'a> {
    Raw {
        owner: &'a NativeImport18OwnedValuePassAttemptData<'a>,
        value: &'a Value,
    },
    Text {
        owner: &'a NativeImport18OwnedValuePassAttemptData<'a>,
        value: NativeImport18EffectiveValueViewData<'a>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum FirstPassNodeOriginData<'a> {
    Raw(&'a Value),
    Text(NativeImport18EffectiveValueViewData<'a>),
}

/// Borrows one normalized node from actual raw or retained flat text custody.
///
/// This DATA view has no Serialize/Deserialize or ordinary owned-Value escape.
/// Text results are returned directly; they are not normalized a second time.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18OwnedValuePassViewData<'a> {
    node: NodeData<'a>,
}

/// Lends exact normalized scalars and nonrecursive child iterators.
pub(crate) enum NativeImport18OwnedValuePassKindData<'a> {
    /// Names JSON null.
    Null,
    /// Lends the actual Boolean value.
    Bool(bool),
    /// Borrows the actual existing locked Number.
    Number(&'a Number),
    /// Borrows the actual existing normalized string.
    String(&'a str),
    /// Iterates actual normalized array order.
    Array(NativeImport18OwnedValuePassArrayData<'a>),
    /// Iterates actual final BTreeMap key order.
    Object(NativeImport18OwnedValuePassObjectData<'a>),
}

/// Iterates one borrowed raw array or one already normalized flat text array.
pub(crate) struct NativeImport18OwnedValuePassArrayData<'a> {
    source: ArrayData<'a>,
}

enum ArrayData<'a> {
    /// Preserves an ordinary raw array and this pass's actual substitutions.
    Raw(
        std::slice::Iter<'a, Value>,
        &'a NativeImport18OwnedValuePassAttemptData<'a>,
    ),
    /// Preserves a completed text result without another adapter pass.
    Text(
        EffectiveArray<'a>,
        &'a NativeImport18OwnedValuePassAttemptData<'a>,
    ),
}

/// Iterates one borrowed raw map or one already normalized flat text map.
pub(crate) struct NativeImport18OwnedValuePassObjectData<'a> {
    source: ObjectData<'a>,
}

enum ObjectData<'a> {
    /// Preserves an ordinary raw map and this pass's actual substitutions.
    Raw(
        serde_json::map::Iter<'a>,
        &'a NativeImport18OwnedValuePassAttemptData<'a>,
    ),
    /// Preserves a completed text result without another adapter pass.
    Text(
        EffectiveObject<'a>,
        &'a NativeImport18OwnedValuePassAttemptData<'a>,
    ),
}

pub(super) fn raw_data<'a>(
    owner: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    value: &'a Value,
) -> NativeImport18OwnedValuePassViewData<'a> {
    NativeImport18OwnedValuePassViewData {
        node: NodeData::Raw { owner, value },
    }
}

impl<'a> NativeImport18OwnedValuePassViewData<'a> {
    pub(super) fn origin_data(self) -> Result<FirstPassNodeOriginData<'a>, ProviderError> {
        match self.node {
            NodeData::Text { value, .. } => Ok(FirstPassNodeOriginData::Text(value)),
            NodeData::Raw { owner, value } => {
                if let Value::Object(values) = value {
                    if matches!(owner.mode, Some(RawMode::Reparse))
                        && values
                            .iter()
                            .next()
                            .is_some_and(|(key, _)| key == RAW_VALUE_KEY)
                    {
                        let position = owner
                            .lookup
                            .get(&(value as *const Value as usize))
                            .ok_or_else(invalid)?;
                        let child = owner.reparses.get(*position).ok_or_else(invalid)?;
                        if !std::ptr::eq(child.source, value) {
                            return Err(invalid());
                        }
                        let child = child.attempt.as_ref().ok_or_else(invalid)?;
                        let payload = values
                            .get(RAW_VALUE_KEY)
                            .and_then(Value::as_str)
                            .ok_or_else(invalid)?;
                        if values.len() != 1
                            || child.texts.first().map(String::as_str) != Some(payload)
                        {
                            return Err(invalid());
                        }
                        return Ok(FirstPassNodeOriginData::Text(child.completed_data()?));
                    }
                }
                Ok(FirstPassNodeOriginData::Raw(value))
            }
        }
    }

    pub(super) fn boundary_data(self) -> &'a NativeImport18OwnedValuePassAttemptData<'a> {
        match self.node {
            NodeData::Raw { owner, .. } | NodeData::Text { owner, .. } => owner,
        }
    }

    /// Resolves the actual one-pass replacement and lends its kind.
    ///
    /// # Errors
    /// Refuses inconsistent private lookup, source identity or incomplete child.
    pub(crate) fn kind_data(
        self,
    ) -> Result<NativeImport18OwnedValuePassKindData<'a>, ProviderError> {
        use NativeImport18OwnedValuePassKindData as Kind;
        match self.node {
            NodeData::Text { owner, value } => text_kind_data(owner, value),
            NodeData::Raw { owner, value } => Ok(match value {
                Value::Null => Kind::Null,
                Value::Bool(value) => Kind::Bool(*value),
                Value::Number(value) => Kind::Number(value),
                Value::String(value) => Kind::String(value),
                Value::Array(values) => Kind::Array(NativeImport18OwnedValuePassArrayData {
                    source: ArrayData::Raw(values.iter(), owner),
                }),
                Value::Object(values) => {
                    if matches!(owner.mode, Some(RawMode::Reparse))
                        && values
                            .iter()
                            .next()
                            .is_some_and(|(key, _)| key == RAW_VALUE_KEY)
                    {
                        let position = owner
                            .lookup
                            .get(&(value as *const Value as usize))
                            .ok_or_else(invalid)?;
                        let child = owner.reparses.get(*position).ok_or_else(invalid)?;
                        if !std::ptr::eq(child.source, value) {
                            return Err(invalid());
                        }
                        let child = child.attempt.as_ref().ok_or_else(invalid)?;
                        let payload = values
                            .get(RAW_VALUE_KEY)
                            .and_then(Value::as_str)
                            .ok_or_else(invalid)?;
                        if values.len() != 1
                            || child.texts.first().map(String::as_str) != Some(payload)
                        {
                            return Err(invalid());
                        }
                        return text_kind_data(owner, child.completed_data()?);
                    }
                    Kind::Object(NativeImport18OwnedValuePassObjectData {
                        source: ObjectData::Raw(values.iter(), owner),
                    })
                }
            }),
        }
    }
}

fn text_kind_data<'a>(
    owner: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    value: NativeImport18EffectiveValueViewData<'a>,
) -> Result<NativeImport18OwnedValuePassKindData<'a>, ProviderError> {
    use NativeImport18EffectiveValueKindData as Text;
    use NativeImport18OwnedValuePassKindData as Kind;
    Ok(match value.kind_data()? {
        Text::Null => Kind::Null,
        Text::Bool(value) => Kind::Bool(value),
        Text::Number(value) => Kind::Number(value),
        Text::String(value) => Kind::String(value),
        Text::Array(values) => Kind::Array(NativeImport18OwnedValuePassArrayData {
            source: ArrayData::Text(values, owner),
        }),
        Text::Object(values) => Kind::Object(NativeImport18OwnedValuePassObjectData {
            source: ObjectData::Text(values, owner),
        }),
    })
}

impl<'a> Iterator for NativeImport18OwnedValuePassArrayData<'a> {
    type Item = NativeImport18OwnedValuePassViewData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.source {
            ArrayData::Raw(values, owner) => values.next().map(|value| raw_data(*owner, value)),
            ArrayData::Text(values, owner) => {
                values
                    .next()
                    .map(|value| NativeImport18OwnedValuePassViewData {
                        node: NodeData::Text {
                            owner: *owner,
                            value,
                        },
                    })
            }
        }
    }
}

impl<'a> Iterator for NativeImport18OwnedValuePassObjectData<'a> {
    type Item = (&'a str, NativeImport18OwnedValuePassViewData<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.source {
            ObjectData::Raw(values, owner) => values
                .next()
                .map(|(key, value)| (key.as_str(), raw_data(*owner, value))),
            ObjectData::Text(values, owner) => values.next().map(|(key, value)| {
                (
                    key,
                    NativeImport18OwnedValuePassViewData {
                        node: NodeData::Text {
                            owner: *owner,
                            value,
                        },
                    },
                )
            }),
        }
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NodeData<'static>>()
        + size_of::<FirstPassNodeOriginData<'static>>()
        + size_of::<Result<FirstPassNodeOriginData<'static>, ProviderError>>()
        + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>() * 2
        + size_of::<usize>() * 4
        + size_of::<NativeImport18OwnedValuePassViewData<'static>>()
        + size_of::<NativeImport18OwnedValuePassKindData<'static>>()
        + size_of::<ArrayData<'static>>()
        + size_of::<ObjectData<'static>>()
        + size_of::<NativeImport18OwnedValuePassArrayData<'static>>()
        + size_of::<NativeImport18OwnedValuePassObjectData<'static>>()
        + size_of::<&mut NativeImport18OwnedValuePassArrayData<'static>>()
        + size_of::<&mut NativeImport18OwnedValuePassObjectData<'static>>()
        + size_of::<Option<NativeImport18OwnedValuePassViewData<'static>>>()
        + size_of::<(&str, NativeImport18OwnedValuePassViewData<'static>)>()
        + size_of::<Option<(&str, NativeImport18OwnedValuePassViewData<'static>)>>()
        + size_of::<Result<NativeImport18OwnedValuePassViewData<'static>, ProviderError>>()
        + size_of::<Result<NativeImport18OwnedValuePassKindData<'static>, ProviderError>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<(&String, &Value)>>()
        + size_of::<(&String, &Value)>()
        + size_of::<Option<&usize>>()
        + size_of::<Result<&usize, ProviderError>>()
        + size_of::<Option<&Reparse>>()
        + size_of::<Result<&Reparse, ProviderError>>()
        + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
        + size_of::<Result<&NativeImport18EffectiveTextAttemptData, ProviderError>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Option<&String>>()
        + size_of::<Option<&str>>()
        + size_of::<&str>() * 2
        + size_of::<&Reparse>()
        + size_of::<&Value>()
        + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>()
        + size_of::<usize>()
}
