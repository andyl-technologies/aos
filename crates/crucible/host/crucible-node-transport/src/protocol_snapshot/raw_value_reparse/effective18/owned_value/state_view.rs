//! Projects the sole first engine state through immutable, short-lived loans.
//!
//! Both the legacy borrowed adapter and the owning first attempt use this same
//! projection. It owns no source guard and applies no further normalization.

use super::view::FirstPassNodeOriginData;
use super::*;

#[derive(Clone, Copy)]
enum NodeData<'a> {
    Raw {
        state: &'a state::FirstPassStateData,
        value: &'a Value,
    },
    Text {
        state: &'a state::FirstPassStateData,
        value: NativeImport18EffectiveValueViewData<'a>,
    },
}

/// Borrows one normalized node from actual raw or retained flat text custody.
///
/// This DATA view has no Serialize/Deserialize or ordinary owned-Value escape.
/// Text results are returned directly; they are not normalized a second time.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18FirstFlatViewData<'a> {
    node: NodeData<'a>,
}

/// Lends exact normalized scalars and nonrecursive child iterators.
pub(crate) enum NativeImport18FirstFlatKindData<'a> {
    /// Names JSON null.
    Null,
    /// Lends the actual Boolean value.
    Bool(bool),
    /// Borrows the actual existing locked Number.
    Number(&'a Number),
    /// Borrows the actual existing normalized string.
    String(&'a str),
    /// Iterates actual normalized array order.
    Array(NativeImport18FirstFlatArrayData<'a>),
    /// Iterates actual final BTreeMap key order.
    Object(NativeImport18FirstFlatObjectData<'a>),
}

/// Iterates one borrowed raw array or one already normalized flat text array.
pub(crate) struct NativeImport18FirstFlatArrayData<'a> {
    source: ArrayData<'a>,
}

enum ArrayData<'a> {
    /// Preserves an ordinary raw array and this pass's actual substitutions.
    Raw(std::slice::Iter<'a, Value>, &'a state::FirstPassStateData),
    /// Preserves a completed text result without another adapter pass.
    Text(EffectiveArray<'a>, &'a state::FirstPassStateData),
}

/// Iterates one borrowed raw map or one already normalized flat text map.
pub(crate) struct NativeImport18FirstFlatObjectData<'a> {
    source: ObjectData<'a>,
}

enum ObjectData<'a> {
    /// Preserves an ordinary raw map and this pass's actual substitutions.
    Raw(serde_json::map::Iter<'a>, &'a state::FirstPassStateData),
    /// Preserves a completed text result without another adapter pass.
    Text(EffectiveObject<'a>, &'a state::FirstPassStateData),
}

pub(super) fn raw_data<'a>(
    state: &'a state::FirstPassStateData,
    value: &'a Value,
) -> NativeImport18FirstFlatViewData<'a> {
    NativeImport18FirstFlatViewData {
        node: NodeData::Raw { state, value },
    }
}

impl<'a> NativeImport18FirstFlatViewData<'a> {
    pub(super) fn origin_data(self) -> Result<FirstPassNodeOriginData<'a>, ProviderError> {
        match self.node {
            NodeData::Text { value, .. } => Ok(FirstPassNodeOriginData::Text(value)),
            NodeData::Raw { state, value } => {
                if let Value::Object(values) = value {
                    if matches!(state.mode, Some(RawMode::Reparse))
                        && values
                            .iter()
                            .next()
                            .is_some_and(|(key, _)| key == RAW_VALUE_KEY)
                    {
                        let position = state
                            .lookup
                            .get(&(value as *const Value as usize))
                            .ok_or_else(invalid)?;
                        let child = state.reparses.get(*position).ok_or_else(invalid)?;
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

    /// Resolves the actual one-pass replacement and lends its kind.
    ///
    /// # Errors
    /// Refuses inconsistent private lookup, source identity or incomplete child.
    pub(crate) fn kind_data(self) -> Result<NativeImport18FirstFlatKindData<'a>, ProviderError> {
        use NativeImport18FirstFlatKindData as Kind;
        match self.node {
            NodeData::Text { state, value } => text_kind_data(state, value),
            NodeData::Raw { state, value } => Ok(match value {
                Value::Null => Kind::Null,
                Value::Bool(value) => Kind::Bool(*value),
                Value::Number(value) => Kind::Number(value),
                Value::String(value) => Kind::String(value),
                Value::Array(values) => Kind::Array(NativeImport18FirstFlatArrayData {
                    source: ArrayData::Raw(values.iter(), state),
                }),
                Value::Object(values) => {
                    if matches!(state.mode, Some(RawMode::Reparse))
                        && values
                            .iter()
                            .next()
                            .is_some_and(|(key, _)| key == RAW_VALUE_KEY)
                    {
                        let position = state
                            .lookup
                            .get(&(value as *const Value as usize))
                            .ok_or_else(invalid)?;
                        let child = state.reparses.get(*position).ok_or_else(invalid)?;
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
                        return text_kind_data(state, child.completed_data()?);
                    }
                    Kind::Object(NativeImport18FirstFlatObjectData {
                        source: ObjectData::Raw(values.iter(), state),
                    })
                }
            }),
        }
    }
}

fn text_kind_data<'a>(
    state: &'a state::FirstPassStateData,
    value: NativeImport18EffectiveValueViewData<'a>,
) -> Result<NativeImport18FirstFlatKindData<'a>, ProviderError> {
    use NativeImport18EffectiveValueKindData as Text;
    use NativeImport18FirstFlatKindData as Kind;
    Ok(match value.kind_data()? {
        Text::Null => Kind::Null,
        Text::Bool(value) => Kind::Bool(value),
        Text::Number(value) => Kind::Number(value),
        Text::String(value) => Kind::String(value),
        Text::Array(values) => Kind::Array(NativeImport18FirstFlatArrayData {
            source: ArrayData::Text(values, state),
        }),
        Text::Object(values) => Kind::Object(NativeImport18FirstFlatObjectData {
            source: ObjectData::Text(values, state),
        }),
    })
}

impl<'a> Iterator for NativeImport18FirstFlatArrayData<'a> {
    type Item = NativeImport18FirstFlatViewData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.source {
            ArrayData::Raw(values, state) => values.next().map(|value| raw_data(state, value)),
            ArrayData::Text(values, state) => {
                values.next().map(|value| NativeImport18FirstFlatViewData {
                    node: NodeData::Text { state, value },
                })
            }
        }
    }
}

impl<'a> Iterator for NativeImport18FirstFlatObjectData<'a> {
    type Item = (&'a str, NativeImport18FirstFlatViewData<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.source {
            ObjectData::Raw(values, state) => values
                .next()
                .map(|(key, value)| (key.as_str(), raw_data(state, value))),
            ObjectData::Text(values, state) => values.next().map(|(key, value)| {
                (
                    key,
                    NativeImport18FirstFlatViewData {
                        node: NodeData::Text { state, value },
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
        + size_of::<&state::FirstPassStateData>() * 2
        + size_of::<usize>() * 4
        + size_of::<NativeImport18FirstFlatViewData<'static>>()
        + size_of::<NativeImport18FirstFlatKindData<'static>>()
        + size_of::<ArrayData<'static>>()
        + size_of::<ObjectData<'static>>()
        + size_of::<NativeImport18FirstFlatArrayData<'static>>()
        + size_of::<NativeImport18FirstFlatObjectData<'static>>()
        + size_of::<&mut NativeImport18FirstFlatArrayData<'static>>()
        + size_of::<&mut NativeImport18FirstFlatObjectData<'static>>()
        + size_of::<Option<NativeImport18FirstFlatViewData<'static>>>()
        + size_of::<(&str, NativeImport18FirstFlatViewData<'static>)>()
        + size_of::<Option<(&str, NativeImport18FirstFlatViewData<'static>)>>()
        + size_of::<Result<NativeImport18FirstFlatViewData<'static>, ProviderError>>()
        + size_of::<Result<NativeImport18FirstFlatKindData<'static>, ProviderError>>()
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
        + size_of::<&state::FirstPassStateData>()
        + size_of::<usize>()
}
