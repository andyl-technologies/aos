//! Borrows physical raw/text nodes through completed-boundary loans.
//!
//! The public constructor admits first-to-second only. Each completed owner and
//! quote row retains the actual immutable source loans; physical identity never
//! stands in for content identity. Iterative boundary resolution lets later
//! exact third/fourth cut APIs extend a validated borrowed
//! chain without another normalizer or recursively nested view types.

use super::super::view::FirstPassNodeOriginData;
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NodeIdentity {
    Raw(usize),
    Text { owner: usize, node: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BoundaryIdentity {
    First(usize),
    OwningFirst(usize),
    Next(usize),
}

#[derive(Clone, Copy)]
pub(super) enum Physical<'a> {
    Raw(&'a Value),
    Text(NativeImport18EffectiveValueViewData<'a>),
}

impl<'a> Physical<'a> {
    pub(super) fn identity_data(self) -> Result<NodeIdentity, ProviderError> {
        match self {
            Self::Raw(value) => Ok(NodeIdentity::Raw(value as *const Value as usize)),
            Self::Text(value) => {
                let mut node = value.node;
                for _ in 0..value.owner.nodes.len() {
                    match &value.owner.nodes.get(node).ok_or_else(invalid)?.kind {
                        super::super::super::Kind::Alias(Some(target)) => node = *target,
                        super::super::super::Kind::Alias(None) => return Err(invalid()),
                        _ => {
                            return Ok(NodeIdentity::Text {
                                owner: value.owner as *const NativeImport18EffectiveTextAttemptData
                                    as usize,
                                node,
                            });
                        }
                    }
                }
                Err(invalid())
            }
        }
    }

    pub(super) fn marker_payload_data(self) -> Result<Option<&'a str>, ProviderError> {
        match self {
            Self::Raw(Value::Object(values)) => {
                let Some((key, value)) = values.iter().next() else {
                    return Ok(None);
                };
                if key != RAW_VALUE_KEY {
                    return Ok(None);
                }
                let payload = value.as_str().ok_or_else(invalid)?;
                if values.len() != 1 {
                    return Err(invalid());
                }
                Ok(Some(payload))
            }
            Self::Text(value) => {
                let NativeImport18EffectiveValueKindData::Object(mut values) = value.kind_data()?
                else {
                    return Ok(None);
                };
                let Some((key, value)) = values.next() else {
                    return Ok(None);
                };
                if key != RAW_VALUE_KEY {
                    return Ok(None);
                }
                let NativeImport18EffectiveValueKindData::String(payload) = value.kind_data()?
                else {
                    return Err(invalid());
                };
                if values.next().is_some() {
                    return Err(invalid());
                }
                Ok(Some(payload))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum FirstSource<'a> {
    Borrowed(&'a NativeImport18OwnedValuePassAttemptData<'a>),
    Owning(&'a NativeImport18OwningFirstAttemptData),
}

impl<'a> FirstSource<'a> {
    pub(super) fn state_data(self) -> &'a super::super::state::FirstPassStateData {
        match self {
            Self::Borrowed(owner) => &owner.state,
            Self::Owning(owner) => owner.state_data(),
        }
    }

    pub(super) fn identity_data(self) -> BoundaryIdentity {
        match self {
            Self::Borrowed(owner) => BoundaryIdentity::First(owner as *const _ as usize),
            Self::Owning(owner) => BoundaryIdentity::OwningFirst(owner as *const _ as usize),
        }
    }

    pub(super) fn same_data(self, other: Self) -> bool {
        self.identity_data() == other.identity_data()
    }

    fn validate_data(self, raw: &RetainedFrame) -> Result<(), ProviderError> {
        let state = self.state_data();
        if !state.started || state.failed || !state.complete || state.mode.is_none() {
            return Err(invalid());
        }
        let original = match self {
            Self::Borrowed(owner) => owner.row.raw_resource_data(),
            Self::Owning(owner) => {
                owner.completed_data()?;
                owner.retained_selection_data()?.retained_frame_data()?
            }
        };
        if !std::ptr::eq(original, raw) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Loans<'a> {
    pub(super) raw: &'a RetainedFrame,
    pub(super) first: FirstSource<'a>,
    // This cohort constructs only the empty slice. A future actual consumer
    // must validate the real chain before exposing a later input constructor.
    pub(super) later: &'a [&'a NativeImport18NextValuePassAttemptData<'a>],
}

impl<'a> Loans<'a> {
    pub(super) fn prior_data(self) -> BoundaryIdentity {
        self.later
            .last()
            .map_or(self.first.identity_data(), |owner| {
                BoundaryIdentity::Next(
                    *owner as *const NativeImport18NextValuePassAttemptData<'a> as usize,
                )
            })
    }

    pub(super) fn validate_data(self) -> Result<(), ProviderError> {
        self.first.validate_data(self.raw)?;
        let mut prior = self.first.identity_data();
        for owner in self.later {
            if owner.state.failed
                || !owner.state.complete
                || owner.row.prewalk.prior != prior
                || !std::ptr::eq(owner.row.prewalk.raw, self.raw)
                || !owner.row.prewalk.first.same_data(self.first)
            {
                return Err(invalid());
            }
            prior = BoundaryIdentity::Next(
                *owner as *const NativeImport18NextValuePassAttemptData<'a> as usize,
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct SourceView<'a> {
    pub(super) loans: Loans<'a>,
    pub(super) origin: Physical<'a>,
    pub(super) created: usize,
}

impl<'a> SourceView<'a> {
    pub(super) fn resolved_data(self) -> Result<(Physical<'a>, usize), ProviderError> {
        let mut physical = self.origin;
        let mut created = self.created;
        if created == 0 {
            if let Physical::Raw(value) = physical {
                match super::super::state_view::raw_data(self.loans.first.state_data(), value)
                    .origin_data()?
                {
                    FirstPassNodeOriginData::Raw(value) => physical = Physical::Raw(value),
                    FirstPassNodeOriginData::Text(value) => {
                        physical = Physical::Text(value);
                        created = 1;
                    }
                }
            }
        }
        for (index, owner) in self.loans.later.iter().enumerate() {
            let stage = add(index, 2)?;
            if created < stage {
                (physical, created) =
                    resolve_boundary_data(&owner.state, physical, created, stage)?;
            }
        }
        Ok((physical, created))
    }

    pub(super) fn identity_data(self) -> Result<NodeIdentity, ProviderError> {
        self.resolved_data()?.0.identity_data()
    }

    pub(super) fn kind_data(self) -> Result<SourceKind<'a>, ProviderError> {
        let (physical, created) = self.resolved_data()?;
        kind_data(self.loans, physical, created)
    }
}

pub(super) fn resolve_boundary_data<'a>(
    owner: &'a engine::NextPassStateData,
    physical: Physical<'a>,
    created: usize,
    stage: usize,
) -> Result<(Physical<'a>, usize), ProviderError> {
    if created >= stage || !matches!(owner.mode, Some(RawMode::Reparse)) {
        return Ok((physical, created));
    }
    let identity = physical.identity_data()?;
    let Some(payload) = physical.marker_payload_data()? else {
        return Ok((physical, created));
    };
    let position = owner.lookup.get(&identity).ok_or_else(invalid)?;
    let child = owner.reparses.get(*position).ok_or_else(invalid)?;
    if child.source != identity {
        return Err(invalid());
    }
    let child = child.attempt.as_ref().ok_or_else(invalid)?;
    if child.texts.first().map(String::as_str) != Some(payload) {
        return Err(invalid());
    }
    Ok((Physical::Text(child.completed_data()?), stage))
}

pub(super) enum SourceKind<'a> {
    Null,
    Bool(bool),
    Number(&'a Number),
    String(&'a str),
    Array(SourceArray<'a>),
    Object(SourceObject<'a>),
}
enum Array<'a> {
    Raw(std::slice::Iter<'a, Value>),
    Text(EffectiveArray<'a>),
}
enum Object<'a> {
    Raw(serde_json::map::Iter<'a>),
    Text(EffectiveObject<'a>),
}
pub(super) struct SourceArray<'a> {
    loans: Loans<'a>,
    created: usize,
    source: Array<'a>,
}
pub(super) struct SourceObject<'a> {
    loans: Loans<'a>,
    created: usize,
    source: Object<'a>,
}

pub(super) fn kind_data<'a>(
    loans: Loans<'a>,
    physical: Physical<'a>,
    created: usize,
) -> Result<SourceKind<'a>, ProviderError> {
    Ok(match physical {
        Physical::Raw(value) => match value {
            Value::Null => SourceKind::Null,
            Value::Bool(value) => SourceKind::Bool(*value),
            Value::Number(value) => SourceKind::Number(value),
            Value::String(value) => SourceKind::String(value),
            Value::Array(value) => SourceKind::Array(SourceArray {
                loans,
                created,
                source: Array::Raw(value.iter()),
            }),
            Value::Object(value) => SourceKind::Object(SourceObject {
                loans,
                created,
                source: Object::Raw(value.iter()),
            }),
        },
        Physical::Text(value) => match value.kind_data()? {
            NativeImport18EffectiveValueKindData::Null => SourceKind::Null,
            NativeImport18EffectiveValueKindData::Bool(value) => SourceKind::Bool(value),
            NativeImport18EffectiveValueKindData::Number(value) => SourceKind::Number(value),
            NativeImport18EffectiveValueKindData::String(value) => SourceKind::String(value),
            NativeImport18EffectiveValueKindData::Array(value) => SourceKind::Array(SourceArray {
                loans,
                created,
                source: Array::Text(value),
            }),
            NativeImport18EffectiveValueKindData::Object(value) => {
                SourceKind::Object(SourceObject {
                    loans,
                    created,
                    source: Object::Text(value),
                })
            }
        },
    })
}

impl<'a> Iterator for SourceArray<'a> {
    type Item = SourceView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let origin = match &mut self.source {
            Array::Raw(values) => Physical::Raw(values.next()?),
            Array::Text(values) => Physical::Text(values.next()?),
        };
        Some(SourceView {
            loans: self.loans,
            origin,
            created: self.created,
        })
    }
}

impl<'a> Iterator for SourceObject<'a> {
    type Item = (&'a str, SourceView<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        let (key, origin) = match &mut self.source {
            Object::Raw(values) => {
                let (key, value) = values.next()?;
                (key.as_str(), Physical::Raw(value))
            }
            Object::Text(values) => {
                let (key, value) = values.next()?;
                (key, Physical::Text(value))
            }
        };
        Some((
            key,
            SourceView {
                loans: self.loans,
                origin,
                created: self.created,
            },
        ))
    }
}

/// Borrows one actual node from the same completed first-pass bank.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18NextValueInputData<'a> {
    pub(super) selected: SourceView<'a>,
}

impl<'a> NativeImport18NextValueInputData<'a> {
    /// Selects an actual first-to-second node without an extra normalization.
    ///
    /// # Errors
    /// Refuses foreign raw/owner/view pairing or an incomplete prior owner.
    pub(crate) fn selected_data(
        raw: &'a RetainedFrame,
        prior: &'a NativeImport18OwnedValuePassAttemptData<'a>,
        selected: NativeImport18OwnedValuePassViewData<'a>,
    ) -> Result<Self, ProviderError> {
        let loans = Loans {
            raw,
            first: FirstSource::Borrowed(prior),
            later: &[],
        };
        loans.validate_data()?;
        if !std::ptr::eq(selected.boundary_data(), prior) {
            return Err(invalid());
        }
        let (origin, created) = match selected.origin_data()? {
            FirstPassNodeOriginData::Raw(value) => (Physical::Raw(value), 0),
            FirstPassNodeOriginData::Text(value) => (Physical::Text(value), 1),
        };
        Ok(Self {
            selected: SourceView {
                loans,
                origin,
                created,
            },
        })
    }

    pub(in super::super) fn owning_root_data(
        first: &'a NativeImport18OwningFirstAttemptData,
    ) -> Result<Self, ProviderError> {
        let selection = first.retained_selection_data()?;
        let raw = selection.retained_frame_data()?;
        let loans = Loans {
            raw,
            first: FirstSource::Owning(first),
            later: &[],
        };
        loans.validate_data()?;
        Ok(Self {
            selected: SourceView {
                loans,
                origin: Physical::Raw(selection.value_data()?),
                created: 0,
            },
        })
    }

    pub(super) fn key_data(self) -> Result<NodeIdentity, ProviderError> {
        self.selected.identity_data()
    }

    // Actual raw plus all retained flat node slots bound logical visits and
    // spine depth. Overwritten slots stay counted; no cap supplies demand.
    pub(super) fn physical_population_data(self) -> Result<usize, ProviderError> {
        self.selected.loans.validate_data()?;
        let mut population = 0;
        let mut raw = super::super::walk::Walk::new_data(&self.selected.loans.raw.value);
        while raw.next_data()?.is_some() {
            population = add(population, 1)?;
        }
        for child in &self.selected.loans.first.state_data().reparses {
            let child = child.attempt.as_ref().ok_or_else(invalid)?;
            if child.failed || !child.complete {
                return Err(invalid());
            }
            population = add(population, child.nodes.len())?;
        }
        for owner in self.selected.loans.later {
            for child in &owner.state.reparses {
                let child = child.attempt.as_ref().ok_or_else(invalid)?;
                if child.failed || !child.complete {
                    return Err(invalid());
                }
                population = add(population, child.nodes.len())?;
            }
        }
        Ok(population)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<FirstSource<'static>>() * 3
        + size_of::<&NativeImport18OwningFirstAttemptData>() * 3
        + size_of::<Result<&RetainedFrame, ProviderError>>()
        + size_of::<&NativeImport18RawSelectionData>()
        + size_of::<Result<&NativeImport18RawSelectionData, ProviderError>>()
        + size_of::<Physical<'static>>() * 3
        + size_of::<NodeIdentity>() * 3
        + size_of::<Result<NodeIdentity, ProviderError>>()
        + size_of::<BoundaryIdentity>() * 2
        + size_of::<Loans<'static>>() * 3
        + size_of::<SourceView<'static>>() * 3
        + size_of::<SourceKind<'static>>()
        + size_of::<Result<SourceKind<'static>, ProviderError>>()
        + size_of::<SourceArray<'static>>()
        + size_of::<SourceObject<'static>>()
        + size_of::<Array<'static>>()
        + size_of::<Object<'static>>()
        + size_of::<Result<(Physical<'static>, usize), ProviderError>>()
        + size_of::<(Physical<'static>, usize)>()
        + size_of::<Option<SourceView<'static>>>()
        + size_of::<Option<(&str, SourceView<'static>)>>()
        + size_of::<std::slice::Iter<'static, &NativeImport18NextValuePassAttemptData<'static>>>()
            * 2
        + size_of::<
            std::iter::Enumerate<
                std::slice::Iter<'static, &NativeImport18NextValuePassAttemptData<'static>>,
            >,
        >()
        + size_of::<Option<&&NativeImport18NextValuePassAttemptData<'static>>>()
        + size_of::<&&NativeImport18NextValuePassAttemptData<'static>>()
        + size_of::<&[&NativeImport18NextValuePassAttemptData<'static>]>()
        + size_of::<&mut SourceArray<'static>>()
        + size_of::<&mut SourceObject<'static>>()
        + size_of::<Result<Option<&str>, ProviderError>>()
        + size_of::<Option<&usize>>()
        + size_of::<Option<&Reparse>>()
        + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
        + size_of::<Option<&String>>()
        + size_of::<Option<&str>>()
        + size_of::<&str>() * 2
        + size_of::<usize>() * 8
}
