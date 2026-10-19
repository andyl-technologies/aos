//! Shares the exact ResponseShape field order without storing sibling loans.
//!
//! Root-relative body and at most two child ordinals are private, derived by
//! actual iteration and resolved only against the same immutable source owner.
//! Replaying an iterator to an ordinal applies no Value normalization.

use super::*;
use crate::bodies::{EffectCertainty, OperationState};

type Flat<'a> = NativeImport18FirstFlatViewData<'a>;
type Kind<'a> = NativeImport18FirstFlatKindData<'a>;

pub(super) trait Source {
    fn body_name_data(&self, index: usize) -> Result<Option<&str>, ProviderError>;
    fn value_data(&self, route: Route) -> Result<Flat<'_>, ProviderError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    pub(super) body: usize,
    pub(super) path: [Option<usize>; 2],
}

impl Route {
    fn root_data(body: usize) -> Self {
        Self {
            body,
            path: [None; 2],
        }
    }

    fn child_data(self, child: usize) -> Result<Self, ProviderError> {
        let mut route = self;
        let slot = route
            .path
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(invalid)?;
        *slot = Some(child);
        Ok(route)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Accepted,
    Completed,
    Error,
}

#[derive(Clone, Copy)]
enum GroupKind {
    Result,
    ErrorDetail,
    Extension,
}

#[derive(Clone, Copy)]
struct Group {
    kind: GroupKind,
    route: Route,
    next: usize,
}

#[derive(Clone, Copy)]
struct ErrorFields {
    route: Route,
    next: usize,
    present: [bool; 5],
}

#[derive(Clone, Copy)]
pub(super) struct SelectedCut {
    pub(super) location: NativeImport18ResponseValueCutLocationData,
    pub(super) route: Route,
}

pub(super) struct Schedule {
    body: usize,
    status: Option<Status>,
    present: u8,
    error: Option<ErrorFields>,
    group: Option<Group>,
    pending: Option<Route>,
    failed: bool,
    finished: bool,
}

impl Schedule {
    pub(super) fn new_data() -> Self {
        Self {
            body: 0,
            status: None,
            present: 0,
            error: None,
            group: None,
            pending: None,
            failed: true,
            finished: false,
        }
    }

    pub(super) fn start_data(&mut self, source: &impl Source) -> Result<(), ProviderError> {
        let mut member = 0;
        loop {
            let name = source.body_name_data(member)?.ok_or_else(invalid)?;
            if name == "status" {
                break;
            }
            member = add(member, 1)?;
        }
        let Kind::String(tag) = source.value_data(Route::root_data(member))?.kind_data()? else {
            return Err(invalid());
        };
        self.status = Some(match tag {
            "accepted" => Status::Accepted,
            "completed" => Status::Completed,
            "error" => Status::Error,
            _ => return Err(invalid()),
        });
        self.failed = false;
        Ok(())
    }

    pub(super) const fn state_data(&self) -> (bool, bool, bool) {
        (self.failed, self.finished, self.pending.is_some())
    }
    pub(super) fn fail_data(&mut self) {
        self.failed = true;
    }
    pub(super) fn resume_data(&mut self) {
        self.failed = false;
    }
    pub(super) fn pending_data(&self) -> Result<Route, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        self.pending.ok_or_else(invalid)
    }
    pub(super) fn complete_data(&mut self) {
        self.pending = None;
        self.failed = false;
    }

    pub(super) fn next_data(
        &mut self,
        source: &impl Source,
    ) -> Result<Option<SelectedCut>, ProviderError> {
        if self.failed || self.pending.is_some() {
            self.failed = true;
            return Err(invalid());
        }
        if self.finished {
            return Ok(None);
        }
        self.failed = true;
        let result = self.advance_data(source);
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    fn advance_data(&mut self, source: &impl Source) -> Result<Option<SelectedCut>, ProviderError> {
        loop {
            if let Some(group) = &mut self.group {
                let Kind::Object(mut values) = source.value_data(group.route)?.kind_data()? else {
                    return Err(invalid());
                };
                if values.nth(group.next).is_some() {
                    let member = group.next;
                    group.next = add(member, 1)?;
                    let location = match group.kind {
                        GroupKind::Result => {
                            NativeImport18ResponseValueCutLocationData::Result(member)
                        }
                        GroupKind::ErrorDetail => {
                            NativeImport18ResponseValueCutLocationData::ErrorDetail(member)
                        }
                        GroupKind::Extension => {
                            NativeImport18ResponseValueCutLocationData::Extension(member)
                        }
                    };
                    let route = group.route.child_data(member)?;
                    self.pending = Some(route);
                    return Ok(Some(SelectedCut { location, route }));
                }
                self.group = None;
            }
            if let Some(error) = &mut self.error {
                let root = source.value_data(error.route)?;
                let next = match root.kind_data()? {
                    Kind::Object(mut values) => values.nth(error.next),
                    Kind::Array(mut values) => values.nth(error.next).map(|value| {
                        (
                            match error.next {
                                0 => "code",
                                1 => "message",
                                2 => "effect",
                                3 => "retryable",
                                4 => "details",
                                _ => "unknown",
                            },
                            value,
                        )
                    }),
                    _ => return Err(invalid()),
                };
                if let Some((name, value)) = next {
                    let index = match name {
                        "code" => 0,
                        "message" => 1,
                        "effect" => 2,
                        "retryable" => 3,
                        "details" => 4,
                        _ => return Err(invalid()),
                    };
                    if error.present[index] {
                        return Err(invalid());
                    }
                    error.present[index] = true;
                    let route = error.route.child_data(error.next)?;
                    error.next = add(error.next, 1)?;
                    match name {
                        "details" => {
                            if !matches!(value.kind_data()?, Kind::Object(_)) {
                                return Err(invalid());
                            }
                            self.group = Some(Group {
                                kind: GroupKind::ErrorDetail,
                                route,
                                next: 0,
                            });
                        }
                        "effect" => {
                            effect_data(value)?;
                        }
                        "retryable" => {
                            if !matches!(value.kind_data()?, Kind::Bool(_)) {
                                return Err(invalid());
                            }
                        }
                        _ => {
                            if !matches!(value.kind_data()?, Kind::String(_)) {
                                return Err(invalid());
                            }
                        }
                    }
                    continue;
                }
                if error.present.iter().any(|present| !present) {
                    return Err(invalid());
                }
                self.error = None;
            }
            let Some(name) = source.body_name_data(self.body)? else {
                if self.present != 7 {
                    return Err(invalid());
                }
                self.finished = true;
                return Ok(None);
            };
            let member = self.body;
            self.body = add(member, 1)?;
            if name == "status" {
                continue;
            }
            let route = Route::root_data(member);
            let value = source.value_data(route)?;
            let mask = match name {
                "operation_state" => 1,
                "extensions" => 2,
                "result" if self.status != Some(Status::Error) => 4,
                "error" if self.status == Some(Status::Error) => 4,
                _ => return Err(invalid()),
            };
            if self.present & mask != 0 {
                return Err(invalid());
            }
            self.present |= mask;
            match name {
                "operation_state" => {
                    operation_data(value)?;
                }
                "extensions" | "result" => {
                    if !matches!(value.kind_data()?, Kind::Object(_)) {
                        return Err(invalid());
                    }
                    self.group = Some(Group {
                        kind: if name == "extensions" {
                            GroupKind::Extension
                        } else {
                            GroupKind::Result
                        },
                        route,
                        next: 0,
                    });
                }
                "error" => {
                    if !matches!(value.kind_data()?, Kind::Object(_) | Kind::Array(_)) {
                        return Err(invalid());
                    }
                    self.error = Some(ErrorFields {
                        route,
                        next: 0,
                        present: [false; 5],
                    });
                }
                _ => return Err(invalid()),
            }
        }
    }
}

pub(super) fn resolve_data(mut value: Flat<'_>, route: Route) -> Result<Flat<'_>, ProviderError> {
    for position in route.path.into_iter().flatten() {
        value = match value.kind_data()? {
            Kind::Object(mut fields) => fields.nth(position).map(|(_, v)| v).ok_or_else(invalid)?,
            Kind::Array(mut fields) => fields.nth(position).ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
    }
    Ok(value)
}

fn unit_variant_data(value: Flat<'_>) -> Result<&str, ProviderError> {
    match value.kind_data()? {
        Kind::String(value) => Ok(value),
        Kind::Object(mut values) => {
            let (key, value) = values.next().ok_or_else(invalid)?;
            if values.next().is_some() || !matches!(value.kind_data()?, Kind::Null) {
                return Err(invalid());
            }
            Ok(key)
        }
        _ => Err(invalid()),
    }
}

fn operation_data(value: Flat<'_>) -> Result<OperationState, ProviderError> {
    Ok(match unit_variant_data(value)? {
        "not_started" => OperationState::NotStarted,
        "running" => OperationState::Running,
        "completed" => OperationState::Completed,
        "unknown" => OperationState::Unknown,
        _ => return Err(invalid()),
    })
}

fn effect_data(value: Flat<'_>) -> Result<EffectCertainty, ProviderError> {
    Ok(match unit_variant_data(value)? {
        "not_started" => EffectCertainty::NotStarted,
        "in_progress" => EffectCertainty::InProgress,
        "completed" => EffectCertainty::Completed,
        "unknown" => EffectCertainty::Unknown,
        _ => return Err(invalid()),
    })
}

pub(super) fn initializer_data() -> usize {
    size_of::<Schedule>() * 2
        + size_of::<Group>()
        + size_of::<Option<Group>>()
        + size_of::<ErrorFields>()
        + size_of::<Option<ErrorFields>>()
        + size_of::<SelectedCut>()
        + size_of::<Option<SelectedCut>>()
        + size_of::<Route>() * 2
        + size_of::<[Option<usize>; 2]>() * 2
}

pub(super) fn counter_data() -> usize {
    size_of::<Schedule>()
        + size_of::<&mut Schedule>() * 3
        + size_of::<&Schedule>()
        + size_of::<Route>() * 4
        + size_of::<Result<Route, ProviderError>>()
        + size_of::<Option<Route>>()
        + size_of::<SelectedCut>() * 2
        + size_of::<Option<SelectedCut>>()
        + size_of::<Result<Option<SelectedCut>, ProviderError>>()
        + size_of::<Status>()
        + size_of::<Option<Status>>()
        + size_of::<GroupKind>()
        + size_of::<Group>()
        + size_of::<Option<Group>>()
        + size_of::<&mut Group>()
        + size_of::<ErrorFields>()
        + size_of::<Option<ErrorFields>>()
        + size_of::<&mut ErrorFields>()
        + size_of::<Flat<'static>>() * 4
        + size_of::<Result<Flat<'static>, ProviderError>>()
        + size_of::<Kind<'static>>() * 3
        + size_of::<Result<Kind<'static>, ProviderError>>()
        + size_of::<NativeImport18FirstFlatObjectData<'static>>() * 2
        + size_of::<NativeImport18FirstFlatArrayData<'static>>() * 2
        + size_of::<Option<(&str, Flat<'static>)>>() * 2
        + size_of::<Option<Flat<'static>>>()
        + size_of::<(&str, Flat<'static>)>() * 2
        + size_of::<&str>() * 4
        + size_of::<Option<&str>>()
        + size_of::<Result<Option<&str>, ProviderError>>()
        + size_of::<std::slice::IterMut<'static, Option<usize>>>()
        // find borrows its iterator mutably and lends a reference to its
        // mutable-reference item to the predicate before returning that item.
        + size_of::<&mut std::slice::IterMut<'static, Option<usize>>>()
        + size_of::<&&mut Option<usize>>()
        + size_of::<std::array::IntoIter<Option<usize>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<Option<usize>, 2>>>()
        + size_of::<Option<&mut Option<usize>>>()
        + size_of::<&mut Option<usize>>() * 2
        + size_of::<std::slice::Iter<'static, bool>>()
        + size_of::<&bool>()
        + size_of::<[bool; 5]>() * 2
        + size_of::<[Option<usize>; 2]>() * 2
        + size_of::<Option<usize>>() * 2
        + size_of::<usize>() * 15
        + size_of::<u8>() * 3
        + size_of::<bool>() * 5
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<OperationState>()
        + size_of::<EffectCertainty>()
        + size_of::<Result<&str, ProviderError>>()
        + super::super::super::state_view::counter_scratch_data()
}
