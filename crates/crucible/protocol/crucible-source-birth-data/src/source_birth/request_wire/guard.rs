//! Keeps every completed or partial typed field under explicit Value retirement.
//!
//! These guards run only in the contained child. Teardown workspace failure
//! aborts that child; it never falls back to recursively dropping deep Values.

use serde_json::Value;

pub(super) trait Retire {
    fn retire(&mut self);
}

pub(super) struct Owned<T: Retire> {
    value: Option<T>,
}

impl<T: Retire> Owned<T> {
    pub(super) fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    pub(super) fn get(&self) -> &T {
        match self.value.as_ref() {
            Some(value) => value,
            None => std::process::abort(),
        }
    }

    pub(super) fn get_mut(&mut self) -> &mut T {
        match self.value.as_mut() {
            Some(value) => value,
            None => std::process::abort(),
        }
    }

    // Private guards are created occupied and consumed once. All field reads
    // finish before this infallible move is used to assemble an actual DTO.
    pub(super) fn into_inner(mut self) -> T {
        match self.value.take() {
            Some(value) => value,
            None => std::process::abort(),
        }
    }
}

impl<T: Retire> Drop for Owned<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.as_mut() {
            value.retire();
        }
    }
}

pub(super) fn retire_value(root: &mut Value) {
    let mut pending = Vec::new();
    if pending.try_reserve(1).is_err() {
        std::process::abort();
    }
    pending.push(std::mem::take(root));
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(mut children) => {
                if pending.try_reserve(children.len()).is_err() {
                    std::process::abort();
                }
                pending.append(&mut children);
            }
            Value::Object(children) => {
                if pending.try_reserve(children.len()).is_err() {
                    std::process::abort();
                }
                for (_, child) in children {
                    pending.push(child);
                }
            }
            _ => {}
        }
    }
}

impl Retire for Value {
    fn retire(&mut self) {
        retire_value(self);
    }
}

impl<T: Retire> Retire for Vec<T> {
    fn retire(&mut self) {
        for value in self {
            value.retire();
        }
    }
}

impl<T: Retire> Retire for Option<T> {
    fn retire(&mut self) {
        if let Some(value) = self {
            value.retire();
        }
    }
}

impl<T: Retire> Retire for std::collections::BTreeMap<String, T> {
    fn retire(&mut self) {
        for value in self.values_mut() {
            value.retire();
        }
    }
}
