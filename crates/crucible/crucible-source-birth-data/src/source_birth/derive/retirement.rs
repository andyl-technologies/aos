//! Installs successful DOM roots immediately and retires them without recursion.
//!
//! This is contained-child cleanup, not allocator admission. Before moving any
//! child into a work bank, its slot is reserved fallibly. Refusal terminates the
//! isolated child rather than unwinding into recursive Value destruction.

use serde_json::Value;

pub(super) struct RetainedValue(Value);

impl RetainedValue {
    pub(super) fn new(value: Value) -> Self {
        Self(value)
    }

    pub(super) fn value(&self) -> &Value {
        &self.0
    }
}

fn reserve_one(bank: &mut Vec<Value>) {
    if bank.try_reserve(1).is_err() {
        std::process::abort();
    }
}

impl Drop for RetainedValue {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        reserve_one(&mut pending);
        pending.push(std::mem::replace(&mut self.0, Value::Null));
        while let Some(value) = pending.pop() {
            match value {
                Value::Array(values) => {
                    let mut values = values.into_iter();
                    while values.len() != 0 {
                        reserve_one(&mut pending);
                        if let Some(child) = values.next() {
                            pending.push(child);
                        }
                    }
                }
                Value::Object(values) => {
                    let mut values = values.into_iter();
                    while values.len() != 0 {
                        reserve_one(&mut pending);
                        if let Some((_key, child)) = values.next() {
                            pending.push(child);
                        }
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
    }
}

#[cfg(test)]
#[path = "retirement/tests.rs"]
mod tests;
