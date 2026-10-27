//! Destroys every retained literal Value with the owner's preadmitted worklist.
//!
//! The bank is reserved from the exact number of Value-producing tokens before
//! construction begins. Completed roots, pending values and open-frame children
//! are disjoint parts of that population. Draining one part at a time therefore
//! needs at most that many worklist slots, including all failure states.
//!
//! Each container gives up all children before its ordinary destructor runs.
//! String/key/Number and empty-container destruction is shallow. This walk never
//! allocates, clones a Value, returns a fallible result or forgets an allocation.

use super::*;

impl Drop for LiteralValue18DecodeAttempt {
    fn drop(&mut self) {
        self.retire_values();
    }
}

impl LiteralValue18DecodeAttempt {
    // This is the sole production retirement path. It leaves both vectors
    // empty before Rust drops their backing; no default field destructor can
    // encounter an owning deep subtree after this method returns.
    fn retire_values(&mut self) {
        if let Some(value) = self.value.take() {
            retire_tree(value, &mut self.retirement);
        }
        if let Some(value) = self.pending.take() {
            retire_tree(value, &mut self.retirement);
        }
        while let Some(frame) = self.frames.pop() {
            match frame {
                Frame::Array(values) => retire_tree(Value::Array(values), &mut self.retirement),
                Frame::Object { values, key } => {
                    drop(key);
                    retire_tree(Value::Object(values), &mut self.retirement);
                }
            }
        }
    }
}

fn retire_tree(value: Value, workspace: &mut Vec<Value>) {
    // The constructor's private population invariant supplies spare capacity
    // for every push. No owner or mutable Value is exposed to callers, and no
    // traversal bank is allocated or replenished during this destructor.
    workspace.push(value);
    while let Some(value) = workspace.pop() {
        match value {
            Value::Array(values) => {
                for child in values {
                    workspace.push(child);
                }
            }
            Value::Object(values) => {
                for (key, child) in values {
                    drop(key);
                    workspace.push(child);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

/// Names actual constant-stack retirement arguments, ownership and iterator views.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<&mut LiteralValue18DecodeAttempt>()
        + size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Frame>()
        + size_of::<Option<Frame>>()
        + size_of::<Vec<Value>>()
        + size_of::<&mut Vec<Value>>()
        + size_of::<std::vec::IntoIter<Value>>()
        + size_of::<Map<String, Value>>()
        + size_of::<serde_json::map::IntoIter>()
        + size_of::<std::collections::btree_map::IntoIter<String, Value>>()
        + size_of::<(String, Value)>()
        + size_of::<Option<(String, Value)>>()
        + size_of::<String>()
        + size_of::<Option<String>>()
}

#[cfg(test)]
#[path = "retirement/tests.rs"]
mod tests;
