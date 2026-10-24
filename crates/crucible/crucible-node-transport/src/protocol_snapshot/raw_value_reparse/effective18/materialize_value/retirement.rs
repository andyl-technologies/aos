//! Retires every construction prefix without a recursive Value destructor.

use super::*;

impl Drop for NativeImport18GuardedValueAttemptData {
    fn drop(&mut self) {
        self.retire_all_data();
    }
}

impl NativeImport18GuardedValueAttemptData {
    pub(super) fn retire_all_data(&mut self) {
        if let Some(value) = self.pending.take() {
            retire_tree(value, &mut self.retirement);
        }
        if let Some(value) = self.pending_old.take() {
            retire_tree(value, &mut self.retirement);
        }
        if let Some(value) = self.root.take() {
            retire_tree(value, &mut self.retirement);
        }
        while let Some(frame) = self.frames.pop() {
            match frame.container {
                Container::Array(values) => retire_tree(Value::Array(values), &mut self.retirement),
                Container::Object(values) => {
                    retire_tree(Value::Object(values), &mut self.retirement)
                }
            }
        }
        // Work contains only indices and shallow String keys. Explicit pops
        // leave the reserved Vec shell empty on every failed prefix as well.
        while self.work.pop().is_some() {}
        self.destination = None;
        self.key = None;
        self.string_bytes = 0;
        self.array_bytes = 0;
        self.tree_members = 0;
        self.tree_containers = 0;
    }
}

fn retire_tree(value: Value, workspace: &mut Vec<Value>) {
    // The disjoint source populations plus actual array placeholders bound all
    // children. Capacity exists before any deep construction; no bank is
    // replenished by this destructor and no child receives Value::drop intact.
    workspace.push(value);
    while let Some(value) = workspace.pop() {
        match value {
            Value::Array(values) => {
                for child in values {
                    workspace.push(child);
                }
            }
            Value::Object(values) => {
                for (_, child) in values {
                    workspace.push(child);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}
