//! Builds one final tree through numeric work items and preinstalled owners.

use super::*;

impl NativeImport18GuardedValueAttemptData {
    pub(super) fn materialize_data(&mut self) -> Result<(), ProviderError> {
        let row = self.row.ok_or_else(invalid)?;
        // No deep child exists until the retirement reserve succeeds.
        self.retirement
            .try_reserve_exact(row.retirement)
            .map_err(|_| exhausted())?;
        self.work
            .try_reserve_exact(row.work)
            .map_err(|_| exhausted())?;
        self.frames
            .try_reserve_exact(row.frames)
            .map_err(|_| exhausted())?;
        if self.retirement.capacity() > row.retirement
            || self.work.capacity() > row.work
            || self.frames.capacity() > row.frames
        {
            return Err(exhausted());
        }
        let root = self
            .source
            .as_ref()
            .ok_or_else(invalid)?
            .completed_data()?
            .node;
        self.work.push(Work::Visit {
            node: root,
            destination: Destination::Root,
        });

        while !self.work.is_empty() {
            self.steps = self.steps.checked_add(1).ok_or_else(exhausted)?;
            if self.steps > row.work {
                return Err(exhausted());
            }
            #[cfg(test)]
            if self.fail_after == Some(self.steps) {
                return Err(invalid());
            }
            #[cfg(test)]
            if self.panic_after == Some(self.steps) {
                panic!("guarded materialization test interruption");
            }
            match self.work.pop().ok_or_else(invalid)? {
                Work::Visit { node, destination } => {
                    self.destination = Some(destination);
                    self.visit_data(node)?;
                }
                Work::Finish { frame } => self.finish_data(frame)?,
            }
        }
        if !self.frames.is_empty()
            || self.pending.is_some()
            || self.destination.is_some()
            || self.key.is_some()
            || self.pending_old.is_some()
            || self.root.is_none()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn visit_data(&mut self, node: usize) -> Result<(), ProviderError> {
        if self.pending.is_some() || self.pending_old.is_some() || self.key.is_some() {
            return Err(invalid());
        }
        let source = self.source.as_ref().ok_or_else(invalid)?;
        let view = NativeImport18EffectiveValueViewData {
            owner: source,
            node,
        };
        match view.kind_data()? {
            NativeImport18EffectiveValueKindData::Null => self.pending = Some(Value::Null),
            NativeImport18EffectiveValueKindData::Bool(value) => {
                self.pending = Some(Value::Bool(value));
            }
            NativeImport18EffectiveValueKindData::Number(value) => {
                self.pending = Some(Value::Number(value.clone()));
            }
            NativeImport18EffectiveValueKindData::String(text) => {
                self.pending = Some(Value::String(String::new()));
                let Some(Value::String(value)) = self.pending.as_mut() else {
                    return Err(invalid());
                };
                value
                    .try_reserve_exact(text.len())
                    .map_err(|_| exhausted())?;
                self.string_bytes = self
                    .string_bytes
                    .checked_add(value.capacity())
                    .ok_or_else(exhausted)?;
                if value.capacity() > text.len() {
                    return Err(exhausted());
                }
                value.push_str(text);
            }
            NativeImport18EffectiveValueKindData::Array(values) => {
                if self.frames.len() == self.frames.capacity() {
                    return Err(exhausted());
                }
                let frame = self.frames.len();
                self.frames.push(BuildFrame {
                    destination: self.destination.take().ok_or_else(invalid)?,
                    container: Container::Array(Vec::new()),
                });
                if self.work.len() == self.work.capacity() {
                    return Err(exhausted());
                }
                self.work.push(Work::Finish { frame });
                let mut length = 0usize;
                for child in values {
                    if self.work.len() == self.work.capacity() {
                        return Err(exhausted());
                    }
                    self.work.push(Work::Visit {
                        node: child.node,
                        destination: Destination::Array {
                            frame,
                            slot: length,
                        },
                    });
                    length = length.checked_add(1).ok_or_else(exhausted)?;
                }
                let Container::Array(values) = &mut self.frames[frame].container else {
                    return Err(invalid());
                };
                values.try_reserve_exact(length).map_err(|_| exhausted())?;
                let allocated = values
                    .capacity()
                    .checked_mul(size_of::<Value>())
                    .ok_or_else(exhausted)?;
                self.array_bytes = self
                    .array_bytes
                    .checked_add(allocated)
                    .ok_or_else(exhausted)?;
                if values.capacity() > length {
                    return Err(exhausted());
                }
                for _ in 0..length {
                    values.push(Value::Null);
                }
                return Ok(());
            }
            NativeImport18EffectiveValueKindData::Object(values) => {
                if self.frames.len() == self.frames.capacity() {
                    return Err(exhausted());
                }
                let frame = self.frames.len();
                self.frames.push(BuildFrame {
                    destination: self.destination.take().ok_or_else(invalid)?,
                    container: Container::Object(Map::new()),
                });
                if self.work.len() == self.work.capacity() {
                    return Err(exhausted());
                }
                self.work.push(Work::Finish { frame });
                for (text, child) in values {
                    self.key = Some(String::new());
                    let key = self.key.as_mut().ok_or_else(invalid)?;
                    key.try_reserve_exact(text.len()).map_err(|_| exhausted())?;
                    self.string_bytes = self
                        .string_bytes
                        .checked_add(key.capacity())
                        .ok_or_else(exhausted)?;
                    if key.capacity() > text.len() {
                        return Err(exhausted());
                    }
                    key.push_str(text);
                    if self.work.len() == self.work.capacity() {
                        return Err(exhausted());
                    }
                    self.work.push(Work::Visit {
                        node: child.node,
                        destination: Destination::Object {
                            frame,
                            key: self.key.take().ok_or_else(invalid)?,
                        },
                    });
                }
                return Ok(());
            }
        }
        self.attach_data()
    }

    fn finish_data(&mut self, frame: usize) -> Result<(), ProviderError> {
        if frame.checked_add(1) != Some(self.frames.len())
            || self.pending.is_some()
            || self.destination.is_some()
        {
            return Err(invalid());
        }
        // No fallible operation separates this pop from the guarded assignment.
        let BuildFrame {
            destination,
            container,
        } = self.frames.pop().ok_or_else(invalid)?;
        self.pending = Some(match container {
            Container::Array(values) => Value::Array(values),
            Container::Object(values) => Value::Object(values),
        });
        self.destination = Some(destination);
        self.attach_data()
    }

    fn attach_data(&mut self) -> Result<(), ProviderError> {
        match self.destination.as_ref().ok_or_else(invalid)? {
            Destination::Root => {
                if self.root.is_some() || self.pending.is_none() {
                    return Err(invalid());
                }
                self.root = self.pending.take();
            }
            Destination::Array { frame, slot } => {
                let frame = self.frames.get_mut(*frame).ok_or_else(invalid)?;
                let Container::Array(values) = &mut frame.container else {
                    return Err(invalid());
                };
                let slot = values.get_mut(*slot).ok_or_else(invalid)?;
                self.pending_old = Some(std::mem::replace(
                    slot,
                    self.pending.take().ok_or_else(invalid)?,
                ));
                if !matches!(self.pending_old.as_ref(), Some(Value::Null)) {
                    return Err(invalid());
                }
                // The selected slot held only its preinstalled Null placeholder.
                self.pending_old = None;
            }
            Destination::Object { frame, key: _ } => {
                let index = *frame;
                let Some(BuildFrame {
                    container: Container::Object(values),
                    ..
                }) = self.frames.get(index)
                else {
                    return Err(invalid());
                };
                let members = self.tree_members.checked_add(1).ok_or_else(exhausted)?;
                let containers = self
                    .tree_containers
                    .checked_add(usize::from(values.is_empty()))
                    .ok_or_else(exhausted)?;
                if self.pending.is_none() {
                    return Err(invalid());
                }
                let Some(Destination::Object { key, .. }) = self.destination.take() else {
                    return Err(invalid());
                };
                let Container::Object(values) = &mut self.frames[index].container else {
                    return Err(invalid());
                };
                // String Ord has no user callback; the pinned GlobalAlloc
                // contract forbids unwind. Any replaced deep output is rooted
                // before validation; no default recursive destructor receives it.
                self.pending_old = values.insert(key, self.pending.take().ok_or_else(invalid)?);
                self.tree_containers = containers;
                if self.pending_old.is_some() {
                    return Err(invalid());
                }
                self.tree_members = members;
            }
        }
        self.destination = None;
        if self.pending.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}
