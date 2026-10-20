//! Traverses an actual existing strict raw Value with bounded borrowed frames.
//!
//! This walker creates no owned JSON, applies no Raw normalization and changes
//! no ordinary parser bound. The existing strict source admits at most sixty-
//! four containers. A caller can skip a Raw branch only after its independent
//! complete source prewalk has checked that original bound.

use super::*;

const RAW_CONTAINER_LIMIT: usize = 64;

enum Frame<'a> {
    Array {
        entries: std::slice::Iter<'a, Value>,
        depth: usize,
    },
    Object {
        entries: serde_json::map::Iter<'a>,
        depth: usize,
    },
}

pub(super) struct Walk<'a> {
    root: &'a Value,
    current: Option<(&'a Value, usize)>,
    frames: [Option<Frame<'a>>; RAW_CONTAINER_LIMIT],
    length: usize,
    first: bool,
    skip: bool,
    finished: bool,
}

impl<'a> Walk<'a> {
    pub(super) fn new_data(root: &'a Value) -> Self {
        Self {
            root,
            current: None,
            frames: std::array::from_fn(|_| None),
            length: 0,
            first: true,
            skip: false,
            finished: false,
        }
    }

    pub(super) fn skip_children_data(&mut self) {
        self.skip = true;
    }

    pub(super) fn next_data(&mut self) -> Result<Option<(&'a Value, usize)>, ProviderError> {
        if self.finished {
            return Ok(None);
        }
        if self.first {
            self.first = false;
            return self.return_data(self.root, 0).map(Some);
        }
        if !self.skip {
            if let Some((value, depth)) = self.current {
                let frame = match value {
                    Value::Array(values) => Some(Frame::Array {
                        entries: values.iter(),
                        depth,
                    }),
                    Value::Object(values) => Some(Frame::Object {
                        entries: values.iter(),
                        depth,
                    }),
                    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
                };
                if let Some(frame) = frame {
                    let slot = self.frames.get_mut(self.length).ok_or_else(invalid)?;
                    *slot = Some(frame);
                    self.length += 1;
                }
            }
        }
        self.skip = false;
        while self.length != 0 {
            let last = self.length - 1;
            let next = match self.frames[last].as_mut().ok_or_else(invalid)? {
                Frame::Array { entries, depth } => entries.next().map(|value| (value, *depth)),
                Frame::Object { entries, depth } => {
                    entries.next().map(|(_, value)| (value, *depth))
                }
            };
            if let Some((value, parent_depth)) = next {
                return self.return_data(value, parent_depth).map(Some);
            }
            self.frames[last] = None;
            self.length = last;
        }
        self.current = None;
        self.finished = true;
        Ok(None)
    }

    fn return_data(
        &mut self,
        value: &'a Value,
        parent_depth: usize,
    ) -> Result<(&'a Value, usize), ProviderError> {
        let container = matches!(value, Value::Array(_) | Value::Object(_));
        let depth = parent_depth
            .checked_add(usize::from(container))
            .ok_or_else(exhausted)?;
        if depth > RAW_CONTAINER_LIMIT {
            return Err(invalid());
        }
        self.current = Some((value, depth));
        Ok((value, depth))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Walk<'static>>()
        + size_of::<&mut Walk<'static>>()
        + size_of::<[Option<Frame<'static>>; RAW_CONTAINER_LIMIT]>()
        + size_of::<Frame<'static>>()
        + size_of::<Option<Frame<'static>>>()
        + size_of::<&mut Option<Frame<'static>>>()
        + size_of::<Option<&mut Option<Frame<'static>>>>()
        + size_of::<Result<&mut Option<Frame<'static>>, ProviderError>>()
        + size_of::<&mut Frame<'static>>()
        + size_of::<Result<&mut Frame<'static>, ProviderError>>()
        + size_of::<Option<&mut Frame<'static>>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<(&Value, usize)>>()
        + size_of::<(&Value, usize)>()
        + size_of::<Result<Option<(&Value, usize)>, ProviderError>>()
        + size_of::<Result<(&Value, usize), ProviderError>>()
        + size_of::<&Value>()
        + size_of::<Option<&Value>>()
        + size_of::<(&String, &Value)>()
        + size_of::<Option<(&String, &Value)>>()
        + size_of::<bool>()
        // Length/last/depth/parent-depth and the array initializer ordinal.
        + size_of::<usize>() * 5
}
