//! Copies one decoded literal iteratively inside the bounded child only.
//!
//! This explicit extra owning graph is never constructed by the parent writer.
//! Each pending child, key and container belongs to State before later work.

use super::*;
use serde_json::{Map, Value};

enum Frame<'a> {
    Array {
        input: std::slice::Iter<'a, Value>,
        output: Vec<Value>,
    },
    Object {
        input: serde_json::map::Iter<'a>,
        output: Map<String, Value>,
        key: Option<String>,
    },
}
struct State<'a> {
    current: Option<Value>,
    frames: Vec<Frame<'a>>,
}
impl Drop for State<'_> {
    fn drop(&mut self) {
        self.current.retire();
        for frame in &mut self.frames {
            match frame {
                Frame::Array { output, .. } => output.retire(),
                Frame::Object { output, .. } => {
                    for value in output.values_mut() {
                        value.retire();
                    }
                }
            }
        }
    }
}
fn text(value: &str) -> Result<String, CodecError> {
    let mut out = String::new();
    out.try_reserve_exact(value.len())?;
    out.push_str(value);
    Ok(out)
}

pub(super) fn clone_inside_child<R: Read>(
    root: &Value,
    input: &mut Decoder<R>,
) -> Result<Owned<Value>, CodecError> {
    let mut state = State {
        current: None,
        frames: Vec::new(),
    };
    let mut next = Some(root);
    loop {
        if let Some(value) = next.take() {
            input.item()?;
            match value {
                Value::Array(values) => {
                    state.frames.try_reserve(1)?;
                    state.frames.push(Frame::Array {
                        input: values.iter(),
                        output: Vec::new(),
                    });
                }
                Value::Object(values) => {
                    state.frames.try_reserve(1)?;
                    state.frames.push(Frame::Object {
                        input: values.iter(),
                        output: Map::new(),
                        key: None,
                    });
                }
                Value::String(value) => state.current = Some(Value::String(text(value)?)),
                Value::Number(value) => state.current = Some(Value::Number(value.clone())),
                Value::Bool(value) => state.current = Some(Value::Bool(*value)),
                Value::Null => state.current = Some(Value::Null),
            }
        }
        if state.current.is_some() {
            let Some(frame) = state.frames.last_mut() else {
                return Ok(Owned::new(match state.current.take() {
                    Some(v) => v,
                    None => std::process::abort(),
                }));
            };
            match frame {
                Frame::Array { output, .. } => {
                    output.try_reserve(1)?;
                    output.push(match state.current.take() {
                        Some(v) => v,
                        None => std::process::abort(),
                    });
                }
                Frame::Object { output, key, .. } => {
                    let key = match key.take() {
                        Some(v) => v,
                        None => std::process::abort(),
                    };
                    let value = match state.current.take() {
                        Some(v) => v,
                        None => std::process::abort(),
                    };
                    output.insert(key, value);
                }
            }
        }
        let Some(frame) = state.frames.last_mut() else {
            std::process::abort()
        };
        match frame {
            Frame::Array { input, .. } => next = input.next(),
            Frame::Object { input, key, .. } => {
                if let Some((name, value)) = input.next() {
                    *key = Some(text(name)?);
                    next = Some(value);
                }
            }
        }
        if next.is_none() {
            let frame = match state.frames.pop() {
                Some(frame) => frame,
                None => std::process::abort(),
            };
            state.current = Some(match frame {
                Frame::Array { output, .. } => Value::Array(output),
                Frame::Object { output, .. } => Value::Object(output),
            });
        }
    }
}
