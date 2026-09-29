//! Validates generic property values with input-proportional traversal state.
//!
//! Generic CBOR nesting has no independent format depth cap. The encoded
//! property byte bound limits traversal memory; claimed collection lengths
//! never determine an allocation size.

use super::Error;
use crate::cbor::Decoder;
use alloc::vec::Vec;

enum Frame<'a> {
    Array {
        remaining: usize,
    },
    Map {
        remaining: usize,
        previous: Option<&'a [u8]>,
    },
}

pub(super) fn skip_value(decoder: &mut Decoder<'_>, max_bytes: usize) -> Result<(), Error> {
    let start = decoder.position();
    let mut frames = Vec::new();
    frames.push(Frame::Array { remaining: 1 });

    while let Some(frame) = frames.last_mut() {
        match frame {
            Frame::Array { remaining } | Frame::Map { remaining, .. } if *remaining == 0 => {
                frames.pop();
                continue;
            }
            Frame::Array { remaining } => *remaining -= 1,
            Frame::Map {
                remaining,
                previous,
            } => {
                let key_start = decoder.position();
                if decoder.text(255)?.is_empty() {
                    return Err(Error::InvalidValue);
                }
                let key = decoder.slice(key_start, decoder.position())?;
                if previous.is_some_and(|prior| prior >= key) {
                    return Err(Error::InvalidValue);
                }
                *previous = Some(key);
                *remaining -= 1;
            }
        }

        match decoder.peek_major()? {
            0 => {
                decoder.uint()?;
            }
            3 => {
                decoder.text(max_bytes)?;
            }
            4 => {
                frames.push(Frame::Array {
                    remaining: decoder.array(max_bytes)?,
                });
            }
            5 => {
                frames.push(Frame::Map {
                    remaining: decoder.map(max_bytes)?,
                    previous: None,
                });
            }
            7 => {
                if !matches!(decoder.simple()?, 0xf4 | 0xf5) {
                    return Err(Error::InvalidValue);
                }
            }
            _ => return Err(Error::InvalidValue),
        }
        if decoder.position() - start > max_bytes {
            return Err(Error::Limit);
        }
    }
    Ok(())
}
