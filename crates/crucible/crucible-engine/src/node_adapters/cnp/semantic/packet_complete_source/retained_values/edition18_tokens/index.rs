//! Validates literal token chronology and records exact constructor child counts.
//!
//! The index is a private disposable DATA cache, omitted from the wire. It is
//! constructed from the actual immutable tokens before the token attempt can
//! complete; callers cannot mutate either bank or substitute numeric counts.

use super::*;

/// Tracks actual container chronology and borrows its previous object key.
pub(super) enum Frame<'a> {
    Array {
        start: usize,
        children: usize,
    },
    Object {
        start: usize,
        keys: usize,
        expects_key: bool,
        previous: Option<&'a str>,
    },
}

fn accept_value(frames: &mut [Frame<'_>], roots: &mut usize) -> Result<(), RuntimeError> {
    match frames.last_mut() {
        Some(Frame::Array { children, .. }) => {
            *children = children.checked_add(1).ok_or(RuntimeError::ResourceLimit)?
        }
        Some(Frame::Object { expects_key, .. }) if !*expects_key => *expects_key = true,
        None if *roots == 0 => *roots = 1,
        _ => return Err(RuntimeError::UnsupportedFacet),
    }
    Ok(())
}

/// Rebuilds exact child counts from the actual closed immutable token sequence.
///
/// # Errors
/// Refuses insufficient workspace, multiple roots, mismatched closes, missing
/// values, duplicate/unsorted keys, incomplete cache or allocation failure.
pub(super) fn finish(data: &mut LiteralValue18Data, containers: usize) -> Result<(), RuntimeError> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(containers)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let mut roots = 0usize;
    let mut index = 0usize;
    // Borrow disjoint actual banks: token references stay only in this local
    // workspace while the already owned numeric cache is populated.
    let LiteralValue18Data {
        chunks,
        container_children,
    } = data;
    for token in chunks.iter().flatten() {
        match token {
            LiteralToken18::ArrayStart | LiteralToken18::ObjectStart => {
                accept_value(&mut frames, &mut roots)?;
                if frames.len() == frames.capacity() {
                    return Err(RuntimeError::ResourceLimit);
                }
                frames.push(if matches!(token, LiteralToken18::ArrayStart) {
                    Frame::Array {
                        start: index,
                        children: 0,
                    }
                } else {
                    Frame::Object {
                        start: index,
                        keys: 0,
                        expects_key: true,
                        previous: None,
                    }
                });
            }
            LiteralToken18::Key(key) => {
                let Some(Frame::Object {
                    keys,
                    expects_key,
                    previous,
                    ..
                }) = frames.last_mut()
                else {
                    return Err(RuntimeError::UnsupportedFacet);
                };
                if !*expects_key || previous.is_some_and(|previous| previous >= key.as_str()) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                *keys = keys.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                *expects_key = false;
                *previous = Some(key);
            }
            LiteralToken18::ArrayEnd => {
                if !matches!(frames.last(), Some(Frame::Array { .. })) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let Some(Frame::Array { start, children }) = frames.pop() else {
                    return Err(RuntimeError::OwnerUnavailable);
                };
                *container_children
                    .get_mut(start)
                    .ok_or(RuntimeError::OwnerUnavailable)? = children;
            }
            LiteralToken18::ObjectEnd => {
                if !matches!(
                    frames.last(),
                    Some(Frame::Object {
                        expects_key: true,
                        ..
                    })
                ) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let Some(Frame::Object { start, keys, .. }) = frames.pop() else {
                    return Err(RuntimeError::OwnerUnavailable);
                };
                *container_children
                    .get_mut(start)
                    .ok_or(RuntimeError::OwnerUnavailable)? = keys;
            }
            _ => accept_value(&mut frames, &mut roots)?,
        }
        index = index.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    }
    if roots != 1 || !frames.is_empty() || container_children.len() != index {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(())
}
