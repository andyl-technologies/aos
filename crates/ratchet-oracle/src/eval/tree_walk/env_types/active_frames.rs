//! Persistent active lexical-frame chain with an unlinked compatibility path.

use super::*;

/// Inline capacity for compatibility active lexical frame suffixes.
const ACTIVE_ENV_INLINE_FRAMES: usize = 2;

/// The active lexical suffix as a persistent innermost frame head.
///
/// Production frames already carry immutable parent links. Retaining only the
/// innermost head makes captured-environment installation and suspension one
/// `Arc` clone instead of rebuilding an outermost-first frame stack. The
/// inline compatibility array is reserved for independently constructed frames
/// that do not form a parent-linked production chain.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveEvalFrames {
    head: Option<Arc<EvalFrame>>,
    len: usize,
    compatibility: Option<smallvec::SmallVec<[Arc<EvalFrame>; ACTIVE_ENV_INLINE_FRAMES]>>,
}

impl ActiveEvalFrames {
    pub(crate) const fn new() -> Self {
        Self {
            head: None,
            len: 0,
            compatibility: None,
        }
    }

    pub(crate) fn from_linked(head: Option<Arc<EvalFrame>>, len: usize) -> Self {
        debug_assert_eq!(head.is_some(), len != 0);
        Self {
            head,
            len,
            compatibility: None,
        }
    }

    pub(crate) fn from_vec(frames: Vec<Arc<EvalFrame>>) -> Self {
        if frames.windows(2).all(|pair| {
            pair[1]
                .parent()
                .is_some_and(|parent| Arc::ptr_eq(parent, &pair[0]))
        }) {
            return Self::from_linked(frames.last().cloned(), frames.len());
        }
        let frames = smallvec::SmallVec::from_vec(frames);
        Self {
            head: frames.last().cloned(),
            len: frames.len(),
            compatibility: Some(frames),
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn last(&self) -> Option<&Arc<EvalFrame>> {
        self.head.as_ref()
    }

    pub(crate) fn linked_parts(&self) -> Option<(Option<&Arc<EvalFrame>>, usize)> {
        self.compatibility
            .is_none()
            .then_some((self.head.as_ref(), self.len))
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Arc<EvalFrame>> {
        if index >= self.len {
            return None;
        }
        if let Some(frames) = &self.compatibility {
            return frames.get(index);
        }
        let mut frame = self.head.as_ref();
        for _ in 0..self.len.saturating_sub(index + 1) {
            frame = frame?.parent();
        }
        frame
    }

    pub(crate) fn get_at_depth(&self, depth: usize) -> Option<&Arc<EvalFrame>> {
        if depth >= self.len {
            return None;
        }
        if let Some(frames) = &self.compatibility {
            return frames.get(self.len - 1 - depth);
        }
        let mut frame = self.head.as_ref();
        for _ in 0..depth {
            frame = frame?.parent();
        }
        frame
    }

    pub(crate) fn push(&mut self, frame: Arc<EvalFrame>) {
        if let Some(frames) = &mut self.compatibility {
            frames.push(Arc::clone(&frame));
        }
        self.head = Some(frame);
        self.len = self.len.saturating_add(1);
    }

    pub(crate) fn try_reserve_exact(&mut self, additional: usize) -> Result<(), ()> {
        if let Some(frames) = &mut self.compatibility {
            frames.try_reserve_exact(additional).map_err(|_| ())?;
        }
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Arc<EvalFrame>> {
        if let Some(frames) = &mut self.compatibility {
            let frame = frames.pop()?;
            self.head = frames.last().cloned();
            self.len = frames.len();
            return Some(frame);
        }
        let frame = self.head.take()?;
        self.head = frame.parent().cloned();
        self.len = self.len.saturating_sub(1);
        Some(frame)
    }

    pub(crate) fn iter_innermost(&self) -> ActiveEvalFramesInnermostIter<'_> {
        match &self.compatibility {
            Some(frames) => ActiveEvalFramesInnermostIter {
                inner: ActiveEvalFramesInnermostIterInner::Compatibility(frames.iter().rev()),
            },
            None => ActiveEvalFramesInnermostIter {
                inner: ActiveEvalFramesInnermostIterInner::Linked(self.head.as_ref()),
            },
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<Arc<EvalFrame>> {
        let mut frames: Vec<_> = self.iter_innermost().cloned().collect();
        frames.reverse();
        frames
    }
}

pub(crate) struct ActiveEvalFramesInnermostIter<'a> {
    inner: ActiveEvalFramesInnermostIterInner<'a>,
}

enum ActiveEvalFramesInnermostIterInner<'a> {
    Linked(Option<&'a Arc<EvalFrame>>),
    Compatibility(std::iter::Rev<std::slice::Iter<'a, Arc<EvalFrame>>>),
}

impl<'a> Iterator for ActiveEvalFramesInnermostIter<'a> {
    type Item = &'a Arc<EvalFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            ActiveEvalFramesInnermostIterInner::Linked(frame) => {
                let current = frame.take()?;
                *frame = current.parent();
                Some(current)
            }
            ActiveEvalFramesInnermostIterInner::Compatibility(frames) => frames.next(),
        }
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for ActiveEvalFrames {
    type Output = Arc<EvalFrame>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .unwrap_or_else(|| panic!("active frame index {index} is out of bounds"))
    }
}

#[cfg(test)]
mod tests;
