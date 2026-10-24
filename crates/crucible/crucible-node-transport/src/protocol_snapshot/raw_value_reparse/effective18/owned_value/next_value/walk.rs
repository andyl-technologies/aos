//! Walks actual prior raw/flat nodes with an independently funded borrowed spine.
//!
//! The spine owns only iterator headers. Dropping it on any quote/read failure
//! is flat and cannot drop a user Value. Its capacity comes from actual prior
//! physical node populations, not an increased parser or logical depth limit.

use super::*;

pub(super) enum Frame<'a> {
    Array {
        entries: SourceArray<'a>,
        depth: usize,
    },
    Object {
        entries: SourceObject<'a>,
        depth: usize,
    },
}

pub(super) struct Walk<'a> {
    root: SourceView<'a>,
    current: Option<(SourceView<'a>, usize)>,
    frames: Vec<Frame<'a>>,
    population: usize,
    visited: usize,
    first: bool,
    skip: bool,
    finished: bool,
}

impl<'a> Walk<'a> {
    pub(super) fn new_data(
        input: NativeImport18NextValueInputData<'a>,
        population: usize,
    ) -> Result<Self, ProviderError> {
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(population)
            .map_err(|_| exhausted())?;
        if frames.capacity() > population {
            // Observe a reserve implementation that exceeds the independently
            // priced spine before any logical walk or child construction. The
            // borrowed iterator bank drops flat on this refusal.
            return Err(exhausted());
        }
        Ok(Self {
            root: input.selected,
            current: None,
            frames,
            population,
            visited: 0,
            first: true,
            skip: false,
            finished: false,
        })
    }

    pub(super) fn skip_children_data(&mut self) {
        self.skip = true;
    }

    pub(super) fn next_data(&mut self) -> Result<Option<(SourceView<'a>, usize)>, ProviderError> {
        if self.finished {
            return Ok(None);
        }
        if self.first {
            self.first = false;
            return self.return_data(self.root, 0).map(Some);
        }
        if !self.skip
            && let Some((value, depth)) = self.current
        {
            let frame = match value.kind_data()? {
                SourceKind::Array(entries) => Some(Frame::Array { entries, depth }),
                SourceKind::Object(entries) => Some(Frame::Object { entries, depth }),
                _ => None,
            };
            if let Some(frame) = frame {
                if self.frames.len() >= self.population {
                    return Err(exhausted());
                }
                self.frames.push(frame);
            }
        }
        self.skip = false;
        while let Some(frame) = self.frames.last_mut() {
            let next = match frame {
                Frame::Array { entries, depth } => entries.next().map(|value| (value, *depth)),
                Frame::Object { entries, depth } => {
                    entries.next().map(|(_, value)| (value, *depth))
                }
            };
            if let Some((value, depth)) = next {
                return self.return_data(value, depth).map(Some);
            }
            self.frames.pop();
        }
        self.current = None;
        self.finished = true;
        Ok(None)
    }

    fn return_data(
        &mut self,
        value: SourceView<'a>,
        parent: usize,
    ) -> Result<(SourceView<'a>, usize), ProviderError> {
        self.visited = add(self.visited, 1)?;
        if self.visited > self.population {
            return Err(exhausted());
        }
        let container = matches!(
            value.kind_data()?,
            SourceKind::Array(_) | SourceKind::Object(_)
        );
        let depth = add(parent, usize::from(container))?;
        self.current = Some((value, depth));
        Ok((value, depth))
    }
}

pub(super) fn workspace_data(population: usize) -> Result<usize, ProviderError> {
    mul(population, size_of::<Frame<'static>>())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Walk<'static>>() * 2
        + size_of::<Result<Walk<'static>, ProviderError>>()
        + size_of::<Vec<Frame<'static>>>() * 2
        + size_of::<Frame<'static>>() * 2
        + size_of::<Option<Frame<'static>>>()
        + size_of::<&mut Walk<'static>>()
        + size_of::<&mut Vec<Frame<'static>>>()
        + size_of::<Option<&mut Frame<'static>>>()
        + size_of::<&mut Frame<'static>>()
        + size_of::<Option<(SourceView<'static>, usize)>>()
        + size_of::<(SourceView<'static>, usize)>()
        + size_of::<Result<Option<(SourceView<'static>, usize)>, ProviderError>>()
        + size_of::<Result<(SourceView<'static>, usize), ProviderError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<usize>() * 5
        + size_of::<bool>()
}
