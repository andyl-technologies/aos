//! Stores the three possible deadline provenance categories inline.
//!
//! Progress, total and outer allowances can tie. Their bounded report storage
//! owns no heap allocation and supplies the same ordered slice to wire codecs.

use std::fmt;
use std::ops::{Deref, DerefMut};

use super::HostDeadlineSource;

/// Stores at most three ordered deadline sources without allocating.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HostDeadlineSources {
    entries: [HostDeadlineSource; 3],
    len: usize,
}

impl HostDeadlineSources {
    /// Returns the initialized provenance in its original order.
    pub fn as_slice(&self) -> &[HostDeadlineSource] {
        &self.entries[..self.len]
    }
}

impl Default for HostDeadlineSources {
    fn default() -> Self {
        Self {
            entries: [HostDeadlineSource::Progress(0); 3],
            len: 0,
        }
    }
}

impl From<[Option<HostDeadlineSource>; 3]> for HostDeadlineSources {
    fn from(candidates: [Option<HostDeadlineSource>; 3]) -> Self {
        let mut sources = Self::default();

        // The input itself bounds the initialized prefix; absent categories
        // consume no slot and cannot change the order of the remaining ones.
        for (index, source) in candidates.into_iter().flatten().enumerate() {
            sources.entries[index] = source;
            sources.len = index + 1;
        }

        sources
    }
}

impl From<[HostDeadlineSource; 1]> for HostDeadlineSources {
    fn from([first]: [HostDeadlineSource; 1]) -> Self {
        [Some(first), None, None].into()
    }
}

impl From<[HostDeadlineSource; 2]> for HostDeadlineSources {
    fn from([first, second]: [HostDeadlineSource; 2]) -> Self {
        [Some(first), Some(second), None].into()
    }
}

impl From<[HostDeadlineSource; 3]> for HostDeadlineSources {
    fn from(sources: [HostDeadlineSource; 3]) -> Self {
        sources.map(Some).into()
    }
}

impl fmt::Debug for HostDeadlineSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.as_slice()).finish()
    }
}

impl Deref for HostDeadlineSources {
    type Target = [HostDeadlineSource];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for HostDeadlineSources {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries[..self.len]
    }
}

impl AsRef<[HostDeadlineSource]> for HostDeadlineSources {
    fn as_ref(&self) -> &[HostDeadlineSource] {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a HostDeadlineSources {
    type Item = &'a HostDeadlineSource;
    type IntoIter = std::slice::Iter<'a, HostDeadlineSource>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}
