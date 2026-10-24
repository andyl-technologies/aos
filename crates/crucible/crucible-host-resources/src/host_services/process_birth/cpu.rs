//! Observes the same authenticated, retained campaign ancestor's CPU counters.
//!
//! These are independent kernel microsecond counters. The owner samples before
//! accepting an attempt and after its physical children and watchers join. A
//! sample grants neither permission to release credit nor a renewed deadline.

use std::fs::File;
use std::io::{self, Read, Seek};

/// Independent kernel CPU counters from the retained original ancestor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalCpuCounters {
    /// Aggregate user and kernel execution in microseconds.
    pub usage_microseconds: u64,
    /// User execution in microseconds.
    pub user_microseconds: u64,
    /// Kernel execution in microseconds.
    pub system_microseconds: u64,
}

impl OriginalCpuCounters {
    /// Computes independent deltas, refusing any backwards kernel counter.
    #[must_use]
    pub fn since(self, before: Self) -> Option<Self> {
        Some(Self {
            usage_microseconds: self
                .usage_microseconds
                .checked_sub(before.usage_microseconds)?,
            user_microseconds: self
                .user_microseconds
                .checked_sub(before.user_microseconds)?,
            system_microseconds: self
                .system_microseconds
                .checked_sub(before.system_microseconds)?,
        })
    }
}

/// Preserves a kernel or format failure independently of the enclosing end.
#[derive(Debug, thiserror::Error)]
pub enum OriginalCpuReadError {
    /// The pinned kernel file could not be rewound or read.
    #[error("original CPU counter IO: {0}")]
    Io(#[from] io::Error),
    /// The kernel file exceeded its bound or had invalid counters.
    #[error("invalid original CPU counter record")]
    InvalidCounter,
}

pub(super) fn read(source: &mut File) -> Result<OriginalCpuCounters, OriginalCpuReadError> {
    source.rewind()?;
    let mut scratch = [0; 4097];
    let mut length = 0;
    while length < scratch.len() {
        let count = source.read(&mut scratch[length..])?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if length > 4096 {
        return Err(OriginalCpuReadError::InvalidCounter);
    }
    let text = std::str::from_utf8(&scratch[..length])
        .map_err(|_| OriginalCpuReadError::InvalidCounter)?;
    parse(text).ok_or(OriginalCpuReadError::InvalidCounter)
}

fn parse(text: &str) -> Option<OriginalCpuCounters> {
    let mut values = [None; 3];
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let value = fields.next()?;
        if fields.next().is_some() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let value = value.parse::<u64>().ok()?;
        let index = match name {
            "usage_usec" => 0,
            "user_usec" => 1,
            "system_usec" => 2,
            _ => continue,
        };
        if values[index].replace(value).is_some() {
            return None;
        }
    }
    Some(OriginalCpuCounters {
        usage_microseconds: values[0]?,
        user_microseconds: values[1]?,
        system_microseconds: values[2]?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pinned_counter_rewinds_and_refuses_backwards_independent_values() {
        let mut source = tempfile::tempfile().unwrap();
        source
            .write_all(b"usage_usec 8\nuser_usec 3\nsystem_usec 5\nnr_periods 0\n")
            .unwrap();
        let first = read(&mut source).unwrap();
        assert_eq!(read(&mut source).unwrap(), first);
        let later = OriginalCpuCounters {
            usage_microseconds: 10,
            user_microseconds: 2,
            system_microseconds: 8,
        };
        assert!(later.since(first).is_none());
    }

    #[test]
    fn malformed_or_overlong_counter_has_no_partial_result() {
        for text in [
            "usage_usec 8\nuser_usec 3\n",
            "usage_usec 8\nuser_usec 3\nsystem_usec 5\nusage_usec 9\n",
            "usage_usec +8\nuser_usec 3\nsystem_usec 5\n",
            "usage_usec 8\nuser_usec 3\nsystem_usec 18446744073709551616\n",
            "usage_usec 8\nuser_usec 3\nsystem_usec 5 extra\n",
            "usage_usec 8\nuser_usec 3\nsystem_usec 5\nunknown bad\n",
        ] {
            assert!(parse(text).is_none());
        }
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(&[b'1'; 4097]).unwrap();
        assert!(matches!(
            read(&mut source),
            Err(OriginalCpuReadError::InvalidCounter)
        ));
    }
}
