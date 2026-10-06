//! Retained operational failures crossing a thread-safe error boundary.
//!
//! Native failures can own cleanup authority that is movable but cannot be
//! borrowed concurrently. Serializing diagnostic access retains the original
//! typed source and its linear custody instead of replacing it with a string.

use std::error::Error;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug)]
pub(crate) struct RetainedOperationError {
    source: Mutex<Box<dyn Error + Send>>,
}

impl RetainedOperationError {
    pub(crate) fn new(source: impl Error + Send + 'static) -> Self {
        Self {
            source: Mutex::new(Box::new(source)),
        }
    }
}

impl fmt::Display for RetainedOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source.lock() {
            Ok(source) => fmt::Display::fmt(&source, formatter),
            Err(_) => formatter.write_str("operational failure diagnostic custody is unavailable"),
        }
    }
}

impl Error for RetainedOperationError {}
