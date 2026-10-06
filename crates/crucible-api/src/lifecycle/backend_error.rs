//! Backend construction failures retaining their original cleanup authority.
//!
//! Cloning a lifecycle error shares the actual cause. RPC serialization may
//! render a diagnostic, while the in-process error keeps native failure and
//! launch-input custody until its final owner drops.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// A shared backend construction failure with its original typed cause.
#[derive(Clone, Debug)]
pub struct LifecycleBackendConstructionError {
    source: Arc<dyn Error + Send + Sync>,
}

impl LifecycleBackendConstructionError {
    pub(crate) fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Arc::new(source),
        }
    }
}

impl PartialEq for LifecycleBackendConstructionError {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.source, &other.source)
    }
}

impl Eq for LifecycleBackendConstructionError {}

impl fmt::Display for LifecycleBackendConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for LifecycleBackendConstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
