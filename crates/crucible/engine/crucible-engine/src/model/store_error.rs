//! Temporal-graph store error formatting and sources.

use super::*;

impl fmt::Display for TemporalGraphStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine { operation, .. } => {
                write!(f, "temporal graph operation {operation} failed")
            }
            Self::Store { operation, .. } => {
                write!(f, "temporal graph store operation {operation} failed")
            }
        }
    }
}

impl Error for TemporalGraphStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine { source, .. } => Some(source.as_ref()),
            Self::Store { source, .. } => Some(source),
        }
    }
}
