//! Compatibility module for package-manager configuration trust consumers.
//!
//! The selected metadata provider owns host-input authentication. The generic
//! package manager reuses that one implementation for manual configuration
//! evaluation rather than carrying a second trust path.

pub use aos_metadata::trust::*;
