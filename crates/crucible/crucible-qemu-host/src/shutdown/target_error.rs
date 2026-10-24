//! Retains typed shutdown refusals without allocating OS diagnostics.
//!
//! Native errors keep their original OS error inline. Static diagnostics borrow
//! their text; authored dynamic errors retain the existing message path and
//! require separate admission. These observations grant no cleanup authority.

use std::borrow::Cow;
use std::io;

use crucible_host_resources::host_supervision::HostSupervisionError;

#[derive(Debug)]
struct NativeIoCause {
    code: i32,
    error: io::Error,
}

impl Clone for NativeIoCause {
    fn clone(&self) -> Self {
        // This variant contains only an OS error, whose complete representation
        // is its raw code. Reconstructing a clone allocates no custom payload.
        Self {
            code: self.code,
            error: io::Error::from_raw_os_error(self.code),
        }
    }
}

impl PartialEq for NativeIoCause {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for NativeIoCause {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TargetCause {
    Supervision(HostSupervisionError),
    NativeIo(NativeIoCause),
}

/// Retains an error returned by a shutdown target operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuShutdownTargetError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Authored detail, borrowed for static text and empty for typed refusals.
    pub message: Cow<'static, str>,
    cause: Option<TargetCause>,
}

impl std::fmt::Display for QemuShutdownTargetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            match &self.cause {
                Some(TargetCause::Supervision(source)) => {
                    return write!(formatter, "{} failed: {source}", self.operation);
                }
                Some(TargetCause::NativeIo(source)) => {
                    return write!(formatter, "{} failed: {}", self.operation, source.error);
                }
                None => {}
            }
        }
        write!(formatter, "{} failed: {}", self.operation, self.message)
    }
}

impl std::error::Error for QemuShutdownTargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(TargetCause::Supervision(source)) => Some(source),
            Some(TargetCause::NativeIo(source)) => Some(&source.error),
            None => None,
        }
    }
}

impl QemuShutdownTargetError {
    /// Creates a target error without copying its diagnostic.
    ///
    /// Static text is borrowed; owned messages retain their existing allocation.
    /// Dynamic diagnostic construction still requires its own admission.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation,
            message: message.into(),
            cause: None,
        }
    }

    /// Retains a native OS error without formatting or allocating its diagnostic.
    ///
    /// The original OS error remains available through the standard error chain.
    /// Cloning preserves its raw code without allocating. Errors without a raw
    /// OS code use the existing authored-message path, whose allocation requires
    /// separate admission.
    #[must_use]
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        match source.raw_os_error() {
            Some(code) => Self {
                operation,
                message: Cow::Borrowed(""),
                cause: Some(TargetCause::NativeIo(NativeIoCause {
                    code,
                    error: source,
                })),
            },
            None => Self::new(operation, source.to_string()),
        }
    }

    /// Retains a typed Cleanup refusal without formatting a diagnostic.
    ///
    /// This preserves the actual cause; it grants no further operation or
    /// physical-return authority.
    #[must_use]
    pub fn operational_supervision(operation: &'static str, source: HostSupervisionError) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            cause: Some(TargetCause::Supervision(source)),
        }
    }

    /// Returns the original typed operational refusal, when present.
    #[must_use]
    pub const fn operational_supervision_source(&self) -> Option<HostSupervisionError> {
        match &self.cause {
            Some(TargetCause::Supervision(source)) => Some(*source),
            _ => None,
        }
    }

    /// Borrows the original native OS error, when present.
    #[must_use]
    pub fn io_source(&self) -> Option<&io::Error> {
        match &self.cause {
            Some(TargetCause::NativeIo(source)) => Some(&source.error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
