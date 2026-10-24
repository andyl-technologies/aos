//! Drives native plugin assertions through a retained Main-worker Source.
//!
//! The driver shares the ordinary keyed launch and exact cleanup path. Its
//! borrowed operation view cannot issue a Main, move a backend guard or release
//! the containing Source. Component entry remains an explicit refusal until an
//! authenticated service supplies that real factory.

pub(super) mod admission;
pub(super) mod driver;
mod diagnostics;
pub use diagnostics::{
    NativeBlockRecoveryObservation, NativeFlightDiagnosticMode, NativeFlightOutputChannel,
    NativeFlightTimerObservation, NativeFourVcpuDiagnostic, NativePartitionVariant,
    NativePluginFlightDiagnostic, NativePluginFlightOutput, NativeRuntimeTraceSummary,
    NativeRuntimeTraceVariant,
};

#[cfg(feature = "private-measurement-domain")]
mod inputs;
#[cfg(feature = "private-measurement-domain")]
pub use inputs::{NativePluginFlightInputError, NativePluginFlightInputs, NativePluginFlightKind};
#[cfg(feature = "private-measurement-domain")]
pub(super) mod runner;
