//! Writes structured operational RAM diagnostics without entering runtime locks.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::io::{self, Write};

use crate::ram_error::RamError;

/// A bounded diagnostic event with an explicit operational purpose.
pub(crate) enum RamDiagnostic<'a> {
    /// Startup rejected actual RAM metadata ownership.
    AdmissionRefused(&'a RamError),
    /// A retained native restore transaction failed.
    RestoreFailed(&'a RamError),
    /// A lifecycle ownership handoff failed.
    LifecycleFailed(&'a RamError),
    /// The expressly selected native test observer could not initialize.
    #[cfg(feature = "native-conformance")]
    ConformanceInstallFailed(&'a RamError),
    /// An ordinary coherent test root matched the independent C full oracle.
    #[cfg(any(test, feature = "native-conformance"))]
    OraclePassed { scope: u32 },
    /// The independent C full oracle disagreed with the coherent test root.
    #[cfg(any(test, feature = "native-conformance"))]
    OracleFailed { scope: u32 },
}

/// Emits one deterministic diagnostic without changing logical guest state.
pub(crate) fn emit(diagnostic: RamDiagnostic<'_>) {
    let _result = write_diagnostic(&mut io::stderr().lock(), diagnostic);
}

fn write_diagnostic(writer: &mut impl Write, diagnostic: RamDiagnostic<'_>) -> io::Result<()> {
    match diagnostic {
        RamDiagnostic::AdmissionRefused(error) => {
            writeln!(
                writer,
                "crucible-qemu-plugin: RAM admission refused: {error}"
            )
        }
        RamDiagnostic::RestoreFailed(error) => {
            writeln!(writer, "native RAM restore failed: {error}")
        }
        RamDiagnostic::LifecycleFailed(error) => writeln!(writer, "RAM lifecycle failed: {error}"),
        #[cfg(feature = "native-conformance")]
        RamDiagnostic::ConformanceInstallFailed(error) => {
            writeln!(
                writer,
                "crucible RAM conformance observer install failed: {error}"
            )
        }
        #[cfg(any(test, feature = "native-conformance"))]
        RamDiagnostic::OraclePassed { scope } => {
            writeln!(writer, "CRUCIBLE-RAM-ORACLE-PASS scope={scope}")
        }
        #[cfg(any(test, feature = "native-conformance"))]
        RamDiagnostic::OracleFailed { scope } => {
            writeln!(writer, "CRUCIBLE-RAM-ORACLE-FAIL scope={scope}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_events_remain_observable_without_runtime_state() {
        let mut output = Vec::new();
        write_diagnostic(&mut output, RamDiagnostic::OraclePassed { scope: 0 }).unwrap();
        write_diagnostic(&mut output, RamDiagnostic::OracleFailed { scope: 1 }).unwrap();
        assert_eq!(
            output,
            b"CRUCIBLE-RAM-ORACLE-PASS scope=0\nCRUCIBLE-RAM-ORACLE-FAIL scope=1\n"
        );
    }
}
