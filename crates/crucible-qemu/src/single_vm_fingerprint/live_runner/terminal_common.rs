//! Shared validation for pause-before-export terminal observations.

use std::fs;
use std::io;
use std::path::Path;

use crate::single_vm_fingerprint::{
    QemuTerminalHorizonTraceImport, QemuTraceFingerprintImportError, SingleVmFingerprintStream,
};

use super::{LivePreparedLaunch, LiveRunnerConfig, LiveRunnerQmpObservation};

/// Failure while inspecting a possibly incomplete terminal trace publication.
#[derive(Debug)]
pub(super) enum TerminalPublicationInspectionError {
    /// Reading a trace that already exists failed.
    Io(io::Error),
    /// Published bytes violated the strict terminal trace contract.
    Trace(QemuTraceFingerprintImportError),
}

/// Inspects one publication snapshot without treating absence as failure.
pub(super) fn inspect_terminal_publication(
    trace: &Path,
    importer: &QemuTerminalHorizonTraceImport,
) -> Result<Option<()>, TerminalPublicationInspectionError> {
    let bytes = match fs::read(trace) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(TerminalPublicationInspectionError::Io(source)),
    };
    importer
        .published_terminal_stream(&bytes)
        .map(|stream| stream.map(|_| ()))
        .map_err(TerminalPublicationInspectionError::Trace)
}

/// Returns the first retained process-identity boundary that drifted.
pub(super) fn prepared_invocation_drift(prepared: &LivePreparedLaunch) -> Option<&'static str> {
    if prepared.spec().executable().as_os_str() != prepared.argv_identity().argv0()
        || prepared.spec().argv() != prepared.argv_identity().argv()
        || prepared.invocation().argv_digest() != prepared.argv_identity().digest()
        || prepared.invocation().paths().cwd != prepared.artifacts().directory()
        || prepared.invocation().paths().qmp_socket != prepared.artifacts().qmp_socket()
        || prepared.invocation().paths().stdout != prepared.artifacts().stdout_log()
        || prepared.invocation().paths().stderr != prepared.artifacts().stderr_log()
        || !prepared.invocation().stdin_is_null()
        || !prepared.invocation().environment_is_cleared()
    {
        return Some("process invocation");
    }
    let process_argv = prepared.process_argv_contract();
    if process_argv.argc() != prepared.argv_identity().argc()
        || process_argv.raw_bytes() != prepared.argv_identity().raw_byte_count()
        || process_argv.digest() != prepared.argv_identity().digest()
    {
        return Some("process argv attestation");
    }
    None
}

/// Returns the first typed terminal QMP boundary that drifted.
pub(super) fn terminal_qmp_drift(
    config: &LiveRunnerConfig,
    observation: &LiveRunnerQmpObservation,
) -> Option<&'static str> {
    if observation.run_state.running
        || observation.run_state.status != crate::QmpRunStateKind::Paused
    {
        return Some("typed QMP non-running paused state");
    }
    if observation.cpu_indexes != expected_cpu_ids(config) {
        return Some("typed QMP vCPU topology");
    }
    None
}

/// Reports whether strict import yielded exactly one sample at `target`.
pub(super) fn is_one_sample_at(stream: &SingleVmFingerprintStream, target: u64) -> bool {
    stream.samples.len() == 1
        && stream.samples.first().map(|sample| sample.icount) == Some(target)
        && stream.final_icount == target
}

/// Returns the configured contiguous QMP CPU-index topology.
pub(super) fn expected_cpu_ids(config: &LiveRunnerConfig) -> Vec<u64> {
    (0..u64::from(config.vcpus())).collect()
}

/// Encodes bytes as lowercase hexadecimal text.
pub(super) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
