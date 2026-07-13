//! Strict import of terminal pause-before-export QEMU traces.
//!
//! The terminal protocol admits diagnostic `rr_switch` and `det_ipi` records,
//! followed by exactly one `terminal_horizon` state record and one
//! `terminal_final` metadata record. The importer validates that protocol and
//! translates the raw terminal RAM and VMState exports into the canonical
//! one-sample fingerprint stream.

use std::collections::BTreeSet;
use std::io::Read;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceFingerprintImport, QemuTraceFingerprintImportError,
    QemuTraceObservationContract, QemuTraceProcessArgvContract, SingleVmFingerprintStream,
};

const TERMINAL_STATE_SCHEMA: &str = "crucible.qemu.terminal-horizon.v1";

const STATE_FIELDS: &[&str] = &[
    "kind",
    "schema",
    "terminal_state_schema",
    "final",
    "retired",
    "vcpu",
    "tracked_vcpus",
    "stop_at",
    "stop_requested",
    "trigger",
    "event_boundary",
    "observed_icount",
    "observed_non_running",
    "terminal_pause_status",
    "terminal_capture_status",
    "terminal_state_complete",
    "terminal_vmstate_export",
    "rr_current_vcpu",
    "rr_cursor_position",
    "rr_switch_quantum",
    "rr_cursor_valid",
    "rr_cursor_source",
    "launch_definition_digest",
    "qemu_build_digest",
    "trace_plugin_build_digest",
    "process_argv_attestation_version",
    "process_argv_encoding",
    "process_argv_argc",
    "process_argv_raw_bytes",
    "process_argv_digest",
    "process_argv_status",
    "stream_hash",
    "register_digests",
    "register_counts",
    "register_file_bytes",
    "register_schema_digests",
    "register_retired",
    "raw_ram_digest",
    "raw_ram_region_map_digest",
    "raw_ram_regions",
    "raw_ram_bytes",
    "raw_ram_status",
    "vmstate_digest",
    "vmstate_bytes",
    "vmstate_status",
    "memory_event_hash",
    "device_event_hash",
    "memory_events",
    "io_events",
    "memory_events_enabled",
    "sample_register_failures",
    "register_read_failures",
    "trajectory_digest_failures",
];

const FINAL_FIELDS: &[&str] = &[
    "kind",
    "schema",
    "terminal_state_schema",
    "final",
    "retired",
    "stop_at",
    "stop_requested",
    "observed_icount",
    "terminal_pause_requested",
    "terminal_pause_status",
    "terminal_callback_completed",
    "terminal_state_emitted",
    "terminal_state_complete",
    "launch_definition_digest",
    "qemu_build_digest",
    "trace_plugin_build_digest",
    "process_argv_attestation_version",
    "process_argv_encoding",
    "process_argv_argc",
    "process_argv_raw_bytes",
    "process_argv_digest",
    "process_argv_status",
];

/// Strict contract for one pause-before-export terminal horizon trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTerminalHorizonTraceImport {
    node: String,
    definition_digest: [u8; 32],
    horizon_icount: u64,
    observation: QemuTraceObservationContract,
    expected_process_argv: QemuTraceProcessArgvContract,
}

impl QemuTerminalHorizonTraceImport {
    /// Builds a terminal trace import contract from independent preflight evidence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when the
    /// node is empty, the horizon is zero, or the underlying canonical import
    /// contract rejects the supplied definition or observation shape.
    pub fn new(
        node: impl Into<String>,
        definition_digest: [u8; 32],
        horizon_icount: u64,
        observation: QemuTraceObservationContract,
        expected_process_argv: QemuTraceProcessArgvContract,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        let node = node.into();
        QemuTraceFingerprintImport::new(
            node.clone(),
            definition_digest,
            horizon_icount,
            horizon_icount,
            observation.clone(),
            expected_process_argv,
        )?;
        Ok(Self {
            node,
            definition_digest,
            horizon_icount,
            observation,
            expected_process_argv,
        })
    }

    /// Imports exactly one terminal state followed by its final metadata record.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError`] for partial input, duplicate
    /// keys, unknown fields or records, invalid terminal status/evidence,
    /// provenance drift, incomplete raw state, or a noncanonical sample.
    pub fn import<R: Read>(
        &self,
        mut reader: R,
    ) -> Result<SingleVmFingerprintStream, QemuTraceFingerprintImportError> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| QemuTraceFingerprintImportError::Io { line: 0, source })?;
        if bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "terminal trace ends in a partial JSON-lines record",
            });
        }
        self.published_terminal_stream(&bytes)?.ok_or(
            QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "terminal trace requires exactly one state and one final record",
            },
        )
    }

    /// Imports the terminal stream if a complete published trace is present.
    ///
    /// Unlike [`Self::import`], this tolerates a partially written trailing
    /// JSON-lines record: the incomplete tail is ignored so a live publication
    /// can be polled until the terminal state and final metadata records both
    /// appear. It returns `Ok(None)` while either record is still absent, and
    /// `Ok(Some(stream))` once the complete, canonical terminal state has been
    /// imported.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError`] when a fully published record
    /// is malformed or duplicated, carries invalid terminal status or evidence,
    /// drifts from the expected provenance, or exports incomplete raw state.
    pub(crate) fn published_terminal_stream(
        &self,
        bytes: &[u8],
    ) -> Result<Option<SingleVmFingerprintStream>, QemuTraceFingerprintImportError> {
        let records = parse_published_records(bytes)?;
        let terminal = terminal_records(&records, false)?;
        let (state, final_record) = match (terminal.state, terminal.final_record) {
            (Some(state), Some(final_record)) => (state, final_record),
            _ => return Ok(None),
        };
        self.validate_state(state, record_line(&records, state))?;
        self.validate_final(final_record, state, record_line(&records, final_record))?;
        self.import_canonical_state(state).map(Some)
    }

    fn validate_state(
        &self,
        value: &Map<String, Value>,
        line: usize,
    ) -> Result<(), QemuTraceFingerprintImportError> {
        require_exact_fields(value, STATE_FIELDS, line)?;
        require_str(value, "kind", "terminal_horizon", line)?;
        require_str(value, "schema", QEMU_TRACE_FINGERPRINT_SCHEMA, line)?;
        require_str(value, "terminal_state_schema", TERMINAL_STATE_SCHEMA, line)?;
        require_bool(value, "final", false, line)?;
        require_u64(value, "stop_at", self.horizon_icount, line)?;
        require_u64(value, "observed_icount", self.horizon_icount, line)?;
        require_bool(value, "stop_requested", true, line)?;
        require_str(value, "trigger", "event", line)?;
        require_str(value, "event_boundary", "horizon-advance", line)?;
        require_bool(value, "observed_non_running", true, line)?;
        require_zero(value, "terminal_pause_status", line)?;
        require_zero(value, "terminal_capture_status", line)?;
        require_bool(value, "terminal_state_complete", true, line)?;
        require_bool(value, "terminal_vmstate_export", true, line)?;
        require_bool(value, "rr_cursor_valid", true, line)?;
        match string_field(value, "rr_cursor_source", line)? {
            "terminal_paused_boundary" | "terminal_last_executed_instruction" => {}
            source => {
                return Err(malformed(
                    line,
                    format!("unsupported terminal RR cursor source `{source}`"),
                ));
            }
        }
        require_zero(value, "process_argv_status", line)?;
        require_zero(value, "raw_ram_status", line)?;
        require_zero(value, "vmstate_status", line)?;
        require_bool(value, "memory_events_enabled", true, line)?;
        require_zero(value, "sample_register_failures", line)?;
        require_zero(value, "register_read_failures", line)?;
        require_zero(value, "trajectory_digest_failures", line)?;
        require_sha256(value, "raw_ram_digest", line)?;
        require_sha256(value, "raw_ram_region_map_digest", line)?;
        require_sha256(value, "vmstate_digest", line)?;
        if u64_field(value, "raw_ram_regions", line)? == 0 {
            return Err(malformed(line, "raw RAM region count must be non-zero"));
        }
        // `raw_ram_bytes` is the effective RAM mapped into the guest address
        // space at the terminal boundary: patch 0036 walks the FlatView of
        // `address_space_memory` and, by design, excludes readonly/ROM sections.
        // `guest_ram_bytes` is a different quantity — the full RAMBlock backing
        // store measured at genesis (patch 0002 sums `block->used_length`). On
        // pc-q35 the two differ by the 256 KiB legacy-BIOS PAM shadow window
        // (0xC0000-0xFFFFF), which is ROM-shadowed once firmware has run and is
        // therefore not RAM-mapped at the terminal boundary (observed:
        // 133955584 vs a 134217728 RAMBlock). The exact mapped total is pinned
        // deterministically by `raw_ram_region_map_digest` and the two-run
        // fingerprint comparison; the only structural invariant here is that the
        // terminal maps a positive amount of RAM not exceeding the backing
        // RAMBlock. (The original `== guest_ram_bytes` equality assumed the two
        // walks agree; that assumption was never exercised by a live run and is
        // false for pc-q35.)
        let raw_ram_bytes = u64_field(value, "raw_ram_bytes", line)?;
        if raw_ram_bytes == 0 || raw_ram_bytes > self.observation.guest_ram_bytes() {
            return Err(malformed(
                line,
                format!(
                    "terminal mapped raw_ram_bytes {raw_ram_bytes} must be in 1..={} \
                     (the genesis RAMBlock total)",
                    self.observation.guest_ram_bytes()
                ),
            ));
        }
        if u64_field(value, "vmstate_bytes", line)? == 0 {
            return Err(malformed(
                line,
                "terminal VMState byte count must be non-zero",
            ));
        }
        require_hex_u64(value, "stream_hash", line)?;
        require_hex_u64(value, "memory_event_hash", line)?;
        require_hex_u64(value, "device_event_hash", line)?;
        self.require_provenance(value, line)
    }

    fn validate_final(
        &self,
        value: &Map<String, Value>,
        state: &Map<String, Value>,
        line: usize,
    ) -> Result<(), QemuTraceFingerprintImportError> {
        require_exact_fields(value, FINAL_FIELDS, line)?;
        require_str(value, "kind", "terminal_final", line)?;
        require_str(value, "schema", QEMU_TRACE_FINGERPRINT_SCHEMA, line)?;
        require_str(value, "terminal_state_schema", TERMINAL_STATE_SCHEMA, line)?;
        require_bool(value, "final", true, line)?;
        require_u64(value, "stop_at", self.horizon_icount, line)?;
        require_u64(value, "observed_icount", self.horizon_icount, line)?;
        require_bool(value, "stop_requested", true, line)?;
        require_bool(value, "terminal_pause_requested", true, line)?;
        require_zero(value, "terminal_pause_status", line)?;
        require_bool(value, "terminal_callback_completed", true, line)?;
        require_bool(value, "terminal_state_emitted", true, line)?;
        require_bool(value, "terminal_state_complete", true, line)?;
        require_zero(value, "process_argv_status", line)?;
        if u64_field(value, "retired", line)? != u64_field(state, "retired", line)? {
            return Err(malformed(
                line,
                "terminal final retired count differs from terminal state",
            ));
        }
        self.require_provenance(value, line)
    }

    fn require_provenance(
        &self,
        value: &Map<String, Value>,
        line: usize,
    ) -> Result<(), QemuTraceFingerprintImportError> {
        let identity = self.observation.identity();
        require_str(
            value,
            "launch_definition_digest",
            identity.launch_definition_digest(),
            line,
        )?;
        require_str(
            value,
            "qemu_build_digest",
            identity.qemu_build_digest(),
            line,
        )?;
        require_str(
            value,
            "trace_plugin_build_digest",
            identity.trace_plugin_build_digest(),
            line,
        )?;
        require_u64(value, "process_argv_attestation_version", 2, line)?;
        require_str(value, "process_argv_encoding", "raw-unix-argv-v2", line)?;
        require_u64(
            value,
            "process_argv_argc",
            self.expected_process_argv.argc(),
            line,
        )?;
        require_u64(
            value,
            "process_argv_raw_bytes",
            self.expected_process_argv.raw_bytes(),
            line,
        )?;
        require_str(
            value,
            "process_argv_digest",
            &lower_hex(&self.expected_process_argv.digest()),
            line,
        )
    }

    fn import_canonical_state(
        &self,
        state: &Map<String, Value>,
    ) -> Result<SingleVmFingerprintStream, QemuTraceFingerprintImportError> {
        let sample = canonical_sample(state, &self.observation)?;
        let final_record = canonical_final(state);
        let encoded = format!(
            "{}\n{}\n",
            Value::Object(sample),
            Value::Object(final_record)
        );
        QemuTraceFingerprintImport::new(
            self.node.clone(),
            self.definition_digest,
            self.horizon_icount,
            self.horizon_icount,
            self.observation.clone(),
            self.expected_process_argv,
        )?
        .import(encoded.as_bytes())
    }
}

fn canonical_sample(
    state: &Map<String, Value>,
    observation: &QemuTraceObservationContract,
) -> Result<Map<String, Value>, QemuTraceFingerprintImportError> {
    let mut sample = state.clone();
    let folded_ram_digest = fold_raw_ram_identity(state)?;
    for field in [
        "kind",
        "terminal_state_schema",
        "observed_non_running",
        "terminal_pause_status",
        "terminal_capture_status",
        "terminal_state_complete",
        "terminal_vmstate_export",
        "raw_ram_region_map_digest",
        "raw_ram_regions",
        "memory_event_hash",
        "device_event_hash",
        "trajectory_digest_failures",
    ] {
        sample.remove(field);
    }
    rename(&mut sample, "raw_ram_digest", "ram_digest");
    rename(&mut sample, "raw_ram_bytes", "ram_bytes");
    rename(&mut sample, "raw_ram_status", "ram_status");
    rename(&mut sample, "vmstate_digest", "device_state_digest");
    rename(&mut sample, "vmstate_bytes", "device_state_bytes");
    rename(&mut sample, "vmstate_status", "device_state_status");
    sample.insert(
        "device_state_sections".to_owned(),
        Value::from(observation.device_state_sections()),
    );
    sample.insert(
        "device_state_schema_digest".to_owned(),
        Value::from(lower_hex(&observation.device_state_schema_digest())),
    );
    sample.insert("device_state_schema_status".to_owned(), Value::from(0));
    sample.insert("device_state_complete".to_owned(), Value::Bool(true));
    sample.insert("device_state_failures".to_owned(), Value::from(0));
    sample.insert("ram_digest".to_owned(), Value::from(folded_ram_digest));
    sample.insert(
        "rr_cursor_source".to_owned(),
        Value::from("live_instruction"),
    );
    Ok(sample)
}

fn fold_raw_ram_identity(
    state: &Map<String, Value>,
) -> Result<String, QemuTraceFingerprintImportError> {
    let line = 1;
    let raw_digest = decode_sha256(string_field(state, "raw_ram_digest", line)?, line)?;
    let map_digest = decode_sha256(
        string_field(state, "raw_ram_region_map_digest", line)?,
        line,
    )?;
    let mut hasher = Sha256::new();
    let domain = b"crucible.qemu.terminal-raw-ram-identity.v1";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(raw_digest);
    hasher.update(map_digest);
    hasher.update(u64_field(state, "raw_ram_regions", line)?.to_be_bytes());
    hasher.update(u64_field(state, "raw_ram_bytes", line)?.to_be_bytes());
    Ok(lower_hex(&hasher.finalize()))
}

fn decode_sha256(encoded: &str, line: usize) -> Result<[u8; 32], QemuTraceFingerprintImportError> {
    if encoded.len() != 64 {
        return Err(malformed(line, "SHA-256 digest must contain 64 hex digits"));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| malformed(line, "invalid SHA-256 hex"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| malformed(line, "invalid SHA-256 hex"))?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn canonical_final(state: &Map<String, Value>) -> Map<String, Value> {
    let mut final_record = Map::new();
    for field in [
        "schema",
        "launch_definition_digest",
        "qemu_build_digest",
        "trace_plugin_build_digest",
        "process_argv_attestation_version",
        "process_argv_encoding",
        "process_argv_argc",
        "process_argv_raw_bytes",
        "process_argv_digest",
        "process_argv_status",
        "retired",
        "observed_icount",
        "vcpu",
        "tracked_vcpus",
        "stop_at",
        "stop_requested",
        "rr_current_vcpu",
        "rr_cursor_position",
        "rr_switch_quantum",
        "rr_cursor_valid",
    ] {
        if let Some(value) = state.get(field) {
            final_record.insert(field.to_owned(), value.clone());
        }
    }
    final_record.insert("final".to_owned(), Value::Bool(true));
    final_record.insert(
        "rr_cursor_source".to_owned(),
        Value::from("last_executed_instruction"),
    );
    final_record
}

fn rename(value: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(field) = value.remove(from) {
        value.insert(to.to_owned(), field);
    }
}

struct TerminalRecords<'a> {
    state: Option<&'a Map<String, Value>>,
    final_record: Option<&'a Map<String, Value>>,
}

fn terminal_records(
    records: &[Map<String, Value>],
    require_final: bool,
) -> Result<TerminalRecords<'_>, QemuTraceFingerprintImportError> {
    let mut state = None;
    let mut final_record = None;
    for (index, record) in records.iter().enumerate() {
        let line = index + 1;
        match string_field(record, "kind", line)? {
            "rr_switch" | "det_ipi" if state.is_none() => {}
            "terminal_horizon" if state.is_none() && final_record.is_none() => {
                state = Some(record);
            }
            "terminal_final" if state.is_some() && final_record.is_none() => {
                final_record = Some(record);
            }
            kind => {
                return Err(malformed(
                    line,
                    format!("unexpected or duplicate terminal trace record `{kind}`"),
                ));
            }
        }
    }
    if require_final && (state.is_none() || final_record.is_none()) {
        return Err(QemuTraceFingerprintImportError::IncompleteTrace {
            reason: "terminal trace requires exactly one state and one final record",
        });
    }
    Ok(TerminalRecords {
        state,
        final_record,
    })
}

fn parse_published_records(
    bytes: &[u8],
) -> Result<Vec<Map<String, Value>>, QemuTraceFingerprintImportError> {
    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    parse_lines(&bytes[..complete_len])
}

fn parse_lines(bytes: &[u8]) -> Result<Vec<Map<String, Value>>, QemuTraceFingerprintImportError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| malformed(1, "terminal trace is not valid UTF-8 JSON-lines"))?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            if line.is_empty() {
                return Err(malformed(index + 1, "blank terminal JSON-lines record"));
            }
            reject_duplicate_top_level_fields(line)
                .map_err(|reason| malformed(index + 1, reason))?;
            serde_json::from_str::<Value>(line)
                .map_err(|source| QemuTraceFingerprintImportError::Json {
                    line: index + 1,
                    source,
                })
                .and_then(|value| {
                    value
                        .as_object()
                        .cloned()
                        .ok_or_else(|| malformed(index + 1, "terminal record must be an object"))
                })
        })
        .collect()
}

fn record_line(records: &[Map<String, Value>], target: &Map<String, Value>) -> usize {
    records
        .iter()
        .position(|record| std::ptr::eq(record, target))
        .map_or(1, |index| index + 1)
}

fn require_exact_fields(
    value: &Map<String, Value>,
    expected: &[&str],
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let unexpected = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(malformed(
            line,
            format!(
                "terminal record fields differ; missing={missing:?}, unexpected={unexpected:?}"
            ),
        ));
    }
    Ok(())
}

fn require_str(
    value: &Map<String, Value>,
    field: &'static str,
    expected: &str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = string_field(value, field, line)?;
    if actual != expected {
        return Err(malformed(
            line,
            format!("{field} must be `{expected}`, got `{actual}`"),
        ));
    }
    Ok(())
}

fn string_field<'a>(
    value: &'a Map<String, Value>,
    field: &'static str,
    line: usize,
) -> Result<&'a str, QemuTraceFingerprintImportError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(line, format!("{field} must be a string")))
}

fn require_bool(
    value: &Map<String, Value>,
    field: &'static str,
    expected: bool,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed(line, format!("{field} must be a boolean")))?;
    if actual != expected {
        return Err(malformed(
            line,
            format!("{field} must be {expected}, got {actual}"),
        ));
    }
    Ok(())
}

fn require_u64(
    value: &Map<String, Value>,
    field: &'static str,
    expected: u64,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = u64_field(value, field, line)?;
    if actual != expected {
        return Err(malformed(
            line,
            format!("{field} must be {expected}, got {actual}"),
        ));
    }
    Ok(())
}

fn require_zero(
    value: &Map<String, Value>,
    field: &'static str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    require_u64(value, field, 0, line)
}

fn u64_field(
    value: &Map<String, Value>,
    field: &'static str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(line, format!("{field} must be a non-negative integer")))
}

fn require_sha256(
    value: &Map<String, Value>,
    field: &'static str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let digest = string_field(value, field, line)?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest.bytes().all(|byte| byte == b'0')
    {
        return Err(malformed(
            line,
            format!("{field} must be a non-zero SHA-256 hex digest"),
        ));
    }
    Ok(())
}

fn require_hex_u64(
    value: &Map<String, Value>,
    field: &'static str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let encoded = string_field(value, field, line)?;
    if encoded.len() != 16
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed(
            line,
            format!("{field} must be 16 lowercase hexadecimal digits"),
        ));
    }
    Ok(())
}

fn malformed(line: usize, reason: impl Into<String>) -> QemuTraceFingerprintImportError {
    QemuTraceFingerprintImportError::MalformedTrace {
        line,
        reason: reason.into(),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn reject_duplicate_top_level_fields(line: &str) -> Result<(), String> {
    let bytes = line.as_bytes();
    let mut index = skip_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return Err("terminal record must be a JSON object".to_owned());
    }
    index += 1;
    let mut seen = BTreeSet::new();
    loop {
        index = skip_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            return Ok(());
        }
        if bytes.get(index) != Some(&b'"') {
            return Err("terminal object key must be a JSON string".to_owned());
        }
        let end = scan_string(bytes, index)?;
        let key = serde_json::from_str::<String>(&line[index..end])
            .map_err(|source| format!("invalid terminal object key: {source}"))?;
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate JSON field `{key}`"));
        }
        index = skip_whitespace(bytes, end);
        if bytes.get(index) != Some(&b':') {
            return Err("terminal object key is not followed by a colon".to_owned());
        }
        index = skip_json_value(bytes, skip_whitespace(bytes, index + 1))?;
        index = skip_whitespace(bytes, index);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => return Ok(()),
            _ => return Err("terminal object value is not followed by comma or close".to_owned()),
        }
    }
}

fn skip_json_value(bytes: &[u8], index: usize) -> Result<usize, String> {
    match bytes.get(index) {
        Some(b'"') => scan_string(bytes, index),
        Some(b'{') | Some(b'[') => scan_composite(bytes, index),
        Some(_) => {
            let mut end = index;
            while let Some(byte) = bytes.get(end) {
                if matches!(byte, b',' | b'}' | b']') || byte.is_ascii_whitespace() {
                    break;
                }
                end += 1;
            }
            if end == index {
                Err("terminal object contains an empty JSON value".to_owned())
            } else {
                Ok(end)
            }
        }
        None => Err("terminal object ends before its JSON value".to_owned()),
    }
}

fn scan_composite(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut stack = vec![bytes[start]];
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'"' => index = scan_string(bytes, index)?,
            b'{' | b'[' => {
                stack.push(*byte);
                index += 1;
            }
            b'}' | b']' => {
                let expected = if *byte == b'}' { b'{' } else { b'[' };
                if stack.pop() != Some(expected) {
                    return Err("terminal JSON has mismatched delimiters".to_owned());
                }
                index += 1;
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => index += 1,
        }
    }
    Err("terminal JSON has an unterminated composite value".to_owned())
}

fn scan_string(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.saturating_add(2),
            b'"' => return Ok(index + 1),
            _ => index += 1,
        }
    }
    Err("terminal JSON has an unterminated string".to_owned())
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}
