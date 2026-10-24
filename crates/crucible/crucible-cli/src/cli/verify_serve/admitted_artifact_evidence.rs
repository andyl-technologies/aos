//! Counted borrowed renderers for authenticated artifact verification evidence.
//!
//! The renderers preserve the canonical field order and escaping while admitting
//! one exact output buffer before rendering. They allocate no private scratch.
//!
//! ```text
//! {"seq":0,"virtual_time":0,"node":"guest","kind":"marker","summary":"ready"}
//! ```

use super::*;

struct CanonicalEntries<'a>(&'a [CanonicalLogEntry]);

impl fmt::Display for CanonicalEntries<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in self.0 {
            writeln!(
                output,
                "{{\"seq\":{},\"virtual_time\":{},\"node\":\"{}\",\"kind\":\"{}\",\"summary\":\"{}\"}}",
                entry.sequence,
                entry.virtual_time_ticks,
                EscapedJson(&entry.node),
                EscapedJson(&entry.kind),
                EscapedJson(&entry.summary),
            )?;
        }
        Ok(())
    }
}

struct EscapedJson<'a>(&'a str);

impl fmt::Display for EscapedJson<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '"' => output.write_str("\\\"")?,
                '\\' => output.write_str("\\\\")?,
                '\n' => output.write_str("\\n")?,
                '\r' => output.write_str("\\r")?,
                '\t' => output.write_str("\\t")?,
                character if character.is_control() => {
                    write!(output, "\\u{:04x}", character as u32)?;
                }
                character => write!(output, "{character}")?,
            }
        }
        Ok(())
    }
}

struct Fingerprints<'a>(&'a [VerifyFingerprintSample]);

impl fmt::Display for Fingerprints<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("crucible.verify.execution-fingerprint-stream.v1\n")?;
        for sample in self.0 {
            write!(output, "sample\t{}\t{}\t", sample.index, sample.instruction)?;
            write_escaped_artifact_field(output, &sample.node)?;
            output.write_str("\t")?;
            write_escaped_artifact_field(output, &sample.digest)?;
            output.write_str("\n")?;
        }
        Ok(())
    }
}

pub(super) fn admitted_canonical_entries(
    entries: &[CanonicalLogEntry],
) -> Result<Vec<u8>, CliError> {
    crucible_session::engine::owned_decode::display_string(&CanonicalEntries(entries))
        .map(String::into_bytes)
        .map_err(CliError::MetadataAdmission)
}

pub(super) fn admitted_fingerprint_stream(
    samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    crucible_session::engine::owned_decode::display_string(&Fingerprints(samples))
        .map(String::into_bytes)
        .map_err(CliError::MetadataAdmission)
}
