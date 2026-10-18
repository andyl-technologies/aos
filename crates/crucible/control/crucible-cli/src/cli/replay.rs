//! Replay execution, schedule-prefix proof, and bisection.

use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TraceRenderReport {
    pub(super) format: OutputFormat,
    pub(super) path: Option<PathBuf>,
    pub(super) bytes: Vec<u8>,
    pub(super) entry_count: usize,
    pub(super) streamed_entries: usize,
    pub(super) canonical_digest: String,
}

pub(super) fn emit_canonical_trace(
    format: OutputFormat,
    entries: &[CanonicalLogEntry],
    trace_path: Option<&Path>,
    stdout: bool,
) -> Result<TraceRenderReport, CliError> {
    if format == OutputFormat::Markdown {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }

    let mut bytes = Vec::new();
    let mut streamed_entries = 0usize;
    match format {
        OutputFormat::Jsonl => {
            let mut trace_file = trace_path.map(fs::File::create).transpose()?;
            for entry in entries {
                let line = json_for_canonical_log_entry(entry);
                if stdout {
                    println!("{line}");
                }
                if let Some(file) = trace_file.as_mut() {
                    writeln!(file, "{line}")?;
                }
                writeln!(&mut bytes, "{line}")?;
                streamed_entries += 1;
            }
        }
        OutputFormat::Json | OutputFormat::Table => {
            let rendered = render_canonical_event_log(format, entries)?;
            if stdout {
                println!("{}", String::from_utf8_lossy(&rendered.bytes));
            }
            if let Some(path) = trace_path {
                fs::write(path, &rendered.bytes)?;
            }
            bytes = rendered.bytes;
        }
        OutputFormat::Markdown => {
            return Err(usage_error(
                "--format markdown is reserved for triage reports, not canonical event-log traces",
            ));
        }
    }

    Ok(TraceRenderReport {
        format,
        path: trace_path.map(Path::to_path_buf),
        bytes,
        entry_count: entries.len(),
        streamed_entries,
        canonical_digest: canonical_log_digest(entries),
    })
}

#[path = "replay/embedded.rs"]
mod embedded;
#[path = "replay/live.rs"]
mod live;
#[path = "replay/proof.rs"]
mod proof;

pub(crate) use live::replay_reproduction_artifact;
pub(crate) use proof::{
    replay_bisect_error, replay_check_mismatch_error, replay_to_savepoint_status_line,
};

#[path = "replay/artifact.rs"]
mod artifact;

pub(super) use artifact::*;
