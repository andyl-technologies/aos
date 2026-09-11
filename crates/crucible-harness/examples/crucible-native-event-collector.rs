//! Bounded, read-only inspection of a native Crucible run-state tree.

#![forbid(unsafe_code)]

mod native_event_collector;

use std::process::ExitCode;

fn main() -> ExitCode {
    match native_event_collector::Args::parse(std::env::args_os().skip(1))
        .and_then(native_event_collector::collect)
    {
        Ok(report) => match serde_json::to_writer_pretty(std::io::stdout(), &report) {
            Ok(()) => {
                println!();
                ExitCode::SUCCESS
            }
            Err(error) => {
                emit_error(format!("encode diagnostic report: {error}"));
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            emit_error(error);
            ExitCode::FAILURE
        }
    }
}

fn emit_error(message: String) {
    let report = native_event_collector::FailureReport {
        format: native_event_collector::REPORT_FORMAT,
        status: "error",
        error: message,
    };
    if serde_json::to_writer_pretty(std::io::stdout(), &report).is_ok() {
        println!();
    }
}
