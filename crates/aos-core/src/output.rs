//! Terminal output handling for the `aos` CLI.
//!
//! All user-facing text flows through a [`Printer`], which maps the
//! `--verbose`, `--quiet`, and `--json` flags onto an [`OutputMode`] and
//! enforces two invariants consistently across every subcommand:
//!
//! - Human-readable text (info, warnings, steps, headers) goes to
//!   **stderr**, so stdout stays reserved for machine-readable data
//!   such as store paths and JSON.
//! - Quiet and JSON modes suppress decorative output; errors are always
//!   surfaced (as a JSON object in JSON mode).
//!
//! The module also provides [`create_spinner`] and
//! [`create_progress_bar`] helpers for long-running operations, built on
//! `indicatif`.

use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Determines how the CLI renders output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Default mode: styled human-readable messages on stderr.
    Normal,
    /// `--quiet`: suppress everything except errors.
    Quiet,
    /// `--json`: machine-readable JSON on stdout; no decorative text.
    Json,
    /// `--verbose`: like [`Normal`](Self::Normal) but callers may emit
    /// additional diagnostic detail.
    Verbose,
}

/// Central output handler that respects `--json`, `--quiet`, and `--verbose`
/// flags.  All user-facing text should flow through a `Printer` so that the
/// output mode is honoured consistently.
#[derive(Clone)]
pub struct Printer {
    mode: OutputMode,
    // Styles (only used in Normal / Verbose modes).
    style_info: Style,
    style_success: Style,
    style_warning: Style,
    style_error: Style,
    style_step: Style,
    style_bold: Style,
}

impl Printer {
    /// Creates a printer from the raw CLI flags.
    ///
    /// Mode precedence is `json > quiet > verbose > normal`: `--json`
    /// wins over `--quiet`, which wins over any `--verbose` count.
    pub fn new(verbose: u8, quiet: bool, json: bool) -> Self {
        let mode = if json {
            OutputMode::Json
        } else if quiet {
            OutputMode::Quiet
        } else if verbose > 0 {
            OutputMode::Verbose
        } else {
            OutputMode::Normal
        };

        Self {
            mode,
            style_info: Style::new().cyan(),
            style_success: Style::new().green().bold(),
            style_warning: Style::new().yellow(),
            style_error: Style::new().red().bold(),
            style_step: Style::new().cyan().bold(),
            style_bold: Style::new().bold(),
        }
    }

    /// Returns the active [`OutputMode`].
    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    // ------------------------------------------------------------------
    // Text helpers — all go to stderr so that stdout is reserved for
    // machine-readable data (store paths, JSON).
    // ------------------------------------------------------------------

    /// Prints an informational message (cyan) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn info(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_info.apply_to(msg)),
        }
    }

    /// Prints a success message (green, bold) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn success(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_success.apply_to(msg)),
        }
    }

    /// Prints a warning (yellow, prefixed with `warning:`) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn warning(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_warning.apply_to(format!("warning: {msg}"))),
        }
    }

    /// Prints an error message (red, bold, prefixed with `error:`).
    ///
    /// Always printed regardless of mode. In JSON mode the message is
    /// emitted to stdout as `{"error": "..."}` instead of styled text on
    /// stderr.
    pub fn error(&self, msg: &str) {
        if self.mode == OutputMode::Json {
            let obj = serde_json::json!({ "error": msg });
            println!("{}", serde_json::to_string(&obj).unwrap_or_default());
        } else {
            eprintln!("{}", self.style_error.apply_to(format!("error: {msg}")));
        }
    }

    /// Prints a step indicator such as `[1/4] Building package ...`
    /// (cyan + bold prefix) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn step(&self, current: usize, total: usize, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!(
                "{} {}",
                self.style_step.apply_to(format!("[{current}/{total}]")),
                msg,
            ),
        }
    }

    /// Prints a bold header line to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn header(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_bold.apply_to(msg)),
        }
    }

    /// Prints unstyled text to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn plain(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{msg}"),
        }
    }

    /// Prints an indented `key: value` pair with a bold key to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn kv(&self, key: &str, value: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("  {}: {}", self.style_bold.apply_to(key), value),
        }
    }

    /// Emits a JSON value to stdout.
    ///
    /// Usually called when `--json` is active, but works in any mode for
    /// callers that always want machine-readable output. Serialisation
    /// failures degrade to printing `{}` rather than erroring.
    pub fn json(&self, value: &serde_json::Value) {
        println!(
            "{}",
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
        );
    }

    /// Emits a JSON value to stdout only when JSON mode is active.
    ///
    /// Returns `true` if JSON was emitted, so callers can skip the
    /// human-readable rendering of the same data.
    pub fn json_if_active(&self, value: &serde_json::Value) -> bool {
        if self.mode == OutputMode::Json {
            self.json(value);
            true
        } else {
            false
        }
    }
}

// ------------------------------------------------------------------
// Progress helpers
// ------------------------------------------------------------------

/// Creates an indeterminate spinner for long-running operations.
///
/// The spinner ticks automatically every 120 ms; call
/// `finish_and_clear` (or another `ProgressBar` finisher) when the
/// operation completes.
pub fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("valid spinner template")
            .tick_chars("-\\|/ "),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// Creates a determinate progress bar for multi-item operations.
///
/// `len` is the total number of items; advance the bar with
/// `ProgressBar::inc` as items complete.
#[allow(dead_code)] // public API
pub fn create_progress_bar(len: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/dim}] {pos}/{len}")
            .expect("valid bar template")
            .progress_chars("=> "),
    );
    pb.set_message(msg.to_string());
    pb
}
