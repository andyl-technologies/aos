use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Determines how the CLI renders output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Normal,
    Quiet,
    Json,
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

    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    // ------------------------------------------------------------------
    // Text helpers — all go to stderr so that stdout is reserved for
    // machine-readable data (store paths, JSON).
    // ------------------------------------------------------------------

    /// Informational message (cyan).
    pub fn info(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_info.apply_to(msg)),
        }
    }

    /// Success message (green, bold).
    pub fn success(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_success.apply_to(msg)),
        }
    }

    /// Warning message (yellow).
    pub fn warning(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_warning.apply_to(format!("warning: {msg}"))),
        }
    }

    /// Error message (red, bold).  Always printed regardless of mode (except
    /// JSON, where it is emitted as a JSON object).
    pub fn error(&self, msg: &str) {
        if self.mode == OutputMode::Json {
            let obj = serde_json::json!({ "error": msg });
            println!("{}", serde_json::to_string(&obj).unwrap_or_default());
        } else {
            eprintln!("{}", self.style_error.apply_to(format!("error: {msg}")));
        }
    }

    /// Step indicator (e.g. "[1/4] Building package ..."), cyan + bold.
    pub fn step(&self, current: usize, total: usize, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!(
                "{} {}",
                self.style_step
                    .apply_to(format!("[{current}/{total}]")),
                msg,
            ),
        }
    }

    /// Print a bold header line.
    pub fn header(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{}", self.style_bold.apply_to(msg)),
        }
    }

    /// Print plain text to stderr (respects quiet).
    pub fn plain(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("{msg}"),
        }
    }

    /// Print a key-value pair with a bold key.
    pub fn kv(&self, key: &str, value: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => eprintln!("  {}: {}", self.style_bold.apply_to(key), value),
        }
    }

    /// Emit a JSON value to stdout (used when `--json` is active, but can
    /// also be called explicitly).
    pub fn json(&self, value: &serde_json::Value) {
        println!(
            "{}",
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
        );
    }

    /// Emit a JSON value only when JSON mode is active.  Returns `true` if
    /// JSON was emitted (so callers can skip human output).
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

/// Create an indeterminate spinner for long-running operations.
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

/// Create a determinate progress bar for multi-item operations.
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
