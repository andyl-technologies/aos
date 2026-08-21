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
//! Long-running work is created through [`Printer::activity`] and
//! [`Printer::transfer`] or [`Printer::items`], which apply the same
//! output-mode contract.

use console::Style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PLAIN_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);
const PLAIN_PROGRESS_PERCENT_STEP: u64 = 10;
const PROGRESS_TICK_INTERVAL: Duration = Duration::from_millis(80);
const SPINNER_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"];
const ACTIVITY_TEMPLATE: &str = "{spinner:.cyan} {wide_msg} {elapsed}";
const ITEM_TEMPLATE: &str =
    "{spinner:.cyan} {msg:32!} [{wide_bar:.cyan/dim}] {pos}/{len} ETA {eta}";
const TRANSFER_TEMPLATE: &str = "{spinner:.cyan} {msg:32!} [{wide_bar:.cyan/dim}] \
     {binary_bytes}/{binary_total_bytes} {percent:>3}% {binary_bytes_per_sec} ETA {eta}";
const STREAM_TEMPLATE: &str =
    "{spinner:.cyan} {msg:48!} {binary_bytes} {binary_bytes_per_sec} {elapsed}";

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

/// Controls how long-running operation progress is rendered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProgressMode {
    /// Uses an updating display on a terminal and stable lines elsewhere.
    #[default]
    Auto,
    /// Always uses an updating terminal display.
    Tty,
    /// Always emits stable, newline-delimited progress updates.
    Plain,
    /// Suppresses progress while retaining final results and errors.
    Off,
}

/// Central output handler that respects `--json`, `--quiet`, and `--verbose`
/// flags.  All user-facing text should flow through a `Printer` so that the
/// output mode is honoured consistently.
#[derive(Clone)]
pub struct Printer {
    mode: OutputMode,
    progress_mode: ProgressMode,
    progress: Arc<MultiProgress>,
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
            progress_mode: ProgressMode::Auto,
            progress: Arc::new(MultiProgress::new()),
            style_info: Style::new().cyan(),
            style_success: Style::new().green().bold(),
            style_warning: Style::new().yellow(),
            style_error: Style::new().red().bold(),
            style_step: Style::new().cyan().bold(),
            style_bold: Style::new().bold(),
        }
    }

    /// Overrides the progress renderer selected for long-running operations.
    #[must_use]
    pub fn with_progress_mode(mut self, progress_mode: ProgressMode) -> Self {
        self.progress_mode = progress_mode;
        self
    }

    /// Returns the active [`OutputMode`].
    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Returns the configured long-running operation progress mode.
    pub fn progress_mode(&self) -> ProgressMode {
        self.progress_mode
    }

    /// Starts reporting a byte-oriented transfer.
    ///
    /// Human-readable progress is written to stderr. Quiet and JSON output
    /// modes return a silent reporter so stdout remains stable for scripts.
    pub fn transfer(&self, action: &str, total_bytes: u64) -> TransferProgress {
        TransferProgress::new(self.clone(), action, total_bytes)
    }

    /// Starts reporting an operation whose total work is not measurable.
    pub fn activity(&self, action: &str) -> ActivityProgress {
        ActivityProgress::new(self.clone(), action)
    }

    /// Starts reporting an operation measured in completed items.
    pub fn items(&self, action: &str, total_items: u64) -> ItemProgress {
        ItemProgress::new(self.clone(), action, total_items)
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
            _ => self.write_human(self.style_info.apply_to(msg)),
        }
    }

    /// Prints a success message (green, bold) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn success(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(self.style_success.apply_to(msg)),
        }
    }

    /// Prints a warning (yellow, prefixed with `warning:`) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn warning(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(self.style_warning.apply_to(format!("warning: {msg}"))),
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
            self.write_human(self.style_error.apply_to(format!("error: {msg}")));
        }
    }

    /// Prints a step indicator such as `[1/4] Building package ...`
    /// (cyan + bold prefix) to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn step(&self, current: usize, total: usize, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(format!(
                "{} {}",
                self.style_step.apply_to(format!("[{current}/{total}]")),
                msg,
            )),
        }
    }

    /// Prints a bold header line to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn header(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(self.style_bold.apply_to(msg)),
        }
    }

    /// Prints unstyled text to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn plain(&self, msg: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(msg),
        }
    }

    /// Prints an indented `key: value` pair with a bold key to stderr.
    ///
    /// Suppressed in quiet and JSON modes.
    pub fn kv(&self, key: &str, value: &str) {
        match self.mode {
            OutputMode::Quiet | OutputMode::Json => {}
            _ => self.write_human(format!("  {}: {}", self.style_bold.apply_to(key), value)),
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

    /// Writes one stable human-readable line without corrupting active bars.
    fn write_human(&self, line: impl Display) {
        let line = line.to_string();
        self.progress.suspend(|| eprintln!("{line}"));
    }
}

/// Reports an operation whose total work is not measurable in advance.
pub struct ActivityProgress {
    printer: Printer,
    progress: ProgressBar,
    started: Instant,
}

impl ActivityProgress {
    fn new(printer: Printer, action: &str) -> Self {
        let renderer = progress_renderer(&printer);
        let progress = printer.progress.add(ProgressBar::new_spinner());
        match renderer {
            ProgressRenderer::Tty => {
                progress.set_style(activity_style());
                progress.set_message(action.to_string());
                progress.enable_steady_tick(PROGRESS_TICK_INTERVAL);
            }
            ProgressRenderer::Plain => {
                progress.set_draw_target(ProgressDrawTarget::hidden());
                printer.info(action);
            }
            ProgressRenderer::Hidden => progress.set_draw_target(ProgressDrawTarget::hidden()),
        }
        Self {
            printer,
            progress,
            started: Instant::now(),
        }
    }

    /// Clears the activity after successful completion.
    pub fn finish(self) {
        self.progress.finish_and_clear();
    }

    /// Clears the activity after successful completion.
    ///
    /// This spelling matches `indicatif` and keeps call sites concise while
    /// they migrate to the printer-owned renderer.
    pub fn finish_and_clear(self) {
        self.finish();
    }

    /// Changes the activity label without starting a second indicator.
    pub fn phase(&self, action: &str) {
        self.progress.set_message(action.to_string());
        if matches!(progress_renderer(&self.printer), ProgressRenderer::Plain) {
            self.printer.info(action);
        }
    }

    /// Emits a warning without corrupting an active terminal spinner.
    pub fn warning(&self, message: &str) {
        self.printer.warning(message);
    }

    /// Returns the wall-clock duration since reporting began.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for ActivityProgress {
    fn drop(&mut self) {
        self.progress.finish_and_clear();
    }
}

/// Reports progress through a known number of discrete items.
pub struct ItemProgress {
    printer: Printer,
    action: String,
    total_items: u64,
    progress: ProgressBar,
    plain: Option<Mutex<u64>>,
}

impl ItemProgress {
    fn new(printer: Printer, action: &str, total_items: u64) -> Self {
        let renderer = progress_renderer(&printer);
        let progress = printer.progress.add(ProgressBar::new(total_items));
        let plain = match renderer {
            ProgressRenderer::Tty => {
                progress.set_style(item_style());
                progress.set_message(action.to_string());
                progress.enable_steady_tick(PROGRESS_TICK_INTERVAL);
                None
            }
            ProgressRenderer::Plain => {
                progress.set_draw_target(ProgressDrawTarget::hidden());
                printer.info(&format!("{action} ({total_items} items)"));
                Some(Mutex::new(0))
            }
            ProgressRenderer::Hidden => {
                progress.set_draw_target(ProgressDrawTarget::hidden());
                None
            }
        };
        Self {
            printer,
            action: action.to_string(),
            total_items,
            progress,
            plain,
        }
    }

    /// Advances the operation by `items` completed items.
    pub fn inc(&self, items: u64) {
        self.progress.inc(items);
        let Some(last_bucket) = &self.plain else {
            return;
        };
        let Ok(mut last_bucket) = last_bucket.lock() else {
            return;
        };
        let completed = self.progress.position().min(self.total_items);
        let percent = if self.total_items == 0 {
            100
        } else {
            completed.saturating_mul(100) / self.total_items
        };
        let bucket = percent / PLAIN_PROGRESS_PERCENT_STEP;
        if bucket <= *last_bucket {
            return;
        }
        *last_bucket = bucket;
        self.printer.info(&format!(
            "{}: {}/{} ({}%)",
            self.action,
            completed,
            self.total_items,
            percent.min(100)
        ));
    }

    /// Clears dynamic output after a successful operation.
    pub fn finish(&self) {
        self.progress.finish_and_clear();
    }

    /// Clears dynamic output after a successful operation.
    pub fn finish_and_clear(&self) {
        self.finish();
    }
}

impl Drop for ItemProgress {
    fn drop(&mut self) {
        self.progress.finish_and_clear();
    }
}

#[derive(Debug)]
struct PlainProgressState {
    last_emit: Instant,
    last_percent_bucket: u64,
}

/// Reports the lifecycle of one byte-oriented transfer.
///
/// A reporter may render as an updating terminal line, stable log lines, or
/// no output according to its parent [`Printer`]. Clones share one counter and
/// terminal line so concurrent workers can report an aggregate transfer.
/// Dropping the final handle clears the line; callers should still use
/// [`finish`](Self::finish) or [`abandon`](Self::abandon) after every worker
/// has stopped to communicate the terminal state explicitly.
#[derive(Clone)]
pub struct TransferProgress {
    inner: Arc<TransferProgressInner>,
}

struct TransferProgressInner {
    printer: Printer,
    action: Mutex<String>,
    total_bytes: AtomicU64,
    progress: ProgressBar,
    plain: Option<Mutex<PlainProgressState>>,
    started: Instant,
    renderer: ProgressRenderer,
}

impl TransferProgress {
    fn new(printer: Printer, action: &str, total_bytes: u64) -> Self {
        let renderer = progress_renderer(&printer);
        let progress = if total_bytes == 0 {
            printer.progress.add(ProgressBar::new_spinner())
        } else {
            printer.progress.add(ProgressBar::new(total_bytes))
        };
        let plain = match renderer {
            ProgressRenderer::Tty => {
                progress.set_style(transfer_style(total_bytes));
                progress.set_message(action.to_string());
                progress.enable_steady_tick(PROGRESS_TICK_INTERVAL);
                None
            }
            ProgressRenderer::Plain => {
                progress.set_draw_target(ProgressDrawTarget::hidden());
                if total_bytes == 0 {
                    printer.info(action);
                } else {
                    printer.info(&format!("{action} ({})", format_bytes(total_bytes)));
                }
                Some(Mutex::new(PlainProgressState {
                    last_emit: Instant::now(),
                    last_percent_bucket: 0,
                }))
            }
            ProgressRenderer::Hidden => {
                progress.set_draw_target(ProgressDrawTarget::hidden());
                None
            }
        };
        Self {
            inner: Arc::new(TransferProgressInner {
                printer,
                action: Mutex::new(action.to_string()),
                total_bytes: AtomicU64::new(total_bytes),
                progress,
                plain,
                started: Instant::now(),
                renderer,
            }),
        }
    }

    /// Changes the phase label without resetting byte progress.
    pub fn phase(&self, action: &str) {
        if let Ok(mut current) = self.inner.action.lock() {
            current.clear();
            current.push_str(action);
        }
        self.inner.progress.set_message(action.to_string());
        if self.inner.plain.is_some() {
            self.inner.printer.info(action);
        }
    }

    /// Changes the expected byte total, including from initially unknown.
    pub fn set_total(&self, total_bytes: u64) {
        self.inner.total_bytes.store(total_bytes, Ordering::Relaxed);
        if total_bytes == 0 {
            self.inner.progress.unset_length();
        } else {
            self.inner.progress.set_length(total_bytes);
            if self.inner.progress.position() > total_bytes {
                self.inner.progress.set_position(total_bytes);
            }
        }
        if matches!(self.inner.renderer, ProgressRenderer::Tty) {
            self.inner.progress.set_style(transfer_style(total_bytes));
        }
        if let Some(plain) = &self.inner.plain {
            if let Ok(mut state) = plain.lock() {
                state.last_percent_bucket = 0;
                state.last_emit = Instant::now();
            }
            if total_bytes > 0 {
                self.inner.printer.info(&format!(
                    "{} ({})",
                    self.action(),
                    format_bytes(total_bytes)
                ));
            }
        }
    }

    /// Sets the number of bytes already completed.
    pub fn set_position(&self, bytes: u64) {
        let total_bytes = self.inner.total_bytes.load(Ordering::Relaxed);
        let position = if total_bytes == 0 {
            bytes
        } else {
            bytes.min(total_bytes)
        };
        self.inner.progress.set_position(position);
        self.maybe_emit_plain(bytes);
    }

    /// Advances the operation by `bytes` bytes.
    pub fn inc(&self, bytes: u64) {
        self.inner.progress.inc(bytes);
        self.maybe_emit_plain(self.inner.progress.position());
    }

    /// Emits a warning without corrupting an active terminal progress line.
    pub fn warning(&self, message: &str) {
        self.inner.printer.warning(message);
    }

    /// Clears dynamic output after a successful operation.
    pub fn finish(&self) {
        self.inner.progress.finish_and_clear();
    }

    /// Clears dynamic output and emits a stable interruption or failure note.
    pub fn abandon(&self, message: &str) {
        self.inner.progress.finish_and_clear();
        self.inner.printer.warning(message);
    }

    /// Returns the wall-clock duration since reporting began.
    pub fn elapsed(&self) -> Duration {
        self.inner.started.elapsed()
    }

    /// Returns the number of bytes reported so far.
    pub fn position(&self) -> u64 {
        self.inner.progress.position()
    }

    fn maybe_emit_plain(&self, bytes: u64) {
        let Some(plain) = &self.inner.plain else {
            return;
        };
        let Ok(mut state) = plain.lock() else {
            return;
        };
        let total_bytes = self.inner.total_bytes.load(Ordering::Relaxed);
        let percent = if total_bytes == 0 {
            0
        } else {
            bytes.saturating_mul(100) / total_bytes
        };
        let bucket = percent / PLAIN_PROGRESS_PERCENT_STEP;
        let now = Instant::now();
        if bucket <= state.last_percent_bucket
            && now.duration_since(state.last_emit) < PLAIN_PROGRESS_INTERVAL
        {
            return;
        }
        state.last_percent_bucket = bucket;
        state.last_emit = now;
        if total_bytes == 0 {
            self.inner.printer.info(&format!(
                "{}: {} transferred",
                self.action(),
                format_bytes(bytes)
            ));
        } else {
            self.inner.printer.info(&format!(
                "{}: {}/{} ({}%)",
                self.action(),
                format_bytes(bytes.min(total_bytes)),
                format_bytes(total_bytes),
                percent.min(100),
            ));
        }
    }

    fn action(&self) -> String {
        self.inner
            .action
            .lock()
            .map(|action| action.clone())
            .unwrap_or_else(|_| "Transfer".to_string())
    }
}

impl Drop for TransferProgressInner {
    fn drop(&mut self) {
        self.progress.finish_and_clear();
    }
}

#[derive(Clone, Copy)]
enum ProgressRenderer {
    Tty,
    Plain,
    Hidden,
}

fn progress_renderer(printer: &Printer) -> ProgressRenderer {
    match (printer.mode, printer.progress_mode) {
        (OutputMode::Quiet | OutputMode::Json, _) | (_, ProgressMode::Off) => {
            ProgressRenderer::Hidden
        }
        (_, ProgressMode::Tty) => ProgressRenderer::Tty,
        (_, ProgressMode::Plain) => ProgressRenderer::Plain,
        (_, ProgressMode::Auto) if atty::is(atty::Stream::Stderr) => ProgressRenderer::Tty,
        _ => ProgressRenderer::Plain,
    }
}

fn activity_style() -> ProgressStyle {
    ProgressStyle::with_template(ACTIVITY_TEMPLATE)
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_strings(SPINNER_TICKS)
}

fn item_style() -> ProgressStyle {
    ProgressStyle::with_template(ITEM_TEMPLATE)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .tick_strings(SPINNER_TICKS)
        .progress_chars("━━ ")
}

fn transfer_style(total_bytes: u64) -> ProgressStyle {
    let template = if total_bytes == 0 {
        STREAM_TEMPLATE
    } else {
        TRANSFER_TEMPLATE
    };
    ProgressStyle::with_template(template)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .tick_strings(SPINNER_TICKS)
        .progress_chars("━━ ")
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_progress_kind_uses_the_shared_spinner() {
        for style in [
            activity_style(),
            item_style(),
            transfer_style(0),
            transfer_style(1),
        ] {
            assert_eq!(style.get_tick_str(0), SPINNER_TICKS[0]);
            assert_eq!(style.get_final_tick_str(), "✓");
        }
    }

    #[test]
    fn byte_format_uses_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn unknown_transfer_counts_bytes_across_clones() {
        let progress = Printer::new(0, true, false).transfer("test", 0);
        let worker = progress.clone();

        progress.inc(512);
        worker.inc(1024);

        assert_eq!(progress.position(), 1536);
    }

    #[test]
    fn adding_a_total_clamps_an_unknown_transfer() {
        let progress = Printer::new(0, true, false).transfer("test", 0);
        progress.set_position(2048);

        progress.set_total(1024);

        assert_eq!(progress.position(), 1024);
    }
}
