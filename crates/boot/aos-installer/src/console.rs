//! Operator-visible progress on the system console.
//!
//! The handler's stdout carries the native result document, so every message
//! goes to `/dev/console` (and to stderr, which the controller journals). A
//! missing console is not an error: headless qualification boots still log.

use std::fs::OpenOptions;
use std::io::{self, Read, Write as _};
use std::thread;
use std::time::Duration;

const CONSOLE: &str = "/dev/console";

/// Writes one line to the console and to stderr.
pub fn say(message: &str) {
    eprintln!("aos-installer: {message}");
    if let Ok(mut console) = OpenOptions::new().write(true).open(CONSOLE) {
        let _ = writeln!(console, "AOS installer: {message}");
    }
}

/// Counts down before an irreversible step, announcing each remaining second.
///
/// The countdown cannot be skipped. Powering the machine off is the abort.
pub fn countdown(seconds: u64, action: &str) {
    for remaining in (1..=seconds).rev() {
        say(&format!(
            "{action} in {remaining}s. Power off now to abort."
        ));
        thread::sleep(Duration::from_secs(1));
    }
}

/// Wraps a reader and reports progress every ten percent of `total` bytes.
pub struct Progress<R> {
    inner: R,
    total: u64,
    read: u64,
    next_decile: u64,
}

impl<R> Progress<R> {
    /// Creates a progress reporter for a stream of `total` bytes.
    pub fn new(inner: R, total: u64) -> Self {
        Self {
            inner,
            total,
            read: 0,
            next_decile: 1,
        }
    }
}

impl<R: Read> Read for Progress<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.read = self.read.saturating_add(count as u64);
        while self.next_decile <= 10
            && self.total > 0
            && self.read.saturating_mul(10) >= self.total.saturating_mul(self.next_decile)
        {
            say(&format!("writing image: {}%", self.next_decile * 10));
            self.next_decile += 1;
        }
        Ok(count)
    }
}
