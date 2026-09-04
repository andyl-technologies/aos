//! Runs the owned fs-verity descriptor qualification inside an isolated VM.
//!
//! The harness supplies an ext4 root and a measurement obtained by its trusted
//! C fixture after sealing a known payload. This is test expectation injection,
//! not a production publication catalog or authorization protocol.

#[cfg(target_os = "linux")]
mod linux;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    linux::run()?;
    Ok(())
}
