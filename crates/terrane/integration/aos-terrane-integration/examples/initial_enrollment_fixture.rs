//! Exercises genuine first enrollment on a supervised disk-backed Linux guest.
//!
//! The administrator creates and consumes opaque receipts in one process. Later
//! selectors observe actual unprivileged quota queries and metadata validation.
//! The content role separately opens genuine recovery, acknowledges Resume and
//! exercises native ContentStore operations; no selector grants live-R authority.
//! The guest supervisor supplies an otherwise fresh protected fixture directory
//! through `TERRANE_INITIAL_FIXTURE_ROOT` and bounds every child process.

#[cfg(target_os = "linux")]
#[path = "initial_enrollment_fixture/native.rs"]
mod native;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "linux")]
    {
        native::run()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "initial enrollment fixture requires a genuine Linux quota guest",
        )
        .into())
    }
}
