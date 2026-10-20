//! Qualifies protected service journals under VM-selected unprivileged credentials.
//!
//! The harness creates the directory ancestry and drops groups, GID, and UID
//! before exec. This fixture neither changes credentials nor creates its root.

#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("service journal qualification failed: {error}");
        std::process::exit(1);
    }
}
