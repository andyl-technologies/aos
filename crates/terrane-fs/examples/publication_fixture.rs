//! Reserves the isolated native publication proof entry point.
//!
//! The publisher task supplies the real single-threaded bootstrap and dispatch.
//! Until then, requesting this executable fails explicitly.

fn main() -> std::process::ExitCode {
    eprintln!("native publication proof is pending implementation");
    std::process::ExitCode::FAILURE
}
