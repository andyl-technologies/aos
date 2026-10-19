//! Runs the isolated configured SDK startup proof when its implementation exists.
//!
//! An example target keeps irreversible native startup outside ordinary test
//! harnesses. This placeholder refuses execution until the proof is implemented.

fn main() -> std::process::ExitCode {
    eprintln!("configured SDK native proof is not implemented");
    std::process::ExitCode::FAILURE
}
