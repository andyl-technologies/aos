//! Reserves the isolated native host-cache proof executable.
//!
//! The cache task supplies actual owner, publisher and quota-helper composition
//! before this executable can qualify any behavior. It is excluded from deployed
//! role defaults by the explicit native test-fixture feature.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("native host-cache proof is pending implementation");
    ExitCode::FAILURE
}
