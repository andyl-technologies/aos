//! Runs both fixed Current-proof purposes under the genuine Cache F original.
//!
//! The protected runner captures the installed PID1 activation and its private
//! views and credentials. Ordinary and Q04 orchestration remains in the
//! application library under the policy and controller features.

use std::error::Error;
use std::io;
use std::process::ExitCode;

use aos_sandbox_cache_signer::run_selected_current_service_once;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-cache-signerd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let mut next = || -> io::Result<u32> {
        arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing fixed UID/GID"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fixed UID/GID"))
    };
    let controller_uid = next()?;
    let controller_gid = next()?;
    let signer_uid = next()?;
    let signer_gid = next()?;
    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "extra signer argument").into());
    }
    run_selected_current_service_once(controller_uid, controller_gid, signer_uid, signer_gid)
}
