//! Runs the separate Source-only readback signer without writer privileges.

use std::error::Error;
use std::io;
use std::process::ExitCode;

use aos_sandbox_broker_session_security::source_signer_exchange::run_source_signer_service_v1;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-source-signerd: {error}");
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
    run_source_signer_service_v1(controller_uid, controller_gid, signer_uid, signer_gid)
}
