//! Runs the image-enrolled authenticated Network broker.
//!
//! The fixed Common startup and shared cold/Session engines own every native,
//! protected-state and financial prefix. The finite runtime dispatches the
//! actual authenticated Inventory19, Prepare63 and Destroy9 request on one F.

use std::env;
use std::process::ExitCode;
use aos_sandbox_network::MAXIMUM_RETAINED_NETWORK_NAMESPACES;

#[path = "aos-netd/runtime.rs"]
mod runtime;

#[derive(Debug, thiserror::Error)]
enum NetworkDaemonErrorV1 {
    #[error("usage: aos-netd MAXIMUM_RETAINED_NAMESPACES")]
    Arguments,
    #[error("Network broker must start with real and effective UID zero")]
    Identity,
}

fn main() -> ExitCode {
    let entered = (|| {
        if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
            return Err(NetworkDaemonErrorV1::Identity);
        }
        parse_capacity()
    })();
    match entered {
        Ok(capacity) => runtime::run(capacity),
        Err(cause) => {
            eprintln!("aos-netd: {cause}");
            ExitCode::FAILURE
        }
    }
}

fn parse_capacity() -> Result<usize, NetworkDaemonErrorV1> {
    let mut arguments = env::args_os();
    let _program = arguments.next().ok_or(NetworkDaemonErrorV1::Arguments)?;
    let value = arguments.next().ok_or(NetworkDaemonErrorV1::Arguments)?;
    if arguments.next().is_some() {
        return Err(NetworkDaemonErrorV1::Arguments);
    }
    let value = value
        .to_str()
        .ok_or(NetworkDaemonErrorV1::Arguments)?
        .parse::<usize>()
        .map_err(|_| NetworkDaemonErrorV1::Arguments)?;
    if value == 0 || value > MAXIMUM_RETAINED_NETWORK_NAMESPACES {
        return Err(NetworkDaemonErrorV1::Arguments);
    }

    Ok(value)
}
