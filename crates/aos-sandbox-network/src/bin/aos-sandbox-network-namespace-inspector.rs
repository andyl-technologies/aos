//! Runs the fixed systemd-activated Network namespace inspector.
//!
//! PID 1 supplies one accepted sequenced-packet socket and protected
//! credentials. The executable accepts no caller-selected arguments.

use std::process::ExitCode;

use aos_sandbox_network::{
    NamespaceInspectorProductionError, run_inherited_network_namespace_inspector,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-network-namespace-inspector: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NamespaceInspectorProductionError> {
    validate_arguments(std::env::args_os())?;
    run_inherited_network_namespace_inspector()
}

fn validate_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), NamespaceInspectorProductionError> {
    drop(arguments.next());
    if arguments.next().is_some() {
        return Err(NamespaceInspectorProductionError::Contract(
            "namespace inspector accepts no arguments",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn fixed_entrypoint_has_no_configuration_arguments() {
        assert!(validate_arguments([OsString::from("inspector")].into_iter()).is_ok());
        assert!(
            validate_arguments(
                [OsString::from("inspector"), OsString::from("untrusted")].into_iter()
            )
            .is_err()
        );
    }
}
