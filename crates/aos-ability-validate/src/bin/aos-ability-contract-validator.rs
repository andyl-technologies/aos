//! Command-line adapter for the hermetic ability build frontend.

use std::path::Path;

use anyhow::{Result, bail};
use aos_ability_validate::build_frontend::{
    assemble_static_contract, resolve_package_projection_file, validate_package_source,
    validate_static_contract, write_exported_artifact_reference,
};

fn main() {
    if let Err(error) = run(std::env::args_os().skip(1).collect()) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<std::ffi::OsString>) -> Result<()> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return usage();
    };
    match command {
        "package-source" if arguments.len() == 3 => {
            validate_package_source(Path::new(&arguments[1]), Path::new(&arguments[2]))
        }
        "resolve-package-projection" if arguments.len() == 5 => resolve_package_projection_file(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            Path::new(&arguments[3]),
            Path::new(&arguments[4]),
        ),
        "assemble-static-contract" if arguments.len() == 4 => assemble_static_contract(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            Path::new(&arguments[3]),
        ),
        "resolve-exported-artifact" if arguments.len() == 5 => {
            let graph = arguments[2]
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("exported graph name is not UTF-8"))?;
            write_exported_artifact_reference(
                Path::new(&arguments[1]),
                graph,
                Path::new(&arguments[3]),
                Path::new(&arguments[4]),
            )
        }
        "static-contract" if arguments.len() == 4 || arguments.len() == 7 => {
            validate_static_contract(&arguments[1..])
        }
        _ => usage(),
    }
}

fn usage<T>() -> Result<T> {
    bail!(
        "usage: aos-ability-contract-validator package-source MANIFEST INTERFACES_DIR\n       aos-ability-contract-validator resolve-package-projection PROJECTION RESOLUTION EXPORTED_GRAPH OUTPUT\n       aos-ability-contract-validator resolve-exported-artifact ROOT GRAPH EXPORTED_GRAPH OUTPUT\n       aos-ability-contract-validator assemble-static-contract SPEC EXPORTED_GRAPH OUTPUT\n       aos-ability-contract-validator static-contract CONTRACT ARTIFACT_CLASS STAGE [OS ARCH VARIANT]"
    )
}
