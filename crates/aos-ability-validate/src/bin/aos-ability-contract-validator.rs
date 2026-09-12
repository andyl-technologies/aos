//! Hermetic build-check frontend for the shared ability semantic validator.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_ability_validate::{
    AbilityContractData, StaticAbilityArtifactClass, StaticAbilityContractExpectation,
    StaticAbilityExecutionStage, StaticAbilityPlatform, validate_ability_contract,
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
        "static-contract" if arguments.len() == 4 || arguments.len() == 7 => {
            validate_static_contract(&arguments[1..])
        }
        _ => usage(),
    }
}

fn validate_package_source(manifest: &Path, interface_directory: &Path) -> Result<()> {
    let manifest_bytes = fs::read(manifest)
        .with_context(|| format!("reading ability manifest {}", manifest.display()))?;
    let mut interface_paths = fs::read_dir(interface_directory)
        .with_context(|| {
            format!(
                "reading retained interface directory {}",
                interface_directory.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    interface_paths.sort();
    let interface_paths = interface_paths
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("json")))
        .collect::<Vec<_>>();
    let interfaces = interface_paths
        .iter()
        .map(|path| {
            fs::read(path).with_context(|| format!("reading retained interface {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    validate_ability_contract(AbilityContractData::PackageSource {
        manifest: &manifest_bytes,
        retained_interfaces: &interfaces,
    })
    .context("ability package failed shared Rust semantic validation")?;
    Ok(())
}

fn validate_static_contract(arguments: &[std::ffi::OsString]) -> Result<()> {
    let contract_path = PathBuf::from(&arguments[0]);
    let artifact_class = match arguments[1].to_str() {
        Some("container") => StaticAbilityArtifactClass::Container,
        Some("bootable") => StaticAbilityArtifactClass::Bootable,
        _ => bail!("artifact class must be container or bootable"),
    };
    let execution_stage = match arguments[2].to_str() {
        Some("-") => None,
        Some("initrd") => Some(StaticAbilityExecutionStage::Initrd),
        Some("host") => Some(StaticAbilityExecutionStage::Host),
        _ => bail!("execution stage must be -, initrd, or host"),
    };
    let platform = if arguments.len() == 6 {
        let text = |index: usize, label: &str| {
            arguments[index]
                .to_str()
                .map(str::to_owned)
                .with_context(|| format!("{label} is not UTF-8"))
        };
        let variant = text(5, "platform variant")?;
        Some(StaticAbilityPlatform {
            os: text(3, "platform operating system")?,
            architecture: text(4, "platform architecture")?,
            variant: (variant != "-").then_some(variant),
        })
    } else {
        None
    };
    let expectation = StaticAbilityContractExpectation {
        artifact_class,
        execution_stage,
        platform,
    };
    let bytes = fs::read(&contract_path).with_context(|| {
        format!(
            "reading static ability contract {}",
            contract_path.display()
        )
    })?;

    validate_ability_contract(AbilityContractData::Static {
        contract: &bytes,
        expectation: &expectation,
    })
    .context("static contract failed shared Rust semantic validation")?;
    Ok(())
}

fn usage<T>() -> Result<T> {
    bail!(
        "usage: aos-ability-contract-validator package-source MANIFEST INTERFACES_DIR\n       aos-ability-contract-validator static-contract CONTRACT ARTIFACT_CLASS STAGE [OS ARCH VARIANT]"
    )
}
