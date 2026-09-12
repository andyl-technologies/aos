//! No-follow capture of a Nix-produced unsigned assembly.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_validate::{
    AbilityContractData, StaticAbilityArtifactClass, StaticAbilityContractExpectation,
    StaticAbilityExecutionStage, StaticAbilityPlatform, validate_ability_contract,
};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::assembly::{
    AssemblyFileKind, AssemblyFileV1, AssemblyToolV1, ImageBudgetsV1, ImageCommandLinesV1,
    ImageLayoutV1, ImageSignerRolesV1, UNSIGNED_IMAGE_ASSEMBLY_V2, UNSIGNED_IMAGE_ASSEMBLY_V3,
    UNSIGNED_IMAGE_ASSEMBLY_V4, UnsignedImageAssemblyV1,
};
use crate::initrd_contract::{ArtifactExecutionStage, InitrdStageContractV1};

const RECIPE_SCHEMA_V2: &str = "aos.image.assembly-recipe/v2";
const RECIPE_SCHEMA_V3: &str = "aos.image.assembly-recipe/v3";
const RECIPE_SCHEMA_V4: &str = "aos.image.assembly-recipe/v4";
const MAX_RECIPE_BYTES: u64 = 1024 * 1024;
const MAX_STATIC_ABILITY_CONTRACT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssemblyRecipeV1 {
    schema_version: String,
    release: String,
    platform: Platform,
    system_variant: String,
    kernel_release: String,
    module_abi: u64,
    recovery_abi: u64,
    sbat_generation: u64,
    sbat: crate::assembly::SbatPolicyV1,
    command_lines: CommandLines,
    signer_roles: SignerRoles,
    layout: ImageLayoutV1,
    budgets: ImageBudgetsV1,
    tools: BTreeMap<String, RecipeTool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeTool {
    executable: String,
    environment: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandLines {
    slot_a: String,
    slot_b: String,
    recovery: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerRoles {
    secure_boot: String,
    module: String,
    pcr: String,
}

/// Captures one immutable assembly directory into its public contract.
///
/// `resolve_owner_nar_hash` receives each exact tool executable and must return
/// the independently queried NAR hash of its owning store output.
///
/// # Errors
///
/// Returns an error for a noncanonical or oversized recipe, a link or special
/// input, a changed file during capture, an unknown/missing tool identity, or
/// any invalid resulting assembly contract.
pub fn capture_unsigned_assembly(
    root: &Path,
    release_id: &str,
    mut resolve_owner_nar_hash: impl FnMut(&str) -> Result<String>,
) -> Result<UnsignedImageAssemblyV1> {
    let recipe_path = root.join("assembly-recipe.json");
    let recipe_bytes = capture_control_file(&recipe_path, "image assembly recipe")?;
    canonical::require_canonical(&recipe_bytes, "image assembly recipe")?;
    let recipe: AssemblyRecipeV1 = canonical::from_slice(&recipe_bytes, "image assembly recipe")?;
    if !matches!(
        recipe.schema_version.as_str(),
        RECIPE_SCHEMA_V2 | RECIPE_SCHEMA_V3 | RECIPE_SCHEMA_V4
    ) {
        bail!("unsupported image assembly recipe schema");
    }
    let has_initrd_contract = matches!(
        recipe.schema_version.as_str(),
        RECIPE_SCHEMA_V3 | RECIPE_SCHEMA_V4
    );
    let has_static_ability_contracts = recipe.schema_version == RECIPE_SCHEMA_V4;
    if [
        recipe.command_lines.slot_a.as_str(),
        recipe.command_lines.slot_b.as_str(),
        recipe.command_lines.recovery.as_str(),
        recipe.signer_roles.secure_boot.as_str(),
        recipe.signer_roles.module.as_str(),
        recipe.signer_roles.pcr.as_str(),
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        bail!("image assembly recipe has an empty command line or signer role");
    }

    let specifications = [
        (
            "bootloader",
            AssemblyFileKind::Bootloader,
            "inputs/systemd-boot.efi",
        ),
        (
            "enrollment",
            AssemblyFileKind::FirmwareEnrollment,
            "inputs/firmware-enrollment.tar",
        ),
        ("initrd", AssemblyFileKind::Initrd, "inputs/initrd.img"),
        ("kernel", AssemblyFileKind::Kernel, "inputs/vmlinuz"),
        (
            "kernel-config",
            AssemblyFileKind::KernelConfig,
            "inputs/kernel.config",
        ),
        (
            "module-certificate",
            AssemblyFileKind::ModuleCertificate,
            "trust/module-signing.crt",
        ),
        (
            "os-release",
            AssemblyFileKind::OsRelease,
            "inputs/os-release",
        ),
        (
            "pcr-public-key",
            AssemblyFileKind::PcrPublicKey,
            "trust/pcr-public.pem",
        ),
        (
            "recovery-initrd-a",
            AssemblyFileKind::RecoveryInitrdA,
            "inputs/recovery-initrd-a.img",
        ),
        (
            "recovery-initrd-b",
            AssemblyFileKind::RecoveryInitrdB,
            "inputs/recovery-initrd-b.img",
        ),
        (
            "recovery-os-release-a",
            AssemblyFileKind::RecoveryOsReleaseA,
            "inputs/recovery-os-release-a",
        ),
        (
            "recovery-os-release-b",
            AssemblyFileKind::RecoveryOsReleaseB,
            "inputs/recovery-os-release-b",
        ),
        (
            "root-filesystem",
            AssemblyFileKind::RootFilesystem,
            "inputs/root.img",
        ),
        (
            "secure-boot-certificate",
            AssemblyFileKind::SecureBootCertificate,
            "trust/secure-boot-db.crt",
        ),
        ("uki-stub", AssemblyFileKind::UkiStub, "inputs/uki-stub.efi"),
        (
            "verity-root-hash",
            AssemblyFileKind::VerityRootHash,
            "inputs/root.roothash",
        ),
        (
            "verity-tree",
            AssemblyFileKind::VerityTree,
            "inputs/root.verity",
        ),
    ];
    let mut files = specifications
        .into_iter()
        .map(|(id, kind, relative)| {
            let path = BundlePath::parse(relative)?;
            let (size_bytes, sha256) = capture_regular_file(&root.join(relative))?;
            Ok(AssemblyFileV1 {
                id: id.to_owned(),
                kind,
                path,
                size_bytes,
                sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let initrd_contract = if has_initrd_contract {
        let relative = "inputs/initrd-stage-contract.json";
        let contract_bytes = capture_control_file(&root.join(relative), "initrd stage contract")?;
        canonical::require_canonical(&contract_bytes, "initrd stage contract")?;
        let contract: InitrdStageContractV1 =
            canonical::from_slice(&contract_bytes, "initrd stage contract")?;
        files.push(AssemblyFileV1 {
            id: "initrd-contract".to_owned(),
            kind: AssemblyFileKind::InitrdContract,
            path: BundlePath::parse(relative)?,
            size_bytes: u64::try_from(contract_bytes.len())?,
            sha256: Sha256Digest::of_bytes(&contract_bytes),
        });
        Some(contract)
    } else {
        None
    };
    if has_static_ability_contracts {
        files.push(capture_static_ability_contract(
            root,
            "initrd-ability-contract",
            AssemblyFileKind::InitrdStaticAbilityContract,
            "inputs/initrd-static-ability-contract.json",
            recipe.platform,
            ArtifactExecutionStage::Initrd,
        )?);
        files.push(capture_static_ability_contract(
            root,
            "host-ability-contract",
            AssemblyFileKind::HostStaticAbilityContract,
            "inputs/host-static-ability-contract.json",
            recipe.platform,
            ArtifactExecutionStage::Host,
        )?);
    }
    files.sort_by(|left, right| left.id.cmp(&right.id));

    let tools = recipe
        .tools
        .into_iter()
        .map(|(id, tool)| {
            let owner_nar_hash = resolve_owner_nar_hash(&tool.executable)
                .with_context(|| format!("resolving owner NAR hash for tool {id}"))?;
            Ok(AssemblyToolV1 {
                id,
                executable: tool.executable,
                owner_nar_hash,
                environment: tool.environment,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let assembly = UnsignedImageAssemblyV1 {
        schema_version: if has_static_ability_contracts {
            UNSIGNED_IMAGE_ASSEMBLY_V4.to_owned()
        } else if has_initrd_contract {
            UNSIGNED_IMAGE_ASSEMBLY_V3.to_owned()
        } else {
            UNSIGNED_IMAGE_ASSEMBLY_V2.to_owned()
        },
        release_id: release_id.to_owned(),
        version: recipe.release,
        platform: recipe.platform,
        system_variant: recipe.system_variant,
        kernel_release: recipe.kernel_release,
        module_abi: recipe.module_abi,
        recovery_abi: recipe.recovery_abi,
        sbat_generation: recipe.sbat_generation,
        sbat: recipe.sbat,
        command_lines: ImageCommandLinesV1 {
            slot_a: recipe.command_lines.slot_a,
            slot_b: recipe.command_lines.slot_b,
            recovery: recipe.command_lines.recovery,
        },
        signer_roles: ImageSignerRolesV1 {
            secure_boot: recipe.signer_roles.secure_boot,
            module: recipe.signer_roles.module,
            pcr: recipe.signer_roles.pcr,
        },
        layout: recipe.layout,
        budgets: recipe.budgets,
        initrd_contract,
        files,
        tools,
    };
    assembly.validate()?;
    Ok(assembly)
}

fn capture_static_ability_contract(
    root: &Path,
    id: &str,
    kind: AssemblyFileKind,
    relative: &str,
    platform: Platform,
    expected_stage: ArtifactExecutionStage,
) -> Result<AssemblyFileV1> {
    let bytes = capture_control_file_with_limit(
        &root.join(relative),
        "static ability contract",
        MAX_STATIC_ABILITY_CONTRACT_BYTES,
    )?;
    let (os, architecture) = match platform {
        Platform::X86_64Linux => ("linux", "amd64"),
        Platform::Aarch64Linux => ("linux", "arm64"),
        Platform::X86_64Darwin | Platform::Aarch64Darwin => {
            bail!("boot static ability contract requires a Linux platform")
        }
    };
    let execution_stage = match expected_stage {
        ArtifactExecutionStage::Initrd => StaticAbilityExecutionStage::Initrd,
        ArtifactExecutionStage::Host => StaticAbilityExecutionStage::Host,
        ArtifactExecutionStage::Build => {
            bail!("boot static ability contract cannot describe the build stage")
        }
    };
    let expectation = StaticAbilityContractExpectation {
        artifact_class: StaticAbilityArtifactClass::Bootable,
        execution_stage: Some(execution_stage),
        platform: Some(StaticAbilityPlatform {
            os: os.to_string(),
            architecture: architecture.to_string(),
            variant: None,
        }),
    };
    validate_ability_contract(AbilityContractData::Static {
        contract: &bytes,
        expectation: &expectation,
    })?;

    Ok(AssemblyFileV1 {
        id: id.to_owned(),
        kind,
        path: BundlePath::parse(relative)?,
        size_bytes: u64::try_from(bytes.len())?,
        sha256: Sha256Digest::of_bytes(&bytes),
    })
}

fn capture_control_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    capture_control_file_with_limit(path, label, MAX_RECIPE_BYTES)
}

fn capture_control_file_with_limit(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>> {
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum {
        bail!("{label} must be a bounded single-link regular file");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    let current = path.symlink_metadata()?;
    if u64::try_from(bytes.len())? != metadata.len()
        || current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
    {
        bail!("{label} changed during capture");
    }
    Ok(bytes)
}

fn capture_regular_file(path: &Path) -> Result<(u64, Sha256Digest)> {
    let mut file = open_regular_nofollow(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 {
        bail!("assembly input must be a nonempty single-link regular file");
    }
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("assembly input size overflow")?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = path.symlink_metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || size != before.len()
        || current.dev() != before.dev()
        || current.ino() != before.ino()
    {
        bail!("assembly input changed during capture");
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((size, Sha256Digest::from_bytes(digest)))
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening assembly input {}", path.display()))?;
    Ok(File::from(descriptor))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;

    fn fixture(schema_version: &str) -> Result<tempfile::TempDir> {
        let temporary = tempfile::tempdir()?;
        for relative in [
            "inputs/systemd-boot.efi",
            "inputs/firmware-enrollment.tar",
            "inputs/initrd.img",
            "inputs/recovery-initrd-a.img",
            "inputs/recovery-initrd-b.img",
            "inputs/recovery-os-release-a",
            "inputs/recovery-os-release-b",
            "inputs/vmlinuz",
            "inputs/kernel.config",
            "trust/module-signing.crt",
            "inputs/os-release",
            "trust/pcr-public.pem",
            "inputs/root.img",
            "trust/secure-boot-db.crt",
            "inputs/uki-stub.efi",
            "inputs/root.roothash",
            "inputs/root.verity",
        ] {
            let path = temporary.path().join(relative);
            fs::create_dir_all(path.parent().context("fixture path has no parent")?)?;
            fs::write(path, relative.as_bytes())?;
        }
        let recipe = json!({
            "schema_version": schema_version,
            "release": "2026.9.0",
            "platform": "x86_64-linux",
            "system_variant": "production",
            "kernel_release": "6.18.33",
            "module_abi": 1,
            "recovery_abi": 1,
            "sbat_generation": 1,
            "sbat":{"component":"aos","vendor":"Andyl Inc.","package":"aos","url":"https://aos.dev"},
            "command_lines": {"slot_a":"root=a","slot_b":"root=b","recovery":"recovery=1"},
            "signer_roles": {"secure_boot":"secure-boot-release","module":"module-release","pcr":"pcr-release"},
            "layout": {
              "sector_size":512,"alignment_sectors":2048,"esp_start_sector":2048,
              "esp_size_mib":384,"root_partition_mib":1024,"verity_partition_mib":16,
              "root_filesystem_type":"erofs","root_filesystem_uuid":"bdfb6fc9-0000-4000-8000-000000000001",
              "root_filesystem_label":"aos-root","erofs_compression_level":19,"esp_extra_free_mib":0,
              "verity_uuid":"00000000-0000-4000-8000-000000000007",
              "verity_salt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "disk_guid":"00000000-0000-0000-0000-000000000001",
              "partition_type_guids":{"esp":"C12A7328-F81F-11D2-BA4B-00A0C93EC93B","root":"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709","verity":"2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5"},
              "partition_guids":{"esp":"00000000-0000-0000-0000-000000000002","root_a":"00000000-0000-0000-0000-000000000003","root_a_hash":"00000000-0000-0000-0000-000000000004","root_b":"00000000-0000-0000-0000-000000000005","root_b_hash":"00000000-0000-0000-0000-000000000006"},
              "fat_volume_id":"ABCDEF01","efi_filenames":{"fallback":"BOOTX64.EFI","systemd_boot":"systemd-bootx64.efi","normal_uki":"aos-generation-0000000001+3.efi"}
            },
            "budgets":{"root_mib":512,"initrd_mib":128,"uki_mib":160,"download_mib":640},
            "tools": {"ukify":{"executable":"/nix/store/00000000000000000000000000000000-systemd/bin/ukify","environment":{}}}
        });
        fs::write(
            temporary.path().join("assembly-recipe.json"),
            canonical::to_vec(&recipe)?,
        )?;
        if matches!(schema_version, RECIPE_SCHEMA_V3 | RECIPE_SCHEMA_V4) {
            write_initrd_contract(&temporary, "initrd")?;
        }
        if schema_version == RECIPE_SCHEMA_V4 {
            write_static_ability_contract(&temporary, "initrd")?;
            write_static_ability_contract(&temporary, "host")?;
        }
        Ok(temporary)
    }

    fn write_static_ability_contract(
        temporary: &tempfile::TempDir,
        execution_stage: &str,
    ) -> Result<()> {
        let contract = json!({
            "schema":"aos.boot.static-abilities/v1",
            "platforms":[{
                "platform":{"os":"linux","architecture":"amd64"},
                "execution_stage":execution_stage,
                "packages":[],
                "abilities":[],
                "unresolved_launch_obligations":[]
            }],
            "runtime_grants":[]
        });
        fs::write(
            temporary.path().join(format!(
                "inputs/{execution_stage}-static-ability-contract.json"
            )),
            canonical::to_vec(&contract)?,
        )?;
        Ok(())
    }

    fn write_initrd_contract(temporary: &tempfile::TempDir, available_stage: &str) -> Result<()> {
        let initrd = fs::read(temporary.path().join("inputs/initrd.img"))?;
        let contract = json!({
            "schema_version":"aos.boot.initrd-stage-contract/v1",
            "stage":"initrd",
            "platform":"x86_64-linux",
            "kernel_release":"6.18.33",
            "artifact":{
                "path":"initrd.img",
                "size_bytes":initrd.len(),
                "sha256":Sha256Digest::of_bytes(&initrd)
            },
            "dependency_roots":[
                {
                    "kind":"kernel",
                    "store_path":"/nix/store/00000000000000000000000000000000-kernel",
                    "available_stage":"build"
                },
                {
                    "kind":"runtime-package",
                    "store_path":"/nix/store/11111111111111111111111111111111-runtime",
                    "available_stage":available_stage
                },
                {
                    "kind":"unit-configuration",
                    "store_path":"/nix/store/22222222222222222222222222222222-units",
                    "available_stage":"build"
                }
            ],
            "rendered_units":["aos-config-seed.service"],
            "rendered_networks":[],
            "load_modules":[],
            "masked_units":[],
            "handoff":{
                "to_stage":"host",
                "mechanism":"systemd-switch-root",
                "completion_target":"initrd-fs.target",
                "required_units":["aos-config-seed.service"],
                "preserved_mounts":[
                    {"initrd_path":"/run","host_path":"/run"},
                    {"initrd_path":"/sysroot/var","host_path":"/var"}
                ],
                "durable_state_roots":[{
                    "initrd_path":"/sysroot/var/lib/profiles/system",
                    "host_path":"/var/lib/profiles/system"
                }],
                "transferable_handles":false,
                "receiving_stage_reauthorizes":true,
                "receiving_stage_reacquires":true
            }
        });
        fs::write(
            temporary.path().join("inputs/initrd-stage-contract.json"),
            canonical::to_vec(&contract)?,
        )?;
        Ok(())
    }

    #[test]
    fn captures_complete_public_only_assembly() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V2)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.files.len(), 17);
        assert_eq!(assembly.tools.len(), 1);
        Ok(())
    }

    #[test]
    fn captures_initrd_contract_and_exact_archive_binding() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.schema_version, UNSIGNED_IMAGE_ASSEMBLY_V3);
        assert_eq!(assembly.files.len(), 18);
        assert!(assembly.initrd_contract.is_some());

        fs::write(
            temporary.path().join("inputs/initrd.img"),
            b"changed archive",
        )?;
        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn captures_stage_specific_static_ability_contracts() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V4)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.schema_version, UNSIGNED_IMAGE_ASSEMBLY_V4);
        assert_eq!(assembly.files.len(), 20);

        write_static_ability_contract(&temporary, "host")?;
        fs::rename(
            temporary
                .path()
                .join("inputs/host-static-ability-contract.json"),
            temporary
                .path()
                .join("inputs/initrd-static-ability-contract.json"),
        )?;
        let error = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })
        .expect_err("a host-stage contract cannot replace the initrd contract");
        assert!(
            error
                .to_string()
                .contains("wrong platform or execution stage")
        );
        Ok(())
    }

    #[test]
    fn rejects_untyped_static_ability_records() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V4)?;
        let path = temporary
            .path()
            .join("inputs/host-static-ability-contract.json");
        let mut contract: serde_json::Value =
            canonical::from_slice(&fs::read(&path)?, "static ability contract fixture")?;
        contract["platforms"][0]["packages"] = json!([{}]);
        fs::write(path, canonical::to_vec(&contract)?)?;

        let error = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })
        .expect_err("an arbitrary object is not a static package record");
        assert!(error.to_string().contains("static ability contract"));
        Ok(())
    }

    #[test]
    fn rejects_a_host_stage_initrd_dependency() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        write_initrd_contract(&temporary, "host")?;

        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_a_required_but_masked_handoff_unit() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let path = temporary.path().join("inputs/initrd-stage-contract.json");
        let mut contract: serde_json::Value =
            canonical::from_slice(&fs::read(&path)?, "initrd stage contract fixture")?;
        contract["masked_units"] = json!(["aos-config-seed.service"]);
        fs::write(path, canonical::to_vec(&contract)?)?;

        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_a_contract_without_a_mandatory_producer_root() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let path = temporary.path().join("inputs/initrd-stage-contract.json");
        let mut contract: serde_json::Value =
            canonical::from_slice(&fs::read(&path)?, "initrd stage contract fixture")?;
        contract["dependency_roots"]
            .as_array_mut()
            .context("fixture dependency roots are an array")?
            .retain(|dependency| dependency["kind"] != "kernel");
        fs::write(path, canonical::to_vec(&contract)?)?;

        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_a_link_substituted_for_an_input() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = fixture(RECIPE_SCHEMA_V2)?;
        let target = temporary.path().join("target");
        fs::write(&target, b"replacement")?;
        fs::remove_file(temporary.path().join("inputs/vmlinuz"))?;
        symlink(target, temporary.path().join("inputs/vmlinuz"))?;
        assert!(
            capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| Ok(format!(
                "sha256:{}",
                "a".repeat(64)
            )),)
            .is_err()
        );
        Ok(())
    }
}
