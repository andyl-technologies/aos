//! No-follow capture of a Nix-produced unsigned assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_package::deployment::model::{Deployment, ResolvedPackages};
use aos_package::native_deployment::{AdmissionCatalog, EvaluationInput};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::assembly::{
    AssemblyFileKind, AssemblyFileV1, AssemblyToolV1, ImageBudgetsV1, ImageCommandLinesV1,
    ImageLayoutV1, ImageSignerRolesV1, UNSIGNED_IMAGE_ASSEMBLY_V3, UnsignedImageAssemblyV1,
};
use crate::initrd_contract::InitrdStageContractV1;

const RECIPE_SCHEMA_V3: &str = "aos.image.assembly-recipe/v3";
const MAX_RECIPE_BYTES: u64 = 1024 * 1024;
const MAX_DEPLOYMENT_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssemblyRecipeV1 {
    schema_version: String,
    release: String,
    platform: Platform,
    system_variant: String,
    kernel_release: String,
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
    if recipe.schema_version != RECIPE_SCHEMA_V3 {
        bail!("unsupported image assembly recipe schema");
    }
    if [
        recipe.command_lines.slot_a.to_string(),
        recipe.command_lines.slot_b.to_string(),
        recipe.command_lines.recovery.to_string(),
        recipe.signer_roles.secure_boot.to_string(),
        recipe.signer_roles.module.to_string(),
        recipe.signer_roles.pcr.to_string(),
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
    let relative = "inputs/initrd-stage-contract.json";
    let contract_bytes = capture_control_file(&root.join(relative), "initrd stage contract")?;
    canonical::require_canonical(&contract_bytes, "initrd stage contract")?;
    let initrd_contract: InitrdStageContractV1 =
        canonical::from_slice(&contract_bytes, "initrd stage contract")?;
    files.push(AssemblyFileV1 {
        id: "initrd-contract".to_owned(),
        kind: AssemblyFileKind::InitrdContract,
        path: BundlePath::parse(relative)?,
        size_bytes: u64::try_from(contract_bytes.len())?,
        sha256: Sha256Digest::of_bytes(&contract_bytes),
    });
    for stage in ["initrd", "host"] {
        files.extend(capture_deployment(root, stage, recipe.platform)?);
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
        schema_version: UNSIGNED_IMAGE_ASSEMBLY_V3.to_owned(),
        release_id: release_id.to_owned(),
        version: recipe.release,
        platform: recipe.platform,
        system_variant: recipe.system_variant,
        kernel_release: recipe.kernel_release,
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
        initrd_contract: Some(initrd_contract),
        files,
        tools,
    };
    assembly.validate()?;
    Ok(assembly)
}

fn capture_deployment(root: &Path, stage: &str, platform: Platform) -> Result<Vec<AssemblyFileV1>> {
    let mut documents = BTreeMap::new();
    let mut files = Vec::new();
    for (kind, filename) in crate::assembly::native_deployment_files(stage) {
        let relative = format!("inputs/{stage}-deployment/{filename}");
        let bytes = capture_control_file_with_limit(
            &root.join(&relative),
            "native deployment document",
            MAX_DEPLOYMENT_DOCUMENT_BYTES,
        )?;
        files.push(AssemblyFileV1 {
            id: format!("{stage}-{}", filename.replace('.', "-")),
            kind,
            path: BundlePath::parse(&relative)?,
            size_bytes: u64::try_from(bytes.len())?,
            sha256: Sha256Digest::of_bytes(&bytes),
        });
        documents.insert(filename, bytes);
    }
    let packages: ResolvedPackages = serde_json::from_slice(&documents["packages.json"])?;
    let deployment = Deployment::decode(&documents["transaction.json"], &packages)?;
    let expected_platform = match platform {
        Platform::X86_64Linux => "x86_64-linux",
        Platform::Aarch64Linux => "aarch64-linux",
        _ => bail!("native boot deployment requires a Linux platform"),
    };
    if packages.system != expected_platform {
        bail!("native deployment target differs from the image target");
    }
    let scope = deployment.scope();
    if (stage == "host" && scope != ["profile", "system"])
        || (stage == "initrd" && (scope.len() != 2 || scope[1] != "initrd"))
    {
        bail!("native deployment has the wrong stage scope");
    }
    let evaluation = EvaluationInput::decode(&documents["evaluation.json"])?;
    if evaluation.schema != "aos.package.evaluation-input"
        || evaluation.packages != packages
        || evaluation.scope != scope
    {
        bail!("native evaluation descriptor differs from the checked deployment");
    }
    for source in std::iter::once(&evaluation.library)
        .chain(&evaluation.configuration)
        .chain(&evaluation.runtime_configuration)
    {
        let source = source.to_str().context("native source path is not UTF-8")?;
        let suffix = source
            .strip_prefix("/nix/store/")
            .context("native source is outside the store")?;
        let component = suffix
            .split('/')
            .next()
            .context("native source lacks its store root")?;
        let root = format!("/nix/store/{component}");
        aos_release::artifact::require_store_path(&root, false)?;
        if !deployment.inputs().contains(&root) {
            bail!("native evaluation source is not retained by the deployment");
        }
    }
    let expected_digest =
        Sha256Digest::parse(std::str::from_utf8(&documents["admission-sha256"])?.trim())?;
    let admission = AdmissionCatalog::decode(&documents["admission.json"], expected_digest)?;
    let mut required_roots = BTreeSet::new();
    for artifact in &packages.artifacts {
        required_roots.insert(artifact.path.as_str());
    }
    for module in &packages.modules {
        required_roots.insert(module.config_root.as_str());
    }
    admission.require_roots(required_roots)?;
    for source in evaluation
        .configuration
        .iter()
        .chain(&evaluation.runtime_configuration)
    {
        let source = source
            .to_str()
            .context("native configuration source is not UTF-8")?;
        let suffix = source
            .strip_prefix("/nix/store/")
            .context("native source is outside store")?;
        let component = suffix
            .split('/')
            .next()
            .context("native source lacks root")?;
        admission.require_roots(std::iter::once(format!("/nix/store/{component}").as_str()))?;
    }
    if stage == "host" {
        let installed: Vec<aos_package::types::InstalledMeta> =
            serde_json::from_slice(&documents["installed.json"])?;
        let selected: BTreeSet<_> = packages
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect();
        let records: BTreeSet<_> = installed
            .iter()
            .map(|record| record.store_path.as_str())
            .collect();
        if records.len() != installed.len() || records != selected {
            bail!("native installed metadata differs from selected image payloads");
        }
        for record in &installed {
            let package = record
                .apm
                .as_ref()
                .context("image payload lacks package metadata")?;
            let envelope = package
                .deployment
                .as_ref()
                .context("image payload lacks native envelope locator")?;
            admission.require_roots(std::iter::once(envelope.store_path.as_str()))?;
            if !deployment.inputs().contains(&envelope.store_path) {
                bail!("native package envelope is not retained by image deployment");
            }
            if let Some(documentation) = &package.module_documentation {
                admission.require_roots(std::iter::once(documentation.store_path.as_str()))?;
                if !deployment.inputs().contains(&documentation.store_path) {
                    bail!("native module documentation is not retained by image deployment");
                }
            }
        }
    }
    let library = evaluation
        .library
        .to_str()
        .context("native library is not UTF-8")?;
    let component = library
        .strip_prefix("/nix/store/")
        .context("native library is outside store")?
        .split('/')
        .next()
        .context("native library lacks root")?;
    let library_root = format!("/nix/store/{component}");
    admission.require_roots(std::iter::once(library_root.as_str()))?;
    let identity = admission
        .roots()
        .get(&library_root)
        .context("native library lacks admission")?;
    if identity.nar_hash != evaluation.library_nar_hash.to_string() {
        bail!("native library descriptor differs from admitted NAR identity");
    }
    Ok(files)
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
        write_initrd_contract(&temporary, "initrd")?;
        write_native_deployment(&temporary, "initrd")?;
        write_native_deployment(&temporary, "host")?;
        Ok(temporary)
    }

    fn write_native_deployment(temporary: &tempfile::TempDir, stage: &str) -> Result<()> {
        let directory = temporary.path().join(format!("inputs/{stage}-deployment"));
        fs::create_dir_all(&directory)?;
        let scope = if stage == "host" {
            json!(["profile", "system"])
        } else {
            json!(["fixture", "initrd"])
        };
        let packages = json!({"system":"x86_64-linux","artifacts":[],"modules":[]});
        let library = "/nix/store/00000000000000000000000000000000-library/default.nix";
        let transaction = json!({"schema":"aos.package.transaction","scope":scope,"system":"x86_64-linux",
            "artifacts":[],"inputs":["/nix/store/00000000000000000000000000000000-library"],"packages":[],"retire":[],
            "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}});
        let mut evaluation = json!({"schema":"aos.package.evaluation-input","library":library,
            "libraryNarHash":format!("sha256:{}", "a".repeat(64)),"scope":scope,"packages":packages,
            "moduleEnvelopes":{},"packageEnvelopes":{},"configuration":[]});
        if stage == "host" {
            evaluation["osRelease"] = json!({"name":"fixture","version":"1.0.0"});
        }
        let admission = canonical::to_vec(
            &json!({"schema":"aos.package.admission","roots":[{"storePath":"/nix/store/00000000000000000000000000000000-library","narHash":format!("sha256:{}", "a".repeat(64)),"narSize":1,"references":[]}]}),
        )?;
        fs::write(
            directory.join("admission-sha256"),
            Sha256Digest::of_bytes(&admission).to_string(),
        )?;
        fs::write(directory.join("admission.json"), admission)?;
        for (name, value) in [
            ("transaction.json", transaction),
            ("packages.json", packages),
            ("evaluation.json", evaluation),
        ] {
            fs::write(directory.join(name), canonical::to_vec(&value)?)?;
        }
        if stage == "host" {
            fs::write(directory.join("installed.json"), b"[]")?;
        }
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
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.files.len(), 29);
        assert!(assembly.initrd_contract.is_some());
        assert_eq!(assembly.tools.len(), 1);
        Ok(())
    }

    #[test]
    fn native_attachments_bind_the_current_archive_store_layout() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        let initrd_tree = temporary.path().join("initrd-tree");
        let root_tree = temporary.path().join("root-tree");
        let host_store = root_tree.join("usr/lib/aos/nix/store");
        let host_bundle = "11111111111111111111111111111111-host-deployment";

        // Absolute runtime aliases must resolve against each archive's backing
        // store, without requiring a mounted /nix overlay or host store access.
        for (stage, tree, store, bundle, relative) in [
            (
                "initrd",
                &initrd_tree,
                "nix/store",
                "00000000000000000000000000000000-initrd-deployment",
                "lib/aos/initrd/deployment",
            ),
            (
                "host",
                &root_tree,
                "usr/lib/aos/nix/store",
                host_bundle,
                "usr/lib/aos/host/deployment",
            ),
        ] {
            let documents = tree.join(store).join(bundle);
            fs::create_dir_all(&documents)?;
            let alias = tree.join(relative);
            fs::create_dir_all(alias.parent().context("fixture bundle lacks parent")?)?;
            symlink(format!("/nix/store/{bundle}"), alias)?;
            for (_, filename) in crate::assembly::native_deployment_files(stage) {
                fs::copy(
                    temporary
                        .path()
                        .join(format!("inputs/{stage}-deployment/{filename}")),
                    documents.join(filename),
                )?;
            }
        }

        let verify = || -> Result<()> {
            let captured_inputs = tempfile::tempdir()?;
            crate::finalize::verify_native_deployment_attachments(
                temporary.path(),
                &assembly,
                captured_inputs.path(),
                &initrd_tree,
                &root_tree,
            )
        };
        verify()?;

        let transaction = host_store.join(host_bundle).join("transaction.json");
        let original = fs::read(&transaction)?;
        fs::write(&transaction, b"changed embedded transaction")?;
        let error = verify().expect_err("changed host deployment must fail custody checks");
        assert!(
            error
                .to_string()
                .contains("differs from embedded deployment")
        );

        fs::write(&transaction, original)?;
        let relocated_store = root_tree.join("relocated-store");
        fs::rename(&host_store, &relocated_store)?;
        symlink(&relocated_store, &host_store)?;
        assert!(
            verify().is_err(),
            "linked backing-store parents must fail closed"
        );
        Ok(())
    }

    #[test]
    fn captures_initrd_contract_and_exact_archive_binding() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        let assembly = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })?;
        assert_eq!(assembly.schema_version, UNSIGNED_IMAGE_ASSEMBLY_V3);
        assert_eq!(assembly.files.len(), 29);
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
    fn rejects_cross_stage_native_transaction() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        fs::copy(
            temporary
                .path()
                .join("inputs/host-deployment/transaction.json"),
            temporary
                .path()
                .join("inputs/initrd-deployment/transaction.json"),
        )?;
        let error = capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })
        .expect_err("host transaction cannot replace initrd transaction");
        assert!(format!("{error:#}").contains("wrong stage scope"));
        Ok(())
    }

    #[test]
    fn rejects_changed_native_admission_bytes() -> Result<()> {
        let temporary = fixture(RECIPE_SCHEMA_V3)?;
        fs::write(
            temporary
                .path()
                .join("inputs/host-deployment/admission.json"),
            b"{}",
        )?;
        capture_unsigned_assembly(temporary.path(), "release-2026.9.0", |_| {
            Ok(format!("sha256:{}", "a".repeat(64)))
        })
        .expect_err("admission bytes must match authenticated digest");
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

        let temporary = fixture(RECIPE_SCHEMA_V3)?;
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
