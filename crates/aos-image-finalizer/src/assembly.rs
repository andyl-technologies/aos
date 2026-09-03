//! Closed unsigned-image assembly manifest.
//!
//! ```json
//! {"schema_version":"aos.image.unsigned-assembly/v1",
//!  "platform":"x86_64-linux","system_variant":"production",
//!  "files":[{"id":"kernel","kind":"kernel","path":"inputs/kernel.nar",
//!  "size_bytes":1,"sha256":"sha256:..."}]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_release::artifact::{BundlePath, require_identifier, require_store_path};
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use serde::{Deserialize, Serialize};

/// Schema for deterministic public-only image inputs.
pub const UNSIGNED_IMAGE_ASSEMBLY_V1: &str = "aos.image.unsigned-assembly/v1";

/// Required deterministic input or public trust artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyFileKind {
    /// Linux kernel output, including its embedded module authority.
    Kernel,
    /// Unsigned normal initrd input.
    Initrd,
    /// Unsigned immutable root filesystem input.
    RootFilesystem,
    /// Deterministic dm-verity hash tree for the unsigned root.
    VerityTree,
    /// ASCII dm-verity root hash for the unsigned root.
    VerityRootHash,
    /// Unsigned systemd-boot PE input.
    Bootloader,
    /// sd-stub PE input used to construct normal and recovery UKIs.
    UkiStub,
    /// Normal UKI os-release section.
    OsRelease,
    /// Recovery slot-A initrd template excluding release-time signatures.
    RecoveryInitrdA,
    /// Recovery slot-B initrd template excluding release-time signatures.
    RecoveryInitrdB,
    /// Recovery slot-A UKI os-release section.
    RecoveryOsReleaseA,
    /// Recovery slot-B UKI os-release section.
    RecoveryOsReleaseB,
    /// Public Secure Boot db certificate.
    SecureBootCertificate,
    /// Public kernel-module X.509 certificate.
    ModuleCertificate,
    /// Public PCR-policy verification key.
    PcrPublicKey,
    /// Public firmware enrollment artifacts.
    FirmwareEnrollment,
}

/// One exact regular file in the captured assembly directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyFileV1 {
    /// Stable input identity.
    pub id: String,
    /// Closed input purpose.
    pub kind: AssemblyFileKind,
    /// Relative regular-file path beneath the assembly root.
    pub path: BundlePath,
    /// Exact file length.
    pub size_bytes: u64,
    /// SHA-256 of exact input bytes.
    pub sha256: Sha256Digest,
}

/// One exact AOS-built executable the external finalizer may invoke.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyToolV1 {
    /// Closed tool purpose, such as `ukify` or `qemu-img`.
    pub id: String,
    /// Exact executable path in the Nix store.
    pub executable: String,
    /// NAR hash of the executable's owning output.
    pub owner_nar_hash: String,
    /// Closed public process environment required by this AOS-built tool.
    pub environment: BTreeMap<String, String>,
}

/// Complete public-only finalization input for one Linux architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedImageAssemblyV1 {
    /// Exact schema identifier.
    pub schema_version: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Release version embedded in image metadata.
    pub version: String,
    /// Exact Linux target.
    pub platform: Platform,
    /// Public system variant.
    pub system_variant: String,
    /// Exact kernel release used for module signatures.
    pub kernel_release: String,
    /// Monotonic AOS module ABI.
    pub module_abi: u64,
    /// Recovery environment compatibility ABI.
    pub recovery_abi: u64,
    /// Monotonic SBAT generation.
    pub sbat_generation: u64,
    /// Exact normal and recovery kernel command lines.
    pub command_lines: ImageCommandLinesV1,
    /// External role assigned to each image signing purpose.
    pub signer_roles: ImageSignerRolesV1,
    /// Deterministic disk, partition, and ESP layout.
    pub layout: ImageLayoutV1,
    /// Fail-closed maximum artifact sizes.
    pub budgets: ImageBudgetsV1,
    /// Sorted exact assembly files.
    pub files: Vec<AssemblyFileV1>,
    /// Sorted exact AOS-built tools.
    pub tools: Vec<AssemblyToolV1>,
}

/// Exact command lines embedded in the finalized UKIs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageCommandLinesV1 {
    /// Slot-A normal boot command line.
    pub slot_a: String,
    /// Slot-B normal boot command line.
    pub slot_b: String,
    /// Recovery boot command line shared by both recovery UKIs.
    pub recovery: String,
}

/// Release signer roles used by the image finalizer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSignerRolesV1 {
    /// Authenticode and recovery-manifest signing role.
    pub secure_boot: String,
    /// Kernel-module signing role.
    pub module: String,
    /// TPM PCR-policy signing role.
    pub pcr: String,
}

/// Deterministic GPT and EFI layout needed for final-byte construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageLayoutV1 {
    /// Logical sector size used by the GPT image.
    pub sector_size: u64,
    /// Partition alignment in logical sectors.
    pub alignment_sectors: u64,
    /// First ESP sector.
    pub esp_start_sector: u64,
    /// Fixed ESP capacity in MiB.
    pub esp_size_mib: u64,
    /// Fixed capacity of each immutable root slot in MiB.
    pub root_partition_mib: u64,
    /// Fixed capacity of each dm-verity slot in MiB.
    pub verity_partition_mib: u64,
    /// Closed root filesystem format.
    pub root_filesystem_type: String,
    /// Deterministic immutable-root filesystem UUID.
    pub root_filesystem_uuid: String,
    /// Immutable-root filesystem label.
    pub root_filesystem_label: String,
    /// Zstandard compression level used when rebuilding EROFS.
    pub erofs_compression_level: u8,
    /// Deterministic dm-verity superblock UUID.
    pub verity_uuid: String,
    /// Deterministic lowercase hexadecimal dm-verity salt.
    pub verity_salt: String,
    /// Additional ESP headroom beyond the transactional calculation.
    pub esp_extra_free_mib: u64,
    /// Deterministic GPT disk GUID.
    pub disk_guid: String,
    /// Architecture-specific GPT partition type GUIDs.
    pub partition_type_guids: PartitionTypeGuidsV1,
    /// Deterministic unique partition GUIDs.
    pub partition_guids: PartitionGuidsV1,
    /// Deterministic FAT volume id as eight uppercase hexadecimal digits.
    pub fat_volume_id: String,
    /// Architecture-specific final EFI filenames.
    pub efi_filenames: EfiFilenamesV1,
}

/// GPT partition type identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionTypeGuidsV1 {
    /// EFI System Partition type GUID.
    pub esp: String,
    /// Discoverable Partitions Specification root type GUID.
    pub root: String,
    /// Discoverable Partitions Specification verity type GUID.
    pub verity: String,
}

/// GPT unique partition identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionGuidsV1 {
    /// ESP partition GUID.
    pub esp: String,
    /// Slot-A root partition GUID.
    pub root_a: String,
    /// Slot-A verity partition GUID.
    pub root_a_hash: String,
    /// Slot-B root partition GUID.
    pub root_b: String,
    /// Slot-B verity partition GUID.
    pub root_b_hash: String,
}

/// EFI artifact filenames installed into the ESP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfiFilenamesV1 {
    /// Removable-media fallback bootloader filename.
    pub fallback: String,
    /// Architecture-specific systemd-boot filename.
    pub systemd_boot: String,
    /// Boot-counted normal UKI filename.
    pub normal_uki: String,
}

/// Artifact ceilings enforced during finalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageBudgetsV1 {
    /// Maximum rebuilt immutable root size in MiB.
    pub root_mib: u64,
    /// Maximum normal or recovery initrd size in MiB.
    pub initrd_mib: u64,
    /// Maximum finalized UKI size in MiB.
    pub uki_mib: u64,
    /// Maximum size of each downloadable encoding in MiB.
    pub download_mib: u64,
}

impl UnsignedImageAssemblyV1 {
    /// Validates the complete unsigned finalization boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong schema or platform, malformed identity,
    /// missing/duplicate/reordered input kinds, invalid paths or byte facts,
    /// or an unpinned/non-store assembly tool.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UNSIGNED_IMAGE_ASSEMBLY_V1 || !self.platform.supports_images() {
            bail!("unsigned image assembly requires the v1 schema and a Linux platform");
        }
        for (value, label) in [
            (&self.release_id, "release id"),
            (&self.system_variant, "system variant"),
            (&self.kernel_release, "kernel release"),
        ] {
            require_identifier(value, label)?;
        }
        self.layout.validate()?;
        if [
            self.budgets.root_mib,
            self.budgets.initrd_mib,
            self.budgets.uki_mib,
            self.budgets.download_mib,
        ]
        .contains(&0)
        {
            bail!("image artifact budgets must be nonzero");
        }
        if self.version.is_empty()
            || self.module_abi == 0
            || self.recovery_abi == 0
            || self.sbat_generation == 0
        {
            bail!("unsigned image assembly has an invalid version or monotonic generation");
        }
        for (value, label) in [
            (&self.command_lines.slot_a, "slot-A command line"),
            (&self.command_lines.slot_b, "slot-B command line"),
            (&self.command_lines.recovery, "recovery command line"),
            (&self.signer_roles.secure_boot, "Secure Boot signer role"),
            (&self.signer_roles.module, "module signer role"),
            (&self.signer_roles.pcr, "PCR signer role"),
        ] {
            if value.is_empty() {
                bail!("unsigned image assembly has an empty {label}");
            }
        }
        if self.files.is_empty()
            || self.files.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self.tools.is_empty()
            || self.tools.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            bail!("assembly files and tools must be nonempty, unique, and sorted");
        }
        let mut paths = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        for file in &self.files {
            require_identifier(&file.id, "assembly file id")?;
            if file.size_bytes == 0 || !paths.insert(file.path.as_str()) || !kinds.insert(file.kind)
            {
                bail!("assembly contains an empty or duplicate file or kind");
            }
        }
        for required in [
            AssemblyFileKind::Kernel,
            AssemblyFileKind::Initrd,
            AssemblyFileKind::RootFilesystem,
            AssemblyFileKind::VerityTree,
            AssemblyFileKind::VerityRootHash,
            AssemblyFileKind::Bootloader,
            AssemblyFileKind::UkiStub,
            AssemblyFileKind::OsRelease,
            AssemblyFileKind::RecoveryInitrdA,
            AssemblyFileKind::RecoveryInitrdB,
            AssemblyFileKind::RecoveryOsReleaseA,
            AssemblyFileKind::RecoveryOsReleaseB,
            AssemblyFileKind::SecureBootCertificate,
            AssemblyFileKind::ModuleCertificate,
            AssemblyFileKind::PcrPublicKey,
            AssemblyFileKind::FirmwareEnrollment,
        ] {
            if !kinds.contains(&required) {
                bail!("unsigned image assembly lacks required {required:?} input");
            }
        }
        for tool in &self.tools {
            require_identifier(&tool.id, "assembly tool id")?;
            require_store_path(&tool.executable, false)?;
            if !tool.executable.contains("/bin/") && !tool.executable.contains("/lib/") {
                bail!("assembly tool must identify an executable below a store output");
            }
            if !(tool.owner_nar_hash.starts_with("sha256:")
                || tool.owner_nar_hash.starts_with("sha256-"))
            {
                bail!("assembly tool lacks a pinned owner NAR hash");
            }
            for (name, value) in &tool.environment {
                match name.as_str() {
                    "LD_LIBRARY_PATH" => {
                        if value.split(':').any(|path| {
                            !path.starts_with("/nix/store/")
                                || path.contains('\n')
                                || path.contains('\0')
                        }) {
                            bail!("assembly tool LD_LIBRARY_PATH must contain only store paths");
                        }
                    }
                    "MTOOLS_SKIP_CHECK" if value == "1" => {}
                    _ => bail!("assembly tool requests an unsupported environment setting"),
                }
            }
        }
        self.validate_input_budgets()?;
        Ok(())
    }

    fn validate_input_budgets(&self) -> Result<()> {
        let mebibytes = |value: u64| {
            value
                .checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow::anyhow!("image budget overflows bytes"))
        };
        for file in &self.files {
            let maximum = match file.kind {
                AssemblyFileKind::RootFilesystem => Some(mebibytes(self.budgets.root_mib)?),
                AssemblyFileKind::Initrd
                | AssemblyFileKind::RecoveryInitrdA
                | AssemblyFileKind::RecoveryInitrdB => Some(mebibytes(self.budgets.initrd_mib)?),
                AssemblyFileKind::VerityTree => Some(mebibytes(self.layout.verity_partition_mib)?),
                _ => None,
            };
            if maximum.is_some_and(|maximum| file.size_bytes > maximum) {
                bail!(
                    "unsigned image input {} exceeds its release budget",
                    file.id
                );
            }
        }
        Ok(())
    }
}

impl ImageLayoutV1 {
    fn validate(&self) -> Result<()> {
        if self.sector_size != 512
            || self.alignment_sectors == 0
            || self.esp_start_sector != self.alignment_sectors
            || self.esp_size_mib < 128
            || self.root_partition_mib == 0
            || self.verity_partition_mib == 0
            || self.root_filesystem_type != "erofs"
            || self.erofs_compression_level == 0
            || self.erofs_compression_level > 22
        {
            bail!("image layout violates the production geometry contract");
        }
        require_identifier(&self.root_filesystem_label, "root filesystem label")?;
        for guid in [
            &self.root_filesystem_uuid,
            &self.verity_uuid,
            &self.disk_guid,
            &self.partition_type_guids.esp,
            &self.partition_type_guids.root,
            &self.partition_type_guids.verity,
            &self.partition_guids.esp,
            &self.partition_guids.root_a,
            &self.partition_guids.root_a_hash,
            &self.partition_guids.root_b,
            &self.partition_guids.root_b_hash,
        ] {
            require_guid(guid)?;
        }
        if self.fat_volume_id.len() != 8
            || !self
                .fat_volume_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        {
            bail!("FAT volume id must be eight uppercase hexadecimal digits");
        }
        if self.verity_salt.len() != 64
            || !self
                .verity_salt
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("dm-verity salt must be 64 lowercase hexadecimal digits");
        }
        for filename in [
            &self.efi_filenames.fallback,
            &self.efi_filenames.systemd_boot,
            &self.efi_filenames.normal_uki,
        ] {
            if filename.is_empty()
                || filename.contains('/')
                || filename.contains('\\')
                || filename == "."
                || filename == ".."
            {
                bail!("EFI filename is not one safe path component");
            }
        }
        Ok(())
    }
}

fn require_guid(value: &str) -> Result<()> {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
        || !value
            .bytes()
            .filter(|byte| *byte != b'-')
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("image layout contains a malformed GUID");
    }
    Ok(())
}
