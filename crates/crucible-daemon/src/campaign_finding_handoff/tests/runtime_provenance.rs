//! Installed replay provenance refusals before private guest materialization.

// crucible-lint: allow panic-shortcut -- fixture setup and exact provenance refusals fail at their source.
#![allow(clippy::expect_used)]

use super::*;
use crate::finding_production_replay::{
    FindingProductionReplayGuestAssets, FindingProductionReplayRuntimeIdentity,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Debug, PartialEq, Eq)]
struct RetainedPath {
    device: u64,
    inode: u64,
    mode: u32,
    bytes: Vec<u8>,
}

struct RuntimeFixture {
    directory: tempfile::TempDir,
    qemu: PathBuf,
    plugin: PathBuf,
    qemu_fields: BTreeMap<&'static str, String>,
    plugin_fields: BTreeMap<&'static str, String>,
    assets: PathBuf,
    blocked_parent: PathBuf,
}

impl RuntimeFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("runtime fixture");
        let qemu = directory.path().join("qemu");
        let plugin = directory.path().join("plugin");
        let assets = directory.path().join("assets");
        let blocked_parent = directory.path().join("other-owner-file");
        fs::write(&qemu, b"unexecuted QEMU fixture").expect("QEMU fixture");
        fs::write(&plugin, b"unloaded plugin fixture").expect("plugin fixture");
        fs::write(&blocked_parent, b"other owner").expect("unrelated owner file");
        fs::create_dir(&assets).expect("private asset parent");
        fs::set_permissions(&assets, fs::Permissions::from_mode(0o700))
            .expect("owner-only materialization parent");
        let version = crucible::SHMEM_ABI_VERSION.to_string();
        let abi = format!("crucible-shmem-abi-v{version}");
        let qemu_fields = BTreeMap::from([
            ("qemu_sim_capability", String::from("qemu-crucible")),
            ("qemu_crucible_atomic_patch_applied", String::from("true")),
            ("qemu_plugins_enabled", String::from("true")),
            ("qemu_build_id", String::from("replay-fixture-build")),
            (
                "qemu_atomic_patch_hash",
                String::from("sha256:fixture-patch"),
            ),
            ("qemu_shmem_abi_version", version.clone()),
            ("qemu_shmem_abi", abi.clone()),
            ("qemu_shmem_header", String::from("crucible_shmem_abi.h")),
            (
                "qemu_shmem_header_hash",
                String::from("sha256:fixture-header"),
            ),
        ]);
        let plugin_fields = BTreeMap::from([
            ("plugin_abi", abi.clone()),
            ("qemu_build_id", String::from("replay-fixture-build")),
            ("shmem_abi_version", version),
            ("shmem_abi", abi),
            (
                "shmem_generated_header_hash",
                String::from("sha256:fixture-header"),
            ),
        ]);
        let fixture = Self {
            directory,
            qemu,
            plugin,
            qemu_fields,
            plugin_fields,
            assets,
            blocked_parent,
        };
        fixture.write_markers();
        fixture
    }

    fn write_markers(&self) {
        for (name, fields) in [
            ("qemu-build-identity.env", &self.qemu_fields),
            ("crucible-qemu-plugin-build-info", &self.plugin_fields),
        ] {
            let text = fields
                .iter()
                .map(|(key, value)| format!("{key}={value}\n"))
                .collect::<String>();
            fs::write(self.directory.path().join(name), text).expect("installed marker");
        }
    }

    fn deployment(&self) -> FindingProductionReplayDeployment {
        let identity = QemuLaunchArtifactIdentity::authenticate(&self.qemu, &self.plugin)
            .expect("authenticate fixture markers");
        let runtime = FindingProductionReplayRuntimeIdentity::new(
            identity.qemu_build_id(),
            identity.qemu_atomic_patch_hash(),
            identity.plugin_abi(),
            identity.shmem_abi_version(),
        )
        .expect("capture installed requirements");
        FindingProductionReplayDeployment::new(
            runtime,
            FindingProductionReplayRootImageFormat::Raw,
            vec![FindingProductionReplayGuestAssets::new(
                VmArchitecture::X86_64,
                FindingProductionReplayAsset::from_bytes(b"kernel".to_vec()),
                FindingProductionReplayAsset::from_bytes(b"root".to_vec()),
                Some(String::from("console=ttyS0")),
            )],
            Some(FindingProductionReplayAsset::from_bytes(b"initrd".to_vec())),
        )
    }

    fn materialize(
        &self,
        deployment: &FindingProductionReplayDeployment,
        parent: &Path,
    ) -> Result<MaterializedFindingReplayGuestAssets, CampaignFindingHandoffError> {
        materialize_finding_replay_guest_assets(deployment, &self.qemu, &self.plugin, parent)
    }

    // This is an inventory of only fixture-owned paths, not a host process or temp scan.
    fn inventory(&self) -> BTreeMap<PathBuf, RetainedPath> {
        let mut paths = fs::read_dir(self.directory.path())
            .expect("fixture root inventory")
            .map(|entry| entry.expect("fixture entry").path())
            .collect::<Vec<_>>();
        for owner in fs::read_dir(&self.assets).expect("asset owners") {
            let owner = owner.expect("owner entry").path();
            paths.push(owner.clone());
            for file in fs::read_dir(owner).expect("owner files") {
                paths.push(file.expect("asset entry").path());
            }
        }
        paths
            .into_iter()
            .map(|path| {
                let metadata = fs::metadata(&path).expect("fixture metadata");
                let bytes = if metadata.is_file() {
                    fs::read(&path).expect("fixture bytes")
                } else {
                    Vec::new()
                };
                (
                    path,
                    RetainedPath {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        mode: metadata.mode(),
                        bytes,
                    },
                )
            })
            .collect()
    }
}

#[test]
fn each_constructible_captured_runtime_mismatch_refuses_before_private_file_creation() {
    for field in 0..3 {
        let fixture = RuntimeFixture::new();
        let valid = fixture.deployment();
        let owner = fixture
            .materialize(&valid, &fixture.assets)
            .expect("other replay owner");
        let installed = valid.runtime();
        let mut fields = [
            installed.qemu_build_id().to_owned(),
            installed.qemu_atomic_patch_hash().to_owned(),
            installed.plugin_abi().to_owned(),
            installed.shmem_abi_version().to_owned(),
        ];
        fields[field].push_str("-different");
        let required = FindingProductionReplayRuntimeIdentity::new(
            fields[0].clone(),
            fields[1].clone(),
            fields[2].clone(),
            fields[3].clone(),
        )
        .expect("bounded mismatched identity");
        let deployment = FindingProductionReplayDeployment::new(
            required,
            valid.root_image_format(),
            valid.guest_assets().to_vec(),
            valid.initrd().cloned(),
        );
        let before = fixture.inventory();

        for parent in [&fixture.assets, &fixture.blocked_parent] {
            assert!(
                matches!(
                    fixture.materialize(&deployment, parent),
                    Err(CampaignFindingHandoffError::RuntimeIdentityMismatch)
                ),
                "captured field {field}"
            );
            assert_eq!(fixture.inventory(), before);
        }
        assert!(owner.directory().is_dir());
    }
}

#[test]
fn installed_required_fields_missing_or_empty_preserve_original_authentication_errors() {
    for (plugin, field) in [
        (false, "qemu_build_id"),
        (false, "qemu_atomic_patch_hash"),
        (true, "plugin_abi"),
        (true, "shmem_abi_version"),
    ] {
        for empty in [false, true] {
            let mut fixture = RuntimeFixture::new();
            let deployment = fixture.deployment();
            let owner = fixture
                .materialize(&deployment, &fixture.assets)
                .expect("other owner");
            let fields = if plugin {
                &mut fixture.plugin_fields
            } else {
                &mut fixture.qemu_fields
            };
            if empty {
                fields.insert(field, String::new());
            } else {
                fields.remove(field);
            }
            fixture.write_markers();
            let before = fixture.inventory();
            let marker = fixture.directory.path().join(if plugin {
                "crucible-qemu-plugin-build-info"
            } else {
                "qemu-build-identity.env"
            });

            for parent in [&fixture.assets, &fixture.blocked_parent] {
                assert!(matches!(
                    fixture.materialize(&deployment, parent),
                    Err(CampaignFindingHandoffError::RuntimeAuthentication(
                        QemuLaunchArtifactIdentityError::MissingField { path, field: actual }
                    )) if path == marker && actual == field
                ));
                assert_eq!(fixture.inventory(), before);
            }
            assert!(owner.directory().is_dir());
        }
    }
}

#[test]
fn unsupported_installed_capability_and_abi_refuse_before_materialization() {
    for unsupported_abi in [false, true] {
        let mut fixture = RuntimeFixture::new();
        let deployment = fixture.deployment();
        let owner = fixture
            .materialize(&deployment, &fixture.assets)
            .expect("other owner");
        if unsupported_abi {
            let version = (crucible::SHMEM_ABI_VERSION + 1).to_string();
            fixture
                .qemu_fields
                .insert("qemu_shmem_abi_version", version.clone());
            fixture.plugin_fields.insert("shmem_abi_version", version);
        } else {
            fixture
                .qemu_fields
                .insert("qemu_sim_capability", String::from("unpatched"));
        }
        fixture.write_markers();
        let before = fixture.inventory();

        for parent in [&fixture.assets, &fixture.blocked_parent] {
            let error = fixture
                .materialize(&deployment, parent)
                .expect_err("unsupported runtime");
            if unsupported_abi {
                assert!(matches!(
                    error,
                    CampaignFindingHandoffError::RuntimeAuthentication(
                        QemuLaunchArtifactIdentityError::Mismatch {
                            field: "QEMU shmem ABI version"
                        }
                    )
                ));
            } else {
                assert!(
                    matches!(error, CampaignFindingHandoffError::RuntimeAuthentication(
                    QemuLaunchArtifactIdentityError::InvalidField { path, field: "qemu_sim_capability" }
                ) if path == fixture.directory.path().join("qemu-build-identity.env"))
                );
            }
            assert_eq!(fixture.inventory(), before);
        }
        assert!(owner.directory().is_dir());
    }
}

#[test]
fn valid_runtime_materializes_exact_assets_and_drop_preserves_another_owner() {
    let fixture = RuntimeFixture::new();
    let deployment = fixture.deployment();
    let other = fixture
        .materialize(&deployment, &fixture.assets)
        .expect("other owner");
    let before = fixture.inventory();
    let owned = fixture
        .materialize(&deployment, &fixture.assets)
        .expect("valid runtime");
    let directory = owned.directory().to_owned();
    assert_ne!(owned.directory(), other.directory());
    assert_eq!(
        owned.root_image_format(),
        FindingProductionReplayRootImageFormat::Raw
    );
    let guest = &owned.guest_assets()[0];
    assert_eq!(guest.architecture(), VmArchitecture::X86_64);
    assert_eq!(guest.kernel_cmdline_prefix(), Some("console=ttyS0"));
    for (path, bytes) in [
        (guest.kernel(), b"kernel".as_slice()),
        (guest.root_image(), b"root".as_slice()),
        (
            owned.initrd().expect("captured initrd"),
            b"initrd".as_slice(),
        ),
    ] {
        assert_eq!(fs::read(path).expect("materialized bytes"), bytes);
        assert_eq!(
            fs::metadata(path).expect("asset permissions").mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::metadata(&fixture.assets)
            .expect("private parent")
            .mode()
            & 0o777,
        0o700
    );

    drop(owned);
    assert!(!directory.exists());
    assert_eq!(fixture.inventory(), before);
    assert!(other.directory().is_dir());
    assert!(matches!(
        fixture.materialize(&deployment, &fixture.blocked_parent),
        Err(CampaignFindingHandoffError::Io(_))
    ));
    assert_eq!(fixture.inventory(), before);
}

#[test]
fn captured_shmem_version_is_rejected_by_the_public_identity_constructor() {
    let fixture = RuntimeFixture::new();
    let deployment = fixture.deployment();
    let identity = deployment.runtime();
    let before = fixture.inventory();

    // Current captures cannot represent an obsolete shmem ABI; installed
    // incompatibility is separately refused through the materialization helper.
    assert!(matches!(
        FindingProductionReplayRuntimeIdentity::new(
            identity.qemu_build_id(),
            identity.qemu_atomic_patch_hash(),
            identity.plugin_abi(),
            (crucible::SHMEM_ABI_VERSION + 1).to_string(),
        ),
        Err(crate::FindingProductionReplayCaptureError::InvalidRuntimeIdentity)
    ));
    assert_eq!(fixture.inventory(), before);
}
