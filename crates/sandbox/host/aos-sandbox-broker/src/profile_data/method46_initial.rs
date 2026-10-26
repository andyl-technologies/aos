//! Defines bounded image-profile DATA for the two manual initial-floor services.
//!
//! The image-built JSON has one strict grammar:
//!
//! ```text
//! AOS_METHOD46_INITIAL_STARTUP_3: fixed unit/subject + executable/PID1/loader
//! pins + sorted runtime pins/closure roots + canonical/source/effective policy
//! pins + normalized unit SHA256 + normal-owner unit/image pins + Controller UID/GID
//! + approval public key
//! ```
//!
//! Parsing and shape comparison authenticate no source, current process, image,
//! journal, TPM or key independence. The genuine caller pays decoding first and
//! retains both raw bytes and the actual serde Result. It must separately join
//! these claims to its original source and native image/credential observations.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::receiving::Method46InitialServiceRoleV1;

use super::runtime_deployment::deserialize_bounded_profile_sequence_v1;
use super::schema::{ImagePinV1, MAXIMUM_PROFILE_BYTES, MAXIMUM_RUNTIME_FILES, require_store_path};

pub mod normal_image;

/// Refuses malformed or foreign initial-producer profile comparison DATA.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("initial METHOD46 image-profile DATA differs")]
pub struct Method46InitialProfileDataErrorV3;

/// Describes the selected manual producer image without admitting an invocation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Method46InitialProfileDataV3 {
    /// Names the exact AOS_METHOD46_INITIAL_STARTUP_3 grammar.
    pub format: String,
    /// Names the fixed Controller or Storage initial-floor unit.
    pub unit: String,
    /// Names that purpose's fixed SELinux process subject.
    pub owner_context: String,
    /// Pins the actual purpose-specific executable.
    pub executable: ImagePinV1,
    /// Pins the selected manager executable.
    pub pid1: ImagePinV1,
    /// Pins the selected native executable loader.
    pub loader: ImagePinV1,
    /// Lists the bounded, strictly sorted runtime-file pins.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub runtime_files: Vec<ImagePinV1>,
    /// Lists the bounded, strictly sorted canonical package roots.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub closure_roots: Vec<String>,
    /// Pins the selected kernel's canonical immutable MAC policy readback.
    pub canonical_policy: ImagePinV1,
    /// Pins the immutable source policy beside this profile.
    pub source_policy: ImagePinV1,
    /// Pins the immutable effective-policy checker output beside this profile.
    pub effective_matrix: ImagePinV1,
    /// Commits the actual unit with only its profile pathname normalized.
    pub unit_sha256: [u8; 32],
    /// Pins the immutable fragment of this purpose's normal stopped owner.
    ///
    /// This pin commits unit bytes. Native PID1 configuration, selected images,
    /// credential provenance and interval currentness require separate checks.
    pub normal_unit_fragment: ImagePinV1,
    /// Pins the selected stopped owner's configured command and runtime files.
    pub normal_image: normal_image::Method46NormalImageDataV1,
    /// Names the configured Controller journal owner, never the root producer.
    pub controller_uid: u32,
    /// Names the configured Controller group for later native comparisons.
    pub controller_gid: u32,
    /// Pins the public independent approval key for this manual purpose.
    ///
    /// Shape validation rejects weak keys. Independence from endpoint, Nix and
    /// Root keys remains a separately required actual authority comparison.
    pub approval_public_key: [u8; 32],
}

impl Method46InitialProfileDataV3 {
    /// Compares bounded canonical shape with the caller's actual source role.
    ///
    /// The role itself is DATA; only the authenticating startup owner can join
    /// it to the original captured invocation. This check performs no IO and
    /// issues no image, key, writer, provisioning or readiness authority.
    ///
    /// # Errors
    /// Rejects a foreign format/unit/subject/executable, sentinel identity or
    /// digest, weak key, malformed policy path, noncanonical bounded inventory,
    /// missing executable/loader pin or runtime outside the declared roots.
    pub fn require_shape_data_v3(
        &self,
        role: Method46InitialServiceRoleV1,
    ) -> Result<(), Method46InitialProfileDataErrorV3> {
        let (unit, context, executable, normal_unit) = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => (
                "aos-sandbox-controller-floor-initialize.service",
                "system_u:system_r:aos_method46_controller_initial_t",
                "/bin/aos-sandbox-controller-floor-initialize",
                "/aos-sandboxd.service",
            ),
            Method46InitialServiceRoleV1::StorageBroker => (
                "aos-sandbox-storage-floor-initialize.service",
                "system_u:system_r:aos_method46_storage_initial_t",
                "/bin/aos-sandbox-storage-floor-initialize",
                "/aos-storaged.service",
            ),
        };
        if self.format != "AOS_METHOD46_INITIAL_STARTUP_3"
            || self.unit != unit
            || self.owner_context != context
            || !self.executable.path.ends_with(executable)
            || !self.pid1.path.ends_with("/lib/systemd/systemd")
            || !self.normal_unit_fragment.path.ends_with(normal_unit)
            || self.normal_unit_fragment.path.len() > 1024
            || self.unit_sha256 == [0; 32]
            || self.controller_uid == 0
            || self.controller_gid == 0
            || self.runtime_files.is_empty()
            || self.runtime_files.len() > MAXIMUM_RUNTIME_FILES
            || self.closure_roots.is_empty()
            || self.closure_roots.len() > MAXIMUM_RUNTIME_FILES
            || self
                .runtime_files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
            || self.closure_roots.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Method46InitialProfileDataErrorV3);
        }
        let approval = VerifyingKey::from_bytes(&self.approval_public_key)
            .map_err(|_| Method46InitialProfileDataErrorV3)?;
        if approval.is_weak() {
            return Err(Method46InitialProfileDataErrorV3);
        }
        self.normal_image.require_shape_data_v1(role)?;

        for root in &self.closure_roots {
            require_store_path(root).map_err(|_| Method46InitialProfileDataErrorV3)?;
            if Path::new(root).components().count() != 4 {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        for pin in self.runtime_files.iter().chain([
            &self.executable,
            &self.pid1,
            &self.loader,
            &self.canonical_policy,
            &self.source_policy,
            &self.effective_matrix,
            &self.normal_unit_fragment,
        ]) {
            require_store_path(&pin.path).map_err(|_| Method46InitialProfileDataErrorV3)?;
            if pin.sha256 == [0; 32] {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        for member in &self.runtime_files {
            if !self.closure_roots.iter().any(|root| {
                Path::new(&member.path)
                    .strip_prefix(root)
                    .is_ok_and(|suffix| suffix.components().count() > 0)
            }) {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        for required in [&self.executable, &self.loader] {
            if !self
                .runtime_files
                .iter()
                .any(|member| member.path == required.path && member.sha256 == required.sha256)
            {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        if !self
            .canonical_policy
            .path
            .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !self
                .source_policy
                .path
                .ends_with("-aos-method46-initial-startup-profile-3/source-policy.33")
            || !self
                .effective_matrix
                .path
                .ends_with("-aos-method46-initial-startup-profile-3/effective-policy.tsv")
            || Path::new(&self.source_policy.path).parent()
                != Path::new(&self.effective_matrix.path).parent()
        {
            return Err(Method46InitialProfileDataErrorV3);
        }
        Ok(())
    }
}

/// Quotes retained and transient decoding storage before parsing bounded bytes.
///
/// This comparison DATA pays nothing by itself. The genuine source separately
/// prices raw acquisition, native file/image reads and unit normalization. Two
/// compiled models and vector carriers, four encoded string extents and bounded
/// key-comparison scratch cover this strict schema's decoding and shape checks.
#[must_use]
pub fn method46_initial_profile_representation_bytes_v3(encoded_bytes: usize) -> Option<usize> {
    if encoded_bytes == 0 || encoded_bytes > MAXIMUM_PROFILE_BYTES {
        return None;
    }
    // Both inventories, both root lists and the bounded argv can coexist in
    // each decoded model. Encoded extents below separately cover string bytes.
    let carriers = MAXIMUM_RUNTIME_FILES.checked_mul(
        std::mem::size_of::<ImagePinV1>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<String>().checked_mul(3)?)?,
    )?;
    std::mem::size_of::<Method46InitialProfileDataV3>()
        .checked_mul(2)?
        .checked_add(carriers.checked_mul(2)?)?
        .checked_add(encoded_bytes.checked_mul(4)?)?
        .checked_add(4096)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn fixture(role: Method46InitialServiceRoleV1) -> Value {
        let (stem, subject) = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => (
                "aos-sandbox-controller-floor-initialize",
                "aos_method46_controller_initial_t",
            ),
            Method46InitialServiceRoleV1::StorageBroker => (
                "aos-sandbox-storage-floor-initialize",
                "aos_method46_storage_initial_t",
            ),
        };
        let package = "/nix/store/00000000000000000000000000000000-aos-sandbox-services-0.1.0";
        let profile =
            "/nix/store/11111111111111111111111111111111-aos-method46-initial-startup-profile-3";
        let executable = json!({"path": format!("{package}/bin/{stem}"), "sha256": ([1_u8; 32])});
        let loader = json!({"path": format!("{package}/lib/ld.so"), "sha256": ([2_u8; 32])});
        json!({
            "format": "AOS_METHOD46_INITIAL_STARTUP_3",
            "unit": format!("{stem}.service"),
            "owner_context": format!("system_u:system_r:{subject}"),
            "executable": executable,
            "pid1": {"path": "/nix/store/22222222222222222222222222222222-systemd-261.2/lib/systemd/systemd", "sha256": ([3_u8; 32])},
            "loader": loader,
            "runtime_files": [executable, loader],
            "closure_roots": [package],
            "canonical_policy": {"path": "/nix/store/33333333333333333333333333333333-aos-selinux-kernel-policy-readback-1/policy.33", "sha256": ([4_u8; 32])},
            "source_policy": {"path": format!("{profile}/source-policy.33"), "sha256": ([5_u8; 32])},
            "effective_matrix": {"path": format!("{profile}/effective-policy.tsv"), "sha256": ([6_u8; 32])},
            "unit_sha256": ([7_u8; 32]),
            "normal_unit_fragment": {
                "path": format!("/nix/store/66666666666666666666666666666666-system-units/{}", match role {
                    Method46InitialServiceRoleV1::ControllerStorageClient => "aos-sandboxd.service",
                    Method46InitialServiceRoleV1::StorageBroker => "aos-storaged.service",
                }),
                "sha256": ([9_u8; 32]),
            },
            "normal_image": normal_image::test_fixture(role),
            "controller_uid": 913,
            "controller_gid": 913,
            "approval_public_key": ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        })
    }

    fn decode(value: Value) -> Method46InitialProfileDataV3 {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn each_fixed_purpose_rejects_the_other_complete_profile() {
        let controller = decode(fixture(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        let storage = decode(fixture(Method46InitialServiceRoleV1::StorageBroker));

        assert!(
            controller
                .require_shape_data_v3(Method46InitialServiceRoleV1::ControllerStorageClient)
                .is_ok()
        );
        assert!(
            storage
                .require_shape_data_v3(Method46InitialServiceRoleV1::StorageBroker)
                .is_ok()
        );
        assert!(
            controller
                .require_shape_data_v3(Method46InitialServiceRoleV1::StorageBroker)
                .is_err()
        );
        assert!(
            storage
                .require_shape_data_v3(Method46InitialServiceRoleV1::ControllerStorageClient)
                .is_err()
        );
    }

    #[test]
    fn selected_runtime_and_policy_bindings_reject_substitution() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let mut wrong_loader = decode(fixture(role));
        wrong_loader.loader.sha256 = [9; 32];
        let mut foreign_member = decode(fixture(role));
        foreign_member.runtime_files[1].path =
            "/nix/store/44444444444444444444444444444444-foreign/lib/ld.so".into();
        let mut repeated_member = decode(fixture(role));
        repeated_member.runtime_files[1].path = repeated_member.runtime_files[0].path.clone();
        let mut foreign_policy = decode(fixture(role));
        foreign_policy.effective_matrix.path = "/nix/store/55555555555555555555555555555555-aos-method46-initial-startup-profile-3/effective-policy.tsv".into();

        for changed in [
            wrong_loader,
            foreign_member,
            repeated_member,
            foreign_policy,
        ] {
            assert!(changed.require_shape_data_v3(role).is_err());
        }
    }

    #[test]
    fn weak_key_and_root_controller_identity_are_not_valid_shape() {
        let role = Method46InitialServiceRoleV1::ControllerStorageClient;
        let mut weak_key = decode(fixture(role));
        weak_key.approval_public_key = [0; 32];
        let mut root_owner = decode(fixture(role));
        root_owner.controller_uid = 0;

        assert!(weak_key.require_shape_data_v3(role).is_err());
        assert!(root_owner.require_shape_data_v3(role).is_err());
    }

    #[test]
    fn normal_fragment_requires_the_selected_immutable_role_and_new_wire_version() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        for path in [
            "/etc/systemd/system/aos-storaged.service",
            "/nix/store/66666666666666666666666666666666-system-units/aos-sandboxd.service",
        ] {
            let mut value = fixture(role);
            value["normal_unit_fragment"]["path"] = json!(path);
            assert!(decode(value).require_shape_data_v3(role).is_err());
        }

        let mut missing = fixture(role);
        missing
            .as_object_mut()
            .unwrap()
            .remove("normal_unit_fragment");
        assert!(serde_json::from_value::<Method46InitialProfileDataV3>(missing).is_err());

        for format in [
            "AOS_METHOD46_INITIAL_STARTUP_1",
            "AOS_METHOD46_INITIAL_STARTUP_2",
        ] {
            let mut old = fixture(role);
            old["format"] = json!(format);
            assert!(decode(old).require_shape_data_v3(role).is_err());
        }

        let mut zero = fixture(role);
        zero["normal_unit_fragment"]["sha256"] = json!(([0_u8; 32]));
        assert!(decode(zero).require_shape_data_v3(role).is_err());
    }

    #[test]
    fn strict_decoder_rejects_unknown_duplicate_and_excess_sequence_fields() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let mut unknown = fixture(role);
        unknown["owner_auth"] = json!("forbidden");
        assert!(serde_json::from_value::<Method46InitialProfileDataV3>(unknown).is_err());

        let encoded = serde_json::to_string(&fixture(role)).unwrap();
        let duplicate = encoded.replacen('{', "{\"format\":\"AOS_METHOD46_INITIAL_STARTUP_3\",", 1);
        assert!(serde_json::from_str::<Method46InitialProfileDataV3>(&duplicate).is_err());

        let mut excessive = fixture(role);
        let mut roots = vec![
            json!("/nix/store/00000000000000000000000000000000-package");
            MAXIMUM_RUNTIME_FILES
        ];
        roots.push(json!(17));
        excessive["closure_roots"] = json!(roots);
        let error = serde_json::from_value::<Method46InitialProfileDataV3>(excessive)
            .err()
            .unwrap();
        assert!(error.to_string().contains("exceeds512"));
        assert!(!error.to_string().contains("expected a string"));
    }
}
