//! Shares the exact publisher profile schema and normal-purpose DATA comparisons.
//!
//! Raw serde and path/contract checks create no Source, startup, journal, key,
//! generation, completion or service proof. Genuine callers separately retain
//! and pay their actual decoded model, immutable files and native observations.

use std::path::Path;

use aos_sandbox_protocol::runtime_deployment::boot_preparation::SignedBootPreparationPurposeDataV1;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::schema::{ImagePinV1, MAXIMUM_PROFILE_BYTES, MAXIMUM_RUNTIME_FILES, require_store_path};

/// Fixed publisher unit; a string comparison never admits its invocation.
pub const PUBLISHER_UNIT_V1: &str = "aos-sandbox-runtime-publisher.service";
/// Fixed producer subject, not a request to change the calling process label.
pub const PUBLISHER_CONTEXT_V1: &str = "system_u:system_r:aos_runtime_deployment_publisher_t";
/// Fixed existing055 helper subject, independently checked by physical custody.
pub const HELPER_CONTEXT_V1: &str = "system_u:system_r:aos_runtime_deployment_helper_t";

/// Refuses malformed or unequal nonauthorizing publisher profile DATA.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("runtime deployment publisher profile DATA differs")]
pub struct RuntimeDeploymentProfileDataErrorV1;

/// Owns the sole strict old publisher JSON shape shared by both live recipes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDeploymentPublisherProfileDataV1 {
    /// Exact AOS_RUNTIME_DEPLOYMENT_STARTUP_1 inner format.
    pub format: String,
    /// Exact fixed publisher unit.
    pub unit: String,
    /// Exact fixed publisher subject.
    pub owner_context: String,
    /// Exact existing helper subject.
    pub helper_context: String,
    /// Immutable actual publisher binary pin.
    pub executable: ImagePinV1,
    /// Immutable selected PID1 image pin.
    pub pid1: ImagePinV1,
    /// Immutable selected loader pin.
    pub loader: ImagePinV1,
    /// Complete canonical runtime-file inventory.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub runtime_files: Vec<ImagePinV1>,
    /// Canonical roots of that runtime closure.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub closure_roots: Vec<String>,
    /// Exact deployment-kernel canonical MAC readback pin.
    pub canonical_policy: ImagePinV1,
    /// Exact immutable source policy pin.
    pub source_policy: ImagePinV1,
    /// Exact immutable effective policy checker result.
    pub effective_matrix: ImagePinV1,
    /// Complete unit bytes with only its self-referencing profile path normalized.
    pub unit_sha256: [u8; 32],
}

impl RuntimeDeploymentPublisherProfileDataV1 {
    /// Applies the original publisher's complete canonical shape checks.
    ///
    /// # Errors
    /// Refuses unknown format/roles, unsorted or excessive runtime roots/files,
    /// malformed store paths, sentinels or a missing executable/loader member.
    pub fn require_shape_data_v1(&self) -> Result<(), RuntimeDeploymentProfileDataErrorV1> {
        if self.format != "AOS_RUNTIME_DEPLOYMENT_STARTUP_1"
            || self.unit != PUBLISHER_UNIT_V1
            || self.owner_context != PUBLISHER_CONTEXT_V1
            || self.helper_context != HELPER_CONTEXT_V1
            || self.unit_sha256 == [0; 32]
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
            return Err(RuntimeDeploymentProfileDataErrorV1);
        }

        for root in &self.closure_roots {
            require_store_path(root).map_err(|_| RuntimeDeploymentProfileDataErrorV1)?;
            if Path::new(root).components().count() != 4 {
                return Err(RuntimeDeploymentProfileDataErrorV1);
            }
        }
        for pin in self.runtime_files.iter().chain([
            &self.executable,
            &self.pid1,
            &self.loader,
            &self.canonical_policy,
            &self.source_policy,
            &self.effective_matrix,
        ]) {
            require_store_path(&pin.path).map_err(|_| RuntimeDeploymentProfileDataErrorV1)?;
            if pin.sha256 == [0; 32] {
                return Err(RuntimeDeploymentProfileDataErrorV1);
            }
        }
        if self.runtime_files.iter().any(|pin| {
            !self.closure_roots.iter().any(|root| {
                Path::new(&pin.path)
                    .strip_prefix(root)
                    .is_ok_and(|suffix| suffix.components().count() > 0)
            })
        }) {
            return Err(RuntimeDeploymentProfileDataErrorV1);
        }
        for required in [&self.executable, &self.loader] {
            if !self
                .runtime_files
                .iter()
                .any(|member| member.path == required.path && member.sha256 == required.sha256)
            {
                return Err(RuntimeDeploymentProfileDataErrorV1);
            }
        }
        if Path::new(&self.executable.path)
            .file_name()
            .is_none_or(|name| name != "aos-sandbox-runtime-publisher")
            || !self
                .canonical_policy
                .path
                .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !self
                .source_policy
                .path
                .ends_with("-aos-runtime-deployment-startup-profile-1/source-policy.33")
            || !self
                .effective_matrix
                .path
                .ends_with("-aos-runtime-deployment-startup-profile-1/effective-policy.tsv")
            || Path::new(&self.source_policy.path).parent()
                != Path::new(&self.effective_matrix.path).parent()
        {
            return Err(RuntimeDeploymentProfileDataErrorV1);
        }
        Ok(())
    }
}

/// Describes the distinct normal boot recipe without manufacturing its source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPreparationPublisherProfileDataV1 {
    /// Exact AOS_RUNTIME_DEPLOYMENT_BOOT_STARTUP_1 outer grammar.
    pub format: String,
    /// Same strict publisher profile used by the existing measured image kernel.
    pub publisher: RuntimeDeploymentPublisherProfileDataV1,
    /// Actual configured immutable nspawn binary selected by the Host image.
    pub nspawn_executable: String,
    /// Actual configured immutable Host daemon package whose sibling is the probe.
    pub hostd_executable: String,
    /// Same canonical deployment-kernel MAC policy as the publisher pin.
    pub selinux_policy: String,
}

/// Checks exact decoded profile bytes against the independently admitted purpose.
///
/// The caller retains its actual serde Result and raw bytes and calls this
/// allocation-free comparison after native protected read/hash. This function
/// does not parse a second time or turn profile DATA into producer authority.
///
/// # Errors
/// Refuses excessive input, wrong normal recipe, any old inner shape failure,
/// altered profile bytes, foreign fixed paths or unequal canonical contracts.
pub fn require_boot_preparation_profile_data_v1(
    bytes: &[u8],
    profile: &BootPreparationPublisherProfileDataV1,
    purpose: &SignedBootPreparationPurposeDataV1,
) -> Result<(), RuntimeDeploymentProfileDataErrorV1> {
    use aos_sandbox_protocol::runtime_deployment::boot_preparation::{
        boot_preparation_credential_contract_data_v1, boot_preparation_directory_contract_data_v1,
        boot_preparation_program_contract_data_v1, boot_preparation_source_contract_data_v1,
    };
    if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    require_boot_preparation_profile_shape_data_v1(profile)?;
    let fields = purpose.fields_v1();
    if fields.publisher_profile != <[u8; 32]>::from(Sha256::digest(bytes))
        || fields.source_contract != boot_preparation_source_contract_data_v1()
        || fields.program_contract
            != boot_preparation_program_contract_data_v1(profile.publisher.executable.sha256)
        || fields.credential_contract != boot_preparation_credential_contract_data_v1()
        || fields.directory_contract != boot_preparation_directory_contract_data_v1()
    {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    Ok(())
}

/// Checks the normal decoded profile shape without authenticating its source.
///
/// Startup retains its original descriptor and decoded model before using this
/// allocation-free comparison. The independent signed-purpose join remains
/// necessary; a valid profile creates no native or signing authority.
///
/// # Errors
/// Refuses foreign formats, malformed fixed paths, a different canonical policy,
/// or PID1 and nspawn binaries selected from different immutable package roots.
pub fn require_boot_preparation_profile_shape_data_v1(
    profile: &BootPreparationPublisherProfileDataV1,
) -> Result<(), RuntimeDeploymentProfileDataErrorV1> {
    profile.publisher.require_shape_data_v1()?;
    if profile.format != "AOS_RUNTIME_DEPLOYMENT_BOOT_STARTUP_1"
        || profile.selinux_policy != profile.publisher.canonical_policy.path
        || !profile.nspawn_executable.ends_with("/bin/systemd-nspawn")
        || !profile.hostd_executable.ends_with("/bin/aos-sandbox-hostd")
    {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    for path in [
        &profile.nspawn_executable,
        &profile.hostd_executable,
        &profile.selinux_policy,
    ] {
        require_store_path(path).map_err(|_| RuntimeDeploymentProfileDataErrorV1)?;
    }
    // The exact selected PID1 and nspawn artifacts must belong to the same
    // package root; native callers still measure both actual retained images.
    let nspawn_root = Path::new(&profile.nspawn_executable)
        .parent()
        .and_then(Path::parent);
    let pid1_root = Path::new(&profile.publisher.pid1.path)
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent);
    if nspawn_root.is_none() || nspawn_root != pid1_root {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    Ok(())
}

/// Normalizes only the sole self-referencing original profile OpenFile line.
///
/// Every other byte, including Source, oneshot, credentials, limits and argv,
/// remains committed. Actual protected fragment/profile custody and payment
/// precede this pure allocation; normalization creates no unit authority.
///
/// # Errors
/// Refuses empty/oversized/non-UTF8 fragments and absent or duplicate profile lines.
pub fn normalize_publisher_unit_data_v1(
    bytes: &[u8],
    profile_path: &str,
) -> Result<Vec<u8>, RuntimeDeploymentProfileDataErrorV1> {
    const PROFILE_FD_NAME: &str = "aos-runtime-deployment-startup-profile";
    const PROFILE_PLACEHOLDER: &str = "@AOS_RUNTIME_DEPLOYMENT_PROFILE@";
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RuntimeDeploymentProfileDataErrorV1)?;
    let actual = format!("OpenFile={profile_path}:{PROFILE_FD_NAME}:read-only\n");
    let placeholder = format!("OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_FD_NAME}:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count()
        != 1
    {
        return Err(RuntimeDeploymentProfileDataErrorV1);
    }
    Ok(text
        .split_inclusive('\n')
        .map(|line| {
            if line == actual {
                placeholder.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

// Both old arrays already admit at most512 elements. Stop BEFORE a 513th
// deserialization/allocation, rather than relying on a post-growth shape check.
fn deserialize_bounded_profile_sequence_v1<'de, T, S>(deserializer: S) -> Result<Vec<T>, S::Error>
where
    T: serde::Deserialize<'de>,
    S: serde::Deserializer<'de>,
{
    struct Sequence<T>(std::marker::PhantomData<T>);

    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for Sequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAXIMUM_RUNTIME_FILES} publisher profile elements"
            )
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while values.len() < MAXIMUM_RUNTIME_FILES {
                match sequence.next_element()? {
                    Some(value) => {
                        values
                            .try_reserve_exact(1)
                            .map_err(serde::de::Error::custom)?;
                        values.push(value);
                    }
                    None => return Ok(values),
                }
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "publisher profile exceeds512 elements",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(Sequence(std::marker::PhantomData))
}

/// Quotes only parsed-profile/normalization storage before their growth.
///
/// Actual raw file readers, hashes, paths and native Files are independently
/// priced by the genuine caller. Existing bounded512 vectors and encoded bytes
/// bound retained model, transient serde strings and the two normalized copies.
#[must_use]
pub fn publisher_profile_comparison_receiving_bytes_v1(
    profile_bytes: usize,
    unit_bytes: usize,
    original_profile_path_bytes: usize,
) -> Option<usize> {
    if profile_bytes == 0
        || profile_bytes > MAXIMUM_PROFILE_BYTES
        || unit_bytes == 0
        || unit_bytes > 64 * 1024
    {
        return None;
    }
    let carriers = MAXIMUM_RUNTIME_FILES.checked_mul(
        std::mem::size_of::<ImagePinV1>().checked_add(std::mem::size_of::<String>())?,
    )?;
    std::mem::size_of::<BootPreparationPublisherProfileDataV1>()
        .checked_mul(2)?
        .checked_add(carriers.checked_mul(2)?)?
        .checked_add(profile_bytes.checked_mul(4)?)?
        .checked_add(unit_bytes.checked_mul(2)?)?
        .checked_add(original_profile_path_bytes.checked_mul(2)?)?
        .checked_add(2 * 128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct BoundedStrings {
        #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
        values: Vec<String>,
    }

    #[test]
    fn sequence_limit_precedes_decode_of_the_first_unadmitted_element() {
        let mut values = vec![serde_json::json!("bounded"); MAXIMUM_RUNTIME_FILES];
        let allowed = serde_json::to_vec(&serde_json::json!({ "values": &values })).unwrap();
        assert_eq!(
            serde_json::from_slice::<BoundedStrings>(&allowed)
                .unwrap()
                .values
                .len(),
            MAXIMUM_RUNTIME_FILES
        );
        values.push(serde_json::json!(17));
        let denied = serde_json::to_vec(&serde_json::json!({ "values": &values })).unwrap();

        let error = serde_json::from_slice::<BoundedStrings>(&denied)
            .err()
            .unwrap();

        assert!(error.to_string().contains("exceeds512"));
        assert!(!error.to_string().contains("expected a string"));
    }
}
