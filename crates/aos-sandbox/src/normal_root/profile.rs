//! One strict selected-image comparison contract shared by Root and Controller.
//!
//! `profile.json` is image-built JSON, not a signed or transferable authority.
//! Its one self-referencing OpenFile pathname is normalized to the documented
//! placeholder; all other bytes of the actual selected unit remain committed.
//!
//! ```text
//! AOS_NORMAL_ROOT_STARTUP_1: unit/context/identities + image pins +
//! canonical policy/source policy/effective checker pins + normalized unit SHA256
//! ```

use std::path::Path;

use serde::Deserialize;

use super::NormalRootStartupErrorV1;

pub(super) const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
pub(super) const MAXIMUM_RUNTIME_FILES: usize = 512;
pub(super) const PROFILE_PLACEHOLDER: &str = "@AOS_NORMAL_ROOT_PROFILE@";
pub(super) const UNIT: &str = "aos-sandbox-policy-authorityd.service";
pub(super) const CONTEXT: &str = "system_u:system_r:aos_sandbox_policy_authority_t";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImagePinV1 {
    pub(super) path: String,
    pub(super) sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NormalRootProfileV1 {
    format: String,
    unit: String,
    context: String,
    pub(super) identities: [u32; 4],
    pub(super) executable: ImagePinV1,
    pub(super) pid1: ImagePinV1,
    pub(super) loader: ImagePinV1,
    pub(super) runtime_files: Vec<ImagePinV1>,
    pub(super) closure_roots: Vec<String>,
    pub(super) canonical_policy: ImagePinV1,
    pub(super) source_policy: ImagePinV1,
    pub(super) effective_matrix: ImagePinV1,
    pub(super) unit_sha256: [u8; 32],
}

impl NormalRootProfileV1 {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, NormalRootStartupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        let profile: Self =
            serde_json::from_slice(bytes).map_err(|_| NormalRootStartupErrorV1::Profile)?;
        if profile.format != "AOS_NORMAL_ROOT_STARTUP_1"
            || profile.unit != UNIT
            || profile.context != CONTEXT
            || profile.identities[0] == 0
            || profile.identities[1] == 0
            || profile.unit_sha256 == [0; 32]
            || profile.runtime_files.is_empty()
            || profile.runtime_files.len() > MAXIMUM_RUNTIME_FILES
            || profile.closure_roots.is_empty()
            || profile.closure_roots.len() > MAXIMUM_RUNTIME_FILES
            || profile
                .closure_roots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || profile
                .runtime_files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        for root in &profile.closure_roots {
            require_store_path(root)?;
            if Path::new(root).components().count() != 4 {
                return Err(NormalRootStartupErrorV1::Profile);
            }
        }
        for pin in profile.runtime_files.iter().chain([
            &profile.executable,
            &profile.pid1,
            &profile.loader,
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]) {
            require_store_path(&pin.path)?;
            if pin.sha256 == [0; 32] {
                return Err(NormalRootStartupErrorV1::Profile);
            }
        }
        for pin in &profile.runtime_files {
            if !profile.closure_roots.iter().any(|root| {
                Path::new(&pin.path)
                    .strip_prefix(root)
                    .is_ok_and(|suffix| suffix.components().count() > 0)
            }) {
                return Err(NormalRootStartupErrorV1::Profile);
            }
        }
        for pin in [&profile.executable, &profile.loader] {
            if !profile
                .runtime_files
                .iter()
                .any(|member| member.path == pin.path && member.sha256 == pin.sha256)
            {
                return Err(NormalRootStartupErrorV1::Profile);
            }
        }
        if Path::new(&profile.executable.path)
            .file_name()
            .is_none_or(|name| name != "aos-sandbox-policy-authorityd")
            || !profile
                .canonical_policy
                .path
                .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !profile
                .effective_matrix
                .path
                .ends_with("-aos-normal-root-startup-profile-1/effective-policy.tsv")
            || !profile
                .source_policy
                .path
                .ends_with("-aos-normal-root-startup-profile-1/source-policy.33")
            || Path::new(&profile.source_policy.path).parent()
                != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        Ok(profile)
    }
}

pub(crate) fn require_store_path(path: &str) -> Result<(), NormalRootStartupErrorV1> {
    let relative = path
        .strip_prefix("/nix/store/")
        .filter(|value| !value.is_empty() && path.len() <= 1024)
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    let root = relative
        .split('/')
        .next()
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    let (hash, name) = root
        .split_once('-')
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        || name.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\\' | b'"'))
    {
        return Err(NormalRootStartupErrorV1::Profile);
    }
    Ok(())
}

pub(super) fn normalized_unit(
    bytes: &[u8],
    profile_path: &str,
) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NormalRootStartupErrorV1::Service)?;
    let actual = format!("OpenFile={profile_path}:aos-normal-root-profile:read-only\n");
    let placeholder = format!("OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count()
        != 1
    {
        return Err(NormalRootStartupErrorV1::Service);
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
