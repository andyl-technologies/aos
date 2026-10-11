//! Closed operator network policy and public CA files for direct provider TLS.
//!
//! ```json
//! {"version":1,"privateEndpoints":[{"origin":"https://s3.fleet.test",
//!   "privateCidrs":["10.42.0.0/24"]}],"rootCertificateFiles":[]}
//! ```
//!
//! This local file authorizes only network reachability and public TLS trust.
//! It contains no provider credentials or Hub bearer material. Server discovery
//! must independently authorize every placement, source and private-stage grant.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use serde::Deserialize;

use super::{PrivateProviderEndpoint, ProviderError, ProviderOptions};

const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 256 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    version: u32,
    private_endpoints: Vec<PrivateProviderEndpoint>,
    root_certificate_files: Vec<String>,
}

impl ProviderOptions {
    /// Reads an explicitly selected bounded local operator network policy.
    ///
    /// Files must be absolute, regular, singly linked, owned by the caller or
    /// root, and not writable by group/others. Final symlinks and FIFOs are
    /// rejected. The operator retains custody of ancestors; this is not a
    /// sandbox for arbitrary untrusted local paths. Certificate files contain
    /// only public CERTIFICATE PEM blocks, with no private-key fallback.
    ///
    /// # Errors
    /// Returns a value-free failure for custody, size, closed schema, invalid
    /// origin/CIDR, unknown version or malformed/non-public certificate material.
    pub fn from_policy_file(path: &Path) -> Result<Self, ProviderError> {
        let bytes = read_public_file(path, MAX_POLICY_BYTES)?;
        let policy: Policy =
            serde_json::from_slice(&bytes).map_err(|_| ProviderError::InvalidGrant)?;
        if policy.version != 1
            || policy.private_endpoints.len() > 16
            || policy.root_certificate_files.len() > 16
        {
            return Err(ProviderError::InvalidGrant);
        }
        let mut origins = std::collections::BTreeSet::new();
        for endpoint in &policy.private_endpoints {
            let origin = super::provider::checked_origin(&endpoint.origin)?;
            if !origins.insert(origin)
                || endpoint.private_cidrs.is_empty()
                || endpoint.private_cidrs.len() > 16
            {
                return Err(ProviderError::InvalidGrant);
            }
            let mut unique = std::collections::BTreeSet::new();
            for range in &endpoint.private_cidrs {
                if !unique.insert(range) {
                    return Err(ProviderError::InvalidGrant);
                }
                super::network::PrivateRange::parse(range)?;
            }
        }
        let mut roots = Vec::with_capacity(policy.root_certificate_files.len());
        let mut paths = std::collections::BTreeSet::new();
        for path in &policy.root_certificate_files {
            if path.len() > 4096 || !paths.insert(path) {
                return Err(ProviderError::InvalidGrant);
            }
            let bytes = read_public_file(Path::new(path), MAX_CERTIFICATE_BYTES)?;
            public_certificate_pem(&bytes)?;
            roots.push(
                reqwest::Certificate::from_pem(&bytes).map_err(|_| ProviderError::InvalidGrant)?,
            );
        }
        Ok(Self {
            private_endpoints: policy.private_endpoints,
            additional_roots: roots,
            ..Self::default()
        })
    }
}

fn read_public_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ProviderError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ProviderError::InvalidGrant);
    }
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ProviderError::InvalidGrant)?,
    );
    let metadata = file.metadata().map_err(|_| ProviderError::InvalidGrant)?;
    let uid = rustix::process::geteuid().as_raw();
    if uid == 65534
        || !metadata.is_file()
        || metadata.nlink() != 1
        || ![uid, 0].contains(&metadata.uid())
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > maximum
    {
        return Err(ProviderError::InvalidGrant);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::InvalidGrant)?;
    if bytes.len() as u64 > maximum {
        return Err(ProviderError::InvalidGrant);
    }
    Ok(bytes)
}

fn public_certificate_pem(bytes: &[u8]) -> Result<(), ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProviderError::InvalidGrant)?;
    let mut inside = false;
    let mut payload = false;
    let mut blocks = 0;
    for line in text.lines() {
        match line {
            "-----BEGIN CERTIFICATE-----" if !inside => {
                inside = true;
                payload = false;
            }
            "-----END CERTIFICATE-----" if inside && payload => {
                inside = false;
                blocks += 1;
            }
            "" if !inside => {}
            line if inside
                && !line.is_empty()
                && line.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                }) =>
            {
                payload = true;
            }
            _ => return Err(ProviderError::InvalidGrant),
        }
    }
    if inside || blocks == 0 || blocks > 16 {
        return Err(ProviderError::InvalidGrant);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn explicit_policy_admits_fleet_origin_and_never_uses_server_or_environment_policy() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"version":1,"privateEndpoints":[{"origin":"https://s3.fleet.test","privateCidrs":["10.42.0.0/24"]}],"rootCertificateFiles":[]}"#).unwrap();
        let options = ProviderOptions::from_policy_file(file.path()).unwrap();
        assert_eq!(options.private_endpoints.len(), 1);
        assert_eq!(options.private_endpoints[0].private_cidrs, ["10.42.0.0/24"]);
        assert!(ProviderOptions::default().private_endpoints.is_empty());
        assert!(!format!("{options:?}").contains("s3.fleet.test"));
    }

    #[test]
    fn policy_unknown_duplicate_oversize_and_world_writable_files_refuse() {
        for bytes in [
            br#"{"version":2,"privateEndpoints":[],"rootCertificateFiles":[]}"#.as_slice(),
            br#"{"version":1,"version":1,"privateEndpoints":[],"rootCertificateFiles":[]}"#,
            br#"{"version":1,"privateEndpoints":[],"rootCertificateFiles":[],"credential":"private-canary"}"#,
            br#"{"version":1,"privateEndpoints":[{"origin":"https://provider.test","privateCidrs":["0.0.0.0/0"]}],"rootCertificateFiles":[]}"#,
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap(); file.write_all(bytes).unwrap();
            let error = ProviderOptions::from_policy_file(file.path()).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("private-canary"));
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![b' '; MAX_POLICY_BYTES as usize + 1])
            .unwrap();
        assert!(ProviderOptions::from_policy_file(file.path()).is_err());
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(ProviderOptions::from_policy_file(file.path()).is_err());
        let directory = tempfile::tempdir().unwrap();
        let alias = directory.path().join("alias");
        symlink(file.path(), &alias).unwrap();
        assert!(ProviderOptions::from_policy_file(&alias).is_err());
    }

    #[test]
    fn certificate_policy_rejects_private_keys_extra_pem_objects_and_incomplete_blocks() {
        for bytes in [
            b"-----BEGIN PRIVATE KEY-----\nprivate-key-canary\n-----END PRIVATE KEY-----\n".as_slice(),
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
            b"-----BEGIN CERTIFICATE-----\nYWJj\n",
        ] { assert!(public_certificate_pem(bytes).is_err()); }
        assert!(
            public_certificate_pem(
                b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
            )
            .is_ok()
        );
    }
}
