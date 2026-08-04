//! Desired-package credential materialization.
//!
//! `apm install --system --from desired.toml` accepts package-scoped
//! credential values keyed by package and credential name. This module
//! validates those values against signed RFC-0001 `expose.config.credentials`
//! metadata, writes plaintext credentials into the systemd plaintext credstore,
//! and encrypts TPM2/signed-PCR credentials into the encrypted credstore.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::desired::{DesiredCredentialValue, DesiredPackageCredentials};
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::types::{
    ApmSettings, CredentialMeta, InstalledMeta, PackageMeta, ProfileScope, validate_credential_name,
};

const DEFAULT_CREDENTIAL_PCR_PUBLIC_KEY: &str = "/etc/aos/pcr-sign.pem";
const GENERATED_CREDENTIAL_RUN_PREFIX: &str = "/run/credstore.encrypted/aos";

#[derive(Debug, Default)]
pub(crate) struct CredentialReconciliation {
    changed: bool,
    restart_units: BTreeSet<String>,
}

impl CredentialReconciliation {
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }

    pub(crate) fn apply(self) -> Result<()> {
        if self.changed {
            apply_credential_reconciliation(&aos_root_path(), self.restart_units)?;
        }
        Ok(())
    }
}

/// Resolves evaluator-produced opaque credential references through the
/// production desired/system-credential materialization path.
///
/// All bytes are placed before the returned reconciliation is applied. The
/// caller applies it after the configuration switch so every changed consumer
/// is restarted at most once, after all credential files are ready.
///
/// # Errors
///
/// Returns an error for plaintext-shaped manifest values, unsupported
/// resolvers, missing desired/system credential bytes, unsafe destinations,
/// failed TPM2 encryption, or failed atomic writes. Resolution fails closed
/// before any consuming unit is restarted.
pub(crate) fn reconcile_secret_refs(
    settings: &ApmSettings,
    root: &Path,
    manifest_credentials: &BTreeMap<String, serde_json::Value>,
) -> Result<CredentialReconciliation> {
    let desired_path = rooted_absolute_path(root, Path::new(crate::desired::DEFAULT_DESIRED_PATH))?;
    let desired = if desired_path.is_file() {
        crate::desired::load_desired_credentials(&desired_path)?
    } else {
        DesiredPackageCredentials::new()
    };
    let mut changed = false;
    let mut restart_units = BTreeSet::new();

    for (package, value) in manifest_credentials {
        let handles = value.as_object().with_context(|| {
            format!("credential handles for package '{package}' must be an object")
        })?;
        for (name, value) in handles {
            let reference: crate::secret_ref::SecretRef = serde_json::from_value(value.clone())
                .with_context(|| format!("parsing secretRef '{package}.{name}'"))?;
            if reference.name != *name {
                bail!("secretRef '{package}.{name}' changes its credential name");
            }
            reference.validate_reference()?;
            let kind = reference.resolver_kind()?;
            if kind == crate::secret_ref::ResolverKind::Tpm2Credstore {
                validate_existing_sealed_reference(root, package, &reference)?;
                continue;
            }
            if matches!(
                kind,
                crate::secret_ref::ResolverKind::Vault | crate::secret_ref::ResolverKind::AwsSm
            ) {
                bail!("secretRef '{package}.{name}' selects an unavailable resolver");
            }
            let source = reference.source.as_deref().with_context(|| {
                format!("secretRef '{package}.{name}' does not declare a credstore source")
            })?;
            let meta = CredentialMeta::from(&reference);
            validate_provisionable_source(package, &meta, source)?;
            let value = match kind {
                crate::secret_ref::ResolverKind::DesiredToml => desired
                    .get(package)
                    .and_then(|credentials| credentials.get(name))
                    .with_context(|| {
                        format!(
                            "secretRef '{package}.{name}' has no value in {}",
                            desired_path.display()
                        )
                    })?
                    .clone(),
                crate::secret_ref::ResolverKind::SystemCredential => {
                    let system_credential = reference.resolver_handle().unwrap_or(name);
                    DesiredCredentialValue::Source(crate::desired::DesiredCredentialSource {
                        system_credential: system_credential.to_string(),
                    })
                }
                crate::secret_ref::ResolverKind::Tpm2Credstore
                | crate::secret_ref::ResolverKind::Vault
                | crate::secret_ref::ResolverKind::AwsSm => {
                    bail!("secretRef '{package}.{name}' selected an invalid materializing resolver")
                }
            };
            let plaintext = desired_credential_plaintext(root, package, name, &value)?;
            let bytes = if reference.encrypted {
                encrypt_desired_credential(settings, root, &meta, &plaintext)?
            } else {
                plaintext
            };
            if write_credential_source(root, source, &bytes)
                .with_context(|| format!("writing secretRef '{package}.{name}'"))?
            {
                changed = true;
                restart_units.extend(reference.units);
            }
        }
    }

    Ok(CredentialReconciliation {
        changed,
        restart_units,
    })
}

fn validate_existing_sealed_reference(
    root: &Path,
    package: &str,
    reference: &crate::secret_ref::SecretRef,
) -> Result<()> {
    if reference.ciphertext.is_some() {
        return Ok(());
    }
    let source = reference.source.as_deref().with_context(|| {
        format!(
            "TPM2 credstore secretRef '{}.{}' has neither source nor package-authored ciphertext",
            package, reference.name
        )
    })?;
    let path = rooted_absolute_path(root, Path::new(source))?;
    let metadata = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "reading TPM2 credstore secretRef '{}.{}' from {}",
            package,
            reference.name,
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::metadata(&path)
            .with_context(|| format!("following sealed credential {}", path.display()))?;
        if !target.is_file() {
            bail!(
                "sealed credential source is not a regular file: {}",
                path.display()
            );
        }
    } else if !metadata.is_file() {
        bail!(
            "sealed credential source is not a regular file: {}",
            path.display()
        );
    }
    Ok(())
}

/// Validate desired credentials against the final package set without writing.
///
/// `installed` is the current explicit profile metadata, and `resolved_roots`
/// are registry-resolved explicit package roots that will be installed before
/// materialization. This catches metadata, source-path, and PCR-key failures
/// before the desired reconciler mutates the package profile.
pub(crate) fn preflight_desired_credentials(
    config: &ApmConfig,
    desired: &DesiredPackageCredentials,
    final_packages: &BTreeSet<String>,
    installed: &[InstalledMeta],
    resolved_roots: &[PackageMeta],
) -> Result<()> {
    preflight_desired_credentials_at_root(
        config,
        &aos_root_path(),
        desired,
        final_packages,
        installed,
        resolved_roots,
    )
}

fn preflight_desired_credentials_at_root(
    config: &ApmConfig,
    root: &Path,
    desired: &DesiredPackageCredentials,
    final_packages: &BTreeSet<String>,
    installed: &[InstalledMeta],
    resolved_roots: &[PackageMeta],
) -> Result<()> {
    if config.scope != ProfileScope::System || desired.is_empty() {
        return Ok(());
    }

    let mut candidates = BTreeMap::<&str, &[CredentialMeta]>::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit || !final_packages.contains(&apm.name) {
            continue;
        }
        if let Some(expose) = apm.expose.as_ref()
            && !expose.config.credentials.is_empty()
        {
            candidates.insert(apm.name.as_str(), expose.config.credentials.as_slice());
        }
    }
    for root in resolved_roots {
        if !final_packages.contains(&root.name) {
            continue;
        }
        if let Some(expose) = root.expose.as_ref()
            && !expose.config.credentials.is_empty()
        {
            candidates.insert(root.name.as_str(), expose.config.credentials.as_slice());
        }
    }

    for (package, package_credentials) in desired {
        if !final_packages.contains(package) {
            bail!(
                "desired credentials reference package '{package}' outside the desired package set"
            );
        }
        let Some(credentials) = candidates.get(package.as_str()) else {
            bail!(
                "desired credentials reference package '{package}' without signed credential metadata"
            );
        };
        validate_desired_package_credentials(
            &config.settings,
            root,
            package,
            credentials,
            package_credentials,
        )?;
    }

    Ok(())
}

/// Materialize desired package credentials.
///
/// Returns the changed state and service reconciliation units.
///
/// # Errors
///
/// Returns an error when desired credentials reference an unknown package or
/// credential, target a non-provisionable credential declaration, cannot be
/// encrypted with the signed-PCR policy, or cannot be written.
pub(crate) async fn reconcile_desired_credentials(
    config: &ApmConfig,
    desired: &DesiredPackageCredentials,
    printer: &Printer,
) -> Result<CredentialReconciliation> {
    if config.scope != ProfileScope::System {
        return Ok(CredentialReconciliation::default());
    }

    let profile = Profile::open_readonly(ProfileScope::System);
    let installed = list_meta(&profile)?;
    let root = aos_root_path();
    let mut changed = false;
    let mut handled_packages = BTreeSet::new();
    let mut restart_units = BTreeSet::new();

    for entry in installed.iter().filter(|entry| {
        entry
            .apm
            .as_ref()
            .is_some_and(|apm| apm.explicit && apm.expose.is_some())
    }) {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        let Some(expose) = apm.expose.as_ref() else {
            continue;
        };
        if expose.config.credentials.is_empty() {
            continue;
        }
        handled_packages.insert(apm.name.clone());
        let desired_package = desired.get(&apm.name);
        changed |= materialize_package_credentials(
            &config.settings,
            &root,
            &apm.name,
            entry,
            desired_package,
            &mut restart_units,
        )?;
    }

    for package in desired.keys() {
        if !handled_packages.contains(package) {
            bail!(
                "desired credentials reference package '{package}' without signed credential metadata"
            );
        }
    }

    if changed {
        printer.info("Reconciled desired package credentials.");
    }

    Ok(CredentialReconciliation {
        changed,
        restart_units,
    })
}

fn materialize_package_credentials(
    settings: &ApmSettings,
    root: &Path,
    package: &str,
    installed: &InstalledMeta,
    desired_package: Option<&BTreeMap<String, DesiredCredentialValue>>,
    restart_units: &mut BTreeSet<String>,
) -> Result<bool> {
    let apm = installed
        .apm
        .as_ref()
        .context("installed package missing apm metadata")?;
    let expose = apm
        .expose
        .as_ref()
        .context("installed package missing expose metadata")?;
    let desired_package = desired_package.cloned().unwrap_or_default();
    validate_desired_package_credentials(
        settings,
        root,
        package,
        &expose.config.credentials,
        &desired_package,
    )?;
    let known_credentials = credential_lookup(&expose.config.credentials);
    let mut changed = false;

    for (name, value) in desired_package {
        let credential = known_credentials
            .get(name.as_str())
            .context("credential validation must run before materialization")?;
        let source = credential
            .source
            .as_deref()
            .context("credential validation must require a source")?;
        let plaintext = desired_credential_plaintext(root, package, &name, &value)?;
        let bytes = if credential.encrypted {
            encrypt_desired_credential(settings, root, credential, &plaintext)?
        } else {
            plaintext
        };
        if write_credential_source(root, source, &bytes)
            .with_context(|| format!("writing desired credential '{package}.{name}'"))?
        {
            changed = true;
            restart_units.extend(credential.units.iter().cloned());
        }
    }

    Ok(changed)
}

fn validate_desired_package_credentials(
    settings: &ApmSettings,
    root: &Path,
    package: &str,
    credentials: &[CredentialMeta],
    desired_package: &BTreeMap<String, DesiredCredentialValue>,
) -> Result<()> {
    let known_credentials = credential_lookup(credentials);
    for (name, value) in desired_package {
        validate_credential_name(name)?;
        validate_desired_credential_value(root, package, name, value)?;
        let Some(credential) = known_credentials.get(name.as_str()) else {
            bail!(
                "desired credentials for package '{package}' reference unknown credential '{name}'"
            );
        };
        let Some(source) = credential.source.as_deref() else {
            bail!(
                "desired credential '{package}.{name}' cannot be provisioned because signed metadata does not declare a credstore source"
            );
        };
        validate_provisionable_source(package, credential, source)?;
        if credential.encrypted {
            credential_pcr_public_key(settings, root)?;
        }
    }
    Ok(())
}

fn validate_desired_credential_value(
    root: &Path,
    package: &str,
    name: &str,
    value: &DesiredCredentialValue,
) -> Result<()> {
    if let DesiredCredentialValue::Source(source) = value {
        validate_credential_name(&source.system_credential).with_context(|| {
            format!("invalid desired system credential name '{package}.{name}'")
        })?;
        let path = system_credential_path(root, &source.system_credential)?;
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "reading system credential '{}' for desired credential '{}.{}' from {}",
                source.system_credential,
                package,
                name,
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!(
                "system credential '{}' for desired credential '{}.{}' must be a regular file: {}",
                source.system_credential,
                package,
                name,
                path.display()
            );
        }
    }
    Ok(())
}

fn desired_credential_plaintext(
    root: &Path,
    package: &str,
    name: &str,
    value: &DesiredCredentialValue,
) -> Result<Vec<u8>> {
    match value {
        DesiredCredentialValue::Plaintext(value) => Ok(value.as_bytes().to_vec()),
        DesiredCredentialValue::Source(source) => {
            validate_desired_credential_value(root, package, name, value)?;
            let path = system_credential_path(root, &source.system_credential)?;
            std::fs::read(&path).with_context(|| {
                format!(
                    "reading system credential '{}' for desired credential '{}.{}' from {}",
                    source.system_credential,
                    package,
                    name,
                    path.display()
                )
            })
        }
    }
}

fn system_credential_path(root: &Path, name: &str) -> Result<PathBuf> {
    rooted_absolute_path(root, &Path::new("/run/credentials/@system").join(name))
}

fn credential_lookup(credentials: &[CredentialMeta]) -> BTreeMap<&str, &CredentialMeta> {
    credentials
        .iter()
        .map(|credential| (credential.name.as_str(), credential))
        .collect()
}

pub(crate) fn validate_provisionable_source(
    package: &str,
    credential: &CredentialMeta,
    source: &str,
) -> Result<()> {
    let source_path = Path::new(source);
    if is_under(source_path, Path::new("/usr/lib/credstore"))
        || is_under(source_path, Path::new("/usr/lib/credstore.encrypted"))
    {
        bail!(
            "desired credential '{}.{}' targets immutable source path '{source}'; use /etc or /run credstore sources for desired provisioning",
            package,
            credential.name
        );
    }
    if is_at_or_under(source_path, Path::new(GENERATED_CREDENTIAL_RUN_PREFIX)) {
        bail!(
            "desired credential '{}.{}' targets AOS generated credential namespace '{source}'; use a package encryptedFile declaration for generated blobs or a non-aos /etc or /run credstore source for desired provisioning",
            package,
            credential.name
        );
    }
    if credential.ciphertext.is_some() {
        bail!(
            "desired credential '{}.{}' cannot override signed inline ciphertext",
            package,
            credential.name
        );
    }
    Ok(())
}

fn encrypt_desired_credential(
    settings: &ApmSettings,
    root: &Path,
    credential: &CredentialMeta,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let public_key = credential_pcr_public_key(settings, root)?;
    let temp = tempfile::Builder::new()
        .prefix("aos-credential-")
        .tempdir()
        .context("creating temporary credential encryption directory")?;
    let input = temp.path().join("plaintext");
    let output = temp.path().join("encrypted");
    std::fs::write(&input, plaintext).with_context(|| format!("writing {}", input.display()))?;
    std::fs::set_permissions(&input, Permissions::from_mode(0o600))
        .with_context(|| format!("setting mode on {}", input.display()))?;

    run_systemd_creds_encrypt(&credential.name, &public_key, &input, &output)
        .context("running systemd-creds encrypt for desired credential")?;

    std::fs::read(&output).with_context(|| format!("reading {}", output.display()))
}

pub(crate) fn run_systemd_creds_encrypt(
    credential_name: &str,
    public_key: &Path,
    input: &Path,
    output: &Path,
) -> Result<()> {
    let args = systemd_creds_encrypt_args(credential_name, public_key, input, output, false);
    let output_status = Command::new("systemd-creds")
        .args(&args)
        .output()
        .context("running systemd-creds encrypt")?;
    if !output_status.status.success() {
        let stderr = String::from_utf8_lossy(&output_status.stderr);
        bail!(
            "systemd-creds failed to encrypt credential '{}': {}{}",
            credential_name,
            output_status.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }
    Ok(())
}

pub(crate) fn systemd_creds_encrypt_pretty(
    credential_name: &str,
    public_key: &Path,
    input: &Path,
) -> Result<String> {
    let args = systemd_creds_encrypt_args(credential_name, public_key, input, Path::new("-"), true);
    let output_status = Command::new("systemd-creds")
        .args(&args)
        .output()
        .context("running systemd-creds encrypt")?;
    if !output_status.status.success() {
        let stderr = String::from_utf8_lossy(&output_status.stderr);
        bail!(
            "systemd-creds failed to encrypt credential '{}': {}{}",
            credential_name,
            output_status.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }
    String::from_utf8(output_status.stdout).context("systemd-creds pretty output is not UTF-8")
}

fn systemd_creds_encrypt_args(
    credential_name: &str,
    public_key: &Path,
    input: &Path,
    output: &Path,
    pretty: bool,
) -> Vec<OsString> {
    let mut name = OsString::from("--name=");
    name.push(credential_name);
    let mut public_key_arg = OsString::from("--tpm2-public-key=");
    public_key_arg.push(public_key.as_os_str());
    let mut args = vec![
        OsString::from("encrypt"),
        name,
        OsString::from("--with-key=tpm2"),
        public_key_arg,
        OsString::from("--tpm2-public-key-pcrs=11"),
    ];
    if pretty {
        args.push(OsString::from("--pretty"));
    }
    args.push(input.as_os_str().to_owned());
    args.push(output.as_os_str().to_owned());
    args
}

pub(crate) fn credential_pcr_public_key(settings: &ApmSettings, root: &Path) -> Result<PathBuf> {
    let configured = settings
        .credential_pcr_public_key
        .as_deref()
        .unwrap_or(DEFAULT_CREDENTIAL_PCR_PUBLIC_KEY);
    let configured = Path::new(configured);
    if !configured.is_absolute() {
        bail!("[settings].credential_pcr_public_key must be an absolute path");
    }
    let host_path = rooted_absolute_path(root, configured)?;
    if !host_path.is_file() {
        bail!(
            "encrypted desired credential provisioning requires PCR public key at {}; configure [settings].credential_pcr_public_key or enable measured boot",
            host_path.display()
        );
    }
    Ok(host_path)
}

fn write_credential_source(root: &Path, source: &str, bytes: &[u8]) -> Result<bool> {
    let targets = credential_targets(root, source)?;
    let changed = targets
        .iter()
        .any(|target| credential_target_changed(&target.path, bytes));
    for target in targets {
        if changed {
            write_secret_file(&target, bytes)?;
        } else {
            ensure_secret_parent(&target)?;
            if target.path.exists() {
                std::fs::set_permissions(&target.path, Permissions::from_mode(0o600))
                    .with_context(|| format!("setting mode on {}", target.path.display()))?;
            }
        }
    }
    Ok(changed)
}

fn credential_target_changed(path: &Path, bytes: &[u8]) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return true;
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return true;
    }
    std::fs::read(path).map(|old| old != bytes).unwrap_or(true)
}

fn write_secret_file(target: &CredentialTarget, bytes: &[u8]) -> Result<()> {
    ensure_secret_parent(target)?;
    let parent = target
        .path
        .parent()
        .with_context(|| format!("credential target has no parent: {}", target.path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file in {}", parent.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("writing temporary file in {}", parent.display()))?;
    temp.as_file()
        .set_permissions(Permissions::from_mode(0o600))
        .with_context(|| format!("setting temporary mode in {}", parent.display()))?;
    temp.persist(&target.path)
        .map_err(|err| err.error)
        .with_context(|| format!("renaming credential into {}", target.path.display()))?;
    std::fs::set_permissions(&target.path, Permissions::from_mode(0o600))
        .with_context(|| format!("setting mode on {}", target.path.display()))?;
    Ok(())
}

fn ensure_secret_parent(target: &CredentialTarget) -> Result<()> {
    let parent = target
        .path
        .parent()
        .with_context(|| format!("credential target has no parent: {}", target.path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let mut dirs = Vec::new();
    let mut current = parent.to_path_buf();
    loop {
        if current.starts_with(&target.directory_root) {
            dirs.push(current.clone());
        }
        if current == target.directory_root {
            break;
        }
        if !current.pop() {
            break;
        }
    }
    for dir in dirs.iter().rev() {
        std::fs::set_permissions(dir, Permissions::from_mode(0o700))
            .with_context(|| format!("setting mode on {}", dir.display()))?;
    }
    Ok(())
}

#[derive(Debug)]
struct CredentialTarget {
    path: PathBuf,
    directory_root: PathBuf,
}

fn credential_targets(root: &Path, source: &str) -> Result<Vec<CredentialTarget>> {
    let source = Path::new(source);
    if is_under(source, Path::new("/etc/credstore.encrypted")) {
        return credential_targets_for_prefix(root, source, "/etc/credstore.encrypted");
    }
    if is_under(source, Path::new("/etc/credstore")) {
        return credential_targets_for_prefix(root, source, "/etc/credstore");
    }
    if is_under(source, Path::new("/run/credstore.encrypted")) {
        if is_at_or_under(source, Path::new(GENERATED_CREDENTIAL_RUN_PREFIX)) {
            bail!(
                "desired credential source '{}' is in the AOS generated credential namespace and cannot be provisioned",
                source.display()
            );
        }
        return Ok(vec![CredentialTarget {
            path: rooted_absolute_path(root, source)?,
            directory_root: root.join("run/credstore.encrypted"),
        }]);
    }
    if is_under(source, Path::new("/run/credstore")) {
        return Ok(vec![CredentialTarget {
            path: rooted_absolute_path(root, source)?,
            directory_root: root.join("run/credstore"),
        }]);
    }
    if is_under(source, Path::new("/usr/lib/credstore.encrypted"))
        || is_under(source, Path::new("/usr/lib/credstore"))
    {
        bail!(
            "desired credential source '{}' is immutable and cannot be provisioned",
            source.display()
        );
    }
    bail!(
        "desired credential source '{}' must be under /etc or /run credstore paths",
        source.display()
    )
}

fn credential_targets_for_prefix(
    root: &Path,
    source: &Path,
    source_prefix: &str,
) -> Result<Vec<CredentialTarget>> {
    let source_prefix = Path::new(source_prefix);
    let rel = source.strip_prefix(source_prefix).with_context(|| {
        format!(
            "credential source must be under {}",
            source_prefix.display()
        )
    })?;
    let etc_prefix = rooted_absolute_path(root, source_prefix)?;
    let var_prefix = root.join("var/etc").join(
        source_prefix
            .strip_prefix("/etc")
            .context("credential source prefix must be under /etc")?,
    );
    Ok(vec![
        CredentialTarget {
            path: var_prefix.join(rel),
            directory_root: var_prefix,
        },
        CredentialTarget {
            path: etc_prefix.join(rel),
            directory_root: etc_prefix,
        },
    ])
}

fn rooted_absolute_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let rel = path
        .strip_prefix("/")
        .with_context(|| format!("path must be absolute: {}", path.display()))?;
    Ok(root.join(rel))
}

fn is_under(path: &Path, prefix: &Path) -> bool {
    path != prefix && path.starts_with(prefix)
}

fn is_at_or_under(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.starts_with(prefix)
}

fn apply_credential_reconciliation(root: &Path, restart_units: BTreeSet<String>) -> Result<()> {
    if root != Path::new("/") {
        return Ok(());
    }

    for unit in restart_units {
        run_systemctl(&["restart", &unit], "restart changed package credential")?;
    }
    Ok(())
}

fn run_systemctl(args: &[&str], action: &str) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("running systemctl to {action}"))?;
    if !status.success() {
        bail!("systemctl failed to {action}: {status}");
    }
    Ok(())
}

pub(crate) fn aos_root_path() -> PathBuf {
    match std::env::var("AOS_ROOT") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                PathBuf::from("/").join(path)
            }
        }
        _ => PathBuf::from("/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApmMeta, ExposeConfigMeta, ExposeMeta};
    use tempfile::TempDir;

    fn installed_with_credentials() -> InstalledMeta {
        InstalledMeta {
            store_path: "/nix/store/pkghash111-web".into(),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "web".into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test".into(),
                installed_at: "2026-06-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: Some(ExposeMeta {
                    target: "aos-pkg-web.target".into(),
                    units: vec!["web.service".into()],
                    images: Vec::new(),
                    requires: Vec::new(),
                    config: ExposeConfigMeta {
                        artifacts: Vec::new(),
                        credentials: vec![
                            CredentialMeta {
                                name: "plain-token".into(),
                                source: Some("/etc/credstore/web/plain-token".into()),
                                ciphertext: None,
                                units: vec!["web.service".into()],
                                encrypted: false,
                            },
                            CredentialMeta {
                                name: "join-token".into(),
                                source: Some("/etc/credstore.encrypted/web/join-token".into()),
                                ciphertext: None,
                                units: vec!["web.service".into()],
                                encrypted: true,
                            },
                            CredentialMeta {
                                name: "inline-secret".into(),
                                source: None,
                                ciphertext: Some("abcDEF0123+/=".into()),
                                units: vec!["web.service".into()],
                                encrypted: true,
                            },
                            CredentialMeta {
                                name: "vendor-secret".into(),
                                source: Some("/usr/lib/credstore.encrypted/vendor-secret".into()),
                                ciphertext: None,
                                units: vec!["web.service".into()],
                                encrypted: true,
                            },
                        ],
                    },
                    provides: Vec::new(),
                    uses: Vec::new(),
                }),
                expose_artifact: None,
                config_module: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    fn package_meta_with_credentials() -> PackageMeta {
        let installed = installed_with_credentials();
        let expose = installed.apm.unwrap().expose;
        PackageMeta {
            name: "web".into(),
            version: "1.0".into(),
            description: "web".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "test".into(),
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/pkghash111-web".into(),
            nar_hash: "sha256:test".into(),
            nar_size: 1,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: String::new(),
            closure_size: 1,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: None,
            requires_features: Vec::new(),
            expose,
            expose_artifact: None,
            config_module: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        }
    }

    fn system_credential_value(name: &str) -> DesiredCredentialValue {
        DesiredCredentialValue::Source(crate::desired::DesiredCredentialSource {
            system_credential: name.into(),
        })
    }

    #[test]
    fn materialize_package_credentials_writes_plaintext_persistent_and_live_sources() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert("plain-token".into(), "s3 cr3t".into());
        let mut restart = BTreeSet::new();

        let changed = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("var/etc/credstore/web/plain-token")).unwrap(),
            "s3 cr3t"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/credstore/web/plain-token")).unwrap(),
            "s3 cr3t"
        );
        assert_eq!(
            std::fs::metadata(tmp.path().join("etc/credstore/web/plain-token"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(tmp.path().join("etc/credstore"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(restart.contains("web.service"));
    }

    #[test]
    fn manifest_secret_ref_resolves_before_one_reconciliation() {
        let tmp = TempDir::new().unwrap();
        let desired_path = tmp.path().join("etc/aos/packages.d/desired.toml");
        std::fs::create_dir_all(desired_path.parent().unwrap()).unwrap();
        std::fs::write(
            &desired_path,
            "[credentials.web]\nplain-token = \"rotated-value\"\n",
        )
        .unwrap();
        let manifest = BTreeMap::from([(
            "web".to_string(),
            serde_json::json!({
                "plain-token": {
                    "name": "plain-token",
                    "source": "/etc/credstore/web/plain-token",
                    "encrypted": false,
                    "units": ["web.service"],
                    "ref": "desired-toml"
                }
            }),
        )]);

        let reconciliation =
            reconcile_secret_refs(&ApmSettings::default(), tmp.path(), &manifest).unwrap();
        assert!(reconciliation.changed());
        for path in [
            "etc/credstore/web/plain-token",
            "var/etc/credstore/web/plain-token",
        ] {
            let path = tmp.path().join(path);
            assert_eq!(std::fs::read(&path).unwrap(), b"rotated-value");
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            reconciliation.restart_units,
            BTreeSet::from(["web.service".to_string()])
        );
    }

    #[test]
    fn preflight_desired_credentials_rejects_packages_outside_desired_set() {
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert(
            "web".into(),
            BTreeMap::from([("plain-token".into(), "secret".into())]),
        );

        let err = preflight_desired_credentials(
            &ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::System,
            },
            &desired,
            &BTreeSet::new(),
            &[installed],
            &[],
        )
        .unwrap_err();

        assert!(err.to_string().contains("outside the desired package set"));
    }

    #[test]
    fn preflight_desired_credentials_validates_resolved_addition_metadata() {
        let mut desired = BTreeMap::new();
        desired.insert(
            "web".into(),
            BTreeMap::from([("missing".into(), "secret".into())]),
        );
        let final_packages = BTreeSet::from(["web".to_string()]);
        let root = package_meta_with_credentials();

        let err = preflight_desired_credentials(
            &ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::System,
            },
            &desired,
            &final_packages,
            &[],
            &[root],
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown credential"));
    }

    #[test]
    fn preflight_desired_credentials_rejects_missing_system_credential_source() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let desired = BTreeMap::from([(
            "web".into(),
            BTreeMap::from([(
                "plain-token".into(),
                system_credential_value("missing-token"),
            )]),
        )]);
        let final_packages = BTreeSet::from(["web".to_string()]);

        let err = preflight_desired_credentials_at_root(
            &ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::System,
            },
            tmp.path(),
            &desired,
            &final_packages,
            &[installed],
            &[],
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("reading system credential 'missing-token'"),
            "{err:?}"
        );
    }

    #[test]
    fn preflight_desired_credentials_rejects_non_regular_system_credential_source() {
        let tmp = TempDir::new().unwrap();
        let system_credential = tmp.path().join("run/credentials/@system/bootstrap-token");
        std::fs::create_dir_all(&system_credential).unwrap();
        let installed = installed_with_credentials();
        let desired = BTreeMap::from([(
            "web".into(),
            BTreeMap::from([(
                "plain-token".into(),
                system_credential_value("bootstrap-token"),
            )]),
        )]);
        let final_packages = BTreeSet::from(["web".to_string()]);

        let err = preflight_desired_credentials_at_root(
            &ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::System,
            },
            tmp.path(),
            &desired,
            &final_packages,
            &[installed],
            &[],
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("must be a regular file"),
            "{err:?}"
        );
    }

    #[test]
    fn preflight_desired_credentials_rejects_symlink_system_credential_source() {
        let tmp = TempDir::new().unwrap();
        let system_credential = tmp.path().join("run/credentials/@system/bootstrap-token");
        std::fs::create_dir_all(system_credential.parent().unwrap()).unwrap();
        let target = tmp.path().join("bootstrap-token-target");
        std::fs::write(&target, "from-system").unwrap();
        std::os::unix::fs::symlink(&target, &system_credential).unwrap();
        let installed = installed_with_credentials();
        let desired = BTreeMap::from([(
            "web".into(),
            BTreeMap::from([(
                "plain-token".into(),
                system_credential_value("bootstrap-token"),
            )]),
        )]);
        let final_packages = BTreeSet::from(["web".to_string()]);

        let err = preflight_desired_credentials_at_root(
            &ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::System,
            },
            tmp.path(),
            &desired,
            &final_packages,
            &[installed],
            &[],
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("must be a regular file"),
            "{err:?}"
        );
    }

    #[test]
    fn materialize_package_credentials_writes_run_sources_only_to_live_root() {
        let tmp = TempDir::new().unwrap();
        let mut installed = installed_with_credentials();
        let expose = installed.apm.as_mut().unwrap().expose.as_mut().unwrap();
        expose.config.credentials[0].source = Some("/run/credstore/plain-token".into());
        let mut desired = BTreeMap::new();
        desired.insert("plain-token".into(), "transient".into());
        let mut restart = BTreeSet::new();

        let changed = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("run/credstore/plain-token")).unwrap(),
            "transient"
        );
        assert!(!tmp.path().join("var/etc/credstore/plain-token").exists());
    }

    #[test]
    fn materialize_package_credentials_reads_system_credential_sources() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let system_credential = tmp.path().join("run/credentials/@system/bootstrap-token");
        std::fs::create_dir_all(system_credential.parent().unwrap()).unwrap();
        std::fs::write(&system_credential, "from-system").unwrap();
        let mut desired = BTreeMap::new();
        desired.insert(
            "plain-token".into(),
            DesiredCredentialValue::Source(crate::desired::DesiredCredentialSource {
                system_credential: "bootstrap-token".into(),
            }),
        );
        let mut restart = BTreeSet::new();

        let changed = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/credstore/web/plain-token")).unwrap(),
            "from-system"
        );
        assert!(restart.contains("web.service"));
    }

    #[test]
    fn materialize_package_credentials_rejects_missing_system_credential_sources() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert(
            "plain-token".into(),
            DesiredCredentialValue::Source(crate::desired::DesiredCredentialSource {
                system_credential: "missing-token".into(),
            }),
        );
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("reading system credential 'missing-token'")
        );
    }

    #[test]
    fn materialize_package_credentials_rejects_symlink_system_credential_sources() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let system_credential = tmp.path().join("run/credentials/@system/bootstrap-token");
        std::fs::create_dir_all(system_credential.parent().unwrap()).unwrap();
        let target = tmp.path().join("bootstrap-token-target");
        std::fs::write(&target, "from-system").unwrap();
        std::os::unix::fs::symlink(&target, &system_credential).unwrap();
        let mut desired = BTreeMap::new();
        desired.insert(
            "plain-token".into(),
            DesiredCredentialValue::Source(crate::desired::DesiredCredentialSource {
                system_credential: "bootstrap-token".into(),
            }),
        );
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("must be a regular file"),
            "{err:?}"
        );
    }

    #[test]
    fn materialize_package_credentials_rejects_unknown_credential() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert("missing".into(), "value".into());
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown credential"));
    }

    #[test]
    fn materialize_package_credentials_rejects_inline_ciphertext_override() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert("inline-secret".into(), "value".into());
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not declare a credstore source")
        );
    }

    #[test]
    fn materialize_package_credentials_rejects_immutable_vendor_sources() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert("vendor-secret".into(), "value".into());
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(err.to_string().contains("immutable source path"));
    }

    #[test]
    fn materialize_package_credentials_rejects_generated_projection_sources() {
        let tmp = TempDir::new().unwrap();
        let mut installed = installed_with_credentials();
        let expose = installed.apm.as_mut().unwrap().expose.as_mut().unwrap();
        expose.config.credentials[3].source =
            Some("/run/credstore.encrypted/aos/web/vendor-secret".into());
        let mut desired = BTreeMap::new();
        desired.insert("vendor-secret".into(), "value".into());
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("AOS generated credential namespace")
        );
    }

    #[test]
    fn encrypted_credentials_require_signed_pcr_public_key() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_credentials();
        let mut desired = BTreeMap::new();
        desired.insert("join-token".into(), "secret".into());
        let mut restart = BTreeSet::new();

        let err = materialize_package_credentials(
            &ApmSettings::default(),
            tmp.path(),
            "web",
            &installed,
            Some(&desired),
            &mut restart,
        )
        .unwrap_err();

        assert!(err.to_string().contains("requires PCR public key"));
    }

    #[test]
    fn systemd_creds_encrypt_args_use_signed_pcr_policy() {
        let args = systemd_creds_encrypt_args(
            "join-token",
            Path::new("/etc/aos/pcr-sign.pem"),
            Path::new("/tmp/in"),
            Path::new("/tmp/out"),
            false,
        );
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "encrypt",
                "--name=join-token",
                "--with-key=tpm2",
                "--tpm2-public-key=/etc/aos/pcr-sign.pem",
                "--tpm2-public-key-pcrs=11",
                "/tmp/in",
                "/tmp/out",
            ]
        );
    }

    #[test]
    fn systemd_creds_encrypt_args_can_emit_pretty_unit_directive() {
        let args = systemd_creds_encrypt_args(
            "join-token",
            Path::new("/etc/aos/pcr-sign.pem"),
            Path::new("/tmp/in"),
            Path::new("-"),
            true,
        );
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "encrypt",
                "--name=join-token",
                "--with-key=tpm2",
                "--tpm2-public-key=/etc/aos/pcr-sign.pem",
                "--tpm2-public-key-pcrs=11",
                "--pretty",
                "/tmp/in",
                "-",
            ]
        );
    }
}
