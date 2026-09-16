//! Desired-package credential materialization.
//!
//! `apm install --system --from desired.toml` accepts package-scoped
//! credential values keyed by package and credential name. This module
//! validates typed configuration credential references, writes plaintext
//! credentials into the systemd plaintext credstore, and encrypts TPM2/signed-PCR
//! credentials into the encrypted credstore.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use rustix::fs::{FlockOperation, flock};

use crate::desired::DesiredCredentialValue;
use crate::secret_ref::SecretRef;
use crate::types::{ApmSettings, validate_credential_name};

const DEFAULT_CREDENTIAL_PCR_PUBLIC_KEY: &str = "/etc/aos/pcr-sign.pem";
const GENERATED_CREDENTIAL_RUN_PREFIX: &str = "/run/credstore.encrypted/aos";
const CREDENTIAL_TRANSACTION_ROOT: &str = "/var/lib/apm/credential-transactions";
const CREDENTIAL_TRANSACTION_SCHEMA: &str = "aos.credential-transaction/v1";

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
    validate_sealed_reference_path(package, &reference.name, &path)
}

fn validate_sealed_reference_in_view(
    root: &Path,
    candidate_etc: &Path,
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
    let source = Path::new(source);
    let path = if source.starts_with("/etc") {
        candidate_etc.join(source.strip_prefix("/etc")?)
    } else {
        rooted_absolute_path(root, source)?
    };
    validate_candidate_sealed_reference_path(package, &reference.name, &path)
}

fn validate_candidate_sealed_reference_path(package: &str, name: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "reading TPM2 credstore secretRef '{}.{}' from {}",
            package,
            name,
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "staged sealed credential source is not a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_sealed_reference_path(package: &str, name: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "reading TPM2 credstore secretRef '{}.{}' from {}",
            package,
            name,
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

pub(crate) fn validate_provisionable_source(
    package: &str,
    credential: &SecretRef,
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
    credential: &SecretRef,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let public_key = credential_pcr_public_key(settings, root)?;
    let args = systemd_creds_encrypt_args(
        &credential.name,
        &public_key,
        Path::new("-"),
        Path::new("-"),
        false,
    );
    let mut child = Command::new("systemd-creds")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting systemd-creds encrypt for desired credential")?;
    child
        .stdin
        .take()
        .context("systemd-creds stdin was not piped")?
        .write_all(plaintext)
        .context("streaming desired credential to systemd-creds")?;
    let output = child
        .wait_with_output()
        .context("waiting for systemd-creds encrypt")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "systemd-creds failed to encrypt credential '{}': {}{}",
            credential.name,
            output.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }
    Ok(output.stdout)
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
    let changed = credential_targets(root, source)?
        .iter()
        .any(|target| credential_target_changed(&target.path, bytes));
    let mut writes = BTreeMap::new();
    writes.insert(source.to_string(), bytes.to_vec());
    publish_credential_sources(root, writes, |_, _| Ok(()))?;
    Ok(changed)
}

fn credential_target_changed(path: &Path, bytes: &[u8]) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return true;
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return true;
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return true;
    }
    std::fs::read(path).map(|old| old != bytes).unwrap_or(true)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialTransactionEntry {
    target: PathBuf,
    staged: PathBuf,
    backup: Option<PathBuf>,
    #[serde(default)]
    delete: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum CredentialMutation {
    Write(Vec<u8>),
    Delete,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialTransactionState {
    Prepared,
    Committed,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialTransactionJournal {
    schema: String,
    boot_id: String,
    state: CredentialTransactionState,
    entries: Vec<CredentialTransactionEntry>,
}

/// Stages every target before mutating any target, then rolls the whole set
/// back if a later commit fails. The hook exists solely to exercise failures
/// at precise commit boundaries in unit tests.
fn publish_credential_sources<F>(
    root: &Path,
    sources: BTreeMap<String, Vec<u8>>,
    before_commit: F,
) -> Result<()>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
    publish_credential_sources_with(root, sources, BTreeSet::new(), before_commit, || Ok(()))
}

fn publish_credential_sources_with<F, G>(
    root: &Path,
    sources: BTreeMap<String, Vec<u8>>,
    deletions: BTreeSet<String>,
    mut before_commit: F,
    after_publish: G,
) -> Result<()>
where
    F: FnMut(usize, &Path) -> Result<()>,
    G: FnOnce() -> Result<()>,
{
    let _transaction_lock = acquire_credential_transaction_lock(root)?;
    let mut target_mutations = BTreeMap::<PathBuf, (CredentialTarget, CredentialMutation)>::new();
    for (source, bytes) in sources {
        for target in credential_targets(root, &source)? {
            match target_mutations.entry(target.path.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((target, CredentialMutation::Write(bytes.clone())));
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get().1 != CredentialMutation::Write(bytes.clone()) =>
                {
                    bail!(
                        "credential sources resolve target {} to conflicting byte values",
                        entry.key().display()
                    );
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }
    for source in deletions {
        for target in credential_targets(root, &source)? {
            match target_mutations.entry(target.path.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((target, CredentialMutation::Delete));
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get().1 != CredentialMutation::Delete =>
                {
                    bail!(
                        "credential source {} is scheduled for both replacement and removal",
                        entry.key().display()
                    );
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }

    recover_credential_transactions_unlocked(root)?;
    let mut staged = Vec::<(CredentialTransactionEntry, Option<Vec<u8>>)>::new();
    for (_, (target, mutation)) in target_mutations {
        ensure_secret_parent(&target)?;
        validate_existing_credential_target(&target.path)?;
        let (delete, bytes) = match mutation {
            CredentialMutation::Write(bytes) => {
                if !credential_target_changed(&target.path, &bytes) {
                    continue;
                }
                (false, Some(bytes))
            }
            CredentialMutation::Delete => {
                if !target.path.exists() {
                    continue;
                }
                (true, None)
            }
        };
        let parent = target.path.parent().with_context(|| {
            format!("credential target has no parent: {}", target.path.display())
        })?;
        let temp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("staging credential in {}", parent.display()))?;
        temp.as_file()
            .set_permissions(Permissions::from_mode(0o600))
            .with_context(|| format!("setting staged credential mode in {}", parent.display()))?;
        temp.as_file()
            .sync_all()
            .with_context(|| format!("syncing staged credential in {}", parent.display()))?;
        let (_, staged_path) = temp
            .keep()
            .with_context(|| format!("retaining staged credential in {}", parent.display()))?;
        let backup = if target.path.exists() {
            let placeholder = tempfile::NamedTempFile::new_in(parent)
                .with_context(|| format!("reserving credential backup in {}", parent.display()))?;
            let backup = placeholder.path().to_path_buf();
            placeholder
                .close()
                .with_context(|| format!("removing backup placeholder in {}", parent.display()))?;
            // Recovery interprets an existing backup as the old credential.
            // Make the placeholder deletion durable before journaling so a
            // power loss cannot resurrect an empty file as rollback data.
            sync_directory(parent)?;
            Some(backup)
        } else {
            None
        };
        staged.push((
            CredentialTransactionEntry {
                target: target.path,
                staged: staged_path,
                backup,
                delete,
            },
            bytes,
        ));
    }
    if staged.is_empty() {
        return after_publish();
    }

    let mut journal = CredentialTransactionJournal {
        schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
        boot_id: current_boot_id(),
        state: CredentialTransactionState::Prepared,
        entries: staged.iter().map(|(entry, _)| entry.clone()).collect(),
    };
    let journal_path = create_credential_transaction_journal(root, &journal)?;
    for (entry, bytes) in &staged {
        let Some(bytes) = bytes else {
            continue;
        };
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&entry.staged)
            .with_context(|| format!("opening staged credential {}", entry.staged.display()))?;
        if let Err(error) = file
            .write_all(bytes)
            .with_context(|| format!("writing staged credential {}", entry.staged.display()))
            .and_then(|()| file.sync_all().context("syncing staged credential"))
        {
            recover_credential_transaction(root, &journal_path)?;
            return Err(error);
        }
    }
    for (index, entry) in journal.entries.iter().enumerate() {
        if let Err(error) = before_commit(index, &entry.target) {
            recover_credential_transaction(root, &journal_path)?;
            return Err(error).context("credential publication aborted before commit");
        }
        if let Err(error) = commit_credential_transaction_entry(entry) {
            recover_credential_transaction(root, &journal_path)?;
            return Err(error);
        }
    }
    if let Err(error) = after_publish() {
        recover_credential_transaction(root, &journal_path)?;
        return Err(error).context("credential publication aborted before durable commit");
    }
    journal.state = CredentialTransactionState::Committed;
    replace_credential_transaction_journal(root, &journal_path, &journal)?;
    recover_credential_transaction(root, &journal_path)
}

fn commit_credential_transaction_entry(entry: &CredentialTransactionEntry) -> Result<()> {
    let parent = entry.target.parent().with_context(|| {
        format!(
            "credential target has no parent: {}",
            entry.target.display()
        )
    })?;
    if let Some(backup) = &entry.backup {
        std::fs::rename(&entry.target, backup)
            .with_context(|| format!("backing up credential target {}", entry.target.display()))?;
    }
    if entry.delete {
        remove_file_if_exists(&entry.staged)?;
    } else {
        std::fs::rename(&entry.staged, &entry.target)
            .with_context(|| format!("publishing credential target {}", entry.target.display()))?;
        std::fs::File::open(&entry.target)
            .with_context(|| format!("opening credential target {}", entry.target.display()))?
            .sync_all()
            .with_context(|| format!("syncing credential target {}", entry.target.display()))?;
    }
    sync_directory(parent)
}

/// Recovers every interrupted credential transaction before consumers start.
///
/// # Errors
///
/// Returns an error if the journal root or an entry is unsafe, a prepared
/// transaction cannot be rolled back, or a committed transaction cannot be
/// finalized durably.
pub(crate) fn recover_credential_transactions(root: &Path) -> Result<()> {
    let _transaction_lock = acquire_credential_transaction_lock(root)?;
    recover_credential_transactions_unlocked(root)
}

fn recover_credential_transactions_unlocked(root: &Path) -> Result<()> {
    let journal_root = credential_transaction_root(root)?;
    if !journal_root.exists() {
        return Ok(());
    }
    ensure_credential_transaction_root(root, &journal_root)?;
    let mut journals = std::fs::read_dir(&journal_root)
        .with_context(|| format!("reading {}", journal_root.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journals.sort_by_key(std::fs::DirEntry::file_name);
    for entry in journals {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "transaction.lock" {
            continue;
        }
        if name.starts_with(".preparing-") || name.starts_with(".update-") {
            remove_file_if_exists(&path)?;
            sync_directory(&journal_root)?;
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            bail!(
                "unexpected file in credential transaction root: {}",
                path.display()
            );
        }
        recover_credential_transaction(root, &path)?;
    }
    Ok(())
}

fn recover_credential_transaction(root: &Path, path: &Path) -> Result<()> {
    validate_transaction_journal_file(path)?;
    let journal: CredentialTransactionJournal = serde_json::from_slice(&std::fs::read(path)?)
        .with_context(|| format!("parsing credential transaction {}", path.display()))?;
    if journal.schema != CREDENTIAL_TRANSACTION_SCHEMA || journal.entries.is_empty() {
        bail!("invalid credential transaction journal {}", path.display());
    }
    let journal = resolve_credential_transaction_journal(root, journal)?;
    let same_boot = journal.boot_id == current_boot_id();
    let mut distinct_paths = BTreeSet::new();
    for entry in &journal.entries {
        validate_transaction_entry(root, entry)?;
        for entry_path in std::iter::once(&entry.target)
            .chain(std::iter::once(&entry.staged))
            .chain(entry.backup.iter())
        {
            if !distinct_paths.insert(entry_path) {
                bail!(
                    "credential transaction contains duplicate path {}",
                    entry_path.display()
                );
            }
        }
    }
    match journal.state {
        CredentialTransactionState::Prepared => {
            for entry in journal.entries.iter().rev() {
                if let Some(backup) = &entry.backup {
                    if backup.exists() {
                        std::fs::rename(backup, &entry.target).with_context(|| {
                            format!("restoring credential target {}", entry.target.display())
                        })?;
                    } else if !entry.staged.exists()
                        && (same_boot || credential_entry_is_persistent(root, entry))
                    {
                        bail!(
                            "prepared credential transaction lost its rollback backup for {}",
                            entry.target.display()
                        );
                    }
                } else if entry.staged.exists() {
                    if entry.target.exists() {
                        bail!(
                            "prepared credential transaction has both staged and target files for {}",
                            entry.target.display()
                        );
                    }
                } else if same_boot || credential_entry_is_persistent(root, entry) {
                    remove_file_if_exists(&entry.target)?;
                }
                remove_file_if_exists(&entry.staged)?;
                if (same_boot || credential_entry_is_persistent(root, entry))
                    && entry.target.is_file()
                {
                    secure_recovered_credential_target(&entry.target)?;
                }
                if let Some(parent) = entry.target.parent()
                    && parent.is_dir()
                {
                    sync_directory(parent)?;
                }
            }
        }
        CredentialTransactionState::Committed => {
            for entry in &journal.entries {
                if same_boot || credential_entry_is_persistent(root, entry) {
                    let complete = if entry.delete {
                        !entry.target.exists() && !entry.staged.exists()
                    } else {
                        entry.target.is_file() && !entry.staged.exists()
                    };
                    if !complete {
                        bail!(
                            "committed credential transaction is incomplete at {}",
                            entry.target.display()
                        );
                    }
                    if !entry.delete {
                        secure_recovered_credential_target(&entry.target)?;
                    }
                }
                if let Some(backup) = &entry.backup {
                    remove_file_if_exists(backup)?;
                }
                if let Some(parent) = entry.target.parent()
                    && parent.is_dir()
                {
                    sync_directory(parent)?;
                }
            }
        }
    }
    remove_file_if_exists(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn secure_recovered_credential_target(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("securing recovered credential {}", path.display()))?;
    std::fs::File::open(path)
        .with_context(|| format!("opening recovered credential {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing recovered credential {}", path.display()))
}

fn credential_transaction_root(root: &Path) -> Result<PathBuf> {
    rooted_absolute_path(root, Path::new(CREDENTIAL_TRANSACTION_ROOT))
}

fn ensure_credential_transaction_root(root: &Path, journal_root: &Path) -> Result<()> {
    ensure_secret_parent(&CredentialTarget {
        path: journal_root.join("journal"),
        directory_root: journal_root.to_path_buf(),
        filesystem_root: root.to_path_buf(),
    })
}

fn acquire_credential_transaction_lock(root: &Path) -> Result<std::fs::File> {
    let journal_root = credential_transaction_root(root)?;
    ensure_credential_transaction_root(root, &journal_root)?;
    let path = journal_root.join("transaction.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| format!("opening credential transaction lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("checking credential transaction lock {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || (metadata.uid() != 0 && !cfg!(test))
    {
        bail!(
            "credential transaction lock {} is not a root-owned regular file with mode 0600",
            path.display()
        );
    }
    flock(&file, FlockOperation::LockExclusive)
        .with_context(|| format!("locking credential transactions at {}", path.display()))?;
    Ok(file)
}

fn current_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

fn logical_credential_transaction_journal(
    root: &Path,
    journal: &CredentialTransactionJournal,
) -> Result<CredentialTransactionJournal> {
    let entries = journal
        .entries
        .iter()
        .map(|entry| {
            Ok(CredentialTransactionEntry {
                target: logical_transaction_path(root, &entry.target)?,
                staged: logical_transaction_path(root, &entry.staged)?,
                backup: entry
                    .backup
                    .as_deref()
                    .map(|path| logical_transaction_path(root, path))
                    .transpose()?,
                delete: entry.delete,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CredentialTransactionJournal {
        schema: journal.schema.clone(),
        boot_id: journal.boot_id.clone(),
        state: journal.state,
        entries,
    })
}

fn resolve_credential_transaction_journal(
    root: &Path,
    journal: CredentialTransactionJournal,
) -> Result<CredentialTransactionJournal> {
    let entries = journal
        .entries
        .into_iter()
        .map(|entry| {
            Ok(CredentialTransactionEntry {
                target: resolve_transaction_path(root, &entry.target)?,
                staged: resolve_transaction_path(root, &entry.staged)?,
                backup: entry
                    .backup
                    .as_deref()
                    .map(|path| resolve_transaction_path(root, path))
                    .transpose()?,
                delete: entry.delete,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CredentialTransactionJournal {
        schema: journal.schema,
        boot_id: journal.boot_id,
        state: journal.state,
        entries,
    })
}

fn logical_transaction_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "credential transaction path {} escapes root {}",
            path.display(),
            root.display()
        )
    })?;
    Ok(Path::new("/").join(relative))
}

fn resolve_transaction_path(root: &Path, path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("credential transaction journal contains an unsafe path");
    }
    rooted_absolute_path(root, path)
}

fn credential_entry_is_persistent(root: &Path, entry: &CredentialTransactionEntry) -> bool {
    entry.target.starts_with(root.join("var/etc/credstore"))
        || entry
            .target
            .starts_with(root.join("var/etc/credstore.encrypted"))
}

fn create_credential_transaction_journal(
    root: &Path,
    journal: &CredentialTransactionJournal,
) -> Result<PathBuf> {
    let journal_root = credential_transaction_root(root)?;
    ensure_credential_transaction_root(root, &journal_root)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".preparing-")
        .tempfile_in(&journal_root)
        .with_context(|| format!("creating journal in {}", journal_root.display()))?;
    let journal = logical_credential_transaction_journal(root, journal)?;
    write_credential_transaction_journal(temp.as_file_mut(), &journal)?;
    let id = temp
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(".preparing-"))
        .context("temporary credential journal has an invalid name")?;
    let path = journal_root.join(format!("transaction-{id}.json"));
    temp.persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing journal in {}", journal_root.display()))?;
    sync_directory(&journal_root)?;
    Ok(path)
}

fn replace_credential_transaction_journal(
    root: &Path,
    path: &Path,
    journal: &CredentialTransactionJournal,
) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("journal {} has no parent", path.display()))?;
    let mut temp = tempfile::Builder::new()
        .prefix(".update-")
        .tempfile_in(parent)
        .with_context(|| format!("staging journal update in {}", parent.display()))?;
    let journal = logical_credential_transaction_journal(root, journal)?;
    write_credential_transaction_journal(temp.as_file_mut(), &journal)?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing journal update {}", path.display()))?;
    sync_directory(parent)
}

fn write_credential_transaction_journal(
    file: &mut std::fs::File,
    journal: &CredentialTransactionJournal,
) -> Result<()> {
    serde_json::to_writer(&mut *file, journal).context("serializing credential transaction")?;
    file.set_permissions(Permissions::from_mode(0o600))
        .context("setting credential transaction journal mode")?;
    file.sync_all()
        .context("syncing credential transaction journal")
}

fn validate_transaction_journal_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("checking credential transaction {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "credential transaction {} is not a regular file",
            path.display()
        );
    }
    if metadata.uid() != 0 && !cfg!(test) {
        bail!(
            "credential transaction {} is not owned by root",
            path.display()
        );
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!(
            "credential transaction {} does not have mode 0600",
            path.display()
        );
    }
    Ok(())
}

fn validate_transaction_entry(root: &Path, entry: &CredentialTransactionEntry) -> Result<()> {
    let allowed_roots = [
        root.join("run/credstore"),
        root.join("run/credstore.encrypted"),
        root.join("etc/credstore"),
        root.join("etc/credstore.encrypted"),
        root.join("var/etc/credstore"),
        root.join("var/etc/credstore.encrypted"),
    ];
    if !allowed_roots
        .iter()
        .any(|prefix| entry.target != *prefix && entry.target.starts_with(prefix))
    {
        bail!(
            "credential transaction target is outside managed roots: {}",
            entry.target.display()
        );
    }
    let parent = entry.target.parent().with_context(|| {
        format!(
            "credential target has no parent: {}",
            entry.target.display()
        )
    })?;
    validate_secret_parent_components(root, parent)?;
    if entry.staged.parent() != Some(parent)
        || entry
            .backup
            .as_deref()
            .is_some_and(|path| path.parent() != Some(parent))
        || entry.staged == entry.target
        || entry.backup.as_ref() == Some(&entry.target)
    {
        bail!("credential transaction contains an unsafe staging path");
    }
    for path in std::iter::once(&entry.target)
        .chain(std::iter::once(&entry.staged))
        .chain(entry.backup.iter())
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    bail!(
                        "credential transaction path is not regular: {}",
                        path.display()
                    );
                }
                if metadata.uid() != 0 && !cfg!(test) {
                    bail!(
                        "credential transaction path is not root-owned: {}",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("checking transaction path {}", path.display()));
            }
        }
    }
    Ok(())
}

fn validate_secret_parent_components(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent.strip_prefix(root).with_context(|| {
        format!(
            "credential transaction parent {} escapes root {}",
            parent.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("credential transaction parent contains an unsafe path component");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    bail!(
                        "credential transaction directory {} is not a real directory",
                        current.display()
                    );
                }
                if metadata.uid() != 0 && !cfg!(test) {
                    bail!(
                        "credential transaction directory {} is not owned by root",
                        current.display()
                    );
                }
                if metadata.permissions().mode() & 0o022 != 0 {
                    bail!(
                        "credential transaction directory {} is group- or world-writable",
                        current.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("checking transaction directory {}", current.display())
                });
            }
        }
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn ensure_secret_parent(target: &CredentialTarget) -> Result<()> {
    let parent = target
        .path
        .parent()
        .with_context(|| format!("credential target has no parent: {}", target.path.display()))?;
    let relative = parent
        .strip_prefix(&target.filesystem_root)
        .with_context(|| {
            format!(
                "credential parent {} escapes managed root {}",
                parent.display(),
                target.filesystem_root.display()
            )
        })?;
    let mut current = target.filesystem_root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("credential target contains an unsafe path component");
        };
        current.push(component);
        ensure_real_secret_directory(&current, current.starts_with(&target.directory_root))?;
    }
    Ok(())
}

fn ensure_real_secret_directory(path: &Path, managed: bool) -> Result<()> {
    let created = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                bail!(
                    "credential directory {} is not a real directory",
                    path.display()
                );
            }
            if metadata.uid() != 0 && !cfg!(test) {
                bail!(
                    "credential directory {} is not owned by root",
                    path.display()
                );
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                bail!(
                    "credential directory {} is group- or world-writable",
                    path.display()
                );
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path)
                .with_context(|| format!("creating credential directory {}", path.display()))?;
            true
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("checking credential directory {}", path.display()));
        }
    };
    if managed {
        std::fs::set_permissions(path, Permissions::from_mode(0o700))
            .with_context(|| format!("setting mode on {}", path.display()))?;
        sync_directory(path)?;
    }
    if created && let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_existing_credential_target(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                bail!("credential target {} is not a regular file", path.display());
            }
            if metadata.uid() != 0 && !cfg!(test) {
                bail!("credential target {} is not owned by root", path.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("checking credential target {}", path.display()))
        }
    }
}

#[derive(Debug)]
struct CredentialTarget {
    path: PathBuf,
    directory_root: PathBuf,
    filesystem_root: PathBuf,
}

fn credential_targets(root: &Path, source: &str) -> Result<Vec<CredentialTarget>> {
    let source = Path::new(source);
    if source
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!(
            "credential source must not contain '..': {}",
            source.display()
        );
    }
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
            filesystem_root: root.to_path_buf(),
        }]);
    }
    if is_under(source, Path::new("/run/credstore")) {
        return Ok(vec![CredentialTarget {
            path: rooted_absolute_path(root, source)?,
            directory_root: root.join("run/credstore"),
            filesystem_root: root.to_path_buf(),
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
            filesystem_root: root.to_path_buf(),
        },
        CredentialTarget {
            path: etc_prefix.join(rel),
            directory_root: etc_prefix,
            filesystem_root: root.to_path_buf(),
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
    use tempfile::TempDir;
    #[test]
    fn credential_publication_rolls_back_every_earlier_target_on_late_failure() {
        let tmp = TempDir::new().unwrap();
        let first = tmp.path().join("run/credstore/alpha");
        let second = tmp.path().join("run/credstore/beta");
        std::fs::create_dir_all(first.parent().unwrap()).unwrap();
        std::fs::write(&first, b"old-alpha").unwrap();
        std::fs::write(&second, b"old-beta").unwrap();
        std::fs::set_permissions(&first, Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&second, Permissions::from_mode(0o600)).unwrap();

        let sources = BTreeMap::from([
            ("/run/credstore/alpha".to_string(), b"new-alpha".to_vec()),
            ("/run/credstore/beta".to_string(), b"new-beta".to_vec()),
        ]);
        let error = publish_credential_sources(tmp.path(), sources, |index, _| {
            if index == 1 {
                bail!("injected late commit failure");
            }
            Ok(())
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected late commit failure"));
        assert_eq!(std::fs::read(first).unwrap(), b"old-alpha");
        assert_eq!(std::fs::read(second).unwrap(), b"old-beta");
    }

    #[test]
    fn credential_removal_is_transactional_and_rollback_capable() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("run/credstore/obsolete");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"old-secret").unwrap();
        std::fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();

        let error = publish_credential_sources_with(
            tmp.path(),
            BTreeMap::new(),
            BTreeSet::from(["/run/credstore/obsolete".to_string()]),
            |_, _| Ok(()),
            || bail!("injected plan failure"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected plan failure"));
        assert_eq!(std::fs::read(&target).unwrap(), b"old-secret");

        publish_credential_sources_with(
            tmp.path(),
            BTreeMap::new(),
            BTreeSet::from(["/run/credstore/obsolete".to_string()]),
            |_, _| Ok(()),
            || Ok(()),
        )
        .unwrap();
        assert!(!target.exists());
    }

    #[test]
    fn credential_publication_rejects_symlinked_destination_directory() {
        let tmp = TempDir::new().unwrap();
        let run = tmp.path().join("run");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, run.join("credstore")).unwrap();

        let error = publish_credential_sources(
            tmp.path(),
            BTreeMap::from([("/run/credstore/token".to_string(), b"secret".to_vec())]),
            |_, _| Ok(()),
        )
        .unwrap_err();

        assert!(error.to_string().contains("is not a real directory"));
        assert!(!outside.join("token").exists());
    }

    #[test]
    fn credential_targets_reject_parent_directory_components() {
        let tmp = TempDir::new().unwrap();
        let error = credential_targets(tmp.path(), "/run/credstore/../escaped").unwrap_err();
        assert!(error.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn prepared_journal_recovers_old_bytes_after_every_committed_prefix() {
        for committed_prefix in 0..=2 {
            let tmp = TempDir::new().unwrap();
            let parent = tmp.path().join("run/credstore");
            std::fs::create_dir_all(&parent).unwrap();
            let mut entries = Vec::new();
            for (name, old, new) in [
                ("alpha", b"old-alpha".as_slice(), b"new-alpha".as_slice()),
                ("beta", b"old-beta".as_slice(), b"new-beta".as_slice()),
            ] {
                let target = parent.join(name);
                let staged = parent.join(format!(".{name}.staged"));
                let backup = parent.join(format!(".{name}.backup"));
                std::fs::write(&target, old).unwrap();
                std::fs::write(&staged, new).unwrap();
                for path in [&target, &staged] {
                    std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
                }
                entries.push(CredentialTransactionEntry {
                    target,
                    staged,
                    backup: Some(backup),
                    delete: false,
                });
            }
            let journal = CredentialTransactionJournal {
                schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
                boot_id: current_boot_id(),
                state: CredentialTransactionState::Prepared,
                entries,
            };
            let journal_path = create_credential_transaction_journal(tmp.path(), &journal).unwrap();
            for entry in journal.entries.iter().take(committed_prefix) {
                commit_credential_transaction_entry(entry).unwrap();
            }

            recover_credential_transactions(tmp.path()).unwrap();

            assert_eq!(std::fs::read(parent.join("alpha")).unwrap(), b"old-alpha");
            assert_eq!(std::fs::read(parent.join("beta")).unwrap(), b"old-beta");
            assert!(!journal_path.exists());
            for entry in &journal.entries {
                assert!(!entry.staged.exists());
                assert!(!entry.backup.as_ref().unwrap().exists());
            }
        }
    }

    #[test]
    fn committed_journal_recovers_new_bytes_and_discards_backups() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("run/credstore");
        std::fs::create_dir_all(&parent).unwrap();
        let target = parent.join("token");
        let staged = parent.join(".token.staged");
        let backup = parent.join(".token.backup");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        for path in [&target, &staged] {
            std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        }
        let mut journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: current_boot_id(),
            state: CredentialTransactionState::Prepared,
            entries: vec![CredentialTransactionEntry {
                target: target.clone(),
                staged,
                backup: Some(backup.clone()),
                delete: false,
            }],
        };
        let journal_path = create_credential_transaction_journal(tmp.path(), &journal).unwrap();
        commit_credential_transaction_entry(&journal.entries[0]).unwrap();
        journal.state = CredentialTransactionState::Committed;
        replace_credential_transaction_journal(tmp.path(), &journal_path, &journal).unwrap();

        recover_credential_transactions(tmp.path()).unwrap();

        assert_eq!(std::fs::read(target).unwrap(), b"new");
        assert!(!backup.exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn prepared_journal_removes_a_new_target_without_an_original() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("run/credstore");
        std::fs::create_dir_all(&parent).unwrap();
        let target = parent.join("token");
        let staged = parent.join(".token.staged");
        std::fs::write(&staged, b"new").unwrap();
        std::fs::set_permissions(&staged, Permissions::from_mode(0o600)).unwrap();
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: current_boot_id(),
            state: CredentialTransactionState::Prepared,
            entries: vec![CredentialTransactionEntry {
                target: target.clone(),
                staged,
                backup: None,
                delete: false,
            }],
        };
        create_credential_transaction_journal(tmp.path(), &journal).unwrap();
        commit_credential_transaction_entry(&journal.entries[0]).unwrap();

        recover_credential_transactions(tmp.path()).unwrap();

        assert!(!target.exists());
    }

    #[test]
    fn prepared_recovery_fails_closed_when_rollback_backup_is_ambiguous() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("var/etc/credstore");
        std::fs::create_dir_all(&parent).unwrap();
        let target = parent.join("token");
        let staged = parent.join(".token.staged");
        let backup = parent.join(".token.backup");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, Permissions::from_mode(0o644)).unwrap();
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: "prior-boot".to_string(),
            state: CredentialTransactionState::Prepared,
            entries: vec![CredentialTransactionEntry {
                target: target.clone(),
                staged,
                backup: Some(backup),
                delete: false,
            }],
        };
        let journal_path = create_credential_transaction_journal(tmp.path(), &journal).unwrap();

        let error = recover_credential_transactions(tmp.path()).unwrap_err();

        assert!(format!("{error:#}").contains("lost its rollback backup"));
        assert_eq!(std::fs::read(target).unwrap(), b"old");
        assert!(journal_path.exists());
    }

    #[test]
    fn prepared_deletion_is_rolled_back_after_target_rename() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("var/etc/credstore");
        std::fs::create_dir_all(&parent).unwrap();
        let target = parent.join("obsolete");
        let staged = parent.join(".obsolete.staged");
        let backup = parent.join(".obsolete.backup");
        std::fs::write(&target, b"old-secret").unwrap();
        std::fs::write(&staged, b"").unwrap();
        for path in [&target, &staged] {
            std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        }
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: current_boot_id(),
            state: CredentialTransactionState::Prepared,
            entries: vec![CredentialTransactionEntry {
                target: target.clone(),
                staged,
                backup: Some(backup),
                delete: true,
            }],
        };
        create_credential_transaction_journal(tmp.path(), &journal).unwrap();
        commit_credential_transaction_entry(&journal.entries[0]).unwrap();

        recover_credential_transactions(tmp.path()).unwrap();

        assert_eq!(std::fs::read(target).unwrap(), b"old-secret");
    }

    #[test]
    fn recovery_rejects_symlinked_journal_root() {
        let tmp = TempDir::new().unwrap();
        let apm = tmp.path().join("var/lib/apm");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&apm).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, apm.join("credential-transactions")).unwrap();

        let error = recover_credential_transactions(tmp.path()).unwrap_err();

        assert!(format!("{error:#}").contains("is not a real directory"));
    }

    #[test]
    fn recovery_rejects_symlinked_journal_file() {
        let tmp = TempDir::new().unwrap();
        let journal_root = credential_transaction_root(tmp.path()).unwrap();
        ensure_credential_transaction_root(tmp.path(), &journal_root).unwrap();
        let outside = tmp.path().join("outside.json");
        std::fs::write(&outside, b"{}").unwrap();
        std::fs::set_permissions(&outside, Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&outside, journal_root.join("transaction-evil.json")).unwrap();

        let error = recover_credential_transactions(tmp.path()).unwrap_err();

        assert!(format!("{error:#}").contains("is not a regular file"));
    }

    #[test]
    fn recovery_removes_incomplete_journal_updates() {
        let tmp = TempDir::new().unwrap();
        let journal_root = credential_transaction_root(tmp.path()).unwrap();
        ensure_credential_transaction_root(tmp.path(), &journal_root).unwrap();
        let preparing = journal_root.join(".preparing-interrupted");
        let update = journal_root.join(".update-interrupted");
        std::fs::write(&preparing, b"partial").unwrap();
        std::fs::write(&update, b"partial").unwrap();

        recover_credential_transactions(tmp.path()).unwrap();

        assert!(!preparing.exists());
        assert!(!update.exists());
    }

    #[test]
    fn recovery_rejects_overlapping_transaction_paths() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("run/credstore");
        std::fs::create_dir_all(&parent).unwrap();
        let target = parent.join("token");
        let staged = parent.join(".token.staged");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        for path in [&target, &staged] {
            std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        }
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: current_boot_id(),
            state: CredentialTransactionState::Prepared,
            entries: vec![
                CredentialTransactionEntry {
                    target: target.clone(),
                    staged: staged.clone(),
                    backup: None,
                    delete: false,
                },
                CredentialTransactionEntry {
                    target,
                    staged,
                    backup: None,
                    delete: false,
                },
            ],
        };
        create_credential_transaction_journal(tmp.path(), &journal).unwrap();

        let error = recover_credential_transactions(tmp.path()).unwrap_err();

        assert!(error.to_string().contains("duplicate path"));
    }

    #[test]
    fn recovery_rejects_symlinked_transaction_parent() {
        let tmp = TempDir::new().unwrap();
        let run = tmp.path().join("run");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, run.join("credstore")).unwrap();
        let target = run.join("credstore/token");
        let staged = run.join("credstore/.token.staged");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        for path in [&target, &staged] {
            std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        }
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: current_boot_id(),
            state: CredentialTransactionState::Prepared,
            entries: vec![CredentialTransactionEntry {
                target,
                staged,
                backup: None,
                delete: false,
            }],
        };
        create_credential_transaction_journal(tmp.path(), &journal).unwrap();

        let error = recover_credential_transactions(tmp.path()).unwrap_err();

        assert!(error.to_string().contains("is not a real directory"));
        assert_eq!(std::fs::read(outside.join("token")).unwrap(), b"old");
    }

    #[test]
    fn next_boot_uses_persistent_source_as_authority_when_mirrors_vanish() {
        let tmp = TempDir::new().unwrap();
        let mut entries = Vec::new();
        for prefix in ["var/etc/credstore", "etc/credstore", "run/credstore"] {
            let parent = tmp.path().join(prefix);
            std::fs::create_dir_all(&parent).unwrap();
            let target = parent.join("token");
            let staged = parent.join(".token.staged");
            let backup = parent.join(".token.backup");
            std::fs::write(&target, b"old").unwrap();
            std::fs::write(&staged, b"new").unwrap();
            for path in [&target, &staged] {
                std::fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
            }
            entries.push(CredentialTransactionEntry {
                target,
                staged,
                backup: Some(backup),
                delete: false,
            });
        }
        let journal = CredentialTransactionJournal {
            schema: CREDENTIAL_TRANSACTION_SCHEMA.to_string(),
            boot_id: "prior-boot".to_string(),
            state: CredentialTransactionState::Prepared,
            entries,
        };
        let journal_path = create_credential_transaction_journal(tmp.path(), &journal).unwrap();
        for entry in &journal.entries {
            commit_credential_transaction_entry(entry).unwrap();
        }
        std::fs::remove_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::remove_dir_all(tmp.path().join("run")).unwrap();

        recover_credential_transactions(tmp.path()).unwrap();

        assert_eq!(
            std::fs::read(tmp.path().join("var/etc/credstore/token")).unwrap(),
            b"old"
        );
        assert!(!journal_path.exists());
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
