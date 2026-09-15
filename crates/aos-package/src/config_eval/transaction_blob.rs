//! Durable transaction-local byte transport for package-owned handlers.
//!
//! Large runtime values do not cross the JSON command-handler envelope. A
//! handler writes one named slot below the private output directory supplied by
//! the runtime. The runtime copies those bytes into its durable transaction
//! directory, derives the content identity and bounded handle, and exposes only
//! references present in a later checked invocation through a private input
//! directory. No filesystem path enters a plan, journal, or provider result.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aos_ability_model::{AbilityValue, LocalKey, TransactionId};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    DurableRequest, MAX_TRANSACTION_BLOB_BYTES, TRANSACTION_BLOB_INPUT_DIRECTORY_ENV,
    TRANSACTION_BLOB_OUTPUT_DIRECTORY_ENV, TRANSACTION_BLOB_OUTPUT_TYPE,
    TRANSACTION_BLOB_REFERENCE_TYPE, TransactionBlobOutput, TransactionBlobReference,
};

const BLOB_DIRECTORY: &str = "transaction-blobs";
const INPUT_DIRECTORY: &str = "inputs";
const NAMESPACE_DIRECTORY: &str = "invocations";
const OBJECT_DIRECTORY: &str = "objects";
const OUTPUT_DIRECTORY: &str = "outputs";
const HANDLE_DOMAIN: &str = "aos.ability.transaction-blob-handle/v1";
const INVOCATION_DOMAIN: &str = "aos.ability.transaction-blob-invocation/v1";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Owns transaction-local blobs below one protected ability transaction.
#[derive(Clone, Debug)]
pub(crate) struct TransactionBlobStore {
    transaction: TransactionId,
    root: PathBuf,
}

/// Supplies the private blob directories for one handler invocation.
pub(crate) struct TransactionBlobInvocation {
    output: PathBuf,
    input: PathBuf,
}

impl TransactionBlobInvocation {
    /// Returns the exact environment additions for the cleared handler process.
    pub(crate) fn environment(&self) -> Vec<(OsString, OsString)> {
        vec![
            (
                OsString::from(TRANSACTION_BLOB_INPUT_DIRECTORY_ENV),
                self.input.as_os_str().to_owned(),
            ),
            (
                OsString::from(TRANSACTION_BLOB_OUTPUT_DIRECTORY_ENV),
                self.output.as_os_str().to_owned(),
            ),
        ]
    }
}

impl TransactionBlobStore {
    /// Opens the blob store beneath an already protected transaction directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction directory is not a real private
    /// directory or the runtime cannot durably create its blob subdirectories.
    pub(crate) fn open(
        transaction_directory: &Path,
        transaction: &TransactionId,
    ) -> std::io::Result<Self> {
        require_real_directory(transaction_directory)?;
        let root = transaction_directory.join(BLOB_DIRECTORY);
        create_private_directory(&root)?;
        create_private_directory(&root.join(NAMESPACE_DIRECTORY))?;
        create_private_directory(&root.join(OBJECT_DIRECTORY))?;
        sync_directory(transaction_directory)?;

        Ok(Self {
            transaction: transaction.clone(),
            root,
        })
    }

    /// Prepares exactly the blobs referenced by one checked durable request.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference names another transaction, an object
    /// is missing or changed, or private invocation directories cannot be made.
    pub(crate) fn prepare(
        &self,
        request: &DurableRequest,
    ) -> std::io::Result<TransactionBlobInvocation> {
        let namespace = Sha256Digest::of_canonical(INVOCATION_DOMAIN, request)
            .map_err(invalid)?
            .hex();
        let namespace = self.root.join(NAMESPACE_DIRECTORY).join(namespace);
        let input = namespace.join(INPUT_DIRECTORY);
        let output = namespace.join(OUTPUT_DIRECTORY);
        create_private_directory(&namespace)?;
        create_private_directory(&input)?;
        create_private_directory(&output)?;

        let references = collect_references(request.inputs.as_json())?;
        retain_only(
            &input,
            references.iter().map(|reference| reference.handle.as_str()),
        )?;
        for reference in references {
            self.expose_reference(&input, &reference)?;
        }
        sync_directory(&input)?;

        Ok(TransactionBlobInvocation { output, input })
    }

    /// Replaces handler output-slot markers with runtime-derived blob references.
    ///
    /// # Errors
    ///
    /// Returns an error when a marker is malformed, its slot is absent or not a
    /// regular file, its bytes exceed the bound, or durable publication fails.
    pub(crate) fn finalize_outputs(
        &self,
        invocation: &TransactionBlobInvocation,
        outputs: &mut std::collections::BTreeMap<LocalKey, AbilityValue>,
    ) -> std::io::Result<()> {
        for value in outputs.values_mut() {
            let transformed = self.finalize_value(&invocation.output, value.as_json())?;
            *value = AbilityValue::new(transformed).map_err(invalid)?;
        }
        Ok(())
    }

    fn finalize_value(
        &self,
        output: &Path,
        value: &serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        if value.get("_type").and_then(serde_json::Value::as_str)
            == Some(TRANSACTION_BLOB_OUTPUT_TYPE)
        {
            let marker: TransactionBlobOutput =
                serde_json::from_value(value.clone()).map_err(invalid)?;
            if marker.kind != TRANSACTION_BLOB_OUTPUT_TYPE {
                return Err(invalid("transaction blob output has an unsupported type"));
            }
            return serde_json::to_value(self.commit_slot(output, &marker.slot)?).map_err(invalid);
        }

        match value {
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| self.finalize_value(output, value))
                .collect::<std::io::Result<Vec<_>>>()
                .map(serde_json::Value::Array),
            serde_json::Value::Object(values) => values
                .iter()
                .map(|(name, value)| Ok((name.clone(), self.finalize_value(output, value)?)))
                .collect::<std::io::Result<serde_json::Map<_, _>>>()
                .map(serde_json::Value::Object),
            _ => Ok(value.clone()),
        }
    }

    fn commit_slot(
        &self,
        output: &Path,
        slot: &LocalKey,
    ) -> std::io::Result<TransactionBlobReference> {
        require_real_directory(output)?;
        let source = output.join(slot.as_str());
        let bytes = read_bounded_regular(&source)?;
        let content_sha256 = Sha256Digest::of_bytes(&bytes);
        let size_bytes = u64::try_from(bytes.len()).map_err(invalid)?;
        let handle_digest = Sha256Digest::of_canonical(
            HANDLE_DOMAIN,
            &serde_json::json!({
                "transaction": self.transaction,
                "slot": slot,
                "content_sha256": content_sha256,
                "size_bytes": size_bytes,
            }),
        )
        .map_err(invalid)?;
        let handle = LocalKey::new(format!("blob-{}", handle_digest.hex())).map_err(invalid)?;
        let destination = self.root.join(OBJECT_DIRECTORY).join(handle.as_str());
        publish_immutable(&destination, &bytes)?;
        remove_regular_if_present(&source)?;

        Ok(TransactionBlobReference {
            kind: TRANSACTION_BLOB_REFERENCE_TYPE.into(),
            transaction: self.transaction.clone(),
            handle,
            content_sha256,
            size_bytes,
        })
    }

    fn expose_reference(
        &self,
        input: &Path,
        reference: &TransactionBlobReference,
    ) -> std::io::Result<()> {
        require_real_directory(input)?;
        if reference.kind != TRANSACTION_BLOB_REFERENCE_TYPE
            || reference.transaction != self.transaction
            || reference.size_bytes > MAX_TRANSACTION_BLOB_BYTES
        {
            return Err(invalid(
                "transaction blob reference is outside the current transaction",
            ));
        }
        let source = self
            .root
            .join(OBJECT_DIRECTORY)
            .join(reference.handle.as_str());
        let bytes = read_bounded_regular(&source)?;
        if u64::try_from(bytes.len()).map_err(invalid)? != reference.size_bytes
            || Sha256Digest::of_bytes(&bytes) != reference.content_sha256
        {
            return Err(invalid(
                "transaction blob bytes differ from their reference",
            ));
        }
        let destination = input.join(reference.handle.as_str());
        remove_regular_if_present(&destination)?;
        publish_immutable(&destination, &bytes)
    }
}

fn collect_references(value: &serde_json::Value) -> std::io::Result<Vec<TransactionBlobReference>> {
    let mut references = Vec::new();
    collect_references_into(value, &mut references)?;
    references.sort_by(|left, right| left.handle.cmp(&right.handle));
    for pair in references.windows(2) {
        if pair[0].handle == pair[1].handle && pair[0] != pair[1] {
            return Err(invalid(
                "transaction blob handle has conflicting authenticated references",
            ));
        }
    }
    references.dedup();
    Ok(references)
}

fn collect_references_into(
    value: &serde_json::Value,
    references: &mut Vec<TransactionBlobReference>,
) -> std::io::Result<()> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_references_into(value, references)?;
            }
        }
        serde_json::Value::Object(values) => {
            if values.get("_type").and_then(serde_json::Value::as_str)
                == Some(TRANSACTION_BLOB_REFERENCE_TYPE)
            {
                references.push(serde_json::from_value(value.clone()).map_err(invalid)?);
                return Ok(());
            }
            for value in values.values() {
                collect_references_into(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn retain_only<'a>(
    directory: &Path,
    expected: impl Iterator<Item = &'a str>,
) -> std::io::Result<()> {
    let expected = expected.collect::<BTreeSet<_>>();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid("transaction blob input name is not UTF-8"));
        };
        if !expected.contains(name) {
            let metadata = entry.file_type()?;
            if !metadata.is_file() || metadata.is_symlink() {
                return Err(invalid("transaction blob input is not a regular file"));
            }
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn read_bounded_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("transaction blob is not a regular file"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_TRANSACTION_BLOB_BYTES {
        return Err(invalid("transaction blob exceeds its size bound"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    std::io::Read::by_ref(&mut file)
        .take(MAX_TRANSACTION_BLOB_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BLOB_BYTES {
        return Err(invalid("transaction blob exceeds its size bound"));
    }
    Ok(bytes)
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("transaction blob object has no parent"))?;
    require_real_directory(parent)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("transaction blob object name is not UTF-8"))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_bounded_regular(path)? != bytes {
                let _ = fs::remove_file(&temporary);
                return Err(invalid(
                    "transaction blob handle conflicts with retained bytes",
                ));
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)
}

fn remove_regular_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(invalid("transaction blob output is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    require_real_directory(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "transaction blob directory is not a real directory",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    use std::num::NonZeroU32;

    use aos_ability_model::{
        AbilityValue, EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName,
        MethodReference, MethodSemantics, ResourceId, ResourceLifetime, ResourceReference,
    };
    use aos_provider_protocol::{REQUEST_SCHEMA, RecoveryMethods};

    use super::*;

    fn transaction() -> TransactionId {
        TransactionId(LocalKey::new("transaction-1").expect("transaction key"))
    }

    fn request(inputs: serde_json::Value) -> DurableRequest {
        let interface = InterfaceKey {
            name: InterfaceName::new("aos.test.blob").expect("interface name"),
            abi: NonZeroU32::new(1).expect("nonzero ABI"),
            descriptor: Sha256Digest::of_bytes(b"interface"),
        };
        DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            method: MethodReference {
                interface: interface.clone(),
                method: LocalKey::new("write").expect("method key"),
            },
            semantics: MethodSemantics {
                required_target_access: aos_ability_model::AccessMode::ExclusiveWrite,
                stops_provider: false,
            },
            recovery: RecoveryMethods {
                reconcile: None,
                cancel: None,
                compensate: None,
            },
            target: ResourceReference {
                interface,
                resource: ResourceId {
                    provider: InstanceId {
                        environment: EnvironmentId {
                            authority: LocalKey::new("test").expect("authority key"),
                            key: LocalKey::new("environment").expect("environment key"),
                            stage: ExecutionStage::Host,
                        },
                        key: LocalKey::new("provider").expect("provider key"),
                    },
                    key: LocalKey::new("resource").expect("resource key"),
                },
                operations: vec![LocalKey::new("write").expect("operation key")],
                lifetime: ResourceLifetime::Transaction,
            },
            inputs: AbilityValue::new(inputs).expect("inputs"),
            resources: Vec::new(),
            native_context_digest: Sha256Digest::of_bytes(b"contexts"),
        }
    }

    #[test]
    fn output_slot_becomes_a_checked_transaction_reference() {
        let temporary = tempfile::tempdir().expect("temporary transaction");
        let store =
            TransactionBlobStore::open(temporary.path(), &transaction()).expect("blob store");
        let producer_request = request(serde_json::json!({}));
        let invocation = store
            .prepare(&producer_request)
            .expect("invocation directories");
        fs::write(invocation.output.join("manifest"), b"canonical manifest").expect("slot bytes");
        let mut outputs = BTreeMap::from([(
            LocalKey::new("result").expect("output key"),
            AbilityValue::new(serde_json::json!({
                "_type": TRANSACTION_BLOB_OUTPUT_TYPE,
                "slot": "manifest",
            }))
            .expect("slot marker"),
        )]);

        store
            .finalize_outputs(&invocation, &mut outputs)
            .expect("finalized outputs");
        let reference: TransactionBlobReference =
            serde_json::from_value(outputs["result"].as_json().clone())
                .expect("transaction blob reference");
        assert_eq!(reference.transaction, transaction());
        assert_eq!(reference.size_bytes, 18);

        let handle = reference.handle.clone();
        let recovered = store
            .prepare(&producer_request)
            .expect("recovered invocation directories");
        assert_eq!(recovered.output, invocation.output);
        fs::write(recovered.output.join("manifest"), b"canonical manifest")
            .expect("recovered slot bytes");
        let mut recovered_outputs = BTreeMap::from([(
            LocalKey::new("result").expect("output key"),
            AbilityValue::new(serde_json::json!({
                "_type": TRANSACTION_BLOB_OUTPUT_TYPE,
                "slot": "manifest",
            }))
            .expect("slot marker"),
        )]);
        store
            .finalize_outputs(&recovered, &mut recovered_outputs)
            .expect("recovered outputs");
        assert_eq!(recovered_outputs["result"], outputs["result"]);

        let consumer = store
            .prepare(&request(
                serde_json::to_value(reference).expect("reference value"),
            ))
            .expect("authorized consumer inputs");
        assert_eq!(
            fs::read(consumer.input.join(handle.as_str())).expect("exposed input"),
            b"canonical manifest"
        );
    }

    #[test]
    fn output_slot_rejects_symbolic_links() {
        let temporary = tempfile::tempdir().expect("temporary transaction");
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        let store =
            TransactionBlobStore::open(temporary.path(), &transaction()).expect("blob store");
        let invocation = store
            .prepare(&request(serde_json::json!({})))
            .expect("invocation");
        symlink(outside.path(), invocation.output.join("manifest")).expect("symbolic link");
        let mut outputs = BTreeMap::from([(
            LocalKey::new("result").expect("output key"),
            AbilityValue::new(serde_json::json!({
                "_type": TRANSACTION_BLOB_OUTPUT_TYPE,
                "slot": "manifest",
            }))
            .expect("slot marker"),
        )]);

        let error = store
            .finalize_outputs(&invocation, &mut outputs)
            .expect_err("symbolic link must be rejected");

        assert!(error.to_string().contains("regular file"));
    }
}
