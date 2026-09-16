//! Durable ownership transfer between the initrd and host ability controllers.
//!
//! The initrd writes a digest-chained journal in the transaction-storage view
//! selected by its checked ability fixed point before publishing a checkpoint
//! in preserved `/run`. The host authenticates its
//! running immutable image and the image-embedded copy of the initrd static
//! contract, checks the exact released journal head, and then appends the
//! receiving record. No process-private handle crosses the stage boundary.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::document::TerminalResult;
use aos_ability_model::plan::ResourceRevision;
use aos_ability_model::{
    ExecutionStage, LocalKey, OperationId, PlanId, ResourceLifetime, ResourceReference, RevisionId,
    TransactionId,
};
use aos_ability_plan::ResolutionPolicyDocument;
use aos_ability_runtime::journal::{FileJournal, JournalLimits, JournalPayload, JournalRecord};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::types::ImageGeneration;

const CHECKPOINT_SCHEMA: &str = "aos.ability.stage-handoff-checkpoint/v1";
const JOURNAL_EVENT_SCHEMA: &str = "aos.ability.stage-handoff-event/v1";
const TRANSACTION_ROOT: &str = "ability-stage-transactions";
const INITRD_TRANSACTION_ROOT: &str = "initrd";
const JOURNAL_FILE: &str = "execution.journal";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const INITRD_STATIC_CONTRACT_PATH: &str = "/usr/lib/aos/initrd/static-ability-contract.json";
const INITRD_CHECKPOINT_PATH: &str = "/run/aos/ability-stage-handoff/initrd.json";
const TRANSACTION_STORAGE_INTERFACE: &str = "aos.boot.transaction-storage-view";
const TRANSACTION_STORAGE_PURPOSE: &str = "initrd-stage-journal";
const DOCUMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Runs the initrd side of the stage handoff.
///
/// `root` is the mounted host root (normally `/sysroot`). The checked resolved
/// stage selects the durable transaction-storage view, and the static contract
/// is read from the current initrd.
///
/// # Errors
///
/// Returns an error when the stage is not `initrd`, an input is unsafe,
/// malformed, noncanonical, or inconsistent, the running image cannot be
/// authenticated, required execution has no supported typed executor, or any
/// journal/checkpoint durability operation fails.
pub fn run_initrd_stage(stage: &str, root: &Path, resolved_stage: &Path) -> Result<()> {
    ensure!(
        stage == "initrd",
        "ability stage runner supports only initrd"
    );
    require_privileged_runtime()?;

    let image = authenticate_immutable_image_beneath(root)
        .context("authenticating the pre-/var initrd target image")?;
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let contract_bytes = read_trusted_file(
        Path::new(INITRD_STATIC_CONTRACT_PATH),
        DOCUMENT_MAX_BYTES,
        "initrd static ability contract",
    )?;
    let resolved_stage_bytes = read_trusted_file(
        resolved_stage,
        DOCUMENT_MAX_BYTES,
        "resolved initrd ability stage",
    )?;
    let transaction_storage = selected_transaction_storage(&resolved_stage_bytes)?;

    run_initrd_stage_with(
        &transaction_storage,
        Path::new(INITRD_CHECKPOINT_PATH),
        &contract_bytes,
        &boot_id,
        image,
        &resolved_stage_bytes,
    )
}

/// Receives ownership of the completed initrd stage journal on the host.
///
/// # Errors
///
/// Returns an error when the source stage is not `initrd`, the checkpoint or
/// journal is absent, unsafe, malformed, torn, or inconsistent, the current
/// boot/image/static-contract identity differs, or durable receipt fails.
pub fn receive_initrd_stage(from_stage: &str, image_profile: &Path) -> Result<()> {
    ensure!(
        from_stage == "initrd",
        "ability stage receiver supports only initrd"
    );
    require_privileged_runtime()?;

    let image = crate::sysroot::running_image_generation_beneath(image_profile, Path::new("/"))
        .context("authenticating the host running image")?;
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let contract_bytes = read_trusted_file(
        Path::new(INITRD_STATIC_CONTRACT_PATH),
        DOCUMENT_MAX_BYTES,
        "host copy of the initrd static ability contract",
    )?;

    receive_initrd_stage_with(
        Path::new(INITRD_CHECKPOINT_PATH),
        &contract_bytes,
        &boot_id,
        ImageIdentity::from_generation(&image),
    )
}

/// Validates the released initrd journal before switching to the host root.
///
/// This barrier performs no journal or checkpoint write. It succeeds only
/// while the authenticated initrd owns an exact two-record journal whose
/// second record durably releases ownership to the host.
///
/// # Errors
///
/// Returns an error when the source stage is not `initrd`, the checkpoint or
/// journal is absent, unsafe, malformed, torn, already received, or
/// inconsistent, or the boot, target image, or static contract differs.
pub fn validate_initrd_stage(from_stage: &str, root: &Path) -> Result<()> {
    ensure!(
        from_stage == "initrd",
        "ability stage validator supports only initrd"
    );
    require_privileged_runtime()?;

    let image = authenticate_immutable_image_beneath(root)
        .context("authenticating the pre-/var initrd target image for stage release")?;
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let contract_bytes = read_trusted_file(
        Path::new(INITRD_STATIC_CONTRACT_PATH),
        DOCUMENT_MAX_BYTES,
        "initrd static ability contract",
    )?;

    validate_initrd_stage_with(
        Path::new(INITRD_CHECKPOINT_PATH),
        &contract_bytes,
        &boot_id,
        image,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImageIdentity {
    toplevel: String,
    module_abi: u32,
    base_lib_abi_hash: String,
    root_verity_roothash: Option<String>,
}

impl ImageIdentity {
    fn from_generation(generation: &ImageGeneration) -> Self {
        Self {
            toplevel: generation.toplevel.clone(),
            module_abi: generation.module_abi,
            base_lib_abi_hash: generation.base_lib_abi_hash.clone(),
            root_verity_roothash: generation.root_verity_roothash.clone(),
        }
    }
}

fn authenticate_immutable_image_beneath(root: &Path) -> Result<ImageIdentity> {
    ensure!(root.is_absolute(), "immutable image root must be absolute");
    let logical_toplevel = fs::read_link(root.join("aos-toplevel"))
        .context("reading immutable image toplevel pointer")?;
    let logical_toplevel_text = logical_toplevel
        .to_str()
        .context("immutable image toplevel pointer is not UTF-8")?;
    super::materialize::validate_canonical_store_path(logical_toplevel_text)
        .context("validating immutable image toplevel pointer")?;

    let relative_toplevel = logical_toplevel
        .strip_prefix("/")
        .context("immutable image toplevel is not absolute")?;
    let physical_toplevel = root.join(relative_toplevel);
    let module_abi = read_identity_field(&physical_toplevel, "module-abi")?
        .parse::<u32>()
        .context("immutable image has an invalid module ABI")?;
    let base_lib_abi_hash = read_identity_field(&physical_toplevel, "base-lib-abi-hash")?;
    let cmdline = fs::read_to_string("/proc/cmdline").context("reading normal boot identity")?;
    let boot_identity =
        aos_boot_identity::parse_normal(&cmdline).context("authenticating normal boot identity")?;

    Ok(ImageIdentity {
        toplevel: logical_toplevel_text.to_string(),
        module_abi,
        base_lib_abi_hash,
        root_verity_roothash: Some(boot_identity.root_hash),
    })
}

fn read_identity_field(toplevel: &Path, name: &str) -> Result<String> {
    let value = fs::read_to_string(toplevel.join("meta").join(name))
        .with_context(|| format!("reading immutable image {name}"))?;
    let value = value.trim();
    ensure!(!value.is_empty(), "immutable image {name} is empty");
    Ok(value.to_string())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageCheckpoint {
    schema: String,
    source_stage: ExecutionStage,
    receiver_stage: ExecutionStage,
    boot_id: String,
    transaction: TransactionId,
    transaction_storage: ResourceReference,
    transaction_root: String,
    image: ImageIdentity,
    static_ability_contract_sha256: Sha256Digest,
    resolved_stage_sha256: Sha256Digest,
    execution_sha256: Sha256Digest,
    journal_head: Sha256Digest,
    status: CheckpointStatus,
}

impl StageCheckpoint {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CHECKPOINT_SCHEMA,
            "unsupported stage checkpoint schema"
        );
        ensure!(
            self.source_stage == ExecutionStage::Initrd
                && self.receiver_stage == ExecutionStage::Host,
            "stage checkpoint names an unsupported transfer"
        );
        validate_boot_id(&self.boot_id)?;
        ensure!(
            self.transaction == transaction_for_boot(&self.boot_id)?,
            "stage checkpoint transaction differs from its boot identity"
        );
        ensure!(
            self.status == CheckpointStatus::OwnershipReleased,
            "stage checkpoint does not release source ownership"
        );
        validate_transaction_storage_reference(&self.transaction_storage)?;
        validate_transaction_storage_path(Path::new(&self.transaction_root))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CheckpointStatus {
    OwnershipReleased,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
enum StageEvent {
    Prepared {
        schema: String,
        source_stage: ExecutionStage,
        receiver_stage: ExecutionStage,
        boot_id: String,
        transaction: TransactionId,
        transaction_storage: ResourceReference,
        transaction_root: String,
        image: ImageIdentity,
        static_ability_contract_sha256: Sha256Digest,
        resolved_stage_sha256: Sha256Digest,
    },
    SourceCompleted {
        schema: String,
        transaction: TransactionId,
        execution: StageExecutionEvidence,
    },
    HostReceived {
        schema: String,
        transaction: TransactionId,
        checkpoint_sha256: Sha256Digest,
        released_journal_head: Sha256Digest,
        image: ImageIdentity,
        static_ability_contract_sha256: Sha256Digest,
        execution: StageExecutionEvidence,
    },
}

impl StageEvent {
    fn execution_digest(&self) -> Result<Sha256Digest> {
        let Self::SourceCompleted { execution, .. } = self else {
            bail!("stage event is not an initrd completion")
        };
        canonical_value_digest(execution)
    }
}

impl JournalPayload for StageEvent {
    fn validate_for_journal(
        &self,
        _limits: JournalLimits,
    ) -> std::result::Result<(), aos_ability_runtime::journal::JournalError> {
        let valid = match self {
            Self::Prepared {
                schema,
                source_stage,
                receiver_stage,
                boot_id,
                transaction,
                ..
            } => {
                schema == JOURNAL_EVENT_SCHEMA
                    && *source_stage == ExecutionStage::Initrd
                    && *receiver_stage == ExecutionStage::Host
                    && validate_boot_id(boot_id).is_ok()
                    && transaction_for_boot(boot_id).is_ok_and(|expected| &expected == transaction)
            }
            Self::SourceCompleted {
                schema, execution, ..
            } => schema == JOURNAL_EVENT_SCHEMA && execution.validate().is_ok(),
            Self::HostReceived {
                schema, execution, ..
            } => schema == JOURNAL_EVENT_SCHEMA && execution.validate().is_ok(),
        };
        if valid {
            Ok(())
        } else {
            Err(aos_ability_runtime::journal::JournalError::Limit(
                "stage handoff event violates its closed schema".to_string(),
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageExecutionEvidence {
    plan: PlanId,
    bundle: Sha256Digest,
    terminal: TerminalResult,
    retained_resources: Vec<StageRetainedResource>,
}

impl StageExecutionEvidence {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.terminal == TerminalResult::Succeeded,
            "initrd ability stage did not establish its target state"
        );
        ensure!(
            self.retained_resources.windows(2).all(|pair| {
                pair[0]
                    .operation
                    .cmp(&pair[1].operation)
                    .then_with(|| pair[0].output.cmp(&pair[1].output))
                    .is_lt()
            }),
            "initrd stage retained resources are not strictly canonical"
        );
        Ok(())
    }

    /// Returns the exact retained resource published by one checked operation.
    pub(crate) fn retained_resource(
        &self,
        operation_key: &str,
        output: &str,
    ) -> Result<&ResourceReference> {
        let matches = self
            .retained_resources
            .iter()
            .filter(|retained| {
                retained.operation.operation.key.as_str() == operation_key
                    && retained.output.as_str() == output
            })
            .collect::<Vec<_>>();
        let [retained] = matches.as_slice() else {
            bail!(
                "initrd stage execution does not retain exactly one {operation_key}.{output} output"
            )
        };
        Ok(&retained.resource)
    }

    fn validate_exact_retained_resource(&self, expected: &ResourceReference) -> Result<()> {
        let matching = self
            .retained_resources
            .iter()
            .filter(|retained| &retained.resource == expected)
            .collect::<Vec<_>>();
        let [retained] = matching.as_slice() else {
            bail!("initrd stage execution did not retain exactly one transaction-storage resource")
        };
        ensure!(
            retained.output.as_str() == "retained-resource",
            "initrd transaction-storage resource came from an unexpected output"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageRetainedResource {
    operation: OperationId,
    output: LocalKey,
    resource: ResourceReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalOwnership {
    Released,
    Received,
}

struct ValidatedRelease {
    checkpoint: StageCheckpoint,
    checkpoint_bytes: Vec<u8>,
    contract_digest: Sha256Digest,
    journal_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionStorageSelection {
    resource: ResourceReference,
    root: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionStorageRealization {
    schema: String,
    path: String,
}

fn selected_transaction_storage(
    resolved_stage_bytes: &[u8],
) -> Result<TransactionStorageSelection> {
    let checked = super::build_stage::decode_resolved_stage(resolved_stage_bytes)?;
    ensure!(
        checked.environment.stage == ExecutionStage::Initrd,
        "resolved ability stage does not select the initrd environment"
    );

    let matching_resources = checked
        .fixed_point
        .resolved_resources
        .values()
        .map(|value| {
            serde_json::from_value::<ResourceRevision>(value.as_json().clone())
                .context("decoding resolved initrd resource")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|revision| {
            revision.kind.as_str() == TRANSACTION_STORAGE_INTERFACE
                && revision
                    .value
                    .as_json()
                    .get("purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some(TRANSACTION_STORAGE_PURPOSE)
        })
        .collect::<Vec<_>>();
    let [revision] = matching_resources.as_slice() else {
        bail!("resolved initrd stage does not select exactly one transaction-storage view")
    };
    ensure!(
        revision.lifetime == ResourceLifetime::Transaction,
        "initrd transaction-storage view has the wrong lifetime"
    );

    let matching_bindings = checked
        .fixed_point
        .checked_bindings
        .iter()
        .filter(|binding| {
            binding.interface.name == revision.kind
                && binding.provider == revision.resource.provider
                && binding
                    .caller_grant
                    .methods
                    .iter()
                    .any(|method| method.as_str() == "materialize")
                && binding.caller_grant.resources.iter().any(|permission| {
                    permission.resource == revision.resource
                        && permission
                            .operations
                            .iter()
                            .any(|operation| operation.as_str() == "materialize")
                })
        })
        .collect::<Vec<_>>();
    let [binding] = matching_bindings.as_slice() else {
        bail!("resolved initrd transaction-storage view has no exact checked caller binding")
    };

    let realization: TransactionStorageRealization =
        serde_json::from_value(revision.realization.as_json().clone())
            .context("decoding initrd transaction-storage realization")?;
    ensure!(
        realization.schema == "aos.boot.transaction-storage-realization/v1",
        "unsupported initrd transaction-storage realization"
    );
    let root = PathBuf::from(realization.path);
    validate_transaction_storage_path(&root)?;

    let resource = ResourceReference {
        interface: binding.interface.clone(),
        resource: revision.resource.clone(),
        operations: vec![LocalKey::new("observe")?],
        lifetime: revision.lifetime.clone(),
    };
    validate_transaction_storage_reference(&resource)?;
    Ok(TransactionStorageSelection { resource, root })
}

fn validate_transaction_storage_reference(resource: &ResourceReference) -> Result<()> {
    ensure!(
        resource.interface.name.as_str() == TRANSACTION_STORAGE_INTERFACE
            && resource.lifetime == ResourceLifetime::Transaction
            && resource.operations.len() == 1
            && resource.operations[0].as_str() == "observe",
        "stage handoff names an invalid transaction-storage resource"
    );
    Ok(())
}

fn validate_transaction_storage_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "transaction-storage path is not absolute"
    );
    let path_text = path
        .to_str()
        .context("transaction-storage path is not UTF-8")?;
    ensure!(
        path_text != "/" && !path_text.ends_with('/') && !path_text.contains("//"),
        "transaction-storage path is not canonical"
    );
    ensure!(
        !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }),
        "transaction-storage path contains traversal components"
    );
    Ok(())
}

fn run_initrd_stage_with(
    transaction_storage: &TransactionStorageSelection,
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
    resolved_stage_bytes: &[u8],
) -> Result<()> {
    validate_boot_id(boot_id)?;
    super::static_packages::verified_initrd_packages(contract_bytes)
        .context("authenticating initrd static ability contract")?;
    let contract_digest = sha256_digest(contract_bytes);

    let transaction = transaction_for_boot(boot_id)?;
    let transaction_root = transaction_storage
        .root
        .to_str()
        .context("selected transaction-storage path is not UTF-8")?
        .to_string();
    let resolved_stage_sha256 = sha256_digest(resolved_stage_bytes);
    let prepared = StageEvent::Prepared {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        source_stage: ExecutionStage::Initrd,
        receiver_stage: ExecutionStage::Host,
        boot_id: boot_id.to_string(),
        transaction: transaction.clone(),
        transaction_storage: transaction_storage.resource.clone(),
        transaction_root: transaction_root.clone(),
        image: image.clone(),
        static_ability_contract_sha256: contract_digest,
        resolved_stage_sha256,
    };
    let transaction_dir = prepare_transaction_directory(&transaction_storage.root, &transaction)?;
    let journal_path = transaction_dir.join(JOURNAL_FILE);
    let opened = FileJournal::<StageEvent>::open(&journal_path, stage_journal_limits())
        .context("opening initrd stage handoff journal")?;
    let mut journal = opened.journal;
    let records = opened.recovery.records();
    let (released_head, completed) = match records {
        [] => {
            journal.ensure_capacity(2)?;
            journal.append(&prepared)?;
            let completed = source_completion_for_run(
                None,
                &transaction,
                || {
                    execute_resolved_initrd_stage(
                        resolved_stage_bytes,
                        contract_bytes,
                        &transaction_storage.root,
                        transaction.clone(),
                    )
                },
                |_| Ok(()),
            )?;
            let head = journal.append(&completed)?.digest();
            (head, completed)
        }
        [first] if first.body() == &prepared => {
            journal.ensure_capacity(1)?;
            let completed = source_completion_for_run(
                None,
                &transaction,
                || {
                    execute_resolved_initrd_stage(
                        resolved_stage_bytes,
                        contract_bytes,
                        &transaction_storage.root,
                        transaction.clone(),
                    )
                },
                |_| Ok(()),
            )?;
            let head = journal.append(&completed)?.digest();
            (head, completed)
        }
        [first, second] if first.body() == &prepared => {
            let completed = source_completion_for_run(
                Some(second.body()),
                &transaction,
                || bail!("settled initrd stage attempted to invoke handlers again"),
                |execution| {
                    validate_resolved_initrd_stage_evidence(resolved_stage_bytes, execution)
                },
            )?;
            (second.digest(), completed)
        }
        [first, second, _] if first.body() == &prepared => {
            source_completion_for_run(
                Some(second.body()),
                &transaction,
                || bail!("received initrd stage attempted to invoke handlers again"),
                |execution| {
                    validate_resolved_initrd_stage_evidence(resolved_stage_bytes, execution)
                },
            )?;
            bail!("initrd stage journal ownership was already received by the host")
        }
        _ => bail!("initrd stage journal differs from the authenticated resolved plan"),
    };
    drop(journal);
    let StageEvent::SourceCompleted { execution, .. } = &completed else {
        bail!("initrd stage did not produce checked source completion")
    };
    execution.validate_exact_retained_resource(&transaction_storage.resource)?;

    let checkpoint = StageCheckpoint {
        schema: CHECKPOINT_SCHEMA.to_string(),
        source_stage: ExecutionStage::Initrd,
        receiver_stage: ExecutionStage::Host,
        boot_id: boot_id.to_string(),
        transaction,
        transaction_storage: transaction_storage.resource.clone(),
        transaction_root,
        image,
        static_ability_contract_sha256: contract_digest,
        resolved_stage_sha256,
        execution_sha256: completed.execution_digest()?,
        journal_head: released_head,
        status: CheckpointStatus::OwnershipReleased,
    };
    checkpoint.validate()?;
    let checkpoint_bytes = aos_contract::canonical::to_vec(&checkpoint)?;
    publish_atomic(checkpoint_path, &checkpoint_bytes)
        .context("publishing preserved initrd stage checkpoint")
}

fn source_completion_for_run<Execute, Validate>(
    existing: Option<&StageEvent>,
    transaction: &TransactionId,
    execute: Execute,
    validate_existing: Validate,
) -> Result<StageEvent>
where
    Execute: FnOnce() -> Result<StageExecutionEvidence>,
    Validate: FnOnce(&StageExecutionEvidence) -> Result<()>,
{
    if let Some(existing) = existing {
        let StageEvent::SourceCompleted {
            transaction: completed_transaction,
            execution,
            ..
        } = existing
        else {
            bail!("initrd stage journal does not record source execution")
        };
        ensure!(
            completed_transaction == transaction,
            "initrd stage completion names another transaction"
        );
        execution.validate()?;
        validate_existing(execution)?;
        return Ok(existing.clone());
    }

    let execution = execute()?;
    execution.validate()?;
    Ok(StageEvent::SourceCompleted {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        transaction: transaction.clone(),
        execution,
    })
}

fn validate_resolved_initrd_stage_evidence(
    resolved_stage_bytes: &[u8],
    execution: &StageExecutionEvidence,
) -> Result<()> {
    let checked = super::build_stage::decode_resolved_stage(resolved_stage_bytes)?;
    ensure!(
        checked.environment.stage == ExecutionStage::Initrd,
        "resolved ability stage does not select the initrd environment"
    );
    ensure!(
        checked.bundle.transition_authority_digest().is_none(),
        "fresh initrd execution unexpectedly carries teardown authority"
    );
    ensure!(
        execution.plan == checked.plan.id() && execution.bundle == checked.bundle.digest()?,
        "retained initrd execution differs from the checked plan bundle"
    );
    for retained in &execution.retained_resources {
        ensure!(
            retained.operation.plan == checked.plan.id(),
            "retained initrd resource names another plan"
        );
        let operation = checked
            .plan
            .operation(&retained.operation.operation)
            .context("retained initrd resource names an unknown operation")?;
        let method = checked
            .plan
            .operation_method(operation)
            .context("retained initrd resource has no checked method")?;
        let output = method
            .outputs
            .get(&retained.output)
            .context("retained initrd resource names an unknown output")?;
        ensure!(
            output.is_retained_resource(),
            "retained initrd resource names a non-retained output"
        );
    }
    execution.validate()
}

fn execute_resolved_initrd_stage(
    resolved_stage_bytes: &[u8],
    contract_bytes: &[u8],
    transaction_root: &Path,
    transaction: TransactionId,
) -> Result<StageExecutionEvidence> {
    let checked = super::build_stage::decode_resolved_stage(resolved_stage_bytes)?;
    ensure!(
        checked.environment.stage == ExecutionStage::Initrd,
        "resolved ability stage does not select the initrd environment"
    );
    ensure!(
        checked.bundle.transition_authority_digest().is_none(),
        "fresh initrd execution unexpectedly carries teardown authority"
    );

    let supported_features = super::native_activation::supported_native_ability_features()?;
    let packages = super::static_packages::verified_initrd_packages(contract_bytes)
        .context("authenticating initrd handler packages")?;
    let dispatcher =
        super::handler_dispatch::HandlerDispatcher::for_static_plan(&checked.plan, &packages)
            .context("constructing initrd handler dispatcher")?;
    let stage_directory = transaction_root
        .join("ability-stage-runtime")
        .join("initrd");
    let mut session = super::transaction_store::AbilityTransactionSession::open_stage(
        &checked.plan,
        transaction.clone(),
        JournalLimits::default(),
        stage_directory,
        supported_features.clone(),
        checked.bundle.clone(),
        packages.clone(),
    )
    .context("opening durable initrd ability transaction")?;

    let resolution_policy = selected_resolution_policy(&checked)?;
    let scope = super::ability_policy::CurrentAuthorityScope {
        plan: checked.plan.id(),
        transaction,
    };
    let current_policy = super::ability_policy::PublishingNativeAdmissionPolicy::new(
        &scope,
        RevisionId(checked.bundle.desired_policy_digest()),
        resolution_policy,
        None,
        None,
        supported_features,
        60_000,
        false,
    );
    let cancellation = super::cancellation::AbilityCancellationGuard::install()
        .context("installing initrd ability cancellation listeners")?;
    let mut observer = super::execution_observer::AbilityExecutionBoundaryObserver::load(
        checked.fixed_point.execution_observer.as_ref(),
    )
    .context("opening initrd execution observation channel")?;
    let terminal = dispatcher.run_static_to_terminal(
        &mut session,
        current_policy,
        cancellation.token(),
        &mut observer,
    )?;

    let summary = session.transaction().summary();
    let mut retained_resources = summary
        .operations()
        .iter()
        .flat_map(|operation| {
            operation
                .retained_resources()
                .iter()
                .map(move |(output, resource)| StageRetainedResource {
                    operation: operation.operation().clone(),
                    output: output.clone(),
                    resource: resource.clone(),
                })
        })
        .collect::<Vec<_>>();
    retained_resources.sort_by(|left, right| {
        left.operation
            .cmp(&right.operation)
            .then_with(|| left.output.cmp(&right.output))
    });
    let evidence = StageExecutionEvidence {
        plan: checked.plan.id(),
        bundle: checked.bundle.digest()?,
        terminal,
        retained_resources,
    };
    evidence.validate()?;
    Ok(evidence)
}

fn selected_resolution_policy(
    checked: &super::build_stage::CheckedResolvedBuildStage,
) -> Result<ResolutionPolicyDocument> {
    let binding = checked.plan.binding_plan().document();
    let matching = checked
        .bundle
        .desired_policies()
        .iter()
        .filter(|policy| {
            policy.desired_state == binding.desired_state
                && policy.environment == binding.environment
                && policy.policy_revision == binding.policy_revision
        })
        .collect::<Vec<_>>();
    let [policy] = matching.as_slice() else {
        bail!("initrd binding plan does not select exactly one authenticated resolution policy")
    };
    Ok((*policy).clone())
}

fn receive_initrd_stage_with(
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
) -> Result<()> {
    let release = load_validated_release(checkpoint_path, contract_bytes, boot_id, &image)?;
    let ownership = read_journal_ownership(&release, &image)?;
    if ownership == JournalOwnership::Received {
        return Ok(());
    }

    let opened = FileJournal::<StageEvent>::open(&release.journal_path, stage_journal_limits())
        .context("opening released initrd stage journal")?;
    ensure!(
        opened.recovery.discarded_torn_bytes() == 0,
        "released initrd stage journal has a torn tail"
    );
    let mut journal = opened.journal;
    let ownership = validate_journal_sequence(
        opened.recovery.records(),
        &release.checkpoint,
        &release.checkpoint_bytes,
        release.contract_digest,
        &image,
    )?;
    if ownership == JournalOwnership::Received {
        return Ok(());
    }
    let execution = source_execution(opened.recovery.records())?.clone();
    let received = StageEvent::HostReceived {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        transaction: release.checkpoint.transaction.clone(),
        checkpoint_sha256: sha256_digest(&release.checkpoint_bytes),
        released_journal_head: release.checkpoint.journal_head,
        image,
        static_ability_contract_sha256: release.contract_digest,
        execution,
    };
    journal.ensure_capacity(1)?;
    journal.append(&received)?;
    Ok(())
}

fn validate_initrd_stage_with(
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
) -> Result<()> {
    let release = load_validated_release(checkpoint_path, contract_bytes, boot_id, &image)?;
    let ownership = read_journal_ownership(&release, &image)?;
    ensure!(
        ownership == JournalOwnership::Released,
        "initrd stage journal ownership was already received by the host"
    );
    Ok(())
}

fn read_journal_ownership(
    release: &ValidatedRelease,
    image: &ImageIdentity,
) -> Result<JournalOwnership> {
    let snapshot = FileJournal::<StageEvent>::read_only_snapshot(
        &release.journal_path,
        stage_journal_limits(),
    )
    .context("reading released initrd stage journal without mutation")?;
    ensure!(
        snapshot.incomplete_tail_bytes() == 0,
        "released initrd stage journal has a torn tail"
    );
    validate_journal_sequence(
        snapshot.records(),
        &release.checkpoint,
        &release.checkpoint_bytes,
        release.contract_digest,
        image,
    )
}

fn load_validated_release(
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: &ImageIdentity,
) -> Result<ValidatedRelease> {
    validate_boot_id(boot_id)?;
    super::static_packages::verified_initrd_packages(contract_bytes)
        .context("reauthenticating initrd static ability contract")?;
    let checkpoint_bytes = read_trusted_file(
        checkpoint_path,
        DOCUMENT_MAX_BYTES,
        "preserved initrd stage checkpoint",
    )?;
    let checkpoint: StageCheckpoint = serde_json::from_slice(&checkpoint_bytes)
        .context("decoding preserved initrd stage checkpoint")?;
    checkpoint.validate()?;
    ensure!(
        aos_contract::canonical::to_vec(&checkpoint)? == checkpoint_bytes,
        "preserved initrd stage checkpoint is not canonical JSON"
    );
    ensure!(
        checkpoint.boot_id == boot_id,
        "stage checkpoint belongs to another boot"
    );
    ensure!(
        checkpoint.image == *image,
        "stage checkpoint belongs to another image"
    );
    let contract_digest = sha256_digest(contract_bytes);
    ensure!(
        checkpoint.static_ability_contract_sha256 == contract_digest,
        "stage checkpoint names another initrd static ability contract"
    );

    let transaction_root = Path::new(&checkpoint.transaction_root);
    let journal_path = existing_transaction_directory(transaction_root, &checkpoint.transaction)?
        .join(JOURNAL_FILE);
    Ok(ValidatedRelease {
        checkpoint,
        checkpoint_bytes,
        contract_digest,
        journal_path,
    })
}

fn validate_journal_sequence(
    records: &[JournalRecord<StageEvent>],
    checkpoint: &StageCheckpoint,
    checkpoint_bytes: &[u8],
    contract_digest: Sha256Digest,
    image: &ImageIdentity,
) -> Result<JournalOwnership> {
    match records {
        [first, second] => {
            ensure!(
                second.digest() == checkpoint.journal_head,
                "released journal head differs from the stage checkpoint"
            );
            validate_source_records(first.body(), second.body(), checkpoint)?;
            Ok(JournalOwnership::Released)
        }
        [first, second, third] => {
            ensure!(
                second.digest() == checkpoint.journal_head,
                "released journal head differs from the stage checkpoint"
            );
            validate_received_record(
                first.body(),
                second.body(),
                third.body(),
                checkpoint,
                checkpoint_bytes,
                contract_digest,
                image,
            )?;
            Ok(JournalOwnership::Received)
        }
        _ => bail!("released initrd stage journal has an invalid state sequence"),
    }
}

fn source_execution(records: &[JournalRecord<StageEvent>]) -> Result<&StageExecutionEvidence> {
    let Some(record) = records.get(1) else {
        bail!("released initrd stage journal has no source execution")
    };
    let StageEvent::SourceCompleted { execution, .. } = record.body() else {
        bail!("initrd stage journal does not record source execution")
    };
    execution.validate()?;
    Ok(execution)
}

fn validate_source_records(
    prepared: &StageEvent,
    source_completed: &StageEvent,
    checkpoint: &StageCheckpoint,
) -> Result<()> {
    let StageEvent::Prepared {
        source_stage,
        receiver_stage,
        boot_id,
        transaction,
        transaction_storage,
        transaction_root,
        image,
        static_ability_contract_sha256,
        resolved_stage_sha256,
        ..
    } = prepared
    else {
        bail!("initrd stage journal does not begin with preparation")
    };
    ensure!(
        *source_stage == checkpoint.source_stage
            && *receiver_stage == checkpoint.receiver_stage
            && boot_id == &checkpoint.boot_id
            && transaction == &checkpoint.transaction
            && transaction_storage == &checkpoint.transaction_storage
            && transaction_root == &checkpoint.transaction_root
            && image == &checkpoint.image
            && *static_ability_contract_sha256 == checkpoint.static_ability_contract_sha256
            && *resolved_stage_sha256 == checkpoint.resolved_stage_sha256,
        "initrd stage journal preparation differs from the released checkpoint"
    );
    let StageEvent::SourceCompleted {
        transaction,
        execution,
        ..
    } = source_completed
    else {
        bail!("initrd stage journal does not record source completion")
    };
    ensure!(
        transaction == &checkpoint.transaction
            && canonical_value_digest(execution)? == checkpoint.execution_sha256,
        "initrd stage completion differs from the released checkpoint"
    );
    execution.validate()?;
    Ok(())
}

fn validate_received_record(
    prepared: &StageEvent,
    source_completed: &StageEvent,
    received: &StageEvent,
    checkpoint: &StageCheckpoint,
    checkpoint_bytes: &[u8],
    contract_digest: Sha256Digest,
    image: &ImageIdentity,
) -> Result<()> {
    validate_source_records(prepared, source_completed, checkpoint)?;
    let StageEvent::HostReceived {
        transaction,
        checkpoint_sha256,
        released_journal_head,
        image: received_image,
        static_ability_contract_sha256,
        execution,
        ..
    } = received
    else {
        bail!("initrd stage journal third record is not a host receipt")
    };
    ensure!(
        transaction == &checkpoint.transaction
            && *checkpoint_sha256 == sha256_digest(checkpoint_bytes)
            && *released_journal_head == checkpoint.journal_head
            && received_image == image
            && *static_ability_contract_sha256 == contract_digest,
        "retained host receipt differs from the current handoff evidence"
    );
    let StageEvent::SourceCompleted {
        execution: source_execution,
        ..
    } = source_completed
    else {
        bail!("initrd stage journal does not record source execution")
    };
    ensure!(
        execution == source_execution,
        "retained host receipt differs from the checked source execution"
    );
    execution.validate()?;
    Ok(())
}

fn prepare_transaction_directory(
    transaction_root: &Path,
    transaction: &TransactionId,
) -> Result<PathBuf> {
    validate_transaction_storage_path(transaction_root)?;
    ensure_private_directory(transaction_root, false)?;
    let root = transaction_root.join(TRANSACTION_ROOT);
    ensure_private_directory(&root, true)?;
    let initrd = root.join(INITRD_TRANSACTION_ROOT);
    ensure_private_directory(&initrd, true)?;
    let transaction_dir = initrd.join(transaction.0.as_str());
    ensure_private_directory(&transaction_dir, true)?;
    sync_directory(&initrd)?;
    Ok(transaction_dir)
}

fn existing_transaction_directory(
    transaction_root: &Path,
    transaction: &TransactionId,
) -> Result<PathBuf> {
    validate_transaction_storage_path(transaction_root)?;
    let transaction_dir = transaction_root
        .join(TRANSACTION_ROOT)
        .join(INITRD_TRANSACTION_ROOT)
        .join(transaction.0.as_str());
    ensure_private_directory(&transaction_dir, false)?;
    Ok(transaction_dir)
}

fn ensure_private_directory(path: &Path, create: bool) -> Result<()> {
    if create {
        match fs::create_dir(path) {
            Ok(()) => {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
                let parent = path.parent().context("private directory has no parent")?;
                sync_directory(parent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting protected directory {}", path.display()))?;
    let owner = rustix::process::geteuid().as_raw();
    ensure!(
        metadata.is_dir(),
        "protected path {} is not a directory",
        path.display()
    );
    ensure!(
        metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "protected directory {} has unsafe ownership or mode",
        path.display()
    );
    Ok(())
}

fn read_trusted_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {label}"))?;
    let metadata = input
        .metadata()
        .with_context(|| format!("inspecting {label}"))?;
    let owner = rustix::process::geteuid().as_raw();
    ensure!(metadata.is_file(), "{label} is not a regular file");
    ensure!(metadata.nlink() == 1, "{label} has multiple hard links");
    ensure!(
        metadata.uid() == owner,
        "{label} is not owned by the controller identity"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "{label} is group/world writable"
    );
    ensure!(metadata.len() <= limit, "{label} exceeds its size bound");
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{label} grew beyond its size bound"
    );
    Ok(bytes)
}

fn publish_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("checkpoint path has no parent")?;
    create_private_tree(parent)?;
    let temporary = parent.join(format!(".initrd.json.tmp.{}", std::process::id()));
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_private_tree(path: &Path) -> Result<()> {
    if path.exists() {
        return ensure_private_directory(path, false);
    }
    let parent = path
        .parent()
        .context("private directory tree has no parent")?;
    create_private_tree(parent)?;
    ensure_private_directory(path, true)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn read_boot_id(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading boot identity {}", path.display()))?;
    let boot_id = value.trim();
    validate_boot_id(boot_id)?;
    Ok(boot_id.to_string())
}

fn validate_boot_id(boot_id: &str) -> Result<()> {
    ensure!(boot_id.len() == 36, "boot identity is not a canonical UUID");
    ensure!(
        boot_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        }),
        "boot identity is not a lowercase canonical UUID"
    );
    Ok(())
}

fn transaction_for_boot(boot_id: &str) -> Result<TransactionId> {
    validate_boot_id(boot_id)?;
    let key = format!("initrd-{}", boot_id.replace('-', ""));
    Ok(TransactionId(LocalKey::new(key)?))
}

fn canonical_value_digest<T: Serialize>(value: &T) -> Result<Sha256Digest> {
    Ok(sha256_digest(&aos_contract::canonical::to_vec(value)?))
}

fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Sha256Digest::from_bytes(digest)
}

fn stage_journal_limits() -> JournalLimits {
    JournalLimits {
        max_body_bytes: DOCUMENT_MAX_BYTES as usize,
        max_depth: 16,
        max_items: aos_ability_model::ABILITY_LIMITS_V1.max_collection_items as usize,
        max_string_bytes: aos_ability_model::ABILITY_LIMITS_V1.max_string_bytes as usize,
        max_records: 3,
        max_file_bytes: DOCUMENT_MAX_BYTES.saturating_mul(4),
    }
}

fn require_privileged_runtime() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "ability stage handoff requires the root controller identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn accepts_only_lowercase_canonical_boot_identities() {
        assert!(validate_boot_id("01234567-89ab-cdef-0123-456789abcdef").is_ok());
        assert!(validate_boot_id("01234567-89AB-CDEF-0123-456789ABCDEF").is_err());
        assert!(validate_boot_id("0123456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn transaction_storage_requires_exact_typed_reference_and_canonical_path() -> Result<()> {
        let resource: ResourceReference = serde_json::from_value(serde_json::json!({
            "interface": {
                "name": TRANSACTION_STORAGE_INTERFACE,
                "abi": 1,
                "descriptor": format!("sha256:{}", "0".repeat(64)),
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "initrd",
                        "stage": "initrd",
                    },
                    "key": "boot-storage",
                },
                "key": TRANSACTION_STORAGE_PURPOSE,
            },
            "operations": ["observe"],
            "lifetime": "transaction",
        }))?;

        validate_transaction_storage_reference(&resource)?;
        validate_transaction_storage_path(Path::new(
            "/run/aos-boot-transaction-storage/aos/initrd-stage-journal",
        ))?;
        let evidence = StageExecutionEvidence {
            plan: PlanId(sha256_digest(b"storage-plan")),
            bundle: sha256_digest(b"storage-bundle"),
            terminal: TerminalResult::Succeeded,
            retained_resources: vec![StageRetainedResource {
                operation: OperationId {
                    plan: PlanId(sha256_digest(b"storage-plan")),
                    operation: aos_ability_model::ScopedOperationKey {
                        scope: aos_ability_model::ScopePath::root(),
                        key: LocalKey::new("materialize-transaction-storage")?,
                    },
                },
                output: LocalKey::new("retained-resource")?,
                resource: resource.clone(),
            }],
        };
        evidence.validate_exact_retained_resource(&resource)?;

        let mut wrong_lifetime = resource;
        wrong_lifetime.lifetime = ResourceLifetime::Persistent;
        assert!(validate_transaction_storage_reference(&wrong_lifetime).is_err());
        assert!(validate_transaction_storage_path(Path::new("relative/journal")).is_err());
        assert!(validate_transaction_storage_path(Path::new("/run/aos/../journal")).is_err());
        Ok(())
    }

    #[test]
    fn stage_execution_requires_success_and_canonical_retained_outputs() -> Result<()> {
        let plan = PlanId(sha256_digest(b"plan"));
        let operation = |key: &str| -> Result<OperationId> {
            Ok(OperationId {
                plan,
                operation: aos_ability_model::ScopedOperationKey {
                    scope: aos_ability_model::ScopePath::root(),
                    key: LocalKey::new(key)?,
                },
            })
        };
        let resource = |key: &str| -> Result<ResourceReference> {
            Ok(serde_json::from_value(serde_json::json!({
                "interface": {
                    "name": "aos.test.resource",
                    "abi": 1,
                    "descriptor": format!("sha256:{}", "0".repeat(64)),
                },
                "resource": {
                    "provider": {
                        "environment": {
                            "authority": "test",
                            "key": "host",
                            "stage": "host",
                        },
                        "key": "provider",
                    },
                    "key": key,
                },
                "operations": ["observe", "remove"],
                "lifetime": "persistent",
            }))?)
        };
        let first = StageRetainedResource {
            operation: operation("commit-authorized-input")?,
            output: LocalKey::new("artifact-resource")?,
            resource: resource("authorized-provisioning-input")?,
        };
        let second = StageRetainedResource {
            operation: operation("observe-authorized-input")?,
            output: LocalKey::new("artifact-resource")?,
            resource: resource("authorized-provisioning-input")?,
        };
        let evidence = StageExecutionEvidence {
            plan,
            bundle: sha256_digest(b"bundle"),
            terminal: TerminalResult::Succeeded,
            retained_resources: vec![first.clone(), second],
        };

        evidence.validate()?;
        assert_eq!(
            evidence.retained_resource("commit-authorized-input", "artifact-resource")?,
            &first.resource
        );

        let mut noncanonical = evidence.clone();
        noncanonical.retained_resources.reverse();
        assert!(noncanonical.validate().is_err());

        let mut failed = evidence;
        failed.terminal = TerminalResult::SettledFailure;
        assert!(failed.validate().is_err());
        Ok(())
    }

    #[test]
    fn restart_after_source_completion_never_invokes_handlers() -> Result<()> {
        let transaction = transaction_for_boot("01234567-89ab-cdef-0123-456789abcdef")?;
        let execution = StageExecutionEvidence {
            plan: PlanId(sha256_digest(b"plan")),
            bundle: sha256_digest(b"bundle"),
            terminal: TerminalResult::Succeeded,
            retained_resources: Vec::new(),
        };
        let completed = StageEvent::SourceCompleted {
            schema: JOURNAL_EVENT_SCHEMA.to_string(),
            transaction: transaction.clone(),
            execution: execution.clone(),
        };
        let handler_invocations = AtomicUsize::new(0);

        let recovered = source_completion_for_run(
            Some(&completed),
            &transaction,
            || {
                handler_invocations.fetch_add(1, Ordering::SeqCst);
                Ok(execution.clone())
            },
            |retained| {
                ensure!(retained == &execution, "retained execution changed");
                Ok(())
            },
        )?;

        assert_eq!(recovered, completed);
        assert_eq!(handler_invocations.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
