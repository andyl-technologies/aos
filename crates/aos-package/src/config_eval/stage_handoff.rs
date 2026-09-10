//! Durable ownership transfer between the initrd and host ability controllers.
//!
//! The initrd writes a digest-chained journal beneath the image profile before
//! publishing a checkpoint in preserved `/run`. The host authenticates its
//! running immutable image and the image-embedded copy of the initrd static
//! contract, checks the exact released journal head, and then appends the
//! receiving record. No process-private handle crosses the stage boundary.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{ExecutionStage, LocalKey, TransactionId};
use aos_ability_runtime::journal::{FileJournal, JournalLimits, JournalPayload, JournalRecord};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::types::ImageGeneration;

const SELECTION_SCHEMA: &str = "aos.ability.initrd-activation-selection/v1";
const CHECKPOINT_SCHEMA: &str = "aos.ability.stage-handoff-checkpoint/v1";
const JOURNAL_EVENT_SCHEMA: &str = "aos.ability.stage-handoff-event/v1";
const STATIC_CONTRACT_SCHEMA: &str = "aos.boot.static-abilities/v1";
const TRANSACTION_ROOT: &str = "ability-stage-transactions";
const INITRD_TRANSACTION_ROOT: &str = "initrd";
const JOURNAL_FILE: &str = "execution.journal";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const INITRD_STATIC_CONTRACT_PATH: &str = "/usr/lib/aos/initrd/static-ability-contract.json";
const INITRD_CHECKPOINT_PATH: &str = "/run/aos/ability-stage-handoff/initrd.json";
const DOCUMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Runs the initrd side of the stage handoff.
///
/// `root` is the mounted host root (normally `/sysroot`), while
/// `image_profile` names its durable image profile. The signed selection and
/// static contract are read from the current initrd.
///
/// # Errors
///
/// Returns an error when the stage is not `initrd`, an input is unsafe,
/// malformed, noncanonical, or inconsistent, the running image cannot be
/// authenticated, required execution has no supported typed executor, or any
/// journal/checkpoint durability operation fails.
pub fn run_initrd_stage(
    stage: &str,
    root: &Path,
    image_profile: &Path,
    input: &Path,
) -> Result<()> {
    ensure!(
        stage == "initrd",
        "ability stage runner supports only initrd"
    );
    require_privileged_runtime()?;

    let image = crate::sysroot::running_image_generation_beneath(image_profile, root)
        .context("authenticating the initrd target image")?;
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let selection_bytes =
        read_trusted_file(input, DOCUMENT_MAX_BYTES, "initrd activation selection")?;
    let contract_bytes = read_trusted_file(
        Path::new(INITRD_STATIC_CONTRACT_PATH),
        DOCUMENT_MAX_BYTES,
        "initrd static ability contract",
    )?;

    run_initrd_stage_with(
        image_profile,
        Path::new(INITRD_CHECKPOINT_PATH),
        &selection_bytes,
        &contract_bytes,
        &boot_id,
        ImageIdentity::from_generation(&image),
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
        image_profile,
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
pub fn validate_initrd_stage(from_stage: &str, root: &Path, image_profile: &Path) -> Result<()> {
    ensure!(
        from_stage == "initrd",
        "ability stage validator supports only initrd"
    );
    require_privileged_runtime()?;

    let image = crate::sysroot::running_image_generation_beneath(image_profile, root)
        .context("authenticating the initrd target image for stage release")?;
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let contract_bytes = read_trusted_file(
        Path::new(INITRD_STATIC_CONTRACT_PATH),
        DOCUMENT_MAX_BYTES,
        "initrd static ability contract",
    )?;

    validate_initrd_stage_with(
        image_profile,
        Path::new(INITRD_CHECKPOINT_PATH),
        &contract_bytes,
        &boot_id,
        ImageIdentity::from_generation(&image),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationSelection {
    schema: String,
    execution_stage: ExecutionStage,
    disposition: ActivationDisposition,
    static_ability_contract_sha256: Sha256Digest,
    activation: Option<serde_json::Value>,
}

impl ActivationSelection {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let selection: Self =
            serde_json::from_slice(bytes).context("decoding initrd activation selection")?;
        ensure!(
            selection.schema == SELECTION_SCHEMA,
            "unsupported initrd activation selection schema"
        );
        ensure!(
            selection.execution_stage == ExecutionStage::Initrd,
            "initrd activation selection names another execution stage"
        );
        ensure!(
            matches!(
                (&selection.disposition, &selection.activation),
                (ActivationDisposition::None, None)
                    | (
                        ActivationDisposition::Required,
                        Some(serde_json::Value::Object(_))
                    )
            ),
            "initrd activation disposition does not match its activation payload"
        );
        ensure!(
            aos_contract::canonical::to_vec(&selection)? == bytes,
            "initrd activation selection is not canonical JSON"
        );
        Ok(selection)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ActivationDisposition {
    None,
    Required,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityContract {
    schema: String,
    platforms: Vec<StaticAbilityPlatform>,
    runtime_grants: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticAbilityPlatform {
    platform: serde_json::Value,
    execution_stage: ExecutionStage,
    packages: Vec<serde_json::Value>,
    abilities: Vec<serde_json::Value>,
    unresolved_launch_obligations: Vec<serde_json::Value>,
}

impl StaticAbilityContract {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let contract: Self =
            serde_json::from_slice(bytes).context("decoding initrd static ability contract")?;
        ensure!(
            contract.schema == STATIC_CONTRACT_SCHEMA,
            "unsupported initrd static ability contract schema"
        );
        ensure!(
            !contract.platforms.is_empty()
                && contract
                    .platforms
                    .iter()
                    .all(|platform| platform.execution_stage == ExecutionStage::Initrd),
            "initrd static ability contract contains another execution stage"
        );
        ensure!(
            contract.runtime_grants.is_empty(),
            "static ability contract must not carry runtime grants"
        );
        ensure!(
            aos_contract::canonical::to_vec(&contract)? == bytes,
            "initrd static ability contract is not canonical JSON"
        );
        Ok(contract)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImageIdentity {
    generation: u32,
    toplevel: String,
    module_abi: u32,
    baselib_digest: String,
    root_verity_roothash: Option<String>,
}

impl ImageIdentity {
    fn from_generation(generation: &ImageGeneration) -> Self {
        Self {
            generation: generation.number,
            toplevel: generation.toplevel.clone(),
            module_abi: generation.module_abi,
            baselib_digest: generation.baselib_digest.clone(),
            root_verity_roothash: generation.root_verity_roothash.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageCheckpoint {
    schema: String,
    source_stage: ExecutionStage,
    receiver_stage: ExecutionStage,
    boot_id: String,
    transaction: TransactionId,
    image: ImageIdentity,
    selection_sha256: Sha256Digest,
    static_ability_contract_sha256: Sha256Digest,
    disposition: ActivationDisposition,
    activation_sha256: Option<Sha256Digest>,
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
            matches!(
                (self.disposition, self.activation_sha256),
                (ActivationDisposition::None, None) | (ActivationDisposition::Required, Some(_))
            ),
            "stage checkpoint disposition differs from its activation commitment"
        );
        ensure!(
            self.status == CheckpointStatus::OwnershipReleased,
            "stage checkpoint does not release source ownership"
        );
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
        image: ImageIdentity,
        selection_sha256: Sha256Digest,
        static_ability_contract_sha256: Sha256Digest,
        disposition: ActivationDisposition,
        activation_sha256: Option<Sha256Digest>,
    },
    SourceCompleted {
        schema: String,
        transaction: TransactionId,
        outcome: SourceOutcome,
    },
    HostReceived {
        schema: String,
        transaction: TransactionId,
        checkpoint_sha256: Sha256Digest,
        released_journal_head: Sha256Digest,
        image: ImageIdentity,
        static_ability_contract_sha256: Sha256Digest,
    },
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
                disposition,
                activation_sha256,
                ..
            } => {
                schema == JOURNAL_EVENT_SCHEMA
                    && *source_stage == ExecutionStage::Initrd
                    && *receiver_stage == ExecutionStage::Host
                    && validate_boot_id(boot_id).is_ok()
                    && transaction_for_boot(boot_id).is_ok_and(|expected| &expected == transaction)
                    && matches!(
                        (disposition, activation_sha256),
                        (ActivationDisposition::None, None)
                            | (ActivationDisposition::Required, Some(_))
                    )
            }
            Self::SourceCompleted { schema, .. } | Self::HostReceived { schema, .. } => {
                schema == JOURNAL_EVENT_SCHEMA
            }
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SourceOutcome {
    NoActivationRequired,
    ActivationSucceeded,
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

fn run_initrd_stage_with(
    image_profile: &Path,
    checkpoint_path: &Path,
    selection_bytes: &[u8],
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
) -> Result<()> {
    validate_boot_id(boot_id)?;
    let selection = ActivationSelection::decode(selection_bytes)?;
    StaticAbilityContract::decode(contract_bytes)?;
    let contract_digest = sha256_digest(contract_bytes);
    ensure!(
        selection.static_ability_contract_sha256 == contract_digest,
        "initrd activation selection names another static ability contract"
    );

    // The selection schema currently leaves required activation as arbitrary
    // JSON. Accepting that as executable input would bypass plan validation
    // and the typed adapter boundary.
    if selection.disposition == ActivationDisposition::Required {
        bail!(
            "required initrd activation has no typed execution contract; refusing to publish a handoff"
        );
    }

    let transaction = transaction_for_boot(boot_id)?;
    let activation_sha256 = selection
        .activation
        .as_ref()
        .map(canonical_value_digest)
        .transpose()?;
    let prepared = StageEvent::Prepared {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        source_stage: ExecutionStage::Initrd,
        receiver_stage: ExecutionStage::Host,
        boot_id: boot_id.to_string(),
        transaction: transaction.clone(),
        image: image.clone(),
        selection_sha256: sha256_digest(selection_bytes),
        static_ability_contract_sha256: contract_digest,
        disposition: selection.disposition,
        activation_sha256,
    };
    let completed = StageEvent::SourceCompleted {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        transaction: transaction.clone(),
        outcome: SourceOutcome::NoActivationRequired,
    };
    let transaction_dir = prepare_transaction_directory(image_profile, &transaction)?;
    let journal_path = transaction_dir.join(JOURNAL_FILE);
    let opened = FileJournal::<StageEvent>::open(&journal_path, stage_journal_limits())
        .context("opening initrd stage handoff journal")?;
    let mut journal = opened.journal;
    let records = opened.recovery.records();
    let released_head = match records {
        [] => {
            journal.ensure_capacity(2)?;
            journal.append(&prepared)?;
            journal.append(&completed)?.digest()
        }
        [first] if first.body() == &prepared => {
            journal.ensure_capacity(1)?;
            journal.append(&completed)?.digest()
        }
        [first, second] if first.body() == &prepared && second.body() == &completed => {
            second.digest()
        }
        [first, second, _] if first.body() == &prepared && second.body() == &completed => {
            bail!("initrd stage journal ownership was already received by the host")
        }
        _ => bail!("initrd stage journal differs from the authenticated boot selection"),
    };
    drop(journal);

    let checkpoint = StageCheckpoint {
        schema: CHECKPOINT_SCHEMA.to_string(),
        source_stage: ExecutionStage::Initrd,
        receiver_stage: ExecutionStage::Host,
        boot_id: boot_id.to_string(),
        transaction,
        image,
        selection_sha256: sha256_digest(selection_bytes),
        static_ability_contract_sha256: contract_digest,
        disposition: selection.disposition,
        activation_sha256,
        journal_head: released_head,
        status: CheckpointStatus::OwnershipReleased,
    };
    checkpoint.validate()?;
    let checkpoint_bytes = aos_contract::canonical::to_vec(&checkpoint)?;
    publish_atomic(checkpoint_path, &checkpoint_bytes)
        .context("publishing preserved initrd stage checkpoint")
}

fn receive_initrd_stage_with(
    image_profile: &Path,
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
) -> Result<()> {
    let release = load_validated_release(
        image_profile,
        checkpoint_path,
        contract_bytes,
        boot_id,
        &image,
    )?;
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
    let received = StageEvent::HostReceived {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        transaction: release.checkpoint.transaction.clone(),
        checkpoint_sha256: sha256_digest(&release.checkpoint_bytes),
        released_journal_head: release.checkpoint.journal_head,
        image,
        static_ability_contract_sha256: release.contract_digest,
    };
    journal.ensure_capacity(1)?;
    journal.append(&received)?;
    Ok(())
}

fn validate_initrd_stage_with(
    image_profile: &Path,
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: ImageIdentity,
) -> Result<()> {
    let release = load_validated_release(
        image_profile,
        checkpoint_path,
        contract_bytes,
        boot_id,
        &image,
    )?;
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
    image_profile: &Path,
    checkpoint_path: &Path,
    contract_bytes: &[u8],
    boot_id: &str,
    image: &ImageIdentity,
) -> Result<ValidatedRelease> {
    validate_boot_id(boot_id)?;
    StaticAbilityContract::decode(contract_bytes)?;
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

    let journal_path =
        existing_transaction_directory(image_profile, &checkpoint.transaction)?.join(JOURNAL_FILE);
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
        image,
        selection_sha256,
        static_ability_contract_sha256,
        disposition,
        activation_sha256,
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
            && image == &checkpoint.image
            && *selection_sha256 == checkpoint.selection_sha256
            && *static_ability_contract_sha256 == checkpoint.static_ability_contract_sha256
            && *disposition == checkpoint.disposition
            && *activation_sha256 == checkpoint.activation_sha256,
        "initrd stage journal preparation differs from the released checkpoint"
    );
    let StageEvent::SourceCompleted {
        transaction,
        outcome,
        ..
    } = source_completed
    else {
        bail!("initrd stage journal does not record source completion")
    };
    ensure!(
        transaction == &checkpoint.transaction
            && matches!(
                (checkpoint.disposition, outcome),
                (
                    ActivationDisposition::None,
                    SourceOutcome::NoActivationRequired
                ) | (
                    ActivationDisposition::Required,
                    SourceOutcome::ActivationSucceeded
                )
            ),
        "initrd stage completion differs from the released checkpoint"
    );
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
    Ok(())
}

fn prepare_transaction_directory(
    image_profile: &Path,
    transaction: &TransactionId,
) -> Result<PathBuf> {
    ensure_private_directory(image_profile, false)?;
    let root = image_profile.join(TRANSACTION_ROOT);
    ensure_private_directory(&root, true)?;
    let initrd = root.join(INITRD_TRANSACTION_ROOT);
    ensure_private_directory(&initrd, true)?;
    let transaction_dir = initrd.join(transaction.0.as_str());
    ensure_private_directory(&transaction_dir, true)?;
    sync_directory(&initrd)?;
    Ok(transaction_dir)
}

fn existing_transaction_directory(
    image_profile: &Path,
    transaction: &TransactionId,
) -> Result<PathBuf> {
    let transaction_dir = image_profile
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

fn canonical_value_digest(value: &serde_json::Value) -> Result<Sha256Digest> {
    Ok(sha256_digest(&aos_contract::canonical::to_vec(value)?))
}

fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Sha256Digest::from_bytes(digest)
}

fn stage_journal_limits() -> JournalLimits {
    JournalLimits {
        max_body_bytes: 64 * 1024,
        max_depth: 16,
        max_items: 256,
        max_string_bytes: 4096,
        max_records: 3,
        max_file_bytes: 256 * 1024,
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
    use super::*;

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    fn image() -> ImageIdentity {
        ImageIdentity {
            generation: 7,
            toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-system".to_string(),
            module_abi: 3,
            baselib_digest: format!("sha256:{}", "b".repeat(64)),
            root_verity_roothash: Some("c".repeat(64)),
        }
    }

    fn contract() -> Result<Vec<u8>> {
        Ok(aos_contract::canonical::to_vec(&StaticAbilityContract {
            schema: STATIC_CONTRACT_SCHEMA.to_string(),
            platforms: vec![StaticAbilityPlatform {
                platform: serde_json::json!({"architecture":"amd64","os":"linux"}),
                execution_stage: ExecutionStage::Initrd,
                packages: Vec::new(),
                abilities: Vec::new(),
                unresolved_launch_obligations: Vec::new(),
            }],
            runtime_grants: Vec::new(),
        })?)
    }

    fn none_selection(contract: &[u8]) -> Result<Vec<u8>> {
        Ok(aos_contract::canonical::to_vec(&ActivationSelection {
            schema: SELECTION_SCHEMA.to_string(),
            execution_stage: ExecutionStage::Initrd,
            disposition: ActivationDisposition::None,
            static_ability_contract_sha256: sha256_digest(contract),
            activation: None,
        })?)
    }

    #[test]
    fn transfers_none_disposition_through_durable_journal() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("image");
        let checkpoint = temporary
            .path()
            .join("run/aos/ability-stage-handoff/initrd.json");
        fs::create_dir(&profile)?;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        let contract = contract()?;
        let selection = none_selection(&contract)?;

        run_initrd_stage_with(
            &profile,
            &checkpoint,
            &selection,
            &contract,
            BOOT_ID,
            image(),
        )?;
        let transaction = transaction_for_boot(BOOT_ID)?;
        let journal = profile
            .join(TRANSACTION_ROOT)
            .join(INITRD_TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(JOURNAL_FILE);
        let released_journal = fs::read(&journal)?;
        let released_checkpoint = fs::read(&checkpoint)?;
        validate_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image())?;
        assert_eq!(fs::read(&journal)?, released_journal);
        assert_eq!(fs::read(&checkpoint)?, released_checkpoint);

        receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image())?;
        receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image())?;

        let snapshot =
            FileJournal::<StageEvent>::read_only_snapshot(journal, stage_journal_limits())?;
        assert_eq!(snapshot.records().len(), 3);
        assert!(matches!(
            snapshot.records()[0].body(),
            StageEvent::Prepared { .. }
        ));
        assert!(matches!(
            snapshot.records()[1].body(),
            StageEvent::SourceCompleted { .. }
        ));
        assert!(matches!(
            snapshot.records()[2].body(),
            StageEvent::HostReceived { .. }
        ));
        Ok(())
    }

    #[test]
    fn initrd_barrier_rejects_a_missing_or_tampered_checkpoint() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("image");
        let checkpoint = temporary
            .path()
            .join("run/aos/ability-stage-handoff/initrd.json");
        fs::create_dir(&profile)?;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        let contract = contract()?;

        assert!(
            validate_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image())
                .expect_err("missing checkpoint must block switch-root")
                .to_string()
                .contains("opening preserved initrd stage checkpoint")
        );

        run_initrd_stage_with(
            &profile,
            &checkpoint,
            &none_selection(&contract)?,
            &contract,
            BOOT_ID,
            image(),
        )?;
        let mut bytes = fs::read(&checkpoint)?;
        let midpoint = bytes.len() / 2;
        bytes[midpoint] ^= 1;
        fs::write(&checkpoint, bytes)?;
        assert!(
            validate_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image()).is_err()
        );
        Ok(())
    }

    #[test]
    fn required_activation_fails_before_durable_state_or_checkpoint() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("image");
        let checkpoint = temporary.path().join("run/initrd.json");
        fs::create_dir(&profile)?;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        let contract = contract()?;
        let selection = aos_contract::canonical::to_vec(&ActivationSelection {
            schema: SELECTION_SCHEMA.to_string(),
            execution_stage: ExecutionStage::Initrd,
            disposition: ActivationDisposition::Required,
            static_ability_contract_sha256: sha256_digest(&contract),
            activation: Some(serde_json::json!({"untyped":"rejected"})),
        })?;

        let error = run_initrd_stage_with(
            &profile,
            &checkpoint,
            &selection,
            &contract,
            BOOT_ID,
            image(),
        )
        .expect_err("untyped execution must fail closed");
        assert!(error.to_string().contains("no typed execution contract"));
        assert!(!profile.join(TRANSACTION_ROOT).exists());
        assert!(!checkpoint.exists());
        Ok(())
    }

    #[test]
    fn receiver_rejects_changed_boot_image_contract_and_checkpoint() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("image");
        let checkpoint = temporary
            .path()
            .join("run/aos/ability-stage-handoff/initrd.json");
        fs::create_dir(&profile)?;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        let contract = contract()?;
        let selection = none_selection(&contract)?;
        run_initrd_stage_with(
            &profile,
            &checkpoint,
            &selection,
            &contract,
            BOOT_ID,
            image(),
        )?;

        let other_boot = "fedcba98-7654-3210-fedc-ba9876543210";
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &contract, other_boot, image())
                .expect_err("other boot must fail")
                .to_string()
                .contains("another boot")
        );
        let mut other_image = image();
        other_image.generation += 1;
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, other_image)
                .expect_err("other image must fail")
                .to_string()
                .contains("another image")
        );
        let mut other_contract: StaticAbilityContract = serde_json::from_slice(&contract)?;
        other_contract.platforms[0].platform =
            serde_json::json!({"architecture":"arm64","os":"linux"});
        let other_contract = aos_contract::canonical::to_vec(&other_contract)?;
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &other_contract, BOOT_ID, image())
                .expect_err("other contract must fail")
                .to_string()
                .contains("another initrd static ability contract")
        );

        let mut bytes = fs::read(&checkpoint)?;
        let midpoint = bytes.len() / 2;
        bytes[midpoint] ^= 1;
        fs::write(&checkpoint, bytes)?;
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image()).is_err()
        );
        Ok(())
    }

    #[test]
    fn receiver_rejects_a_torn_or_mutated_released_journal() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("image");
        let checkpoint = temporary
            .path()
            .join("run/aos/ability-stage-handoff/initrd.json");
        fs::create_dir(&profile)?;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        let contract = contract()?;
        run_initrd_stage_with(
            &profile,
            &checkpoint,
            &none_selection(&contract)?,
            &contract,
            BOOT_ID,
            image(),
        )?;
        let transaction = transaction_for_boot(BOOT_ID)?;
        let journal = profile
            .join(TRANSACTION_ROOT)
            .join(INITRD_TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(JOURNAL_FILE);
        let pristine = fs::read(&journal)?;

        let mut mutated = pristine.clone();
        let index = mutated.len() / 2;
        mutated[index] ^= 1;
        fs::write(&journal, &mutated)?;
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image()).is_err()
        );

        fs::write(&journal, &pristine[..pristine.len() - 7])?;
        assert!(
            receive_initrd_stage_with(&profile, &checkpoint, &contract, BOOT_ID, image()).is_err()
        );
        Ok(())
    }
}
