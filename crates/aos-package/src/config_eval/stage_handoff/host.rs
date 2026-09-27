//! Host-stage execution after durable initrd ownership receipt.
//!
//! The host replays the initrd receipt before admitting its own source plan.
//! Its journal and transaction session live in the host slot selected by the
//! package-owned transaction-storage ability.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_runtime::journal::FileJournal;
use aos_ability_validate::StaticAbilityExecutionStage;

use super::{
    BOOT_ID_PATH, DOCUMENT_MAX_BYTES, ImageIdentity, JOURNAL_EVENT_SCHEMA, JOURNAL_FILE,
    StageEvent, TransactionStorageSelection, execute_source_stage, prepare_transaction_directory,
    read_boot_id, read_trusted_file, receive_initrd_stage, require_privileged_runtime,
    selected_transaction_storage, sha256_digest, source_completion_for_run, stage_journal_limits,
    transaction_for_boot, validate_source_contract_binding, validate_source_stage_evidence,
};

/// Receives the initrd journal and executes the sealed host source stage.
///
/// # Errors
///
/// Returns an error when the handoff, image, static contracts, source bundle,
/// root observations, journal, or checked native effects fail validation.
pub fn run_host_stage(
    image_profile: &Path,
    initrd_source_stage_bundle: &Path,
    initrd_static_contract_identity: &str,
    initrd_static_contract: &Path,
    source_stage_bundle: &Path,
    static_contract_identity: &str,
    static_contract: &Path,
) -> Result<()> {
    require_privileged_runtime()?;
    receive_initrd_stage(
        "initrd",
        image_profile,
        initrd_source_stage_bundle,
        initrd_static_contract_identity,
        initrd_static_contract,
    )
    .context("receiving initrd ownership before host-stage execution")?;

    let generation =
        crate::sysroot::running_image_generation_beneath(image_profile, Path::new("/"))
            .context("authenticating the host running image")?;
    let image = ImageIdentity::from_generation(&generation);
    let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
    let contract_bytes = read_trusted_file(
        static_contract,
        DOCUMENT_MAX_BYTES,
        "host static ability contract",
    )?;
    let source_stage_bytes = read_trusted_file(
        source_stage_bundle,
        DOCUMENT_MAX_BYTES,
        "host source stage bundle",
    )?;
    validate_source_contract_binding(
        &source_stage_bytes,
        static_contract_identity,
        &contract_bytes,
        StaticAbilityExecutionStage::Host,
    )?;
    let transaction_storage =
        selected_transaction_storage(&source_stage_bytes, StaticAbilityExecutionStage::Host)?;

    run_host_stage_with(
        &transaction_storage,
        &contract_bytes,
        static_contract_identity,
        &boot_id,
        image,
        &source_stage_bytes,
    )
}

fn run_host_stage_with(
    transaction_storage: &TransactionStorageSelection,
    contract_bytes: &[u8],
    static_contract_identity: &str,
    boot_id: &str,
    image: ImageIdentity,
    source_stage_bundle_bytes: &[u8],
) -> Result<()> {
    let packages = super::super::static_packages::verified_stage_packages(
        contract_bytes,
        StaticAbilityExecutionStage::Host,
    )
    .context("authenticating host static ability contract")?;
    let transaction = transaction_for_boot(StaticAbilityExecutionStage::Host, boot_id)?;
    let transaction_root = transaction_storage
        .root
        .to_str()
        .context("selected transaction-storage path is not UTF-8")?
        .to_string();
    let transaction_dir = prepare_transaction_directory(
        &transaction_storage.root,
        StaticAbilityExecutionStage::Host,
        &transaction,
    )?;
    let admitted = super::super::source_stage_admission::load_or_admit_source_stage(
        source_stage_bundle_bytes,
        &packages,
        static_contract_identity,
        boot_id,
        &transaction_dir,
    )?;
    let prepared = StageEvent::HostPrepared {
        schema: JOURNAL_EVENT_SCHEMA.to_string(),
        boot_id: boot_id.to_string(),
        transaction: transaction.clone(),
        transaction_storage: transaction_storage.resource.clone(),
        transaction_root,
        image,
        static_ability_contract_identity: static_contract_identity.to_string(),
        static_ability_contract_sha256: sha256_digest(contract_bytes),
        source_stage_bundle_sha256: sha256_digest(source_stage_bundle_bytes),
        source_stage_admission_sha256: admitted.record_digest,
    };
    let journal_path = transaction_dir.join(JOURNAL_FILE);
    let opened = FileJournal::<StageEvent>::open(&journal_path, stage_journal_limits())
        .context("opening host stage journal")?;
    let mut journal = opened.journal;
    let records = opened.recovery.records();
    let existing = match records {
        [] => {
            journal.ensure_capacity(2)?;
            journal.append(&prepared)?;
            None
        }
        [first] if first.body() == &prepared => {
            journal.ensure_capacity(1)?;
            None
        }
        [first, second] if first.body() == &prepared => Some(second.body()),
        _ => bail!("host stage journal differs from the authenticated resolved plan"),
    };
    let already_completed = existing.is_some();
    let completion = source_completion_for_run(
        existing,
        &transaction,
        || {
            execute_source_stage(
                &admitted,
                &packages,
                &transaction_storage.root,
                transaction.clone(),
                StaticAbilityExecutionStage::Host,
            )
        },
        |execution| {
            validate_source_stage_evidence(
                &admitted.checked,
                execution,
                StaticAbilityExecutionStage::Host,
            )
        },
    )?;
    if !already_completed {
        journal.append(&completion)?;
    }
    let StageEvent::SourceCompleted { execution, .. } = completion else {
        bail!("host stage did not produce checked source completion")
    };
    validate_source_stage_evidence(
        &admitted.checked,
        &execution,
        StaticAbilityExecutionStage::Host,
    )
}
