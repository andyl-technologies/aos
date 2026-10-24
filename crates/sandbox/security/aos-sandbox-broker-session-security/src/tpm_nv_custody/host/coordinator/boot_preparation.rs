//! Owns the finite normal publisher and exits with every reached owner resident.
//!
//! The only entry takes the actual admitted Boot Source. It derives its sole
//! record from same-Origin facts and a freshly authenticated protected055 cut,
//! completes that exact native transaction, then uses the common atomic writer
//! for canonical JSON and its full-record completed-target companion.

use std::fs::File;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox_controller_domain::{
    JournalRecord, JournalTransaction, RecordNamespace, RuntimeBootPreparationOriginsOriginalV1,
    RuntimeBootPreparationStartupOriginalV1, RuntimeDeploymentComparisonOriginsV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_host::phase0_probe::{
    Phase0DeploymentFactsDataV2, Phase0DeploymentFactsOriginalV2,
};
use aos_sandbox_linux::protected_file::{
    FixedProtectedReadOriginalV3,
    ReadinessAtomicWriteOriginalV2, ReadinessAtomicWritePurposeV2,
};
use aos_sandbox_protocol::runtime_deployment::{
    boot_preparation::{
        BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1, BOOT_PREPARATION_COMPLETION_BYTES_V1,
        BOOT_PREPARATION_RECORD_BODY_BYTES_V1, BOOT_PREPARATION_RECORD_BYTES_V1,
        BootPreparationCompletionFieldsDataV1, BootPreparationRecordDataV1,
        SignedBootPreparationCompletionDataV1, SignedBootPreparationRecordDataV1,
        boot_preparation_key_data_v1, boot_preparation_transaction_data_v1,
    },
    readiness_preparation::{
        BACKEND_READINESS_PREPARATION_SCHEMA_V1, BackendReadinessPreparationDataV1,
        MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1,
    },
};
use ed25519_dalek::Signer as _;
use rustix::fs::{Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};

use super::super::{journal::CanaryHostNativeStepV2, physical::HostBootPhysicalConsumerV1};
use super::{CanarySigningDiagnosticV2, CanarySigningOriginalV2};

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-runtime-publisher.service";
const OUTPUT_DIRECTORY: &str = "/var/lib/aos/sandbox/runtime-deployment/readiness";
const OUTPUT_ANCESTRY: [&str; 6] = [
    "var",
    "lib",
    "aos",
    "sandbox",
    "runtime-deployment",
    "readiness",
];
const JSON_PATH: &str = "/var/lib/aos/sandbox/runtime-deployment/readiness/backend-readiness.json";
const COMPLETION_PATH: &str =
    "/var/lib/aos/sandbox/runtime-deployment/readiness/backend-readiness-completion-v1";

#[derive(Debug, thiserror::Error)]
enum Cause {
    #[error("normal startup original refused")]
    Startup(#[from] aos_sandbox_controller_domain::RuntimeBootPreparationStartupClosedV1),
    #[error("normal Origins admission refused")]
    Admission(#[from] aos_sandbox_controller_domain::RuntimeBootPreparationOriginsClosedV1),
    #[error("normal same-Source comparison refused")]
    Comparison(#[from] aos_sandbox_controller_domain::RuntimeDeploymentComparisonErrorV1),
    #[error("normal signing original refused")]
    Signing(#[from] CanarySigningDiagnosticV2),
    #[error("normal retained native journal admission refused")]
    JournalAdmission(#[from] super::super::journal::CanaryJournalAdmissionDiagnosticV2),
    #[error("normal journal original refused")]
    Journal(#[from] super::super::HostOwnedJournalErrorV1),
    #[error("normal physical original refused")]
    Physical(#[from] super::super::physical::CanaryPhysicalErrorV2),
    #[error("normal physical preparation refused")]
    PhysicalPreparation(#[from] super::super::physical::PhysicalTpmFailureV1),
    #[error("normal native current-boot observation refused")]
    Clock(#[from] aos_sandbox_controller_domain::RuntimeDeploymentOriginalClockCauseV3),
    #[error("normal fixed native directory observation refused")]
    Directory(#[from] rustix::io::Errno),
    #[error("normal authenticated phase-0 facts refused")]
    Facts(#[from] aos_sandbox_host::phase0_probe::Phase0DeploymentFactsClosedV2),
    #[error("normal record encoding refused")]
    Wire(#[from] aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1),
    #[error("normal atomic output refused")]
    Write(
        #[from]
        aos_sandbox_linux::protected_file::ReadinessAtomicWriteClosedV2,
    ),
    #[error("normal exact native readback refused")]
    Readback(#[from] aos_sandbox_linux::protected_file::FixedProtectedReadClosedV3),
    #[error("normal actor was interrupted")]
    Unwind,
    #[error("normal original coordinates differ or are incomplete")]
    Changed,
}

// Concrete finite debt slots remain on the caller's stack until native exit.
// A full ledger cannot silently discard either an owner or a later cause.
struct Ledger {
    first: Option<Cause>,
    later: [Option<Cause>; 32],
    next: usize,
}

impl Ledger {
    fn new() -> Self {
        Self {
            first: None,
            later: std::array::from_fn(|_| None),
            next: 0,
        }
    }

    fn retain(&mut self, result: Result<(), Cause>) {
        if let Err(cause) = result {
            if self.first.is_none() {
                self.first = Some(cause);
            } else {
                let Some(slot) = self.later.get_mut(self.next) else {
                    std::process::abort();
                };
                if slot.is_some() {
                    std::process::abort();
                }
                *slot = Some(cause);
                self.next += 1;
            }
        }
    }
}

struct Outputs {
    facts: Phase0DeploymentFactsOriginalV2,
    data: Option<Phase0DeploymentFactsDataV2>,
    json: Option<Vec<u8>>,
    record: Option<SignedBootPreparationRecordDataV1>,
    transaction: Option<JournalTransaction>,
    record_preimage: Option<Vec<u8>>,
    completion_preimage: Option<Vec<u8>>,
    record_bytes: [u8; BOOT_PREPARATION_RECORD_BYTES_V1],
    completion_bytes: [u8; BOOT_PREPARATION_COMPLETION_BYTES_V1],
    completion: Option<SignedBootPreparationCompletionDataV1>,
    directory: DirectoryOriginal,
    json_write: ReadinessAtomicWriteOriginalV2,
    completion_write: ReadinessAtomicWriteOriginalV2,
    json_read: FixedProtectedReadOriginalV3,
    completion_read: FixedProtectedReadOriginalV3,
}

impl Outputs {
    fn new() -> Self {
        Self {
            facts: Phase0DeploymentFactsOriginalV2::new(),
            data: None,
            json: None,
            record: None,
            transaction: None,
            record_preimage: None,
            completion_preimage: None,
            record_bytes: [0; BOOT_PREPARATION_RECORD_BYTES_V1],
            completion_bytes: [0; BOOT_PREPARATION_COMPLETION_BYTES_V1],
            completion: None,
            directory: DirectoryOriginal::new(),
            json_write: ReadinessAtomicWriteOriginalV2::new(),
            completion_write: ReadinessAtomicWriteOriginalV2::new(),
            json_read: FixedProtectedReadOriginalV3::new(),
            completion_read: FixedProtectedReadOriginalV3::new(),
        }
    }

    fn receiving_demand(
        origins: &RuntimeDeploymentComparisonOriginsV1<'_>,
    ) -> Option<ResourceVector> {
        let profile = origins.boot_profile_data_v1().ok()?;
        let facts = Phase0DeploymentFactsOriginalV2::receiving_demand_v2(
            Path::new(CREDENTIAL_DIRECTORY),
            &profile.nspawn_executable,
            Path::new(&profile.hostd_executable),
            &profile.selinux_policy,
        )?;
        // Codec preimages are each shorter than twice their fixed complete wire.
        // The sole JSON codec has an independent fixed16KiB output ceiling.
        let wire =
            BOOT_PREPARATION_RECORD_BYTES_V1.checked_add(BOOT_PREPARATION_COMPLETION_BYTES_V1)?;
        let bytes = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(wire.checked_mul(6)?)?
            .checked_add(MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1.checked_mul(4)?)?
            .checked_add(profile.nspawn_executable.len().checked_mul(2)?)?
            .checked_add(size_of::<JournalRecord>().checked_mul(2)?)?
            .checked_add(size_of::<JournalTransaction>().checked_mul(2)?)?;
        let mut demand = facts
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
            .ok()?;
        for maximum in [
            MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1,
            BOOT_PREPARATION_COMPLETION_BYTES_V1,
        ] {
            let (memory, files) = FixedProtectedReadOriginalV3::receiving_obligations_v3(maximum)?;
            demand = demand
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                        .with(D::OpenFiles, u64::try_from(files).ok()?)
                        .with(D::MetadataEntries, 1)
                        .with(D::OutputBytes, u64::try_from(maximum.checked_add(1)?).ok()?),
                )
                .ok()?;
        }
        demand
            .checked_add(DirectoryOriginal::receiving_demand()?)
            .ok()
    }

    fn observe_facts(
        &mut self,
        origins: &RuntimeDeploymentComparisonOriginsV1<'_>,
    ) -> Result<(), Cause> {
        let profile = origins.boot_profile_data_v1()?;
        self.data = self.facts.observe_once_v2(
            Path::new(CREDENTIAL_DIRECTORY),
            &profile.nspawn_executable,
            Path::new(&profile.hostd_executable),
            &profile.selinux_policy,
        )?;
        let facts = self.data.as_ref().ok_or(Cause::Changed)?;
        let source = origins.boot_source_comparison_data_v1()?;
        let genesis = origins.genesis_claims();
        if facts.observation.boot_id != source.boot
            || facts.declared_pid1_digest != origins.retained_pid1()?.measured_digest_v1()
            || facts.observation.nspawn_sha256 != genesis.nspawn_digest
            || facts.supervisor_profile_digest != genesis.supervisor_filter
            || facts.payload_filter_digest != genesis.payload_filter
            || facts.observation.selinux_policy_sha256 != genesis.mac_policy
        {
            return Err(Cause::Changed);
        }
        Ok(())
    }

    fn publish(
        &mut self,
        origins: &RuntimeDeploymentComparisonOriginsV1<'_>,
        ledger: &mut Ledger,
    ) -> Result<(), Cause> {
        let json = self.json.as_deref().ok_or(Cause::Changed)?;
        let completion = self.completion.as_ref().ok_or(Cause::Changed)?;
        let mut quote = ResourceVector::ZERO;
        for (purpose, bytes) in [
            (ReadinessAtomicWritePurposeV2::BootPreparation, json.len()),
            (
                ReadinessAtomicWritePurposeV2::BootPreparationCompletion,
                completion.bytes_v1().len(),
            ),
        ] {
            let shape = ReadinessAtomicWriteOriginalV2::receiving_shape_v2(purpose, bytes)
                .ok_or(Cause::Changed)?;
            quote = quote
                .checked_add(
                    ResourceVector::ZERO
                        .with(
                            D::MemoryBytes,
                            u64::try_from(shape.memory_bytes).map_err(|_| Cause::Changed)?,
                        )
                        .with(
                            D::OpenFiles,
                            u64::try_from(shape.open_files).map_err(|_| Cause::Changed)?,
                        )
                        .with(
                            D::MetadataEntries,
                            u64::try_from(shape.namespace_entries).map_err(|_| Cause::Changed)?,
                        )
                        .with(
                            D::StorageBytes,
                            u64::try_from(shape.storage_bytes).map_err(|_| Cause::Changed)?,
                        )
                        .with(
                            D::OutputBytes,
                            u64::try_from(shape.output_bytes).map_err(|_| Cause::Changed)?,
                        ),
                )
                .map_err(|_| Cause::Changed)?;
        }
        origins.admit_boot_publisher_representation_v1(Some(quote))?;
        self.directory.capture_once()?;
        let directory = self.directory.file()?;
        self.json_write.replace_once_v2(
            directory.as_fd(),
            ReadinessAtomicWritePurposeV2::BootPreparation,
            json,
        )?;
        self.completion_write.replace_once_v2(
            directory.as_fd(),
            ReadinessAtomicWritePurposeV2::BootPreparationCompletion,
            completion.bytes_v1(),
        )?;

        // Both real readback bodies and their own two independent posts run,
        // even when the first completed-file comparison refuses.
        let first = readback(&mut self.json_read, Path::new(JSON_PATH), json);
        let second = readback(
            &mut self.completion_read,
            Path::new(COMPLETION_PATH),
            completion.bytes_v1(),
        );
        ledger.retain(first);
        ledger.retain(second);
        Ok(())
    }
}

fn readback(
    original: &mut FixedProtectedReadOriginalV3,
    path: &Path,
    expected: &[u8],
) -> Result<(), Cause> {
    let body = (|| {
        original.capture_once_v3(path)?;
        let metadata = original.metadata_v3().ok_or(Cause::Changed)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Cause::Changed);
        }
        original.read_exact_bytes_and_eof_once_v3(expected.len())?;
        Ok(())
    })();
    let post = original.finish_once_v3(path).map_err(Cause::from);
    body.and(post)?;
    if original.bytes_completed_v3() != Some(expected) {
        return Err(Cause::Changed);
    }
    Ok(())
}

// These seven actual directory descriptions and their original metadata stay
// resident after failed validation. A separate seven-description named pass is
// reserved before the body; it cannot be consumed by retries or body traffic.
struct DirectoryOriginal {
    original: [Option<File>; 7],
    original_stats: [Option<Result<Stat, rustix::io::Errno>>; 7],
    named: [Option<File>; 7],
    named_stats: [Option<Result<Stat, rustix::io::Errno>>; 7],
    entered: bool,
    posted: bool,
    first: Option<Cause>,
    later: Option<Cause>,
}

impl DirectoryOriginal {
    fn new() -> Self {
        Self {
            original: std::array::from_fn(|_| None),
            original_stats: std::array::from_fn(|_| None),
            named: std::array::from_fn(|_| None),
            named_stats: std::array::from_fn(|_| None),
            entered: false,
            posted: false,
            first: None,
            later: None,
        }
    }

    fn receiving_demand() -> Option<ResourceVector> {
        Some(
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(
                        size_of::<Self>()
                            .checked_mul(2)?
                            .checked_add(OUTPUT_DIRECTORY.len().checked_mul(4)?)?,
                    )
                    .ok()?,
                )
                .with(D::OpenFiles, 14)
                .with(D::MetadataEntries, 14),
        )
    }

    fn capture_once(&mut self) -> Result<(), Cause> {
        if self.entered {
            return Err(Cause::Changed);
        }
        self.entered = true;
        let result = capture_directory(&mut self.original, &mut self.original_stats);
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first = Some(cause);
                Err(Cause::Changed)
            }
        }
    }

    fn file(&self) -> Result<&File, Cause> {
        if self.first.is_some() {
            return Err(Cause::Changed);
        }
        self.original[6].as_ref().ok_or(Cause::Changed)
    }

    fn finish_once(&mut self) -> Result<(), Cause> {
        if !self.entered {
            return Ok(());
        }
        if self.posted {
            return Err(Cause::Changed);
        }
        self.posted = true;
        let result = capture_directory(&mut self.named, &mut self.named_stats).and_then(|()| {
            for (before, after) in self.original_stats.iter().zip(&self.named_stats) {
                if let (Some(Ok(before)), Some(Ok(after))) = (before, after) {
                    if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
                        return Err(Cause::Changed);
                    }
                } else {
                    return Err(Cause::Changed);
                }
            }
            Ok(())
        });
        if let Err(cause) = result {
            if self.first.is_none() {
                self.first = Some(cause);
            } else {
                self.later = Some(cause);
            }
        }
        if self.first.is_some() {
            Err(Cause::Changed)
        } else {
            Ok(())
        }
    }
}

fn capture_directory(
    files: &mut [Option<File>; 7],
    stats: &mut [Option<Result<Stat, rustix::io::Errno>>; 7],
) -> Result<(), Cause> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    files[0] = Some(File::from(rustix::fs::open("/", flags, Mode::empty())?));
    for index in 0..7 {
        let directory = files[index].as_ref().ok_or(Cause::Changed)?;
        stats[index] = Some(rustix::fs::fstat(directory));
        let stat = match stats[index].as_ref() {
            Some(Ok(stat)) => stat,
            Some(Err(cause)) => return Err((*cause).into()),
            None => return Err(Cause::Changed),
        };
        if stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o022 != 0
            || (index == 6 && stat.st_mode & 0o777 != 0o700)
        {
            return Err(Cause::Changed);
        }
        if let Some(name) = OUTPUT_ANCESTRY.get(index) {
            files[index + 1] = Some(File::from(rustix::fs::openat(
                directory,
                *name,
                flags,
                Mode::empty(),
            )?));
        }
    }
    Ok(())
}

/// Runs the sole normal completed055 preparation and exits with all owners held.
///
/// The caller captures Source before argv and admits its original startup. This
/// entry creates no provisioned state and accepts no DATA, key, file, role,
/// effect callback, generation or claimed native target. Every exit performs
/// the same independently owed Source after while the caller's Source and this
/// function's reached original owners remain resident. Process status is the
/// final PID1 success witness; no return value can release the original Source.
pub fn run_runtime_boot_preparation_once_v1(
    startup: &RuntimeBootPreparationStartupOriginalV1,
) -> ! {
    let mut admitted = match RuntimeBootPreparationOriginsOriginalV1::new(startup) {
        Ok(owner) => owner,
        Err(cause) => {
            let _cause = cause;
            let _after = startup.finish_source_after_owed_once_v1(Err(
                aos_sandbox_controller_domain::RuntimeBootPreparationStartupClosedV1,
            ));
            std::process::exit(1);
        }
    };
    let admission_result = caught(|| admitted.admit_once_v1().map_err(Into::into));
    if admission_result.is_err() {
        let _after = startup.finish_source_after_owed_once_v1(Err(
            aos_sandbox_controller_domain::RuntimeBootPreparationStartupClosedV1,
        ));
        std::process::exit(1);
    }
    let origins = admitted
        .origins_v1()
        .unwrap_or_else(|| std::process::abort());
    let demand = Outputs::receiving_demand(origins).and_then(|demand| {
        let carriers = size_of::<Ledger>()
            .checked_mul(2)?
            .checked_add(size_of::<CanarySigningOriginalV2<'_, '_>>().checked_mul(2)?)?
            .checked_add(
                size_of::<super::super::journal::HostCanaryJournalAdmissionV2<'_, '_>>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<HostBootPhysicalConsumerV1<'_, '_, '_>>().checked_mul(2)?)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(carriers).ok()?))
            .ok()
    });
    let receiving = origins.admit_boot_publisher_representation_v1(demand);
    if receiving.is_err() {
        let _after = startup.finish_source_after_owed_once_v1(Err(
            aos_sandbox_controller_domain::RuntimeBootPreparationStartupClosedV1,
        ));
        std::process::exit(1);
    }

    let mut ledger = Ledger::new();
    let mut outputs = Outputs::new();
    let mut signing = CanarySigningOriginalV2::new(origins);
    let mut journals = super::super::journal::HostCanaryJournalAdmissionV2::new(origins);
    let native = match origins.prepare_boot_native_original_v1() {
        Ok(native) => native,
        Err(cause) => {
            ledger.retain(Err(cause.into()));
            finish(startup, &mut ledger);
        }
    };
    ledger.retain(caught(|| {
        native.prepare_once_v1()?;
        signing.capture_boot_once_v1(&native)?;
        outputs.observe_facts(origins)?;
        journals.admit_boot_once_v1(&native)?;
        Ok(())
    }));
    if ledger.first.is_some() {
        ledger.retain(journals.drain_boot_after_unwind_once_v1().map_err(Into::into));
        ledger.retain(native.finish_outer_startup_after_owed_once_v1().map_err(Into::into));
        ledger.retain(signing.recheck_boot_once_v1(&native).map_err(Into::into));
        ledger.retain(native.require_clock_owed_once_v1().map_err(Into::into));
        ledger.retain(origins.recheck().map_err(Into::into));
        finish(startup, &mut ledger);
    }
    let owner = journals
        .owner_mut()
        .unwrap_or_else(|_| std::process::abort());
    let mut physical = match HostBootPhysicalConsumerV1::retain(owner, &native) {
        Ok(physical) => physical,
        Err(cause) => {
            ledger.retain(Err(cause.into()));
            finish(startup, &mut ledger);
        }
    };
    let body_result = caught(|| {
        physical.prepare_once()?;
        if physical.admit(&native)? != crate::tpm_nv_custody::FloorRecoveryV1::Current {
            return Err(Cause::Changed);
        }
        let before = physical.main_data(&native)?;
        if before.stored.prepared.is_some()
            || before.stored.current != before.stored.checkpoint.cut()
        {
            return Err(Cause::Changed);
        }
        let generation = before
            .stored
            .checkpoint
            .ordinal()
            .checked_add(1)
            .ok_or(Cause::Changed)?;
        if before
            .last
            .as_ref()
            .map_or(before.stored.checkpoint.ordinal() != 1, |last| {
                last.fields_v1().publisher_generation != before.stored.checkpoint.ordinal()
            })
        {
            return Err(Cause::Changed);
        }
        let facts = outputs.data.as_ref().ok_or(Cause::Changed)?;
        let profile = origins.boot_profile_data_v1()?;
        let source = origins.boot_source_comparison_data_v1()?;
        let purpose = origins.boot_purpose_v1().ok_or(Cause::Changed)?;
        let genesis = origins.genesis_claims();
        let json = BackendReadinessPreparationDataV1 {
            schema: BACKEND_READINESS_PREPARATION_SCHEMA_V1.to_owned(),
            publisher_generation: generation,
            boot_id: source.boot,
            nspawn_store_path: profile.nspawn_executable.clone(),
            nspawn_device: facts.nspawn_device,
            nspawn_inode: facts.nspawn_inode,
            probe_digest: facts.probe_digest,
            supervisor_profile_digest: facts.supervisor_profile_digest,
            payload_filter_digest: facts.payload_filter_digest,
        };
        outputs.json = Some(json.encode_data_v1()?);
        let fields = BootPreparationRecordDataV1 {
            purpose: purpose.digest_v1(),
            signed_genesis_digest: Sha256::digest(origins.signed_genesis()).into(),
            node: genesis.node,
            deployment: genesis.deployment,
            publisher_generation: generation,
            boot: source.boot,
            publisher_invocation: source.recipient_invocation,
            previous_record: before
                .last
                .as_ref()
                .map_or([0; 32], SignedBootPreparationRecordDataV1::digest_v1),
            source_contract: purpose.fields_v1().source_contract,
            publisher_profile: genesis.publisher_profile,
            nspawn_path_digest: Sha256::digest(profile.nspawn_executable.as_bytes()).into(),
            nspawn_device: facts.nspawn_device,
            nspawn_inode: facts.nspawn_inode,
            nspawn_digest: facts.observation.nspawn_sha256,
            pid1_digest: origins.retained_pid1()?.measured_digest_v1(),
            hostd_digest: facts.observation.hostd_sha256,
            inspector_digest: facts.observation.inspector_sha256,
            probe_digest: facts.probe_digest,
            mac_policy_digest: facts.observation.selinux_policy_sha256,
            supervisor_profile_digest: facts.supervisor_profile_digest,
            payload_filter_digest: facts.payload_filter_digest,
            artifact_digest: Sha256::digest(outputs.json.as_deref().ok_or(Cause::Changed)?).into(),
            predecessor_ordinal: before.stored.checkpoint.ordinal(),
            predecessor_sequence: before.stored.current.sequence(),
            predecessor_head: before.stored.current.head(),
            predecessor_nv: physical.final_nv()?,
        };
        outputs.record_preimage = Some(fields.signing_bytes_v1()?);
        signing.recheck_boot_once_v1(&native)?;
        origins.recheck()?;
        physical.terminal_observations(&native)?;
        native.require_clock()?;
        let signature = signing
            .key
            .as_ref()
            .ok_or(Cause::Changed)?
            .sign(outputs.record_preimage.as_deref().ok_or(Cause::Changed)?)
            .to_bytes();
        outputs.record_bytes[..BOOT_PREPARATION_RECORD_BODY_BYTES_V1]
            .copy_from_slice(&fields.encode_body_v1()?);
        outputs.record_bytes[BOOT_PREPARATION_RECORD_BODY_BYTES_V1..].copy_from_slice(&signature);
        // The actual signature is parked before any independent post can refuse.
        ledger.retain(signing.recheck_boot_once_v1(&native).map_err(Into::into));
        ledger.retain(origins.recheck().map_err(Into::into));
        ledger.retain(physical.terminal_observations(&native).map_err(Into::into));
        if ledger.first.is_some() {
            return Ok(());
        }
        outputs.record = Some(SignedBootPreparationRecordDataV1::verify_v1(
            &outputs.record_bytes,
            purpose,
        )?);
        let row = outputs.record.as_ref().ok_or(Cause::Changed)?;
        let native_transaction = boot_preparation_transaction_data_v1(row.fields_v1())?;
        outputs.transaction = Some(
            JournalTransaction::new(
                native_transaction,
                vec![JournalRecord::put(
                    RecordNamespace::HostCatalogReconciliation,
                    boot_preparation_key_data_v1(generation)?.to_vec(),
                    row.bytes_v1().to_vec(),
                )],
            )
            .map_err(aos_sandbox_controller_domain::JournalError::from)
            .map_err(super::super::HostOwnedJournalErrorV1::from)?,
        );
        let transaction = outputs.transaction.as_ref().ok_or(Cause::Changed)?;
        let intent = physical.fund(transaction, &native)?;
        // Generation is the actual funded native055 target ordinal. The plan
        // is compared before PREPARE, EXTEND or either durable append.
        if intent.target().ordinal() != generation
            || intent.target().cut().sequence()
                != fields
                    .predecessor_sequence
                    .checked_add(3)
                    .ok_or(Cause::Changed)?
        {
            return Err(Cause::Changed);
        }
        physical.commit(CanaryHostNativeStepV2::Prepare, transaction, &native)?;
        physical.extend(transaction, &native)?;
        physical.commit(CanaryHostNativeStepV2::Main, transaction, &native)?;
        physical.commit(CanaryHostNativeStepV2::Finalize, transaction, &native)?;
        if physical.classify(&native)? != crate::tpm_nv_custody::FloorRecoveryV1::Current {
            return Err(Cause::Changed);
        }
        let completed = physical.main_data(&native)?;
        if completed.stored.prepared.is_some()
            || completed.stored.current != intent.target().cut()
            || completed.stored.checkpoint != intent.target()
            || completed
                .last
                .as_ref()
                .is_none_or(|last| last.bytes_v1() != row.bytes_v1())
        {
            return Err(Cause::Changed);
        }
        let target = BootPreparationCompletionFieldsDataV1 {
            target_head: completed.stored.current.head(),
            target_nv: physical.final_nv()?,
            native_transaction,
        };
        if target.target_nv != completed.stored.checkpoint.nv_value() {
            return Err(Cause::Changed);
        }
        outputs.completion_preimage = Some(target.signing_bytes_v1(row)?);
        signing.recheck_boot_once_v1(&native)?;
        origins.recheck()?;
        physical.terminal_observations(&native)?;
        native.require_clock()?;
        let signature = signing
            .key
            .as_ref()
            .ok_or(Cause::Changed)?
            .sign(
                outputs
                    .completion_preimage
                    .as_deref()
                    .ok_or(Cause::Changed)?,
            )
            .to_bytes();
        outputs.completion_bytes[..BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1]
            .copy_from_slice(&target.encode_body_v1(row)?);
        outputs.completion_bytes[BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1..]
            .copy_from_slice(&signature);
        ledger.retain(signing.recheck_boot_once_v1(&native).map_err(Into::into));
        ledger.retain(origins.recheck().map_err(Into::into));
        ledger.retain(physical.terminal_observations(&native).map_err(Into::into));
        if ledger.first.is_some() {
            return Ok(());
        }
        outputs.completion = Some(SignedBootPreparationCompletionDataV1::verify_v1(
            &outputs.completion_bytes,
            purpose,
        )?);
        origins.recheck()?;
        native.require_clock()?;
        outputs.publish(origins, &mut ledger)?;
        Ok(())
    });
    ledger.retain(body_result);

    // Every whole owner is still in this frame. Body failure cannot short
    // circuit the other owners or consume their separately reserved post lane.
    ledger.retain(outputs.directory.finish_once());
    ledger.retain(physical.drain_pending_input_after_unwind_once_v1().map_err(Into::into));
    ledger.retain(physical.drain_pending_helper_after_unwind_once_v1().map_err(Into::into));
    ledger.retain(native.finish_outer_startup_after_owed_once_v1().map_err(Into::into));
    ledger.retain(physical.terminal_observations(&native).map_err(Into::into));
    ledger.retain(signing.recheck_boot_once_v1(&native).map_err(Into::into));
    ledger.retain(native.require_clock_owed_once_v1().map_err(Into::into));
    ledger.retain(origins.recheck().map_err(Into::into));
    finish(startup, &mut ledger)
}

fn caught(action: impl FnOnce() -> Result<(), Cause>) -> Result<(), Cause> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result,
        Err(_) => Err(Cause::Unwind),
    }
}

fn finish(startup: &RuntimeBootPreparationStartupOriginalV1, ledger: &mut Ledger) -> ! {
    ledger.retain(startup.require_current_v1().map_err(Into::into));
    let body = if ledger.first.is_none() {
        Ok(())
    } else {
        Err(aos_sandbox_controller_domain::RuntimeBootPreparationStartupClosedV1)
    };
    ledger.retain(
        startup
            .finish_source_after_owed_once_v1(body)
            .map_err(Into::into),
    );
    // process::exit preserves both this frame and its callers' live owner
    // frames. Returning would invoke the entered Source's deliberately fatal
    // Drop and release lower failed prefixes before the process exit witness.
    std::process::exit(if ledger.first.is_none() { 0 } else { 1 })
}
