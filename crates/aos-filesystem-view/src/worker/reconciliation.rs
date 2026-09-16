//! Dormant effect composition for worker restart, quarantine, repair, and reap.
//!
//! The pure lifecycle reducer emits [`ReconciliationAction`] values. This
//! adapter is the only constructible seam in this crate that can hand those
//! actions to a process/filesystem owner, seal exact effect receipts, and feed
//! opaque evidence back into the reducer. It installs no supervisor or worker.
//!
//! A privileged effect process publishes one canonical protected readback:
//!
//! ```text
//! AOSWEO01 | version | attachment | attachment-generation | intent-sequence
//!           | intent-digest | previous-readback-digest | result
//!           | result-specific descriptor? | raw-observation-digest | checksum
//! ```
//!
//! The adapter writes the exact `AOSWIO01` intent before dispatch and accepts
//! no scalar proof from the dispatcher. Both files are descriptor-relative to
//! the fixed protected root; this dormant module creates no service or watcher.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::{AttachmentId, MediaType, ObjectDescriptor, ObjectDigest, Revision};
use aos_sandbox_linux::immutable_file::FsVerityPublicationRoot;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use super::{
    AttachmentHealth, ConsumerEvidence, InventoryEvidence, LifecycleError, ProcessEvidence,
    ReconciliationAction, RepairEvidence, WorkerLifecycle,
};

const FIXED_RECONCILIATION_ROOT: &str = "/var/lib/aos/sandbox/filesystem-view/reconciliation";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSWRO01";
const INTENT_MAGIC: &[u8; 8] = b"AOSWIO01";
const READBACK_MAGIC: &[u8; 8] = b"AOSWEO01";
const MAXIMUM_RECEIPT_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

/// Reports whether an exact old-generation reap completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReapEffectResult {
    /// Every inventory-named resource was removed and durably observed absent.
    Reaped,
    /// A definite retryable failure left the same reap obligation pending.
    Retryable,
}

/// Dispatches privileged effects selected by one reconciliation action.
///
/// Implementations only request the effect. They cannot supply terminal values
/// or construct a [`SealedEffectReceipt`]. After dispatch, the adapter accepts
/// results exclusively from its fixed protected effect-readback file.
pub trait ReconciliationEffectExecutor {
    /// Stops/faults one exact connection and optionally quarantines its index.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn fault_connection(
        &mut self,
        generation: u64,
        quarantine: Option<&ObjectDescriptor>,
    ) -> Result<(), ReconciliationAdapterError>;

    /// Inventories exact worker/cache state and atomically publishes repaired bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn inventory_and_repair(
        &mut self,
        inventory: InventoryEvidence,
        quarantined: &ObjectDescriptor,
    ) -> Result<(), ReconciliationAdapterError>;

    /// Launches a nonauthoritative replacement and proves exact readiness.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn launch_replacement(
        &mut self,
        generation: u64,
        authority: [u8; 32],
    ) -> Result<(), ReconciliationAdapterError>;

    /// Atomically publishes one ready replacement generation.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn publish_replacement(&mut self, generation: u64) -> Result<(), ReconciliationAdapterError>;

    /// Durably records consumer-visible attachment health.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn record_attachment_health(
        &mut self,
        generation: Revision,
        health: AttachmentHealth,
    ) -> Result<(), ReconciliationAdapterError>;

    /// Stops the exact consuming attachment and proves it has no live process.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn stop_consumer(
        &mut self,
        attachment: AttachmentId,
        generation: Revision,
    ) -> Result<(), ReconciliationAdapterError>;

    /// Removes only resources named by the exact authenticated inventory.
    ///
    /// # Errors
    ///
    /// Returns an error when dispatch cannot be requested.
    fn reap_generation(
        &mut self,
        generation: u64,
        inventory: InventoryEvidence,
    ) -> Result<(), ReconciliationAdapterError>;
}

/// Identifies the exact protected pre-effect intent supplied for terminal observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReconciliationEffectIntentV1 {
    sequence: u64,
    digest: ObjectDigest,
    previous_effect: ObjectDigest,
}

/// Carries opaque terminal data issued only by the fixed protected readback owner.
struct ReconciliationTerminalReadbackV1 {
    attachment: AttachmentId,
    attachment_generation: Revision,
    readback: EffectReadback,
}

/// Carries one sealed terminal effect observation.
#[must_use = "apply the observation to the lifecycle reducer or persist it"]
pub struct ReconciliationObservation {
    inner: ReconciliationObservationInner,
}

enum ReconciliationObservationInner {
    /// No effect was authorized.
    None,
    /// Fault/quarantine completed and the reducer was already faulted.
    ConnectionFaulted {
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Exact repair produced opaque reducer evidence.
    RepairValidated {
        /// Existing reducer evidence bound to the same receipt.
        evidence: RepairEvidence,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Replacement launch reached exact readiness.
    ReplacementReady {
        /// Existing reducer evidence bound to the same receipt.
        evidence: ProcessEvidence,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Atomic replacement publication completed.
    ReplacementPublished {
        /// Exact published connection generation.
        generation: u64,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Health state reached durable readback.
    AttachmentHealthRecorded {
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Consumer stop reached authoritative readback.
    ConsumerStopped {
        /// Existing reducer evidence bound to the same receipt.
        evidence: ConsumerEvidence,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Exact old-generation reap completed.
    GenerationReaped {
        /// Exact inventory authorizing the reaped resource set.
        inventory: InventoryEvidence,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
    /// Exact old-generation reap remains retryable.
    GenerationReapRetryable {
        /// Exact inventory retaining the retry obligation.
        inventory: InventoryEvidence,
        /// Owner-issued durable receipt.
        receipt: SealedEffectReceipt,
    },
}

fn sealed_observation(inner: ReconciliationObservationInner) -> ReconciliationObservation {
    ReconciliationObservation { inner }
}

/// Carries an owner-issued receipt whose fields cannot be caller-selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedEffectReceipt {
    sequence: u64,
    digest: ObjectDigest,
}

impl SealedEffectReceipt {
    /// Returns the monotone owner-local receipt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the complete hash-chain receipt commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptRecord {
    receipt: SealedEffectReceipt,
    state: u8,
    lifecycle_predecessor: ObjectDigest,
    lifecycle_successor: ObjectDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IntentBody {
    Fault {
        generation: u64,
        evidence: [u8; 32],
        quarantine: Option<ObjectDescriptor>,
    },
    Repair {
        inventory: InventoryEvidence,
        quarantined: ObjectDescriptor,
    },
    Launch {
        generation: u64,
        authority: [u8; 32],
    },
    Publish {
        generation: u64,
    },
    Health {
        generation: Revision,
        health: AttachmentHealth,
    },
    Stop,
    Reap {
        generation: u64,
        inventory: InventoryEvidence,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingIntent {
    sequence: u64,
    previous_effect: ObjectDigest,
    body: IntentBody,
    digest: ObjectDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EffectResult {
    Completed,
    Repaired(ObjectDescriptor),
    Reaped,
    ReapRetryable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectReadback {
    raw: ObjectDigest,
    result: EffectResult,
    digest: ObjectDigest,
}

fn push_descriptor(
    bytes: &mut Vec<u8>,
    descriptor: &ObjectDescriptor,
) -> Result<(), ReconciliationAdapterError> {
    let media = descriptor.media_type().as_str().as_bytes();
    let length =
        u16::try_from(media.len()).map_err(|_| ReconciliationAdapterError::InvalidIntent)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(descriptor.digest().as_bytes());
    bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    Ok(())
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ReconciliationAdapterError> {
    let end = offset
        .checked_add(length)
        .ok_or(ReconciliationAdapterError::InvalidIntent)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(ReconciliationAdapterError::InvalidIntent)?;
    *offset = end;
    Ok(value)
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, ReconciliationAdapterError> {
    Ok(u64::from_be_bytes(
        take(bytes, offset, 8)?
            .try_into()
            .map_err(|_| ReconciliationAdapterError::InvalidIntent)?,
    ))
}

fn take_digest(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], ReconciliationAdapterError> {
    take(bytes, offset, 32)?
        .try_into()
        .map_err(|_| ReconciliationAdapterError::InvalidIntent)
}

fn take_descriptor(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<ObjectDescriptor, ReconciliationAdapterError> {
    let media_length = u16::from_be_bytes(
        take(bytes, offset, 2)?
            .try_into()
            .map_err(|_| ReconciliationAdapterError::InvalidIntent)?,
    ) as usize;
    let media = std::str::from_utf8(take(bytes, offset, media_length)?)
        .map_err(|_| ReconciliationAdapterError::InvalidIntent)?;
    let media =
        MediaType::new(media.to_owned()).map_err(|_| ReconciliationAdapterError::InvalidIntent)?;
    let digest = ObjectDigest::from_bytes(take_digest(bytes, offset)?);
    let size = take_u64(bytes, offset)?;
    if digest.as_bytes() == &[0; 32] {
        return Err(ReconciliationAdapterError::InvalidIntent);
    }
    Ok(ObjectDescriptor::new(media, digest, size))
}

fn health_code(health: AttachmentHealth) -> u8 {
    match health {
        AttachmentHealth::Preparing => 0,
        AttachmentHealth::Ready => 1,
        AttachmentHealth::Faulted => 2,
        AttachmentHealth::Revoking => 3,
        AttachmentHealth::Revoked => 4,
    }
}

fn decode_health(code: u8) -> Result<AttachmentHealth, ReconciliationAdapterError> {
    match code {
        0 => Ok(AttachmentHealth::Preparing),
        1 => Ok(AttachmentHealth::Ready),
        2 => Ok(AttachmentHealth::Faulted),
        3 => Ok(AttachmentHealth::Revoking),
        4 => Ok(AttachmentHealth::Revoked),
        _ => Err(ReconciliationAdapterError::InvalidIntent),
    }
}

fn encode_intent(
    attachment: AttachmentId,
    attachment_generation: Revision,
    sequence: u64,
    previous_effect: ObjectDigest,
    body: &IntentBody,
) -> Result<Vec<u8>, ReconciliationAdapterError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INTENT_MAGIC);
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(attachment.as_bytes());
    bytes.extend_from_slice(&attachment_generation.get().to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(previous_effect.as_bytes());
    match body {
        IntentBody::Fault {
            generation,
            evidence,
            quarantine,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(evidence);
            bytes.push(u8::from(quarantine.is_some()));
            if let Some(descriptor) = quarantine {
                push_descriptor(&mut bytes, descriptor)?;
            }
        }
        IntentBody::Repair {
            inventory,
            quarantined,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&inventory.generation().to_be_bytes());
            bytes.extend_from_slice(&inventory.digest());
            push_descriptor(&mut bytes, quarantined)?;
        }
        IntentBody::Launch {
            generation,
            authority,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(authority);
        }
        IntentBody::Publish { generation } => {
            bytes.push(4);
            bytes.extend_from_slice(&generation.to_be_bytes());
        }
        IntentBody::Health { generation, health } => {
            bytes.push(5);
            bytes.extend_from_slice(&generation.get().to_be_bytes());
            bytes.push(health_code(*health));
        }
        IntentBody::Stop => bytes.push(6),
        IntentBody::Reap {
            generation,
            inventory,
        } => {
            bytes.push(7);
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(&inventory.generation().to_be_bytes());
            bytes.extend_from_slice(&inventory.digest());
        }
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_intent(
    bytes: &[u8],
    attachment: AttachmentId,
    attachment_generation: Revision,
) -> Result<PendingIntent, ReconciliationAdapterError> {
    if bytes.len() < 8 + 4 + 16 + 8 + 8 + 32 + 1 + 32 || bytes.len() > MAXIMUM_RECEIPT_JOURNAL_BYTES
    {
        return Err(ReconciliationAdapterError::InvalidIntent);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != checksum
        || &payload[..8] != INTENT_MAGIC
        || payload[8..12] != 2_u32.to_be_bytes()
        || payload[12..28] != *attachment.as_bytes()
        || payload[28..36] != attachment_generation.get().to_be_bytes()
    {
        return Err(ReconciliationAdapterError::InvalidIntent);
    }
    let mut offset = 36;
    let sequence = take_u64(payload, &mut offset)?;
    let previous_effect = ObjectDigest::from_bytes(take_digest(payload, &mut offset)?);
    let tag = *take(payload, &mut offset, 1)?
        .first()
        .ok_or(ReconciliationAdapterError::InvalidIntent)?;
    let body = match tag {
        1 => {
            let generation = take_u64(payload, &mut offset)?;
            let evidence = take_digest(payload, &mut offset)?;
            let present = *take(payload, &mut offset, 1)?
                .first()
                .ok_or(ReconciliationAdapterError::InvalidIntent)?;
            let quarantine = match present {
                0 => None,
                1 => Some(take_descriptor(payload, &mut offset)?),
                _ => return Err(ReconciliationAdapterError::InvalidIntent),
            };
            IntentBody::Fault {
                generation,
                evidence,
                quarantine,
            }
        }
        2 => {
            let generation = take_u64(payload, &mut offset)?;
            let digest = take_digest(payload, &mut offset)?;
            let inventory = InventoryEvidence::from_authenticated(generation, digest)?;
            IntentBody::Repair {
                inventory,
                quarantined: take_descriptor(payload, &mut offset)?,
            }
        }
        3 => IntentBody::Launch {
            generation: take_u64(payload, &mut offset)?,
            authority: take_digest(payload, &mut offset)?,
        },
        4 => IntentBody::Publish {
            generation: take_u64(payload, &mut offset)?,
        },
        5 => IntentBody::Health {
            generation: Revision::new(take_u64(payload, &mut offset)?),
            health: decode_health(
                *take(payload, &mut offset, 1)?
                    .first()
                    .ok_or(ReconciliationAdapterError::InvalidIntent)?,
            )?,
        },
        6 => IntentBody::Stop,
        7 => {
            let generation = take_u64(payload, &mut offset)?;
            let inventory_generation = take_u64(payload, &mut offset)?;
            let inventory = InventoryEvidence::from_authenticated(
                inventory_generation,
                take_digest(payload, &mut offset)?,
            )?;
            IntentBody::Reap {
                generation,
                inventory,
            }
        }
        _ => return Err(ReconciliationAdapterError::InvalidIntent),
    };
    if offset != payload.len() || sequence == 0 {
        return Err(ReconciliationAdapterError::InvalidIntent);
    }
    Ok(PendingIntent {
        sequence,
        previous_effect,
        body,
        digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    })
}

fn decode_readback(
    bytes: &[u8],
    attachment: AttachmentId,
    attachment_generation: Revision,
    intent: &PendingIntent,
) -> Result<EffectReadback, ReconciliationAdapterError> {
    if bytes.len() < 8 + 4 + 16 + 8 + 8 + 32 + 32 + 1 + 32 + 32
        || bytes.len() > MAXIMUM_RECEIPT_JOURNAL_BYTES
    {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != checksum
        || &payload[..8] != READBACK_MAGIC
        || payload[8..12] != 1_u32.to_be_bytes()
        || payload[12..28] != *attachment.as_bytes()
        || payload[28..36] != attachment_generation.get().to_be_bytes()
    {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    let mut offset = 36;
    if take_u64(payload, &mut offset)? != intent.sequence
        || take_digest(payload, &mut offset)? != *intent.digest.as_bytes()
        || take_digest(payload, &mut offset)? != *intent.previous_effect.as_bytes()
    {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    let tag = *take(payload, &mut offset, 1)?
        .first()
        .ok_or(ReconciliationAdapterError::InvalidEffectReadback)?;
    let result = match tag {
        0 => EffectResult::Completed,
        1 => EffectResult::Repaired(
            take_descriptor(payload, &mut offset)
                .map_err(|_| ReconciliationAdapterError::InvalidEffectReadback)?,
        ),
        2 => EffectResult::Reaped,
        3 => EffectResult::ReapRetryable,
        _ => return Err(ReconciliationAdapterError::InvalidEffectReadback),
    };
    let raw = ObjectDigest::from_bytes(take_digest(payload, &mut offset)?);
    if offset != payload.len() || raw.as_bytes() == &[0; 32] {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    Ok(EffectReadback {
        raw,
        result,
        digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    })
}

fn encode_readback(
    attachment: AttachmentId,
    attachment_generation: Revision,
    intent: &PendingIntent,
    terminal: ReconciliationTerminalReadbackV1,
) -> Result<Vec<u8>, ReconciliationAdapterError> {
    if terminal.attachment != attachment || terminal.attachment_generation != attachment_generation
    {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(READBACK_MAGIC);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(attachment.as_bytes());
    bytes.extend_from_slice(&attachment_generation.get().to_be_bytes());
    bytes.extend_from_slice(&intent.sequence.to_be_bytes());
    bytes.extend_from_slice(intent.digest.as_bytes());
    bytes.extend_from_slice(intent.previous_effect.as_bytes());
    let observation = match terminal.readback.result {
        EffectResult::Completed => {
            bytes.push(0);
            terminal.readback.raw
        }
        EffectResult::Repaired(descriptor) => {
            bytes.push(1);
            push_descriptor(&mut bytes, &descriptor)?;
            terminal.readback.raw
        }
        EffectResult::Reaped => {
            bytes.push(2);
            terminal.readback.raw
        }
        EffectResult::ReapRetryable => {
            bytes.push(3);
            terminal.readback.raw
        }
    };
    if observation.as_bytes() == &[0; 32] {
        return Err(ReconciliationAdapterError::InvalidEffectReadback);
    }
    bytes.extend_from_slice(observation.as_bytes());
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn observation_receipt(observation: &ReconciliationObservation) -> Option<SealedEffectReceipt> {
    match &observation.inner {
        ReconciliationObservationInner::None => None,
        ReconciliationObservationInner::ConnectionFaulted { receipt }
        | ReconciliationObservationInner::RepairValidated { receipt, .. }
        | ReconciliationObservationInner::ReplacementReady { receipt, .. }
        | ReconciliationObservationInner::ReplacementPublished { receipt, .. }
        | ReconciliationObservationInner::AttachmentHealthRecorded { receipt }
        | ReconciliationObservationInner::ConsumerStopped { receipt, .. }
        | ReconciliationObservationInner::GenerationReaped { receipt, .. }
        | ReconciliationObservationInner::GenerationReapRetryable { receipt, .. } => Some(*receipt),
    }
}

fn lifecycle_digest(
    lifecycle: &WorkerLifecycle,
) -> Result<ObjectDigest, ReconciliationAdapterError> {
    let snapshot = lifecycle.snapshot();
    let authority = snapshot.active_artifacts().0;
    let key: [u8; 32] =
        Sha256::digest(b"aos.filesystem-view.reconciliation-lifecycle-binding.v1\0").into();
    let codec = super::DurableStateCodec::new(
        authority,
        key,
        super::DurableStateLimits {
            maximum_bytes: MAXIMUM_RECEIPT_JOURNAL_BYTES,
            maximum_registration_records: 1,
        },
    )
    .map_err(|_| ReconciliationAdapterError::InvalidJournal)?;
    let bytes = codec
        .encode_lifecycle_snapshot(&snapshot)
        .map_err(|_| ReconciliationAdapterError::InvalidJournal)?;
    Ok(ObjectDigest::from_bytes(Sha256::digest(bytes).into()))
}

fn apply_observation_to_lifecycle(
    lifecycle: &mut WorkerLifecycle,
    observation: &ReconciliationObservationInner,
) -> Result<ReconciliationAction, ReconciliationAdapterError> {
    match observation {
        ReconciliationObservationInner::None
        | ReconciliationObservationInner::ConnectionFaulted { .. }
        | ReconciliationObservationInner::AttachmentHealthRecorded { .. } => {
            Ok(ReconciliationAction::None)
        }
        ReconciliationObservationInner::RepairValidated { evidence, .. } => {
            Ok(lifecycle.record_repair_validated(evidence.clone())?)
        }
        ReconciliationObservationInner::ReplacementReady { evidence, .. } => {
            Ok(lifecycle.record_replacement_ready(*evidence)?)
        }
        ReconciliationObservationInner::ReplacementPublished { generation, .. } => {
            Ok(lifecycle.record_replacement_published(*generation)?)
        }
        ReconciliationObservationInner::ConsumerStopped { evidence, .. } => {
            Ok(lifecycle.record_consumer_stopped(*evidence)?)
        }
        ReconciliationObservationInner::GenerationReaped { inventory, .. } => {
            Ok(lifecycle.record_reap_confirmed(*inventory)?)
        }
        ReconciliationObservationInner::GenerationReapRetryable { inventory, .. } => {
            Ok(lifecycle.retry_reap(*inventory)?)
        }
    }
}

fn next_receipt_sequence(length: usize) -> Result<u64, ReconciliationAdapterError> {
    u64::try_from(length)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(ReconciliationAdapterError::ReceiptCapacity)
}

fn encode_receipts(
    attachment: AttachmentId,
    generation: Revision,
    receipts: &[ReceiptRecord],
) -> Result<Vec<u8>, ReconciliationAdapterError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECEIPT_MAGIC);
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(attachment.as_bytes());
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(receipts.len())
            .map_err(|_| ReconciliationAdapterError::ReceiptCapacity)?
            .to_be_bytes(),
    );
    for (index, record) in receipts.iter().enumerate() {
        if record.receipt.sequence != index as u64 + 1
            || record.receipt.digest.as_bytes() == &[0; 32]
        {
            return Err(ReconciliationAdapterError::InvalidJournal);
        }
        bytes.extend_from_slice(&record.receipt.sequence.to_be_bytes());
        bytes.extend_from_slice(record.receipt.digest.as_bytes());
        if record.state > 2 {
            return Err(ReconciliationAdapterError::InvalidJournal);
        }
        bytes.push(record.state);
        if record.lifecycle_predecessor.as_bytes() == &[0; 32]
            || record.lifecycle_successor.as_bytes() == &[0; 32]
        {
            return Err(ReconciliationAdapterError::InvalidJournal);
        }
        bytes.extend_from_slice(record.lifecycle_predecessor.as_bytes());
        bytes.extend_from_slice(record.lifecycle_successor.as_bytes());
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAXIMUM_RECEIPT_JOURNAL_BYTES {
        return Err(ReconciliationAdapterError::ReceiptCapacity);
    }
    Ok(bytes)
}

fn decode_receipts(
    bytes: &[u8],
    attachment: AttachmentId,
    generation: Revision,
    maximum: usize,
) -> Result<Vec<ReceiptRecord>, ReconciliationAdapterError> {
    const HEADER: usize = 8 + 4 + 16 + 8 + 4;
    if bytes.len() < HEADER + 32 || bytes.len() > MAXIMUM_RECEIPT_JOURNAL_BYTES {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != checksum
        || &payload[..8] != RECEIPT_MAGIC
        || payload[8..12] != 3_u32.to_be_bytes()
        || payload[12..28] != *attachment.as_bytes()
        || payload[28..36] != generation.get().to_be_bytes()
    {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    let count = u32::from_be_bytes(
        payload[36..40]
            .try_into()
            .map_err(|_| ReconciliationAdapterError::InvalidJournal)?,
    ) as usize;
    let records_bytes = count
        .checked_mul(105)
        .and_then(|bytes| HEADER.checked_add(bytes))
        .ok_or(ReconciliationAdapterError::InvalidJournal)?;
    if count > maximum || payload.len() != records_bytes {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(count)
        .map_err(|_| ReconciliationAdapterError::ReceiptCapacity)?;
    for index in 0..count {
        let offset = index
            .checked_mul(105)
            .and_then(|value| HEADER.checked_add(value))
            .ok_or(ReconciliationAdapterError::InvalidJournal)?;
        let sequence = u64::from_be_bytes(
            payload[offset..offset + 8]
                .try_into()
                .map_err(|_| ReconciliationAdapterError::InvalidJournal)?,
        );
        let digest = ObjectDigest::from_bytes(
            payload[offset + 8..offset + 40]
                .try_into()
                .map_err(|_| ReconciliationAdapterError::InvalidJournal)?,
        );
        let state = match payload[offset + 40] {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => return Err(ReconciliationAdapterError::InvalidJournal),
        };
        let lifecycle_predecessor = ObjectDigest::from_bytes(
            payload[offset + 41..offset + 73]
                .try_into()
                .map_err(|_| ReconciliationAdapterError::InvalidJournal)?,
        );
        let lifecycle_successor = ObjectDigest::from_bytes(
            payload[offset + 73..offset + 105]
                .try_into()
                .map_err(|_| ReconciliationAdapterError::InvalidJournal)?,
        );
        if sequence != index as u64 + 1 || digest.as_bytes() == &[0; 32] {
            return Err(ReconciliationAdapterError::InvalidJournal);
        }
        receipts.push(ReceiptRecord {
            receipt: SealedEffectReceipt { sequence, digest },
            state,
            lifecycle_predecessor,
            lifecycle_successor,
        });
    }
    if encode_receipts(attachment, generation, &receipts)? != bytes {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    Ok(receipts)
}

fn read_at(root: &OwnedFd, name: &str) -> Result<Vec<u8>, ReconciliationAdapterError> {
    let descriptor = rustix::fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
    {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAXIMUM_RECEIPT_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_RECEIPT_JOURNAL_BYTES {
        return Err(ReconciliationAdapterError::InvalidJournal);
    }
    Ok(bytes)
}

fn remove_exact_temporary(
    root: &OwnedFd,
    name: &str,
    expected: &[u8],
) -> Result<(), ReconciliationAdapterError> {
    match rustix::fs::statat(root, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_nlink != 1
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || read_at(root, name)? != expected
            {
                return Err(ReconciliationAdapterError::ForeignTemporary);
            }
            rustix::fs::unlinkat(root, name, rustix::fs::AtFlags::empty())?;
            rustix::fs::fsync(root)?;
            Ok(())
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn inspect_root(root: &OwnedFd) -> Result<RootIdentity, ReconciliationAdapterError> {
    let stat = rustix::fs::fstat(root)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(ReconciliationAdapterError::RootChanged);
    }
    Ok(RootIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode & 0o7777,
    })
}

fn open_owner_lock(root: &OwnedFd) -> Result<OwnedFd, ReconciliationAdapterError> {
    let descriptor = rustix::fs::openat(
        root,
        ".owner.lock",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(ReconciliationAdapterError::InvalidOwnerLock);
    }
    rustix::fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if matches!(
            error,
            rustix::io::Errno::AGAIN | rustix::io::Errno::WOULDBLOCK
        ) {
            ReconciliationAdapterError::OwnerBusy
        } else {
            error.into()
        }
    })?;
    Ok(descriptor)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

/// Reads effect-terminal observations from the fixed protected owner root.
///
/// This owner is held only by the reconciliation adapter and installs no
/// service or watcher. It authenticates the fixed backend result before it
/// privately publishes the canonical `AOSWEO01` source record.
struct DormantReconciliationReadbackOwner {
    root: OwnedFd,
    root_identity: RootIdentity,
    protected_root: FsVerityPublicationRoot,
    attachment: AttachmentId,
    attachment_generation: Revision,
    backend_name: String,
    source_name: String,
}

impl DormantReconciliationReadbackOwner {
    /// Opens the fixed protected readback root for one attachment generation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the fixed root and identity are protected and
    /// the requested attachment identity is non-sentinel.
    fn open_fixed(
        attachment: AttachmentId,
        attachment_generation: Revision,
    ) -> Result<Self, ReconciliationAdapterError> {
        if attachment.as_bytes() == &[0; 16] || attachment_generation.get() == 0 {
            return Err(ReconciliationAdapterError::InvalidIdentity);
        }
        let root = rustix::fs::open(
            FIXED_RECONCILIATION_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_identity = inspect_root(&root)?;
        let protected_root = FsVerityPublicationRoot::from_protected_absolute_path(Path::new(
            FIXED_RECONCILIATION_ROOT,
        ))?;
        if protected_root.device() != root_identity.device
            || protected_root.inode() != root_identity.inode
        {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        let source_name = format!(
            "{}-{}.effect-source",
            hex(attachment.as_bytes()),
            attachment_generation.get()
        );
        let backend_name = format!(
            "{}-{}.effect-backend",
            hex(attachment.as_bytes()),
            attachment_generation.get()
        );
        Ok(Self {
            root,
            root_identity,
            protected_root,
            attachment,
            attachment_generation,
            backend_name,
            source_name,
        })
    }

    /// Reads one exact intent-bound terminal observation.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent, substituted, malformed, or stale backend
    /// record, or if the fixed protected root identity changed.
    fn observe_terminal(
        &self,
        intent: ReconciliationEffectIntentV1,
    ) -> Result<ReconciliationTerminalReadbackV1, ReconciliationAdapterError> {
        self.recheck_root()?;
        let bytes = read_at(&self.root, &self.backend_name)?;
        self.recheck_root()?;
        let pending = PendingIntent {
            sequence: intent.sequence,
            previous_effect: intent.previous_effect,
            body: IntentBody::Publish { generation: 0 },
            digest: intent.digest,
        };
        let readback = decode_readback(
            &bytes,
            self.attachment,
            self.attachment_generation,
            &pending,
        )?;
        self.publish(intent, readback.result.clone(), readback.raw)?;
        let sealed = read_at(&self.root, &self.source_name)?;
        let readback = decode_readback(
            &sealed,
            self.attachment,
            self.attachment_generation,
            &pending,
        )?;
        Ok(ReconciliationTerminalReadbackV1 {
            attachment: self.attachment,
            attachment_generation: self.attachment_generation,
            readback,
        })
    }

    fn publish(
        &self,
        intent: ReconciliationEffectIntentV1,
        result: EffectResult,
        observation: ObjectDigest,
    ) -> Result<(), ReconciliationAdapterError> {
        self.recheck_root()?;
        let pending = PendingIntent {
            sequence: intent.sequence,
            previous_effect: intent.previous_effect,
            body: IntentBody::Publish { generation: 0 },
            digest: intent.digest,
        };
        let bytes = encode_readback(
            self.attachment,
            self.attachment_generation,
            &pending,
            ReconciliationTerminalReadbackV1 {
                attachment: self.attachment,
                attachment_generation: self.attachment_generation,
                readback: EffectReadback {
                    raw: observation,
                    result,
                    digest: ObjectDigest::from_bytes([0; 32]),
                },
            },
        )?;
        if read_at(&self.root, &self.source_name)
            .as_ref()
            .is_ok_and(|current| current == &bytes)
        {
            rustix::fs::fsync(&self.root)?;
            return Ok(());
        }
        self.validate_source_predecessor(intent.previous_effect)?;
        let temporary = format!(".{}-{}.tmp", self.source_name, intent.sequence);
        remove_exact_temporary(&self.root, &temporary, &bytes)?;
        let descriptor = rustix::fs::openat(
            &self.root,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if read_at(&self.root, &temporary)? != bytes {
            return Err(ReconciliationAdapterError::InvalidEffectReadback);
        }
        self.validate_source_predecessor(intent.previous_effect)?;
        if rustix::fs::renameat(
            &self.root,
            temporary.as_str(),
            &self.root,
            &self.source_name,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || !read_at(&self.root, &self.source_name)
                .as_ref()
                .is_ok_and(|current| current == &bytes)
        {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        self.recheck_root()
    }

    fn validate_source_predecessor(
        &self,
        expected: ObjectDigest,
    ) -> Result<(), ReconciliationAdapterError> {
        match read_at(&self.root, &self.source_name) {
            Ok(previous)
                if ObjectDigest::from_bytes(Sha256::digest(previous).into()) == expected =>
            {
                Ok(())
            }
            Err(ReconciliationAdapterError::Rustix(error))
                if error == rustix::io::Errno::NOENT && expected.as_bytes() == &[0; 32] =>
            {
                Ok(())
            }
            Ok(_) | Err(ReconciliationAdapterError::Rustix(rustix::io::Errno::NOENT)) => {
                Err(ReconciliationAdapterError::ConcurrentReplacement)
            }
            Err(error) => Err(error),
        }
    }

    fn recheck_root(&self) -> Result<(), ReconciliationAdapterError> {
        if inspect_root(&self.root)? != self.root_identity {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        self.protected_root.recheck_protected_path()?;
        let reopened = rustix::fs::open(
            FIXED_RECONCILIATION_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if inspect_root(&reopened)? != self.root_identity {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        Ok(())
    }
}

/// Binds effect receipts to one fixed protected owner and exact attachment.
pub struct DormantReconciliationAdapter {
    root: OwnedFd,
    _owner_lock: OwnedFd,
    root_identity: RootIdentity,
    protected_root: FsVerityPublicationRoot,
    terminal_owner: DormantReconciliationReadbackOwner,
    attachment: AttachmentId,
    attachment_generation: Revision,
    journal_name: String,
    intent_name: String,
    readback_name: String,
    maximum_receipts: usize,
    receipts: Vec<ReceiptRecord>,
    pending_intent: Option<PendingIntent>,
    outcome_unknown: bool,
    outcome_successor: Option<Vec<ReceiptRecord>>,
    outcome_predecessor: Option<Vec<u8>>,
    outcome_predecessor_absent: bool,
}

impl DormantReconciliationAdapter {
    /// Constructs a dormant adapter for one exact attachment generation.
    ///
    /// # Errors
    ///
    /// Returns [`ReconciliationAdapterError::InvalidIdentity`] for sentinels.
    pub fn open_fixed(
        attachment: AttachmentId,
        attachment_generation: Revision,
        maximum_receipts: usize,
    ) -> Result<Self, ReconciliationAdapterError> {
        if attachment.as_bytes() == &[0; 16]
            || attachment_generation.get() == 0
            || maximum_receipts == 0
        {
            return Err(ReconciliationAdapterError::InvalidIdentity);
        }
        let root = rustix::fs::open(
            FIXED_RECONCILIATION_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_identity = inspect_root(&root)?;
        let owner_lock = open_owner_lock(&root)?;
        let terminal_owner =
            DormantReconciliationReadbackOwner::open_fixed(attachment, attachment_generation)?;
        let protected_root = FsVerityPublicationRoot::from_protected_absolute_path(Path::new(
            FIXED_RECONCILIATION_ROOT,
        ))?;
        if protected_root.device() != root_identity.device
            || protected_root.inode() != root_identity.inode
        {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        let journal_name = format!(
            "{}-{}.receipts",
            hex(attachment.as_bytes()),
            attachment_generation.get()
        );
        let intent_name = format!(
            "{}-{}.intent",
            hex(attachment.as_bytes()),
            attachment_generation.get()
        );
        let readback_name = format!(
            "{}-{}.effect-readback",
            hex(attachment.as_bytes()),
            attachment_generation.get()
        );
        let receipts = match read_at(&root, &journal_name) {
            Ok(bytes) => {
                decode_receipts(&bytes, attachment, attachment_generation, maximum_receipts)?
            }
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        let mut pending_intent = match read_at(&root, &intent_name) {
            Ok(bytes) => Some(decode_intent(&bytes, attachment, attachment_generation)?),
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                None
            }
            Err(error) => return Err(error),
        };
        let next_sequence = next_receipt_sequence(receipts.len())?;
        let intent_temporary = format!(".{}-{next_sequence}.tmp", intent_name);
        match read_at(&root, &intent_temporary) {
            Ok(bytes) if pending_intent.is_none() => {
                let staged = decode_intent(&bytes, attachment, attachment_generation)?;
                if staged.sequence != next_sequence {
                    return Err(ReconciliationAdapterError::ForeignTemporary);
                }
                remove_exact_temporary(&root, &intent_temporary, &bytes)?;
            }
            Ok(_) => return Err(ReconciliationAdapterError::ForeignTemporary),
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
            }
            Err(error) => return Err(error),
        }
        if pending_intent.as_ref().is_some_and(|intent| {
            intent.sequence != receipts.len() as u64 && intent.sequence != next_sequence
        }) {
            return Err(ReconciliationAdapterError::InvalidIntent);
        }
        if pending_intent.as_ref().is_some_and(|intent| {
            intent.sequence == receipts.len() as u64
                && receipts.last().is_some_and(|record| record.state == 2)
        }) {
            rustix::fs::unlinkat(&root, &intent_name, rustix::fs::AtFlags::empty())?;
            rustix::fs::fsync(&root)?;
            pending_intent = None;
        }
        Ok(Self {
            root,
            _owner_lock: owner_lock,
            root_identity,
            protected_root,
            terminal_owner,
            attachment,
            attachment_generation,
            journal_name,
            intent_name,
            readback_name,
            maximum_receipts,
            receipts,
            pending_intent,
            outcome_unknown: false,
            outcome_successor: None,
            outcome_predecessor: None,
            outcome_predecessor_absent: false,
        })
    }

    /// Executes one reducer-selected effect and seals its terminal observation.
    ///
    /// # Errors
    ///
    /// Returns [`ReconciliationAdapterError`] for a foreign lifecycle, invalid
    /// owner receipt, mismatched repaired artifact, or effect-owner failure.
    pub fn execute(
        &mut self,
        lifecycle: &WorkerLifecycle,
        action: ReconciliationAction,
        effects: &mut impl ReconciliationEffectExecutor,
    ) -> Result<ReconciliationObservation, ReconciliationAdapterError> {
        if lifecycle.attachment() != (self.attachment, self.attachment_generation) {
            return Err(ReconciliationAdapterError::ForeignLifecycle);
        }
        if let ReconciliationAction::None = &action {
            return Ok(sealed_observation(ReconciliationObservationInner::None));
        }
        if self.pending_intent.is_some() {
            return Err(ReconciliationAdapterError::PendingIntent);
        }
        let body = match action {
            ReconciliationAction::None => {
                return Ok(sealed_observation(ReconciliationObservationInner::None));
            }
            ReconciliationAction::FaultConnection {
                generation,
                quarantine,
                evidence,
            } => IntentBody::Fault {
                generation,
                evidence: evidence.digest(),
                quarantine,
            },
            ReconciliationAction::InventoryAndRepair { inventory } => IntentBody::Repair {
                inventory,
                quarantined: lifecycle.active_artifacts().0.clone(),
            },
            ReconciliationAction::LaunchReplacement {
                generation,
                authority,
            } => IntentBody::Launch {
                generation,
                authority,
            },
            ReconciliationAction::PublishReplacement { generation } => {
                IntentBody::Publish { generation }
            }
            ReconciliationAction::RecordAttachmentHealth { generation, health } => {
                if generation != self.attachment_generation {
                    return Err(ReconciliationAdapterError::ForeignLifecycle);
                }
                IntentBody::Health { generation, health }
            }
            ReconciliationAction::StopConsumer => IntentBody::Stop,
            ReconciliationAction::ReapGeneration {
                generation,
                inventory,
            } => IntentBody::Reap {
                generation,
                inventory,
            },
        };
        self.persist_new_intent(body)?;
        // Dispatch failure cannot prove absence of an effect. The exact intent
        // remains durable and recovery must observe it without reissuing it.
        self.dispatch_pending(effects)?;
        let intent = self
            .pending_intent
            .as_ref()
            .ok_or(ReconciliationAdapterError::InvalidIntent)?;
        let terminal = self
            .terminal_owner
            .observe_terminal(ReconciliationEffectIntentV1 {
                sequence: intent.sequence,
                digest: intent.digest,
                previous_effect: intent.previous_effect,
            })?;
        self.persist_terminal_readback(terminal)?;
        self.recover_terminal_observation(lifecycle)?
            .ok_or(ReconciliationAdapterError::EffectReadbackMissing)
    }

    /// Reconstructs an observation after dispatch or a process restart.
    ///
    /// The exact intent remains durable until the returned receipt is consumed.
    /// This method never dispatches an effect a second time.
    ///
    /// # Errors
    ///
    /// Returns an error for substituted intent/readback bytes or a result whose
    /// type does not match the durably recorded action.
    pub fn recover_terminal_observation(
        &mut self,
        lifecycle: &WorkerLifecycle,
    ) -> Result<Option<ReconciliationObservation>, ReconciliationAdapterError> {
        if self.outcome_unknown {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        if lifecycle.attachment() != (self.attachment, self.attachment_generation) {
            return Err(ReconciliationAdapterError::ForeignLifecycle);
        }
        let Some(intent) = self.pending_intent.clone() else {
            return Ok(None);
        };
        let readback_bytes = match read_at(&self.root, &self.readback_name) {
            Ok(bytes) => bytes,
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let readback = decode_readback(
            &readback_bytes,
            self.attachment,
            self.attachment_generation,
            &intent,
        )?;
        let receipt = if intent.sequence == self.receipts.len() as u64 {
            let record = self
                .receipts
                .last()
                .ok_or(ReconciliationAdapterError::InvalidJournal)?;
            if record.state == 2 {
                return Err(ReconciliationAdapterError::ReceiptReplay);
            }
            if record.receipt != self.receipt_for(&intent, &readback)? {
                return Err(ReconciliationAdapterError::InvalidEffectReadback);
            }
            if lifecycle_digest(lifecycle)? != record.lifecycle_predecessor {
                return Err(ReconciliationAdapterError::ForeignLifecycle);
            }
            record.receipt
        } else {
            self.seal_intent(lifecycle, &intent, &readback)?
        };
        let observation = self.observation_for(intent.body, readback.result, receipt)?;
        let record = self
            .receipts
            .iter()
            .find(|record| record.receipt == receipt)
            .ok_or(ReconciliationAdapterError::InvalidJournal)?;
        let mut successor = WorkerLifecycle::restore(lifecycle.snapshot())?;
        let _ = apply_observation_to_lifecycle(&mut successor, &observation.inner)?;
        if lifecycle_digest(lifecycle)? != record.lifecycle_predecessor
            || lifecycle_digest(&successor)? != record.lifecycle_successor
        {
            return Err(ReconciliationAdapterError::ForeignLifecycle);
        }
        Ok(Some(observation))
    }

    /// Completes protected readback for an already-durable intent without redispatch.
    ///
    /// # Errors
    ///
    /// Returns an error while terminal observation is unavailable or exact
    /// protected replacement cannot be proven.
    pub fn resume_terminal_observation(
        &mut self,
        lifecycle: &WorkerLifecycle,
    ) -> Result<ReconciliationObservation, ReconciliationAdapterError> {
        if let Some(observation) = self.recover_terminal_observation(lifecycle)? {
            return Ok(observation);
        }
        let intent = self
            .pending_intent
            .as_ref()
            .ok_or(ReconciliationAdapterError::InvalidIntent)?;
        let terminal = self
            .terminal_owner
            .observe_terminal(ReconciliationEffectIntentV1 {
                sequence: intent.sequence,
                digest: intent.digest,
                previous_effect: intent.previous_effect,
            })?;
        self.persist_terminal_readback(terminal)?;
        self.recover_terminal_observation(lifecycle)?
            .ok_or(ReconciliationAdapterError::EffectReadbackMissing)
    }

    fn dispatch_pending(
        &self,
        effects: &mut impl ReconciliationEffectExecutor,
    ) -> Result<(), ReconciliationAdapterError> {
        let intent = self
            .pending_intent
            .as_ref()
            .ok_or(ReconciliationAdapterError::InvalidIntent)?;
        match &intent.body {
            IntentBody::Fault {
                generation,
                quarantine,
                ..
            } => effects.fault_connection(*generation, quarantine.as_ref()),
            IntentBody::Repair {
                inventory,
                quarantined,
            } => effects.inventory_and_repair(*inventory, quarantined),
            IntentBody::Launch {
                generation,
                authority,
            } => effects.launch_replacement(*generation, *authority),
            IntentBody::Publish { generation } => effects.publish_replacement(*generation),
            IntentBody::Health { generation, health } => {
                effects.record_attachment_health(*generation, *health)
            }
            IntentBody::Stop => effects.stop_consumer(self.attachment, self.attachment_generation),
            IntentBody::Reap {
                generation,
                inventory,
            } => effects.reap_generation(*generation, *inventory),
        }
    }

    fn persist_terminal_readback(
        &self,
        terminal: ReconciliationTerminalReadbackV1,
    ) -> Result<(), ReconciliationAdapterError> {
        let intent = self
            .pending_intent
            .as_ref()
            .ok_or(ReconciliationAdapterError::InvalidIntent)?;
        let bytes = encode_readback(
            self.attachment,
            self.attachment_generation,
            intent,
            terminal,
        )?;
        if read_at(&self.root, &self.readback_name)
            .as_ref()
            .is_ok_and(|observed| observed == &bytes)
        {
            rustix::fs::fsync(&self.root)?;
            return Ok(());
        }
        let predecessor_matches = match read_at(&self.root, &self.readback_name) {
            Ok(previous) => {
                ObjectDigest::from_bytes(Sha256::digest(&previous).into()) == intent.previous_effect
            }
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                intent.previous_effect.as_bytes() == &[0; 32]
            }
            Err(error) => return Err(error),
        };
        if !predecessor_matches {
            return Err(ReconciliationAdapterError::ConcurrentReplacement);
        }
        let temporary = format!(".{}-{}.tmp", self.readback_name, intent.sequence);
        remove_exact_temporary(&self.root, &temporary, &bytes)?;
        let descriptor = rustix::fs::openat(
            &self.root,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if read_at(&self.root, &temporary)? != bytes {
            return Err(ReconciliationAdapterError::InvalidEffectReadback);
        }
        let predecessor_still_matches = match read_at(&self.root, &self.readback_name) {
            Ok(previous) => {
                ObjectDigest::from_bytes(Sha256::digest(&previous).into()) == intent.previous_effect
            }
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                intent.previous_effect.as_bytes() == &[0; 32]
            }
            Err(error) => return Err(error),
        };
        if !predecessor_still_matches {
            return Err(ReconciliationAdapterError::ConcurrentReplacement);
        }
        if rustix::fs::renameat(
            &self.root,
            temporary.as_str(),
            &self.root,
            &self.readback_name,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || !read_at(&self.root, &self.readback_name)
                .as_ref()
                .is_ok_and(|observed| observed == &bytes)
        {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        Ok(())
    }

    /// Applies a terminal observation to the existing lifecycle reducer.
    ///
    /// # Errors
    ///
    /// Returns [`ReconciliationAdapterError`] when the sealed receipt was not
    /// issued by this fixed owner, was already consumed, or the reducer rejects
    /// the transition.
    pub fn apply(
        &mut self,
        lifecycle: &mut WorkerLifecycle,
        observation: ReconciliationObservation,
    ) -> Result<ReconciliationAction, ReconciliationAdapterError> {
        if self.outcome_unknown {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        if lifecycle.attachment() != (self.attachment, self.attachment_generation) {
            return Err(ReconciliationAdapterError::ForeignLifecycle);
        }
        let receipt = observation_receipt(&observation);
        let predecessor = receipt
            .map(|_| encode_receipts(self.attachment, self.attachment_generation, &self.receipts))
            .transpose()?;
        if let Some(receipt) = receipt {
            let record = self
                .receipts
                .iter()
                .find(|record| record.receipt == receipt)
                .ok_or(ReconciliationAdapterError::InvalidObservation)?;
            if record.state == 2 {
                return Err(ReconciliationAdapterError::ReceiptReplay);
            }
            if lifecycle_digest(lifecycle)? != record.lifecycle_predecessor {
                return Err(ReconciliationAdapterError::ForeignLifecycle);
            }
        }
        let mut successor_lifecycle = WorkerLifecycle::restore(lifecycle.snapshot())?;
        let action = apply_observation_to_lifecycle(&mut successor_lifecycle, &observation.inner)?;
        if let Some(receipt) = receipt {
            let record = self
                .receipts
                .iter()
                .find(|record| record.receipt == receipt)
                .ok_or(ReconciliationAdapterError::InvalidObservation)?;
            if lifecycle_digest(&successor_lifecycle)? != record.lifecycle_successor {
                return Err(ReconciliationAdapterError::InvalidObservation);
            }
            let mut successor_receipts = self.receipts.clone();
            let record = successor_receipts
                .iter_mut()
                .find(|record| record.receipt == receipt)
                .ok_or(ReconciliationAdapterError::InvalidObservation)?;
            let already_prepared = record.state == 1;
            record.state = 1;
            let predecessor = predecessor.ok_or(ReconciliationAdapterError::InvalidJournal)?;
            if !already_prepared {
                if self
                    .persist_receipts(&successor_receipts, &predecessor, false)
                    .is_err()
                {
                    self.outcome_unknown = true;
                    self.outcome_successor = Some(successor_receipts);
                    self.outcome_predecessor = Some(predecessor);
                    self.outcome_predecessor_absent = false;
                    return Err(ReconciliationAdapterError::OutcomeUnknown);
                }
                self.receipts = successor_receipts.clone();
            }
            *lifecycle = successor_lifecycle;
            let applied_predecessor =
                encode_receipts(self.attachment, self.attachment_generation, &self.receipts)?;
            let record = successor_receipts
                .iter_mut()
                .find(|record| record.receipt == receipt)
                .ok_or(ReconciliationAdapterError::InvalidObservation)?;
            record.state = 2;
            if self
                .persist_receipts(&successor_receipts, &applied_predecessor, false)
                .is_err()
            {
                self.outcome_unknown = true;
                self.outcome_successor = Some(successor_receipts);
                self.outcome_predecessor = Some(applied_predecessor);
                self.outcome_predecessor_absent = false;
                return Err(ReconciliationAdapterError::OutcomeUnknown);
            }
            self.receipts = successor_receipts;
            self.clear_consumed_intent(receipt.sequence)?;
            return Ok(action);
        }
        *lifecycle = successor_lifecycle;
        Ok(action)
    }

    fn persist_new_intent(&mut self, body: IntentBody) -> Result<(), ReconciliationAdapterError> {
        self.recheck_root()?;
        if self.outcome_unknown {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        if self.receipts.len() >= self.maximum_receipts {
            return Err(ReconciliationAdapterError::ReceiptCapacity);
        }
        let sequence = next_receipt_sequence(self.receipts.len())?;
        let previous_effect = match read_at(&self.root, &self.readback_name) {
            Ok(bytes) => ObjectDigest::from_bytes(Sha256::digest(&bytes).into()),
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                ObjectDigest::from_bytes([0; 32])
            }
            Err(error) => return Err(error),
        };
        let bytes = encode_intent(
            self.attachment,
            self.attachment_generation,
            sequence,
            previous_effect,
            &body,
        )?;
        match read_at(&self.root, &self.intent_name) {
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
            }
            Ok(_) => return Err(ReconciliationAdapterError::PendingIntent),
            Err(error) => return Err(error),
        }
        let temporary = format!(".{}-{}.tmp", self.intent_name, sequence);
        remove_exact_temporary(&self.root, &temporary, &bytes)?;
        let descriptor = rustix::fs::openat(
            &self.root,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if read_at(&self.root, &temporary)? != bytes {
            return Err(ReconciliationAdapterError::InvalidIntent);
        }
        if !matches!(read_at(&self.root, &self.intent_name), Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT)
        {
            return Err(ReconciliationAdapterError::ConcurrentReplacement);
        }
        if rustix::fs::renameat(
            &self.root,
            temporary.as_str(),
            &self.root,
            &self.intent_name,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || !read_at(&self.root, &self.intent_name)
                .as_ref()
                .is_ok_and(|current| current == &bytes)
        {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        self.pending_intent = Some(decode_intent(
            &bytes,
            self.attachment,
            self.attachment_generation,
        )?);
        Ok(())
    }

    fn seal_intent(
        &mut self,
        lifecycle: &WorkerLifecycle,
        intent: &PendingIntent,
        readback: &EffectReadback,
    ) -> Result<SealedEffectReceipt, ReconciliationAdapterError> {
        if intent.sequence != next_receipt_sequence(self.receipts.len())?
            || readback.raw.as_bytes() == &[0; 32]
        {
            return Err(ReconciliationAdapterError::InvalidObservation);
        }
        let receipt = self.receipt_for(intent, readback)?;
        let predecessor_bytes =
            encode_receipts(self.attachment, self.attachment_generation, &self.receipts)?;
        let predecessor_absent = self.receipts.is_empty();
        let lifecycle_predecessor = lifecycle_digest(lifecycle)?;
        let observation =
            self.observation_for(intent.body.clone(), readback.result.clone(), receipt)?;
        let mut successor_lifecycle = WorkerLifecycle::restore(lifecycle.snapshot())?;
        let _ = apply_observation_to_lifecycle(&mut successor_lifecycle, &observation.inner)?;
        let lifecycle_successor = lifecycle_digest(&successor_lifecycle)?;
        let mut successor = self.receipts.clone();
        successor.push(ReceiptRecord {
            receipt,
            state: 0,
            lifecycle_predecessor,
            lifecycle_successor,
        });
        if self
            .persist_receipts(&successor, &predecessor_bytes, predecessor_absent)
            .is_err()
        {
            self.outcome_unknown = true;
            self.outcome_successor = Some(successor);
            self.outcome_predecessor = Some(predecessor_bytes);
            self.outcome_predecessor_absent = predecessor_absent;
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        self.receipts = successor;
        Ok(receipt)
    }

    fn receipt_for(
        &self,
        intent: &PendingIntent,
        readback: &EffectReadback,
    ) -> Result<SealedEffectReceipt, ReconciliationAdapterError> {
        if intent.sequence == 0 || readback.raw.as_bytes() == &[0; 32] {
            return Err(ReconciliationAdapterError::InvalidObservation);
        }
        let predecessor = if intent.sequence == 1 {
            ObjectDigest::from_bytes([0; 32])
        } else {
            self.receipts
                .get(intent.sequence as usize - 2)
                .ok_or(ReconciliationAdapterError::InvalidJournal)?
                .receipt
                .digest
        };
        let mut hasher = Sha256::new();
        hasher.update(b"aos.filesystem-view.reconciliation-effect.v2\0");
        hasher.update(self.root_identity.device.to_be_bytes());
        hasher.update(self.root_identity.inode.to_be_bytes());
        hasher.update(self.attachment.as_bytes());
        hasher.update(self.attachment_generation.get().to_be_bytes());
        hasher.update(intent.sequence.to_be_bytes());
        hasher.update(predecessor.as_bytes());
        hasher.update(intent.digest.as_bytes());
        hasher.update(readback.digest.as_bytes());
        hasher.update(readback.raw.as_bytes());
        let receipt = SealedEffectReceipt {
            sequence: intent.sequence,
            digest: ObjectDigest::from_bytes(hasher.finalize().into()),
        };
        Ok(receipt)
    }

    fn observation_for(
        &self,
        body: IntentBody,
        result: EffectResult,
        receipt: SealedEffectReceipt,
    ) -> Result<ReconciliationObservation, ReconciliationAdapterError> {
        let inner = match (body, result) {
            (IntentBody::Fault { .. }, EffectResult::Completed) => {
                ReconciliationObservationInner::ConnectionFaulted { receipt }
            }
            (
                IntentBody::Repair {
                    inventory,
                    quarantined,
                },
                EffectResult::Repaired(repaired),
            ) => ReconciliationObservationInner::RepairValidated {
                evidence: RepairEvidence::from_verified_repair(
                    quarantined,
                    inventory,
                    repaired,
                    *receipt.digest.as_bytes(),
                )?,
                receipt,
            },
            (
                IntentBody::Launch {
                    generation,
                    authority,
                },
                EffectResult::Completed,
            ) => ReconciliationObservationInner::ReplacementReady {
                evidence: ProcessEvidence::from_authenticated(
                    generation,
                    authority,
                    *receipt.digest.as_bytes(),
                )?,
                receipt,
            },
            (IntentBody::Publish { generation }, EffectResult::Completed) => {
                ReconciliationObservationInner::ReplacementPublished {
                    generation,
                    receipt,
                }
            }
            (IntentBody::Health { .. }, EffectResult::Completed) => {
                ReconciliationObservationInner::AttachmentHealthRecorded { receipt }
            }
            (IntentBody::Stop, EffectResult::Completed) => {
                ReconciliationObservationInner::ConsumerStopped {
                    evidence: ConsumerEvidence::from_authenticated(
                        self.attachment,
                        self.attachment_generation,
                        *receipt.digest.as_bytes(),
                    )?,
                    receipt,
                }
            }
            (IntentBody::Reap { inventory, .. }, EffectResult::Reaped) => {
                ReconciliationObservationInner::GenerationReaped { inventory, receipt }
            }
            (IntentBody::Reap { inventory, .. }, EffectResult::ReapRetryable) => {
                ReconciliationObservationInner::GenerationReapRetryable { inventory, receipt }
            }
            _ => return Err(ReconciliationAdapterError::InvalidEffectReadback),
        };
        Ok(sealed_observation(inner))
    }

    fn persist_receipts(
        &self,
        receipts: &[ReceiptRecord],
        predecessor: &[u8],
        predecessor_absent: bool,
    ) -> Result<(), ReconciliationAdapterError> {
        self.recheck_root()?;
        self.validate_journal_head(predecessor, predecessor_absent)?;
        let bytes = encode_receipts(self.attachment, self.attachment_generation, receipts)?;
        let temporary = format!(".{}-{}.tmp", self.journal_name, receipts.len());
        remove_exact_temporary(&self.root, &temporary, &bytes)?;
        let descriptor = rustix::fs::openat(
            &self.root,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if read_at(&self.root, &temporary)? != bytes {
            return Err(ReconciliationAdapterError::InvalidJournal);
        }
        self.validate_journal_head(predecessor, predecessor_absent)?;
        if rustix::fs::renameat(
            &self.root,
            temporary.as_str(),
            &self.root,
            &self.journal_name,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
        {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        if read_at(&self.root, &self.journal_name)? != bytes {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        self.recheck_root()?;
        Ok(())
    }

    fn validate_journal_head(
        &self,
        predecessor: &[u8],
        predecessor_absent: bool,
    ) -> Result<(), ReconciliationAdapterError> {
        match read_at(&self.root, &self.journal_name) {
            Ok(bytes) if bytes == predecessor && !predecessor_absent => Ok(()),
            Err(ReconciliationAdapterError::Rustix(error))
                if error == rustix::io::Errno::NOENT && predecessor_absent =>
            {
                Ok(())
            }
            Ok(_) | Err(ReconciliationAdapterError::Rustix(rustix::io::Errno::NOENT)) => {
                Err(ReconciliationAdapterError::ConcurrentReplacement)
            }
            Err(error) => Err(error),
        }
    }

    fn clear_consumed_intent(&mut self, sequence: u64) -> Result<(), ReconciliationAdapterError> {
        let intent = self
            .pending_intent
            .as_ref()
            .ok_or(ReconciliationAdapterError::InvalidIntent)?;
        if intent.sequence != sequence {
            return Err(ReconciliationAdapterError::InvalidIntent);
        }
        let expected = encode_intent(
            self.attachment,
            self.attachment_generation,
            intent.sequence,
            intent.previous_effect,
            &intent.body,
        )?;
        if read_at(&self.root, &self.intent_name)? != expected {
            return Err(ReconciliationAdapterError::InvalidIntent);
        }
        rustix::fs::unlinkat(&self.root, &self.intent_name, rustix::fs::AtFlags::empty())?;
        rustix::fs::fsync(&self.root)?;
        self.pending_intent = None;
        Ok(())
    }

    /// Resolves an ambiguous receipt replacement by exact fixed-root readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the current journal is the exact requested
    /// successor or its exact predecessor permits retrying the retained temp.
    pub fn recover_receipt_journal(&mut self) -> Result<(), ReconciliationAdapterError> {
        if !self.outcome_unknown {
            return Ok(());
        }
        let successor = self
            .outcome_successor
            .clone()
            .ok_or(ReconciliationAdapterError::OutcomeUnknown)?;
        let expected = encode_receipts(self.attachment, self.attachment_generation, &successor)?;
        let temporary = format!(".{}-{}.tmp", self.journal_name, successor.len());
        if read_at(&self.root, &self.journal_name)
            .as_ref()
            .is_ok_and(|bytes| bytes == &expected)
        {
            rustix::fs::fsync(&self.root)?;
            remove_exact_temporary(&self.root, &temporary, &expected)?;
            self.outcome_unknown = false;
            self.receipts = successor;
            self.outcome_successor = None;
            self.outcome_predecessor = None;
            self.outcome_predecessor_absent = false;
            if let Some(sequence) = self.pending_intent.as_ref().and_then(|intent| {
                self.receipts
                    .get(intent.sequence as usize - 1)
                    .filter(|record| record.state == 2)
                    .map(|_| intent.sequence)
            }) {
                self.clear_consumed_intent(sequence)?;
            }
            return Ok(());
        }
        let predecessor_bytes = self
            .outcome_predecessor
            .as_ref()
            .ok_or(ReconciliationAdapterError::OutcomeUnknown)?;
        let current_is_predecessor = match read_at(&self.root, &self.journal_name) {
            Ok(bytes) => bytes == *predecessor_bytes,
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                self.outcome_predecessor_absent
            }
            Err(error) => return Err(error),
        };
        if !current_is_predecessor {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        match read_at(&self.root, &temporary) {
            Ok(bytes) if bytes == expected => {}
            Err(ReconciliationAdapterError::Rustix(error)) if error == rustix::io::Errno::NOENT => {
                let descriptor = rustix::fs::openat(
                    &self.root,
                    temporary.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )?;
                let mut file = File::from(descriptor);
                file.write_all(&expected)?;
                file.sync_all()?;
                drop(file);
                if read_at(&self.root, &temporary)? != expected {
                    return Err(ReconciliationAdapterError::OutcomeUnknown);
                }
            }
            Ok(_) | Err(_) => return Err(ReconciliationAdapterError::OutcomeUnknown),
        }
        if rustix::fs::renameat(
            &self.root,
            temporary.as_str(),
            &self.root,
            &self.journal_name,
        )
        .is_err()
            || rustix::fs::fsync(&self.root).is_err()
            || !read_at(&self.root, &self.journal_name)
                .as_ref()
                .is_ok_and(|bytes| bytes == &expected)
        {
            return Err(ReconciliationAdapterError::OutcomeUnknown);
        }
        self.outcome_unknown = false;
        self.receipts = successor;
        self.outcome_successor = None;
        self.outcome_predecessor = None;
        self.outcome_predecessor_absent = false;
        if let Some(sequence) = self.pending_intent.as_ref().and_then(|intent| {
            self.receipts
                .get(intent.sequence as usize - 1)
                .filter(|record| record.state == 2)
                .map(|_| intent.sequence)
        }) {
            self.clear_consumed_intent(sequence)?;
        }
        Ok(())
    }

    fn recheck_root(&self) -> Result<(), ReconciliationAdapterError> {
        if inspect_root(&self.root)? != self.root_identity {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        self.protected_root.recheck_protected_path()?;
        let reopened = rustix::fs::open(
            FIXED_RECONCILIATION_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if inspect_root(&reopened)? != self.root_identity {
            return Err(ReconciliationAdapterError::RootChanged);
        }
        Ok(())
    }
}

/// Reports dormant reconciliation composition failure.
#[derive(Debug, thiserror::Error)]
pub enum ReconciliationAdapterError {
    /// Adapter attachment identity or receipt bound is invalid.
    #[error("invalid reconciliation adapter identity")]
    InvalidIdentity,
    /// Another independently opened owner holds the protected-root lease.
    #[error("reconciliation protected root is owned by another process")]
    OwnerBusy,
    /// The provisioned protected-root owner lease is not a safe regular file.
    #[error("invalid reconciliation owner lock")]
    InvalidOwnerLock,
    /// The reducer belongs to another attachment generation.
    #[error("reconciliation action belongs to another lifecycle")]
    ForeignLifecycle,
    /// Effect owner returned sentinel or mismatched readback.
    #[error("reconciliation effect observation is invalid")]
    InvalidObservation,
    /// The durable pre-effect intent is malformed or substituted.
    #[error("invalid reconciliation effect intent")]
    InvalidIntent,
    /// An earlier durable intent must be recovered before another dispatch.
    #[error("a reconciliation effect intent is already pending")]
    PendingIntent,
    /// The fixed protected effect readback is absent after dispatch.
    #[error("reconciliation effect readback is not yet present")]
    EffectReadbackMissing,
    /// The fixed protected effect readback does not bind the pending intent.
    #[error("invalid reconciliation effect readback")]
    InvalidEffectReadback,
    /// The durable journal predecessor changed before atomic replacement.
    #[error("concurrent reconciliation journal replacement rejected")]
    ConcurrentReplacement,
    /// A sealed receipt was already consumed by lifecycle reconciliation.
    #[error("reconciliation receipt replay was rejected")]
    ReceiptReplay,
    /// The bounded protected receipt journal cannot retain another record.
    #[error("reconciliation receipt capacity exhausted")]
    ReceiptCapacity,
    /// Protected receipt bytes are malformed, truncated, or substituted.
    #[error("invalid reconciliation receipt journal")]
    InvalidJournal,
    /// A deterministic journal temporary was not the exact expected file.
    #[error("foreign reconciliation journal temporary")]
    ForeignTemporary,
    /// The retained fixed protected root changed identity or mode.
    #[error("reconciliation protected root changed")]
    RootChanged,
    /// Receipt publication may have completed and requires exact reopen/readback.
    #[error("reconciliation receipt publication outcome is unknown")]
    OutcomeUnknown,
    /// Descriptor-relative protected-root operation failed.
    #[error("reconciliation protected-root operation failed: {0}")]
    Rustix(#[from] rustix::io::Errno),
    /// Protected absolute-path root validation failed.
    #[error("protected reconciliation root validation failed: {0}")]
    PublicationRoot(#[from] aos_sandbox_linux::immutable_file::PublicationRootError),
    /// Receipt journal file I/O failed.
    #[error("reconciliation receipt journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Existing lifecycle validation rejected constructed evidence.
    #[error("worker lifecycle rejected effect evidence: {0}")]
    Lifecycle(#[from] LifecycleError),
    /// Privileged owner rejected or could not durably observe the exact effect.
    #[error("reconciliation effect owner failed: {0}")]
    Effect(String),
}
