//! Bounded incoming execution-transfer observations under the original writer.
//!
//! ```text
//! <ledger>/receiving/<two-hex>/<operation-and-offer-digest>
//!   sealed-v1(source-key, exact-prepared-state, archive, publication, phase)
//! ```
//!
//! Records cannot reconstruct a stopped World or a live readiness capability.
//! All transitions retain the same exact source root; terminal observations
//! cannot be removed or rewritten. The existing writer and retention generation
//! cover this namespace as well as ordinary attempt records.

use super::*;

const MAGIC: &[u8] = b"crucible.executor.receiving-transfer.v1\0";
const DOMAIN: &str = "crucible.executor.receiving-transfer.v1";

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_RECEIVING_PUBLICATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceivingTransferPhase {
    Ready,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceivingTransferRecord {
    source_key: AttemptExecutionKey,
    source: AttemptRuntimeState,
    archive: crucible_campaign::CampaignArchiveManifestId,
    publication: CampaignHash,
    phase: ReceivingTransferPhase,
}

impl ReceivingTransferRecord {
    /// Builds an observation from a live source claim, never from a replay row.
    pub(crate) fn for_stopped_owner(
        source: &crate::SourceTransferPreparation<'_>,
        archive: crucible_campaign::CampaignArchiveManifestId,
        destination: DaemonEpoch,
        checkpoint: ExactCheckpointId,
        possession: &crate::campaign_transfer::CampaignArchiveExecutionPossession,
    ) -> Option<Self> {
        let (source_key, state) = source.binding();
        let fence = state.source_transfer()?;
        (fence.phase() == SourceTransferPhase::Prepared
            && fence.intent().destination == destination
            && state.checkpoint() == Some(checkpoint))
        .then_some(Self {
            source_key,
            source: state,
            archive,
            publication: possession.publication(),
            phase: ReceivingTransferPhase::Ready,
        })
    }

    pub(crate) const fn phase(self) -> ReceivingTransferPhase {
        self.phase
    }

    pub(crate) const fn binding(self) -> (AttemptExecutionKey, AttemptRuntimeState) {
        (self.source_key, self.source)
    }

    pub(crate) fn ownership_generation(self) -> Option<u64> {
        self.source
            .source_transfer()
            .map(|state| state.intent().offer_generation)
    }

    pub(crate) fn readiness(self) -> CampaignHash {
        // Phase is excluded: source release and destination commit bind the
        // same complete readiness identity, with no caller-chosen digest.
        let mut record = self;
        record.phase = ReceivingTransferPhase::Ready;
        CampaignHash::derive("crucible.executor.receiving-readiness.v1", &record.encode())
    }

    pub(crate) fn committed(self) -> Option<Self> {
        (self.phase == ReceivingTransferPhase::Ready).then_some(Self {
            phase: ReceivingTransferPhase::Committed,
            ..self
        })
    }

    pub(crate) fn aborted(self) -> Option<Self> {
        (self.phase == ReceivingTransferPhase::Ready).then_some(Self {
            phase: ReceivingTransferPhase::Aborted,
            ..self
        })
    }

    fn storage_digest(self) -> Result<CampaignHash, AssignmentLedgerError> {
        let intent = self
            .source
            .source_transfer()
            .ok_or_else(|| corrupt("receiving-source-fence"))?
            .intent();
        let mut bytes = [0_u8; 40];
        bytes[..32].copy_from_slice(&intent.operation.as_bytes());
        bytes[32..].copy_from_slice(&intent.offer_generation.to_be_bytes());
        Ok(CampaignHash::derive(
            "crucible.executor.receiving-key.v1",
            &bytes,
        ))
    }

    fn valid(self) -> bool {
        self.publication.as_bytes() != [0; 32]
            && self.source_key.scope() == AttemptExecutionScope::Semantic
            && self.source.validates_for_key(self.source_key)
            && self.source.checkpoint().is_some()
            && self.source.source_transfer().is_some_and(|state| {
                state.valid() && state.phase() == SourceTransferPhase::Prepared
            })
    }

    fn preserves(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        self.phase == ReceivingTransferPhase::Ready
            && self.source_key == next.source_key
            && self.source == next.source
            && self.archive == next.archive
            && self.publication == next.publication
            && matches!(
                next.phase,
                ReceivingTransferPhase::Committed | ReceivingTransferPhase::Aborted
            )
    }

    fn encode(self) -> Vec<u8> {
        let source = encode_attempt_state(self.source_key, self.source);
        let mut payload = Vec::with_capacity(MAGIC.len() + source.len() + 256);
        payload.extend_from_slice(MAGIC);
        push_bytes(&mut payload, &source);
        push_bytes(&mut payload, self.archive.to_text().as_bytes());
        payload.extend_from_slice(&self.publication.as_bytes());
        payload.push(match self.phase {
            ReceivingTransferPhase::Ready => 0,
            ReceivingTransferPhase::Committed => 1,
            ReceivingTransferPhase::Aborted => 2,
        });
        seal(payload, DOMAIN)
    }

    fn decode(bytes: &[u8]) -> Result<Self, AssignmentLedgerError> {
        let mut cursor = RecordCursor::new(open_sealed(bytes, DOMAIN)?);
        cursor.require(MAGIC)?;
        let (source_key, source) = decode_attempt_state(cursor.bytes()?)?;
        let archive = crucible_campaign::CampaignArchiveManifestId::parse(
            std::str::from_utf8(cursor.bytes()?).map_err(|_| corrupt("receiving-archive-text"))?,
        )?;
        let publication = CampaignHash::from_bytes(cursor.fixed()?);
        let phase = match cursor.byte()? {
            0 => ReceivingTransferPhase::Ready,
            1 => ReceivingTransferPhase::Committed,
            2 => ReceivingTransferPhase::Aborted,
            _ => return Err(corrupt("receiving-phase")),
        };
        cursor.finish()?;
        let record = Self {
            source_key,
            source,
            archive,
            publication,
            phase,
        };
        if !record.valid() {
            return Err(corrupt("receiving-binding"));
        }
        Ok(record)
    }
}

pub(crate) enum ReceivingTransferCas {
    Advanced,
    Conflict,
}

impl DirectoryAssignmentLedger {
    fn receiving_path(
        &self,
        record: ReceivingTransferRecord,
    ) -> Result<PathBuf, AssignmentLedgerError> {
        let encoded = encode_hex(&record.storage_digest()?.as_bytes());
        Ok(self
            .root
            .join("receiving")
            .join(&encoded[..2])
            .join(encoded))
    }

    pub(crate) fn load_receiving_transfer(
        &self,
        binding: ReceivingTransferRecord,
    ) -> Result<Option<ReceivingTransferRecord>, AssignmentLedgerError> {
        self.verify_authority()?;
        let path = self.receiving_path(binding)?;
        let Some(bytes) = read_optional_bounded(&self.authority, &path)? else {
            return Ok(None);
        };
        sync_record_parent(&self.authority, &path)?;
        let record = ReceivingTransferRecord::decode(&bytes)?;
        if self.receiving_path(record)? != path {
            return Err(corrupt("receiving-path-identity"));
        }
        self.verify_authority()?;
        Ok(Some(record))
    }

    pub(crate) fn compare_exchange_receiving_transfer(
        &mut self,
        expected: Option<ReceivingTransferRecord>,
        next: ReceivingTransferRecord,
    ) -> Result<ReceivingTransferCas, AssignmentLedgerError> {
        self.verify_authority()?;
        if !next.valid() {
            return Err(corrupt("receiving-binding"));
        }
        let current = self.load_receiving_transfer(next)?;
        if current != expected
            || current.is_some_and(|record| !record.preserves(next))
            || (current.is_none() && next.phase != ReceivingTransferPhase::Ready)
        {
            return Ok(ReceivingTransferCas::Conflict);
        }
        self.advance_retention_state()?;
        replace_mutable(&self.authority, &self.receiving_path(next)?, &next.encode())?;
        #[cfg(test)]
        if FAIL_AFTER_RECEIVING_PUBLICATION.replace(false) {
            return Err(AssignmentLedgerError::Io {
                operation: "injected-receiving-post-publication",
                path: self.receiving_path(next)?,
                source: std::io::Error::other(
                    "actual receiving publication completed before injected refusal",
                ),
            });
        }
        self.verify_authority()?;
        Ok(ReceivingTransferCas::Advanced)
    }
}

impl DirectoryAssignmentLedger {
    pub(super) fn visit_receiving_records(
        &self,
        maximum: usize,
        visitor: &mut dyn FnMut(ReceivingTransferRecord),
        boundary: &mut dyn FnMut() -> Result<(), AssignmentLedgerError>,
    ) -> Result<(), AssignmentLedgerError> {
        visit_records(&self.authority, &self.root, maximum, visitor, boundary)
    }
}

pub(super) fn visit_records(
    authority: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
    maximum: usize,
    visitor: &mut dyn FnMut(ReceivingTransferRecord),
    boundary: &mut dyn FnMut() -> Result<(), AssignmentLedgerError>,
) -> Result<(), AssignmentLedgerError> {
    let incoming = root.join("receiving");
    let Some(directory) = authority
        .open_directory_optional(&incoming, "open-receiving-root")
        .map_err(|source| anchored_ledger_error(source, "open-receiving-root"))?
    else {
        return Ok(());
    };
    let shards = directory
        .entry_names(MAX_RUNTIME_ATTEMPT_SHARDS, "read-receiving-shards")
        .map_err(|source| anchored_ledger_error(source, "read-receiving-shards"))?;
    let mut visited = 0_usize;
    for name in shards {
        let name = name
            .to_str()
            .ok_or_else(|| corrupt("receiving-shard-name"))?;
        if !canonical_hex(name, 2) {
            return Err(corrupt("receiving-shard-name"));
        }
        let shard_name = name;
        let path = incoming.join(shard_name);
        let shard = directory
            .open_directory(&path, "open-receiving-shard")
            .map_err(|source| anchored_ledger_error(source, "open-receiving-shard"))?;
        let mut failure = None;
        let complete = shard
            .visit_entry_names_bounded(
                MAX_RUNTIME_ATTEMPT_RECORDS,
                "read-receiving-records",
                &mut |name| {
                    let result = (|| {
                        if visited >= maximum {
                            return Err(corrupt("receiving-inventory-limit"));
                        }
                        let name = name
                            .to_str()
                            .ok_or_else(|| corrupt("receiving-record-name"))?;
                        if !canonical_hex(name, 64) {
                            return Err(corrupt("receiving-record-name"));
                        }
                        boundary()?;
                        let path = path.join(name);
                        let bytes = read_optional_bounded(&shard, &path)?
                            .ok_or_else(|| corrupt("receiving-record-disappeared"))?;
                        let record = ReceivingTransferRecord::decode(&bytes)?;
                        let digest = encode_hex(&record.storage_digest()?.as_bytes());
                        if digest != name || &digest[..2] != shard_name {
                            return Err(corrupt("receiving-path-identity"));
                        }
                        visitor(record);
                        visited += 1;
                        boundary()?;
                        Ok::<(), AssignmentLedgerError>(())
                    })();
                    match result {
                        Ok(()) => true,
                        Err(error) => {
                            failure = Some(error);
                            false
                        }
                    }
                },
            )
            .map_err(|source| anchored_ledger_error(source, "read-receiving-records"))?;
        if let Some(error) = failure {
            return Err(error);
        }
        if !complete {
            return Err(corrupt("receiving-inventory-incomplete"));
        }
        shard
            .verify_path_binding()
            .map_err(|source| anchored_ledger_error(source, "verify-receiving-shard"))?;
    }
    directory
        .verify_path_binding()
        .map_err(|source| anchored_ledger_error(source, "verify-receiving-root"))?;
    authority
        .verify_path_binding()
        .map_err(|source| anchored_ledger_error(source, "verify-ledger-root"))
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
