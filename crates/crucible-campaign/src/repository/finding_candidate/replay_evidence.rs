//! Publication and bounded reads for native triage replay evidence.

use super::*;

impl CampaignRepository {
    /// Publishes one transport-neutral native triage replay record.
    ///
    /// The referenced reproduction and every observed-signature dependency
    /// must already be durable. Repeating the operation returns the same ID.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when any referenced object
    /// is absent, corrupt, or inconsistent with the observed signature.
    pub fn publish_finding_triage_replay_evidence(
        &self,
        evidence: &FindingTriageReplayEvidence,
    ) -> Result<FindingTriageReplayEvidenceId, CampaignRepositoryError> {
        let plan = evidence.storage_plan()?;
        let expected_content = plan.root.content_id();
        self.validate_finding_triage_replay_evidence(evidence)?;

        // Rebuild and authenticate the complete deterministic plan before the
        // first durable write. The second pass publishes one bounded chunk at a
        // time, so maximum evidence does not require another full payload copy.
        for (index, descriptor) in plan.chunks.iter().copied().enumerate() {
            evidence.chunk_envelope(index, descriptor)?;
        }
        for (index, descriptor) in plan.chunks.iter().copied().enumerate() {
            let content = self.put_envelope(evidence.chunk_envelope(index, descriptor)?)?;
            if content != descriptor.content() {
                return Err(integrity(
                    "finding-triage-replay-evidence-chunk-publication-id-mismatch",
                ));
            }
        }
        let content = self.put_envelope(plan.root)?;
        if content != expected_content {
            return Err(integrity(
                "finding-triage-replay-evidence-publication-id-mismatch",
            ));
        }
        self.verify_campaign_closure(content)?;
        FindingTriageReplayEvidenceId::from_content_id(content).map_err(Into::into)
    }

    /// Loads and authenticates one native triage replay record.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the record or one of its
    /// referenced objects is absent, corrupt, or inconsistent.
    pub fn load_finding_triage_replay_evidence(
        &self,
        id: FindingTriageReplayEvidenceId,
    ) -> Result<FindingTriageReplayEvidence, CampaignRepositoryError> {
        let evidence = self.decode_finding_triage_replay_evidence(id.content_id())?;
        self.validate_finding_triage_replay_evidence(&evidence)?;
        Ok(evidence)
    }

    /// Describes the authenticated stored envelopes for one replay record.
    ///
    /// The returned order is always the root followed by payload chunks in
    /// logical order. Repeated content IDs remain distinct positions.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error when the root, a payload
    /// chunk, or a referenced logical dependency is absent or inconsistent.
    pub fn describe_finding_triage_replay_storage(
        &self,
        id: FindingTriageReplayEvidenceId,
    ) -> Result<FindingTriageReplayStorageDescription, CampaignRepositoryError> {
        let root = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::FindingTriageReplayEvidence,
        )?;
        let root_schema_version = root.schema_version();
        let mut objects = vec![FindingTriageReplayStorageObject::new(
            0,
            FindingTriageReplayStorageObjectRole::Root,
            id.content_id(),
            canonical_envelope_bytes(&root)?,
        )];

        let logical_payload_bytes = match root_schema_version {
            1 => {
                let evidence = FindingTriageReplayEvidence::from_canonical_bytes(root.body())?;
                self.validate_finding_triage_replay_dependencies(
                    evidence.reproduction(),
                    evidence.observed_signature(),
                )?;
                u64::try_from(evidence.payload().len()).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "finding-triage-replay-payload-bytes",
                    }
                })?
            }
            2 => {
                let manifest =
                    FindingTriageReplayEvidence::manifest_from_canonical_bytes(root.body())?;
                self.validate_finding_triage_replay_dependencies(
                    manifest.reproduction(),
                    manifest.observed_signature(),
                )?;
                for (index, descriptor) in manifest.chunks().iter().copied().enumerate() {
                    let chunk = self.require_record_kind(
                        descriptor.content(),
                        crate::CampaignRecordKind::FindingTriageReplayEvidenceChunk,
                    )?;
                    let payload =
                        FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
                    if payload.len() != descriptor.logical_bytes() as usize {
                        return Err(integrity(
                            "finding-triage-replay-evidence-chunk-length-mismatch",
                        ));
                    }
                    drop(payload);
                    let ordinal = u32::try_from(index + 1).map_err(|_| {
                        CampaignCodecError::LimitExceeded {
                            limit: "finding-triage-replay-storage-object-ordinal",
                        }
                    })?;
                    let chunk_index =
                        u32::try_from(index).map_err(|_| CampaignCodecError::LimitExceeded {
                            limit: "finding-triage-replay-storage-object-ordinal",
                        })?;
                    objects.push(FindingTriageReplayStorageObject::new(
                        ordinal,
                        FindingTriageReplayStorageObjectRole::PayloadChunk {
                            index: chunk_index,
                            logical_payload_bytes: descriptor.logical_bytes(),
                        },
                        descriptor.content(),
                        canonical_envelope_bytes(&chunk)?,
                    ));
                }
                u64::try_from(manifest.payload_bytes()?).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "finding-triage-replay-payload-bytes",
                    }
                })?
            }
            _ => {
                return Err(integrity("finding-triage-replay-evidence-envelope-version"));
            }
        };

        FindingTriageReplayStorageDescription::new(
            id,
            root_schema_version,
            logical_payload_bytes,
            objects,
        )
        .map_err(Into::into)
    }

    /// Reads one authenticated bounded range from a described stored envelope.
    ///
    /// `object_ordinal` addresses the root-then-payload order returned by
    /// [`Self::describe_finding_triage_replay_storage`]. The stored root layout
    /// is reauthenticated before the range is read, binding the ordinal and
    /// content identity to `id`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error for a zero-length, oversized,
    /// overflowing, out-of-bounds, or unknown range. Returns a store, codec, or
    /// integrity error when the authenticated layout cannot be read.
    pub fn read_finding_triage_replay_storage_range(
        &self,
        id: FindingTriageReplayEvidenceId,
        object_ordinal: u32,
        range: crucible_cas::content_store::ByteRange,
    ) -> Result<Vec<u8>, CampaignRepositoryError> {
        if range.length == 0 || range.length > MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-length",
            });
        }
        let end = range.offset.checked_add(range.length).ok_or(
            CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-overflow",
            },
        )?;
        let object = self.resolve_finding_triage_replay_storage_object(id, object_ordinal)?;
        if end > object.stored_envelope_bytes() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-range-bounds",
            });
        }

        let source = self.blobs.read(object.content(), Some(range))?;
        if source.logical_length() != range.length {
            return Err(integrity(
                "finding-triage-replay-storage-range-length-mismatch",
            ));
        }
        source.read_all(range.length).map_err(Into::into)
    }

    fn resolve_finding_triage_replay_storage_object(
        &self,
        id: FindingTriageReplayEvidenceId,
        object_ordinal: u32,
    ) -> Result<FindingTriageReplayStorageObject, CampaignRepositoryError> {
        let root = self.require_record_kind(
            id.content_id(),
            crate::CampaignRecordKind::FindingTriageReplayEvidence,
        )?;
        if object_ordinal == 0 {
            return Ok(FindingTriageReplayStorageObject::new(
                0,
                FindingTriageReplayStorageObjectRole::Root,
                id.content_id(),
                canonical_envelope_bytes(&root)?,
            ));
        }
        if root.schema_version() != 2 {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-object-ordinal",
            });
        }

        let manifest = FindingTriageReplayEvidence::manifest_from_canonical_bytes(root.body())?;
        let chunk_index =
            object_ordinal
                .checked_sub(1)
                .ok_or(CampaignRepositoryError::InvalidRequest {
                    reason: "finding-triage-replay-storage-object-ordinal",
                })?;
        let descriptor = manifest
            .chunks()
            .get(usize::try_from(chunk_index).map_err(|_| {
                CampaignRepositoryError::InvalidRequest {
                    reason: "finding-triage-replay-storage-object-ordinal",
                }
            })?)
            .copied()
            .ok_or(CampaignRepositoryError::InvalidRequest {
                reason: "finding-triage-replay-storage-object-ordinal",
            })?;
        let chunk = self.require_record_kind(
            descriptor.content(),
            crate::CampaignRecordKind::FindingTriageReplayEvidenceChunk,
        )?;
        let logical_bytes = FindingTriageReplayEvidence::chunk_from_canonical_bytes(chunk.body())?;
        if logical_bytes.len() != descriptor.logical_bytes() as usize {
            return Err(integrity(
                "finding-triage-replay-evidence-chunk-length-mismatch",
            ));
        }

        Ok(FindingTriageReplayStorageObject::new(
            object_ordinal,
            FindingTriageReplayStorageObjectRole::PayloadChunk {
                index: chunk_index,
                logical_payload_bytes: descriptor.logical_bytes(),
            },
            descriptor.content(),
            canonical_envelope_bytes(&chunk)?,
        ))
    }
}

fn canonical_envelope_bytes(envelope: &ObjectEnvelope) -> Result<u64, CampaignRepositoryError> {
    u64::try_from(envelope.canonical_bytes().len()).map_err(|_| {
        CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-envelope-bytes",
        }
        .into()
    })
}
