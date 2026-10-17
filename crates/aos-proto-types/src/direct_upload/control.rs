//! Bounded control encoding and batch shape checks shared by all runtimes.

use std::{collections::BTreeSet, io};

use serde::{de::DeserializeOwned, Serialize};

use super::validation::require;
use super::*;

/// Encodes a complete control envelope without allocating beyond its limit.
///
/// # Errors
/// Returns a value-free error for serialization failure or encoded size above
/// 256 KiB. Validation of the operation's semantic shape remains separate.
pub fn encode_direct_control<T: Serialize>(value: &T) -> DirectUploadResult<Vec<u8>> {
    let mut output = LimitedWriter(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|_| {
        DirectUploadError("direct-upload control encoding exceeds limit or is invalid")
    })?;
    Ok(output.0)
}

/// Decodes a closed typed control after checking raw size before parsing.
///
/// # Errors
/// Returns a value-free error for an excessive, malformed, unknown or duplicate
/// field. The selected type must use closed Serde declarations. Authentication
/// and semantic operation validation must be performed by the caller.
pub fn decode_direct_control<T: DeserializeOwned>(bytes: &[u8]) -> DirectUploadResult<T> {
    require(
        bytes.len() <= MAX_DIRECT_CONTROL_BYTES,
        "direct-upload control exceeds limit",
    )?;
    serde_json::from_slice(bytes).map_err(|_| DirectUploadError("invalid direct-upload control"))
}

/// Decodes the exact public RPC body before any generated unknown-field elision.
///
/// The method is the generated RPC name, with no arbitrary service/path routing.
/// Authentication remains the serving adapter's responsibility. Discovery uses
/// the separate closed [`DirectGetCapabilities`] model.
///
/// # Errors
/// Returns an error for an unknown method, excessive or nonclosed body, malformed
/// batch, duplicate item or operation exceeding aggregate protocol limits.
pub fn decode_direct_public_request(
    method: &str,
    bytes: &[u8],
) -> DirectUploadResult<DirectUploadRequest> {
    let request = match method {
        "BeginBatch" => DirectUploadRequest::BeginBatch(decode_direct_control(bytes)?),
        "StatusBatch" => DirectUploadRequest::StatusBatch(decode_direct_control(bytes)?),
        "GrantPartsBatch" => DirectUploadRequest::GrantPartsBatch(decode_direct_control(bytes)?),
        "ReportPartsBatch" => DirectUploadRequest::ReportPartsBatch(decode_direct_control(bytes)?),
        "CompleteBatch" => DirectUploadRequest::CompleteBatch(decode_direct_control(bytes)?),
        "Abort" => DirectUploadRequest::Abort(decode_direct_control(bytes)?),
        _ => return Err(DirectUploadError("unknown direct-upload public method")),
    };
    request.validate()?;
    Ok(request)
}

struct LimitedWriter(Vec<u8>);

impl io::Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_DIRECT_CONTROL_BYTES)
        {
            return Err(io::Error::other("direct-upload control exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DirectSessionRef {
    /// Checks an exact session identity and immutable admission commitment.
    ///
    /// # Errors
    /// Returns an error for malformed session identity or fingerprint.
    pub fn validate(&self) -> DirectUploadResult<()> {
        require(
            valid_direct_identity(&self.session_id)
                && valid_direct_digest(&self.logical_fingerprint),
            "invalid direct-upload session reference",
        )
    }
}

impl DirectPlacementRef {
    /// Checks a lossless SQL placement identity and immutable snapshot digest.
    ///
    /// # Errors
    /// Returns an error for a zero/out-of-range identity or malformed digest.
    pub fn validate(&self) -> DirectUploadResult<()> {
        require(
            [
                self.placement_id,
                self.placement_resource_version,
                self.write_spec_version,
                self.binding_id,
                self.binding_resource_version,
                self.binding_write_revision,
            ]
            .iter()
            .all(|value| (1..=i64::MAX as u64).contains(&value.get()))
                && valid_direct_digest(&self.placement_fingerprint)
                && valid_direct_digest(&self.profile_fingerprint)
                && valid_direct_digest(&self.private_policy_digest),
            "invalid direct-upload placement reference",
        )
    }
}

impl DirectSessionStatus {
    /// Checks a bounded sparse page against its complete destination declaration.
    ///
    /// # Errors
    /// Returns an error for invalid source/version, unordered destinations or
    /// parts, changed geometry, malformed pending state or a foreign cursor.
    pub fn validate(&self) -> DirectUploadResult<()> {
        self.session.validate()?;
        self.intent.validate()?;
        version(self.resource_version)?;
        count(self.placements.len(), MAX_DIRECT_PLACEMENTS)?;
        require(
            self.parts.len() <= MAX_DIRECT_BATCH_PARTS,
            "direct-upload status part budget exceeded",
        )?;
        let mut previous = 0;
        for placement in &self.placements {
            placement.validate()?;
            require(
                placement.placement_id.get() > previous,
                "unordered direct-upload status destinations",
            )?;
            previous = placement.placement_id.get();
        }
        let mut previous_part = (0, 0);
        for item in &self.parts {
            require(
                self.placements.contains(&item.placement)
                    && (item.placement.placement_id.get(), item.part_number) > previous_part,
                "unordered or foreign direct-upload status part",
            )?;
            self.intent.part_range(item.part_number)?;
            previous_part = (item.placement.placement_id.get(), item.part_number);
            if let Some(observed) = &item.observed {
                observed.part.validate(&self.intent)?;
                require(
                    observed.part.part_number == item.part_number
                        && valid_direct_etag(&observed.etag)
                        && observed.part.checksum.algorithm == item.placement.checksum_algorithm,
                    "direct-upload status observation mismatch",
                )?;
            }
            require(
                !item.unknown || item.pending_operation_id.is_some(),
                "direct-upload unknown state lacks operation fence",
            )?;
            if let Some(pending) = &item.pending_operation_id {
                operation(pending)?;
            }
        }
        if let Some(cursor) = &self.next_cursor {
            require(
                self.placements.contains(&cursor.placement)
                    && cursor.part_number <= self.intent.part_count()?
                    && (cursor.placement.placement_id.get(), cursor.part_number) >= previous_part,
                "invalid direct-upload next cursor",
            )?;
        }
        Ok(())
    }

    /// Checks resume echo against independently retained original declarations.
    ///
    /// # Errors
    /// Returns an error for malformed page or changed session/source/destinations.
    pub fn validate_for(
        &self,
        session: &DirectSessionRef,
        intent: &DirectUploadIntent,
        placements: &[DirectPlacementRef],
    ) -> DirectUploadResult<()> {
        self.validate()?;
        require(
            &self.session == session && &self.intent == intent && self.placements == placements,
            "direct-upload resume admission mismatch",
        )
    }
}

impl DirectUploadResponse {
    /// Checks complete response bytes and aggregate sparse/grant/item budgets.
    ///
    /// Grant URLs additionally require `DirectPartGrant::validate_for` with the
    /// independently retained expected inputs before any provider request.
    ///
    /// # Errors
    /// Returns an error for excessive bytes/counts or duplicate/malformed items.
    pub fn validate(&self) -> DirectUploadResult<()> {
        operation(&self.operation_id)?;
        encode_direct_control(self)?;
        require(
            self.sessions.len() + self.errors.len() <= MAX_DIRECT_BATCH_ITEMS
                && self.grants.len() <= MAX_DIRECT_BATCH_PARTS,
            "direct-upload reply count exceeds limit",
        )?;
        let mut identities = BTreeSet::new();
        let mut aggregate = 0;
        for status in &self.sessions {
            status.validate()?;
            unique(&mut identities, status.session.session_id.clone())?;
            aggregate += status.parts.len();
        }
        require(
            aggregate <= MAX_DIRECT_BATCH_PARTS,
            "direct-upload reply part budget exceeded",
        )?;
        identities.clear();
        for grant in &self.grants {
            require(
                valid_direct_digest(&grant.grant_id)
                    && grant.grant_revision.get() > 0
                    && grant.url.len() <= MAX_DIRECT_GRANT_URL_BYTES,
                "invalid direct-upload reply grant",
            )?;
            unique(&mut identities, grant.grant_id.clone())?;
        }
        identities.clear();
        for item in &self.errors {
            require(
                valid_direct_identity(&item.item_id),
                "invalid direct-upload reply error identity",
            )?;
            unique(&mut identities, item.item_id.clone())?;
        }
        Ok(())
    }
}

impl DirectUploadRequest {
    /// Checks aggregate batch budgets and closed identity/descriptor shapes.
    ///
    /// Stored intent geometry, authorization and complete required-placement
    /// membership must additionally be checked by the server against admission.
    ///
    /// # Errors
    /// Returns an error for excessive encoded/aggregate size, duplicates,
    /// malformed identities or invalid operation-specific declarations.
    pub fn validate(&self) -> DirectUploadResult<()> {
        encode_direct_control(self)?;
        let mut identities = BTreeSet::new();
        match self {
            Self::BeginBatch(batch) => {
                operation(&batch.operation_id)?;
                count(batch.items.len(), MAX_DIRECT_BATCH_ITEMS)?;
                for intent in &batch.items {
                    intent.validate()?;
                    unique(&mut identities, intent.client_operation_id.clone())?;
                }
            }
            Self::StatusBatch(batch) => {
                operation(&batch.operation_id)?;
                let items = &batch.items;
                count(items.len(), MAX_DIRECT_BATCH_ITEMS)?;
                let mut aggregate = 0usize;
                for item in items {
                    item.session.validate()?;
                    unique(&mut identities, item.session.session_id.clone())?;
                    require(item.maximum_parts > 0, "invalid direct-upload status page")?;
                    aggregate = aggregate
                        .checked_add(item.maximum_parts as usize)
                        .ok_or(DirectUploadError("direct-upload status budget overflow"))?;
                    if let Some(cursor) = &item.after {
                        cursor.placement.validate()?;
                        require(
                            cursor.part_number <= MAX_DIRECT_PARTS,
                            "invalid direct-upload status cursor",
                        )?;
                    }
                }
                require(
                    aggregate <= MAX_DIRECT_BATCH_PARTS,
                    "direct-upload aggregate part budget exceeded",
                )?;
            }
            Self::GrantPartsBatch(batch) => {
                operation(&batch.operation_id)?;
                let items = &batch.items;
                count(items.len(), MAX_DIRECT_BATCH_PARTS)?;
                for item in items {
                    item.session.validate()?;
                    item.placement.validate()?;
                    operation(&item.operation_id)?;
                    part_shape(&item.part)?;
                    unique(
                        &mut identities,
                        format!(
                            "{}:{}:{}",
                            item.session.session_id,
                            item.placement.placement_id.get(),
                            item.part.part_number
                        ),
                    )?;
                }
            }
            Self::ReportPartsBatch(batch) => {
                operation(&batch.operation_id)?;
                let items = &batch.items;
                count(items.len(), MAX_DIRECT_BATCH_PARTS)?;
                for item in items {
                    item.session.validate()?;
                    item.placement.validate()?;
                    operation(&item.operation_id)?;
                    operation(&item.grant_id)?;
                    require(
                        item.grant_revision.get() > 0,
                        "invalid direct-upload grant revision",
                    )?;
                    part_shape(&item.observed.part)?;
                    require(
                        valid_direct_etag(&item.observed.etag),
                        "invalid direct-upload provider ETag",
                    )?;
                    unique(&mut identities, item.operation_id.clone())?;
                }
            }
            Self::CompleteBatch(batch) => {
                operation(&batch.operation_id)?;
                let items = &batch.items;
                count(items.len(), MAX_DIRECT_BATCH_ITEMS)?;
                for item in items {
                    item.session.validate()?;
                    operation(&item.operation_id)?;
                    version(item.expected_resource_version)?;
                    unique(&mut identities, item.session.session_id.clone())?;
                    count(item.manifests.len(), MAX_DIRECT_PLACEMENTS)?;
                    let mut previous = 0;
                    for manifest in &item.manifests {
                        manifest.placement.validate()?;
                        require(
                            manifest.placement.placement_id.get() > previous
                                && manifest.part_count <= MAX_DIRECT_PARTS
                                && valid_direct_digest(&manifest.manifest_digest),
                            "invalid direct-upload manifest commitment",
                        )?;
                        previous = manifest.placement.placement_id.get();
                    }
                }
            }
            Self::Abort(batch) => {
                operation(&batch.operation_id)?;
                let items = &batch.items;
                count(items.len(), MAX_DIRECT_BATCH_ITEMS)?;
                for item in items {
                    item.session.validate()?;
                    operation(&item.operation_id)?;
                    version(item.expected_resource_version)?;
                    unique(&mut identities, item.session.session_id.clone())?;
                }
            }
        }
        Ok(())
    }
}

fn part_shape(part: &DirectPart) -> DirectUploadResult<()> {
    require(
        (1..=MAX_DIRECT_PARTS).contains(&part.part_number)
            && part.byte_size.get() > 0
            && part.byte_size.get() <= MAX_DIRECT_PART_BYTES
            && part
                .offset
                .get()
                .checked_add(part.byte_size.get())
                .is_some_and(|end| end <= MAX_DIRECT_OBJECT_BYTES)
            && valid_direct_digest(&part.sha256),
        "invalid direct-upload part declaration",
    )?;
    let checksum = part.checksum.decoded()?;
    require(
        part.checksum.algorithm != DirectChecksumAlgorithm::Sha256
            || hex::encode(checksum) == part.sha256,
        "direct-upload checksum mismatch",
    )
}

fn count(value: usize, maximum: usize) -> DirectUploadResult<()> {
    require(
        value > 0 && value <= maximum,
        "direct-upload batch count exceeds limit",
    )
}

fn operation(value: &str) -> DirectUploadResult<()> {
    require(
        valid_direct_digest(value),
        "invalid direct-upload operation identity",
    )
}

fn version(value: WireInteger) -> DirectUploadResult<()> {
    require(
        (1..=i64::MAX as u64).contains(&value.get()),
        "invalid direct-upload resource version",
    )
}

fn unique(values: &mut BTreeSet<String>, value: String) -> DirectUploadResult<()> {
    require(values.insert(value), "duplicate direct-upload batch item")
}
