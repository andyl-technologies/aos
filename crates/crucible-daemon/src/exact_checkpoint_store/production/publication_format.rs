//! Production checkpoint publication and root-format encoding.

use super::*;

pub(super) struct ProductionSourcePreparation {
    pub(super) source: Arc<dyn ProductionExactCheckpointPublicationSource>,
    pub(super) production_identity: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) configuration: ContentHash,
    pub(super) maximum_checkpoint_bytes: u64,
    pub(super) cancellation: Option<ExecutionCancellation>,
    pub(super) native_retirement: Option<ProductionExactCheckpointRetirement>,
    pub(super) promotion_source: Option<ExactCheckpointId>,
    pub(super) promotion_evidence: Option<Vec<u8>>,
    pub(super) choice_closure: Vec<u8>,
    pub(super) reuse: Option<ProductionRepositoryReuse>,
}

type ProductionRootChildren = (
    ContentId,
    Vec<ContentId>,
    Option<ExactCheckpointId>,
    Option<ContentId>,
    ContentId,
);

#[cfg(test)]
pub(super) fn prepare_production_source(
    source: Arc<dyn ProductionExactCheckpointPublicationSource>,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    maximum_checkpoint_bytes: u64,
) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
    prepare_production_source_with_cancellation(ProductionSourcePreparation {
        source,
        production_identity,
        scenario,
        configuration,
        maximum_checkpoint_bytes,
        cancellation: None,
        native_retirement: None,
        promotion_source: None,
        promotion_evidence: None,
        choice_closure: crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty()
            .to_canonical_bytes()
            .map_err(|_| invalid_root("empty choice closure could not be encoded"))?,
        reuse: None,
    })
}

pub(super) fn prepare_production_source_with_cancellation(
    preparation: ProductionSourcePreparation,
) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
    let ProductionSourcePreparation {
        source,
        production_identity,
        scenario,
        configuration,
        maximum_checkpoint_bytes,
        cancellation,
        native_retirement,
        promotion_source,
        promotion_evidence,
        choice_closure,
        reuse,
    } = preparation;

    check_cancellation(cancellation.as_ref())?;
    let manifest_bytes = source.manifest();
    if manifest_bytes.len() as u64 > MAX_PRODUCTION_MANIFEST_BYTES {
        return Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "production-manifest",
            length: manifest_bytes.len() as u64,
            maximum: MAX_PRODUCTION_MANIFEST_BYTES,
        });
    }
    let mut owned_manifest = Vec::new();
    owned_manifest
        .try_reserve_exact(manifest_bytes.len())
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    owned_manifest.extend_from_slice(manifest_bytes);
    check_cancellation(cancellation.as_ref())?;
    let mut manifest_source = BlobHandle::from_bytes(owned_manifest);
    if let Some(cancellation) = cancellation.as_ref() {
        manifest_source = cancellation_blob_handle(manifest_source, cancellation.clone());
    }
    let manifest_id = ContentId::for_source(
        ObjectKind::DeviceState,
        PRODUCTION_MANIFEST_SCHEMA_VERSION,
        &manifest_source,
    )
    .map_err(map_checkpoint_store_error)?;

    if reuse
        .as_ref()
        .is_some_and(|reused| reused.placements.len() != source.objects().len())
    {
        return Err(invalid_root("repository object placement count changed"));
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(source.objects().len())
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    let mut object_bytes = 0_u64;
    for (ordinal, object) in source.objects().iter().enumerate() {
        check_cancellation(cancellation.as_ref())?;
        object_bytes = object_bytes
            .checked_add(object.length())
            .ok_or_else(|| invalid_root("production object byte count overflow"))?;
        let content = if let Some(reused) = &reuse {
            reused.placements[ordinal]
        } else {
            let handle = portable_object_handle(Arc::clone(&source), *object, cancellation.clone());
            production_object_content_id(&handle)?
        };
        objects.push(ProductionObjectPlacement {
            object: *object,
            content,
        });
    }
    validate_production_checkpoint_bytes(
        manifest_source.logical_length(),
        object_bytes,
        maximum_checkpoint_bytes,
    )?;
    validate_production_object_inventory_bound(
        manifest_source.logical_length(),
        u64::try_from(objects.len())
            .map_err(|_| invalid_root("production object count is not representable"))?,
    )?;

    let mut indexes = Vec::new();
    let index_capacity = objects.len().div_ceil(PRODUCTION_INDEX_PAGE_OBJECTS);
    indexes
        .try_reserve_exact(index_capacity)
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    for page in objects.chunks(PRODUCTION_INDEX_PAGE_OBJECTS) {
        check_cancellation(cancellation.as_ref())?;
        let envelope = encode_index_page(page)?;
        let bytes = envelope.canonical_bytes();
        let id = envelope.content_id(ObjectKind::ExactManifest);
        let mut source = BlobHandle::from_bytes(bytes);
        if let Some(cancellation) = cancellation.as_ref() {
            source = cancellation_blob_handle(source, cancellation.clone());
        }
        indexes.push((id, source));
    }
    let index_count = u32::try_from(indexes.len())
        .map_err(|_| invalid_root("production index count exceeds root representation"))?;
    let promotion_evidence = if let Some(bytes) = promotion_evidence {
        if bytes.is_empty() || bytes.len() as u64 > MAX_PRODUCTION_PROMOTION_EVIDENCE_BYTES {
            return Err(invalid_root("replay-oracle evidence length is invalid"));
        }
        let mut source = BlobHandle::from_bytes(bytes);
        if let Some(cancellation) = cancellation.as_ref() {
            source = cancellation_blob_handle(source, cancellation.clone());
        }
        let identity = ContentId::for_source(
            ObjectKind::Observation,
            PRODUCTION_PROMOTION_EVIDENCE_SCHEMA_VERSION,
            &source,
        )
        .map_err(map_checkpoint_store_error)?;
        Some((identity, source))
    } else {
        None
    };
    if promotion_source.is_some() != promotion_evidence.is_some() {
        return Err(invalid_root(
            "replay-oracle source and evidence must be prepared together",
        ));
    }
    if choice_closure.is_empty()
        || choice_closure.len() as u64 > MAX_PRODUCTION_CHOICE_CLOSURE_BYTES
    {
        return Err(invalid_root("checkpoint choice closure length is invalid"));
    }
    crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
        &choice_closure,
    )
    .map_err(|_| invalid_root("checkpoint choice closure is malformed"))?;
    let mut choice_closure = BlobHandle::from_bytes(choice_closure);
    if let Some(cancellation) = cancellation.as_ref() {
        choice_closure = cancellation_blob_handle(choice_closure, cancellation.clone());
    }
    let choice_id = ContentId::for_source(
        ObjectKind::Observation,
        PRODUCTION_CHOICE_CLOSURE_SCHEMA_VERSION,
        &choice_closure,
    )
    .map_err(map_checkpoint_store_error)?;

    let body = encode_production_root_body(ProductionRootBody {
        production_identity,
        scenario,
        configuration,
        manifest_bytes: manifest_source.logical_length(),
        object_count: u64::try_from(objects.len())
            .map_err(|_| invalid_root("production object count is not representable"))?,
        object_bytes,
        index_count,
    });
    let mut children = BTreeSet::new();
    children.insert(ContentChild::new(PRODUCTION_MANIFEST_ROLE, manifest_id)?);
    children.insert(ContentChild::new(
        PRODUCTION_CHOICE_CLOSURE_ROLE,
        choice_id,
    )?);
    if let Some(source) = promotion_source {
        children.insert(ContentChild::new(
            PRODUCTION_PROMOTION_SOURCE_ROLE,
            source.content_id(),
        )?);
    }
    if let Some((identity, _)) = &promotion_evidence {
        children.insert(ContentChild::new(
            PRODUCTION_PROMOTION_EVIDENCE_ROLE,
            *identity,
        )?);
    }
    for (index, (identity, _)) in indexes.iter().enumerate() {
        children.insert(ContentChild::new(index_role(index)?, *identity)?);
    }
    let root_envelope = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        body,
    )?;
    let root = ExactCheckpointId::try_from(root_envelope.content_id(ObjectKind::ExactManifest))
        .map_err(|_| invalid_root("production root identity"))?;
    let mut root_source = BlobHandle::from_bytes(root_envelope.canonical_bytes());
    if let Some(cancellation) = cancellation.as_ref() {
        root_source = cancellation_blob_handle(root_source, cancellation.clone());
    }
    Ok(PreparedProductionExactCheckpoint {
        root,
        root_source,
        manifest_id,
        manifest_source,
        source,
        objects,
        indexes,
        reuse_backend: reuse.map(|reused| reused.backend),
        production_identity,
        promotion_source,
        promotion_evidence,
        choice_closure: (choice_id, choice_closure),
        scenario,
        configuration,
        object_bytes,
        cancellation,
        native_retirement,
    })
}

pub(super) fn encode_index_page(
    placements: &[ProductionObjectPlacement],
) -> Result<ContentEnvelope, ExactCheckpointStoreError> {
    if placements.is_empty() || placements.len() > PRODUCTION_INDEX_PAGE_OBJECTS {
        return Err(invalid_root(
            "production index page has an invalid object count",
        ));
    }
    let mut body =
        Vec::with_capacity(PRODUCTION_INDEX_MAGIC.len() + 4 + placements.len().saturating_mul(40));
    body.extend_from_slice(PRODUCTION_INDEX_MAGIC);
    body.extend_from_slice(
        &u32::try_from(placements.len())
            .map_err(|_| invalid_root("production index page count is not representable"))?
            .to_be_bytes(),
    );
    let mut children = BTreeSet::new();
    let mut previous = None;
    for placement in placements {
        if previous.is_some_and(|prior| prior >= placement.object.identity()) {
            return Err(invalid_root(
                "production index input is not strictly sorted",
            ));
        }
        previous = Some(placement.object.identity());
        body.extend_from_slice(&placement.object.identity().bytes);
        body.extend_from_slice(&placement.object.length().to_be_bytes());
        children.insert(ContentChild::new(
            object_role(placement.object.identity()),
            placement.content,
        )?);
    }
    ContentEnvelope::new(
        PRODUCTION_INDEX_SCHEMA,
        PRODUCTION_INDEX_SCHEMA_VERSION,
        children,
        body,
    )
    .map_err(Into::into)
}

pub(super) fn decode_index_page(
    envelope: &ContentEnvelope,
) -> Result<Vec<ProductionObjectPlacement>, ExactCheckpointStoreError> {
    let bytes = envelope.body();
    if bytes.len() < 12 || &bytes[..8] != PRODUCTION_INDEX_MAGIC {
        return Err(invalid_root("production index body framing is invalid"));
    }
    let count = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| invalid_root("production index count is invalid"))?,
    ) as usize;
    if count == 0 || count > PRODUCTION_INDEX_PAGE_OBJECTS {
        return Err(invalid_root("production index object count is invalid"));
    }
    let expected = 12_usize
        .checked_add(
            count
                .checked_mul(40)
                .ok_or_else(|| invalid_root("production index body length overflow"))?,
        )
        .ok_or_else(|| invalid_root("production index body length overflow"))?;
    if bytes.len() != expected || envelope.children().len() != count {
        return Err(invalid_root(
            "production index body or child count mismatch",
        ));
    }
    let mut placements = Vec::new();
    placements
        .try_reserve_exact(count)
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    let mut children = envelope.children().iter();
    let mut previous = None;
    let (records, remainder) = bytes[12..].as_chunks::<40>();
    if !remainder.is_empty() {
        return Err(invalid_root("production index record is truncated"));
    }
    for record in records {
        let mut raw = [0_u8; 32];
        raw.copy_from_slice(&record[..32]);
        let identity = ContentHash { bytes: raw };
        let length = u64::from_be_bytes(
            record[32..40]
                .try_into()
                .map_err(|_| invalid_root("production object length is invalid"))?,
        );
        if previous.is_some_and(|prior| prior >= identity) {
            return Err(invalid_root("production index records are not sorted"));
        }
        previous = Some(identity);
        let child = children
            .next()
            .ok_or_else(|| invalid_root("production index child is missing"))?;
        if child.role() != object_role(identity)
            || child.id().kind() != ObjectKind::DeviceState
            || child.id().schema_version() != PRODUCTION_OBJECT_SCHEMA_VERSION
        {
            return Err(invalid_root("production index child binding is invalid"));
        }
        placements.push(ProductionObjectPlacement {
            object: ProductionExactCheckpointObject::new(identity, length),
            content: child.id(),
        });
    }
    if children.next().is_some() {
        return Err(invalid_root("production index contains an extra child"));
    }
    Ok(placements)
}

#[derive(Clone, Copy)]
pub(super) struct ProductionRootBody {
    pub(super) production_identity: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) configuration: ContentHash,
    pub(super) manifest_bytes: u64,
    pub(super) object_count: u64,
    pub(super) object_bytes: u64,
    pub(super) index_count: u32,
}

pub(super) fn encode_production_root_body(body: ProductionRootBody) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PRODUCTION_ROOT_BODY_BYTES);
    bytes.extend_from_slice(&body.production_identity.bytes);
    bytes.extend_from_slice(&body.scenario.bytes);
    bytes.extend_from_slice(&body.configuration.bytes);
    bytes.extend_from_slice(&body.manifest_bytes.to_be_bytes());
    bytes.extend_from_slice(&body.object_count.to_be_bytes());
    bytes.extend_from_slice(&body.object_bytes.to_be_bytes());
    bytes.extend_from_slice(&body.index_count.to_be_bytes());
    bytes
}

pub(super) fn decode_production_root_body(
    bytes: &[u8],
) -> Result<ProductionRootBody, ExactCheckpointStoreError> {
    if bytes.len() != PRODUCTION_ROOT_BODY_BYTES {
        return Err(invalid_root("production root body length mismatch"));
    }
    let hash = |range: std::ops::Range<usize>| {
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes[range]);
        ContentHash { bytes: value }
    };
    Ok(ProductionRootBody {
        production_identity: hash(0..32),
        scenario: hash(32..64),
        configuration: hash(64..96),
        manifest_bytes: u64::from_be_bytes(
            bytes[96..104]
                .try_into()
                .map_err(|_| invalid_root("production manifest length is invalid"))?,
        ),
        object_count: u64::from_be_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| invalid_root("production object count is invalid"))?,
        ),
        object_bytes: u64::from_be_bytes(
            bytes[112..120]
                .try_into()
                .map_err(|_| invalid_root("production object bytes are invalid"))?,
        ),
        index_count: u32::from_be_bytes(
            bytes[120..124]
                .try_into()
                .map_err(|_| invalid_root("production index count is invalid"))?,
        ),
    })
}

pub(super) fn decode_production_root_children(
    envelope: &ContentEnvelope,
    index_count: u32,
) -> Result<ProductionRootChildren, ExactCheckpointStoreError> {
    let expected = usize::try_from(index_count)
        .map_err(|_| invalid_root("production index count is not representable"))?;
    if !matches!(envelope.children().len(), count if count == expected.saturating_add(2) || count == expected.saturating_add(4))
    {
        return Err(invalid_root("production root child count mismatch"));
    }
    let mut manifest = None;
    let mut promotion_source = None;
    let mut promotion_evidence = None;
    let mut choice_closure = None;
    let mut indexes = vec![None; expected];
    for child in envelope.children() {
        if child.role() == PRODUCTION_MANIFEST_ROLE {
            if manifest.replace(child.id()).is_some()
                || child.id().kind() != ObjectKind::DeviceState
                || child.id().schema_version() != PRODUCTION_MANIFEST_SCHEMA_VERSION
            {
                return Err(invalid_root("production manifest child is invalid"));
            }
            continue;
        }
        if child.role() == PRODUCTION_PROMOTION_SOURCE_ROLE {
            let source = ExactCheckpointId::try_from(child.id())
                .map_err(|_| invalid_root("replay-oracle source child is invalid"))?;
            if promotion_source.replace(source).is_some() {
                return Err(invalid_root("replay-oracle source child is duplicated"));
            }
            continue;
        }
        if child.role() == PRODUCTION_PROMOTION_EVIDENCE_ROLE {
            if child.id().kind() != ObjectKind::Observation
                || child.id().schema_version() != PRODUCTION_PROMOTION_EVIDENCE_SCHEMA_VERSION
                || promotion_evidence.replace(child.id()).is_some()
            {
                return Err(invalid_root("replay-oracle evidence child is invalid"));
            }
            continue;
        }
        if child.role() == PRODUCTION_CHOICE_CLOSURE_ROLE {
            if child.id().kind() != ObjectKind::Observation
                || child.id().schema_version() != PRODUCTION_CHOICE_CLOSURE_SCHEMA_VERSION
                || choice_closure.replace(child.id()).is_some()
            {
                return Err(invalid_root("checkpoint choice closure child is invalid"));
            }
            continue;
        }
        let suffix = child
            .role()
            .strip_prefix(PRODUCTION_INDEX_ROLE_PREFIX)
            .ok_or_else(|| invalid_root("production root contains an unknown child role"))?;
        let index = usize::from_str_radix(suffix, 16)
            .map_err(|_| invalid_root("production index child role is invalid"))?;
        if suffix.len() != 8
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || index >= indexes.len()
            || index_role(index)? != child.role()
            || indexes[index].replace(child.id()).is_some()
            || child.id().kind() != ObjectKind::ExactManifest
            || child.id().schema_version() != PRODUCTION_INDEX_SCHEMA_VERSION
        {
            return Err(invalid_root("production index child binding is invalid"));
        }
    }
    let manifest = manifest.ok_or_else(|| invalid_root("production manifest child is missing"))?;
    let indexes = indexes
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid_root("production index child sequence is incomplete"))?;
    Ok((
        manifest,
        indexes,
        promotion_source,
        promotion_evidence,
        choice_closure.ok_or_else(|| invalid_root("checkpoint choice closure child is missing"))?,
    ))
}

pub(super) fn validate_production_checkpoint_bytes(
    manifest_bytes: u64,
    object_bytes: u64,
    maximum: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let length = manifest_bytes
        .checked_add(object_bytes)
        .ok_or_else(|| invalid_root("production checkpoint byte count overflow"))?;
    if length == 0 || length > maximum {
        return Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "production-closure",
            length,
            maximum,
        });
    }
    Ok(())
}

pub(super) fn validate_production_index_geometry(
    object_count: u64,
    index_count: u32,
) -> Result<(), ExactCheckpointStoreError> {
    let page = u64::try_from(PRODUCTION_INDEX_PAGE_OBJECTS)
        .map_err(|_| invalid_root("production index page size is not representable"))?;
    let expected = if object_count == 0 {
        0
    } else {
        object_count
            .checked_add(page - 1)
            .ok_or_else(|| invalid_root("production index count overflow"))?
            / page
    };
    if expected != u64::from(index_count) {
        return Err(invalid_root(
            "production index page geometry is not canonical",
        ));
    }
    Ok(())
}

pub(super) fn validate_production_object_inventory_bound(
    manifest_bytes: u64,
    object_count: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let minimum_manifest_bytes = object_count
        .checked_mul(PRODUCTION_OBJECT_IDENTITY_BYTES)
        .ok_or_else(|| invalid_root("production object inventory byte count overflow"))?;
    if minimum_manifest_bytes > manifest_bytes {
        return Err(invalid_root(
            "production object count exceeds the manifest-derived bound",
        ));
    }
    Ok(())
}

pub(super) fn index_role(index: usize) -> Result<String, ExactCheckpointStoreError> {
    let index = u32::try_from(index)
        .map_err(|_| invalid_root("production index ordinal is not representable"))?;
    Ok(format!("{PRODUCTION_INDEX_ROLE_PREFIX}{index:08x}"))
}

pub(super) fn object_role(identity: ContentHash) -> String {
    format!("{PRODUCTION_OBJECT_ROLE_PREFIX}{}", identity.to_hex())
}

pub(super) fn portable_object_handle(
    source: Arc<dyn ProductionExactCheckpointPublicationSource>,
    object: ProductionExactCheckpointObject,
    cancellation: Option<ExecutionCancellation>,
) -> BlobHandle {
    BlobHandle::new(Arc::new(PortableObjectBlobSource {
        source,
        object,
        cancellation,
    }))
}

pub(super) fn production_object_content_id(
    source: &BlobHandle,
) -> Result<ContentId, ExactCheckpointStoreError> {
    match ContentId::for_source(
        ObjectKind::DeviceState,
        PRODUCTION_OBJECT_SCHEMA_VERSION,
        source,
    ) {
        Ok(identity) => Ok(identity),
        Err(StoreError::StreamIo { source, .. }) if is_checkpoint_cancellation_io(&source) => {
            Err(ExactCheckpointStoreError::Canceled)
        }
        Err(StoreError::StreamIo { source, .. }) if source.kind() == io::ErrorKind::InvalidData => {
            Err(invalid_root(
                "production object failed native identity authentication",
            ))
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn production_object_put_error(error: StoreError) -> ExactCheckpointStoreError {
    match error {
        StoreError::StreamIo { source, .. } if is_checkpoint_cancellation_io(&source) => {
            ExactCheckpointStoreError::Canceled
        }
        StoreError::StreamIo { source, .. } if source.kind() == io::ErrorKind::InvalidData => {
            invalid_root("production object changed after preparation")
        }
        error => error.into(),
    }
}

pub(super) struct PortableObjectBlobSource {
    source: Arc<dyn ProductionExactCheckpointPublicationSource>,
    object: ProductionExactCheckpointObject,
    cancellation: Option<ExecutionCancellation>,
}

impl BlobSource for PortableObjectBlobSource {
    fn logical_length(&self) -> u64 {
        self.object.length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        check_cancellation_store(self.cancellation.as_ref())?;
        let source = self
            .source
            .open_object(self.object.identity())
            .map_err(|error| StoreError::StreamIo {
                operation: "open-production-checkpoint-object",
                source: io::Error::other(error.to_string()),
            })?;
        Ok(Box::new(NativeIdentityReader {
            source,
            expected: self.object.identity(),
            length: self.object.length(),
            observed: 0,
            hasher: blake3::Hasher::new(),
            finished: false,
            cancellation: self.cancellation.clone(),
        }))
    }
}

pub(super) struct NativeIdentityReader {
    source: Box<dyn Read + Send>,
    expected: ContentHash,
    length: u64,
    observed: u64,
    hasher: blake3::Hasher,
    finished: bool,
    cancellation: Option<ExecutionCancellation>,
}

impl Read for NativeIdentityReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.finished {
            return Ok(0);
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        let limit = buffer.len().min(CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES);
        let count = self.source.read(&mut buffer[..limit])?;
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        if count == 0 {
            self.finished = true;
            let observed = ContentHash {
                bytes: *self.hasher.finalize().as_bytes(),
            };
            if self.observed != self.length || observed != self.expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "production checkpoint object failed native identity authentication",
                ));
            }
            return Ok(0);
        }
        self.observed = self
            .observed
            .checked_add(u64::try_from(count).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "object length is not representable",
                )
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object length overflow"))?;
        if self.observed > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "production checkpoint object exceeded its declared length",
            ));
        }
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

pub(super) fn check_cancellation(
    cancellation: Option<&ExecutionCancellation>,
) -> Result<(), ExactCheckpointStoreError> {
    if cancellation.is_some_and(ExecutionCancellation::is_canceled) {
        return Err(ExactCheckpointStoreError::Canceled);
    }
    Ok(())
}

pub(super) fn check_cancellation_store(
    cancellation: Option<&ExecutionCancellation>,
) -> Result<(), StoreError> {
    if cancellation.is_some_and(ExecutionCancellation::is_canceled) {
        return Err(StoreError::StreamIo {
            operation: "open-canceled-production-checkpoint-object",
            source: checkpoint_cancellation_io(),
        });
    }
    Ok(())
}

pub(super) fn map_production_lifecycle_error(
    error: LifecycleApiError,
) -> ExactCheckpointStoreError {
    match error {
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            ..
        } => ExactCheckpointStoreError::Canceled,
        error => ExactCheckpointStoreError::Production(error),
    }
}

pub(super) fn lifecycle_store_error(error: StoreError) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: format!("read production checkpoint CAS object: {error}"),
    }
}

pub(super) fn production_lifecycle_error(error: StoreError) -> LifecycleApiError {
    match map_checkpoint_store_error(error) {
        ExactCheckpointStoreError::Canceled => LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            message: String::from("production checkpoint installation canceled"),
        },
        error => LifecycleApiError::LoopFactory {
            message: format!("read production checkpoint CAS object: {error}"),
        },
    }
}
