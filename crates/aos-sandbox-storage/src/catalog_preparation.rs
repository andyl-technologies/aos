//! Retained, non-authorizing Storage catalog preparations.
//!
//! Preparation admits an independently signed `StoragePrepareCatalog` grant,
//! resolves a catalog through protected node policy, and retains the exact
//! canonical request and resolved catalog in the Storage journal. The returned
//! receipt is authenticated replay evidence only. It cannot authorize Apply,
//! which must present a fresh, independently signed mutation grant.
//!
//! ```text
//! retained-preparation-v1 =
//!   magic || version || operation-id || sandbox-id || request-id ||
//!   preparation-digest || consumption-state || apply-request-id ||
//!   apply-transport-digest || apply-semantic-digest || apply-plan-digest ||
//!   apply-lease-digest || catalog-binding || inventory-binding ||
//!   expected-head || host-boot-id || expiry || plan-digest || lease-digest ||
//!   assignment-digest || sealed-preparation-fence || sealed-preparation-effect ||
//!   sealed-preparation-operation-fence || canonical-request || resolved-catalog || receipt
//! ```
//!
//! Version two inserts the exact catalog format and root-policy digest after
//! `assignment-digest`. A version-one record remains byte-for-byte readable,
//! but cannot yield execution authority because it predates that binding.

use aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse;
use aos_sandbox_core::{BrokerArgumentCommitment, ObjectDigest};
use aos_sandbox_protocol::semantics::storage_prepare::{
    CanonicalStoragePreparationSemanticsV1, StoragePreparationOperationV1,
};

use crate::{
    AuthorizedStorageResolutionV1, CatalogBindingV1, CatalogPlanV1, ReservationPolicy,
    ResolvedCatalogCommitmentV1, catalog::ExecutionCatalogBindingV1,
};

const RECORD_MAGIC: &[u8; 8] = b"AOSSPR01";
const LEGACY_RECORD_VERSION: u16 = 1;
const EXECUTION_RECORD_VERSION: u16 = 2;
const RECEIPT_MAGIC: &[u8; 8] = b"AOSSPRC1";
const RECEIPT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_REQUEST_BYTES: usize = 32 * 1024;
const MAXIMUM_RESOLVED_CATALOG_BYTES: usize = 64 * 1024;
const MAXIMUM_RECEIPT_BYTES: usize = 4 * 1024;
const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparationRecordFormatV1 {
    LegacyV1,
    ExecutionV2,
}

impl PreparationRecordFormatV1 {
    const fn version(self) -> u16 {
        match self {
            Self::LegacyV1 => LEGACY_RECORD_VERSION,
            Self::ExecutionV2 => EXECUTION_RECORD_VERSION,
        }
    }

    fn from_version(version: u16) -> Result<Self, StorageCatalogPreparationError> {
        match version {
            LEGACY_RECORD_VERSION => Ok(Self::LegacyV1),
            EXECUTION_RECORD_VERSION => Ok(Self::ExecutionV2),
            _ => Err(StorageCatalogPreparationError::CorruptRecord),
        }
    }
}

/// Reports fail-closed catalog preparation resolution or retention failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageCatalogPreparationError {
    /// The current protected inventory does not match the signed request.
    #[error("storage preparation inventory binding is stale")]
    InventoryMismatch,
    /// The physical catalog head changed before durable retention.
    #[error("storage preparation catalog head is stale")]
    StaleCatalogHead,
    /// The retained boot-local preparation reached its exclusive expiry.
    #[error("storage preparation expired before Apply")]
    Expired,
    /// The retained preparation belongs to a previous host boot.
    #[error("storage preparation belongs to another host boot")]
    HostBootMismatch,
    /// Protected policy could not resolve the requested operation.
    #[error("storage preparation could not be resolved by protected policy")]
    ResolutionRejected,
    /// The resolver returned a catalog that widens or changes portable intent.
    #[error("storage preparation resolver returned mismatched semantics")]
    ResolutionMismatch,
    /// The operation identifier was reused with different canonical meaning.
    #[error("storage preparation operation identity equivocated")]
    Equivocation,
    /// Retained authenticated bytes are malformed or internally inconsistent.
    #[error("retained storage preparation is corrupt")]
    CorruptRecord,
}

/// Resolves portable preparation meaning exclusively through protected policy.
///
/// Implementations are node-local authority components. They may consult
/// protected roots, policy domains, handle catalogs, GUID observations, and
/// fixed quota limits, but must never treat caller-provided names or local
/// identities as resolution inputs.
pub trait ProtectedStorageCatalogResolverV1 {
    /// Resolves one exact future catalog against the current protected head.
    ///
    /// # Errors
    ///
    /// Returns [`StorageCatalogPreparationError`] when a handle is unknown,
    /// protected policy denies the request, or current state cannot produce one
    /// closed catalog plan.
    fn resolve(
        &self,
        authorization: &AuthorizedStorageResolutionV1,
        current_head: CatalogBindingV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogPreparationError>;
}

/// Carries the safe result returned by successful preparation or exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageCatalogPreparationOutcomeV1 {
    operation_id: [u8; 16],
    catalog: CatalogBindingV1,
    expires_boottime_nanoseconds: u64,
    non_authorizing_receipt: Vec<u8>,
}

impl StorageCatalogPreparationOutcomeV1 {
    pub(crate) fn new(
        operation_id: [u8; 16],
        catalog: CatalogBindingV1,
        expires_boottime_nanoseconds: u64,
        non_authorizing_receipt: Vec<u8>,
    ) -> Result<Self, StorageCatalogPreparationError> {
        if operation_id == [0; 16]
            || expires_boottime_nanoseconds == 0
            || non_authorizing_receipt.is_empty()
            || non_authorizing_receipt.len() > MAXIMUM_RECEIPT_BYTES
        {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        Ok(Self {
            operation_id,
            catalog,
            expires_boottime_nanoseconds,
            non_authorizing_receipt,
        })
    }

    /// Returns the durable operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact resolved catalog binding required by later Apply.
    #[must_use]
    pub const fn catalog(&self) -> CatalogBindingV1 {
        self.catalog
    }

    /// Returns the exclusive current-boot preparation expiry.
    #[must_use]
    pub const fn expires_boottime_nanoseconds(&self) -> u64 {
        self.expires_boottime_nanoseconds
    }

    /// Returns authenticated replay evidence that grants no mutation authority.
    #[must_use]
    pub fn non_authorizing_receipt(&self) -> &[u8] {
        &self.non_authorizing_receipt
    }

    /// Encodes the bounded protobuf response body.
    #[must_use]
    pub fn response(&self) -> PrepareStorageCatalogResponse {
        PrepareStorageCatalogResponse {
            operation_id: self.operation_id.to_vec(),
            catalog_generation: self.catalog.generation(),
            catalog_digest: self.catalog.digest().as_bytes().to_vec(),
            preparation_expires_boottime_nanoseconds: self.expires_boottime_nanoseconds,
            non_authorizing_receipt: self.non_authorizing_receipt.clone(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedStorageCatalogPreparationV1 {
    record_format: PreparationRecordFormatV1,
    operation_id: [u8; 16],
    sandbox_id: [u8; 16],
    request_id: [u8; 16],
    preparation_digest: ObjectDigest,
    catalog: ResolvedCatalogCommitmentV1,
    inventory: CatalogBindingV1,
    expected_head: CatalogBindingV1,
    host_boot_id: [u8; 16],
    expires_boottime_nanoseconds: u64,
    plan_digest: ObjectDigest,
    lease_digest: ObjectDigest,
    assignment_digest: ObjectDigest,
    root_policy_digest: ObjectDigest,
    sealed_fence: Vec<u8>,
    sealed_effect: Vec<u8>,
    sealed_operation_fence: Vec<u8>,
    canonical_request: Vec<u8>,
    receipt: Vec<u8>,
    consumption: Option<StorageCatalogConsumptionV1>,
}

/// Cross-links a retained preparation to one atomically admitted Apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageCatalogConsumptionV1 {
    apply_request_id: [u8; 16],
    apply_transport_digest: ObjectDigest,
    apply_semantic_digest: ObjectDigest,
    apply_plan_digest: ObjectDigest,
    apply_lease_digest: ObjectDigest,
}

impl StorageCatalogConsumptionV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        apply_request_id: [u8; 16],
        apply_transport_digest: ObjectDigest,
        apply_semantic_digest: ObjectDigest,
        apply_plan_digest: ObjectDigest,
        apply_lease_digest: ObjectDigest,
    ) -> Result<Self, StorageCatalogPreparationError> {
        if apply_request_id == [0; 16]
            || [
                apply_transport_digest,
                apply_semantic_digest,
                apply_plan_digest,
                apply_lease_digest,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }

        Ok(Self {
            apply_request_id,
            apply_transport_digest,
            apply_semantic_digest,
            apply_plan_digest,
            apply_lease_digest,
        })
    }

    pub(crate) const fn apply_request_id(self) -> [u8; 16] {
        self.apply_request_id
    }

    pub(crate) const fn apply_transport_digest(self) -> ObjectDigest {
        self.apply_transport_digest
    }

    pub(crate) const fn apply_semantic_digest(self) -> ObjectDigest {
        self.apply_semantic_digest
    }

    pub(crate) const fn apply_plan_digest(self) -> ObjectDigest {
        self.apply_plan_digest
    }

    pub(crate) const fn apply_lease_digest(self) -> ObjectDigest {
        self.apply_lease_digest
    }
}

pub(crate) struct NewStorageCatalogPreparationV1 {
    pub(crate) record: RetainedStorageCatalogPreparationV1,
    pub(crate) receipt_payload: Vec<u8>,
}

/// Retains the exact authenticated Prepare admission records across Apply replacement.
pub(crate) struct StoragePreparationAuthorityRecordsV1<'a> {
    pub(crate) sealed_fence: &'a [u8],
    pub(crate) sealed_effect: &'a [u8],
    pub(crate) sealed_operation_fence: &'a [u8],
}

impl RetainedStorageCatalogPreparationV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        semantics: &CanonicalStoragePreparationSemanticsV1,
        catalog: ResolvedCatalogCommitmentV1,
        request_id: [u8; 16],
        host_boot_id: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
        plan_digest: ObjectDigest,
        lease_digest: ObjectDigest,
        authority_records: StoragePreparationAuthorityRecordsV1<'_>,
    ) -> Result<NewStorageCatalogPreparationV1, StorageCatalogPreparationError> {
        validate_resolution(semantics, &catalog)?;
        if host_boot_id == [0; 16]
            || request_id == [0; 16]
            || semantics.expires_boottime_nanoseconds() > effect_deadline_boottime_nanoseconds
            || [
                authority_records.sealed_fence,
                authority_records.sealed_effect,
                authority_records.sealed_operation_fence,
            ]
            .iter()
            .any(|record| record.is_empty() || record.len() > MAXIMUM_AUTHORITY_RECORD_BYTES)
        {
            return Err(StorageCatalogPreparationError::ResolutionMismatch);
        }
        let preparation_digest = semantics.argument_commitment().digest();
        let assignment_digest = ObjectDigest::from_bytes(*semantics.fence().assignment_digest());
        let (record_format, root_policy_digest) = match catalog.format_version() {
            2 => (
                PreparationRecordFormatV1::LegacyV1,
                ObjectDigest::from_bytes([0; 32]),
            ),
            3 => {
                let execution = catalog
                    .execution_binding()
                    .map_err(|_| StorageCatalogPreparationError::ResolutionMismatch)?;
                (
                    PreparationRecordFormatV1::ExecutionV2,
                    execution.root_policy_digest(),
                )
            }
            _ => return Err(StorageCatalogPreparationError::ResolutionMismatch),
        };
        let receipt_payload = encode_receipt_payload(
            semantics.operation_id(),
            catalog.binding(),
            semantics.expires_boottime_nanoseconds(),
            preparation_digest,
            plan_digest,
            lease_digest,
        );
        let record = Self {
            record_format,
            operation_id: semantics.operation_id(),
            sandbox_id: *semantics.fence().sandbox_id(),
            request_id,
            preparation_digest,
            catalog,
            inventory: semantics.inventory_binding(),
            expected_head: semantics.expected_catalog_head(),
            host_boot_id,
            expires_boottime_nanoseconds: semantics.expires_boottime_nanoseconds(),
            plan_digest,
            lease_digest,
            assignment_digest,
            root_policy_digest,
            sealed_fence: authority_records.sealed_fence.to_vec(),
            sealed_effect: authority_records.sealed_effect.to_vec(),
            sealed_operation_fence: authority_records.sealed_operation_fence.to_vec(),
            canonical_request: semantics.canonical_bytes().to_vec(),
            receipt: Vec::new(),
            consumption: None,
        };
        Ok(NewStorageCatalogPreparationV1 {
            record,
            receipt_payload,
        })
    }

    pub(crate) fn with_receipt(
        mut self,
        receipt: Vec<u8>,
    ) -> Result<Self, StorageCatalogPreparationError> {
        if receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        self.receipt = receipt;
        Ok(self)
    }

    pub(crate) fn encode_payload(&self) -> Result<Vec<u8>, StorageCatalogPreparationError> {
        if self.canonical_request.is_empty()
            || self.canonical_request.len() > MAXIMUM_CANONICAL_REQUEST_BYTES
            || self.catalog.canonical_bytes().is_empty()
            || self.catalog.canonical_bytes().len() > MAXIMUM_RESOLVED_CATALOG_BYTES
            || self.receipt.is_empty()
            || self.receipt.len() > MAXIMUM_RECEIPT_BYTES
            || [
                self.sealed_fence.as_slice(),
                self.sealed_effect.as_slice(),
                self.sealed_operation_fence.as_slice(),
            ]
            .iter()
            .any(|record| record.is_empty() || record.len() > MAXIMUM_AUTHORITY_RECORD_BYTES)
        {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        let format_bytes = match self.record_format {
            PreparationRecordFormatV1::LegacyV1 => 0,
            PreparationRecordFormatV1::ExecutionV2 => 34,
        };
        let mut encoder = Encoder::with_capacity(
            532 + format_bytes
                + self.sealed_fence.len()
                + self.sealed_effect.len()
                + self.sealed_operation_fence.len()
                + self.canonical_request.len()
                + self.catalog.canonical_bytes().len()
                + self.receipt.len(),
        );
        encoder.fixed(RECORD_MAGIC);
        encoder.fixed(&self.record_format.version().to_be_bytes());
        encoder.fixed(&self.operation_id);
        encoder.fixed(&self.sandbox_id);
        encoder.fixed(&self.request_id);
        encoder.fixed(self.preparation_digest.as_bytes());
        match self.consumption {
            None => {
                encoder.fixed(&[1]);
                encoder.fixed(&[0; 16]);
                for _ in 0..4 {
                    encoder.fixed(&[0; 32]);
                }
            }
            Some(consumption) => {
                encoder.fixed(&[2]);
                encoder.fixed(&consumption.apply_request_id);
                encoder.fixed(consumption.apply_transport_digest.as_bytes());
                encoder.fixed(consumption.apply_semantic_digest.as_bytes());
                encoder.fixed(consumption.apply_plan_digest.as_bytes());
                encoder.fixed(consumption.apply_lease_digest.as_bytes());
            }
        }
        encoder.binding(self.catalog.binding());
        encoder.binding(self.inventory);
        encoder.binding(self.expected_head);
        encoder.fixed(&self.host_boot_id);
        encoder.fixed(&self.expires_boottime_nanoseconds.to_be_bytes());
        encoder.fixed(self.plan_digest.as_bytes());
        encoder.fixed(self.lease_digest.as_bytes());
        encoder.fixed(self.assignment_digest.as_bytes());
        if self.record_format == PreparationRecordFormatV1::ExecutionV2 {
            encoder.fixed(&self.catalog.format_version().to_be_bytes());
            encoder.fixed(self.root_policy_digest.as_bytes());
        }
        encoder.variable(&self.sealed_fence)?;
        encoder.variable(&self.sealed_effect)?;
        encoder.variable(&self.sealed_operation_fence)?;
        encoder.variable(&self.canonical_request)?;
        encoder.variable(self.catalog.canonical_bytes())?;
        encoder.variable(&self.receipt)?;
        Ok(encoder.finish())
    }

    pub(crate) fn decode_payload(bytes: &[u8]) -> Result<Self, StorageCatalogPreparationError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.fixed::<8>()? != *RECORD_MAGIC {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        let record_format =
            PreparationRecordFormatV1::from_version(u16::from_be_bytes(decoder.fixed()?))?;
        let operation_id = decoder.nonzero::<16>()?;
        let sandbox_id = decoder.nonzero::<16>()?;
        let request_id = decoder.nonzero::<16>()?;
        let preparation_digest = ObjectDigest::from_bytes(decoder.nonzero()?);
        let consumption_state = decoder.fixed::<1>()?[0];
        let apply_request_id = decoder.fixed::<16>()?;
        let apply_transport_digest = ObjectDigest::from_bytes(decoder.fixed()?);
        let apply_semantic_digest = ObjectDigest::from_bytes(decoder.fixed()?);
        let apply_plan_digest = ObjectDigest::from_bytes(decoder.fixed()?);
        let apply_lease_digest = ObjectDigest::from_bytes(decoder.fixed()?);
        let consumption = match consumption_state {
            1 if apply_request_id == [0; 16]
                && [
                    apply_transport_digest,
                    apply_semantic_digest,
                    apply_plan_digest,
                    apply_lease_digest,
                ]
                .iter()
                .all(|digest| digest.as_bytes() == &[0; 32]) =>
            {
                None
            }
            2 => Some(StorageCatalogConsumptionV1::new(
                apply_request_id,
                apply_transport_digest,
                apply_semantic_digest,
                apply_plan_digest,
                apply_lease_digest,
            )?),
            _ => return Err(StorageCatalogPreparationError::CorruptRecord),
        };
        let catalog_binding = decoder.binding()?;
        let inventory = decoder.binding()?;
        let expected_head = decoder.binding()?;
        let host_boot_id = decoder.nonzero::<16>()?;
        let expires_boottime_nanoseconds = u64::from_be_bytes(decoder.nonzero()?);
        let plan_digest = ObjectDigest::from_bytes(decoder.nonzero()?);
        let lease_digest = ObjectDigest::from_bytes(decoder.nonzero()?);
        let assignment_digest = ObjectDigest::from_bytes(decoder.nonzero()?);
        let (catalog_format, root_policy_digest) = match record_format {
            PreparationRecordFormatV1::LegacyV1 => (2, ObjectDigest::from_bytes([0; 32])),
            PreparationRecordFormatV1::ExecutionV2 => (
                u16::from_be_bytes(decoder.fixed()?),
                ObjectDigest::from_bytes(decoder.fixed()?),
            ),
        };
        let sealed_fence = decoder.variable(MAXIMUM_AUTHORITY_RECORD_BYTES)?.to_vec();
        let sealed_effect = decoder.variable(MAXIMUM_AUTHORITY_RECORD_BYTES)?.to_vec();
        let sealed_operation_fence = decoder.variable(MAXIMUM_AUTHORITY_RECORD_BYTES)?.to_vec();
        let canonical_request = decoder.variable(MAXIMUM_CANONICAL_REQUEST_BYTES)?.to_vec();
        let catalog_bytes = decoder.variable(MAXIMUM_RESOLVED_CATALOG_BYTES)?;
        let receipt = decoder.variable(MAXIMUM_RECEIPT_BYTES)?.to_vec();
        decoder.finish()?;
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_operation_fence.is_empty()
            || canonical_request.is_empty()
            || receipt.is_empty()
        {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        let actual_preparation =
            BrokerArgumentCommitment::for_canonical_bytes(&canonical_request).digest();
        if actual_preparation != preparation_digest {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(catalog_bytes)
            .map_err(|_| StorageCatalogPreparationError::CorruptRecord)?;
        if catalog.binding() != catalog_binding {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        match record_format {
            PreparationRecordFormatV1::LegacyV1 if catalog.format_version() == catalog_format => {}
            PreparationRecordFormatV1::ExecutionV2 => {
                let execution = catalog
                    .execution_binding()
                    .map_err(|_| StorageCatalogPreparationError::CorruptRecord)?;
                if catalog.format_version() != catalog_format
                    || execution.catalog() != catalog_binding
                    || execution.root_policy_digest() != root_policy_digest
                {
                    return Err(StorageCatalogPreparationError::CorruptRecord);
                }
            }
            PreparationRecordFormatV1::LegacyV1 => {
                return Err(StorageCatalogPreparationError::CorruptRecord);
            }
        }
        Ok(Self {
            record_format,
            operation_id,
            sandbox_id,
            request_id,
            preparation_digest,
            catalog,
            inventory,
            expected_head,
            host_boot_id,
            expires_boottime_nanoseconds,
            plan_digest,
            lease_digest,
            assignment_digest,
            root_policy_digest,
            sealed_fence,
            sealed_effect,
            sealed_operation_fence,
            canonical_request,
            receipt,
            consumption,
        })
    }

    pub(crate) fn replay_matches(
        &self,
        semantics: &CanonicalStoragePreparationSemanticsV1,
        plan_digest: ObjectDigest,
        lease_digest: ObjectDigest,
        host_boot_id: [u8; 16],
        now_boottime_nanoseconds: u64,
    ) -> Result<(), StorageCatalogPreparationError> {
        if self.operation_id != semantics.operation_id()
            || self.sandbox_id != *semantics.fence().sandbox_id()
            || self.request_id != *semantics.header().request_id()
            || self.preparation_digest != semantics.argument_commitment().digest()
            || self.canonical_request != semantics.canonical_bytes()
            || self.inventory != semantics.inventory_binding()
            || self.expected_head != semantics.expected_catalog_head()
            || self.assignment_digest.as_bytes() != semantics.fence().assignment_digest()
        {
            return Err(StorageCatalogPreparationError::Equivocation);
        }
        if self.plan_digest != plan_digest
            || self.lease_digest != lease_digest
            || self.host_boot_id != host_boot_id
            || now_boottime_nanoseconds >= self.expires_boottime_nanoseconds
        {
            return Err(StorageCatalogPreparationError::ResolutionRejected);
        }
        Ok(())
    }

    pub(crate) fn outcome(
        &self,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageCatalogPreparationError> {
        StorageCatalogPreparationOutcomeV1::new(
            self.operation_id,
            self.catalog.binding(),
            self.expires_boottime_nanoseconds,
            self.receipt.clone(),
        )
    }

    pub(crate) const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    pub(crate) const fn sandbox_id(&self) -> [u8; 16] {
        self.sandbox_id
    }

    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn expected_head(&self) -> CatalogBindingV1 {
        self.expected_head
    }

    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.catalog
    }

    pub(crate) const fn preparation_digest(&self) -> ObjectDigest {
        self.preparation_digest
    }

    pub(crate) const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    pub(crate) const fn expires_boottime_nanoseconds(&self) -> u64 {
        self.expires_boottime_nanoseconds
    }

    pub(crate) const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    pub(crate) const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    pub(crate) const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    pub(crate) fn execution_binding(
        &self,
    ) -> Result<ExecutionCatalogBindingV1, StorageCatalogPreparationError> {
        if self.record_format != PreparationRecordFormatV1::ExecutionV2 {
            return Err(StorageCatalogPreparationError::ResolutionRejected);
        }
        let execution = self
            .catalog
            .execution_binding()
            .map_err(|_| StorageCatalogPreparationError::CorruptRecord)?;
        if execution.root_policy_digest() != self.root_policy_digest {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        Ok(execution)
    }

    pub(crate) fn sealed_fence(&self) -> &[u8] {
        &self.sealed_fence
    }

    pub(crate) fn sealed_effect(&self) -> &[u8] {
        &self.sealed_effect
    }

    pub(crate) fn sealed_operation_fence(&self) -> &[u8] {
        &self.sealed_operation_fence
    }

    pub(crate) fn expected_receipt_payload(&self) -> Vec<u8> {
        encode_receipt_payload(
            self.operation_id,
            self.catalog.binding(),
            self.expires_boottime_nanoseconds,
            self.preparation_digest,
            self.plan_digest,
            self.lease_digest,
        )
    }

    pub(crate) fn receipt(&self) -> &[u8] {
        &self.receipt
    }

    pub(crate) const fn consumption(&self) -> Option<StorageCatalogConsumptionV1> {
        self.consumption
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume(
        &self,
        apply_request_id: [u8; 16],
        apply_transport_digest: ObjectDigest,
        apply_semantic_digest: ObjectDigest,
        apply_plan_digest: ObjectDigest,
        apply_lease_digest: ObjectDigest,
    ) -> Result<Self, StorageCatalogPreparationError> {
        let consumption = StorageCatalogConsumptionV1::new(
            apply_request_id,
            apply_transport_digest,
            apply_semantic_digest,
            apply_plan_digest,
            apply_lease_digest,
        )?;
        if self
            .consumption
            .is_some_and(|existing| existing != consumption)
        {
            return Err(StorageCatalogPreparationError::Equivocation);
        }

        let mut consumed = self.clone();
        consumed.consumption = Some(consumption);
        Ok(consumed)
    }
}

pub(crate) fn encode_receipt_payload(
    operation_id: [u8; 16],
    catalog: CatalogBindingV1,
    expires_boottime_nanoseconds: u64,
    preparation_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    lease_digest: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(170);
    bytes.extend_from_slice(RECEIPT_MAGIC);
    bytes.extend_from_slice(&RECEIPT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&operation_id);
    bytes.extend_from_slice(&catalog.generation().to_be_bytes());
    bytes.extend_from_slice(catalog.digest().as_bytes());
    bytes.extend_from_slice(&expires_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(preparation_digest.as_bytes());
    bytes.extend_from_slice(plan_digest.as_bytes());
    bytes.extend_from_slice(lease_digest.as_bytes());
    bytes
}

pub(crate) fn validate_resolution(
    semantics: &CanonicalStoragePreparationSemanticsV1,
    catalog: &ResolvedCatalogCommitmentV1,
) -> Result<(), StorageCatalogPreparationError> {
    if catalog.generation()
        != semantics
            .expected_catalog_head()
            .generation()
            .checked_add(1)
            .ok_or(StorageCatalogPreparationError::ResolutionMismatch)?
    {
        return Err(StorageCatalogPreparationError::ResolutionMismatch);
    }
    let matches = match (semantics.operation(), catalog.plan()) {
        (
            StoragePreparationOperationV1::CreateWorkspace {
                quota_bytes,
                reservation_bytes,
            },
            CatalogPlanV1::CreateWorkspace { space, .. },
        ) => space_within_request(*space, quota_bytes, reservation_bytes),
        (
            StoragePreparationOperationV1::Snapshot { storage_handle },
            CatalogPlanV1::Snapshot { source, .. },
        ) => source.storage_handle() == storage_handle,
        (
            StoragePreparationOperationV1::HoldSnapshot {
                storage_handle,
                version_handle,
                hold_id,
            },
            CatalogPlanV1::HoldSnapshot {
                snapshot,
                hold_id: resolved_hold,
            },
        ) => {
            snapshot.dataset().storage_handle() == storage_handle
                && snapshot.version_handle() == version_handle
                && resolved_hold.as_bytes() == hold_id
        }
        (
            StoragePreparationOperationV1::ReleaseHold {
                storage_handle,
                version_handle,
                hold_id,
            },
            CatalogPlanV1::ReleaseHold {
                snapshot,
                hold_id: resolved_hold,
            },
        ) => {
            snapshot.dataset().storage_handle() == storage_handle
                && snapshot.version_handle() == version_handle
                && resolved_hold.as_bytes() == hold_id
        }
        (
            StoragePreparationOperationV1::Clone {
                storage_handle,
                version_handle,
                hold_id,
                quota_bytes,
                reservation_bytes,
            },
            CatalogPlanV1::Clone {
                source,
                origin_hold,
                space,
                ..
            },
        ) => {
            source.dataset().storage_handle() == storage_handle
                && source.version_handle() == version_handle
                && origin_hold.hold_id().as_bytes() == hold_id
                && origin_hold.snapshot_guid() == source.guid()
                && space_within_request(*space, quota_bytes, reservation_bytes)
        }
        (
            StoragePreparationOperationV1::SetQuota {
                storage_handle,
                quota_bytes,
                reservation_bytes,
            },
            CatalogPlanV1::SetQuota { dataset, space, .. },
        ) => {
            dataset.storage_handle() == storage_handle
                && space_within_request(*space, quota_bytes, reservation_bytes)
        }
        (
            StoragePreparationOperationV1::Destroy {
                storage_handle,
                version_handle: None,
            },
            CatalogPlanV1::DestroyDataset { dataset },
        ) => dataset.storage_handle() == storage_handle,
        (
            StoragePreparationOperationV1::Destroy {
                storage_handle,
                version_handle: Some(version_handle),
            },
            CatalogPlanV1::DestroySnapshot { snapshot },
        ) => {
            snapshot.dataset().storage_handle() == storage_handle
                && snapshot.version_handle() == version_handle
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StorageCatalogPreparationError::ResolutionMismatch)
    }
}

fn space_within_request(
    space: crate::WorkspaceSpacePolicyV1,
    requested_quota_bytes: u64,
    requested_reservation_bytes: u64,
) -> bool {
    let reservation = match space.reservation() {
        ReservationPolicy::None => 0,
        ReservationPolicy::Exact(bytes) => bytes,
    };
    space.refquota_bytes() <= requested_quota_bytes
        && reservation <= requested_reservation_bytes
        && (requested_reservation_bytes != 0 || reservation == 0)
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn binding(&mut self, binding: CatalogBindingV1) {
        self.fixed(&binding.generation().to_be_bytes());
        self.fixed(binding.digest().as_bytes());
    }

    fn variable(&mut self, value: &[u8]) -> Result<(), StorageCatalogPreparationError> {
        let length = u32::try_from(value.len())
            .map_err(|_| StorageCatalogPreparationError::CorruptRecord)?;
        self.fixed(&length.to_be_bytes());
        self.fixed(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], StorageCatalogPreparationError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageCatalogPreparationError::CorruptRecord)
    }

    fn nonzero<const N: usize>(&mut self) -> Result<[u8; N], StorageCatalogPreparationError> {
        let value = self.fixed()?;
        if value == [0; N] {
            Err(StorageCatalogPreparationError::CorruptRecord)
        } else {
            Ok(value)
        }
    }

    fn binding(&mut self) -> Result<CatalogBindingV1, StorageCatalogPreparationError> {
        let generation = u64::from_be_bytes(self.nonzero()?);
        let digest = ObjectDigest::from_bytes(self.nonzero()?);
        CatalogBindingV1::from_publisher(generation, digest)
            .map_err(|_| StorageCatalogPreparationError::CorruptRecord)
    }

    fn variable(&mut self, maximum: usize) -> Result<&'a [u8], StorageCatalogPreparationError> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        if length > maximum {
            return Err(StorageCatalogPreparationError::CorruptRecord);
        }
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageCatalogPreparationError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(StorageCatalogPreparationError::CorruptRecord)?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), StorageCatalogPreparationError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(StorageCatalogPreparationError::CorruptRecord)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::root_policy::WorkspaceRootPolicyV1;
    use crate::{
        ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1, ResolvedDataset,
        StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn domains() -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([11; 32]),
            ObjectDigest::from_bytes([12; 32]),
            ObjectDigest::from_bytes([13; 32]),
            ObjectDigest::from_bytes([14; 32]),
        )
        .unwrap()
    }

    fn catalog(execution: bool) -> ResolvedCatalogCommitmentV1 {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 15).unwrap();
        let ancestor = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project",
            16,
            [17; 32],
            domains(),
        )
        .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/workspace", domains()).unwrap();
        let plan = CatalogPlanV1::CreateWorkspace {
            destination,
            space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap(),
            ancestor,
        };
        if execution {
            ResolvedCatalogCommitmentV1::new_execution_v3(
                21,
                domains(),
                plan,
                Some(WorkspaceRootPolicyV1::create_initialize()),
            )
            .unwrap()
        } else {
            ResolvedCatalogCommitmentV1::new(21, domains(), plan).unwrap()
        }
    }

    fn retained(execution: bool) -> RetainedStorageCatalogPreparationV1 {
        let canonical_request = vec![31, 32, 33];
        let catalog = catalog(execution);
        let root_policy_digest = catalog
            .execution_binding()
            .map(|binding| binding.root_policy_digest())
            .unwrap_or_else(|_| ObjectDigest::from_bytes([0; 32]));
        RetainedStorageCatalogPreparationV1 {
            record_format: if execution {
                PreparationRecordFormatV1::ExecutionV2
            } else {
                PreparationRecordFormatV1::LegacyV1
            },
            operation_id: [34; 16],
            sandbox_id: [35; 16],
            request_id: [36; 16],
            preparation_digest: BrokerArgumentCommitment::for_canonical_bytes(&canonical_request)
                .digest(),
            catalog,
            inventory: CatalogBindingV1::from_publisher(19, ObjectDigest::from_bytes([37; 32]))
                .unwrap(),
            expected_head: CatalogBindingV1::from_publisher(20, ObjectDigest::from_bytes([38; 32]))
                .unwrap(),
            host_boot_id: [39; 16],
            expires_boottime_nanoseconds: 40,
            plan_digest: ObjectDigest::from_bytes([41; 32]),
            lease_digest: ObjectDigest::from_bytes([42; 32]),
            assignment_digest: ObjectDigest::from_bytes([43; 32]),
            root_policy_digest,
            sealed_fence: vec![44],
            sealed_effect: vec![45],
            sealed_operation_fence: vec![46],
            canonical_request,
            receipt: vec![47],
            consumption: None,
        }
    }

    #[test]
    fn legacy_v1_record_replays_exact_bytes_and_digest() {
        let record = retained(false);
        let encoded = record.encode_payload().unwrap();
        let decoded = RetainedStorageCatalogPreparationV1::decode_payload(&encoded).unwrap();

        assert_eq!(decoded.encode_payload().unwrap(), encoded);
        assert_eq!(decoded.record_format, PreparationRecordFormatV1::LegacyV1);
        assert!(decoded.execution_binding().is_err());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&encoded)),
            // Independently reproduced by the original V1 encoder from
            // repository snapshot 4a33683d345191588525ea73a6574d23889988a4.
            [
                115, 120, 96, 5, 64, 213, 198, 174, 215, 151, 200, 117, 32, 23, 228, 86, 67, 20,
                196, 151, 17, 151, 245, 138, 23, 178, 145, 5, 21, 30, 145, 203,
            ]
        );
    }

    #[test]
    fn execution_v2_record_binds_exact_catalog_format_and_root_policy() {
        let record = retained(true);
        let encoded = record.encode_payload().unwrap();
        let decoded = RetainedStorageCatalogPreparationV1::decode_payload(&encoded).unwrap();
        let execution = decoded.execution_binding().unwrap();

        assert_eq!(decoded.encode_payload().unwrap(), encoded);
        assert_eq!(execution.catalog(), decoded.catalog.binding());
        assert_eq!(execution.root_policy_digest(), decoded.root_policy_digest);

        for offset in [8, 475, 476, 477] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 1;
            assert!(matches!(
                RetainedStorageCatalogPreparationV1::decode_payload(&tampered),
                Err(StorageCatalogPreparationError::CorruptRecord)
            ));
        }

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            RetainedStorageCatalogPreparationV1::decode_payload(&trailing),
            Err(StorageCatalogPreparationError::CorruptRecord)
        ));
    }
}
