//! Bounded inert CNP/1 content transfer and explicit consuming-operation pins.
//!
//! ```text
//! blob_begin(content) -> contiguous blob_chunk(offset, bytes)* -> blob_finish
//! verified transfer -> consuming-schema verification -> operation content pin
//! ```
//!
//! This in-memory receiver reserves complete declared lengths before accepting
//! bytes. It never interprets a content reference as a path or network address.
//! Verification proves local byte possession; a trusted installed validator
//! separately authorizes access under the consuming schema. Transfer retirement
//! and operation-pin settlement are independent custody transitions.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use crucible_node_contract::{Bytes, ContentRef, Id, U64, Validate};

use crate::{ProviderError, envelope::RequestOrigin};

/// Selects finite storage, metadata, and chunk allowances for one receiver.
#[derive(Clone, Copy, Debug)]
pub struct BlobLimits {
    /// Bounds reserved complete content bytes, including quarantined pins.
    pub reserved_bytes: usize,
    /// Bounds one complete content object before any allocation.
    pub content_bytes: usize,
    /// Bounds decoded bytes in one admitted chunk.
    pub chunk_bytes: usize,
    /// Bounds active transfer records independently for each sender origin.
    pub transfers_per_origin: usize,
    /// Bounds retained retired identities independently for each origin.
    pub tombstones_per_origin: usize,
    /// Bounds remembered chunk boundaries per transfer, including exact retries.
    pub chunks_per_transfer: usize,
    /// Bounds operation-pin records over the receiver's entire lifetime.
    pub operation_pins: usize,
}

/// Identifies one transfer in an authenticated origin and surviving incarnation.
///
/// Dispatchers derive this scope from the admitted connection, never from an
/// untrusted body field. This portable identity itself grants no authority.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TransferKey {
    /// Identifies the authenticated sender direction.
    pub origin: RequestOrigin,
    /// Identifies the admitted simulation session.
    pub session: Id,
    /// Identifies the surviving provider incarnation.
    pub incarnation: Id,
    /// Identifies the sender's original transfer.
    pub transfer: Id,
}

/// Reports retained transfer progress without making content semantically usable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobProgress {
    /// Echoes the original sender-generated transfer identity.
    pub transfer_id: Id,
    /// Gives the next required contiguous decoded-byte offset.
    pub next_offset: U64,
    /// Gives the admitted maximum decoded bytes in one chunk.
    pub maximum_chunk_bytes: U64,
}

/// Validates content through a trusted installed consuming-schema implementation.
///
/// Implementations must validate the exact schema identity, its available bound
/// definition, and the complete supplied bytes. They may not resolve arbitrary
/// network references or substitute successful digest verification for schema
/// validation. Providers cannot select a permissive validator for their claims.
pub trait BlobSchemaVerifier {
    /// Validates exact verified bytes before an operation receives access.
    ///
    /// # Errors
    /// Rejects unsupported, unavailable, malformed, or out-of-scope schemas and
    /// bytes that violate the selected consuming contract.
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError>;
}

/// Identifies the custody transition an installed verifier must authenticate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobCustody {
    /// Moves transfer custody into this original consuming operation.
    Operation(Id),
    /// Establishes recoverable possession in an admitted durable store.
    DurableStore,
    /// Discharges this original operation's content-pin obligation.
    OperationSettled(Id),
}

/// Authenticates content custody under host-installed storage and owner policy.
pub trait BlobCustodyVerifier {
    /// Verifies the exact original transfer, content, owner, and custody receipt.
    ///
    /// # Errors
    /// Rejects foreign, missing, stale, uncertain, or merely syntactic receipts.
    /// Success must establish the stated custody, rather than trusting an owner
    /// ID, copied content hash, transport acknowledgment, or boolean assertion.
    fn verify_custody(
        &self,
        transfer: &TransferKey,
        content: &ContentRef,
        custody: &BlobCustody,
        receipt: &ContentRef,
    ) -> Result<(), ProviderError>;
}

/// Selects an explicit transfer-pin retirement, independently of operation pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobRetirement {
    /// Abandons content that has never been exposed to a consuming operation.
    AbandonInert,
    /// Transfers custody into an existing original operation pin.
    Operation {
        /// Names the original consuming operation.
        owner: Id,
        /// Binds the authenticated transfer-of-custody evidence.
        receipt: ContentRef,
    },
    /// Establishes verified recoverable custody in an admitted durable store.
    DurableStore {
        /// Binds the authenticated durable publication evidence.
        receipt: ContentRef,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinState {
    Held,
    Quarantined,
    Settled,
}

struct PinRecord {
    owner: Id,
    schema: ContentRef,
    state: PinState,
    receipt: Option<ContentRef>,
}

struct TransferRecord {
    content: ContentRef,
    length: usize,
    bytes: Vec<u8>,
    chunks: BTreeMap<usize, usize>,
    verified: bool,
    quarantined: bool,
    exposed: bool,
    retirement: Option<BlobRetirement>,
    pins: BTreeMap<u64, PinRecord>,
    charged: bool,
}

impl TransferRecord {
    fn unresolved_pins(&self) -> bool {
        self.pins.values().any(|pin| pin.state != PinState::Settled)
    }
}

struct ReceiverState {
    records: BTreeMap<TransferKey, TransferRecord>,
    reserved: usize,
    next_pin: u64,
    pins_created: usize,
}

/// Receives unresolved content custody when its dispatcher disappears.
///
/// Implementations are trusted host supervisors. They must retain the supplied
/// ledger until the original operations are reaped or authenticated custody is
/// transferred. Accepting the value and immediately dropping it is not valid
/// supervision. A supervisor cannot report native qualification through this API.
pub trait BlobSupervisor {
    /// Takes ownership of unresolved transfer and operation-pin obligations.
    fn quarantine(&self, custody: BlobQuarantine);
}

/// Owns a disappeared receiver's retained ledger for supervised reconciliation.
pub struct BlobQuarantine {
    session: Id,
    incarnation: Id,
    limits: BlobLimits,
    state: Rc<RefCell<ReceiverState>>,
}

/// Identifies a retained operation pin without exposing content bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedContentPin {
    /// Identifies the original scoped transfer.
    pub transfer: TransferKey,
    /// Identifies the receiver-local original pin.
    pub pin: U64,
    /// Identifies the original consuming operation.
    pub owner: Id,
    /// Commits to the original verified content.
    pub content: ContentRef,
    /// Commits to the originally validated consuming schema.
    pub schema: ContentRef,
}

impl BlobQuarantine {
    /// Enumerates original unresolved pins under retained immutable identities.
    ///
    /// # Errors
    /// Refuses a conflicting receiver borrow without discarding custody.
    pub fn unresolved_pins(&self) -> Result<Vec<QuarantinedContentPin>, ProviderError> {
        let state = self
            .state
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        Ok(state
            .records
            .iter()
            .flat_map(|(key, record)| {
                record
                    .pins
                    .iter()
                    .filter(|(_, pin)| pin.state != PinState::Settled)
                    .map(|(id, pin)| QuarantinedContentPin {
                        transfer: key.clone(),
                        pin: U64::new(*id),
                        owner: pin.owner.clone(),
                        content: record.content.clone(),
                        schema: pin.schema.clone(),
                    })
            })
            .collect())
    }

    /// Rebinds the same retained ledger to an installed supervisor for reconciliation.
    ///
    /// This preserves original transfer and pin identities. It does not retry
    /// native operations or grant access to quarantined consuming pins.
    pub fn recover(self, supervisor: Rc<dyn BlobSupervisor>) -> BlobReceiver {
        BlobReceiver {
            session: self.session,
            incarnation: self.incarnation,
            limits: self.limits,
            state: self.state,
            supervisor,
        }
    }
}

/// Proves verified local transfer possession without exposing its bytes.
///
/// Only the receiving ledger can create this value. It conveys neither schema
/// approval nor durable storage or native state qualification.
#[derive(Clone)]
pub struct VerifiedTransfer {
    receiver: Rc<RefCell<ReceiverState>>,
    key: TransferKey,
    content: ContentRef,
}

impl VerifiedTransfer {
    /// Returns the exact locally verified content commitment.
    pub fn content(&self) -> &ContentRef {
        &self.content
    }

    /// Returns the original transfer scope.
    pub fn transfer(&self) -> &TransferKey {
        &self.key
    }
}

/// Retains schema-validated bytes for one original consuming operation.
///
/// Dropping a pin does not settle custody: its ledger entry becomes quarantined
/// and its content reservation remains charged. Explicit settlement requires a
/// trusted custody receipt. Pins cannot be cloned into independent obligations.
#[must_use = "content pins require explicit custody settlement"]
pub struct OperationContentPin {
    receiver: Rc<RefCell<ReceiverState>>,
    key: TransferKey,
    pin: u64,
    owner: Id,
    schema: ContentRef,
    settled: bool,
}

impl OperationContentPin {
    /// Returns the original consuming-operation identity.
    pub fn owner(&self) -> &Id {
        &self.owner
    }

    /// Returns the exact schema admitted before byte access.
    pub fn schema(&self) -> &ContentRef {
        &self.schema
    }

    /// Provides a bounded borrow of schema-validated content under retained custody.
    ///
    /// The callback cannot borrow the receiver again while accessing content.
    ///
    /// # Errors
    /// Refuses settled, quarantined, unavailable, or conflicting ledger state.
    pub fn with_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> Result<T, ProviderError> {
        if self.settled {
            return Err(ProviderError::Correlation("content pin is settled"));
        }
        let state = self
            .receiver
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get(&self.key)
            .ok_or(ProviderError::Correlation(
                "content transfer is unavailable",
            ))?;
        let pin = record
            .pins
            .get(&self.pin)
            .ok_or(ProviderError::Correlation("content pin is unavailable"))?;
        if !record.verified
            || record.quarantined
            || pin.state != PinState::Held
            || pin.owner != self.owner
        {
            return Err(ProviderError::Correlation("content pin is not usable"));
        }
        Ok(inspect(&record.bytes))
    }
}

impl Drop for OperationContentPin {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(mut state) = self.receiver.try_borrow_mut()
            && let Some(pin) = state
                .records
                .get_mut(&self.key)
                .and_then(|record| record.pins.get_mut(&self.pin))
            && pin.state == PinState::Held
        {
            pin.state = PinState::Quarantined;
        }
        // A concurrent borrow cannot establish settlement. The retained Held
        // entry remains an unresolved obligation even if quarantine is delayed.
    }
}

/// Owns bounded inline transfers for one admitted session and incarnation.
///
/// The receiver is process-local infrastructure, not an authenticated provider
/// dispatcher or a durable content store. Its caller authenticates origins and
/// journals requests before invoking mutations. Unknown pins must remain under
/// supervised custody; dropping this receiver with unresolved operation pins
/// transfers its retained ledger to the mandatory trusted host supervisor.
pub struct BlobReceiver {
    session: Id,
    incarnation: Id,
    limits: BlobLimits,
    state: Rc<RefCell<ReceiverState>>,
    supervisor: Rc<dyn BlobSupervisor>,
}

impl BlobReceiver {
    /// Creates a finite receiver without allocating declared content objects.
    ///
    /// # Errors
    /// Rejects zero metadata/chunk limits, chunk limits beyond CNP/1's ceiling,
    /// or per-origin transfer limits beyond the baseline journal ceiling.
    pub fn new(
        session: Id,
        incarnation: Id,
        limits: BlobLimits,
        supervisor: Rc<dyn BlobSupervisor>,
    ) -> Result<Self, ProviderError> {
        if limits.chunk_bytes == 0
            || limits.chunk_bytes > 1_048_576
            || limits.transfers_per_origin == 0
            || limits.transfers_per_origin > 4096
            || limits.tombstones_per_origin == 0
            || limits.tombstones_per_origin > 4096
            || limits.chunks_per_transfer == 0
            || limits.operation_pins == 0
        {
            return Err(ProviderError::ResourceExhausted(
                "invalid content-transfer limits",
            ));
        }
        Ok(Self {
            session,
            incarnation,
            limits,
            state: Rc::new(RefCell::new(ReceiverState {
                records: BTreeMap::new(),
                reserved: 0,
                next_pin: 1,
                pins_created: 0,
            })),
            supervisor,
        })
    }

    /// Reserves an original transfer before accepting any content bytes.
    ///
    /// # Errors
    /// Rejects stale scope, conflicting/retired identities and exhausted byte or
    /// record quotas. Exact active retries recover the original next offset.
    pub fn begin(
        &mut self,
        key: TransferKey,
        content: ContentRef,
    ) -> Result<BlobProgress, ProviderError> {
        self.check_scope(&key)?;
        content.validate()?;
        let length = usize::try_from(content.length.get())
            .map_err(|_| ProviderError::ResourceExhausted("unrepresentable content length"))?;
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        if let Some(record) = state.records.get(&key) {
            if record.content != content || record.retirement.is_some() {
                return Err(ProviderError::Conflict(
                    "transfer identity cannot be reused",
                ));
            }
            if record.quarantined {
                return Err(ProviderError::Correlation("transfer is quarantined"));
            }
            return progress(&key, record.bytes.len(), self.limits.chunk_bytes);
        }
        let count = state
            .records
            .iter()
            .filter(|(existing, record)| {
                existing.origin == key.origin && record.retirement.is_none()
            })
            .count();
        let reserved = state
            .reserved
            .checked_add(length)
            .filter(|total| *total <= self.limits.reserved_bytes)
            .ok_or(ProviderError::ResourceExhausted("content byte reservation"))?;
        if length > self.limits.content_bytes || count >= self.limits.transfers_per_origin {
            return Err(ProviderError::ResourceExhausted(
                "content object or transfer-record ceiling",
            ));
        }
        // The complete allocation is allowed only after the complete quota
        // check. Reserving once avoids transient old/new buffers during growth.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProviderError::ResourceExhausted("content allocation refused"))?;
        state.records.insert(
            key.clone(),
            TransferRecord {
                content,
                length,
                bytes,
                chunks: BTreeMap::new(),
                verified: false,
                quarantined: false,
                exposed: false,
                retirement: None,
                pins: BTreeMap::new(),
                charged: true,
            },
        );
        state.reserved = reserved;
        progress(&key, 0, self.limits.chunk_bytes)
    }

    /// Accepts a contiguous chunk or the exact bytes of an original chunk retry.
    ///
    /// # Errors
    /// Rejects gaps, overlaps, changed retries, empty/excessive chunks, stale
    /// scope, retired/quarantined records, length overruns and metadata limits.
    /// All validation precedes mutation; the complete buffer is already reserved.
    pub fn chunk(
        &mut self,
        key: &TransferKey,
        offset: U64,
        bytes: &Bytes,
    ) -> Result<BlobProgress, ProviderError> {
        self.check_scope(key)?;
        let offset = usize::try_from(offset.get())
            .map_err(|_| ProviderError::Conflict("unrepresentable chunk offset"))?;
        let bytes = bytes.as_slice();
        if bytes.is_empty() || bytes.len() > self.limits.chunk_bytes {
            return Err(ProviderError::ResourceExhausted(
                "chunk length outside allowance",
            ));
        }
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get_mut(key)
            .ok_or(ProviderError::Correlation("unknown content transfer"))?;
        if record.retirement.is_some() || record.quarantined {
            return Err(ProviderError::Correlation(
                "content transfer is unavailable",
            ));
        }
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= record.length)
            .ok_or(ProviderError::Conflict("chunk exceeds declared content"))?;
        if offset < record.bytes.len() {
            if record.chunks.get(&offset) != Some(&bytes.len())
                || record.bytes.get(offset..end) != Some(bytes)
            {
                return Err(ProviderError::Conflict("chunk retry differs from original"));
            }
            return progress(key, record.bytes.len(), self.limits.chunk_bytes);
        }
        if offset != record.bytes.len() || record.verified {
            return Err(ProviderError::Conflict(
                "chunk is not next contiguous write",
            ));
        }
        if record.chunks.len() >= self.limits.chunks_per_transfer {
            return Err(ProviderError::ResourceExhausted("chunk metadata ceiling"));
        }
        record.bytes.extend_from_slice(bytes);
        record.chunks.insert(offset, bytes.len());
        progress(key, record.bytes.len(), self.limits.chunk_bytes)
    }

    /// Verifies complete length and raw-octet identity without granting byte access.
    ///
    /// # Errors
    /// Rejects stale, unknown, retired, truncated, corrupt or quarantined content.
    /// A failed finish retains inert quarantined storage until explicit abandon.
    pub fn finish(&mut self, key: &TransferKey) -> Result<VerifiedTransfer, ProviderError> {
        self.check_scope(key)?;
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get_mut(key)
            .ok_or(ProviderError::Correlation("unknown content transfer"))?;
        if record.retirement.is_some() || record.quarantined {
            return Err(ProviderError::Correlation(
                "content transfer is unavailable",
            ));
        }
        if let Err(error) = record.content.verify(&record.bytes) {
            record.quarantined = true;
            return Err(error.into());
        }
        record.verified = true;
        Ok(VerifiedTransfer {
            receiver: Rc::clone(&self.state),
            key: key.clone(),
            content: record.content.clone(),
        })
    }

    /// Grants one operation pin after trusted consuming-schema verification.
    ///
    /// # Errors
    /// Rejects foreign possession tokens, unsupported schemas, retired or corrupt
    /// records and exhausted pin metadata. Failed validation creates no byte access.
    pub fn pin_operation(
        &mut self,
        verified: &VerifiedTransfer,
        owner: Id,
        schema: ContentRef,
        validator: &dyn BlobSchemaVerifier,
    ) -> Result<OperationContentPin, ProviderError> {
        if !Rc::ptr_eq(&self.state, &verified.receiver) {
            return Err(ProviderError::Correlation("foreign verified transfer"));
        }
        schema.validate()?;
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        if state.pins_created >= self.limits.operation_pins {
            return Err(ProviderError::ResourceExhausted(
                "operation pin metadata ceiling",
            ));
        }
        let pin = state.next_pin;
        let next = pin.checked_add(1).ok_or(ProviderError::ResourceExhausted(
            "operation pin identity exhausted",
        ))?;
        let record = state
            .records
            .get_mut(&verified.key)
            .ok_or(ProviderError::Correlation("unknown verified transfer"))?;
        if !record.verified
            || record.quarantined
            || record.retirement.is_some()
            || record.content != verified.content
        {
            return Err(ProviderError::Correlation(
                "verified transfer is unavailable",
            ));
        }
        validator.verify_schema(&schema, &record.content, &record.bytes)?;
        record.pins.insert(
            pin,
            PinRecord {
                owner: owner.clone(),
                schema: schema.clone(),
                state: PinState::Held,
                receipt: None,
            },
        );
        record.exposed = true;
        state.next_pin = next;
        state.pins_created += 1;
        Ok(OperationContentPin {
            receiver: Rc::clone(&self.state),
            key: verified.key.clone(),
            pin,
            owner,
            schema,
            settled: false,
        })
    }

    /// Settles the exact original operation pin under authenticated custody.
    ///
    /// # Errors
    /// Rejects foreign pins, changed retry receipts and unverified settlement.
    /// Errors leave the original content and operation obligation retained.
    pub fn settle_pin(
        &mut self,
        pin: &mut OperationContentPin,
        receipt: &ContentRef,
        verifier: &dyn BlobCustodyVerifier,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.state, &pin.receiver) {
            return Err(ProviderError::Correlation("foreign content pin"));
        }
        receipt.validate()?;
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get_mut(&pin.key)
            .ok_or(ProviderError::Correlation(
                "content pin transfer unavailable",
            ))?;
        let retained = record
            .pins
            .get(&pin.pin)
            .ok_or(ProviderError::Correlation("content pin unavailable"))?;
        if retained.owner != pin.owner {
            return Err(ProviderError::Correlation("content pin owner mismatch"));
        }
        if retained.state == PinState::Settled {
            if retained.receipt.as_ref() != Some(receipt) {
                return Err(ProviderError::Conflict("settlement retry changed receipt"));
            }
            pin.settled = true;
            return Ok(());
        }
        verifier.verify_custody(
            &pin.key,
            &record.content,
            &BlobCustody::OperationSettled(pin.owner.clone()),
            receipt,
        )?;
        if let Some(retained) = record.pins.get_mut(&pin.pin) {
            retained.state = PinState::Settled;
            retained.receipt = Some(receipt.clone());
        }
        pin.settled = true;
        reclaim_if_settled(&mut state, &pin.key);
        Ok(())
    }

    /// Retires only the authenticated origin's original transfer pin.
    ///
    /// # Errors
    /// Rejects foreign origins, tombstone exhaustion, changed retries, abandonment
    /// of exposed content and unverified custody. Live operation pins survive
    /// transfer retirement and prevent storage reclamation.
    pub fn retire(
        &mut self,
        origin: RequestOrigin,
        key: &TransferKey,
        retirement: BlobRetirement,
        verifier: &dyn BlobCustodyVerifier,
    ) -> Result<(), ProviderError> {
        self.check_scope(key)?;
        if origin != key.origin {
            return Err(ProviderError::Correlation(
                "foreign transfer retirement origin",
            ));
        }
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get(key)
            .ok_or(ProviderError::Correlation("unknown content transfer"))?;
        if let Some(previous) = &record.retirement {
            return if previous == &retirement {
                Ok(())
            } else {
                Err(ProviderError::Conflict(
                    "retirement retry changed disposition",
                ))
            };
        }
        let count = state
            .records
            .iter()
            .filter(|(existing, record)| existing.origin == origin && record.retirement.is_some())
            .count();
        if count >= self.limits.tombstones_per_origin {
            return Err(ProviderError::ResourceExhausted(
                "transfer tombstone ceiling",
            ));
        }
        match &retirement {
            BlobRetirement::AbandonInert if record.exposed => {
                return Err(ProviderError::Correlation(
                    "consumed content cannot be abandoned as inert",
                ));
            }
            BlobRetirement::AbandonInert => {}
            BlobRetirement::Operation { owner, receipt } => {
                if !record.verified
                    || !record
                        .pins
                        .values()
                        .any(|pin| &pin.owner == owner && pin.state != PinState::Quarantined)
                {
                    return Err(ProviderError::Correlation(
                        "consuming operation lacks known content custody",
                    ));
                }
                receipt.validate()?;
                verifier.verify_custody(
                    key,
                    &record.content,
                    &BlobCustody::Operation(owner.clone()),
                    receipt,
                )?;
            }
            BlobRetirement::DurableStore { receipt } => {
                if !record.verified {
                    return Err(ProviderError::Correlation(
                        "unverified content has no durable transfer custody",
                    ));
                }
                receipt.validate()?;
                verifier.verify_custody(
                    key,
                    &record.content,
                    &BlobCustody::DurableStore,
                    receipt,
                )?;
            }
        }
        if let Some(record) = state.records.get_mut(key) {
            record.retirement = Some(retirement);
        }
        reclaim_if_settled(&mut state, key);
        Ok(())
    }

    /// Returns bytes reserved by transfer and unresolved operation custody.
    ///
    /// # Errors
    /// Refuses a conflicting receiver borrow without changing reservations.
    pub fn reserved_bytes(&self) -> Result<usize, ProviderError> {
        self.state
            .try_borrow()
            .map(|state| state.reserved)
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))
    }

    /// Revokes content access while retaining every original operation pin.
    ///
    /// Supervised recovery uses this after a disappeared dispatcher or holder.
    /// It establishes neither native cancellation nor settled content custody.
    ///
    /// # Errors
    /// Refuses a conflicting receiver borrow without releasing any obligation.
    pub fn contain_operation_pins(&mut self) -> Result<(), ProviderError> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        for record in state.records.values_mut() {
            for pin in record.pins.values_mut() {
                if pin.state == PinState::Held {
                    pin.state = PinState::Quarantined;
                }
            }
        }
        Ok(())
    }

    /// Recovers an original quarantined pin solely for authenticated settlement.
    ///
    /// # Errors
    /// Rejects changed scope or inventory, settled pins, and active pins whose
    /// original holder remains authoritative. Recovery never enables byte access.
    pub fn recover_quarantined_pin(
        &self,
        original: &QuarantinedContentPin,
    ) -> Result<OperationContentPin, ProviderError> {
        self.check_scope(&original.transfer)?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("content receiver is already borrowed"))?;
        let record = state
            .records
            .get(&original.transfer)
            .ok_or(ProviderError::Correlation("unknown quarantined transfer"))?;
        let pin = record
            .pins
            .get(&original.pin.get())
            .ok_or(ProviderError::Correlation("unknown quarantined pin"))?;
        if pin.state != PinState::Quarantined
            || pin.owner != original.owner
            || record.content != original.content
            || pin.schema != original.schema
        {
            return Err(ProviderError::Correlation(
                "quarantined pin inventory changed",
            ));
        }
        Ok(OperationContentPin {
            receiver: Rc::clone(&self.state),
            key: original.transfer.clone(),
            pin: original.pin.get(),
            owner: original.owner.clone(),
            schema: original.schema.clone(),
            settled: false,
        })
    }

    fn check_scope(&self, key: &TransferKey) -> Result<(), ProviderError> {
        if key.session != self.session || key.incarnation != self.incarnation {
            return Err(ProviderError::Correlation("stale content transfer scope"));
        }
        Ok(())
    }
}

impl Drop for BlobReceiver {
    fn drop(&mut self) {
        let unresolved = self
            .state
            .try_borrow()
            .map(|state| {
                state.records.values().any(|record| {
                    record.unresolved_pins() || record.verified && record.retirement.is_none()
                })
            })
            .unwrap_or(true);
        if unresolved {
            // The reference receiver cannot reap or authenticate a disappeared
            // consuming operation. Preserve its bounded ledger instead of
            // freeing unknown custody. The host retains the owned ledger and
            // explicitly reconciles the original operations, never replacements.
            self.supervisor.quarantine(BlobQuarantine {
                session: self.session.clone(),
                incarnation: self.incarnation.clone(),
                limits: self.limits,
                state: Rc::clone(&self.state),
            });
        }
    }
}

fn reclaim_if_settled(state: &mut ReceiverState, key: &TransferKey) {
    if let Some(record) = state.records.get_mut(key)
        && record.retirement.is_some()
        && !record.unresolved_pins()
        && record.charged
    {
        state.reserved -= record.length;
        record.charged = false;
        record.bytes = Vec::new();
        record.chunks.clear();
    }
}

fn progress(key: &TransferKey, offset: usize, chunk: usize) -> Result<BlobProgress, ProviderError> {
    Ok(BlobProgress {
        transfer_id: key.transfer.clone(),
        next_offset: U64::new(
            u64::try_from(offset)
                .map_err(|_| ProviderError::ResourceExhausted("content offset unrepresentable"))?,
        ),
        maximum_chunk_bytes: U64::new(
            u64::try_from(chunk)
                .map_err(|_| ProviderError::ResourceExhausted("chunk limit unrepresentable"))?,
        ),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crucible_node_contract::canonical;

    use super::*;

    #[derive(Default)]
    struct Supervisor {
        retained: RefCell<Vec<BlobQuarantine>>,
    }

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, custody: BlobQuarantine) {
            self.retained.borrow_mut().push(custody);
        }
    }

    struct Verifier {
        accepted: bool,
    }

    impl BlobSchemaVerifier for Verifier {
        fn verify_schema(
            &self,
            _schema: &ContentRef,
            content: &ContentRef,
            bytes: &[u8],
        ) -> Result<(), ProviderError> {
            if !self.accepted {
                return Err(ProviderError::Correlation("test schema refused"));
            }
            content.verify(bytes)?;
            Ok(())
        }
    }

    impl BlobCustodyVerifier for Verifier {
        fn verify_custody(
            &self,
            _transfer: &TransferKey,
            _content: &ContentRef,
            _custody: &BlobCustody,
            _receipt: &ContentRef,
        ) -> Result<(), ProviderError> {
            if !self.accepted {
                return Err(ProviderError::Correlation("test custody refused"));
            }
            Ok(())
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn key(origin: RequestOrigin, transfer: &str) -> TransferKey {
        TransferKey {
            origin,
            session: id("session"),
            incarnation: id("incarnation"),
            transfer: id(transfer),
        }
    }

    fn reference(bytes: &[u8]) -> ContentRef {
        canonical::content_ref(bytes, "application/octet-stream").unwrap()
    }

    fn setup() -> (BlobReceiver, Rc<Supervisor>) {
        let supervisor = Rc::new(Supervisor::default());
        let limits = BlobLimits {
            reserved_bytes: 8,
            content_bytes: 8,
            chunk_bytes: 4,
            transfers_per_origin: 2,
            tombstones_per_origin: 2,
            chunks_per_transfer: 4,
            operation_pins: 4,
        };
        let receiver =
            BlobReceiver::new(id("session"), id("incarnation"), limits, supervisor.clone())
                .unwrap();
        (receiver, supervisor)
    }

    fn transfer(
        receiver: &mut BlobReceiver,
        key: &TransferKey,
        payload: &[u8],
    ) -> VerifiedTransfer {
        receiver.begin(key.clone(), reference(payload)).unwrap();
        for (index, chunk) in payload.chunks(4).enumerate() {
            receiver
                .chunk(
                    key,
                    U64::new((index * 4) as u64),
                    &Bytes::new(chunk.to_vec()),
                )
                .unwrap();
        }
        receiver.finish(key).unwrap()
    }

    #[test]
    fn contiguous_writes_and_exact_retries_preserve_original_bytes() {
        let (mut receiver, _) = setup();
        let key = key(RequestOrigin::Controller, "transfer");
        receiver.begin(key.clone(), reference(b"abcdef")).unwrap();
        receiver
            .chunk(&key, U64::new(0), &Bytes::new(b"abc".to_vec()))
            .unwrap();

        for (offset, bytes) in [(0, b"ab".as_slice()), (0, b"abd"), (1, b"bc"), (4, b"de")] {
            assert!(
                receiver
                    .chunk(&key, U64::new(offset), &Bytes::new(bytes.to_vec()))
                    .is_err()
            );
        }
        assert_eq!(
            receiver
                .begin(key.clone(), reference(b"abcdef"))
                .unwrap()
                .next_offset
                .get(),
            3
        );
        assert_eq!(
            receiver
                .chunk(&key, U64::new(0), &Bytes::new(b"abc".to_vec()))
                .unwrap()
                .next_offset
                .get(),
            3
        );
        receiver
            .chunk(&key, U64::new(3), &Bytes::new(b"def".to_vec()))
            .unwrap();
        let verified = receiver.finish(&key).unwrap();
        assert_eq!(receiver.finish(&key).unwrap().content(), verified.content());
        assert!(
            receiver
                .chunk(&key, U64::new(6), &Bytes::new(b"x".to_vec()))
                .is_err()
        );

        let pin = receiver
            .pin_operation(
                &verified,
                id("operation"),
                reference(b"schema"),
                &Verifier { accepted: true },
            )
            .unwrap();
        assert_eq!(pin.with_bytes(|bytes| bytes.to_vec()).unwrap(), b"abcdef");
    }

    #[test]
    fn corrupt_and_truncated_finish_remain_inert_until_explicit_abandon() {
        for payload in [b"bad".as_slice(), b"a"] {
            let (mut receiver, _) = setup();
            let key = key(RequestOrigin::Controller, "transfer");
            receiver.begin(key.clone(), reference(b"abc")).unwrap();
            receiver
                .chunk(&key, U64::new(0), &Bytes::new(payload.to_vec()))
                .unwrap();

            assert!(receiver.finish(&key).is_err());
            assert!(
                receiver
                    .chunk(&key, U64::new(0), &Bytes::new(b"abc".to_vec()))
                    .is_err()
            );
            assert_eq!(receiver.reserved_bytes().unwrap(), 3);
            receiver
                .retire(
                    RequestOrigin::Controller,
                    &key,
                    BlobRetirement::AbandonInert,
                    &Verifier { accepted: false },
                )
                .unwrap();
            assert_eq!(receiver.reserved_bytes().unwrap(), 0);
            assert!(receiver.begin(key.clone(), reference(b"abc")).is_err());
        }
    }

    #[test]
    fn reservations_scope_and_origin_limits_refuse_before_writes() {
        let (mut receiver, _) = setup();
        let controller = key(RequestOrigin::Controller, "same-id");
        let provider = key(RequestOrigin::Provider, "same-id");
        receiver
            .begin(controller.clone(), reference(b"abcd"))
            .unwrap();
        receiver
            .begin(provider.clone(), reference(b"abcd"))
            .unwrap();

        assert_eq!(receiver.reserved_bytes().unwrap(), 8);
        assert!(
            receiver
                .begin(key(RequestOrigin::Controller, "too-large"), reference(b"x"))
                .is_err()
        );
        assert!(
            receiver
                .chunk(&controller, U64::new(0), &Bytes::new(b"abcde".to_vec()))
                .is_err()
        );
        assert!(
            receiver
                .retire(
                    RequestOrigin::Provider,
                    &controller,
                    BlobRetirement::AbandonInert,
                    &Verifier { accepted: true }
                )
                .is_err()
        );
        let mut stale = controller.clone();
        stale.incarnation = id("foreign-incarnation");
        assert!(
            receiver
                .chunk(&stale, U64::new(0), &Bytes::new(b"abcd".to_vec()))
                .is_err()
        );
        assert!(receiver.begin(stale, reference(b"abcd")).is_err());
        assert_eq!(
            receiver
                .begin(controller, reference(b"abcd"))
                .unwrap()
                .next_offset
                .get(),
            0
        );
    }

    #[test]
    fn only_schema_validated_local_possession_creates_content_access() {
        let (mut receiver, _) = setup();
        let verified = transfer(
            &mut receiver,
            &key(RequestOrigin::Controller, "transfer"),
            b"abc",
        );
        assert!(
            receiver
                .pin_operation(
                    &verified,
                    id("operation"),
                    reference(b"schema"),
                    &Verifier { accepted: false }
                )
                .is_err()
        );

        let (mut foreign, _) = setup();
        assert!(
            foreign
                .pin_operation(
                    &verified,
                    id("operation"),
                    reference(b"schema"),
                    &Verifier { accepted: true }
                )
                .is_err()
        );
        assert!(
            receiver
                .retire(
                    RequestOrigin::Controller,
                    verified.transfer(),
                    BlobRetirement::DurableStore {
                        receipt: reference(b"receipt")
                    },
                    &Verifier { accepted: false }
                )
                .is_err()
        );
        assert_eq!(receiver.reserved_bytes().unwrap(), 3);
    }

    #[test]
    fn transfer_retirement_preserves_operation_pin_until_authentic_settlement() {
        let (mut receiver, _) = setup();
        let verified = transfer(
            &mut receiver,
            &key(RequestOrigin::Controller, "transfer"),
            b"abc",
        );
        let mut pin = receiver
            .pin_operation(
                &verified,
                id("operation"),
                reference(b"schema"),
                &Verifier { accepted: true },
            )
            .unwrap();
        let retirement = BlobRetirement::Operation {
            owner: id("operation"),
            receipt: reference(b"moved"),
        };
        assert!(
            receiver
                .retire(
                    RequestOrigin::Controller,
                    verified.transfer(),
                    BlobRetirement::AbandonInert,
                    &Verifier { accepted: true }
                )
                .is_err()
        );
        receiver
            .retire(
                RequestOrigin::Controller,
                verified.transfer(),
                retirement.clone(),
                &Verifier { accepted: true },
            )
            .unwrap();
        receiver
            .retire(
                RequestOrigin::Controller,
                verified.transfer(),
                retirement,
                &Verifier { accepted: true },
            )
            .unwrap();

        assert_eq!(receiver.reserved_bytes().unwrap(), 3);
        assert_eq!(pin.with_bytes(|bytes| bytes.to_vec()).unwrap(), b"abc");
        assert!(
            receiver
                .settle_pin(
                    &mut pin,
                    &reference(b"settled"),
                    &Verifier { accepted: false }
                )
                .is_err()
        );
        assert_eq!(receiver.reserved_bytes().unwrap(), 3);
        receiver
            .settle_pin(
                &mut pin,
                &reference(b"settled"),
                &Verifier { accepted: true },
            )
            .unwrap();
        receiver
            .settle_pin(
                &mut pin,
                &reference(b"settled"),
                &Verifier { accepted: true },
            )
            .unwrap();
        assert!(
            receiver
                .settle_pin(
                    &mut pin,
                    &reference(b"changed"),
                    &Verifier { accepted: true }
                )
                .is_err()
        );
        assert_eq!(receiver.reserved_bytes().unwrap(), 0);
        assert!(pin.with_bytes(|_| ()).is_err());
    }

    #[test]
    fn dropped_pins_and_dispatchers_transfer_owned_ledger_to_supervision() {
        let (mut receiver, supervisor) = setup();
        let verified = transfer(
            &mut receiver,
            &key(RequestOrigin::Controller, "transfer"),
            b"abc",
        );
        let pin = receiver
            .pin_operation(
                &verified,
                id("operation"),
                reference(b"schema"),
                &Verifier { accepted: true },
            )
            .unwrap();
        drop(pin);
        assert_eq!(receiver.reserved_bytes().unwrap(), 3);
        drop(receiver);

        let custody = supervisor.retained.borrow_mut().pop().unwrap();
        let original = custody.unresolved_pins().unwrap().pop().unwrap();
        let mut receiver = custody.recover(supervisor.clone());
        let mut pin = receiver.recover_quarantined_pin(&original).unwrap();
        assert!(pin.with_bytes(|_| ()).is_err());
        receiver
            .settle_pin(
                &mut pin,
                &reference(b"settled"),
                &Verifier { accepted: true },
            )
            .unwrap();
        receiver
            .retire(
                RequestOrigin::Controller,
                verified.transfer(),
                BlobRetirement::DurableStore {
                    receipt: reference(b"durable"),
                },
                &Verifier { accepted: true },
            )
            .unwrap();
        assert_eq!(receiver.reserved_bytes().unwrap(), 0);
        drop(receiver);
        assert!(supervisor.retained.borrow().is_empty());
    }

    #[test]
    fn empty_content_has_no_chunks_and_tombstones_prevent_identity_reuse() {
        let (mut receiver, _) = setup();
        let key = key(RequestOrigin::Controller, "empty");
        receiver.begin(key.clone(), reference(b"")).unwrap();
        assert!(
            receiver
                .chunk(&key, U64::new(0), &Bytes::new(Vec::new()))
                .is_err()
        );
        receiver.finish(&key).unwrap();
        receiver
            .retire(
                RequestOrigin::Controller,
                &key,
                BlobRetirement::AbandonInert,
                &Verifier { accepted: true },
            )
            .unwrap();
        receiver
            .retire(
                RequestOrigin::Controller,
                &key,
                BlobRetirement::AbandonInert,
                &Verifier { accepted: true },
            )
            .unwrap();
        assert!(receiver.begin(key.clone(), reference(b"")).is_err());
        assert!(
            receiver
                .retire(
                    RequestOrigin::Controller,
                    &key,
                    BlobRetirement::DurableStore {
                        receipt: reference(b"receipt")
                    },
                    &Verifier { accepted: true }
                )
                .is_err()
        );
    }

    #[test]
    fn finished_transfer_remains_pinned_after_dispatcher_drop() {
        let (mut receiver, supervisor) = setup();
        let verified = transfer(
            &mut receiver,
            &key(RequestOrigin::Controller, "transfer"),
            b"abc",
        );
        drop(receiver);
        assert_eq!(supervisor.retained.borrow().len(), 1);
        let custody = supervisor.retained.borrow_mut().pop().unwrap();
        let mut receiver = custody.recover(supervisor.clone());
        assert_eq!(receiver.reserved_bytes().unwrap(), 3);
        receiver
            .retire(
                RequestOrigin::Controller,
                verified.transfer(),
                BlobRetirement::AbandonInert,
                &Verifier { accepted: false },
            )
            .unwrap();
    }
}
