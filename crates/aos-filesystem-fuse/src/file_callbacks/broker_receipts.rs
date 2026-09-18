//! Sealed receipt conversion for a future descriptor-owning Linux broker.
//!
//! This module performs no descriptor or kernel I/O. Its concrete authenticated
//! adapter verifies a canonical signed broker outcome, constructs the only
//! sealed completion types, verifies their exact connection and currentness
//! bindings, and mints private callback receipts. No scalar receipt constructor
//! exists outside this module.

#![allow(
    private_bounds,
    reason = "the authenticated broker adapter is intentionally dormant until activation"
)]

use aos_filesystem_view::{
    BackingIdentity, MetadataConnection, RegistrationOperation, WorkerError,
};

use super::{BackingCloseReceipt, BackingOpenReceipt, FileCallbackError};

mod authenticated;
pub(crate) mod dormant_adapter;

pub(crate) use authenticated::{
    BrokerCompletionAdmission, CommittedBrokerReceipt, DormantBrokerCompletionVerifier,
    PendingBackingCloseReceipt, PendingBackingOpenReceipt, ProtectedBrokerCompletionAuthority,
    SIGNED_BACKING_COMPLETION_BYTES, SignedBackingCompletion,
};

impl BackingOpenReceipt {
    fn from_broker_observation(
        authority_binding: [u8; 32],
        worker_brand: u64,
        reducer_identity: [u8; 32],
        callback_request_identity: [u8; 32],
        raw_handle: u64,
        broker_execution: [u8; 32],
        operation: RegistrationOperation,
        backing_id: u64,
        backing: BackingIdentity,
        broker_generation: u64,
        broker_sequence: u64,
        publication_generation: u64,
        currentness_commitment: [u8; 32],
        descriptor_commitment: [u8; 32],
    ) -> Result<Self, FileCallbackError> {
        if authority_binding == [0; 32]
            || worker_brand == 0
            || reducer_identity == [0; 32]
            || callback_request_identity == [0; 32]
            || raw_handle == 0
            || broker_execution == [0; 32]
            || backing_id == 0
            || broker_generation == 0
            || broker_sequence == 0
            || publication_generation == 0
            || currentness_commitment == [0; 32]
            || descriptor_commitment == [0; 32]
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            authority_binding,
            worker_brand,
            reducer_identity,
            callback_request_identity,
            raw_handle,
            broker_execution,
            operation,
            backing_id,
            backing,
            broker_generation,
            broker_sequence,
            publication_generation,
            currentness_commitment,
            descriptor_commitment,
        })
    }
}

impl BackingCloseReceipt {
    fn from_broker_observation(
        authority_binding: [u8; 32],
        worker_brand: u64,
        reducer_identity: [u8; 32],
        callback_request_identity: [u8; 32],
        raw_handle: u64,
        broker_execution: [u8; 32],
        operation: RegistrationOperation,
        backing_id: u64,
        backing: BackingIdentity,
        broker_generation: u64,
        broker_sequence: u64,
        publication_generation: u64,
        currentness_commitment: [u8; 32],
        descriptor_commitment: [u8; 32],
    ) -> Result<Self, FileCallbackError> {
        if authority_binding == [0; 32]
            || worker_brand == 0
            || reducer_identity == [0; 32]
            || callback_request_identity == [0; 32]
            || raw_handle == 0
            || broker_execution == [0; 32]
            || backing_id == 0
            || broker_generation == 0
            || broker_sequence == 0
            || publication_generation == 0
            || currentness_commitment == [0; 32]
            || descriptor_commitment == [0; 32]
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            authority_binding,
            worker_brand,
            reducer_identity,
            callback_request_identity,
            raw_handle,
            broker_execution,
            operation,
            backing_id,
            backing,
            broker_generation,
            broker_sequence,
            publication_generation,
            currentness_commitment,
            descriptor_commitment,
        })
    }
}

mod sealed {
    /// Prevents portable or downstream callers from implementing completion evidence.
    pub trait Sealed {}
}

/// Projects a completed descriptor-owning broker OPEN operation.
///
/// Only this module's concrete authenticated completion implements the private
/// sealing trait. These projections retain validation data and are not
/// independently sufficient evidence.
pub(crate) trait CompletedBackingOpen: sealed::Sealed {
    /// Returns the exact prepared-connection authority binding.
    fn authority_binding(&self) -> [u8; 32];

    /// Returns the exact private worker-instance brand.
    fn worker_brand(&self) -> u64;

    /// Returns the commitment to the worker-minted callback-reducer brand.
    fn reducer_identity(&self) -> [u8; 32];

    /// Returns the unique callback request identity.
    fn callback_request_identity(&self) -> [u8; 32];

    /// Returns the exact pending worker handle.
    fn raw_handle(&self) -> u64;

    /// Returns the authenticated broker execution identity.
    fn broker_execution(&self) -> [u8; 32];

    /// Returns the broker execution generation that performed the effect.
    fn broker_generation(&self) -> u64;

    /// Returns the authenticated session sequence that completed the effect.
    fn broker_sequence(&self) -> u64;

    /// Returns the current backing-publication generation.
    fn publication_generation(&self) -> u64;

    /// Returns the commitment to the complete broker-currentness observation.
    fn currentness_commitment(&self) -> [u8; 32];

    /// Returns the exact durable registration operation.
    fn operation(&self) -> RegistrationOperation;

    /// Returns the exact verified backing used by the descriptor operation.
    fn backing(&self) -> BackingIdentity;

    /// Returns the nonzero selector created by the broker operation.
    fn backing_id(&self) -> u64;

    /// Returns the commitment to the descriptor identity owned by the completion.
    fn descriptor_commitment(&self) -> [u8; 32];
}

/// Projects a completed descriptor-owning broker CLOSE operation.
///
/// This trait is sealed for the same reason as [`CompletedBackingOpen`]. A close
/// completion must retain authenticated identity for the exact descriptor it
/// consumed even though no live descriptor is returned to portable code.
pub(crate) trait CompletedBackingClose: sealed::Sealed {
    /// Returns the exact prepared-connection authority binding.
    fn authority_binding(&self) -> [u8; 32];

    /// Returns the exact private worker-instance brand.
    fn worker_brand(&self) -> u64;

    /// Returns the commitment to the worker-minted callback-reducer brand.
    fn reducer_identity(&self) -> [u8; 32];

    /// Returns the exact active or rejected callback request authorizing close.
    fn callback_request_identity(&self) -> [u8; 32];

    /// Returns the exact pending or active worker handle.
    fn raw_handle(&self) -> u64;

    /// Returns the authenticated broker execution identity.
    fn broker_execution(&self) -> [u8; 32];

    /// Returns the broker execution generation that performed the effect.
    fn broker_generation(&self) -> u64;

    /// Returns the authenticated session sequence that completed the effect.
    fn broker_sequence(&self) -> u64;

    /// Returns the current backing-publication generation.
    fn publication_generation(&self) -> u64;

    /// Returns the commitment to the complete broker-currentness observation.
    fn currentness_commitment(&self) -> [u8; 32];

    /// Returns the exact durable registration operation.
    fn operation(&self) -> RegistrationOperation;

    /// Returns the exact verified backing whose descriptor was closed.
    fn backing(&self) -> BackingIdentity;

    /// Returns the exact nonzero selector consumed by the close.
    fn backing_id(&self) -> u64;

    /// Returns the commitment to the descriptor identity consumed by the close.
    fn descriptor_commitment(&self) -> [u8; 32];
}

/// Converts sealed broker completions into callback receipts for one generation.
pub(crate) struct DormantBackingReceiptFactory {
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    durable_revision: u64,
    durable_commitment: [u8; 32],
}

impl DormantBackingReceiptFactory {
    /// Binds receipt conversion to one worker and authenticated broker snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] for sentinel identities, or a
    /// worker integrity error when the connection is already faulted.
    fn for_connection(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_identity: [u8; 32],
        callback_request_identity: [u8; 32],
        raw_handle: u64,
        broker_execution: [u8; 32],
        broker_generation: u64,
        broker_sequence: u64,
        publication_generation: u64,
        currentness_commitment: [u8; 32],
        durable_revision: u64,
        durable_commitment: [u8; 32],
    ) -> Result<Self, FileCallbackError> {
        let authority_binding = connection.connection_binding();
        let worker_brand = connection.callback_instance_brand();
        if connection.is_faulted() {
            return Err(FileCallbackError::Worker(WorkerError::IntegrityFailure));
        }
        if authority_binding == [0; 32]
            || worker_brand == 0
            || reducer_identity == [0; 32]
            || callback_request_identity == [0; 32]
            || raw_handle == 0
            || broker_execution == [0; 32]
            || broker_generation == 0
            || broker_sequence == 0
            || publication_generation == 0
            || currentness_commitment == [0; 32]
            || durable_revision == 0
            || durable_commitment == [0; 32]
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            authority_binding,
            worker_brand,
            reducer_identity,
            callback_request_identity,
            raw_handle,
            broker_execution,
            broker_generation,
            broker_sequence,
            publication_generation,
            currentness_commitment,
            durable_revision,
            durable_commitment,
        })
    }

    /// Mints one move-only OPEN receipt from a sealed completed broker effect.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] unless every connection, operation,
    /// backing, selector, descriptor, and currentness field is exact and nonzero.
    pub(crate) fn mint_open(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        expected_operation: RegistrationOperation,
        expected_backing: BackingIdentity,
        completion: impl CompletedBackingOpen,
    ) -> Result<BackingOpenReceipt, FileCallbackError> {
        self.validate_connection(connection)?;
        if !self.matches_currentness(&completion)
            || completion.operation() != expected_operation
            || completion.backing() != expected_backing
            || completion.backing_id() == 0
            || completion.descriptor_commitment() == [0; 32]
        {
            return Err(FileCallbackError::Stale);
        }
        BackingOpenReceipt::from_broker_observation(
            self.authority_binding,
            self.worker_brand,
            self.reducer_identity,
            self.callback_request_identity,
            self.raw_handle,
            self.broker_execution,
            expected_operation,
            completion.backing_id(),
            expected_backing,
            self.broker_generation,
            self.broker_sequence,
            self.publication_generation,
            self.currentness_commitment,
            completion.descriptor_commitment(),
        )
    }

    /// Mints one move-only CLOSE receipt from a sealed completed broker effect.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] unless every connection, operation,
    /// backing, selector, descriptor, and currentness field is exact and nonzero.
    pub(crate) fn mint_close(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        expected_operation: RegistrationOperation,
        expected_backing: BackingIdentity,
        expected_backing_id: u64,
        expected_descriptor_commitment: [u8; 32],
        completion: impl CompletedBackingClose,
    ) -> Result<BackingCloseReceipt, FileCallbackError> {
        self.validate_connection(connection)?;
        if expected_backing_id == 0
            || expected_descriptor_commitment == [0; 32]
            || !self.matches_currentness(&CloseCompletion(&completion))
            || completion.operation() != expected_operation
            || completion.backing() != expected_backing
            || completion.backing_id() != expected_backing_id
            || completion.descriptor_commitment() != expected_descriptor_commitment
        {
            return Err(FileCallbackError::Stale);
        }
        BackingCloseReceipt::from_broker_observation(
            self.authority_binding,
            self.worker_brand,
            self.reducer_identity,
            self.callback_request_identity,
            self.raw_handle,
            self.broker_execution,
            expected_operation,
            expected_backing_id,
            expected_backing,
            self.broker_generation,
            self.broker_sequence,
            self.publication_generation,
            self.currentness_commitment,
            expected_descriptor_commitment,
        )
    }

    fn validate_connection(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
    ) -> Result<(), FileCallbackError> {
        if connection.is_faulted() {
            return Err(FileCallbackError::Worker(WorkerError::IntegrityFailure));
        }
        if connection.connection_binding() != self.authority_binding
            || connection.callback_instance_brand() != self.worker_brand
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(())
    }

    fn matches_currentness<T: BrokerCompletion>(&self, completion: &T) -> bool {
        completion.authority_binding() == self.authority_binding
            && completion.worker_brand() == self.worker_brand
            && completion.reducer_identity() == self.reducer_identity
            && completion.callback_request_identity() == self.callback_request_identity
            && completion.raw_handle() == self.raw_handle
            && completion.broker_execution() == self.broker_execution
            && completion.broker_generation() == self.broker_generation
            && completion.broker_sequence() == self.broker_sequence
            && completion.publication_generation() == self.publication_generation
            && completion.currentness_commitment() == self.currentness_commitment
    }
}

trait BrokerCompletion {
    fn authority_binding(&self) -> [u8; 32];
    fn worker_brand(&self) -> u64;
    fn reducer_identity(&self) -> [u8; 32];
    fn callback_request_identity(&self) -> [u8; 32];
    fn raw_handle(&self) -> u64;
    fn broker_execution(&self) -> [u8; 32];
    fn broker_generation(&self) -> u64;
    fn broker_sequence(&self) -> u64;
    fn publication_generation(&self) -> u64;
    fn currentness_commitment(&self) -> [u8; 32];
}

impl<T: CompletedBackingOpen> BrokerCompletion for T {
    fn authority_binding(&self) -> [u8; 32] {
        CompletedBackingOpen::authority_binding(self)
    }

    fn worker_brand(&self) -> u64 {
        CompletedBackingOpen::worker_brand(self)
    }

    fn reducer_identity(&self) -> [u8; 32] {
        CompletedBackingOpen::reducer_identity(self)
    }

    fn callback_request_identity(&self) -> [u8; 32] {
        CompletedBackingOpen::callback_request_identity(self)
    }

    fn raw_handle(&self) -> u64 {
        CompletedBackingOpen::raw_handle(self)
    }

    fn broker_execution(&self) -> [u8; 32] {
        CompletedBackingOpen::broker_execution(self)
    }

    fn broker_generation(&self) -> u64 {
        CompletedBackingOpen::broker_generation(self)
    }

    fn broker_sequence(&self) -> u64 {
        CompletedBackingOpen::broker_sequence(self)
    }

    fn publication_generation(&self) -> u64 {
        CompletedBackingOpen::publication_generation(self)
    }

    fn currentness_commitment(&self) -> [u8; 32] {
        CompletedBackingOpen::currentness_commitment(self)
    }
}

struct CloseCompletion<'a, T>(&'a T);

impl<T: CompletedBackingClose> BrokerCompletion for CloseCompletion<'_, T> {
    fn authority_binding(&self) -> [u8; 32] {
        self.0.authority_binding()
    }

    fn worker_brand(&self) -> u64 {
        self.0.worker_brand()
    }

    fn reducer_identity(&self) -> [u8; 32] {
        self.0.reducer_identity()
    }

    fn callback_request_identity(&self) -> [u8; 32] {
        self.0.callback_request_identity()
    }

    fn raw_handle(&self) -> u64 {
        self.0.raw_handle()
    }

    fn broker_execution(&self) -> [u8; 32] {
        self.0.broker_execution()
    }

    fn broker_generation(&self) -> u64 {
        self.0.broker_generation()
    }

    fn broker_sequence(&self) -> u64 {
        self.0.broker_sequence()
    }

    fn publication_generation(&self) -> u64 {
        self.0.publication_generation()
    }

    fn currentness_commitment(&self) -> [u8; 32] {
        self.0.currentness_commitment()
    }
}
