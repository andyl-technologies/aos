//! Defines the stable namespace identities shared by journal and broker records.
//!
//! Namespace bytes are part of both framed journal records and authenticated
//! broker MAC inputs. This registry supplies only identity: domain owners retain
//! record validation, writer admission, transitions, and semantic authority.
//!
//! ```text
//! namespace = registered u8 identity
//! ```

/// Selects the independently materialized keyspace changed by a record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RecordNamespace {
    /// Desired resource state indexed by stable resource identity.
    DesiredState = 1,
    /// Durable operation state indexed by operation identity.
    Operation = 2,
    /// Effect intent and completion evidence indexed by effect identity.
    Effect = 3,
    /// Idempotency decisions indexed by caller-provided request key.
    Idempotency = 4,
    /// Ownership-pending controller gates indexed by operation identity.
    OwnershipGate = 5,
    /// Durable authority publications isolated from generic desired-state keys.
    AuthorityPublication = 6,
    /// Controller-resolved publisher capabilities and current authority records.
    PublisherAuthority = 7,
    /// Current publisher policy, resource bindings, and controller generation heads.
    PublisherPolicy = 8,
    /// Publisher execution and immutable challenge-registration audit records.
    PublisherIngress = 9,
    /// Runtime holder decisions, pending intents, and monotone sandbox heads.
    RuntimeAuthority = 10,
    /// Immutable observed runtime generations and exact latest-generation heads.
    RuntimeGeneration = 11,
    /// Signed namespace targets allocated to observed runtime generations.
    NamespaceTarget = 12,
    /// Exact controller Mount attempts admitted from live namespace authority.
    MountAttempt = 13,
    /// Successful Mount receipts bound to exact controller attempts.
    MountCompletion = 14,
    /// Latest authenticated complete Mount resource inventory.
    MountInventory = 15,
    /// Immutable generations of attachment desired state.
    AttachmentDesired = 16,
    /// Durable post-attach kernel verification for attachment generations.
    AttachmentVerification = 17,
    /// Immutable filesystem-view revisions and their durable source handles.
    FilesystemViewRevision = 18,
    /// Namespace-bound logical destination slots for filesystem attachments.
    AttachmentSlot = 19,
    /// Canonical portable sandbox specifications indexed by content identity.
    SandboxSpec = 20,
    /// Node-local broker materialization state for destination-slot anchors.
    MountDestinationSlot = 21,
    /// Latest authenticated complete Mount destination-slot inventory.
    DestinationSlotInventory = 22,
    /// Exact controller destination-slot effects admitted before Mount I/O.
    DestinationSlotAttempt = 23,
    /// Successful Mount destination-slot receipts bound to admitted effects.
    DestinationSlotCompletion = 24,
    /// Latest authenticated complete Storage workspace-resource inventory.
    StorageResourceInventory = 25,
    /// Latest authenticated complete Network namespace-resource inventory.
    NetworkResourceInventory = 26,
    /// Durable pending and confirmed complete Host launch catalogs.
    HostCatalogReconciliation = 27,
    /// Storage operation reservations bound to one physical catalog head.
    StorageCatalogReservation = 28,
    /// Immutable observed Storage physical-catalog transitions.
    StorageCatalogTransition = 29,
    /// Current authenticated Storage physical-catalog head.
    StorageCatalogHead = 30,
    /// Protected Storage runtime-authority configuration binding.
    StorageRuntimeConfiguration = 31,
    /// Authenticated Storage workspace publication inputs bound to operations.
    StorageWorkspacePublicationIntent = 32,
    /// Authenticated, exactly-once Storage root-pin effect attempts.
    StorageWorkspacePinAttempt = 33,
    /// Authenticated operation-keyed Storage catalog preparations.
    StorageCatalogPreparation = 34,
    /// Authenticated Storage workspace-pin repair admission intents.
    StorageWorkspacePinRepairIntent = 35,
    /// Authenticated Host Guardian execution records keyed by request identity.
    HostExecution = 36,
    /// Monotone protected Storage resolver-policy generation and digest floor.
    StorageResolverPolicyFloor = 37,
    /// Fixed node identity bound to one controller state directory.
    ControllerIdentity = 38,
    /// Broker-owned physical source realizations retained for Mount resources.
    MountSourcePin = 39,
    /// Authenticated Mount source-provider acquisition attempts and tombstones.
    MountSourceAcquisition = 40,
    /// Protected SourceProvider authority, key, route, and revocation state.
    SourceProviderAuthority = 41,
    /// Latest exact Mount source-acquisition inventory observation.
    MountSourceAcquisitionInventory = 42,
    /// Controller attachment-source custody attempts.
    AttachmentSourceAttempt = 43,
    /// Exact completion evidence for attachment-source custody attempts.
    AttachmentSourceCompletion = 44,
    /// Protected one-shot Mount-manager startup inventory and custody authority.
    MountManagerStartupAuthority = 45,
    /// Durable global space held for an admitted operation's terminal record.
    GlobalCapacityReservation = 46,
    /// Protected canonical full histories for authenticated broker sessions.
    BrokerSessionTraffic = 47,
    /// Monotone protected authorization-time observations for dormant CLI binding.
    CliAuthorizationTime = 48,
    /// Protected current heads, idempotency reservations, and operator-recovery transitions.
    OperatorRecovery = 49,
    /// Protected canonical filesystem-worker passthrough registration snapshots.
    FilesystemWorkerRegistration = 50,
    /// Immutable public-operation project and capability-selector bindings.
    PublicOperationAuthorization = 51,
    /// Controller custody of one lifecycle atomic Storage snapshot exchange.
    LifecycleAtomicSnapshotSource = 52,
    /// Holder-bound OpenSSH access issued by one authorized public operation.
    PublicAttachRoute = 53,
    /// Durable, non-admitted public attach identity awaiting Host gate readback.
    PublicAttachPending = 54,
    /// Immutable signed Storage group history retained across session rollover.
    BrokerSessionStorageGroupArchive = 55,
    /// Controller reservation for one physically verified guest-root publication.
    GuestRootPublication = 56,
    /// Exact authorized Mount Acquire packets linked to attachment-source custody.
    AttachmentSourceDispatch = 57,
    /// Durable ambiguous or completed Storage guest-root population attempts.
    StorageGuestRootPublicationAttempt = 58,
    /// Immutable original signed Storage inventory histories for status recovery.
    BrokerSessionStorageInventoryArchive = 59,
    /// Exact read-only Storage inventory abandonment and signed peer attestation.
    BrokerSessionStorageInventoryAbandonment = 60,
    /// Protected first-capability idempotency decisions and entitlement cross-links.
    PublicCapabilityBootstrap = 61,
    /// Storage-owned retained execution-output capacity and deletion tombstones.
    StorageExecutionOutput = 62,
    /// Controller-owned one-shot accepted-Create source before cross-owner grants.
    ControllerExecutionPreissue = 63,
    /// Controller-owned immutable original Host execution-output reserve attempt.
    ControllerExecutionOutputAttempt = 64,
    /// Controller-owned authenticated Host output-reservation settlement.
    ControllerExecutionOutputSettlement = 65,
    /// Controller-owned original cross-process Host argument-observation attempt.
    ControllerExecutionArgumentAttempt = 66,
    /// Controller-owned authenticated fresh Host argument observation custody.
    ControllerExecutionArgumentReceipt = 67,
    /// Non-authorizing canonical execution-spec attempt and its exact source heads.
    ControllerExecutionSpecAttempt = 68,
    /// Controller-wide frozen Create source during a closed root policy CAS.
    ControllerPolicyHold = 69,
    /// Source-domain-wide frozen ancestry during a closed root policy CAS.
    SourceDomainPolicyHold = 70,
    /// Controller reservation for one authenticated execution Observe operation.
    ControllerExecutionObserveReservation = 71,
    /// Controller-held prepare floor for an exact failed-before-commit Create.
    ControllerCreateFailurePrepare = 72,
    /// Controller-owned signed Host no-Apply request and historical stage cursor.
    ControllerNoApplySettlementCursor = 73,
    /// Controller-owned original signed Storage output-reserve attempt.
    ControllerStorageOutputReserveAttempt = 74,
    /// Non-authorizing later-read resource preparations and retained quarantine.
    ControllerConsumerReadAttempt = 75,
    /// Purpose-owned original offline paired Nix provisioning history.
    NixOfflineProvisioning = 76,
    /// The Controller's closed native shared resource account and claim ledger.
    ControllerResourceReservation = 80,
}

impl RecordNamespace {
    /// Decodes one registered namespace identity without admitting a record.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownRecordNamespace`] when the byte has no registered identity.
    pub fn from_byte(value: u8) -> Result<Self, UnknownRecordNamespace> {
        match value {
            1 => Ok(Self::DesiredState),
            2 => Ok(Self::Operation),
            3 => Ok(Self::Effect),
            4 => Ok(Self::Idempotency),
            5 => Ok(Self::OwnershipGate),
            6 => Ok(Self::AuthorityPublication),
            7 => Ok(Self::PublisherAuthority),
            8 => Ok(Self::PublisherPolicy),
            9 => Ok(Self::PublisherIngress),
            10 => Ok(Self::RuntimeAuthority),
            11 => Ok(Self::RuntimeGeneration),
            12 => Ok(Self::NamespaceTarget),
            13 => Ok(Self::MountAttempt),
            14 => Ok(Self::MountCompletion),
            15 => Ok(Self::MountInventory),
            16 => Ok(Self::AttachmentDesired),
            17 => Ok(Self::AttachmentVerification),
            18 => Ok(Self::FilesystemViewRevision),
            19 => Ok(Self::AttachmentSlot),
            20 => Ok(Self::SandboxSpec),
            21 => Ok(Self::MountDestinationSlot),
            22 => Ok(Self::DestinationSlotInventory),
            23 => Ok(Self::DestinationSlotAttempt),
            24 => Ok(Self::DestinationSlotCompletion),
            25 => Ok(Self::StorageResourceInventory),
            26 => Ok(Self::NetworkResourceInventory),
            27 => Ok(Self::HostCatalogReconciliation),
            28 => Ok(Self::StorageCatalogReservation),
            29 => Ok(Self::StorageCatalogTransition),
            30 => Ok(Self::StorageCatalogHead),
            31 => Ok(Self::StorageRuntimeConfiguration),
            32 => Ok(Self::StorageWorkspacePublicationIntent),
            33 => Ok(Self::StorageWorkspacePinAttempt),
            34 => Ok(Self::StorageCatalogPreparation),
            35 => Ok(Self::StorageWorkspacePinRepairIntent),
            36 => Ok(Self::HostExecution),
            37 => Ok(Self::StorageResolverPolicyFloor),
            38 => Ok(Self::ControllerIdentity),
            39 => Ok(Self::MountSourcePin),
            40 => Ok(Self::MountSourceAcquisition),
            41 => Ok(Self::SourceProviderAuthority),
            42 => Ok(Self::MountSourceAcquisitionInventory),
            43 => Ok(Self::AttachmentSourceAttempt),
            44 => Ok(Self::AttachmentSourceCompletion),
            45 => Ok(Self::MountManagerStartupAuthority),
            46 => Ok(Self::GlobalCapacityReservation),
            47 => Ok(Self::BrokerSessionTraffic),
            48 => Ok(Self::CliAuthorizationTime),
            49 => Ok(Self::OperatorRecovery),
            50 => Ok(Self::FilesystemWorkerRegistration),
            51 => Ok(Self::PublicOperationAuthorization),
            52 => Ok(Self::LifecycleAtomicSnapshotSource),
            53 => Ok(Self::PublicAttachRoute),
            54 => Ok(Self::PublicAttachPending),
            55 => Ok(Self::BrokerSessionStorageGroupArchive),
            56 => Ok(Self::GuestRootPublication),
            57 => Ok(Self::AttachmentSourceDispatch),
            58 => Ok(Self::StorageGuestRootPublicationAttempt),
            59 => Ok(Self::BrokerSessionStorageInventoryArchive),
            60 => Ok(Self::BrokerSessionStorageInventoryAbandonment),
            61 => Ok(Self::PublicCapabilityBootstrap),
            62 => Ok(Self::StorageExecutionOutput),
            63 => Ok(Self::ControllerExecutionPreissue),
            64 => Ok(Self::ControllerExecutionOutputAttempt),
            65 => Ok(Self::ControllerExecutionOutputSettlement),
            66 => Ok(Self::ControllerExecutionArgumentAttempt),
            67 => Ok(Self::ControllerExecutionArgumentReceipt),
            68 => Ok(Self::ControllerExecutionSpecAttempt),
            69 => Ok(Self::ControllerPolicyHold),
            70 => Ok(Self::SourceDomainPolicyHold),
            71 => Ok(Self::ControllerExecutionObserveReservation),
            72 => Ok(Self::ControllerCreateFailurePrepare),
            73 => Ok(Self::ControllerNoApplySettlementCursor),
            74 => Ok(Self::ControllerStorageOutputReserveAttempt),
            75 => Ok(Self::ControllerConsumerReadAttempt),
            76 => Ok(Self::NixOfflineProvisioning),
            80 => Ok(Self::ControllerResourceReservation),
            _ => Err(UnknownRecordNamespace),
        }
    }
}

/// Reports a byte outside the registered namespace identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown record namespace")]
pub struct UnknownRecordNamespace;
