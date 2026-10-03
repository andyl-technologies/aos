//! Canonical fixed-purpose floor claims, not privileged owner constructors.
//!
//! Broker framing remains exactly version one. Host055 framing is distinct:
//!
//! ```text
//! AOSRDF01 | version:u16be=1 | reserved:u16be=0 | ordinal:u64be |
//! scope:32 | native-next-sequence:u64be | complete-main-HEAD:32 |
//! predecessor-NV:32 | exact-main-TX-digest:32                  (156 bytes)
//! AOSRDI01 | version:u16be=1 | reserved:u16be=0 |
//! predecessor:AOSRDF01:156 | target:AOSRDF01:156             (324 bytes)
//! ```
//!
//! Host scope and complete HEAD must come from the existing genuine Core
//! comparison in the eventual closed coordinator. Shape-valid records, hash
//! equations and reducer results authenticate neither those inputs nor fresh
//! NV. No Journal, startup, process, signer or physical owner is constructed.

use aos_sandbox::JournalTransaction;

use super::digest::{hash_parts, successor_sequence, transaction_digest_v1};
use super::{FloorErrorV1, RecordPurposeDataV1};

/// Retains the original fixed Broker profile width.
pub(crate) const PROFILE_BYTES: usize = 112;
/// Fixes both purpose-specific checkpoint body widths.
pub(crate) const CHECKPOINT_BYTES: usize = 156;
/// Fixes both purpose-specific intent widths.
pub(crate) const INTENT_BYTES: usize = 12 + 2 * CHECKPOINT_BYTES;
/// Fixes the original defined SHA-256 extend public attributes.
pub(crate) const NV_ATTRIBUTES_DEFINED: u32 = 0x0004_0044;
/// Fixes the original written SHA-256 extend public attributes.
pub(crate) const NV_ATTRIBUTES_WRITTEN: u32 = NV_ATTRIBUTES_DEFINED | 0x2000_0000;

const SCOPE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.scope.v1\0";

/// Selects a fixed endpoint and a collision-checked local owner NV handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FloorEndpointV1 {
    /// Selects the original Controller endpoint's local NV index.
    ControllerStorageClient = 1,
    /// Selects the original Storage endpoint's local NV index.
    StorageBroker = 2,
}

impl FloorEndpointV1 {
    /// These are local owner assignments, not globally registered TCG handles.
    pub(crate) const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
        }
    }
}

/// Pins one already provisioned deployment, endpoint, and TPM salt key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FloorProfileV1 {
    endpoint: FloorEndpointV1,
    node: [u8; 16],
    deployment_epoch: [u8; 16],
    stable_endpoint: [u8; 32],
    salt_key_name_digest: [u8; 32],
}

impl FloorProfileV1 {
    /// Constructs shape-only provisioning claims; it installs no NV index.
    ///
    /// # Errors
    ///
    /// Rejects zero node, deployment, endpoint or salt commitments.
    pub(crate) fn new(
        endpoint: FloorEndpointV1,
        node: [u8; 16],
        deployment_epoch: [u8; 16],
        stable_endpoint: [u8; 32],
        salt_key_name_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        if node == [0; 16]
            || deployment_epoch == [0; 16]
            || stable_endpoint == [0; 32]
            || salt_key_name_digest == [0; 32]
        {
            return Err(FloorErrorV1::Encoding);
        }
        Ok(Self {
            endpoint,
            node,
            deployment_epoch,
            stable_endpoint,
            salt_key_name_digest,
        })
    }

    /// Returns the fixed Broker endpoint DATA.
    pub(crate) const fn endpoint(self) -> FloorEndpointV1 {
        self.endpoint
    }

    /// Returns the independently supplied stable endpoint claim.
    pub(crate) const fn stable_endpoint(self) -> [u8; 32] {
        self.stable_endpoint
    }

    /// Returns the provisioned node claim.
    pub(crate) const fn node(self) -> [u8; 16] {
        self.node
    }

    /// Returns the provisioned salt Name commitment.
    pub(crate) const fn salt_key_name_digest(self) -> [u8; 32] {
        self.salt_key_name_digest
    }

    /// Encodes the original fixed 112-byte Broker provisioning claim.
    pub(crate) fn encode(self) -> [u8; PROFILE_BYTES] {
        let mut bytes = [0; PROFILE_BYTES];
        header(&mut bytes, b"AOSBTP01");
        bytes[12] = self.endpoint as u8;
        bytes[16..32].copy_from_slice(&self.node);
        bytes[32..48].copy_from_slice(&self.deployment_epoch);
        bytes[48..80].copy_from_slice(&self.stable_endpoint);
        bytes[80..112].copy_from_slice(&self.salt_key_name_digest);
        bytes
    }

    /// Decodes the original fixed Broker provisioning claim.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical framing, reserved bytes, endpoint codes or sentinel fields.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        require_header(bytes, b"AOSBTP01", PROFILE_BYTES)?;
        if bytes[13..16] != [0; 3] {
            return Err(FloorErrorV1::Encoding);
        }
        let endpoint = match bytes[12] {
            1 => FloorEndpointV1::ControllerStorageClient,
            2 => FloorEndpointV1::StorageBroker,
            _ => return Err(FloorErrorV1::Encoding),
        };
        Self::new(
            endpoint,
            array(bytes, 16)?,
            array(bytes, 32)?,
            array(bytes, 48)?,
            array(bytes, 80)?,
        )
    }

    /// Computes the original Broker scope DATA without admitting a provisioned owner.
    pub(crate) fn scope(self) -> [u8; 32] {
        hash_parts(SCOPE_DOMAIN, &[&self.encode()])
    }

    /// Computes the Name of the exact written TPMS_NV_PUBLIC, without a TPM2B prefix.
    pub(crate) fn nv_name(self) -> [u8; 34] {
        let mut public = [0; 14];
        public[0..4].copy_from_slice(&self.endpoint.nv_index().to_be_bytes());
        public[4..6].copy_from_slice(&0x000b_u16.to_be_bytes());
        public[6..10].copy_from_slice(&NV_ATTRIBUTES_WRITTEN.to_be_bytes());
        // Empty authPolicy occupies two zero bytes at 10..12.
        public[12..14].copy_from_slice(&32_u16.to_be_bytes());
        let mut name = [0; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        name[2..].copy_from_slice(&hash_parts(b"", &[&public]));
        name
    }
}

/// Represents only a complete-map HEAD and native frame boundary as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FloorCutV1 {
    sequence: u64,
    head: [u8; 32],
}

impl FloorCutV1 {
    /// Constructs a shape-valid cut without authenticating its origin.
    ///
    /// # Errors
    ///
    /// Rejects zero/exhausted sequences or an empty head commitment.
    pub(crate) fn new(sequence: u64, head: [u8; 32]) -> Result<Self, FloorErrorV1> {
        if sequence == 0 || sequence == u64::MAX || head == [0; 32] {
            return Err(FloorErrorV1::Encoding);
        }
        Ok(Self { sequence, head })
    }

    /// Returns the compared next native sequence.
    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the compared complete-map commitment.
    pub(crate) const fn head(self) -> [u8; 32] {
        self.head
    }
}

/// Owns the single checked checkpoint body behind distinct purpose wrappers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CheckpointBodyV1 {
    ordinal: u64,
    scope: [u8; 32],
    cut: FloorCutV1,
    predecessor_nv: [u8; 32],
    transaction_digest: [u8; 32],
}

impl CheckpointBodyV1 {
    fn new(
        purpose: RecordPurposeDataV1,
        ordinal: u64,
        scope: [u8; 32],
        cut: FloorCutV1,
        predecessor_nv: [u8; 32],
        transaction_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        if ordinal == 0
            || ordinal == u64::MAX
            || scope == [0; 32]
            || (predecessor_nv == [0; 32]) != (ordinal == 1)
            || (transaction_digest == [0; 32]) != (ordinal == 1)
        {
            return Err(FloorErrorV1::Encoding);
        }
        if purpose == RecordPurposeDataV1::RuntimeDeploymentV1 {
            let sequence = ordinal
                .checked_sub(1)
                .and_then(|steps| steps.checked_mul(3))
                .and_then(|frames| frames.checked_add(4))
                .filter(|sequence| *sequence != u64::MAX)
                .ok_or(FloorErrorV1::Encoding)?;
            if cut.sequence != sequence {
                return Err(FloorErrorV1::Encoding);
            }
        }
        Ok(Self {
            ordinal,
            scope,
            cut,
            predecessor_nv,
            transaction_digest,
        })
    }

    /// Returns the shape-checked native cut DATA.
    pub(super) const fn cut(self) -> FloorCutV1 {
        self.cut
    }

    /// Compares the claimed scope without authenticating its source.
    ///
    /// # Errors
    ///
    /// Returns the original provisioning error for a different scope.
    pub(super) fn require_scope(self, scope: [u8; 32]) -> Result<(), FloorErrorV1> {
        if self.scope == scope {
            Ok(())
        } else {
            Err(FloorErrorV1::Provisioning)
        }
    }

    fn encode(self, purpose: RecordPurposeDataV1) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        header(&mut bytes, purpose.checkpoint_magic());
        bytes[12..20].copy_from_slice(&self.ordinal.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.scope);
        bytes[52..60].copy_from_slice(&self.cut.sequence.to_be_bytes());
        bytes[60..92].copy_from_slice(&self.cut.head);
        bytes[92..124].copy_from_slice(&self.predecessor_nv);
        bytes[124..156].copy_from_slice(&self.transaction_digest);
        bytes
    }

    fn decode(purpose: RecordPurposeDataV1, bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        require_header(bytes, purpose.checkpoint_magic(), CHECKPOINT_BYTES)?;
        Self::new(
            purpose,
            u64::from_be_bytes(array(bytes, 12)?),
            array(bytes, 20)?,
            FloorCutV1::new(u64::from_be_bytes(array(bytes, 52)?), array(bytes, 60)?)?,
            array(bytes, 92)?,
            array(bytes, 124)?,
        )
    }

    fn extend_input(self, purpose: RecordPurposeDataV1) -> [u8; 32] {
        hash_parts(purpose.extend_domain(), &[&self.encode(purpose)])
    }

    /// Computes only a closed purpose's checkpoint NV equation.
    pub(super) fn nv_value(self, purpose: RecordPurposeDataV1) -> [u8; 32] {
        hash_parts(b"", &[&self.predecessor_nv, &self.extend_input(purpose)])
    }
}

/// Owns the single predecessor, transaction and successor equation engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IntentBodyV1 {
    predecessor: CheckpointBodyV1,
    target: CheckpointBodyV1,
}

// Defers the original Broker scope hash until its original check boundary.
// Host context is only inert scope DATA, never a provisioning/currentness owner.
#[derive(Clone, Copy)]
enum RecordScopeDataV1 {
    Broker(FloorProfileV1),
    Host([u8; 32]),
}

impl RecordScopeDataV1 {
    const fn purpose(self) -> RecordPurposeDataV1 {
        match self {
            Self::Broker(_) => RecordPurposeDataV1::BrokerV1,
            Self::Host(_) => RecordPurposeDataV1::RuntimeDeploymentV1,
        }
    }

    fn scope(self) -> [u8; 32] {
        match self {
            Self::Broker(profile) => profile.scope(),
            Self::Host(scope) => scope,
        }
    }

    const fn transaction_scope(self) -> [u8; 32] {
        match self {
            Self::Broker(_) => [0; 32],
            Self::Host(scope) => scope,
        }
    }
}

impl IntentBodyV1 {
    fn new(
        context: RecordScopeDataV1,
        predecessor: CheckpointBodyV1,
        target_cut: FloorCutV1,
        transaction: &JournalTransaction,
    ) -> Result<Self, FloorErrorV1> {
        if successor_sequence(predecessor.cut.sequence, transaction)? != target_cut.sequence {
            return Err(FloorErrorV1::Successor);
        }
        let transaction_digest = transaction_digest_v1(
            context.purpose(),
            context.transaction_scope(),
            transaction,
        )?;
        Self::from_digest(
            context.purpose(),
            context.scope(),
            predecessor,
            target_cut,
            transaction_digest,
        )
    }

    fn from_digest(
        purpose: RecordPurposeDataV1,
        scope: [u8; 32],
        predecessor: CheckpointBodyV1,
        target_cut: FloorCutV1,
        transaction_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        predecessor.require_scope(scope)?;
        if target_cut.sequence <= predecessor.cut.sequence || transaction_digest == [0; 32] {
            return Err(FloorErrorV1::Successor);
        }
        let ordinal = predecessor
            .ordinal
            .checked_add(1)
            .ok_or(FloorErrorV1::Successor)?;
        let target = CheckpointBodyV1::new(
            purpose,
            ordinal,
            scope,
            target_cut,
            predecessor.nv_value(purpose),
            transaction_digest,
        )?;
        Ok(Self {
            predecessor,
            target,
        })
    }

    /// Returns the already shape-checked successor DATA.
    pub(super) const fn target(self) -> CheckpointBodyV1 {
        self.target
    }

    fn require_transaction(
        self,
        purpose: RecordPurposeDataV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        if successor_sequence(self.predecessor.cut.sequence, transaction)?
            != self.target.cut.sequence
            || transaction_digest_v1(purpose, self.target.scope, transaction)?
                != self.target.transaction_digest
        {
            return Err(FloorErrorV1::Successor);
        }
        Ok(())
    }

    /// Compares the exact predecessor and successor equations.
    ///
    /// # Errors
    ///
    /// Preserves scope, successor and checkpoint-encoding rejections.
    pub(super) fn require_predecessor(
        self,
        purpose: RecordPurposeDataV1,
        scope: [u8; 32],
        predecessor: CheckpointBodyV1,
    ) -> Result<(), FloorErrorV1> {
        let expected = Self::from_digest(
            purpose,
            scope,
            predecessor,
            self.target.cut,
            self.target.transaction_digest,
        )?;
        if expected == self {
            Ok(())
        } else {
            Err(FloorErrorV1::Successor)
        }
    }

    fn encode(self, purpose: RecordPurposeDataV1) -> [u8; INTENT_BYTES] {
        let mut bytes = [0; INTENT_BYTES];
        header(&mut bytes, purpose.intent_magic());
        bytes[12..168].copy_from_slice(&self.predecessor.encode(purpose));
        bytes[168..324].copy_from_slice(&self.target.encode(purpose));
        bytes
    }

    fn decode(context: RecordScopeDataV1, bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        let purpose = context.purpose();
        require_header(bytes, purpose.intent_magic(), INTENT_BYTES)?;
        let intent = Self {
            predecessor: CheckpointBodyV1::decode(purpose, &bytes[12..168])?,
            target: CheckpointBodyV1::decode(purpose, &bytes[168..324])?,
        };
        intent.require_predecessor(purpose, context.scope(), intent.predecessor)?;
        Ok(intent)
    }
}

/// Retains the original Broker checkpoint API over the single canonical body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FloorCheckpointV1 {
    /// Retains the shared canonical body inside the closed Broker wrapper.
    pub(super) body: CheckpointBodyV1,
}

impl FloorCheckpointV1 {
    /// Constructs the original Broker claim, never a provisioning owner.
    ///
    /// # Errors
    ///
    /// Rejects ordinal/scope and initial-versus-successor sentinel combinations.
    pub(crate) fn new(
        ordinal: u64,
        scope: [u8; 32],
        cut: FloorCutV1,
        predecessor_nv: [u8; 32],
        transaction_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: CheckpointBodyV1::new(
                RecordPurposeDataV1::BrokerV1,
                ordinal,
                scope,
                cut,
                predecessor_nv,
                transaction_digest,
            )?,
        })
    }

    /// Returns the original compared Broker cut.
    pub(crate) const fn cut(self) -> FloorCutV1 {
        self.body.cut()
    }

    /// Returns the original claimed Broker floor ordinal.
    pub(crate) const fn ordinal(self) -> u64 {
        self.body.ordinal
    }

    /// Compares the original Broker provisioning scope.
    ///
    /// # Errors
    ///
    /// Returns the original provisioning error for a different scope.
    pub(crate) fn require_profile(self, profile: FloorProfileV1) -> Result<(), FloorErrorV1> {
        self.body.require_scope(profile.scope())
    }

    /// Encodes the exact original AOSBTF01 claim.
    pub(crate) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        self.body.encode(RecordPurposeDataV1::BrokerV1)
    }

    /// Decodes only the original AOSBTF01 claim.
    ///
    /// # Errors
    ///
    /// Preserves original header, cut and checkpoint rejection order.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: CheckpointBodyV1::decode(RecordPurposeDataV1::BrokerV1, bytes)?,
        })
    }

    /// Computes the original fixed Broker extension preimage DATA.
    pub(crate) fn extend_input(self) -> [u8; 32] {
        self.body.extend_input(RecordPurposeDataV1::BrokerV1)
    }

    /// Computes the original Broker NV equation without observing hardware.
    pub(crate) fn nv_value(self) -> [u8; 32] {
        self.body.nv_value(RecordPurposeDataV1::BrokerV1)
    }
}

/// Retains the original Broker intent API over the single canonical body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FloorIntentV1 {
    /// Retains the shared successor body inside the closed Broker wrapper.
    pub(super) body: IntentBodyV1,
}

impl FloorIntentV1 {
    /// Compares the original exact Broker successor transaction.
    ///
    /// # Errors
    ///
    /// Preserves sequence-before-digest-before-profile/successor rejection.
    pub(crate) fn new(
        profile: FloorProfileV1,
        predecessor: FloorCheckpointV1,
        target_cut: FloorCutV1,
        transaction: &JournalTransaction,
    ) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: IntentBodyV1::new(
                RecordScopeDataV1::Broker(profile),
                predecessor.body,
                target_cut,
                transaction,
            )?,
        })
    }

    /// Returns the original target Broker claim.
    pub(crate) const fn target(self) -> FloorCheckpointV1 {
        FloorCheckpointV1 {
            body: self.body.target,
        }
    }

    /// Returns the original predecessor Broker claim.
    pub(crate) const fn predecessor(self) -> FloorCheckpointV1 {
        FloorCheckpointV1 {
            body: self.body.predecessor,
        }
    }

    /// Returns the original exact ordered transaction commitment.
    pub(crate) const fn transaction_digest(self) -> [u8; 32] {
        self.body.target.transaction_digest
    }

    /// Compares the original exact transaction sequence and digest.
    ///
    /// # Errors
    ///
    /// Preserves original sequence-first mismatch and digest-validation errors.
    pub(crate) fn require_transaction(
        self,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.body
            .require_transaction(RecordPurposeDataV1::BrokerV1, transaction)
    }

    /// Compares the original Broker predecessor and target equation.
    ///
    /// # Errors
    ///
    /// Preserves original provisioning, successor and encoding rejections.
    pub(crate) fn require_predecessor(
        self,
        profile: FloorProfileV1,
        predecessor: FloorCheckpointV1,
    ) -> Result<(), FloorErrorV1> {
        self.body.require_predecessor(
            RecordPurposeDataV1::BrokerV1,
            profile.scope(),
            predecessor.body,
        )
    }

    /// Encodes the exact original AOSBTI01 claim.
    pub(crate) fn encode(self) -> [u8; INTENT_BYTES] {
        self.body.encode(RecordPurposeDataV1::BrokerV1)
    }

    /// Decodes only the original AOSBTI01 claim.
    ///
    /// # Errors
    ///
    /// Preserves outer-header, predecessor, target and equation check order.
    pub(crate) fn decode(profile: FloorProfileV1, bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: IntentBodyV1::decode(RecordScopeDataV1::Broker(profile), bytes)?,
        })
    }
}

/// Represents distinct Host055 checkpoint DATA, never a live floor witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostFloorCheckpointDataV1 {
    /// Retains the shared canonical body inside the distinct Host DATA wrapper.
    pub(super) body: CheckpointBodyV1,
}

impl HostFloorCheckpointDataV1 {
    /// Compares the initial cut4/ordinal1 claim without authenticating its inputs.
    ///
    /// The independent provisioner must separately initialize the exact signed
    /// genesis/native association, sidecar and NV. Runtime absence never adopts
    /// this value as a baseline.
    ///
    /// # Errors
    ///
    /// Rejects invalid scope/head or a cut other than the initialized sequence4.
    pub(crate) fn initial(scope: [u8; 32], cut: FloorCutV1) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: CheckpointBodyV1::new(
                RecordPurposeDataV1::RuntimeDeploymentV1,
                1,
                scope,
                cut,
                [0; 32],
                [0; 32],
            )?,
        })
    }

    /// Returns the compared complete native cut DATA.
    pub(crate) const fn cut(self) -> FloorCutV1 {
        self.body.cut()
    }

    /// Returns the claimed actual floor-advance ordinal, not a generation.
    pub(crate) const fn ordinal(self) -> u64 {
        self.body.ordinal
    }

    /// Encodes the distinct AOSRDF01 claim.
    pub(crate) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        self.body.encode(RecordPurposeDataV1::RuntimeDeploymentV1)
    }

    /// Decodes only exact Host055 checkpoint DATA.
    ///
    /// # Errors
    ///
    /// Rejects foreign framing, invalid sentinels or checked ordinal/cut geometry.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: CheckpointBodyV1::decode(RecordPurposeDataV1::RuntimeDeploymentV1, bytes)?,
        })
    }

    /// Computes the distinct fixed Host055 extension preimage DATA.
    pub(crate) fn extend_input(self) -> [u8; 32] {
        self.body.extend_input(RecordPurposeDataV1::RuntimeDeploymentV1)
    }

    /// Computes SHA256(predecessor NV || extension), never fresh NV readback.
    pub(crate) fn nv_value(self) -> [u8; 32] {
        self.body.nv_value(RecordPurposeDataV1::RuntimeDeploymentV1)
    }
}

/// Represents distinct exact Host055 successor DATA, not durable preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostFloorIntentDataV1 {
    /// Retains the shared successor body inside the distinct Host DATA wrapper.
    pub(super) body: IntentBodyV1,
}

impl HostFloorIntentDataV1 {
    /// Compares an exact Host transaction without replacing genuine Core validation.
    ///
    /// The future closed owner must first authenticate the original complete
    /// native/schema/predecessor and actual signed immutable one-PUT phase.
    ///
    /// # Errors
    ///
    /// Rejects a different scope, sequence, namespace, transaction or ordinal.
    pub(crate) fn compare_successor(
        scope: [u8; 32],
        predecessor: HostFloorCheckpointDataV1,
        target_cut: FloorCutV1,
        transaction: &JournalTransaction,
    ) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: IntentBodyV1::new(
                RecordScopeDataV1::Host(scope),
                predecessor.body,
                target_cut,
                transaction,
            )?,
        })
    }

    /// Returns the target Host checkpoint DATA.
    pub(crate) const fn target(self) -> HostFloorCheckpointDataV1 {
        HostFloorCheckpointDataV1 {
            body: self.body.target,
        }
    }

    /// Returns the predecessor Host checkpoint DATA.
    pub(crate) const fn predecessor(self) -> HostFloorCheckpointDataV1 {
        HostFloorCheckpointDataV1 {
            body: self.body.predecessor,
        }
    }

    /// Compares the exact ordered Host transaction commitment and frame count.
    ///
    /// # Errors
    ///
    /// Rejects different identity/order/namespace/bytes or native successor.
    pub(crate) fn require_transaction(
        self,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.body
            .require_transaction(RecordPurposeDataV1::RuntimeDeploymentV1, transaction)
    }

    /// Encodes only distinct AOSRDI01 preparation DATA.
    pub(crate) fn encode(self) -> [u8; INTENT_BYTES] {
        self.body.encode(RecordPurposeDataV1::RuntimeDeploymentV1)
    }

    /// Decodes a Host claim and compares its scope/predecessor/target equation.
    ///
    /// # Errors
    ///
    /// Rejects foreign framing, malformed body or a transplanted scope/equation.
    pub(crate) fn decode(scope: [u8; 32], bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        Ok(Self {
            body: IntentBodyV1::decode(RecordScopeDataV1::Host(scope), bytes)?,
        })
    }
}

fn header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
}

fn require_header(bytes: &[u8], magic: &[u8; 8], length: usize) -> Result<(), FloorErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != magic
        || bytes[8..10] != [0, 1]
        || bytes[10..12] != [0; 2]
    {
        return Err(FloorErrorV1::Encoding);
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], FloorErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(FloorErrorV1::Encoding)
}
