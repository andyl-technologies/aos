//! Closed native execution commands and their complete original authority scope.

use crucible_node_contract::{HashRef, Id, Position, U64, Validate};

/// Identifies the separately negotiated native command extension.
pub const NODE_CONTROL_VERSION: u16 = 1;
/// Bounds a native command before any variable-size allocation.
pub const NODE_CONTROL_MAX_BODY_BYTES: usize = 4_096;
/// Sizes the fixed native command framing header.
pub const NODE_CONTROL_HEADER_BYTES: usize = 16;

/// Binds a command to a complete live admitted owner incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerScope {
    /// Identifies the admitted provider session.
    pub session: Id,
    /// Identifies the native process or realization incarnation.
    pub incarnation: Id,
    /// Identifies the durably committed complete world activation.
    pub activation: Id,
    /// Identifies the logical public participant.
    pub node: Id,
    /// Identifies the exclusive native execution owner.
    pub owner: Id,
    /// Identifies the positive current world generation.
    pub world_generation: U64,
    /// Identifies the positive current owner generation.
    pub owner_generation: U64,
    /// Commits to complete immutable world compatibility.
    pub world_binding: HashRef,
    /// Commits to complete immutable owner compatibility.
    pub owner_binding: HashRef,
}

impl OwnerScope {
    /// Commits to the complete originally prepared native owner scope.
    ///
    /// # Errors
    /// Rejects invalid scope fields or noncanonical binding identities.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        self.validate()?;
        let mut encoded = Vec::new();
        super::codec::scope(&mut encoded, self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-native-prepared-scope.v1\0");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    pub(super) fn validate(&self) -> Result<(), NativeCommandError> {
        if self.world_generation.get() == 0 || self.owner_generation.get() == 0 {
            return Err(NativeCommandError::Invalid("generation must be positive"));
        }
        for (hash, domain) in [
            (&self.world_binding, "cnp.world-binding.v1"),
            (&self.owner_binding, "cnp.owner-binding.v1"),
        ] {
            hash.validate()
                .map_err(|_| NativeCommandError::Invalid("invalid binding hash"))?;
            if hash.algorithm != "blake3-256" || hash.domain != domain {
                return Err(NativeCommandError::Invalid("wrong binding identity domain"));
            }
        }
        Ok(())
    }
}

/// Selects one independently qualified native stop representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryPolicy {
    /// Requires physical suspension at an ordinary exact horizon.
    HorizonPark,
    /// Requires separately qualified preservation of an unresolved input boundary.
    InputBlockedPark,
}

/// Distinguishes physical-time execution from finite same-time settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionKind {
    /// Authorizes modeled transitions strictly before a later physical instant.
    ExactRun {
        /// Locates the original stopped execution cursor.
        start: Position,
        /// Locates the exclusive execution limit.
        limit: Position,
        /// Selects the admitted native stop representation.
        boundary_policy: BoundaryPolicy,
    },
    /// Authorizes a finite same-time phase range without later clock advancement.
    BoundarySettle {
        /// Locates the first authorized same-time phase.
        start: Position,
        /// Locates the exclusive same-time phase limit.
        limit: Position,
    },
}

impl ExecutionKind {
    /// Returns the original inclusive execution cursor.
    pub fn start(self) -> Position {
        match self {
            Self::ExactRun { start, .. } | Self::BoundarySettle { start, .. } => start,
        }
    }

    /// Returns the exclusive execution or phase limit.
    pub fn limit(self) -> Position {
        match self {
            Self::ExactRun { limit, .. } | Self::BoundarySettle { limit, .. } => limit,
        }
    }
}

/// Carries a complete immutable original native command without granting authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionCommand {
    /// Names the original positive command sequence within its owner incarnation.
    pub sequence: U64,
    /// Binds all live and immutable owner/world identities.
    pub scope: OwnerScope,
    /// Identifies the original retained operation.
    pub operation: Id,
    /// Identifies the opaque coordinator execution grant.
    pub grant: Id,
    /// Identifies the immutable staged input epoch.
    pub input_epoch: Id,
    /// Identifies the frozen complete staged input batch.
    pub input_batch: Id,
    /// Commits to its unchanged complete canonical contents and order.
    pub input_batch_hash: HashRef,
    /// Locates the exclusive complete input authorization prefix.
    pub closed_input_prefix: Position,
    /// Commits to the full immutable original native authorization record.
    ///
    /// The native journal must retain and authenticate that record. A caller's
    /// digest alone never proves admission, staged input or local grant custody.
    pub authorization_digest: [u8; 32],
    /// Selects the admitted native execution operation and timing bounds.
    pub kind: ExecutionKind,
}

impl ExecutionCommand {
    /// Commits to every byte of the original versioned native command.
    ///
    /// # Errors
    /// Rejects a command that cannot be encoded under the closed extension.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let encoded = super::encode_command(self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-native-command.v1\0");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Checks the closed local schema without authenticating native permission.
    ///
    /// # Errors
    /// Rejects zero sequence/generations, wrong hash domains, regressing bounds,
    /// time advancement in settlement and incomplete declared input prefixes.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.scope.validate()?;
        if self.sequence.get() == 0 {
            return Err(NativeCommandError::Invalid(
                "command sequences begin at one",
            ));
        }
        self.input_batch_hash
            .validate()
            .map_err(|_| NativeCommandError::Invalid("invalid input batch hash"))?;
        if self.input_batch_hash.algorithm != "blake3-256"
            || self.input_batch_hash.domain != "cnp.input-batch.v1"
        {
            return Err(NativeCommandError::Invalid(
                "wrong input batch identity domain",
            ));
        }
        let start = self.kind.start();
        let limit = self.kind.limit();
        if start >= limit || self.closed_input_prefix < limit {
            return Err(NativeCommandError::Invalid(
                "incomplete execution or input prefix",
            ));
        }
        match self.kind {
            ExecutionKind::ExactRun { .. } if start.time_ps >= limit.time_ps => Err(
                NativeCommandError::Invalid("exact execution requires a later physical limit"),
            ),
            ExecutionKind::BoundarySettle { .. } if start.time_ps != limit.time_ps => Err(
                NativeCommandError::Invalid("settlement cannot advance physical time"),
            ),
            _ => Ok(()),
        }
    }
}

/// Reports malformed native framing or conflicting original command custody.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeCommandError {
    /// The frame cannot be interpreted under this closed extension.
    #[error("invalid native command: {0}")]
    Invalid(&'static str),
    /// The peer selected an unsupported independent extension version.
    #[error("unsupported native command extension version {0}")]
    UnsupportedVersion(u16),
    /// The command cannot fit its admitted finite byte or journal allowance.
    #[error("native command resource allowance exhausted")]
    ResourceLimit,
    /// A live identity or original request disagrees with retained native custody.
    #[error("native command authority or identity conflict")]
    Conflict,
}
