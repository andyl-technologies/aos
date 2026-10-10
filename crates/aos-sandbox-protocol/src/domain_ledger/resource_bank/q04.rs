//! Owns the complete historical co-issuance grammar and passive replay.
//!
//! ```text
//! AOSRSQ01 | original787 | grant531 | use531 | Spec/compile joins184 | SHA32
//! AOSRSQ02 | same body2041 | normalized32 | input-sha32 | input-bytes8 |
//!            Project-continuation176 | Q-intake-id16 | observer-quota8 | SHA32
//! ```

use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceDimension, ResourceVector};
use sha2::{Digest as _, Sha256};

use super::{
    AccountHead, AccountKind, Claim, ClaimPurpose, ClaimState, CoissuanceBinding as Binding,
    CoissuanceMutation, InputAssociation, JournalRecord, Q04CutIdentityV1, RecordNamespace,
    ResourceBankDataError, codec, replay,
};

pub(super) const PREFIX: u8 = b'q';
pub(super) const RECORD_BYTES: usize = 2073;
const INPUT_RECORD_BYTES: usize = 2345;
/// Specifies the six canonical bank members in the original Controller hold.
pub const BANK_MEMBERS: usize = 6;

fn derived_id(domain: &[u8], identity: &Q04CutIdentityV1) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(identity.digest().as_bytes())
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

pub(super) fn residual_claim(binding: Binding) -> Result<Claim, ResourceBankDataError> {
    Ok(Claim {
        amount: binding
            .original
            .claim
            .amount
            .checked_sub(binding.grant.amount)?,
        ..binding.original.claim
    })
}

pub(super) fn child_head(binding: Binding) -> Result<AccountHead, ResourceBankDataError> {
    let grant = binding.grant;
    Ok(AccountHead {
        enrollment: grant.enrollment,
        id: grant.child,
        parent: grant.account,
        kind: AccountKind::Sandbox,
        generation: 1,
        project: grant.project,
        sandbox: grant.sandbox,
        tree_revision: grant.tree_revision,
        baseline: ResourceVector::ZERO,
        account: ResourceAccount::from_usage(
            ResourceCeilings::bounded(grant.amount),
            ResourceVector::ZERO,
            binding.use_claim.amount,
        )?,
    })
}

fn require_binding(binding: Binding) -> Result<(), ResourceBankDataError> {
    let original = binding.original.claim;
    let grant = binding.grant;
    let use_claim = binding.use_claim;
    if grant
        != (Claim {
            id: grant.id,
            child: grant.child,
            sandbox: grant.sandbox,
            purpose: ClaimPurpose::InclusiveGrant,
            amount: grant.amount,
            ..original
        })
        || grant.sandbox == [0; 16]
        || grant.child != grant.sandbox
        || use_claim
            != (Claim {
                id: use_claim.id,
                account: grant.child,
                child: [0; 16],
                purpose: ClaimPurpose::Q04Preparation,
                amount: use_claim.amount,
                ..grant
            })
        || [original.id, grant.id, use_claim.id]
            .iter()
            .enumerate()
            .any(|(index, id)| {
                *id == [0; 16] || [original.id, grant.id, use_claim.id][..index].contains(id)
            })
        || binding.specification_size == 0
        || binding.specification_operation == [0; 16]
        || [
            binding.specification,
            binding.specification_record,
            binding.specification_request,
            binding.candidate,
            binding.policy_binding,
        ]
        .contains(&[0; 32])
        || original.state != ClaimState::Reserved
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    match binding.origin {
        None if use_claim.amount != grant.amount => {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Some(origin) => {
            if origin.normalized == [0; 32]
                || origin.digest == [0; 32]
                || origin.bytes == 0
                || origin.bytes > 4 * 1024 * 1024
                || origin.intake == [0; 16]
                || origin.observations < 27
            {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            grant.amount.checked_sub(use_claim.amount)?;
            residual_claim(binding)?
                .amount
                .checked_sub(origin.continuation)?;
            original
                .amount
                .checked_sub(use_claim.amount.checked_add(origin.continuation)?)?;
        }
        None => {}
    }
    residual_claim(binding)?;
    codec::encode_claim(grant)?;
    codec::encode_claim(use_claim)?;
    Ok(())
}

pub(super) fn require_replayed(
    state: &replay::State,
    binding: Binding,
) -> Result<(), ResourceBankDataError> {
    require_binding(binding)?;
    if let Some(origin) = binding.origin {
        let intake = codec::decode_claim(
            replay::record_bytes(state, replay::CLAIM_PREFIX, origin.intake)
                .ok_or(ResourceBankDataError::CorruptLedger)?,
        )?;
        if intake.purpose != ClaimPurpose::Q04OriginalIntake
            || intake.state != ClaimState::Committed
            || intake.enrollment != binding.original.claim.enrollment
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let bytes = state
            .get(&(
                RecordNamespace::ControllerPolicyHold,
                super::CONTROLLER_INPUT_ORIGIN_KEY.to_vec(),
            ))
            .ok_or(ResourceBankDataError::CorruptLedger)?;
        if !matches_origin_bytes(binding, bytes)? {
            return Err(ResourceBankDataError::CorruptLedger);
        }
    }
    // Original co-issuance remains immutable. Only an exact typed terminal
    // successor may change its current use/head; a newer generation alone
    // cannot waive the original association or create spare capacity.
    let (use_claim, child) = super::settlement::current_use(state, binding)?;
    for claim in [residual_claim(binding)?, binding.grant, use_claim] {
        if replay::record_bytes(state, replay::CLAIM_PREFIX, claim.id)
            .map(codec::decode_claim)
            .transpose()?
            != Some(claim)
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
    }
    if replay::find_head(state, binding.grant.child)? != child
        || replay::record_bytes(state, replay::PREPARATION_PREFIX, binding.original.claim.id)
            .map(codec::decode_preparation)
            .transpose()?
            != Some(binding.original)
        || replay::record_bytes(state, PREFIX, binding.original.claim.id)
            .map(decode)
            .transpose()?
            != Some(binding)
    {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

pub(super) fn original_claim(binding: Binding) -> Claim {
    binding.original.claim
}

pub(super) fn contains_use(binding: Binding, claim: Claim) -> bool {
    claim == binding.use_claim
        || claim
            == (Claim {
                state: ClaimState::Committed,
                ..binding.use_claim
            })
}

pub(super) fn use_claim(binding: Binding) -> Claim {
    binding.use_claim
}

pub(super) fn has_input_origin(binding: Binding) -> bool {
    binding.origin.is_some()
}

/// Checks the complete selected Q04 input association and historical replay.
///
/// # Errors
///
/// Rejects ambiguous or malformed co-issuance, incompatible presence of input
/// bytes, invalid provenance joins, and incomplete replay. Retained Policy
/// decoding and identity mismatches are deliberately coarsened to `CorruptLedger`.
pub fn require_input_history(
    state: &replay::State,
    identity: &Q04CutIdentityV1,
    bytes: Option<&[u8]>,
) -> Result<(), ResourceBankDataError> {
    let mut selected = None;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || key.first() != Some(&PREFIX)
        {
            continue;
        }
        let binding = decode(value)?;
        if binding.original.claim.operation != identity.operation().into_bytes() {
            continue;
        }
        if selected.replace(binding).is_some() {
            return Err(ResourceBankDataError::CorruptLedger);
        }
    }
    match (selected, bytes) {
        (Some(binding), Some(bytes)) if has_input_origin(binding) => {
            super::require_origin_identity(bytes, identity)
                .map_err(|_| ResourceBankDataError::CorruptLedger)?;
            if !matches_origin_bytes(binding, bytes)? {
                return Err(ResourceBankDataError::CorruptLedger);
            }
            require_replayed(state, binding)
        }
        (Some(binding), None) if !has_input_origin(binding) => Ok(()),
        (None, None) => Ok(()),
        _ => Err(ResourceBankDataError::CorruptLedger),
    }
}

pub(super) fn matches_origin_record(
    binding: Binding,
    record: &JournalRecord,
) -> Result<bool, ResourceBankDataError> {
    if record.namespace() != RecordNamespace::ControllerPolicyHold
        || record.key() != super::CONTROLLER_INPUT_ORIGIN_KEY
    {
        return Ok(false);
    }
    match record.value() {
        Some(bytes) => matches_origin_bytes(binding, bytes),
        None => Ok(false),
    }
}

pub(super) fn matches_origin_bytes(
    binding: Binding,
    bytes: &[u8],
) -> Result<bool, ResourceBankDataError> {
    let Some(origin) = binding.origin else {
        return Ok(false);
    };
    if bytes.len() as u64 != origin.bytes
        || <[u8; 32]>::from(Sha256::digest(bytes)) != origin.digest
    {
        return Ok(false);
    }
    let input = aos_sandbox_policy::RetainedPublisherCompilerOriginV3::from_record_bytes(bytes)
        .map_err(|_| ResourceBankDataError::CorruptLedger)?;
    Ok(input.project().into_bytes() == binding.grant.project
        && input.original_target().into_bytes() == binding.grant.sandbox
        && input.normalized_input().as_bytes() == &origin.normalized
        && input.candidate().as_bytes() == &binding.candidate)
}

pub(super) enum EncodedBinding {
    Legacy([u8; RECORD_BYTES]),
    Input([u8; INPUT_RECORD_BYTES]),
}

impl EncodedBinding {
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Legacy(bytes) => bytes,
            Self::Input(bytes) => bytes,
        }
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl AsRef<[u8]> for EncodedBinding {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub(super) fn encode(binding: Binding) -> Result<EncodedBinding, ResourceBankDataError> {
    require_binding(binding)?;
    let mut encoded = if binding.origin.is_some() {
        EncodedBinding::Input([0; INPUT_RECORD_BYTES])
    } else {
        EncodedBinding::Legacy([0; RECORD_BYTES])
    };
    let bytes: &mut [u8] = match &mut encoded {
        EncodedBinding::Legacy(bytes) => bytes,
        EncodedBinding::Input(bytes) => bytes,
    };
    bytes[..8].copy_from_slice(if binding.origin.is_some() {
        b"AOSRSQ02"
    } else {
        b"AOSRSQ01"
    });
    bytes[8..795].copy_from_slice(&codec::encode_preparation(binding.original)?);
    bytes[795..1326].copy_from_slice(&codec::encode_claim(binding.grant)?);
    bytes[1326..1857].copy_from_slice(&codec::encode_claim(binding.use_claim)?);
    bytes[1857..1889].copy_from_slice(&binding.specification);
    bytes[1889..1897].copy_from_slice(&binding.specification_size.to_be_bytes());
    bytes[1897..1929].copy_from_slice(&binding.specification_record);
    bytes[1929..1945].copy_from_slice(&binding.specification_operation);
    bytes[1945..1977].copy_from_slice(&binding.specification_request);
    bytes[1977..2009].copy_from_slice(&binding.candidate);
    bytes[2009..2041].copy_from_slice(&binding.policy_binding);
    if let Some(origin) = binding.origin {
        bytes[2041..2073].copy_from_slice(&origin.normalized);
        bytes[2073..2105].copy_from_slice(&origin.digest);
        bytes[2105..2113].copy_from_slice(&origin.bytes.to_be_bytes());
        for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            let start = 2113 + index * 8;
            bytes[start..start + 8]
                .copy_from_slice(&origin.continuation.get(dimension).to_be_bytes());
        }
        bytes[2289..2305].copy_from_slice(&origin.intake);
        bytes[2305..2313].copy_from_slice(&origin.observations.to_be_bytes());
    }
    let end = bytes.len() - 32;
    let checksum = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
    Ok(encoded)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Binding, ResourceBankDataError> {
    let input = bytes.len() == INPUT_RECORD_BYTES && bytes.get(..8) == Some(b"AOSRSQ02");
    if !input && (bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(b"AOSRSQ01")) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let fixed = |range: std::ops::Range<usize>| -> Result<[u8; 32], ResourceBankDataError> {
        bytes[range]
            .try_into()
            .map_err(|_| ResourceBankDataError::CorruptLedger)
    };
    let binding = Binding {
        original: codec::decode_preparation(&bytes[8..795])?,
        grant: codec::decode_claim(&bytes[795..1326])?,
        use_claim: codec::decode_claim(&bytes[1326..1857])?,
        specification: fixed(1857..1889)?,
        specification_size: u64::from_be_bytes(
            bytes[1889..1897]
                .try_into()
                .map_err(|_| ResourceBankDataError::CorruptLedger)?,
        ),
        specification_record: fixed(1897..1929)?,
        specification_operation: bytes[1929..1945]
            .try_into()
            .map_err(|_| ResourceBankDataError::CorruptLedger)?,
        specification_request: fixed(1945..1977)?,
        candidate: fixed(1977..2009)?,
        policy_binding: fixed(2009..2041)?,
        origin: if input {
            let mut values = [0; ResourceDimension::COUNT];
            for (index, value) in values.iter_mut().enumerate() {
                let start = 2113 + index * 8;
                *value = u64::from_be_bytes(
                    bytes[start..start + 8]
                        .try_into()
                        .map_err(|_| ResourceBankDataError::CorruptLedger)?,
                );
            }
            Some(InputAssociation {
                normalized: fixed(2041..2073)?,
                digest: fixed(2073..2105)?,
                bytes: u64::from_be_bytes(
                    bytes[2105..2113]
                        .try_into()
                        .map_err(|_| ResourceBankDataError::CorruptLedger)?,
                ),
                continuation: ResourceVector::new(values),
                intake: bytes[2289..2305]
                    .try_into()
                    .map_err(|_| ResourceBankDataError::CorruptLedger)?,
                observations: u64::from_be_bytes(
                    bytes[2305..2313]
                        .try_into()
                        .map_err(|_| ResourceBankDataError::CorruptLedger)?,
                ),
            })
        } else {
            None
        },
    };
    if encode(binding)?.as_slice() != bytes {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(binding)
}

/// Constructs the complete historical Sandbox child without current authority.
///
/// # Errors
/// Retains the original reserved-use account arithmetic failure.
pub fn sandbox_child(
    before: AccountHead,
    sandbox: [u8; 16],
    amount: ResourceVector,
    retained_use: ResourceVector,
) -> Result<AccountHead, ResourceBankDataError> {
    Ok(AccountHead {
        enrollment: before.enrollment,
        id: sandbox,
        parent: before.id,
        kind: AccountKind::Sandbox,
        generation: 1,
        project: before.project,
        sandbox,
        tree_revision: before.tree_revision,
        baseline: ResourceVector::ZERO,
        account: ResourceAccount::from_usage(
            ResourceCeilings::bounded(amount),
            ResourceVector::ZERO,
            retained_use,
        )?,
    })
}

/// Constructs the original inclusive claim at its original derived-hash stage.
pub fn inclusive_claim_for_cut(
    original: Claim,
    identity: &Q04CutIdentityV1,
    sandbox: [u8; 16],
    amount: ResourceVector,
) -> Claim {
    Claim {
        id: derived_id(b"AOS-Q04-INCLUSIVE-GRANT-V1", identity),
        child: sandbox,
        sandbox,
        purpose: ClaimPurpose::InclusiveGrant,
        amount,
        ..original
    }
}

/// Constructs the original retained-use claim after inclusive claim construction.
pub fn retained_use_claim_for_cut(
    grant: Claim,
    identity: &Q04CutIdentityV1,
    sandbox: [u8; 16],
    retained_use: ResourceVector,
) -> Claim {
    Claim {
        id: derived_id(b"AOS-Q04-RETAINED-USE-V1", identity),
        account: sandbox,
        child: [0; 16],
        sandbox,
        purpose: ClaimPurpose::Q04Preparation,
        amount: retained_use,
        ..grant
    }
}

impl CoissuanceMutation<'_> {
    /// Runs the complete original co-issuance records operation.
    ///
    /// # Errors
    /// Retains the existing replay, binding and arithmetic refusal order.
    pub fn records(&self) -> Result<[JournalRecord; BANK_MEMBERS], ResourceBankDataError> {
        let row = |prefix, id, bytes: Vec<u8>| {
            JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(prefix, id).to_vec(),
                bytes,
            )
        };
        Ok([
            row(
                replay::HEAD_PREFIX,
                self.after.id,
                codec::encode_head(*self.after)?.to_vec(),
            ),
            row(
                replay::CLAIM_PREFIX,
                self.residual.id,
                codec::encode_claim(*self.residual)?.to_vec(),
            ),
            row(
                replay::CLAIM_PREFIX,
                self.binding.grant.id,
                codec::encode_claim(self.binding.grant)?.to_vec(),
            ),
            row(
                replay::HEAD_PREFIX,
                self.child.id,
                codec::encode_head(*self.child)?.to_vec(),
            ),
            row(
                replay::CLAIM_PREFIX,
                self.binding.use_claim.id,
                codec::encode_claim(self.binding.use_claim)?.to_vec(),
            ),
            row(PREFIX, self.residual.id, encode(*self.binding)?.to_vec()),
        ])
    }

    /// Runs the complete original co-issuance require_predecessor operation.
    ///
    /// # Errors
    /// Retains the existing replay, binding and arithmetic refusal order.
    pub fn require_predecessor(&self, state: &replay::State) -> Result<(), ResourceBankDataError> {
        let original = self.binding.original;
        if replay::validate(state)? != Some(self.before.enrollment)
            || replay::find_head(state, self.before.id)? != (*self.before)
            || self.before.kind != AccountKind::Project
            || original.claim.enrollment != self.before.enrollment
            || original.claim.account != self.before.id
            || original.claim.project != self.before.project
            || original.claim.tree_revision != self.before.tree_revision
            || (*self.after)
                != (AccountHead {
                    generation: self
                        .before
                        .generation
                        .checked_add(1)
                        .ok_or(ResourceBankDataError::Conflict)?,
                    ..(*self.before)
                })
            || replay::record_bytes(state, replay::CLAIM_PREFIX, original.claim.id)
                .map(codec::decode_claim)
                .transpose()?
                != Some(original.claim)
            || replay::record_bytes(state, replay::PREPARATION_PREFIX, original.claim.id)
                .map(codec::decode_preparation)
                .transpose()?
                != Some(original)
            || replay::has_head(state, self.child.id)
            || [self.binding.grant.id, self.binding.use_claim.id]
                .into_iter()
                .any(|id| replay::record_bytes(state, replay::CLAIM_PREFIX, id).is_some())
            || replay::record_bytes(state, PREFIX, original.claim.id).is_some()
        {
            return Err(ResourceBankDataError::Conflict);
        }
        require_binding(*self.binding)?;
        if (*self.residual) != residual_claim(*self.binding)?
            || (*self.child) != child_head(*self.binding)?
        {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }
}
