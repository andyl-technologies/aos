//! Encodes the closed native Controller resource-account and claim formats.
//!
//! ```text
//! head  = AOSRSH01 || enrollment[96] || id[16] || parent[16] || kind:u8
//!         || generation:u64be || project[16] || sandbox[16] || tree[32]
//!         || ceiling[22*u64be] || baseline[22*u64be]
//!         || committed[22*u64be] || reserved[22*u64be] || sha256[32]
//! claim = AOSRSC02 || enrollment[96] || id[16] || account[16] || child[16]
//!         || owner[32] || purpose:u8 || operation[16] || project[16]
//!         || sandbox[16] || tree[32] || cut[25] || amount[22*u64be]
//!         || state:u8 || genesis-instance[32] || sha256[32]
//! preparation = AOSRSP01 || original-claim[531] || nonce[16]
//!               || controller-names[48] || source-names[48] || source-sequence:u64be
//!               || floor[32] || tree-head[32] || lineage-head[32] || sha256[32]
//! enrollment = node[16] || policy-epoch[16] || boot[16]
//!              || producer-invocation[16] || image-manifest[32]
//! image-policy = AOSRSB01 || node[16] || policy-epoch[16]
//!                || capacity[22*u64be] || baseline[22*u64be]
//!                || controller[22*u64be] || components[22*u64be]
//!                || sha256[32]
//! host-image-policy = AOSRSB02 || node[16] || policy-epoch[16]
//!                     || capacity[22*u64be] || baseline[22*u64be]
//!                     || controller[22*u64be] || components[22*u64be]
//!                     || host-service[22*u64be] || host-control[22*u64be]
//!                     || sha256[32]
//! pid1-delivery = AOSRSE01 || enrollment[96] || controller-invocation[16]
//!                 || sha256[32]
//! ```
//!
//! Every dimension is present, finite, and ordered by the sole resource
//! registry. A checksum establishes canonical bytes, never producer authority.
//! The 776-byte V1 policy and claim purposes 1 through 6 remain strict. The
//! 1128-byte Host policy uses claim family `AOSRSC03` only for purposes 7 and 8;
//! its claim layout is otherwise the same 531-byte canonical record.
//! The 1304-byte `AOSRSB03` adds the full Controller FirstGlobal prefix vector
//! after the Host vectors. Its 531-byte `AOSRSC04` claims accept only purpose 9;
//! neither a historical prefix claim nor these image bytes construct a loan.
//! The 1480-byte `AOSRSB04` adds I at 1272..1448 and moves the checksum to
//! 1448..1480. Its same-width `AOSRSC06` claims accept only purpose 11. P and I
//! partition the original Controller envelope; neither family pays an operation.
//!
//! `AOSRSB05` is exactly 1656 bytes: the Q04 intake vector occupies
//! 1448..1624 and the checksum occupies 1624..1656. `AOSRSC07` is the same
//! 531-byte claim layout, admitting only purpose 12, Q04OriginalIntake.
//!
//! `AOSRSB06` is exactly 1832 bytes: it keeps Q's body through 1624,
//! appends Root R at 1624..1800, and checksums 1800..1832. Its same-width
//! `AOSRSC08` admits only purpose 13, RootReceiving, in Components.

use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceDimension, ResourceLimit, ResourceVector};
use sha2::{Digest as _, Sha256};

use super::{AccountHead, AccountKind, Claim, ClaimCut, ClaimPurpose, ClaimState, EnrollmentIdentity, ImageBootstrapPolicy, ResourceReservationErrorV1};
use super::PreparationBinding;

pub(super) const HEAD_BYTES: usize = 945;
pub(super) const CLAIM_BYTES: usize = 531;
pub(super) const PREPARATION_BYTES: usize = 787;
const HEAD_MAGIC: &[u8; 8] = b"AOSRSH01";
const CLAIM_MAGIC: &[u8; 8] = b"AOSRSC02";
pub(super) const IMAGE_POLICY_BYTES: usize = 776;
pub(super) const HOST_IMAGE_POLICY_BYTES: usize = 1128;
pub(super) const FIRST_GLOBAL_IMAGE_POLICY_BYTES: usize = 1304;
pub(super) const NIX_INTAKE_IMAGE_POLICY_BYTES: usize = 1480;
pub(super) const Q04_INTAKE_IMAGE_POLICY_BYTES: usize = 1656;
pub(super) const ROOT_IMAGE_POLICY_BYTES: usize = 1832;
const IMAGE_POLICY_MAGIC: &[u8; 8] = b"AOSRSB01";

pub(super) fn decode_image_policy(
    bytes: &[u8],
) -> Result<ImageBootstrapPolicy, ResourceReservationErrorV1> {
    let (length, magic) = match bytes.get(..8) {
        Some(magic) if magic == b"AOSRSB06" => (ROOT_IMAGE_POLICY_BYTES, b"AOSRSB06"),
        Some(magic) if magic == b"AOSRSB05" => (Q04_INTAKE_IMAGE_POLICY_BYTES, b"AOSRSB05"),
        Some(magic) if magic == b"AOSRSB04" => (NIX_INTAKE_IMAGE_POLICY_BYTES, b"AOSRSB04"),
        Some(magic) if magic == b"AOSRSB03" => (FIRST_GLOBAL_IMAGE_POLICY_BYTES, b"AOSRSB03"),
        Some(magic) if magic == b"AOSRSB02" => (HOST_IMAGE_POLICY_BYTES, b"AOSRSB02"),
        _ => (IMAGE_POLICY_BYTES, IMAGE_POLICY_MAGIC),
    };
    require_record(bytes, length, magic)?;

    // Only the selected closed format enables suffix fields; input length
    // never selects or admits another layout.
    let policy = ImageBootstrapPolicy {
        node: fixed(&bytes[8..24])?,
        epoch: fixed(&bytes[24..40])?,
        capacity: decode_vector(&bytes[40..216])?,
        baseline: decode_vector(&bytes[216..392])?,
        controller: decode_vector(&bytes[392..568])?,
        components: decode_vector(&bytes[568..744])?,
        host: if length >= HOST_IMAGE_POLICY_BYTES {
            Some(super::HostComponentPolicy {
                service: decode_vector(&bytes[744..920])?,
                control: decode_vector(&bytes[920..1096])?,
            })
        } else {
            None
        },
        first_global_prefix: if length >= FIRST_GLOBAL_IMAGE_POLICY_BYTES {
            Some(decode_vector(&bytes[1096..1272])?)
        } else {
            None
        },
        nix_original_start_intake: if length >= NIX_INTAKE_IMAGE_POLICY_BYTES {
            Some(decode_vector(&bytes[1272..1448])?)
        } else {
            None
        },
        q04_original_intake: if length >= Q04_INTAKE_IMAGE_POLICY_BYTES {
            Some(decode_vector(&bytes[1448..1624])?)
        } else {
            None
        },
        root_receiving: if length >= ROOT_IMAGE_POLICY_BYTES {
            Some(decode_vector(&bytes[1624..1800])?)
        } else {
            None
        },
    };
    policy.validate()?;
    Ok(policy)
}

pub(super) fn decode_pid1_delivery(
    bytes: &[u8],
) -> Result<(EnrollmentIdentity, [u8; 16]), ResourceReservationErrorV1> {
    require_record(bytes, 152, b"AOSRSE01")?;
    let enrollment = decode_enrollment(&bytes[8..104])?;
    let invocation = fixed(&bytes[104..120])?;
    if invocation == [0; 16] {
        return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
    }
    Ok((enrollment, invocation))
}

pub(super) fn encode_head(head: AccountHead) -> Result<[u8; HEAD_BYTES], ResourceReservationErrorV1> {
    validate_head(head)?;
    let mut bytes = [0; HEAD_BYTES];
    bytes[..8].copy_from_slice(HEAD_MAGIC);
    encode_enrollment(head.enrollment, &mut bytes[8..104]);
    bytes[104..120].copy_from_slice(&head.id);
    bytes[120..136].copy_from_slice(&head.parent);
    bytes[136] = match head.kind {
        AccountKind::Node => 1,
        AccountKind::Controller => 2,
        AccountKind::Components => 3,
        AccountKind::Project => 4,
        AccountKind::Sandbox => 5,
        AccountKind::Operation => 6,
    };
    bytes[137..145].copy_from_slice(&head.generation.to_be_bytes());
    bytes[145..161].copy_from_slice(&head.project);
    bytes[161..177].copy_from_slice(&head.sandbox);
    bytes[177..209].copy_from_slice(&head.tree_revision);
    encode_vector(super::replay::finite_ceilings(head)?, &mut bytes[209..385]);
    encode_vector(head.baseline, &mut bytes[385..561]);
    encode_vector(head.account.committed(), &mut bytes[561..737]);
    encode_vector(head.account.reserved(), &mut bytes[737..913]);
    let checksum = Sha256::digest(&bytes[..913]);
    bytes[913..].copy_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn decode_head(bytes: &[u8]) -> Result<AccountHead, ResourceReservationErrorV1> {
    require_record(bytes, HEAD_BYTES, HEAD_MAGIC)?;
    let kind = match bytes[136] {
        1 => AccountKind::Node,
        2 => AccountKind::Controller,
        3 => AccountKind::Components,
        4 => AccountKind::Project,
        5 => AccountKind::Sandbox,
        6 => AccountKind::Operation,
        _ => return Err(ResourceReservationErrorV1::CorruptLedger),
    };
    let head = AccountHead {
        enrollment: decode_enrollment(&bytes[8..104])?,
        id: fixed(&bytes[104..120])?,
        parent: fixed(&bytes[120..136])?,
        kind,
        generation: u64::from_be_bytes(fixed(&bytes[137..145])?),
        project: fixed(&bytes[145..161])?,
        sandbox: fixed(&bytes[161..177])?,
        tree_revision: fixed(&bytes[177..209])?,
        baseline: decode_vector(&bytes[385..561])?,
        account: ResourceAccount::from_usage(
            ResourceCeilings::bounded(decode_vector(&bytes[209..385])?),
            decode_vector(&bytes[561..737])?,
            decode_vector(&bytes[737..913])?,
        )?,
    };
    validate_head(head)?;
    Ok(head)
}

pub(super) fn encode_claim(claim: Claim) -> Result<[u8; CLAIM_BYTES], ResourceReservationErrorV1> {
    validate_claim(claim)?;
    let mut bytes = [0; CLAIM_BYTES];
    bytes[..8].copy_from_slice(CLAIM_MAGIC);
    if claim.purpose == ClaimPurpose::ControllerFirstGlobalPrefix {
        bytes[..8].copy_from_slice(b"AOSRSC04");
    }
    if claim.purpose == ClaimPurpose::NixOriginalStartIntake {
        bytes[..8].copy_from_slice(b"AOSRSC06");
    }
    if claim.purpose == ClaimPurpose::Q04OriginalIntake {
        bytes[..8].copy_from_slice(b"AOSRSC07");
    }
    if claim.purpose == ClaimPurpose::RootReceiving {
        bytes[..8].copy_from_slice(b"AOSRSC08");
    }
    if matches!(claim.purpose,
        ClaimPurpose::HostComponentBootstrap | ClaimPurpose::HostControlInterval)
    {
        bytes[..8].copy_from_slice(b"AOSRSC03");
    }
    encode_enrollment(claim.enrollment, &mut bytes[8..104]);
    bytes[104..120].copy_from_slice(&claim.id);
    bytes[120..136].copy_from_slice(&claim.account);
    bytes[136..152].copy_from_slice(&claim.child);
    bytes[152..184].copy_from_slice(&claim.owner);
    bytes[184] = match claim.purpose {
        ClaimPurpose::ControllerBootstrap => 1,
        ClaimPurpose::ComponentEnvelope => 2,
        ClaimPurpose::InclusiveGrant => 3,
        ClaimPurpose::Snapshot => 4,
        ClaimPurpose::ProjectPreparation => 5,
        ClaimPurpose::Q04Preparation => 6,
        ClaimPurpose::HostComponentBootstrap => 7,
        ClaimPurpose::HostControlInterval => 8,
        ClaimPurpose::ControllerFirstGlobalPrefix => 9,
        ClaimPurpose::NixOriginalStartIntake => 11,
        ClaimPurpose::Q04OriginalIntake => 12,
        ClaimPurpose::RootReceiving => 13,
    };
    bytes[185..201].copy_from_slice(&claim.operation);
    bytes[201..217].copy_from_slice(&claim.project);
    bytes[217..233].copy_from_slice(&claim.sandbox);
    bytes[233..265].copy_from_slice(&claim.tree_revision);
    if let ClaimCut::Operation {
        original_wall_seconds,
        original_boottime_nanoseconds,
        deadline_boottime_nanoseconds,
    } = claim.cut {
        bytes[265] = 1;
        bytes[266..274].copy_from_slice(&original_wall_seconds.to_be_bytes());
        bytes[274..282].copy_from_slice(&original_boottime_nanoseconds.to_be_bytes());
        bytes[282..290].copy_from_slice(&deadline_boottime_nanoseconds.to_be_bytes());
    }
    encode_vector(claim.amount, &mut bytes[290..466]);
    bytes[466] = match claim.state {
        ClaimState::Reserved => 1,
        ClaimState::Committed => 2,
        ClaimState::Released => 3,
    };
    bytes[467..499].copy_from_slice(&claim.genesis_instance);
    let checksum = Sha256::digest(&bytes[..499]);
    bytes[499..].copy_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn decode_claim(bytes: &[u8]) -> Result<Claim, ResourceReservationErrorV1> {
    let host = bytes.get(..8) == Some(b"AOSRSC03".as_slice());
    let first_global = bytes.get(..8) == Some(b"AOSRSC04".as_slice());
    let intake = bytes.get(..8) == Some(b"AOSRSC06".as_slice());
    let q04_intake = bytes.get(..8) == Some(b"AOSRSC07".as_slice());
    let root = bytes.get(..8) == Some(b"AOSRSC08".as_slice());
    if root {
        require_record(bytes, CLAIM_BYTES, b"AOSRSC08")?;
    } else if q04_intake {
        require_record(bytes, CLAIM_BYTES, b"AOSRSC07")?;
    } else if intake {
        require_record(bytes, CLAIM_BYTES, b"AOSRSC06")?;
    } else if first_global {
        require_record(bytes, CLAIM_BYTES, b"AOSRSC04")?;
    } else if host {
        require_record(bytes, CLAIM_BYTES, b"AOSRSC03")?;
    } else {
        require_record(bytes, CLAIM_BYTES, CLAIM_MAGIC)?;
    }
    let claim = Claim {
        enrollment: decode_enrollment(&bytes[8..104])?,
        id: fixed(&bytes[104..120])?,
        account: fixed(&bytes[120..136])?,
        child: fixed(&bytes[136..152])?,
        owner: fixed(&bytes[152..184])?,
        purpose: match bytes[184] {
            1 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::ControllerBootstrap,
            2 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::ComponentEnvelope,
            3 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::InclusiveGrant,
            4 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::Snapshot,
            5 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::ProjectPreparation,
            6 if !host && !first_global && !intake && !q04_intake && !root => ClaimPurpose::Q04Preparation,
            7 if host => ClaimPurpose::HostComponentBootstrap,
            8 if host => ClaimPurpose::HostControlInterval,
            9 if first_global => ClaimPurpose::ControllerFirstGlobalPrefix,
            11 if intake => ClaimPurpose::NixOriginalStartIntake,
            12 if q04_intake => ClaimPurpose::Q04OriginalIntake,
            13 if root => ClaimPurpose::RootReceiving,
            _ => return Err(ResourceReservationErrorV1::CorruptLedger),
        },
        operation: fixed(&bytes[185..201])?,
        project: fixed(&bytes[201..217])?,
        sandbox: fixed(&bytes[217..233])?,
        tree_revision: fixed(&bytes[233..265])?,
        cut: match bytes[265] {
            0 if bytes[266..290] == [0; 24] => ClaimCut::BootLifetime,
            1 => ClaimCut::Operation {
                original_wall_seconds: i64::from_be_bytes(fixed(&bytes[266..274])?),
                original_boottime_nanoseconds: u64::from_be_bytes(fixed(&bytes[274..282])?),
                deadline_boottime_nanoseconds: u64::from_be_bytes(fixed(&bytes[282..290])?),
            },
            _ => return Err(ResourceReservationErrorV1::CorruptLedger),
        },
        amount: decode_vector(&bytes[290..466])?,
        genesis_instance: fixed(&bytes[467..499])?,
        state: match bytes[466] {
            1 => ClaimState::Reserved,
            2 => ClaimState::Committed,
            3 => ClaimState::Released,
            _ => return Err(ResourceReservationErrorV1::CorruptLedger),
        },
    };
    validate_claim(claim)?;
    Ok(claim)
}

// This native association retains actual original joins, not a transferable
// Root or Source loan. The nested claim uses the same sole canonical codec.
pub(super) fn encode_preparation(binding: PreparationBinding) -> Result<[u8; PREPARATION_BYTES], ResourceReservationErrorV1> {
    if binding.claim.purpose != ClaimPurpose::ProjectPreparation
        || binding.nonce == [0; 16] || binding.source_sequence == 0
        || [binding.floor, binding.tree_head, binding.lineage_head].contains(&[0; 32])
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    let mut bytes = [0; PREPARATION_BYTES];
    bytes[..8].copy_from_slice(b"AOSRSP01");
    bytes[8..539].copy_from_slice(&encode_claim(binding.claim)?);
    bytes[539..555].copy_from_slice(&binding.nonce);
    bytes[555..603].copy_from_slice(&binding.controller_names.to_bytes());
    bytes[603..651].copy_from_slice(&binding.source_names.to_bytes());
    bytes[651..659].copy_from_slice(&binding.source_sequence.to_be_bytes());
    bytes[659..691].copy_from_slice(&binding.floor);
    bytes[691..723].copy_from_slice(&binding.tree_head);
    bytes[723..755].copy_from_slice(&binding.lineage_head);
    let checksum = Sha256::digest(&bytes[..755]);
    bytes[755..].copy_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn decode_preparation(bytes: &[u8]) -> Result<PreparationBinding, ResourceReservationErrorV1> {
    require_record(bytes, PREPARATION_BYTES, b"AOSRSP01")?;
    let binding = PreparationBinding {
        claim: decode_claim(&bytes[8..539])?,
        nonce: fixed(&bytes[539..555])?,
        controller_names: crate::journal::ProtectedJournalNamesV1::from_bytes(&bytes[555..603])
            .map_err(crate::journal::JournalError::from)?,
        source_names: crate::journal::ProtectedJournalNamesV1::from_bytes(&bytes[603..651])
            .map_err(crate::journal::JournalError::from)?,
        source_sequence: u64::from_be_bytes(fixed(&bytes[651..659])?),
        floor: fixed(&bytes[659..691])?,
        tree_head: fixed(&bytes[691..723])?,
        lineage_head: fixed(&bytes[723..755])?,
    };
    if encode_preparation(binding)?.as_slice() != bytes {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(binding)
}

fn validate_head(head: AccountHead) -> Result<(), ResourceReservationErrorV1> {
    validate_enrollment(head.enrollment)?;
    if head.id == [0; 16] || head.generation == 0
        || (head.kind == AccountKind::Node) != (head.parent == [0; 16])
        || head.id == head.parent
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    head.account.committed().checked_sub(head.baseline)?;
    match head.kind {
        AccountKind::Node | AccountKind::Controller | AccountKind::Components
            if head.project != [0; 16] || head.sandbox != [0; 16] || head.tree_revision != [0; 32] =>
                return Err(ResourceReservationErrorV1::CorruptLedger),
        AccountKind::Project if head.project == [0; 16] || head.sandbox != [0; 16]
            || head.tree_revision == [0; 32] => return Err(ResourceReservationErrorV1::CorruptLedger),
        AccountKind::Sandbox if head.project == [0; 16] || head.sandbox == [0; 16]
            || head.tree_revision == [0; 32] => return Err(ResourceReservationErrorV1::CorruptLedger),
        _ => {}
    }
    for dimension in ResourceDimension::ALL {
        if !matches!(head.account.ceilings().get(dimension), ResourceLimit::Bounded(_)) {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
    }
    Ok(())
}

fn validate_claim(claim: Claim) -> Result<(), ResourceReservationErrorV1> {
    validate_enrollment(claim.enrollment)?;
    if claim.id == [0; 16] || claim.account == [0; 16] || claim.owner == [0; 32]
        || claim.child == claim.account
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    match (claim.purpose, claim.cut) {
        (ClaimPurpose::RootReceiving, ClaimCut::BootLifetime)
            if claim.state == ClaimState::Reserved
            && claim.owner == claim.enrollment.manifest
            && claim.child == [0; 16] && claim.operation == [0; 16]
            && claim.project == [0; 16] && claim.sandbox == [0; 16]
            && claim.tree_revision == [0; 32] && claim.genesis_instance == [0; 32] => {}
        (ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
            | ClaimPurpose::Q04OriginalIntake,
            ClaimCut::BootLifetime)
            if matches!(claim.state, ClaimState::Reserved | ClaimState::Committed)
            && claim.owner == claim.enrollment.manifest
            && claim.child == [0; 16] && claim.operation == [0; 16]
            && claim.project == [0; 16] && claim.sandbox == [0; 16]
            && claim.tree_revision == [0; 32] && claim.genesis_instance == [0; 32] => {}
        (ClaimPurpose::HostComponentBootstrap | ClaimPurpose::HostControlInterval,
            ClaimCut::BootLifetime)
            if claim.state == ClaimState::Reserved
            && claim.owner == claim.enrollment.manifest
            && claim.operation == [0; 16] && claim.project == [0; 16]
            && claim.sandbox == [0; 16] && claim.tree_revision == [0; 32]
            && claim.genesis_instance == [0; 32]
            && ((claim.purpose == ClaimPurpose::HostComponentBootstrap
                && claim.child != [0; 16])
                || (claim.purpose == ClaimPurpose::HostControlInterval
                    && claim.child == [0; 16])) => {}
        (ClaimPurpose::ProjectPreparation, ClaimCut::Operation {
            original_boottime_nanoseconds, deadline_boottime_nanoseconds, ..
        }) if claim.operation != [0; 16] && claim.project != [0; 16]
            && claim.sandbox == [0; 16] && claim.tree_revision != [0; 32]
            && claim.child == [0; 16] && claim.genesis_instance != [0; 32]
            && original_boottime_nanoseconds < deadline_boottime_nanoseconds => {}
        (ClaimPurpose::Snapshot | ClaimPurpose::Q04Preparation, ClaimCut::Operation {
            original_boottime_nanoseconds, deadline_boottime_nanoseconds, ..
        }) if claim.operation != [0; 16] && claim.project != [0; 16]
            && claim.sandbox != [0; 16] && claim.tree_revision != [0; 32]
            && claim.child == [0; 16]
            && ((claim.purpose == ClaimPurpose::Snapshot && claim.genesis_instance == [0; 32])
                || (claim.purpose == ClaimPurpose::Q04Preparation && claim.genesis_instance != [0; 32]))
            && original_boottime_nanoseconds < deadline_boottime_nanoseconds => {}
        (ClaimPurpose::Snapshot | ClaimPurpose::Q04Preparation, _) =>
            return Err(ResourceReservationErrorV1::CorruptLedger),
        (ClaimPurpose::InclusiveGrant, ClaimCut::Operation {
            original_boottime_nanoseconds, deadline_boottime_nanoseconds, ..
        }) if claim.child != [0; 16] && claim.operation != [0; 16]
            && claim.genesis_instance != [0; 32] && claim.project != [0; 16]
            && claim.tree_revision != [0; 32]
            && original_boottime_nanoseconds < deadline_boottime_nanoseconds => {}
        (ClaimPurpose::ControllerBootstrap | ClaimPurpose::ComponentEnvelope, ClaimCut::BootLifetime)
            if claim.child != [0; 16]
            && claim.operation == [0; 16] && claim.genesis_instance == [0; 32] => {}
        _ => return Err(ResourceReservationErrorV1::CorruptLedger),
    }
    Ok(())
}

fn validate_enrollment(value: EnrollmentIdentity) -> Result<(), ResourceReservationErrorV1> {
    if value.node == [0; 16] || value.epoch == [0; 16] || value.boot == [0; 16]
        || value.invocation == [0; 16] || value.manifest == [0; 32]
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(())
}

fn encode_enrollment(value: EnrollmentIdentity, bytes: &mut [u8]) {
    bytes[..16].copy_from_slice(&value.node);
    bytes[16..32].copy_from_slice(&value.epoch);
    bytes[32..48].copy_from_slice(&value.boot);
    bytes[48..64].copy_from_slice(&value.invocation);
    bytes[64..96].copy_from_slice(&value.manifest);
}

fn decode_enrollment(bytes: &[u8]) -> Result<EnrollmentIdentity, ResourceReservationErrorV1> {
    let value = EnrollmentIdentity {
        node: fixed(&bytes[..16])?,
        epoch: fixed(&bytes[16..32])?,
        boot: fixed(&bytes[32..48])?,
        invocation: fixed(&bytes[48..64])?,
        manifest: fixed(&bytes[64..96])?,
    };
    validate_enrollment(value)?;
    Ok(value)
}

fn encode_vector(vector: ResourceVector, bytes: &mut [u8]) {
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        bytes[index * 8..(index + 1) * 8].copy_from_slice(&vector.get(dimension).to_be_bytes());
    }
}

fn decode_vector(bytes: &[u8]) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let mut values = [0; ResourceDimension::COUNT];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        let slot = values.get_mut(index).ok_or(ResourceReservationErrorV1::CorruptLedger)?;
        *slot = u64::from_be_bytes(fixed(chunk)?);
    }
    if bytes.len() != ResourceDimension::COUNT * 8 {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(ResourceVector::new(values))
}

fn require_record(bytes: &[u8], length: usize, magic: &[u8; 8]) -> Result<(), ResourceReservationErrorV1> {
    if bytes.len() != length || &bytes[..8] != magic
        || Sha256::digest(&bytes[..length - 32])[..] != bytes[length - 32..]
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ResourceReservationErrorV1> {
    bytes.try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)
}

#[cfg(test)]
mod image_policy_tests {
    use sha2::{Digest as _, Sha256};

    use super::{
        FIRST_GLOBAL_IMAGE_POLICY_BYTES, HOST_IMAGE_POLICY_BYTES, IMAGE_POLICY_BYTES,
        ImageBootstrapPolicy, NIX_INTAKE_IMAGE_POLICY_BYTES, Q04_INTAKE_IMAGE_POLICY_BYTES,
        ROOT_IMAGE_POLICY_BYTES, ResourceDimension, ResourceReservationErrorV1, ResourceVector,
        decode_image_policy, encode_vector,
    };
    use crate::controller_resource_reservation::HostComponentPolicy;

    const FORMATS: [(&[u8; 8], usize); 6] = [
        (b"AOSRSB01", IMAGE_POLICY_BYTES),
        (b"AOSRSB02", HOST_IMAGE_POLICY_BYTES),
        (b"AOSRSB03", FIRST_GLOBAL_IMAGE_POLICY_BYTES),
        (b"AOSRSB04", NIX_INTAKE_IMAGE_POLICY_BYTES),
        (b"AOSRSB05", Q04_INTAKE_IMAGE_POLICY_BYTES),
        (b"AOSRSB06", ROOT_IMAGE_POLICY_BYTES),
    ];

    // These bytes describe a policy only; no original file or paid owner exists.
    fn fixture(version: usize) -> (ImageBootstrapPolicy, Vec<u8>) {
        let subdivision = ResourceVector::new([1; ResourceDimension::COUNT])
            .with(ResourceDimension::CpuMicrosPerPeriod, 1000)
            .with(ResourceDimension::MemoryBytes, 4096)
            .with(ResourceDimension::Pids, 2)
            .with(ResourceDimension::OpenFiles, 80);
        let policy = ImageBootstrapPolicy {
            node: [1; 16],
            epoch: [2; 16],
            capacity: ResourceVector::new([100_000_000; ResourceDimension::COUNT]),
            baseline: ResourceVector::new([1_000_000; ResourceDimension::COUNT]),
            controller: ResourceVector::new([50_000_000; ResourceDimension::COUNT]),
            components: ResourceVector::new([20_000_000; ResourceDimension::COUNT]),
            host: (version >= 2).then_some(HostComponentPolicy {
                service: subdivision,
                control: subdivision.with(ResourceDimension::Pids, 3),
            }),
            first_global_prefix: (version >= 3).then_some(subdivision),
            nix_original_start_intake: (version >= 4)
                .then_some(subdivision.with(ResourceDimension::Pids, 4)),
            q04_original_intake: (version >= 5).then_some(ResourceVector::new(
                [2 * 1024 * 1024; ResourceDimension::COUNT],
            )),
            root_receiving: (version >= 6).then_some(subdivision),
        };
        let (magic, length) = FORMATS[version - 1];
        let mut bytes = vec![0; length];
        bytes[..8].copy_from_slice(magic);
        bytes[8..24].copy_from_slice(&policy.node);
        bytes[24..40].copy_from_slice(&policy.epoch);
        for (offset, vector) in [
            (40, policy.capacity),
            (216, policy.baseline),
            (392, policy.controller),
            (568, policy.components),
        ] {
            encode_vector(vector, &mut bytes[offset..offset + 176]);
        }
        if let Some(host) = policy.host {
            encode_vector(host.service, &mut bytes[744..920]);
            encode_vector(host.control, &mut bytes[920..1096]);
        }
        for (offset, vector) in [
            (1096, policy.first_global_prefix),
            (1272, policy.nix_original_start_intake),
            (1448, policy.q04_original_intake),
            (1624, policy.root_receiving),
        ] {
            if let Some(vector) = vector {
                encode_vector(vector, &mut bytes[offset..offset + 176]);
            }
        }
        refresh_checksum(&mut bytes);
        (policy, bytes)
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let body_end = bytes.len() - 32;
        let checksum = Sha256::digest(&bytes[..body_end]);
        bytes[body_end..].copy_from_slice(&checksum);
    }

    #[test]
    fn all_image_policy_formats_preserve_vectors_and_optional_fields() {
        for version in 1..=6 {
            let (expected, bytes) = fixture(version);

            let actual = decode_image_policy(&bytes).unwrap();

            assert_eq!(actual, expected, "version {version}");
            assert_eq!(actual.host.is_some(), version >= 2);
            assert_eq!(actual.first_global_prefix.is_some(), version >= 3);
            assert_eq!(actual.nix_original_start_intake.is_some(), version >= 4);
            assert_eq!(actual.q04_original_intake.is_some(), version >= 5);
            assert_eq!(actual.root_receiving.is_some(), version >= 6);
        }
    }

    #[test]
    fn every_image_policy_short_prefix_and_trailing_byte_is_corrupt() {
        for version in 1..=6 {
            let (_, mut bytes) = fixture(version);

            for end in 0..bytes.len() {
                assert!(
                    matches!(
                        decode_image_policy(&bytes[..end]),
                        Err(ResourceReservationErrorV1::CorruptLedger)
                    ),
                    "version {version}, prefix {end}"
                );
            }
            bytes.push(0);

            assert!(
                matches!(
                    decode_image_policy(&bytes),
                    Err(ResourceReservationErrorV1::CorruptLedger)
                ),
                "version {version}, trailing byte"
            );
        }
    }

    #[test]
    fn image_policy_framing_refuses_before_semantic_validation() {
        for version in 1..=6 {
            let (_, bytes) = fixture(version);

            for (other_magic, _) in FORMATS {
                if other_magic == FORMATS[version - 1].0 {
                    continue;
                }
                let mut wrong_width = bytes.clone();
                wrong_width[..8].copy_from_slice(other_magic);
                wrong_width[8..24].fill(0);
                refresh_checksum(&mut wrong_width);

                assert!(matches!(
                    decode_image_policy(&wrong_width),
                    Err(ResourceReservationErrorV1::CorruptLedger)
                ));
            }

            let mut unknown = bytes.clone();
            unknown[..8].copy_from_slice(b"AOSRSB07");
            unknown[8..24].fill(0);
            refresh_checksum(&mut unknown);

            assert!(matches!(
                decode_image_policy(&unknown),
                Err(ResourceReservationErrorV1::CorruptLedger)
            ));

            let mut bad_checksum = bytes.clone();
            bad_checksum[8..24].fill(0);

            assert!(matches!(
                decode_image_policy(&bad_checksum),
                Err(ResourceReservationErrorV1::CorruptLedger)
            ));

            let mut zero_identity = bytes;
            zero_identity[8..24].fill(0);
            refresh_checksum(&mut zero_identity);

            assert!(matches!(
                decode_image_policy(&zero_identity),
                Err(ResourceReservationErrorV1::EnrollmentUnavailable)
            ));
        }
    }

    #[test]
    fn image_policy_q_failure_precedes_invalid_root_service() {
        let (expected, mut bytes) = fixture(6);
        let minimum =
            crate::controller_resource_reservation::q04_intake::minimum_failure_demand().unwrap();
        let undersized = minimum.with(ResourceDimension::MemoryBytes, 0);
        encode_vector(undersized, &mut bytes[1448..1624]);
        encode_vector(ResourceVector::ZERO, &mut bytes[1624..1800]);
        refresh_checksum(&mut bytes);

        assert!(matches!(
            decode_image_policy(&bytes),
            Err(ResourceReservationErrorV1::Accounting(
                aos_sandbox_core::AccountingError::InsufficientAmount {
                    dimension: ResourceDimension::MemoryBytes,
                    available: 0,
                    requested,
                }
            )) if requested == minimum.get(ResourceDimension::MemoryBytes)
        ));

        encode_vector(
            ResourceVector::new([2 * 1024 * 1024; ResourceDimension::COUNT]),
            &mut bytes[1448..1624],
        );
        refresh_checksum(&mut bytes);

        assert!(matches!(
            decode_image_policy(&bytes),
            Err(ResourceReservationErrorV1::EnrollmentUnavailable)
        ));

        encode_vector(expected.root_receiving.unwrap(), &mut bytes[1624..1800]);
        refresh_checksum(&mut bytes);

        assert_eq!(decode_image_policy(&bytes).unwrap(), expected);
    }
}
