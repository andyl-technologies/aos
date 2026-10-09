//! Exact codec, allowance and physical-versus-logical contract controls.

use super::*;

fn record() -> NativeConsoleRecord {
    NativeConsoleRecord {
        owner: NativeConsoleOwner {
            slot: 2,
            region: [7; 16],
            process: 9,
            authorization: 11,
        },
        origin: NativeConsoleOrigin {
            stream: 3,
            logical_generation: 4,
            node_sequence: 1,
            stream_sequence: 1,
            logical_ps: 501,
            raw_prefix: 10,
            vcpu: 1,
            byte: 0xff,
        },
        authorization_advance: 12,
        phase: NativeConsolePhase::Grant,
    }
}

fn plan() -> NativeConsolePlan {
    NativeConsolePlan {
        slot: 2,
        logical_generation: 4,
        node_sequence_base: 0,
        streams: vec![NativeConsoleStream {
            stream: 3,
            device: NativeConsoleDevice::Serial16550,
            device_identity: [1; 32],
            owner_mask: 0b11,
            sequence_base: 0,
        }],
    }
}

fn authorization() -> NativeConsoleAuthorization {
    NativeConsoleAuthorization {
        publication: 2,
        owner: record().owner,
        logical_generation: 4,
        advance: 12,
        prior_sequence: 0,
        prior_ring_end: 0,
        allowance: 2,
        phase_token: 1,
        phase: NativeConsolePhase::Grant,
    }
}

#[test]
fn native_console_exact_record_refuses_unknown_and_noncanonical_fields()
-> Result<(), NativeConsoleError> {
    let value = record();
    let bytes = value.encode()?;
    assert_eq!(&bytes[..8], b"NCOR\x01\x00\x80\x00");
    assert_eq!(&bytes[72..80], &501_u64.to_le_bytes());
    assert_eq!(bytes[101], 0xff);
    assert_eq!(NativeConsoleRecord::decode(&bytes), Ok(value));
    assert!(NativeConsoleRecord::decode(&bytes[..127]).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(NativeConsoleRecord::decode(&trailing).is_err());
    for at in [0, 4, 6, 12, 32, 40, 56, 64, 88, 96, 100, 102, 127] {
        let mut corrupt = bytes;
        if matches!(at, 12 | 32 | 40 | 56 | 64) {
            let length = if at == 12 { 4 } else { 8 };
            corrupt[at..at + length].fill(0);
        } else {
            corrupt[at] = if at == 96 { 64 } else { 0xff };
        }
        assert!(
            NativeConsoleRecord::decode(&corrupt).is_err(),
            "offset {at}"
        );
    }
    Ok(())
}

#[test]
fn native_console_plan_refuses_unsorted_shapes_and_unsupported_vm_owners()
-> Result<(), NativeConsoleError> {
    let value = plan();
    let bytes = value.encode()?;
    assert_eq!(bytes.len(), 128);
    assert_eq!(NativeConsolePlan::decode(&bytes), Ok(value.clone()));
    assert!(value.validate_vm_shape(1).is_err());
    assert!(value.validate_vm_shape(2).is_ok());
    assert!(value.validate_vm_shape(64).is_ok());
    assert!(value.validate_vm_shape(65).is_err());
    let mut duplicates = value.clone();
    duplicates.streams.push(duplicates.streams[0].clone());
    assert!(duplicates.encode().is_err());
    let mut reserved = bytes.clone();
    reserved[127] = 1;
    assert!(NativeConsolePlan::decode(&reserved).is_err());
    let mut foreign_kind = bytes.clone();
    foreign_kind[68] = 3;
    assert!(NativeConsolePlan::decode(&foreign_kind).is_err());
    let mut other_capacity = bytes.clone();
    put32(&mut other_capacity, 24, 4095);
    assert!(NativeConsolePlan::decode(&other_capacity).is_err());
    let mut empty = value;
    empty.streams.clear();
    assert_eq!(NativeConsolePlan::decode(&empty.encode()?), Ok(empty));
    Ok(())
}

#[test]
fn native_console_capability_and_frontier_preserve_exact_distinct_publications()
-> Result<(), NativeConsoleError> {
    let capability = NativeConsoleCapability {
        slot: 2,
        region: [7; 16],
        process: 9,
        plan_hash: plan().digest()?,
        resolved_streams: [5; 32],
    };
    let bytes = capability.encode()?;
    assert_eq!(NativeConsoleCapability::decode(&bytes), Ok(capability));
    let mut unsupported = bytes;
    put32(&mut unsupported, 8, 0b1111);
    assert!(NativeConsoleCapability::decode(&unsupported).is_err());
    let frontier = NativeConsoleFrontier {
        sequence: 1,
        ring_end: 1,
        logical_ps: 501,
        raw_prefix: 10,
        owner: record().owner,
        accepted_advance: 14,
        logical_generation: 4,
        request: 0,
        plan_hash: capability.plan_hash,
    };
    let bytes = frontier.encode()?;
    assert_eq!(NativeConsoleFrontier::decode(&bytes), Ok(frontier));
    assert_ne!(frontier.accepted_advance, record().authorization_advance);
    let mut unsealed = bytes;
    put32(&mut unsealed, 120, 0);
    assert!(NativeConsoleFrontier::decode(&unsealed).is_err());
    let mut odd = frontier;
    odd.request = 1;
    assert!(odd.encode().is_err());
    let mut in_progress = bytes;
    put64(&mut in_progress, 40, 15);
    assert!(NativeConsoleFrontier::decode(&in_progress).is_err());
    let mut grant = authorization().encode()?;
    put64(&mut grant, 48, 13);
    assert!(NativeConsoleAuthorization::decode(&grant).is_err());

    // Coherent zero snapshots remain shape-valid, never execution authority.
    let mut zero = record();
    zero.authorization_advance = 0;
    assert!(zero.encode().is_ok());
    let mut zero = authorization();
    zero.advance = 0;
    assert!(zero.encode().is_ok());
    let mut zero = frontier;
    zero.accepted_advance = 0;
    assert!(zero.encode().is_ok());
    Ok(())
}

#[test]
fn native_console_reobserved_grant_cannot_refill_or_bypass_complete_drain()
-> Result<(), NativeConsoleError> {
    let grant = authorization();
    assert_eq!(
        NativeConsoleAuthorization::decode(&grant.encode()?),
        Ok(grant)
    );
    let mut ledger = NativeConsoleAllowance::default();
    ledger.observe(grant, 0, 0)?;
    ledger.preflight(2)?;
    ledger.charge(1)?;
    ledger.observe(
        NativeConsoleAuthorization {
            publication: 4,
            ..grant
        },
        0,
        0,
    )?;
    assert_eq!(ledger.remaining(), 1);
    let changed = NativeConsoleAuthorization {
        allowance: 1,
        publication: 6,
        ..grant
    };
    assert!(ledger.observe(changed, 0, 0).is_err());
    assert!(ledger.preflight(2).is_err());
    assert_eq!(ledger.remaining(), 1);
    ledger.charge(1)?;
    let next = NativeConsoleAuthorization {
        owner: NativeConsoleOwner {
            authorization: 12,
            ..grant.owner
        },
        publication: 6,
        prior_sequence: 2,
        prior_ring_end: 2,
        ..grant
    };
    assert!(ledger.observe(next, 2, 1).is_err());
    assert!(ledger.observe(next, 1, 2).is_err());
    ledger.observe(next, 2, 2)?;
    assert!(ledger.observe(grant, 0, 0).is_err());
    assert_eq!(ledger.remaining(), 2);

    let mut overflow = NativeConsoleAllowance::default();
    let last = NativeConsoleAuthorization {
        prior_sequence: u64::MAX,
        ..grant
    };
    overflow.observe(last, u64::MAX, 0)?;
    assert!(overflow.preflight(1).is_err());
    Ok(())
}

#[test]
fn native_console_physical_binding_changes_never_restamp_logical_origin()
-> Result<(), NativeConsoleError> {
    let original = record();
    let moved = NativeConsoleRecord {
        owner: NativeConsoleOwner {
            slot: 5,
            region: [8; 16],
            process: 21,
            authorization: 27,
        },
        authorization_advance: 32,
        ..original
    };
    assert_ne!(original.encode()?, moved.encode()?);
    assert_eq!(original.origin, moved.origin);
    let mut changed = moved;
    changed.origin.raw_prefix += 1;
    assert_ne!(original.origin, changed.origin);
    let mut moved_plan = plan();
    moved_plan.slot = 5;
    assert_ne!(plan().digest()?, moved_plan.digest()?);
    assert_eq!(plan().streams, moved_plan.streams);
    Ok(())
}
