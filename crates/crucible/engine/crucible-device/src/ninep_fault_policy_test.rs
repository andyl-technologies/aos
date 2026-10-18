//! 9p fault-directive and visibility-policy tests.

use std::collections::BTreeMap;

use super::test_support::*;
use super::*;
fn file_object(path: &str, version: u32, data: &[u8]) -> NinepObjectVersion {
    NinepObjectVersion {
        path: path.to_owned(),
        version,
        mode: 0o100_644,
        data: data.to_vec(),
        deleted: false,
    }
}

fn install_result(dev: &mut NinepDevice, t: u64, request: &[u8], result: NinepResultDirective) {
    let sequence = u32::from(u16::from_le_bytes([request[5], request[6]]));
    let mut directive = ResolvedNinepRequestDirective::fault_free(t, sequence, request)
        .unwrap_or_else(|error| panic!("valid directive: {error}"));
    directive.result = result;
    ok(dev.install_fault_directive(t, sequence, request, directive));
}

#[test]
fn required_directive_is_fail_closed_and_preserves_server_state() {
    let mut dev = device();
    dev.require_fault_directives();
    let request = tattach(2, 1);
    let error = dev
        .submit(0, &request)
        .expect_err("missing exact directive must fail");
    assert!(matches!(
        error,
        crate::DeviceError::MissingNinepFaultDirective { tag: 2 }
    ));
    assert!(dev.server().fids().is_empty());
}

#[test]
fn errno_directive_returns_rlerror_without_attach_side_effects() {
    let mut dev = device();
    dev.require_fault_directives();
    let request = tattach(2, 1);
    install_result(
        &mut dev,
        0,
        &request,
        NinepResultDirective::Errno(errno::EIO),
    );
    let (_, reply) = round_trip(&mut dev, 0, &request);
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::EIO);
    assert!(dev.server().fids().is_empty());
    assert!(dev.snapshot().directives.is_empty());
}

#[test]
fn stale_read_uses_exact_object_bytes_and_survives_restore_before_consumption() {
    let mut dev = device();
    dev.require_fault_directives();
    let request = tread(9, 55, 1, 3);
    install_result(
        &mut dev,
        7,
        &request,
        NinepResultDirective::Stale(file_object("/captured", 4, b"ABCDE")),
    );
    let snapshot = dev.snapshot();
    let mut restored = ok(NinepDevice::restore(&snapshot, sample_tree()));
    let (_, reply) = round_trip(&mut restored, 7, &request);
    assert_eq!(reply_type(&reply), codec::RREAD);
    assert_eq!(&reply[11..], b"BCD");
    assert!(restored.snapshot().directives.is_empty());
}

fn atomic_visibility(retain_deleted_objects: bool) -> NinepVisibilityPolicy {
    NinepVisibilityPolicy {
        scope: NinepVisibilityScope::Global,
        atomic_metadata_and_data: true,
        retain_deleted_objects,
    }
}

#[test]
fn visible_deletion_hides_base_tree_and_already_walked_fids() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &twalk(3, 1, 2, &["alpha"]));
    let deletion = NinepObjectVersion {
        path: String::from("/alpha"),
        version: 2,
        mode: 0,
        data: Vec::new(),
        deleted: true,
    };
    ok(dev.commit_visibility_update(
        [7; 32],
        deletion,
        atomic_visibility(true),
        NinepVisibilityRelease::AtNanos(0),
        0,
    ));
    ok(dev.advance_visibility(0, &BTreeMap::new()));

    let (_, existing) = round_trip(&mut dev, 3, &tread(4, 2, 0, 8));
    assert_eq!(reply_type(&existing), codec::RLERROR);
    assert_eq!(rlerror_code(&existing), errno::ENOENT);
    let (_, new_walk) = round_trip(&mut dev, 4, &twalk(5, 1, 3, &["alpha"]));
    assert_eq!(reply_type(&new_walk), codec::RLERROR);
    assert_eq!(rlerror_code(&new_walk), errno::ENOENT);
}

#[test]
fn visible_creation_is_discoverable_by_normal_walk_and_tracks_updates() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    ok(dev.commit_visibility_update(
        [1; 32],
        file_object("/new", 1, b"first"),
        atomic_visibility(false),
        NinepVisibilityRelease::AtNanos(0),
        0,
    ));
    ok(dev.advance_visibility(0, &BTreeMap::new()));
    let (_, walked) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["new"]));
    assert_eq!(reply_type(&walked), codec::RWALK);
    let (_, first) = round_trip(&mut dev, 3, &tread(4, 2, 0, 16));
    assert_eq!(&first[11..], b"first");

    ok(dev.commit_visibility_update(
        [2; 32],
        file_object("/new", 2, b"second"),
        atomic_visibility(false),
        NinepVisibilityRelease::AtNanos(0),
        0,
    ));
    ok(dev.advance_visibility(0, &BTreeMap::new()));
    let (_, second) = round_trip(&mut dev, 4, &tread(5, 2, 0, 16));
    assert_eq!(&second[11..], b"second");
}

#[test]
fn visible_walk_never_traverses_through_a_regular_object() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    for (identity, object) in [
        ([3; 32], file_object("/a", 1, b"regular")),
        ([4; 32], file_object("/a/b", 1, b"unreachable")),
    ] {
        ok(dev.commit_visibility_update(
            identity,
            object,
            atomic_visibility(false),
            NinepVisibilityRelease::AtNanos(0),
            0,
        ));
    }
    ok(dev.advance_visibility(0, &BTreeMap::new()));
    let (_, walked) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["a", "b"]));
    assert_eq!(reply_type(&walked), codec::RWALK);
    assert_eq!(u16::from_le_bytes([walked[7], walked[8]]), 1);
}

#[test]
fn unsupported_object_result_shapes_are_rejected_before_installation() {
    let mut dev = device();
    for request in [tstatfs(8, 1), twalk(9, 1, 2, &["bin", "tool"])] {
        let sequence = u32::from(u16::from_le_bytes([request[5], request[6]]));
        let mut directive = ResolvedNinepRequestDirective::fault_free(4, sequence, &request)
            .unwrap_or_else(|error| panic!("valid request identity: {error}"));
        directive.result = NinepResultDirective::Stale(file_object("/x", 1, b"x"));
        assert!(
            dev.install_fault_directive(4, sequence, &request, directive)
                .is_err()
        );
    }
}

#[test]
fn fault_resource_usage_tracks_sessions_fids_and_object_versions() {
    let mut dev = device();
    assert_eq!(
        ok(dev.fault_resource_usage()),
        NinepFaultResourceUsage {
            sessions: 1,
            fids: 0,
            object_versions: 0,
        }
    );

    let attach = tattach(2, 1);
    assert_eq!(dev.potential_fid_growth(&attach, false), 1);
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &attach);
    assert_eq!(dev.potential_fid_growth(&attach, false), 0);

    let update_id = [9; 32];
    ok(dev.commit_visibility_update(
        update_id,
        file_object("/retained", 1, b"version-one"),
        atomic_visibility(false),
        NinepVisibilityRelease::AtNanos(0),
        0,
    ));
    assert!(dev.contains_visibility_update(&update_id));
    assert_eq!(
        ok(dev.fault_resource_usage()),
        NinepFaultResourceUsage {
            sessions: 1,
            fids: 1,
            object_versions: 1,
        }
    );

    let next_session = tversion(3, MAX_MSIZE, codec::PROTOCOL_VERSION);
    assert_eq!(dev.potential_session_growth(&next_session), 1);
    let stale_read = tread(4, 55, 0, 4);
    install_result(
        &mut dev,
        2,
        &stale_read,
        NinepResultDirective::Stale(file_object("/stale", 2, b"stale")),
    );
    assert_eq!(
        ok(dev.fault_resource_usage()),
        NinepFaultResourceUsage {
            sessions: 1,
            fids: 1,
            object_versions: 2,
        }
    );

    round_trip(&mut dev, 3, &next_session);
    assert_eq!(dev.potential_session_growth(&next_session), 0);
    assert_eq!(
        ok(dev.fault_resource_usage()),
        NinepFaultResourceUsage {
            sessions: 2,
            fids: 0,
            object_versions: 2,
        }
    );
}
