//! Actual framed-child custody controls; typed metadata grants no source authority.

#[path = "extension_attachment_tests/peer.rs"]
mod peer;

use super::*;
use peer::Peer;

#[test]
fn source_policy_refusal_retains_original_typed_child_before_discovery() {
    let mut peer = Peer::launch();
    let pid = peer.guard.as_ref().unwrap().provider_pid();
    let slot = peer.guard.as_ref().unwrap().supervision_id();
    let controller = peer.controller.take().unwrap();
    let selected = controller.selected_extensions().unwrap().to_vec();
    let registrar = peer.registrar.take().unwrap();
    let guard = peer.guard.take().unwrap();
    let guard = guard.attach_extensions(controller, registrar).ok().unwrap();

    // The existing source policy intentionally has no typed opt-in. A genuine
    // Hello cannot authorize discovery, realization or a native companion.
    let failure = CnpReferencePreparation::prepare(guard, &peer.installed)
        .err()
        .unwrap();
    assert_eq!(
        failure.error.effects,
        crate::node_contract::EffectKnowledge::None
    );
    assert_eq!(failure.guard.provider_pid(), pid);
    assert_eq!(failure.guard.supervision_id(), slot);
    let custody = failure.guard.custody.as_ref().unwrap();
    assert!(custody.preparation_started);
    assert!(custody.companion.is_none());
    assert_eq!(
        custody.controller.as_ref().unwrap().selected_extensions(),
        Some(selected.as_slice())
    );
    let super::super::process::CnpRegistrar::Extensions(registrar) =
        custody.handshake.as_ref().unwrap()
    else {
        panic!("the same original typed registrar was lost");
    };
    custody
        .controller
        .as_ref()
        .unwrap()
        .verify_extension_registrar(registrar)
        .unwrap();

    peer.guard = Some(failure.guard);
    peer.finish();
    assert!(!peer.path().join("unexpected-control.json").exists());
}

#[test]
fn foreign_original_child_refusal_returns_all_unchanged_attachment_owners() {
    let mut first = Peer::launch();
    let mut second = Peer::launch();
    let first_pid = first.guard.as_ref().unwrap().provider_pid();
    let second_pid = second.controller.as_ref().unwrap().peer_pid();
    let controller = second.controller.take().unwrap();
    let selected = controller.selected_extensions().unwrap().to_vec();
    let registrar = second.registrar.take().unwrap();

    let refused = first
        .guard
        .take()
        .unwrap()
        .attach_extensions(controller, registrar)
        .err()
        .unwrap();

    assert_eq!(refused.guard.provider_pid(), first_pid);
    assert_eq!(refused.controller.peer_pid(), second_pid);
    assert_eq!(
        refused.controller.selected_extensions(),
        Some(selected.as_slice())
    );
    refused
        .controller
        .verify_extension_registrar(&refused.registrar)
        .unwrap();
    assert!(refused.guard.custody.as_ref().unwrap().controller.is_none());
    first.guard = Some(refused.guard);
    second.guard = Some(
        second
            .guard
            .take()
            .unwrap()
            .attach_extensions(refused.controller, refused.registrar)
            .ok()
            .unwrap(),
    );
    first.finish();
    second.finish();
}

#[test]
fn duplicate_attachment_and_revoked_registrar_preserve_original_child_and_journals() {
    let mut peer = Peer::launch();
    let mut other = Peer::launch();
    let pid = peer.guard.as_ref().unwrap().provider_pid();
    peer.guard = Some(
        peer.guard
            .take()
            .unwrap()
            .attach_extensions(
                peer.controller.take().unwrap(),
                peer.registrar.take().unwrap(),
            )
            .ok()
            .unwrap(),
    );
    let refused = peer
        .guard
        .take()
        .unwrap()
        .attach_extensions(
            other.controller.take().unwrap(),
            other.registrar.take().unwrap(),
        )
        .err()
        .unwrap();
    assert_eq!(refused.guard.provider_pid(), pid);
    assert_eq!(
        refused
            .guard
            .custody
            .as_ref()
            .unwrap()
            .controller
            .as_ref()
            .unwrap()
            .peer_pid(),
        pid.unwrap()
    );
    peer.guard = Some(refused.guard);
    other.controller = Some(refused.controller);
    other.registrar = Some(refused.registrar);

    // Revoking that actual peer's gate must not turn a returned controller into
    // an attachable fresh lease, even though every wire tuple still matches.
    other.registrar.as_mut().unwrap().contain();
    let refused = other
        .guard
        .take()
        .unwrap()
        .attach_extensions(
            other.controller.take().unwrap(),
            other.registrar.take().unwrap(),
        )
        .err()
        .unwrap();
    assert_eq!(
        refused.guard.provider_pid(),
        Some(refused.controller.peer_pid())
    );
    assert!(
        refused
            .controller
            .verify_extension_registrar(&refused.registrar)
            .is_err()
    );
    assert!(refused.guard.custody.as_ref().unwrap().controller.is_none());
    other.guard = Some(refused.guard);
    other.controller = Some(refused.controller);
    other.registrar = Some(refused.registrar);
    peer.finish();
    other.finish();
}
