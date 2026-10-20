//! Pure complete-cut preimage regressions; no native or signature admission.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::Audience;
use crate::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2;

// As in the existing private outcome-carrier tests, this assembles model DATA
// within its owning module. It supplies no native original or verified signer.
fn outcome_data() -> AuthenticatedBrokerMethodOutcomeV1 {
    let method = BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
    let envelope = validate_decoded_request_envelope(BrokerRequestEnvelope {
        method: method.into(), body: vec![1], ..Default::default()
    }, aos_sandbox_model::ProtocolId::HostBroker, 0).unwrap();
    let request = AuthenticatedBrokerMethodRequestV1 {
        direction: AuthenticatedBrokerRequestDirectionV1::ClientSend,
        method, semantics: AuthenticatedBrokerMethodSemanticsV1::HostInventoryRuntime,
        canonical_packet: vec![1, 2], exact_body: vec![1], semantic_commitment: [1; 32],
        catalog_binding: None, published_catalog_binding: None,
        peer: PeerCredentials { uid: 0, gid: 0, pid: Some(9) },
        peer_policy: PeerPolicy { uid: 0, gid: Some(0), audience: Audience::AUDIENCE_NODE_CONTROLLER },
        session_binding: [2; 32], request_id: [3; 16], client_sequence: 1,
        maximum_response_bytes: 8192, deadline_boottime_nanoseconds: 100,
        signed_request_digest: [4; 32], envelope, outcome_context: RequestOutcomeContextV1::None,
    };
    AuthenticatedBrokerMethodOutcomeV1 {
        direction: AuthenticatedBrokerOutcomeDirectionV1::ClientReceive,
        method, canonical_packet: vec![3, 4], request, broker_sequence: 1,
        result: AuthenticatedBrokerMethodResultV1::Success {
            semantic_commitment: [5; 32], exact_body: Vec::new(),
            filesystem_worker_qualification_commitment: None,
        },
    }
}

fn cut(outcome: &AuthenticatedBrokerMethodOutcomeV1) -> DeleteSessionInventoryCutDataV2<'_> {
    DeleteSessionInventoryCutDataV2 { role: 1, outcome, kernel_boot: [6; 16],
        native: (7, 8, 9, 10), protected: (11, [12; 32]), inventory: (13, [14; 32]), count: 0 }
}

#[test]
fn complete_cut_separates_native_protected_inventory_and_full_packet_preimages() {
    let outcome = outcome_data();
    let expected = cut(&outcome).owner_cut_data_v2().unwrap();

    let mut changed = cut(&outcome);
    changed.native.1 += 1;
    assert_ne!(changed.owner_cut_data_v2().unwrap(), expected);
    let mut changed = cut(&outcome);
    changed.protected.0 += 1;
    assert_ne!(changed.owner_cut_data_v2().unwrap(), expected);
    let mut changed = cut(&outcome);
    changed.inventory.0 += 1;
    assert_ne!(changed.owner_cut_data_v2().unwrap(), expected);
    let mut changed = cut(&outcome);
    changed.count = 1;
    assert_ne!(changed.owner_cut_data_v2().unwrap(), expected);

    let mut changed_packet = outcome.clone();
    changed_packet.request.canonical_packet[1] ^= 1;
    assert_ne!(cut(&changed_packet).owner_cut_data_v2().unwrap(), expected);
    let mut changed_packet = outcome.clone();
    changed_packet.canonical_packet[1] ^= 1;
    assert_ne!(cut(&changed_packet).owner_cut_data_v2().unwrap(), expected);
}

#[test]
fn cross_role_direction_and_missing_native_boundary_cannot_be_encoded_as_the_same_cut() {
    let outcome = outcome_data();
    let mut changed = cut(&outcome);
    changed.role = 2;
    assert!(changed.owner_cut_data_v2().is_err());
    let mut changed = cut(&outcome);
    changed.native.0 = 0;
    assert!(changed.owner_cut_data_v2().is_err());
    let mut changed = cut(&outcome);
    changed.kernel_boot = [0; 16];
    assert!(changed.owner_cut_data_v2().is_err());
    let mut changed = outcome.clone();
    changed.direction = AuthenticatedBrokerOutcomeDirectionV1::ServerSend;
    assert!(cut(&changed).owner_cut_data_v2().is_err());
}
