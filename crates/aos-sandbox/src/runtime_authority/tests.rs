//! Pure codec and model tests for protected runtime-authority records.

#![allow(clippy::unwrap_used)]

use aos_sandbox_core::{ObjectDigest, OperationId, PrincipalId};

use super::*;
use crate::publication::tests::descriptor_free_activation_fixture;

fn pending(state: RuntimeAuthorityStateV1) -> RuntimeAuthorityPendingV1 {
    let (draft, _) = descriptor_free_activation_fixture(1);
    RuntimeAuthorityPendingV1 {
        operation: OperationId::from_bytes([31; 16]),
        request_digest: [32; 32],
        state,
        holder: (state == RuntimeAuthorityStateV1::Bound)
            .then_some(PrincipalId::from_bytes([33; 16])),
        expected_revision: None,
        revision: 1,
        predecessor_digest: None,
        manifest: draft.manifest().clone(),
        source_draft_digest: draft.digest(),
    }
}

fn binding(state: RuntimeAuthorityStateV1) -> RuntimeAuthorityBindingV1 {
    let (draft, prepared) = descriptor_free_activation_fixture(1);
    let mut binding = RuntimeAuthorityBindingV1 {
        operation: OperationId::from_bytes([41; 16]),
        request_digest: [42; 32],
        state,
        holder: (state == RuntimeAuthorityStateV1::Bound)
            .then_some(PrincipalId::from_bytes([43; 16])),
        revision: 1,
        predecessor_digest: None,
        manifest: draft.manifest().clone(),
        source_draft_digest: draft.digest(),
        publication_digest: prepared.digest(),
        lease_generation: prepared.lease_generation(),
        lease_digest: prepared.lease_digest(),
        digest: ObjectDigest::from_bytes([0; 32]),
    };
    let bytes = encode_binding(&binding).unwrap();
    binding.digest = binding_digest(&bytes);
    binding
}

#[test]
fn public_intents_reject_reserved_identities_and_revisions() {
    assert!(
        matches!(
            RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0; 16]), None),
            Err(RuntimeAuthorityError::InvalidIntent)
        ),
        "a missing holder must not become a pending binding"
    );
    assert!(matches!(
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([1; 16]), Some(0)),
        Err(RuntimeAuthorityError::InvalidIntent)
    ));
    assert!(matches!(
        RuntimeAuthorityIntentV1::revoke(Some(0)),
        Err(RuntimeAuthorityError::InvalidIntent)
    ));
    assert_eq!(
        RuntimeAuthorityIntentV1::revoke(Some(7))
            .unwrap()
            .expected_revision(),
        Some(7)
    );
    let bound =
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([1; 16]), Some(7)).unwrap();
    assert_eq!(bound.state(), RuntimeAuthorityStateV1::Bound);
    assert_ne!(
        bound.digest(),
        RuntimeAuthorityIntentV1::revoke(Some(7)).unwrap().digest(),
        "the operation commitment must distinguish binding from revocation"
    );
    assert_ne!(
        bound.digest(),
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([2; 16]), Some(7))
            .unwrap()
            .digest(),
        "the operation commitment must bind the exact holder"
    );
}

#[test]
fn pending_codec_round_trips_both_closed_decisions() {
    for state in [
        RuntimeAuthorityStateV1::Bound,
        RuntimeAuthorityStateV1::Revoked,
    ] {
        let pending = pending(state);
        let bytes = encode_pending(&pending).unwrap();
        let recovered = decode_pending(&bytes).unwrap();
        assert_eq!(recovered.intent_digest(), pending.intent_digest());
        assert_eq!(recovered, pending);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_pending(&trailing),
            Err(RuntimeAuthorityError::CorruptState)
        ));
    }
}

#[test]
fn pending_codec_rejects_holder_state_and_revision_substitution() {
    let original = pending(RuntimeAuthorityStateV1::Bound);

    let mut missing_holder = original.clone();
    missing_holder.holder = None;
    let bytes = encode_pending(&missing_holder).unwrap();
    assert!(matches!(
        decode_pending(&bytes),
        Err(RuntimeAuthorityError::CorruptState)
    ));

    let mut skipped_revision = original;
    skipped_revision.revision = 2;
    let bytes = encode_pending(&skipped_revision).unwrap();
    assert!(matches!(
        decode_pending(&bytes),
        Err(RuntimeAuthorityError::CorruptState)
    ));
}

#[test]
fn binding_codec_derives_digest_and_rejects_corruption() {
    for state in [
        RuntimeAuthorityStateV1::Bound,
        RuntimeAuthorityStateV1::Revoked,
    ] {
        let binding = binding(state);
        let bytes = encode_binding(&binding).unwrap();
        let recovered = decode_binding(&bytes).unwrap();
        assert_eq!(recovered, binding);
        assert_eq!(recovered.digest(), binding_digest(&bytes));

        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            decode_binding(&corrupt),
            Err(RuntimeAuthorityError::CorruptState)
        ));
    }
}

#[test]
fn head_codec_and_keys_bind_exact_sandbox_revision_and_digest() {
    let binding = binding(RuntimeAuthorityStateV1::Bound);
    let head = RuntimeAuthorityHeadV1 {
        sandbox: binding.sandbox(),
        revision: binding.revision(),
        binding_digest: binding.digest(),
    };
    let bytes = encode_head(head);
    assert_eq!(decode_head(&bytes).unwrap(), head);
    assert_eq!(
        binding_identity_from_key(&binding_key(binding.sandbox(), binding.revision())).unwrap(),
        (binding.sandbox(), binding.revision())
    );
    assert_eq!(
        sandbox_from_current_key(&current_key(binding.sandbox())).unwrap(),
        binding.sandbox()
    );
}

#[test]
fn configured_limits_cannot_weaken_fixed_ceilings() {
    assert!(RuntimeAuthorityLimits::new(1, 1, 1).is_ok());
    assert!(matches!(
        RuntimeAuthorityLimits::new(0, 1, 1),
        Err(RuntimeAuthorityError::InvalidLimits)
    ));
    assert!(matches!(
        RuntimeAuthorityLimits::new(1, MAXIMUM_RECORD_BYTES + 1, 1),
        Err(RuntimeAuthorityError::InvalidLimits)
    ));
}
