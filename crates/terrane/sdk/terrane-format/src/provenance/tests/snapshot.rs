//! Exercises genuine terminal-key snapshot signatures and exact source authority.

use super::*;
use crate::refs::{RefName, SnapshotEnvelope};
use alloc::string::String;

fn snapshot_token(verbs: u8, caveats: Vec<crate::auth::Caveat>) -> Token {
    let commit = unsigned_commit();
    let token = Token::decode(commit.provenance.embedded_token.as_deref().unwrap()).unwrap();
    let mut authority = token
        .verify(&issuer_keys(), 100)
        .unwrap()
        .authority()
        .clone();
    authority.grants =
        vec![Grant::new("refs/heads/main".to_string(), Verbs::new(verbs).unwrap()).unwrap()];
    Token::issue(
        authority,
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap()
    .attenuate(
        crate::auth::Attenuation {
            caveats,
            ..crate::auth::Attenuation::default()
        },
        &[9; 32],
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
    )
    .unwrap()
}

fn envelope() -> SnapshotEnvelope {
    SnapshotEnvelope {
        tag: RefName::parse("refs/tags/release").unwrap(),
        commit: [1; 32],
        attestation: vec![0xa0],
        signer_key: String::new(),
        signature: [0; 64],
    }
}

#[test]
fn prov_snapshot_signature_binds_exact_preimage_and_terminal_key() {
    with_request(|request| {
        let request = Request {
            verb: Verb::Tag,
            ..*request
        };
        let token = snapshot_token(8, Vec::new());
        let verified = token.verify(&issuer_keys(), request.now).unwrap();
        assert!(verified.authorize(&request).is_ok());
        assert!(
            verified
                .authorize(&Request {
                    verb: Verb::Commit,
                    ..request
                })
                .is_err()
        );
        assert!(
            verified
                .authorize(&Request {
                    verb: Verb::Admin,
                    ..request
                })
                .is_err()
        );
        let signed =
            sign_snapshot(envelope(), &token, &[10; 32], &issuer_keys(), &request).unwrap();
        let preimage = signed.signature_preimage().unwrap();
        assert_eq!(preimage[0], 0xa4);
        assert_eq!(signed.signer_key.len(), 64);
        assert!(
            signed
                .signer_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let expected = SigningKey::from_bytes(&[10; 32]).sign(&preimage).to_bytes();
        assert_eq!(signed.signature, expected);
        assert!(
            verify_snapshot(
                &signed,
                &signed.tag,
                [1; 32],
                &token,
                &issuer_keys(),
                &request
            )
            .is_ok()
        );
        assert!(sign_snapshot(envelope(), &token, &[9; 32], &issuer_keys(), &request).is_err());
    });
}

#[test]
fn prov_snapshot_verification_rejects_wrong_target_scope_and_signature() {
    with_request(|request| {
        let request = Request {
            verb: Verb::Tag,
            ..*request
        };
        let token = snapshot_token(8, Vec::new());
        let signed =
            sign_snapshot(envelope(), &token, &[10; 32], &issuer_keys(), &request).unwrap();
        assert!(
            verify_snapshot(
                &signed,
                &signed.tag,
                [2; 32],
                &token,
                &issuer_keys(),
                &request
            )
            .is_err()
        );
        let other_tag = RefName::parse("refs/tags/other").unwrap();
        assert!(
            verify_snapshot(
                &signed,
                &other_tag,
                [1; 32],
                &token,
                &issuer_keys(),
                &request
            )
            .is_err()
        );
        for changed_request in [
            Request {
                reference: b"refs/heads/other",
                ..request
            },
            Request {
                verb: Verb::Commit,
                ..request
            },
            Request {
                now: 201,
                ..request
            },
        ] {
            assert!(
                verify_snapshot(
                    &signed,
                    &signed.tag,
                    [1; 32],
                    &token,
                    &issuer_keys(),
                    &changed_request
                )
                .is_err()
            );
            assert!(
                sign_snapshot(
                    envelope(),
                    &token,
                    &[10; 32],
                    &issuer_keys(),
                    &changed_request
                )
                .is_err()
            );
        }
        for field in ["tag", "attestation", "key", "signature", "commit"] {
            let mut changed = signed.clone();
            match field {
                "tag" => changed.tag = other_tag.clone(),
                "attestation" => changed.attestation = vec![0xa1, 0x61, b'x', 1],
                "key" => changed.signer_key = "issuer-key".to_string(),
                "signature" => changed.signature[0] ^= 1,
                "commit" => changed.commit = [2; 32],
                _ => unreachable!(),
            }
            assert!(
                verify_snapshot(
                    &changed,
                    &changed.tag,
                    changed.commit,
                    &token,
                    &issuer_keys(),
                    &request
                )
                .is_err(),
                "{field}"
            );
        }
        let mut malformed = envelope();
        malformed.attestation = vec![0x80];
        assert!(sign_snapshot(malformed, &token, &[10; 32], &issuer_keys(), &request).is_err());
        assert!(verify_snapshot(&signed, &signed.tag, [1; 32], &token, &[], &request).is_err());
    });
}

#[test]
fn prov_snapshot_tag_scope_accepts_admin_implication_and_rejects_commit_only() {
    with_request(|request| {
        let source_request = Request {
            verb: Verb::Tag,
            ..*request
        };
        let admin_token = snapshot_token(16, Vec::new());
        let signed = sign_snapshot(
            envelope(),
            &admin_token,
            &[10; 32],
            &issuer_keys(),
            &source_request,
        )
        .unwrap();
        assert!(
            verify_snapshot(
                &signed,
                &signed.tag,
                signed.commit,
                &admin_token,
                &issuer_keys(),
                &source_request
            )
            .is_ok()
        );

        let explicit_admin = Request {
            verb: Verb::Admin,
            ..source_request
        };
        assert!(
            sign_snapshot(
                envelope(),
                &admin_token,
                &[10; 32],
                &issuer_keys(),
                &explicit_admin
            )
            .is_ok()
        );
        let commit_token = snapshot_token(4, Vec::new());
        assert!(
            sign_snapshot(
                envelope(),
                &commit_token,
                &[10; 32],
                &issuer_keys(),
                &source_request
            )
            .is_err()
        );
        assert!(
            verify_snapshot(
                &signed,
                &signed.tag,
                signed.commit,
                &commit_token,
                &issuer_keys(),
                &source_request
            )
            .is_err()
        );
    });
}

#[test]
fn prov_snapshot_tag_scope_enforces_exact_source_caveats() {
    use crate::auth::{Caveat, RequestRoot};

    with_request(|request| {
        let roots = [RequestRoot {
            path: b"/private",
            domain: "private:source",
        }];
        let source_request = Request {
            verb: Verb::Tag,
            roots: &roots,
            ..*request
        };
        let token = snapshot_token(
            8,
            vec![
                Caveat::Ref("refs/heads/main".to_string()),
                Caveat::Root("/private".to_string()),
                Caveat::Domain("private:source".to_string()),
                Caveat::Surface("sdk".to_string()),
                Caveat::Epoch("refs/heads/main".to_string(), 4),
                Caveat::Verb(Verbs::new(8).unwrap()),
            ],
        );
        let signed = sign_snapshot(
            envelope(),
            &token,
            &[10; 32],
            &issuer_keys(),
            &source_request,
        )
        .unwrap();
        assert!(
            verify_snapshot(
                &signed,
                &signed.tag,
                signed.commit,
                &token,
                &issuer_keys(),
                &source_request
            )
            .is_ok()
        );

        let wrong_roots = [RequestRoot {
            path: b"/other",
            domain: "private:source",
        }];
        let wrong_domain = [RequestRoot {
            path: b"/private",
            domain: "private:other",
        }];
        let wrong_epochs = [("refs/heads/main", 5)];
        for changed in [
            Request {
                reference: b"refs/heads/other",
                ..source_request
            },
            Request {
                roots: &wrong_roots,
                ..source_request
            },
            Request {
                roots: &wrong_domain,
                ..source_request
            },
            Request {
                surface: "api",
                ..source_request
            },
            Request {
                epochs: &wrong_epochs,
                ..source_request
            },
        ] {
            assert!(
                sign_snapshot(envelope(), &token, &[10; 32], &issuer_keys(), &changed).is_err()
            );
            assert!(
                verify_snapshot(
                    &signed,
                    &signed.tag,
                    signed.commit,
                    &token,
                    &issuer_keys(),
                    &changed
                )
                .is_err()
            );
        }
    });
}
