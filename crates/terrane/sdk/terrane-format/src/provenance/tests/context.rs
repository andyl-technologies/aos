//! Exercises signed original authoring scopes and explicit legacy compatibility.

use super::*;
use crate::{
    auth::{Caveat, RequestRoot},
    refs::CommitContext,
};

fn scoped_commit(request: &Request<'_>) -> Commit {
    let mut commit = unsigned_commit();
    let token = Token::decode(commit.provenance.embedded_token.as_deref().unwrap()).unwrap();
    let mut authority = token
        .verify(&issuer_keys(), 100)
        .unwrap()
        .authority()
        .clone();
    authority.grants = vec![
        Grant::new(
            "refs/heads/main:/lib/**".to_string(),
            Verbs::new(4).unwrap(),
        )
        .unwrap(),
    ];
    let token = Token::issue(
        authority,
        &[7; 32],
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let token = token
        .attenuate(
            crate::auth::Attenuation {
                caveats: vec![
                    Caveat::Ref("refs/heads/main".to_string()),
                    Caveat::Surface(request.surface.to_string()),
                    Caveat::Domain("private:build".to_string()),
                    Caveat::Locality(request.locality.clone()),
                    Caveat::Epoch("refs/heads/main".to_string(), 4),
                ],
                ..Default::default()
            },
            &[9; 32],
            SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
    commit.provenance.embedded_token = Some(token.encode());
    commit.profile_pair.commit_context = Some(CommitContext::from_request(request).unwrap());
    commit
}

fn scoped_request<T>(action: impl FnOnce(&Request<'_>) -> T) -> T {
    let locality = Locality {
        region: Some("west".to_string()),
        zone: Some("a".to_string()),
        host: Some("author".to_string()),
    };
    let roots = [RequestRoot {
        path: b"/lib/narrow",
        domain: "private:build",
    }];
    action(&Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &roots,
        now: 100,
        surface: "api",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    })
}

#[test]
fn prov_commit_history_preserves_original_scope_with_narrow_root_grants() {
    scoped_request(|request| {
        let authored = scoped_commit(request);
        let signed = sign_authored(authored, &[10; 32], &issuer_keys(), request, 4).unwrap();
        let bytes = signed.commit().encode().unwrap();
        let decoded = Commit::decode(&bytes).unwrap();
        assert_eq!(
            decoded.profile_pair.commit_context,
            signed.commit().profile_pair.commit_context
        );

        let destination = Locality {
            region: Some("east".to_string()),
            ..Locality::default()
        };
        let current = Request {
            reference: b"refs/tags/release",
            surface: "sdk",
            locality: &destination,
            now: 300,
            epochs: &[("refs/tags/release", 20)],
            ..*request
        };
        assert!(verify(&decoded, &issuer_keys(), &current, 20).is_err());
        let historical =
            verify_history(&decoded, &issuer_keys(), request.roots, request.epochs).unwrap();
        assert_eq!(historical.identity(), signed.identity());
        assert_eq!(
            historical.signing_public_key(),
            SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()
        );
    });
}

#[test]
fn prov_commit_context_rejects_tampered_scope_and_unvalidated_roots() {
    scoped_request(|request| {
        let signed = sign_authored(
            scoped_commit(request),
            &[10; 32],
            &issuer_keys(),
            request,
            4,
        )
        .unwrap();
        let changed_roots = [RequestRoot {
            path: b"/lib/other",
            domain: "private:build",
        }];
        let changed_domain = [RequestRoot {
            path: b"/lib/narrow",
            domain: "public",
        }];
        for roots in [&changed_roots[..], &changed_domain[..], &[]] {
            assert!(
                verify_history(signed.commit(), &issuer_keys(), roots, request.epochs).is_err()
            );
        }
        assert!(
            verify_history(
                signed.commit(),
                &issuer_keys(),
                request.roots,
                &[("refs/heads/main", 5)]
            )
            .is_err()
        );

        for changed_request in [
            Request {
                surface: "sdk",
                ..*request
            },
            Request {
                reference: b"refs/heads/other",
                ..*request
            },
        ] {
            let mut changed = signed.commit().clone();
            changed.profile_pair.commit_context =
                Some(CommitContext::from_request(&changed_request).unwrap());
            assert!(
                verify_history(
                    &changed,
                    &issuer_keys(),
                    request.roots,
                    changed_request.epochs
                )
                .is_err()
            );
        }
        let mut changed = signed.commit().clone();
        changed.profile_pair.commit_context = None;
        assert!(verify(&changed, &issuer_keys(), request, 4).is_err());
    });
}

#[test]
fn prov_commit_signature_binds_context_even_when_changed_scope_is_authorized() {
    scoped_request(|request| {
        let mut broad = unsigned_commit();
        broad.profile_pair.commit_context = Some(CommitContext::from_request(request).unwrap());
        let signed = sign_authored(broad, &[9; 32], &issuer_keys(), request, 4).unwrap();
        let locality = Locality::default();
        let roots = [RequestRoot {
            path: b"/elsewhere",
            domain: "public",
        }];
        for changed_request in [
            Request {
                surface: "sdk",
                ..*request
            },
            Request {
                locality: &locality,
                ..*request
            },
            Request {
                roots: &roots,
                ..*request
            },
        ] {
            let mut changed = signed.commit().clone();
            changed.profile_pair.commit_context =
                Some(CommitContext::from_request(&changed_request).unwrap());
            assert_eq!(
                verify_diagnostic(&changed, &issuer_keys(), &changed_request, 4).unwrap_err(),
                Diagnostic::Signature
            );
            assert!(verify(signed.commit(), &issuer_keys(), &changed_request, 4).is_err());
            assert!(
                sign(
                    signed.commit().clone(),
                    &[9; 32],
                    &issuer_keys(),
                    &changed_request,
                    4
                )
                .is_err()
            );
        }
    });
}

#[test]
fn prov_commit_authored_requires_context_and_legacy_bytes_remain_explicit() {
    with_request(|request| {
        let legacy = sign(unsigned_commit(), &[9; 32], &issuer_keys(), request, 4).unwrap();
        let bytes = legacy.commit().encode().unwrap();
        let decoded = Commit::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert!(decoded.profile_pair.commit_context.is_none());
        assert!(verify(&decoded, &issuer_keys(), request, 4).is_ok());
        assert!(verify_history(&decoded, &issuer_keys(), request.roots, request.epochs).is_err());
        assert!(sign_authored(unsigned_commit(), &[9; 32], &issuer_keys(), request, 4).is_err());
        assert!(CommitContext::from_request(request).is_err());
    });
}

#[test]
fn prov_commit_context_canonicalizes_unsigned_root_pairs_and_rejects_duplicates() {
    scoped_request(|request| {
        let roots = [
            RequestRoot {
                path: b"/\xff",
                domain: "z",
            },
            RequestRoot {
                path: b"/a",
                domain: "z",
            },
            RequestRoot {
                path: b"/a",
                domain: "a",
            },
        ];
        let context = CommitContext::from_request(&Request {
            roots: &roots,
            ..*request
        })
        .unwrap();
        let pairs: Vec<_> = context
            .roots()
            .iter()
            .map(|root| (root.path(), root.domain()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (b"/a".as_slice(), "a"),
                (b"/a".as_slice(), "z"),
                (b"/\xff".as_slice(), "z")
            ]
        );

        for path in [b"relative".as_slice(), b"/a/../b", b"/a/", b"//a", b"/a\0b"] {
            let roots = [RequestRoot {
                path,
                domain: "private:build",
            }];
            assert!(
                CommitContext::from_request(&Request {
                    roots: &roots,
                    ..*request
                })
                .is_err()
            );
        }
        let duplicate = [roots[0], roots[0]];
        assert!(
            CommitContext::from_request(&Request {
                roots: &duplicate,
                ..*request
            })
            .is_err()
        );
        assert!(
            CommitContext::from_request(&Request {
                surface: "unregistered",
                ..*request
            })
            .is_err()
        );
    });
}
