//! Checks principal-kind distinctions using genuinely verified token claims.
//!
//! These comparisons grant no request authority. The caller must independently
//! authorize both scopes and retain their current controls and expiry checks.

#![allow(clippy::unwrap_used, reason = "signed test fixtures must verify")]

use super::AuthorizedRef;
use terrane_core::auth::{Authority, Grant, IssuerKey, Token, Verb, Verbs};
use terrane_core::refs::PrincipalKind;

fn key(hexadecimal: &str) -> [u8; 32] {
    assert_eq!(hexadecimal.len(), 64);
    core::array::from_fn(|index| {
        u8::from_str_radix(&hexadecimal[index * 2..index * 2 + 2], 16).unwrap()
    })
}

fn captured(subject: &str, kind: PrincipalKind, alternate: bool) -> AuthorizedRef {
    let secret = key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let issuer = if alternate { "second" } else { "first" };
    let token = Token::issue(
        Authority {
            issuer: issuer.into(),
            key_id: "key".into(),
            subject: subject.into(),
            kind,
            groups: if alternate {
                vec!["builders".into()]
            } else {
                vec![]
            },
            not_after: 100,
            not_before: None,
            token_id: [u8::from(alternate); 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &secret,
        public,
    )
    .unwrap();
    let verified = token
        .verify(
            &[IssuerKey {
                issuer: issuer.into(),
                key_id: "key".into(),
                public_key: public,
                retirement: None,
            }],
            1,
        )
        .unwrap();

    AuthorizedRef {
        reference: if alternate {
            "refs/heads/_/destination"
        } else {
            "refs/heads/_/source"
        }
        .into(),
        record: None,
        token: verified,
        verb: if alternate { Verb::Commit } else { Verb::Read },
        root_paths: vec![b"/".to_vec()],
        root_domains: vec![if alternate { "destination" } else { "source" }.into()],
        surface: "sdk".into(),
        token_bytes: token.encode(),
    }
}

#[test]
fn authenticated_principal_comparison_requires_name_and_kind() {
    let kinds = [
        PrincipalKind::Human,
        PrincipalKind::Workload,
        PrincipalKind::Service,
    ];
    for left_kind in kinds {
        let left = captured("same-name", left_kind, false);
        for right_kind in kinds {
            let right = captured("same-name", right_kind, true);
            assert_eq!(left.subject(), right.subject());
            assert_eq!(left.same_principal(&right), left_kind == right_kind);
            assert_eq!(right.same_principal(&left), left_kind == right_kind);
        }
        assert!(!left.same_principal(&captured("another-name", left_kind, true)));
    }
}

#[test]
fn authenticated_principal_comparison_keeps_request_claims_independent() {
    let source = captured("same-name", PrincipalKind::Human, false);
    let destination = captured("same-name", PrincipalKind::Human, true);

    assert_ne!(
        source.token.authority().issuer,
        destination.token.authority().issuer
    );
    assert_ne!(
        source.token.authority().groups,
        destination.token.authority().groups
    );
    assert_ne!(
        source.token.authority().token_id,
        destination.token.authority().token_id
    );
    assert_ne!(source.reference(), destination.reference());
    assert_ne!(source.verb(), destination.verb());
    assert!(source.same_principal(&destination));
}
