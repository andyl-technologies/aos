//! Tests genuine Ed25519 signatures, canonical preimages, closed schema,
//! monotone attenuation, canonical byte globs, and every request caveat.

#![allow(clippy::expect_used)]

use super::*;
use alloc::{string::ToString, vec};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("valid test fixture"), 16)
                .expect("valid test fixture")
        })
        .collect()
}

fn issuer_secret() -> [u8; 32] {
    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .expect("valid test fixture")
}

fn delegate_secret() -> [u8; 32] {
    hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        .try_into()
        .expect("valid test fixture")
}

fn delegate_public() -> [u8; 32] {
    SigningKey::from_bytes(&delegate_secret())
        .verifying_key()
        .to_bytes()
}

fn grant(pattern: &str, mask: u8) -> Grant {
    Grant::new(
        pattern.to_string(),
        Verbs::new(mask).expect("valid test fixture"),
    )
    .expect("valid test fixture")
}

fn authority() -> Authority {
    Authority {
        issuer: "issuer.example".to_string(),
        key_id: "k1".to_string(),
        subject: "ci-job".to_string(),
        kind: PrincipalKind::Workload,
        groups: vec!["builders".to_string()],
        not_after: 1_760_003_600,
        not_before: None,
        token_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        grants: vec![grant("refs/heads/pr/**", 7)],
        workload: None,
    }
}

fn keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer.example".to_string(),
        key_id: "k1".to_string(),
        public_key: SigningKey::from_bytes(&issuer_secret())
            .verifying_key()
            .to_bytes(),
        retirement: None,
    }]
}

fn token() -> Token {
    Token::issue(authority(), &issuer_secret(), delegate_public()).expect("valid test fixture")
}

fn request<'a>(locality: &'a Locality, roots: &'a [RequestRoot<'a>]) -> Request<'a> {
    Request {
        reference: b"refs/heads/pr/1234",
        verb: Verb::Commit,
        roots,
        now: 1_760_000_000,
        surface: "fuse",
        locality,
        epochs: &[("refs/heads/pr/1234", 1)],
    }
}

#[test]
fn auth_token_chain_golden_preimages_and_signatures() {
    let token = token();
    assert_eq!(
        format::authority_preimage(&token.authority),
        hex(concat!(
            "a9016e6973737565722e6578616d706c6502626b31036663692d6a6f62040205",
            "81686275696c64657273061a68e7861008500102030405060708090a0b0c0d0e",
            "0f1009818270726566732f68656164732f70722f2a2a070b58203d4017c3e843",
            "895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        ))
    );
    assert_eq!(
        token.authority.signature.as_slice(),
        hex(
            "7239961b2b42911f2f2ad53e5b8715d82f18ba850cad724863832e43d45bbd4ccffd924ffa1189b7695a7d6c610fb766ff7ea30a26cd69924f9f140edac5f609"
        )
    );

    let token = token
        .attenuate(
            Attenuation {
                caveats: vec![
                    Caveat::Ref("refs/heads/pr/1234".to_string()),
                    Caveat::Epoch("refs/heads/pr/1234".to_string(), 1),
                ],
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    assert_eq!(
        format::attenuation_preimage(&token.blocks[0]),
        hex(concat!(
            "a20482826372656672726566732f68656164732f70722f31323334836565706f",
            "636872726566732f68656164732f70722f31323334010558203d4017c3e84389",
            "5a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        ))
    );
    assert_eq!(
        token.blocks[0].signature.as_slice(),
        hex(
            "3fda3b61fb042cf3fe81e027fb7968fef6f8e40fb59e7ccb98117c97392ba0bbd5aa8e92a5faf958af1cb6f61f739b5c6cec2e194e644058ea2d4f8989ac700c"
        )
    );
    let decoded = Token::decode(&token.encode()).expect("valid test fixture");
    assert_eq!(decoded, token);
    let verified = verify(&token.encode(), &keys(), 1_760_000_000).expect("valid test fixture");
    let locality = Locality::default();
    let mut context = request(&locality, &[]);
    assert!(verified.authorize(&context).is_ok());
    context.reference = b"refs/heads/pr/1235";
    assert_eq!(verified.authorize(&context), Err(Unauthorized));
    context.reference = b"refs/heads/pr/1234";
    context.epochs = &[("refs/heads/pr/1234", 2)];
    assert_eq!(verified.authorize(&context), Err(Unauthorized));
}

#[test]
fn auth_verify_pure_rejects_unknown_retired_keys_time_and_broken_chains() {
    let token = token();
    assert!(
        token
            .verify(&keys(), token.authority.body.not_after)
            .is_ok()
    );
    assert!(
        token
            .verify(&keys(), token.authority.body.not_after + 1)
            .is_err()
    );
    assert!(token.verify(&[], 1).is_err());
    let mut rotated = keys();
    rotated[0].retirement = Some(100);
    assert!(token.verify(&rotated, 99).is_ok());
    assert!(token.verify(&rotated, 100).is_err());
    rotated.push(IssuerKey {
        key_id: "new".to_string(),
        retirement: None,
        ..keys().remove(0)
    });
    assert!(token.verify(&rotated, 100).is_err());

    let mut future = authority();
    future.not_before = Some(100);
    let future =
        Token::issue(future, &issuer_secret(), delegate_public()).expect("valid test fixture");
    assert!(future.verify(&keys(), 99).is_err());
    assert!(future.verify(&keys(), 100).is_ok());

    let mut bad = token.clone();
    bad.authority.signature[0] ^= 1;
    assert_eq!(
        bad.verify_diagnostic(&keys(), 1)
            .expect_err("expected rejection"),
        Diagnostic::Signature
    );
    let mut bad = token
        .attenuate(
            Attenuation::default(),
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    bad.blocks[0].signature[0] ^= 1;
    assert!(bad.verify(&keys(), 1).is_err());
    bad.blocks[0].signature = token.authority.signature;
    assert!(bad.verify(&keys(), 1).is_err());
}

#[test]
fn auth_verify_pure_rejects_unknown_noncanonical_truncated_and_oversized_fields() {
    let bytes = token().encode();
    for length in 0..bytes.len() {
        assert!(Token::decode(&bytes[..length]).is_err(), "length {length}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Token::decode(&trailing).is_err());
    let mut unknown = bytes.clone();
    unknown[1] = 0xab;
    unknown.extend([13, 0]);
    assert!(Token::decode(&unknown).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.splice(2..3, [0x18, 1]);
    assert!(Token::decode(&noncanonical).is_err());
    let mut duplicate = bytes.clone();
    duplicate[19] = 1;
    assert!(Token::decode(&duplicate).is_err());
    assert!(Token::decode(&vec![0; 65_537]).is_err());

    let mut att = token()
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Surface("x".to_string())],
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture")
        .encode();
    let name = att
        .windows(7)
        .position(|window| window == b"surface")
        .expect("valid test fixture");
    att[name..name + 7].copy_from_slice(b"unknown");
    assert!(Token::decode(&att).is_err());
}

#[test]
fn auth_attenuation_monotone_rejects_signed_widening() {
    let parent = token();
    for restriction in [
        Attenuation {
            not_after: Some(authority().not_after + 1),
            ..Attenuation::default()
        },
        Attenuation {
            grants: Some(vec![grant("refs/heads/**", 7)]),
            ..Attenuation::default()
        },
        Attenuation {
            grants: Some(vec![grant("refs/heads/pr/**", 16)]),
            ..Attenuation::default()
        },
    ] {
        assert!(
            parent
                .attenuate(restriction.clone(), &delegate_secret(), delegate_public())
                .is_err()
        );
        // Independently construct a genuinely signed malicious block to prove
        // the verifier enforces monotonicity rather than trusting the issuer API.
        let mut child = parent.clone();
        let mut block = Signed {
            body: restriction,
            next_key: delegate_public(),
            signature: [0; 64],
        };
        let mut preimage = parent.authority.signature.to_vec();
        preimage.extend(format::attenuation_preimage(&block));
        block.signature = SigningKey::from_bytes(&delegate_secret())
            .sign(&preimage)
            .to_bytes();
        child.blocks.push(block);
        assert_eq!(
            child
                .verify_diagnostic(&keys(), 1)
                .expect_err("expected rejection"),
            Diagnostic::Widening
        );
    }
    let narrowed = parent
        .attenuate(
            Attenuation {
                not_before: Some(10),
                not_after: Some(100),
                grants: Some(vec![grant("refs/heads/pr/1234", 1)]),
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    assert!(narrowed.verify(&keys(), 10).is_ok());
    assert!(
        narrowed
            .attenuate(
                Attenuation {
                    not_before: Some(9),
                    ..Attenuation::default()
                },
                &delegate_secret(),
                delegate_public()
            )
            .is_err()
    );
    assert!(
        narrowed
            .attenuate(
                Attenuation {
                    grants: Some(vec![grant("refs/heads/pr/1234", 4)]),
                    ..Attenuation::default()
                },
                &delegate_secret(),
                delegate_public()
            )
            .is_err()
    );
}

#[test]
fn auth_attenuation_offline_all_caveats_and_literal_verb_masks() {
    let mut authority = authority();
    authority.grants = vec![grant("refs/heads/pr/**", 16)];
    let parent =
        Token::issue(authority, &issuer_secret(), delegate_public()).expect("valid test fixture");
    let locality = Locality {
        region: Some("west".to_string()),
        ..Locality::default()
    };
    let caveats = vec![
        Caveat::Before(1_760_000_001),
        Caveat::After(1_759_999_999),
        Caveat::Ref("refs/heads/pr/*".to_string()),
        Caveat::Root("/safe/**".to_string()),
        Caveat::Verb(Verbs::new(1).expect("valid test fixture")),
        Caveat::Domain("private".to_string()),
        Caveat::Surface("fuse".to_string()),
        Caveat::Locality(locality.clone()),
        Caveat::Epoch("refs/heads/pr/1234".to_string(), 1),
    ];
    let token = parent
        .attenuate(
            Attenuation {
                caveats,
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    let verified = token
        .verify(&keys(), 1_760_000_000)
        .expect("valid test fixture");
    let roots = [RequestRoot {
        path: b"/safe/a/b",
        domain: "private",
    }];
    let mut context = request(&locality, &roots);
    context.verb = Verb::Read;
    assert!(verified.authorize(&context).is_ok());
    for verb in [Verb::Commit, Verb::Admin] {
        context.verb = verb;
        assert!(verified.authorize(&context).is_err());
    }
    context.verb = Verb::Read;
    context.now += 1;
    assert!(verified.authorize(&context).is_err());
    context.now -= 2;
    assert!(verified.authorize(&context).is_err());
    context.now += 1;
    context.surface = "http";
    assert!(verified.authorize(&context).is_err());
    context.surface = "fuse";
    context.epochs = &[];
    assert!(verified.authorize(&context).is_err());
    context.epochs = &[("refs/heads/pr/1234", 1), ("refs/heads/pr/1234", 1)];
    assert!(verified.authorize(&context).is_err());
    context.epochs = &[("refs/heads/pr/1234", 1)];
    let other_locality = Locality::default();
    context.locality = &other_locality;
    assert!(verified.authorize(&context).is_err());
    context.locality = &locality;
    context.roots = &[RequestRoot {
        path: b"/safe/a",
        domain: "public",
    }];
    assert!(verified.authorize(&context).is_err());
    context.roots = &[RequestRoot {
        path: b"/other",
        domain: "private",
    }];
    assert!(verified.authorize(&context).is_err());
}

#[test]
fn auth_attenuation_monotone_glob_language_and_union_containment() {
    assert!(pattern::matches("refs/heads/*", b"refs/heads/main"));
    assert!(!pattern::matches("refs/heads/*", b"refs/heads/pr/1"));
    assert!(pattern::matches("refs/heads/**", b"refs/heads/pr/1"));
    assert!(!pattern::matches("refs/heads/main", b"refs/heads/MAIN"));
    assert!(
        pattern::contained(
            &grant("refs/heads/pr/*", 1),
            &[grant("refs/heads/pr/**", 1)],
            1
        )
        .expect("valid test fixture")
    );
    assert!(
        !pattern::contained(
            &grant("refs/heads/pr/**", 1),
            &[grant("refs/heads/pr/*", 1)],
            1
        )
        .expect("valid test fixture")
    );
    assert!(
        pattern::contained(
            &grant("refs/heads/main:/a/*", 1),
            &[grant("refs/heads/main", 1)],
            1
        )
        .expect("valid test fixture")
    );
    assert!(
        !pattern::contained(
            &grant("refs/heads/main", 1),
            &[grant("refs/heads/main:/a/**", 1)],
            1
        )
        .expect("valid test fixture")
    );
    assert!(
        pattern::contained(
            &grant("refs/heads/main", 5),
            &[grant("refs/heads/main", 1), grant("refs/heads/main", 4)],
            4
        )
        .expect("valid test fixture")
    );
    assert!(
        !pattern::contained(
            &grant("refs/heads/other", 1),
            &[grant("refs/heads/main", 16)],
            1
        )
        .expect("valid test fixture")
    );
    for invalid in [
        "refs/heads//main",
        "refs/heads/../main",
        "refs/heads/main:relative",
        "refs/heads/main:/a/../b",
    ] {
        assert!(
            Grant::new(
                invalid.to_string(),
                Verbs::new(1).expect("valid test fixture")
            )
            .is_err()
        );
    }
    for mask in [0, 32, 255] {
        assert!(Verbs::new(mask).is_err());
    }
    for mask in [2, 4, 8, 16] {
        assert!(
            Verbs::new(mask)
                .expect("valid test fixture")
                .contains(Verb::Read)
        );
    }
    for mask in [2, 8] {
        assert!(
            !Verbs::new(mask)
                .expect("valid test fixture")
                .contains(Verb::Commit)
        );
    }
}

#[test]
fn auth_attenuation_monotone_scope_union_and_caveats_survive_append() {
    let mut body = authority();
    body.grants = vec![
        grant("refs/heads/main:/a/**", 4),
        grant("refs/heads/main:/b/**", 1),
        grant("refs/heads/source", 2),
    ];
    let parent =
        Token::issue(body, &issuer_secret(), delegate_public()).expect("valid test fixture");
    let locality = Locality::default();
    let roots = [
        RequestRoot {
            path: b"/a/one",
            domain: "public",
        },
        RequestRoot {
            path: b"/b/two",
            domain: "public",
        },
    ];
    let verified = parent.verify(&keys(), 10).expect("valid test fixture");
    let mut context = request(&locality, &roots);
    context.now = 10;
    context.reference = b"refs/heads/main";
    context.verb = Verb::Read;
    assert!(verified.authorize(&context).is_ok());
    context.verb = Verb::Commit;
    assert!(verified.authorize(&context).is_err());
    context.roots = &[];
    assert!(verified.authorize(&context).is_err());
    context.reference = b"refs/heads/source";
    context.verb = Verb::Fork;
    assert!(verified.authorize(&context).is_ok());
    context.verb = Verb::Commit;
    assert!(verified.authorize(&context).is_err());
    context.reference = b"refs/heads/new";
    assert!(verified.authorize(&context).is_err());

    let first = token()
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Surface("fuse".to_string())],
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    let second = first
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Verb(Verbs::new(1).expect("valid test fixture"))],
                ..Attenuation::default()
            },
            &delegate_secret(),
            delegate_public(),
        )
        .expect("valid test fixture");
    let verified = second.verify(&keys(), 10).expect("valid test fixture");
    context.reference = b"refs/heads/pr/1234";
    context.verb = Verb::Read;
    assert!(verified.authorize(&context).is_ok());
    context.surface = "http";
    assert!(verified.authorize(&context).is_err());
    for reference in [
        b"refs/heads//main".as_slice(),
        b"refs/heads/../main",
        b"refs/heads/main\0",
    ] {
        context.reference = reference;
        assert!(verified.authorize(&context).is_err());
    }
}

#[test]
fn auth_verify_pure_accepts_unbounded_schema_text_and_canonical_root_bytes() {
    let mut body = authority();
    body.subject = "s".repeat(70_000);
    body.groups = vec!["group".to_string(); 300];
    body.grants = vec![grant("refs/heads/main:/a:b/*", 1)];
    let token =
        Token::issue(body, &issuer_secret(), delegate_public()).expect("valid large subject");
    let verified = verify(&token.encode(), &keys(), 10).expect("schema has no text size cap");
    let locality = Locality::default();
    let roots = [RequestRoot {
        path: b"/a:b/file*",
        domain: "public",
    }];
    let mut context = request(&locality, &roots);
    context.reference = b"refs/heads/main";
    context.verb = Verb::Read;
    context.now = 10;
    assert!(verified.authorize(&context).is_ok());
    for reference in [
        b"refs/unknown/main".as_slice(),
        b"refs/heads/a?",
        b"refs/heads/a..b",
        b"refs/heads/\xc3\xa9",
    ] {
        context.reference = reference;
        assert!(verified.authorize(&context).is_err());
    }
}
