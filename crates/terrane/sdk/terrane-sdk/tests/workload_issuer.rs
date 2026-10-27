//! Exercises actual private key files, canonical tokens and bounded job lifetimes.

#![cfg(all(feature = "tokio", unix))]
#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use std::{
    fs,
    num::NonZeroU64,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use terrane_format::auth::{
    self, Attenuation, Grant, IssuerKey, Locality, PrincipalKind, Request, Token, Verb, Verbs,
};
use terrane_sdk::{
    store::{Clock, TokioLocalFs},
    workload::{IssuerPolicy, MintError, StaticKeyIssuer, WorkloadClaims},
};

const SEED: [u8; 32] = [23; 32];
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    key: PathBuf,
    owner: u32,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "terrane-workload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst),
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let key = directory.join("issuer.seed");
        fs::write(&key, SEED).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = fs::symlink_metadata(&key).unwrap().uid();
        Self {
            directory,
            key,
            owner,
        }
    }

    fn issuer(&self, lifetime: u64, margin: u64, retirement: Option<u64>) -> StaticKeyIssuer {
        let mut key = public_key();
        key.retirement = retirement;
        StaticKeyIssuer::open(
            &self.key,
            self.owner,
            IssuerPolicy::new(key, lifetime, margin).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn public_key() -> IssuerKey {
    IssuerKey {
        issuer: "warehouse-jobs".into(),
        key_id: "primary".into(),
        public_key: auth::public_key_from_secret(&SEED),
        retirement: None,
    }
}

fn claims() -> WorkloadClaims {
    WorkloadClaims {
        subject: "ci-job".into(),
        workload: "job/run-123/instance-456".into(),
        groups: vec!["builders".into()],
        grants: vec![Grant::new("refs/heads/jobs/**".into(), Verbs::new(7).unwrap()).unwrap()],
        expected_end: 120,
        not_after: None,
    }
}

struct Times {
    values: Vec<SystemTime>,
    reads: AtomicUsize,
}

impl Times {
    fn new(seconds: &[u64]) -> Self {
        Self {
            values: seconds
                .iter()
                .map(|s| UNIX_EPOCH + Duration::from_secs(*s))
                .collect(),
            reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Clock for Times {
    fn now(&self) -> SystemTime {
        self.values[self
            .reads
            .fetch_add(1, Ordering::SeqCst)
            .min(self.values.len() - 1)]
    }

    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
}

#[tokio::test]
async fn private_file_mints_exact_authenticated_workload_claims() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(60, 5, None);
    let claims = claims();
    let credential = issuer
        .mint(&TokioLocalFs, &Times::new(&[100]), claims.clone())
        .await
        .unwrap();
    let token = Token::decode(credential.token()).unwrap();
    let verified = token.verify(&[public_key()], 100).unwrap();
    let authority = verified.authority();

    assert_eq!(authority.issuer, "warehouse-jobs");
    assert_eq!(authority.key_id, "primary");
    assert_eq!(authority.kind, PrincipalKind::Workload);
    assert_eq!(authority.subject, claims.subject);
    assert_eq!(
        authority.workload.as_deref(),
        Some(claims.workload.as_str())
    );
    assert_eq!(authority.groups, claims.groups);
    assert_eq!(authority.grants, claims.grants);
    assert_eq!(authority.not_before, Some(100));
    assert_eq!(authority.not_after, 125);
    assert_eq!(token.encode(), credential.token());
    assert_eq!(
        token.signing_public_key(),
        auth::public_key_from_secret(credential.signing_secret())
    );
    assert!(token.verify(&[public_key()], 125).is_ok());
    assert!(token.verify(&[public_key()], 126).is_err());
    assert!(token.verify(&[public_key()], 99).is_err());
}

#[tokio::test]
async fn ci_change_credentials_allow_only_baseline_fork_and_assigned_branch_writes() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(60, 5, None);

    for change in [1, 123, u64::MAX] {
        let claims = WorkloadClaims::ci_change(
            "ci-job".into(),
            format!("run-{change}"),
            NonZeroU64::new(change).unwrap(),
            120,
        )
        .unwrap();
        let credential = issuer
            .mint(&TokioLocalFs, &Times::new(&[100]), claims)
            .await
            .unwrap();
        let token = Token::decode(credential.token()).unwrap();
        let verified = token.verify(&[public_key()], 100).unwrap();
        let authority = verified.authority();
        let assigned = format!("refs/heads/ci/pr/{change}");

        assert!(authority.groups.is_empty());
        assert_eq!(authority.grants.len(), 2);
        assert_eq!(authority.grants[0].pattern(), "refs/heads/ci/master");
        assert_eq!(authority.grants[0].verbs().bits(), 2);
        assert_eq!(authority.grants[1].pattern(), assigned);
        assert_eq!(authority.grants[1].verbs().bits(), 4);
        assert_eq!(authority.not_after, 125);

        for (reference, read, fork, commit) in [
            ("refs/heads/ci/master", true, true, false),
            (assigned.as_str(), true, false, true),
            ("refs/heads/ci/pr/0", false, false, false),
            ("refs/heads/ci/pr/0123", false, false, false),
            ("refs/heads/ci/pr/123/child", false, false, false),
            ("refs/heads/other", false, false, false),
            ("refs/tags/ci/pr/123", false, false, false),
        ] {
            for (verb, permitted) in [
                (Verb::Read, read),
                (Verb::Fork, fork),
                (Verb::Commit, commit),
                (Verb::Tag, false),
                (Verb::Admin, false),
            ] {
                let request = Request {
                    reference: reference.as_bytes(),
                    verb,
                    roots: &[],
                    now: 100,
                    surface: "sdk",
                    locality: &Locality::default(),
                    epochs: &[],
                };
                assert_eq!(
                    verified.authorize(&request).is_ok(),
                    permitted,
                    "change {change}: {verb:?} on {reference}"
                );
            }
        }
    }

    for (subject, workload) in [("", "run-1"), ("ci-job", "")] {
        assert!(
            WorkloadClaims::ci_change(
                subject.into(),
                workload.into(),
                NonZeroU64::new(1).unwrap(),
                120,
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn every_lifetime_bound_can_narrow_but_never_widen_issuance() {
    let fixture = Fixture::new();
    for (lifetime, margin, retirement, requested, expected) in [
        (60, 5, None, None, 125),
        (10, 5, None, None, 110),
        (60, 5, Some(115), None, 114),
        (60, 5, None, Some(109), 109),
        (60, 0, None, Some(200), 120),
    ] {
        let issuer = fixture.issuer(lifetime, margin, retirement);
        let mut claims = claims();
        claims.not_after = requested;
        let credential = issuer
            .mint(&TokioLocalFs, &Times::new(&[100]), claims)
            .await
            .unwrap();
        let token = Token::decode(credential.token()).unwrap();
        let verified = token.verify(&[issuer.policy().key().clone()], 100).unwrap();
        assert_eq!(verified.authority().not_after, expected);
    }
}

#[tokio::test]
async fn real_entropy_produces_distinct_tokens_and_offline_attenuation_keys() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(60, 5, None);
    let a = issuer
        .mint(&TokioLocalFs, &Times::new(&[100]), claims())
        .await
        .unwrap();
    let b = issuer
        .mint(&TokioLocalFs, &Times::new(&[100]), claims())
        .await
        .unwrap();
    let token_a = Token::decode(a.token()).unwrap();
    let token_b = Token::decode(b.token()).unwrap();
    assert_ne!(a.token(), b.token());
    assert_ne!(a.signing_secret(), b.signing_secret());
    assert_ne!(
        token_a
            .verify(&[public_key()], 100)
            .unwrap()
            .authority()
            .token_id,
        token_b
            .verify(&[public_key()], 100)
            .unwrap()
            .authority()
            .token_id
    );

    let narrowed = Attenuation {
        not_after: Some(110),
        grants: Some(vec![
            Grant::new("refs/heads/jobs/run-123".into(), Verbs::new(1).unwrap()).unwrap(),
        ]),
        ..Default::default()
    };
    let child = token_a
        .attenuate(
            narrowed.clone(),
            a.signing_secret(),
            auth::public_key_from_secret(&[9; 32]),
        )
        .unwrap();
    assert_eq!(child.verify(&[public_key()], 100).unwrap().not_after(), 110);
    assert!(
        token_a
            .attenuate(
                narrowed,
                b.signing_secret(),
                auth::public_key_from_secret(&[9; 32])
            )
            .is_err()
    );
}

#[tokio::test]
async fn expired_overflowing_and_discontinuous_time_refuse_issuance() {
    let fixture = Fixture::new();
    for (lifetime, margin, retirement, end, requested, times) in [
        (u64::MAX - 1, 0, None, 120, None, vec![100]),
        (60, 5, None, 95, None, vec![100]),
        (60, 5, None, u64::MAX, None, vec![100]),
        (60, 5, Some(100), 120, None, vec![100]),
        (60, 5, Some(0), 120, None, vec![100]),
        (60, 5, None, 120, Some(100), vec![100]),
        (60, 5, None, 120, None, vec![100, 99]),
        (60, 5, None, 120, None, vec![100, 125]),
    ] {
        let issuer = fixture.issuer(lifetime, margin, retirement);
        let mut claims = claims();
        claims.expected_end = end;
        claims.not_after = requested;
        assert!(matches!(
            issuer
                .mint(&TokioLocalFs, &Times::new(&times), claims)
                .await,
            Err(MintError::Lifetime)
        ));
    }
    let clock = Times {
        values: vec![UNIX_EPOCH - Duration::from_secs(1)],
        reads: AtomicUsize::new(0),
    };
    assert!(matches!(
        fixture
            .issuer(60, 5, None)
            .mint(&TokioLocalFs, &clock, claims())
            .await,
        Err(MintError::Clock)
    ));
}

#[tokio::test]
async fn missing_identity_and_invalid_canonical_grants_never_issue_credentials() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(60, 5, None);
    for mutation in 0..3 {
        let mut claims = claims();
        match mutation {
            0 => claims.subject.clear(),
            1 => claims.workload.clear(),
            _ => claims.grants.clear(),
        }
        assert!(matches!(
            issuer
                .mint(&TokioLocalFs, &Times::new(&[100]), claims)
                .await,
            Err(MintError::Claims)
        ));
    }
}

#[test]
fn key_file_rejects_links_inode_kinds_permissions_lengths_and_wrong_public_keys() {
    let fixture = Fixture::new();
    let open = |path: &std::path::Path, owner| {
        StaticKeyIssuer::open(path, owner, IssuerPolicy::new(public_key(), 60, 5).unwrap())
    };
    let link = fixture.directory.join("symlink");
    symlink(&fixture.key, &link).unwrap();
    assert!(open(&link, fixture.owner).is_err());
    let hard = fixture.directory.join("hardlink");
    fs::hard_link(&fixture.key, &hard).unwrap();
    assert!(open(&fixture.key, fixture.owner).is_err());
    fs::remove_file(hard).unwrap();
    assert!(open(&fixture.directory, fixture.owner).is_err());
    let fifo = fixture.directory.join("fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    assert!(open(&fifo, fixture.owner).is_err());
    assert!(open(&fixture.key, fixture.owner.wrapping_add(1)).is_err());
    // The sticky bit exercises special-bit refusal without Nix's setuid chmod
    // restriction preventing the fixture from reaching the issuer at all.
    for mode in [0o644, 0o660, 0o700, 0o1600] {
        fs::set_permissions(&fixture.key, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(fs::metadata(&fixture.key).unwrap().mode() & 0o7777, mode);
        assert!(open(&fixture.key, fixture.owner).is_err());
    }
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o600)).unwrap();
    for bytes in [vec![], vec![23; 31], vec![23; 33], vec![24; 32]] {
        fs::write(&fixture.key, bytes).unwrap();
        assert!(open(&fixture.key, fixture.owner).is_err());
    }
    fs::write(&fixture.key, SEED).unwrap();
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(open(&fixture.key, fixture.owner).is_ok());
}

#[test]
fn policy_paths_and_local_errors_fail_closed_without_disclosing_key_material() {
    for (lifetime, margin) in [(0, 0), (u64::MAX, 0), (60, 61)] {
        assert!(matches!(
            IssuerPolicy::new(public_key(), lifetime, margin),
            Err(MintError::Policy)
        ));
    }
    let fixture = Fixture::new();
    for path in [
        PathBuf::from("relative.seed"),
        fixture.directory.join("../issuer.seed"),
        fixture.directory.join("missing"),
    ] {
        let result = StaticKeyIssuer::open(
            &path,
            fixture.owner,
            IssuerPolicy::new(public_key(), 60, 5).unwrap(),
        );
        let error = result.err().unwrap();
        assert!(
            !error
                .to_string()
                .contains(&path.to_string_lossy().to_string())
        );
        assert!(!error.to_string().contains("23"));
    }
    let mut key = public_key();
    key.issuer.clear();
    assert!(IssuerPolicy::new(key, 60, 5).is_err());
    let mut key = public_key();
    key.key_id.clear();
    assert!(IssuerPolicy::new(key, 60, 5).is_err());
}
