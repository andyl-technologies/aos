//! Integration coverage for the dev seed (RFC-0004 `serve --dev --seed`).
//!
//! Verifies that [`seed_dev`](aos_hub::seed::seed_dev) populates a
//! fresh hub with the demo org/user/binding/registry, that the generated
//! surface verifies and indexes (so `list_packages` shows the seeded
//! packages), that the demo user can log in with the seeded password, and that
//! re-running the seed is a safe no-op.

use aos_hub::auth::password::verify_password;
use aos_hub::db::Database;
use aos_hub::seed::{seed_dev, SeedOutcome, DEMO_EMAIL, DEMO_ORG, DEMO_PASSWORD};

#[tokio::test]
async fn seed_creates_browsable_registry_and_login() {
    let root = tempfile::tempdir().unwrap();
    let db = Database::open(&root.path().join("hub.db")).await.unwrap();

    let report = match seed_dev(&db, root.path()).await.unwrap() {
        SeedOutcome::Seeded(report) => report,
        SeedOutcome::AlreadySeeded => panic!("fresh hub should seed"),
    };

    // Org, project, user, membership all exist.
    let org = db
        .org_by_slug(DEMO_ORG)
        .await
        .unwrap()
        .expect("demo org exists");
    assert_eq!(db.list_projects(org.id).await.unwrap().len(), 1);
    let user = db
        .user_by_email(DEMO_EMAIL)
        .await
        .unwrap()
        .expect("demo user exists");
    assert_eq!(db.list_storage_bindings(org.id).await.unwrap().len(), 1);

    // The demo user can log in with the seeded password.
    let (_, phc) = db
        .user_for_password(DEMO_EMAIL)
        .await
        .unwrap()
        .expect("demo user has a password");
    assert!(verify_password(DEMO_PASSWORD, &phc));
    assert!(db.user_has_password(user).await.unwrap());

    // The registry exists, is bound, and indexed cleanly — list_packages shows
    // the seeded packages (the generated surface verified).
    let registry = db
        .registry_by_slug(&report.canonical)
        .await
        .unwrap()
        .expect("seeded registry exists");
    let packages = db.list_packages(registry.id).await.unwrap();
    let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
    assert!(names.contains(&"curl".to_string()), "{names:?}");
    assert!(names.contains(&"openssl".to_string()), "{names:?}");
    assert!(names.contains(&"jq".to_string()), "{names:?}");

    // A release + channel were indexed (require_signatures was on, so this only
    // happens if every signature verified).
    assert!(!db.list_releases(registry.id).await.unwrap().is_empty());
    assert!(!db.list_channels(registry.id).await.unwrap().is_empty());

    // The report carries usable demo creds + a publish token.
    assert_eq!(report.login_email, DEMO_EMAIL);
    assert_eq!(report.login_password, DEMO_PASSWORD);
    assert!(!report.token_secret.is_empty());
    assert_eq!(report.browse_url, format!("/{}/", report.canonical));
}

#[tokio::test]
async fn re_seeding_is_a_safe_no_op() {
    let root = tempfile::tempdir().unwrap();
    let db = Database::open(&root.path().join("hub.db")).await.unwrap();

    assert!(matches!(
        seed_dev(&db, root.path()).await.unwrap(),
        SeedOutcome::Seeded(_)
    ));

    // A second run detects the existing demo org and skips.
    assert!(matches!(
        seed_dev(&db, root.path()).await.unwrap(),
        SeedOutcome::AlreadySeeded
    ));

    // Still exactly one org / one registry — no duplication.
    let org = db.org_by_slug(DEMO_ORG).await.unwrap().unwrap();
    assert_eq!(db.org_registry_count(org.id).await.unwrap(), 1);
}
