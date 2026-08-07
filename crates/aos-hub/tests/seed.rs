//! Integration coverage for the dev seed (RFC-0004 `serve --dev --seed`).
//!
//! Verifies that [`seed_dev`](aos_hub::seed::seed_dev) populates a
//! fresh hub with the demo org/user/instance-binding/registry, that the generated
//! surface verifies and indexes (so `list_packages` shows the seeded
//! packages), that the demo user can log in with the seeded password, and that
//! re-running the seed is a safe no-op.

use aos_hub::auth::password::verify_password;
use aos_hub::db::Database;
use aos_hub::seed::{
    seed_dev, SeedOutcome, SeedRouteConfig, DEMO_EMAIL, DEMO_ORG, DEMO_PASSWORD,
    DEMO_PRIVATE_REGISTRY,
};
use aos_hub_core::service::RouteReservationKey;

fn route_config<'a>(keys: &'a [RouteReservationKey]) -> SeedRouteConfig<'a> {
    SeedRouteConfig {
        listen_addr: "127.0.0.1:8420".parse().unwrap(),
        external_url: "http://127.0.0.1:8420",
        reservation_keys: keys,
    }
}

#[tokio::test]
async fn seed_creates_browsable_registry_and_login() {
    let root = tempfile::tempdir().unwrap();
    let db = Database::open(&root.path().join("hub.db")).await.unwrap();

    let keys = [RouteReservationKey {
        version: 1,
        secret: vec![9; 32],
        active: true,
    }];
    let report = match seed_dev(&db, root.path(), &route_config(&keys))
        .await
        .unwrap()
    {
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
    assert!(db.list_storage_bindings(org.id).await.unwrap().is_empty());
    let binding = db
        .instance_default_binding()
        .await
        .unwrap()
        .expect("seed instance binding exists");
    assert_eq!(binding.kind, "local_fs");
    assert_eq!(
        binding.local_root_path.as_deref(),
        Some(root.path().join("storage").to_string_lossy().as_ref())
    );

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
    assert!(names.contains(&"aos-system".to_string()), "{names:?}");
    let images = db.list_system_images(registry.id).await.unwrap();
    assert_eq!(images.len(), 2);
    assert!(images.iter().any(|image| image.format == "raw"));
    assert!(images.iter().any(|image| image.format == "qcow2"));
    let private = db
        .registry_by_slug(&format!("{DEMO_ORG}/{DEMO_PRIVATE_REGISTRY}"))
        .await
        .unwrap()
        .expect("private image registry exists");
    assert_eq!(private.visibility, "private");
    assert_eq!(db.list_system_images(private.id).await.unwrap().len(), 2);
    assert_eq!(
        db.ready_registry_canonical_url(registry.id)
            .await
            .unwrap()
            .as_deref(),
        Some("http://127.0.0.1:8420/demo/cdn")
    );
    assert_eq!(
        db.ready_registry_canonical_url(private.id)
            .await
            .unwrap()
            .as_deref(),
        Some("http://127.0.0.1:8420/demo/private-images")
    );

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
    let keys = [RouteReservationKey {
        version: 1,
        secret: vec![9; 32],
        active: true,
    }];

    assert!(matches!(
        seed_dev(&db, root.path(), &route_config(&keys))
            .await
            .unwrap(),
        SeedOutcome::Seeded(_)
    ));

    // A second run detects the existing demo org and skips.
    assert!(matches!(
        seed_dev(&db, root.path(), &route_config(&keys))
            .await
            .unwrap(),
        SeedOutcome::AlreadySeeded
    ));

    // Still exactly one org / the same public+private registries — no duplication.
    let org = db.org_by_slug(DEMO_ORG).await.unwrap().unwrap();
    assert_eq!(db.org_registry_count(org.id).await.unwrap(), 2);
}
