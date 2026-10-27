//! Runs real creator events and administrative success/refusal sequences.

use super::{
    config::{self, Case, LIMIT, SEED},
    observations::{self, Claims, Originals},
    stage,
};
use std::{
    fs::{self, File},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

/// Executes genuine creators and the actual administrative success or refusal flow.
///
/// # Errors
/// Returns actual creator, durable configuration, enrollment or native observation errors.
///
/// # Panics
/// Panics if a required physical fixture invariant is not observed.
pub(super) async fn run(selector: &str) -> io::Result<()> {
    stage("case-create before");
    let case = Case::create(selector)?;
    stage("case-create after");
    stage("write-intent before");
    case.write_intent(selector == "partial-quota")?;
    stage("write-intent after");
    if selector.starts_with("initialize-") {
        return initialize(&case, selector).await;
    }
    if selector == "preexisting" {
        let claims = Claims::capture()?;
        fs::create_dir(case.root(0))?;
        assert!(
            case.initial(0, SEED).await.is_err(),
            "existing root must not mint a creator receipt"
        );
        case.assert_unassigned()?;
        claims.assert_unchanged()?;
        println!("PASS actual pre-existing root refuses creator authority");
        return Ok(());
    }
    if selector == "reused-project" {
        provision_existing_owner(&case)?;
    }
    stage("core-public before");
    let mut receipts = vec![case.initial(0, SEED).await?];
    stage("core-public after");
    if selector != "incomplete" {
        stage("core-private before");
        receipts.push(
            case.initial(
                1,
                if selector == "wrong-profile" {
                    [8; 32]
                } else {
                    SEED
                },
            )
            .await?,
        );
        stage("core-private after");
    }
    stage("originals-capture before");
    let originals = Originals::capture(&receipts)?;
    stage("originals-capture after");
    stage("claims-capture before");
    let claims = Claims::capture()?;
    stage("claims-capture after");
    if selector == "unknown" {
        fs::write(
            case.root(0).join("unrecognized"),
            b"real unregistered namespace entry",
        )?;
    }
    stage("aos-provision before");
    let result = aos_terrane_integration::host::initial_enrollment::provision(
        &case.config(),
        &case.ledger(),
        &case.roles(),
        receipts,
    );
    stage("aos-provision returned");
    match selector {
        "positive" => {
            result?;
            stage("ready-ledger before");
            assert_eq!(observations::ledger_phase(&case.ledger())?, "ready");
            stage("ready-ledger after");
            stage("originals-verify before");
            originals.verify()?;
            stage("originals-verify after");
            stage("initial-claims-verify before");
            observations::verify_initial_claims(&case)?;
            stage("initial-claims-verify after");
            stage("private-custody before");
            let metadata = fs::metadata(case.root(1))?;
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
                (0, 845, 0o750)
            );
            stage("private-custody after");
            stage("hash-candidates before");
            let present = originals.present_private_hash(&case)?;
            let absent = present
                .parent()
                .ok_or_else(|| io::Error::other("snapshot has no parent"))?
                .join("0".repeat(64));
            assert!(!absent.exists());
            config::write_toml(
                &case.path.join("private-hash.toml"),
                &config::PrivateHash { present, absent },
                0o644,
            )?;
            stage("hash-candidates after");
            stage("claims-save before");
            Claims::capture()?.save(&case)?;
            stage("claims-save after");
            // The protected case parent prevented even temporary exposure while
            // the fresh factory's portable root was being created. Only the
            // final private traversal boundary permits publishing this parent.
            stage("case-publish before");
            fs::set_permissions(&case.path, fs::Permissions::from_mode(0o755))?;
            File::open(&case.path)?.sync_all()?;
            stage("case-publish after");
            println!(
                "PASS genuine same-process public/private first enrollment preserves original inodes and bytes"
            );
        }
        "partial-quota" => {
            #[allow(
                clippy::expect_used,
                reason = "The native fixture asserts a real kernel quota failure."
            )]
            let error = result.expect_err("1KiB finite project must reject real inode transfer");
            // Linux EDQUOT must come from the actual kernel operation; a
            // parser, stale-preimage or injected callback error is insufficient.
            const LINUX_EDQUOT: i32 = 122;
            assert_eq!(
                error.raw_os_error(),
                Some(LINUX_EDQUOT),
                "requires actual EDQUOT, observed {error}"
            );
            let administrative_project = terrane_linux::host_quota::NativeProject::inspect(
                &File::open(case.administrative(0))?,
            )?;
            assert!(
                originals.assigned_original([case.project(0), case.project(1)])?
                    || administrative_project.project_id == case.project(0),
                "must observe actual partial assignment of a durably claimed original or administrative directory"
            );
            assert_eq!(observations::ledger_phase(&case.ledger())?, "provisioning");
            observations::verify_initial_claims(&case)?;
            let retained = Claims::capture()?;
            assert!(
                aos_terrane_integration::host::serve(&case.config(), &case.ledger()).is_err(),
                "incomplete enrollment must refuse broker startup"
            );
            retained.verify_members()?;
            claims.verify_members()?;
            println!(
                "PASS actual partial EDQUOT leaves durable incomplete enrollment and permanent claims"
            );
        }
        "unknown" | "wrong-profile" | "incomplete" | "reused-project" => {
            assert!(
                result.is_err(),
                "real preflight refusal unexpectedly enrolled"
            );
            case.assert_unassigned()?;
            claims.assert_unchanged()?;
            println!("PASS real {selector} refuses before claims, scaffold and project setters");
        }
        _ => return Err(io::Error::other("invalid administrative selector")),
    }
    Ok(())
}

async fn initialize(case: &Case, selector: &str) -> io::Result<()> {
    for owner in 0..2 {
        fs::set_permissions(
            case.administrative(owner),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    let claims = Claims::capture()?;
    if selector == "initialize-existing" {
        fs::create_dir(case.root(1))?;
    } else if selector == "initialize-unsafe-parent" {
        fs::set_permissions(&case.path, fs::Permissions::from_mode(0o755))?;
    }
    let result = aos_terrane_integration::host::initial_enrollment::initialize(
        &case.config(),
        &case.ledger(),
        &case.roles(),
    )
    .await;

    if selector != "initialize-positive" {
        let error = result.err().ok_or_else(|| {
            io::Error::other("fresh partition initialization unexpectedly accepted unsafe input")
        })?;
        assert_eq!(
            error.kind(),
            if selector == "initialize-existing" {
                io::ErrorKind::AlreadyExists
            } else {
                io::ErrorKind::PermissionDenied
            }
        );
        assert!(
            !case.root(0).exists(),
            "complete preflight must precede the first creator"
        );
        case.assert_unassigned()?;
        claims.assert_unchanged()?;
        println!("PASS actual {selector} refuses the complete partition before creator effects");
        return Ok(());
    }

    result?;
    assert_eq!(observations::ledger_phase(&case.ledger())?, "ready");
    observations::verify_initial_claims(case)?;
    let ledger = fs::read(case.ledger())?;
    let retained_claims = Claims::capture()?;
    let roots = [fs::metadata(case.root(0))?, fs::metadata(case.root(1))?];
    assert!(
        aos_terrane_integration::host::initial_enrollment::initialize(
            &case.config(),
            &case.ledger(),
            &case.roles(),
        )
        .await
        .is_err(),
        "a completed initialization must never replay"
    );
    assert_eq!(fs::read(case.ledger())?, ledger);
    retained_claims.assert_unchanged()?;
    for (owner, original) in roots.iter().enumerate() {
        let current = fs::metadata(case.root(owner))?;
        assert_eq!(
            (current.dev(), current.ino()),
            (original.dev(), original.ino())
        );
        let project =
            terrane_linux::host_quota::NativeProject::inspect(&File::open(case.root(owner))?)?;
        assert_eq!(project.project_id, case.project(owner));
        assert_eq!(current.uid(), 0);
        assert_eq!(
            current.mode() & 0o7777,
            if owner == 0 { 0o755 } else { 0o750 }
        );
    }
    println!(
        "PASS actual complete fresh initialization creates genuine public/private buckets and refuses replay without mutation"
    );
    Ok(())
}

fn provision_existing_owner(case: &Case) -> io::Result<()> {
    let layout = case.path.join("existing-owner");
    fs::create_dir(&layout)?;
    for label in terrane_linux::host_quota::ROOT_LABELS {
        if label != "layout-root" {
            fs::create_dir(layout.join(label))?;
        }
    }
    let config_path = case.path.join("existing-host.toml");
    config::write_toml(
        &config_path,
        &config::Host {
            socket: case.path.join("existing.sock"),
            epoch: "000000000000000000000000000000ff".to_owned(),
            tier_charge_budget_bytes: LIMIT,
            owners: vec![config::Owner {
                owner_id: "legitimate-existing-owner".to_owned(),
                domain: "public".to_owned(),
                project_id: case.project(0),
                hard_limit_bytes: LIMIT,
                allowed_client_uids: vec![840, 841],
                roots: config::roots(&layout, None),
            }],
        },
        0o600,
    )?;
    // The ordinary helper performs its real complete global claim and ledger
    // ordering. No fixture directly assigns an unclaimed project identifier.
    aos_terrane_integration::host::provision(
        &config_path,
        &case.path.join("existing-ledger.toml"),
    )?;
    let quota =
        terrane_linux::host_quota::NativeQuota::query(&File::open(&layout)?, case.project(0))?;
    assert_eq!(quota.hard_limit_bytes, LIMIT);
    Ok(())
}
