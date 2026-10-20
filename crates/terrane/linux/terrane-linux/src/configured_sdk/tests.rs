//! Checks pure refusal ordering, bounded credential I/O and diagnostic redaction.
//!
//! These tests never install the irreversible filter. Actual single-process
//! startup belongs to the explicitly invoked configured SDK example fixture.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    error::Error as _,
    fs::{self, File},
    io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use terrane_sdk::{config::Config, repository::Error as RepositoryError, role::Role};

use super::{Error, FailureKind, TOKEN_FILE_BYTE_BUDGET, preflight, tokens};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TRUST: &str = r#"
[local_repository]
authority_directory = "/missing-configured-sdk-authority"
issuer = "explicit"
key_id = "existing"
owner_uid = 840
store_name = "local"
domain = "public"
default_private_domain = "private:operator"
current_reference = "refs/heads/_/main"
acl = []
[local_repository.timing]
maximum_ms = 30000
grace_ms = 60000
margin_ms = 10000
"#;

fn configuration(
    store: &str,
    exposure: &str,
    extra: &str,
) -> Result<Config, terrane_sdk::config::ConfigError> {
    Config::parse(&format!("store = '{store}'\n{exposure}\n{TRUST}\n{extra}"))
}

fn exposure(id: &str, endpoint: &str, token: &str) -> String {
    format!(
        "[[expose]]\nid='{id}'\nview='refs/heads/_/main'\nsurface='sdk'\nat='{endpoint}'\ntoken='{token}'\nmode={{reader='pinned'}}\n"
    )
}

#[test]
fn preflight_refuses_unavailable_compositions_before_missing_authority_io() -> TestResult {
    for store in [
        "disk(/missing-cache)",
        "bucket(s3://missing/prefix)",
        "routed[bucket(file:///missing-bucket),disk(/missing-cache)]",
    ] {
        let config = configuration(store, "", "")?;
        let error = preflight(&config, Role::Serve).expect_err("unsupported store");
        assert_eq!(error.kind(), FailureKind::UnsupportedStore);
        assert!(!error.requires_process_exit());
    }
    let config = configuration(
        "bucket(file:///missing-configured-sdk-bucket)",
        "",
        "[host_tier]\npath='/missing-cache'\nsize_bytes=1024\nreassembly='never'\n",
    )?;
    assert_eq!(
        preflight(&config, Role::Serve)
            .expect_err("host tier unavailable")
            .kind(),
        FailureKind::HostTierUnavailable
    );
    Ok(())
}

#[test]
fn preflight_refuses_roles_and_missing_trust_without_installation() -> TestResult {
    let config = configuration("bucket(file:///missing-configured-sdk-bucket)", "", "")?;
    for role in [
        Role::Publish,
        Role::Gc,
        Role::Realize,
        Role::FuseWorker,
        Role::Job,
    ] {
        let error = preflight(&config, role).expect_err("serve-only repository owner");
        assert_eq!(error.kind(), FailureKind::ServeOnly);
        assert!(!error.requires_process_exit());
    }
    let missing = Config::parse("store='bucket(file:///missing-configured-sdk-bucket)'")?;
    assert_eq!(
        preflight(&missing, Role::Serve)
            .expect_err("no inferred authority")
            .kind(),
        FailureKind::MissingLocalTrust
    );
    assert_eq!(
        preflight(&config, Role::Serve)
            .expect_err("no fake empty daemon")
            .kind(),
        FailureKind::EmptyExposures
    );
    Ok(())
}

#[test]
fn role_selection_and_instance_credentials_fail_before_any_repository_open() -> TestResult {
    let config = Config::parse(&format!(
        "role='serve'\nstore='bucket(file:///missing-configured-sdk-bucket)'\n{TRUST}"
    ))?;
    let error = preflight(&config, Role::Publish).expect_err("explicit role mismatch");
    assert_eq!(error.kind(), FailureKind::RoleSelection);
    assert!(!error.requires_process_exit());

    let config = configuration(
        "bucket(file:///missing-configured-sdk-bucket)",
        "",
        "[tokens]\nhost_token='file:/missing-instance-capability'\n",
    )?;
    let error = preflight(&config, Role::Serve).expect_err("no implicit instance token use");
    assert_eq!(error.kind(), FailureKind::InstanceCredentialsUnavailable);
    assert!(!error.requires_process_exit());
    Ok(())
}

#[test]
fn encoded_bucket_traversal_is_rejected_without_path_normalization() -> TestResult {
    let config = configuration("bucket(file:///tmp/%2e%2e/forbidden)", "", "")?;
    assert_eq!(
        preflight(&config, Role::Serve)
            .expect_err("encoded traversal")
            .kind(),
        FailureKind::InvalidPath
    );
    Ok(())
}

#[test]
fn pure_sdk_profile_matches_the_actual_compiled_registry() -> TestResult {
    let parsed = configuration(
        "bucket(file:///missing-configured-sdk-bucket)",
        &exposure(
            "snapshot",
            "/missing-configured-sdk-output",
            "file:/missing-capability",
        ),
        "",
    );
    if terrane_sdk::surface::registration("sdk").is_none() {
        assert!(
            matches!(parsed, Err(terrane_sdk::config::ConfigError::UnavailableSurface(name)) if name == "sdk")
        );
    } else {
        let config = parsed?;
        let plan = preflight(&config, Role::Serve)?;
        assert!(!format!("{plan:?}").contains("missing-capability"));
    }
    Ok(())
}

#[test]
fn complete_exposure_list_rejects_late_unsupported_credentials_without_effects() -> TestResult {
    let exposures = exposure(
        "first",
        "/missing-sdk-first",
        "file:/missing-valid-capability",
    ) + &exposure(
        "second",
        "/missing-sdk-second",
        "secret:unsupported-provider",
    );
    let parsed = configuration(
        "bucket(file:///missing-configured-sdk-bucket)",
        &exposures,
        "",
    );
    if terrane_sdk::surface::registration("sdk").is_none() {
        assert!(
            matches!(parsed, Err(terrane_sdk::config::ConfigError::UnavailableSurface(name)) if name == "sdk")
        );
        return Ok(());
    }
    let config = parsed?;
    let error = preflight(&config, Role::Serve).expect_err("no pretend secret provider");
    assert_eq!(error.kind(), FailureKind::UnsupportedCredentialReference);
    assert!(!error.requires_process_exit());
    Ok(())
}

#[test]
fn preflight_rejects_endpoints_overlapping_repository_state() -> TestResult {
    let parsed = configuration(
        "bucket(file:///missing-configured-sdk-bucket)",
        &exposure(
            "snapshot",
            "/missing-configured-sdk-bucket/output",
            "file:/missing-capability",
        ),
        "",
    );
    if terrane_sdk::surface::registration("sdk").is_none() {
        assert!(
            matches!(parsed, Err(terrane_sdk::config::ConfigError::UnavailableSurface(name)) if name == "sdk")
        );
        return Ok(());
    }
    let config = parsed?;
    assert_eq!(
        preflight(&config, Role::Serve)
            .expect_err("repository overlap")
            .kind(),
        FailureKind::OverlappingEndpoint
    );
    Ok(())
}

#[test]
fn credential_references_have_no_provider_or_path_normalization_fallback() {
    for reference in [
        "relative",
        "file:relative",
        "secret:locator",
        "anonymous:refs/heads/_/main:read",
        "file:/",
        "/tmp/../secret",
        "/tmp/./secret",
        "/tmp//secret",
        "/tmp/secret/",
    ] {
        assert!(
            tokens::credential_path(reference).is_err(),
            "accepted {reference}"
        );
    }
    assert_eq!(
        tokens::credential_path("file:/tmp/explicit.cap").expect("explicit file"),
        Path::new("/tmp/explicit.cap")
    );
    assert_eq!(
        tokens::credential_path("/tmp/explicit.cap").expect("absolute file"),
        Path::new("/tmp/explicit.cap")
    );
}

#[test]
fn native_token_reads_are_regular_nofollow_and_bounded() -> TestResult {
    let temporary = Temporary::new()?;
    let token = temporary.0.join("explicit.cap");
    fs::write(&token, b"explicit exposure capability")?;
    assert_eq!(tokens::read_token(&token)?, b"explicit exposure capability");

    let link = temporary.0.join("alias.cap");
    symlink(&token, &link)?;
    assert!(tokens::read_token(&link).is_err());
    let alias = temporary.0.join("alias-parent");
    symlink(&temporary.0, &alias)?;
    assert!(tokens::read_token(&alias.join("explicit.cap")).is_err());
    assert_eq!(
        tokens::read_token(&temporary.0),
        Err(tokens::TokenFileError::NotRegular)
    );

    let oversized = temporary.0.join("oversized.cap");
    File::create(&oversized)?.set_len(TOKEN_FILE_BYTE_BUDGET as u64 + 1)?;
    assert_eq!(
        tokens::read_token(&oversized),
        Err(tokens::TokenFileError::TooLarge)
    );
    let empty = temporary.0.join("empty.cap");
    File::create(&empty)?;
    assert_eq!(
        tokens::read_token(&empty),
        Err(tokens::TokenFileError::Empty)
    );
    Ok(())
}

#[test]
fn fifo_and_device_credentials_are_classified_before_any_read() -> TestResult {
    let temporary = Temporary::new()?;
    let fifo = temporary.0.join("token.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    assert_eq!(
        tokens::read_token(&fifo),
        Err(tokens::TokenFileError::NotRegular)
    );
    assert_eq!(
        tokens::read_token(Path::new("/dev/null")),
        Err(tokens::TokenFileError::NotRegular)
    );
    Ok(())
}

#[test]
fn failure_display_debug_and_entire_source_chain_redact_private_data() {
    const SECRET: &str = "capability-bytes-must-never-appear";
    let error = Error::repository(
        FailureKind::Preparation,
        RepositoryError::Io(io::Error::other(SECRET)),
    );
    assert_eq!(error.io_kind(), Some(io::ErrorKind::Other));
    assert!(error.requires_process_exit());
    assert!(!format!("{error}: {error:?}").contains(SECRET));
    let mut source = error.source();
    while let Some(cause) = source {
        assert!(!format!("{cause}: {cause:?}").contains(SECRET));
        source = cause.source();
    }
}

struct Temporary(PathBuf);

impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "terrane-sdk-token-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("could not allocate owned test directory"))
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        // A test panic must not replace its original diagnostic with cleanup.
        let _ = fs::remove_dir_all(&self.0);
    }
}
