//! Dispatches fixed native selectors without serializing creator authority.

#[path = "admin.rs"]
mod admin;
#[path = "capabilities.rs"]
mod capabilities;
#[path = "config.rs"]
mod config;
#[path = "observations.rs"]
mod observations;
#[path = "publisher.rs"]
mod publisher;
#[path = "reader.rs"]
mod reader;

use std::io;

const SELECTORS: &[&str] = &[
    "positive",
    "unknown",
    "wrong-profile",
    "incomplete",
    "preexisting",
    "reused-project",
    "partial-quota",
    "initialize-positive",
    "initialize-existing",
    "initialize-unsafe-parent",
    "serve-positive",
    "publisher-positive",
    "publisher-reassembly",
    "reassembly-public-private",
    "release-public-private",
    "seed-release-public-private",
    "recovered-release-public-private",
    "seed-manifest-release-public-private",
    "recovered-manifest-release-public-private",
    "ready-public-private",
    "open-public-private",
    "verify-positive",
    "read-public",
    "read-private",
    "read-publisher",
    "foreign-private",
    "capabilities-update",
];

/// Dispatches one fixed native fixture selector.
///
/// # Errors
/// Returns invalid-selector, native authorization, runtime, fixture or explicitly
/// unsupported-operation errors.
///
/// # Panics
/// Panics if a required physical fixture invariant is not observed.
pub(super) fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() == 1 && arguments[0] == "--list" {
        for selector in SELECTORS {
            println!("{selector}");
        }
        return Ok(());
    }
    let [selector] = arguments.as_slice() else {
        return Err(io::Error::other("requires one fixed fixture selector"));
    };
    let result = match selector.as_str() {
        "serve-positive" => {
            stage("native-root-check before");
            terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
            stage("native-root-check after");
            let case = config::Case::existing("positive")?;
            aos_terrane_integration::host::serve(&case.config(), &case.ledger())
        }
        "verify-positive" => {
            stage("native-root-check before");
            terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
            stage("native-root-check after");
            let case = config::Case::existing("positive")?;
            observations::Claims::read_saved(&case)?.verify_members()?;
            println!("PASS immutable initial claim bytes and incarnations");
            Ok(())
        }
        "publisher-positive" => publisher::run(),
        "publisher-reassembly" => publisher::run_reassembly(),
        "reassembly-public-private" => publisher::prepare_reassembly(),
        "release-public-private" => publisher::prepare_release(),
        "seed-release-public-private" => publisher::seed_release(),
        "recovered-release-public-private" => publisher::recovered_release(),
        "seed-manifest-release-public-private" => publisher::seed_manifest_release(),
        "recovered-manifest-release-public-private" => publisher::recovered_manifest_release(),
        "ready-public-private" => publisher::prepare(),
        "open-public-private" => publisher::prepare_objects(),
        "read-public" | "read-private" | "read-publisher" | "foreign-private" => {
            reader::run(selector)
        }
        "capabilities-update" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(capabilities::run())
        }
        selector if SELECTORS.contains(&selector) => {
            stage("native-root-check before");
            terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
            stage("native-root-check after");
            stage("tokio-runtime before");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            stage("tokio-runtime after");
            runtime.block_on(admin::run(selector))
        }
        _ => Err(io::Error::other(
            "unknown initial enrollment fixture selector",
        )),
    };
    if result.is_ok() {
        println!("INITIAL_ENROLLMENT_PASS {selector}");
    }
    result
}

fn source_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

// Fixed labels locate a failed operation without inspecting or wrapping its error.
fn stage(label: &'static str) {
    use std::io::Write as _;
    let _ = writeln!(io::stderr().lock(), "INITIAL_ENROLLMENT_STAGE {label}");
}
