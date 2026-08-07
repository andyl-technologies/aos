//! Checks the Crucible crate-root safe/unsafe fence.
//!
//! The crate table in RFC-0010 file 27 is the source of truth for which runtime
//! crates forbid `unsafe` entirely and which crates are explicit unsafe
//! boundaries. This test is the first `gate:harness-lint` shape check: adding a
//! new `crucible-*` package or changing a crate root fence must update this
//! executable list.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[path = "support/crate_unsafe_fence.rs"]
mod support;

use support::*;

const SAFE_FENCE: &str = "#![forbid(unsafe_code)]";
const UNSAFE_FENCE: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

#[derive(Clone, Copy)]
struct FenceSpec {
    package: &'static str,
    root: &'static str,
    unsafe_boundary: bool,
    safe_wrapper_contract: &'static [&'static str],
}

const FENCE_SPECS: &[FenceSpec] = &[
    FenceSpec {
        package: "crucible-cas",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-sim",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-assert",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-shmem",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "safe typed region accessors",
            "safe SPSC push/pop",
            "wrappers that uphold alignment",
        ],
    },
    FenceSpec {
        package: "crucible-protocol",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "public callers use safe setup descriptor handover wrappers",
            "validate the fixed two-fd order and descriptor count",
        ],
    },
    FenceSpec {
        package: "crucible-device",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-qemu",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "public callers use a safe host-driver API",
            "validates process and mapping invariants",
        ],
    },
    FenceSpec {
        package: "crucible-qemu-plugin",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "validate raw QEMU",
            "delegate to safe Rust shims",
        ],
    },
    FenceSpec {
        package: "crucible-debug-gateway",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-guest",
        root: "src/lib.rs",
        unsafe_boundary: true,
        safe_wrapper_contract: &[
            "Unsafe boundary discipline:",
            "public callers use safe doorbell and marker accessors",
            "guest/register and shared-region invariants",
        ],
    },
    FenceSpec {
        package: "crucible",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-session",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-api",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-daemon",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-cli",
        root: "src/main.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
    FenceSpec {
        package: "crucible-harness",
        root: "src/lib.rs",
        unsafe_boundary: false,
        safe_wrapper_contract: &[],
    },
];

#[test]
fn crucible_crate_roots_carry_declared_unsafe_fence() -> Result<(), Box<dyn std::error::Error>> {
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    assert_expected_crucible_package_set(&crates_dir, &mut failures)?;

    for spec in FENCE_SPECS {
        let root_path = crates_dir.join(spec.package).join(spec.root);
        let content = fs::read_to_string(&root_path)?;
        let active_attrs = crate_root_inner_attributes(&content);
        let required = if spec.unsafe_boundary {
            UNSAFE_FENCE
        } else {
            SAFE_FENCE
        };
        let rejected = if spec.unsafe_boundary {
            SAFE_FENCE
        } else {
            UNSAFE_FENCE
        };

        if !active_attrs.contains(&required) {
            failures.push(format!(
                "{}: missing required crate-root fence `{required}`",
                display_repo_path(&root_path)
            ));
        }

        if active_attrs.contains(&rejected) {
            failures.push(format!(
                "{}: carries contradictory crate-root fence `{rejected}`",
                display_repo_path(&root_path)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible crate unsafe-fence lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn unsafe_boundary_crates_document_safe_wrapper_contracts() -> Result<(), Box<dyn std::error::Error>>
{
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    for spec in FENCE_SPECS {
        let root_path = crates_dir.join(spec.package).join(spec.root);
        let content = fs::read_to_string(&root_path)?;

        if spec.unsafe_boundary && spec.safe_wrapper_contract.is_empty() {
            failures.push(format!(
                "{}: unsafe boundary has no safe-wrapper contract",
                display_repo_path(&root_path)
            ));
            continue;
        }

        for required in spec.safe_wrapper_contract {
            if !content.contains(required) {
                failures.push(format!(
                    "{}: missing safe-wrapper contract phrase `{required}`",
                    display_repo_path(&root_path)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible unsafe-boundary wrapper contract lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn unsafe_usage_is_confined_to_safe_wrapper_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    for spec in FENCE_SPECS {
        let package_dir = crates_dir.join(spec.package);
        for source in rust_sources(&package_dir)? {
            let content = fs::read_to_string(&source)?;
            failures.extend(unsafe_source_failures(
                &source,
                &content,
                spec.unsafe_boundary,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible unsafe source-boundary lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn crate_root_attribute_scanner_ignores_inactive_fences() {
    let source = r#"
//! Inner docs are allowed before crate attributes.
//! #![forbid(unsafe_code)]
/*
#![forbid(unsafe_code)]
*/
// #![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

fn later_item() {}
#![forbid(unsafe_code)]
"#;

    assert_eq!(
        crate_root_inner_attributes(source),
        vec![UNSAFE_FENCE],
        "only active crate-root inner attributes should be accepted"
    );
}

#[test]
fn unsafe_source_scanner_rejects_boundary_drift() {
    let safe_crate_findings = unsafe_source_failures(
        Path::new("crates/crucible/src/lib.rs"),
        r#"
            pub fn bad() {
                // SAFETY: this crate is not an enumerated unsafe boundary.
                unsafe {}
            }
        "#,
        false,
    );
    assert_contains(
        &safe_crate_findings,
        "outside enumerated unsafe-boundary crate",
    );

    let unsafe_boundary_findings = unsafe_source_failures(
        Path::new("crates/crucible-shmem/src/lib.rs"),
        r#"
            pub unsafe fn leaky_public_api() {}

            unsafe fn leaky_private_helper() {}

            pub trait LeakyTrait {
                unsafe fn leaky_trait_method();
            }

            unsafe extern "C" {
                pub fn raw_ffi_import();
                pub static mut RAW_STATE: u8;
            }

            unsafe extern "C" fn leaky_private_callback() {}

            unsafe impl Send for LeakyRing {}

            fn bare_block() {
                unsafe {}
            }

            fn stale_comment() {
                // SAFETY: separated from the block by a blank line.

                unsafe {}
            }

            fn empty_safety_comment() {
                // SAFETY:
                unsafe {}
            }
        "#,
        true,
    );
    assert_contains(&unsafe_boundary_findings, "unsafe item");
    assert_contains(&unsafe_boundary_findings, "unsafe impl without SAFETY");
    assert_contains(&unsafe_boundary_findings, "public unsafe API");
    assert_contains(&unsafe_boundary_findings, "public unsafe extern item");
    assert_contains(&unsafe_boundary_findings, "bare unsafe block");

    let allowed_boundary_findings = unsafe_source_failures(
        Path::new("crates/crucible-shmem/src/lib.rs"),
        r#"
            pub fn safe_wrapper() {
                // SAFETY: the wrapper validates the pointer before dereference.
                unsafe {}
            }

            unsafe extern "C" {
                fn private_raw_ffi_import();
            }

            // SAFETY: the ring wrapper owns the producer/consumer invariants.
            unsafe impl Send for PrivateRing {}
        "#,
        true,
    );
    assert!(
        allowed_boundary_findings.is_empty(),
        "expected private unsafe helper and safe wrapper sample to pass, got {allowed_boundary_findings:?}"
    );
}
