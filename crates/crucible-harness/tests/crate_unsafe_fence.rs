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

const SAFE_FENCE: &str = "#![forbid(unsafe_code)]";
const UNSAFE_FENCE: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

#[derive(Clone, Copy)]
struct FenceSpec {
    package: &'static str,
    root: &'static str,
    unsafe_boundary: bool,
}

const FENCE_SPECS: &[FenceSpec] = &[
    FenceSpec {
        package: "crucible-sim",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-assert",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-shmem",
        root: "src/lib.rs",
        unsafe_boundary: true,
    },
    FenceSpec {
        package: "crucible-protocol",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-device",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-qemu",
        root: "src/lib.rs",
        unsafe_boundary: true,
    },
    FenceSpec {
        package: "crucible-qemu-plugin",
        root: "src/lib.rs",
        unsafe_boundary: true,
    },
    FenceSpec {
        package: "crucible-guest",
        root: "src/lib.rs",
        unsafe_boundary: true,
    },
    FenceSpec {
        package: "crucible",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-session",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-api",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-daemon",
        root: "src/lib.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-cli",
        root: "src/main.rs",
        unsafe_boundary: false,
    },
    FenceSpec {
        package: "crucible-harness",
        root: "src/lib.rs",
        unsafe_boundary: false,
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

fn crate_root_inner_attributes(source: &str) -> Vec<&str> {
    let mut attrs = Vec::new();
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//!") {
            continue;
        }

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }

        if let Some(attribute) = active_inner_attribute(trimmed) {
            attrs.push(attribute);
            continue;
        }

        break;
    }

    attrs
}

fn active_inner_attribute(line: &str) -> Option<&str> {
    let candidate = match line.split_once("//") {
        Some((before_comment, _comment)) => before_comment.trim_end(),
        None => line,
    };

    candidate.strip_prefix("#![")?;
    Some(candidate)
}

fn workspace_crates_dir() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("crucible-harness manifest is not inside crates/"))
}

fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected: Vec<String> = FENCE_SPECS
        .iter()
        .map(|spec| spec.package.to_string())
        .collect();
    expected.sort();

    let mut found = Vec::new();
    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("crucible") {
            found.push(name);
        }
    }
    found.sort();

    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected [{}], found [{}]",
            expected.join(", "),
            found.join(", ")
        ));
    }

    Ok(())
}

fn display_repo_path(path: &Path) -> String {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new(""));
    path.strip_prefix(crates_dir)
        .map(|relative| format!("crates/{}", relative.display()))
        .unwrap_or_else(|_| path.display().to_string())
}
