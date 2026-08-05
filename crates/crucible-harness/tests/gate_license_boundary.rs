//! Enforces `gate:license-boundary` for the Crucible/QEMU process boundary.
//!
//! The gate is intentionally static and package-independent: it reads Cargo
//! metadata, source text, the public interface manifest, the generated C view,
//! and committed golden bytes without linking the QEMU plugin or importing
//! QEMU internals.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

const APACHE_LICENSE: &str = "Apache-2.0";
const BOUNDARY_LICENSE: &str = "MIT OR Apache-2.0";
const PLUGIN_LICENSE: &str = "GPL-2.0-only";
const PLUGIN_PACKAGE: &str = "crucible-qemu-plugin";
const DEBUG_GATEWAY_PACKAGE: &str = "crucible-debug-gateway";
const BOUNDARY_PACKAGES: &[&str] = &["crucible-protocol", "crucible-shmem"];

#[path = "gate_license_boundary/contributor_authorization.rs"]
mod contributor_authorization;
#[path = "gate_license_boundary/dependencies.rs"]
mod dependencies;
#[path = "gate_license_boundary/guest_assertions.rs"]
mod guest_assertions;

#[test]
fn repository_publishes_each_declared_license_scope() -> Result<(), Box<dyn Error>> {
    let root = workspace_crates_dir()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("crates/ must be inside the repository")?;
    for (relative, identifying_text) in [
        ("LICENSES/Apache-2.0.txt", "Apache License"),
        ("LICENSES/MIT.txt", "Permission is hereby granted"),
        ("LICENSES/GPL-2.0-only.txt", "GNU GENERAL PUBLIC LICENSE"),
        (
            "LICENSES/GPL-2.0-or-later.txt",
            "GNU GENERAL PUBLIC LICENSE",
        ),
    ] {
        let content = fs::read_to_string(root.join(relative))?;
        assert!(
            content.contains(identifying_text),
            "{relative} does not contain the expected license text"
        );
    }

    let licensing = fs::read_to_string(root.join("LICENSING.md"))?;
    for marker in [
        "`crucible-protocol` and `crucible-shmem` | MIT OR Apache-2.0",
        "`crucible-qemu-plugin` | GPL-2.0-only",
        "`crucible-debug-gateway` | GPL-2.0-only",
        "`crucible-qemu-trace-plugin` | GPL-2.0-only",
        "unmarked files default to GPL-2.0-or-later",
        "shared memory is the high-throughput data plane",
        "complete corresponding source",
    ] {
        assert!(
            licensing.contains(marker),
            "LICENSING.md must contain `{marker}`"
        );
    }
    let readme = fs::read_to_string(root.join("README.md"))?;
    assert!(readme.contains("license-multi--license"));
    assert!(readme.contains("[contribution requirements](CONTRIBUTING.md)"));
    Ok(())
}

#[test]
fn qemu_patch_created_files_match_license_inventory() -> Result<(), Box<dyn Error>> {
    let root = workspace_crates_dir()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("crates/ must be inside the repository")?;
    let patch_dir = root.join("pkgs/emulation/qemu-patches");
    let mut created = BTreeSet::new();

    for entry in fs::read_dir(&patch_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("patch") {
            continue;
        }
        let patch = fs::read_to_string(path)?;
        let mut lines = patch.lines();
        while let Some(line) = lines.next() {
            if line != "--- /dev/null" {
                continue;
            }
            let created_line = lines.next().ok_or("new-file patch lacks +++ path")?;
            let path = created_line
                .strip_prefix("+++ b/")
                .ok_or("new-file patch has an unexpected +++ path")?;
            created.insert(path.to_owned());
        }
    }

    let expected = BTreeSet::from([
        "accel/tcg/crucible-translation-prefetch.c".to_owned(),
        "accel/tcg/tcg-accel-ops-preemption.c".to_owned(),
        "accel/tcg/tcg-accel-ops-sim-shmem.c".to_owned(),
        "accel/tcg/tcg-accel-ops-sim-shmem.h".to_owned(),
        "accel/tcg/tcg-accel-ops-sim.c".to_owned(),
        "block/crucible-shmem.c".to_owned(),
        "include/system/crucible-plugin-wake.h".to_owned(),
        "include/system/crucible-sim-ipi.h".to_owned(),
        "include/system/crucible-sim-preemption.h".to_owned(),
    ]);
    assert_eq!(created, expected, "QEMU patch-created file set drifted");

    let inventory = fs::read_to_string(patch_dir.join("LICENSES.md"))?;
    for path in expected {
        let row = format!("| `{path}` | GPL-2.0-or-later |");
        assert!(
            inventory.contains(&row),
            "QEMU patch license inventory must contain `{row}`"
        );
    }
    Ok(())
}

#[test]
fn cargo_metadata_preserves_component_licenses() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let workspace: Value = fs::read_to_string(crates.join("Cargo.toml"))?.parse()?;
    assert_eq!(
        workspace["workspace"]["package"]["license"].as_str(),
        Some(APACHE_LICENSE)
    );

    let members = workspace["workspace"]["members"]
        .as_array()
        .ok_or("workspace.members must be an array")?;
    let mut failures = Vec::new();

    for member in members {
        let package = member.as_str().ok_or("workspace member must be a string")?;
        let manifest_path = crates.join(package).join("Cargo.toml");
        let manifest: Value = fs::read_to_string(&manifest_path)?.parse()?;
        let package_table = manifest["package"]
            .as_table()
            .ok_or("package metadata must be a table")?;
        let package_name = package_table["name"]
            .as_str()
            .ok_or("package.name must be a string")?;
        let expected = expected_license(package_name);
        let actual = declared_package_license(package_table, APACHE_LICENSE);

        if actual.as_deref() != Some(expected) {
            failures.push(format!(
                "{}: expected explicit license `{expected}`, found {actual:?}",
                display_repo_path(&manifest_path)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Cargo license boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn gpl_side_internal_dependencies_are_only_permissive_boundary_crates() -> Result<(), Box<dyn Error>>
{
    let crates = workspace_crates_dir()?;
    let workspace: Value = fs::read_to_string(crates.join("Cargo.toml"))?.parse()?;
    let workspace_dependencies = workspace["workspace"]["dependencies"]
        .as_table()
        .ok_or("workspace.dependencies must be a table")?;
    let mut failures = Vec::new();

    for gpl_package in [PLUGIN_PACKAGE, DEBUG_GATEWAY_PACKAGE] {
        let manifest_path = crates.join(gpl_package).join("Cargo.toml");
        let manifest: Value = fs::read_to_string(&manifest_path)?.parse()?;
        dependencies::visit_production_dependency_tables(
            &manifest,
            &mut |table_name, dependencies| {
                for (name, dependency) in dependencies {
                    let package = dependencies::resolved_dependency_package(
                        name,
                        dependency,
                        workspace_dependencies,
                    );
                    let is_internal_crucible =
                        package == "crucible" || package.starts_with("crucible-");
                    if is_internal_crucible && !BOUNDARY_PACKAGES.contains(&package) {
                        failures.push(format!(
                            "{gpl_package}: production {table_name} entry `{package}` crosses the GPL boundary"
                        ));
                    }
                }
            },
        )?;
    }

    for boundary in BOUNDARY_PACKAGES {
        let boundary_manifest: Value =
            fs::read_to_string(crates.join(boundary).join("Cargo.toml"))?.parse()?;
        assert_eq!(
            boundary_manifest["package"]["license"].as_str(),
            Some(BOUNDARY_LICENSE),
            "{boundary} must remain GPL-compatible"
        );
    }

    let plugin_package = fs::read_to_string(
        crates
            .parent()
            .ok_or("crates/ must be inside the repository")?
            .join("pkgs/emulation/crucible-qemu-plugin.nix"),
    )?;
    assert!(
        plugin_package.contains("LICENSES/MIT.txt"),
        "the GPL plugin package must retain the MIT notice for its dual-licensed boundary crates"
    );
    let gateway_package = fs::read_to_string(
        crates
            .parent()
            .ok_or("crates/ must be inside the repository")?
            .join("pkgs/tools/crucible/crucible.nix"),
    )?;
    for marker in [
        "LICENSES/GPL-2.0-only.txt",
        "share/licenses/crucible-debug-gateway/COMPONENT",
        "crucible-protocol is used under its MIT option",
    ] {
        assert!(
            gateway_package.contains(marker),
            "the GPL debugger gateway package must contain `{marker}`"
        );
    }

    assert!(
        failures.is_empty(),
        "GPL-side dependency boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn apache_host_crates_do_not_define_qemu_plugin_abi() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let mut failures = Vec::new();

    for entry in fs::read_dir(&crates)? {
        let entry = entry?;
        let package_dir = entry.path();
        if !package_dir.join("Cargo.toml").is_file() {
            continue;
        }
        let package = entry.file_name().to_string_lossy().into_owned();
        if package == PLUGIN_PACKAGE {
            continue;
        }
        visit_rust_sources(&package_dir.join("src"), &mut |path, source| {
            for forbidden in dependencies::forbidden_qemu_abi_surfaces(source) {
                if source.contains(forbidden) {
                    failures.push(format!(
                        "{}: non-plugin source contains forbidden QEMU ABI surface `{forbidden}`",
                        display_repo_path(path)
                    ));
                }
            }
        })?;
    }

    assert!(
        failures.is_empty(),
        "QEMU ABI leaked into non-plugin workspace code:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn public_shmem_interface_is_process_shaped() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let shmem = crates.join("crucible-shmem");
    let interface_path = shmem.join("interface/crucible-shmem-abi.toml");
    let interface: Value = fs::read_to_string(&interface_path)?.parse()?;

    assert_eq!(
        interface["interface"]["kind"].as_str(),
        Some("process-shared-memory")
    );
    assert_eq!(
        interface["interface"]["license"].as_str(),
        Some(BOUNDARY_LICENSE)
    );
    assert_eq!(
        interface["interface"]["independently_implementable"].as_bool(),
        Some(true)
    );
    assert_eq!(
        interface["transport"]["data_plane"].as_str(),
        Some("shared-memory")
    );
    assert_eq!(
        interface["transport"]["steady_state_syscalls_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        interface["transport"]["data_plane_socket_round_trips"].as_bool(),
        Some(false)
    );
    assert_eq!(
        interface["transport"]["scheduler_ceiling_futex_wake"].as_str(),
        Some("unconditional-currently")
    );
    let additional_futex = string_set(&interface["transport"]["additional_futex_wake_categories"])?;
    assert!(additional_futex.contains("service-or-backpressure-producer-release"));
    assert!(additional_futex.contains("frame-delivery"));
    assert_eq!(
        interface["transport"]["wakeup"].as_str(),
        Some("non-private-futex+plugin-eventfd")
    );
    assert_eq!(
        interface["transport"]["plugin_eventfd_quantum_wake_write"].as_str(),
        Some("minimum-one")
    );
    assert_eq!(
        interface["transport"]["plugin_eventfd_qemu_registration"].as_str(),
        Some("required-before-ready")
    );
    let eventfd_additional =
        string_set(&interface["transport"]["plugin_eventfd_additional_writes"])?;
    assert!(eventfd_additional.contains("unchanged-icount-retry"));
    assert!(eventfd_additional.contains("host-io-service"));
    assert_eq!(
        interface["transport"]["future_waiter_armed_wake_optimization"].as_str(),
        Some("documented-not-implemented")
    );

    let forbidden = string_set(&interface["representation"]["forbidden"])?;
    for required in [
        "native-pointer",
        "function-pointer",
        "callback-table",
        "qemu-private-structure",
        "rust-native-enum-layout",
        "compiler-dependent-bitfield",
    ] {
        assert!(
            forbidden.contains(required),
            "interface policy must forbid {required}"
        );
    }

    let header_path = shmem.join("include/crucible_shmem_abi.h");
    let header = fs::read_to_string(&header_path)?;
    assert!(header.starts_with("/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n"));
    assert!(header.contains("Public process ABI: independently implementable"));
    assert!(
        !header.contains("(*"),
        "public C ABI must not contain function pointers"
    );
    for line in header.lines().filter(|line| line.trim_end().ends_with(';')) {
        assert!(
            !line.contains('*'),
            "public C ABI field must not be a pointer: {line}"
        );
    }

    Ok(())
}

#[test]
fn independent_fixture_parser_matches_all_abi_views() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let shmem = crates.join("crucible-shmem");
    let interface: Value =
        fs::read_to_string(shmem.join("interface/crucible-shmem-abi.toml"))?.parse()?;
    let interface_version = interface["interface"]["abi_version"]
        .as_integer()
        .ok_or("interface ABI version must be an integer")?;
    let rust_version: i64 = fs::read_to_string(shmem.join("src/abi_version.in"))?
        .trim()
        .parse()?;
    let header = fs::read_to_string(shmem.join("include/crucible_shmem_abi.h"))?;
    let fixture = parse_fixture(&fs::read_to_string(
        shmem.join("tests/fixtures/shmem_abi_golden.fixture"),
    )?)?;

    assert_eq!(interface_version, rust_version);
    assert_eq!(fixture.abi_version, rust_version as u32);
    assert!(header.contains(&format!(
        "#define CRUCIBLE_SHMEM_ABI_VERSION {rust_version}u"
    )));
    assert!(header.contains("#define CRUCIBLE_SHMEM_REGION_HEADER_ABI_VERSION_OFFSET 8u"));
    assert!(header.contains("#define CRUCIBLE_SHMEM_REGION_HEADER_SIZE 256u"));
    assert!(header.contains("#define CRUCIBLE_SHMEM_NODE_SLOT_SIZE 128u"));
    assert!(header.contains("#define CRUCIBLE_SHMEM_RING_HEADER_SIZE 128u"));
    assert!(header.contains("#define CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE 4632u"));

    let magic = bytes_at(&fixture, 0, 8)?;
    assert_eq!(magic, b"CRUCSHM1");
    let version_bytes = bytes_at(&fixture, 8, 4)?;
    let version = u32::from_le_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);
    assert_eq!(version, fixture.abi_version);
    assert_eq!(fixture.total_len, 9_880);
    Ok(())
}

#[test]
fn boundary_artifacts_and_code_docs_remain_explicit() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let plugin: Value =
        fs::read_to_string(crates.join(PLUGIN_PACKAGE).join("Cargo.toml"))?.parse()?;
    let plugin_artifacts = plugin["lib"]["crate-type"]
        .as_array()
        .ok_or("plugin crate-type must be an array")?;
    assert_eq!(
        plugin_artifacts.as_slice(),
        [Value::String(String::from("cdylib"))]
    );

    for boundary in BOUNDARY_PACKAGES {
        let manifest: Value =
            fs::read_to_string(crates.join(boundary).join("Cargo.toml"))?.parse()?;
        assert!(
            manifest
                .get("lib")
                .and_then(|lib| lib.get("crate-type"))
                .is_none()
        );
    }

    let docs = [
        (
            "crucible-qemu-plugin/src/lib.rs",
            [
                "SPDX-License-Identifier: GPL-2.0-only",
                "versioned socket control protocol",
            ]
            .as_slice(),
        ),
        (
            "crucible-debug-gateway/src/lib.rs",
            [
                "SPDX-License-Identifier: GPL-2.0-only",
                "versioned owned-byte protocol",
                "separate process",
            ]
            .as_slice(),
        ),
        (
            "crucible-shmem/src/lib.rs",
            [
                "SPDX-License-Identifier: MIT OR Apache-2.0",
                "independently implementable process ABI",
                "never contains native pointers",
            ]
            .as_slice(),
        ),
        (
            "crucible-protocol/src/lib.rs",
            [
                "SPDX-License-Identifier: MIT OR Apache-2.0",
                "public host/plugin process protocol",
                "independently implementable",
            ]
            .as_slice(),
        ),
    ];
    for (relative, markers) in docs {
        let source = fs::read_to_string(crates.join(relative))?;
        for marker in markers {
            assert!(
                source.contains(marker),
                "{relative} must document `{marker}`"
            );
        }
    }
    Ok(())
}

fn expected_license(package: &str) -> &'static str {
    match package {
        PLUGIN_PACKAGE | DEBUG_GATEWAY_PACKAGE => PLUGIN_LICENSE,
        "crucible-protocol" | "crucible-shmem" => BOUNDARY_LICENSE,
        _ => APACHE_LICENSE,
    }
}

fn declared_package_license(
    package: &toml::map::Map<String, Value>,
    workspace_license: &str,
) -> Option<String> {
    match package.get("license") {
        Some(Value::String(license)) => Some(license.clone()),
        Some(Value::Table(inherited))
            if inherited.get("workspace").and_then(Value::as_bool) == Some(true) =>
        {
            Some(workspace_license.to_owned())
        }
        _ => None,
    }
}

fn string_set(value: &Value) -> Result<BTreeSet<&str>, Box<dyn Error>> {
    Ok(value
        .as_array()
        .ok_or("expected string array")?
        .iter()
        .map(|item| item.as_str().ok_or("expected string item"))
        .collect::<Result<_, _>>()?)
}

fn workspace_crates_dir() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "crucible-harness manifest must be inside crates/".into())
}

fn visit_rust_sources(
    directory: &Path,
    visitor: &mut impl FnMut(&Path, &str),
) -> Result<(), Box<dyn Error>> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            visit_rust_sources(&path, visitor)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            let source = fs::read_to_string(&path)?;
            visitor(&path, &source);
        }
    }
    Ok(())
}

struct GoldenFixture {
    abi_version: u32,
    total_len: usize,
    chunks: Vec<(usize, Vec<u8>)>,
}

fn parse_fixture(source: &str) -> Result<GoldenFixture, Box<dyn Error>> {
    let mut abi_version = None;
    let mut total_len = None;
    let mut chunks = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("invalid fixture line")?;
        match key {
            "abi_version" => abi_version = Some(value.parse()?),
            "total_len" => total_len = Some(value.parse()?),
            offset => chunks.push((offset.parse()?, decode_hex(value)?)),
        }
    }
    Ok(GoldenFixture {
        abi_version: abi_version.ok_or("missing fixture ABI version")?,
        total_len: total_len.ok_or("missing fixture length")?,
        chunks,
    })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("fixture hex must have even length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

fn bytes_at(fixture: &GoldenFixture, offset: usize, len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; len];
    let mut written = vec![false; len];
    for (chunk_offset, chunk) in &fixture.chunks {
        for (index, byte) in chunk.iter().enumerate() {
            let absolute = chunk_offset + index;
            if (offset..offset + len).contains(&absolute) {
                let destination = absolute - offset;
                bytes[destination] = *byte;
                written[destination] = true;
            }
        }
    }
    if written.iter().any(|present| !present) {
        return Err(format!(
            "fixture has no committed bytes for {offset}..{}",
            offset + len
        )
        .into());
    }
    Ok(bytes)
}

fn display_repo_path(path: &Path) -> String {
    let root = workspace_crates_dir()
        .ok()
        .and_then(|crates| crates.parent().map(Path::to_path_buf));
    root.as_deref()
        .and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path)
        .display()
        .to_string()
}
