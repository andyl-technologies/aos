//! Source ownership discovery for structural integration tests.
//!
//! Bazel catalogs establish package ownership. Unmigrated test harnesses retain
//! Cargo discovery until their declared runtime inputs include the catalog.

// crucible-lint: allow rust-allow -- Each integration target imports the workspace helpers it needs.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) struct PackageEntry {
    name: String,
    directory: PathBuf,
}

impl PackageEntry {
    pub(crate) fn path(&self) -> PathBuf {
        self.directory.clone()
    }

    pub(crate) fn file_name(&self) -> OsString {
        OsString::from(&self.name)
    }
}

pub(crate) fn crates_directory() -> PathBuf {
    if let Some(catalog) = std::env::var_os("AOS_SOURCE_CATALOG") {
        let catalog = Path::new(&catalog);
        assert!(
            catalog.is_file(),
            "declared workspace source catalog is absent"
        );
        assert_eq!(
            catalog.file_name(),
            Some(std::ffi::OsStr::new("source_catalog.json"))
        );
        return catalog
            .parent()
            .unwrap_or_else(|| panic!("source catalog has no workspace directory"))
            .to_path_buf();
    }

    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(directory) = manifest_directory
        .ancestors()
        .find(|directory| directory.join("source_catalog.json").is_file())
    {
        return directory.to_path_buf();
    }

    // Bazel test runfiles preserve workspace-relative paths, while the
    // compile-time manifest directory may name a different action sandbox.
    if let Ok(current) = std::env::current_dir()
        && let Some(directory) = current
            .ancestors()
            .map(|directory| directory.join("crates"))
            .find(|directory| directory.join("source_catalog.json").is_file())
    {
        return directory;
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|directory| {
            fs::read_to_string(directory.join("Cargo.toml"))
                .is_ok_and(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
        })
        .unwrap_or_else(|| panic!("test package has no enclosing Cargo workspace"))
        .to_path_buf()
}

pub(crate) fn repository_root() -> PathBuf {
    crates_directory()
        .parent()
        .unwrap_or_else(|| panic!("Cargo workspace has no repository parent"))
        .to_path_buf()
}

pub(crate) fn package_entries(crates: &Path) -> io::Result<Vec<io::Result<PackageEntry>>> {
    let catalog = crates.join("source_catalog.json");
    if catalog.exists() {
        return catalog_entries(crates, &fs::read_to_string(catalog)?);
    }

    // This fallback serves Cargo-only harnesses during the staged migration.
    // A present but invalid catalog always fails rather than changing owners.
    let manifest: toml::Value = fs::read_to_string(crates.join("Cargo.toml"))?
        .parse()
        .map_err(io::Error::other)?;
    let members = manifest["workspace"]["members"]
        .as_array()
        .ok_or_else(|| io::Error::other("workspace.members must be an array"))?;
    let mut entries = Vec::new();

    for member in members {
        let member = member
            .as_str()
            .ok_or_else(|| io::Error::other("workspace member must be a string"))?;
        let directory = crates.join(member);
        let package: toml::Value = fs::read_to_string(directory.join("Cargo.toml"))?
            .parse()
            .map_err(io::Error::other)?;
        let name = package["package"]["name"]
            .as_str()
            .ok_or_else(|| io::Error::other("workspace package must declare package.name"))?;
        entries.push(Ok(PackageEntry {
            name: name.to_owned(),
            directory,
        }));
    }

    Ok(entries)
}

#[derive(serde::Deserialize)]
struct SourceCatalog {
    schema_version: u32,
    packages: Vec<SourcePackage>,
}

#[derive(serde::Deserialize)]
struct SourcePackage {
    name: String,
    directory: PathBuf,
}

fn catalog_entries(crates: &Path, contents: &str) -> io::Result<Vec<io::Result<PackageEntry>>> {
    let catalog: SourceCatalog = serde_json::from_str(contents).map_err(io::Error::other)?;
    if catalog.schema_version != 1 || catalog.packages.is_empty() {
        return Err(io::Error::other("invalid workspace source catalog"));
    }

    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = Vec::new();
    for package in catalog.packages {
        let relative = package
            .directory
            .strip_prefix("crates")
            .map_err(io::Error::other)?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || package.name.is_empty()
            || !names.insert(package.name.clone())
            || !directories.insert(relative.to_path_buf())
        {
            return Err(io::Error::other(
                "invalid or duplicate source package ownership",
            ));
        }
        entries.push(Ok(PackageEntry {
            name: package.name,
            directory: crates.join(relative),
        }));
    }

    Ok(entries)
}

pub(crate) fn package_directory(crates: &Path, package: &str) -> io::Result<PathBuf> {
    for entry in package_entries(crates)? {
        let entry = entry?;
        if entry.name == package {
            return Ok(entry.directory);
        }
    }

    Err(io::Error::other(format!(
        "workspace package {package} is absent"
    )))
}

// Missing packages keep their expected path so source-contract diagnostics name
// the absent artifact; tests that require a manifest use package_directory.
pub(crate) fn package_path(crates: &Path, package: &str) -> PathBuf {
    package_directory(crates, package).unwrap_or_else(|_| crates.join(package))
}
