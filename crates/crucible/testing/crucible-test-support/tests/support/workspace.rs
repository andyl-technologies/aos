//! Manifest-driven workspace discovery for structural integration tests.
//!
//! Cargo package names establish ownership; member paths only organize readers.

// crucible-lint: allow rust-allow -- Each integration target imports the workspace helpers it needs.
#![allow(dead_code)]

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
