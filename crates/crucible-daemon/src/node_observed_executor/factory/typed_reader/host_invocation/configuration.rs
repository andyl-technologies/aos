//! Measures explicitly selected public source roles before private issuance.
//!
//! ```json
//! {"descriptor":"/nix/store/.../implementation.json", "package":{"hash":{},"length":"5030","media_type":"application/json"}, "roles":{"provider":{"path":"/nix/store/.../provider","content":{}}}}
//! ```
//!
//! The abbreviated example shows shape only. Each complete content reference and
//! all twelve named roles are mandatory; the document contains no credentials.

use std::{collections::BTreeMap, path::PathBuf};

use crucible_node_contract::{ContentRef, Validate};
use serde::{Deserialize, Serialize};

use super::super::super::{NodeObservedError, refused};
use super::super::InstalledTypedReaderPackage;

const ROLES: [&str; 12] = [
    "build_closure",
    "contract",
    "event",
    "handler",
    "input",
    "namespace_publication",
    "native",
    "provider",
    "reader_definition",
    "recipe",
    "source",
    "stop",
];

/// Pins one independently selected public original artifact and its full identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTypedReaderPublicRole {
    /// Names the exact immutable original public file.
    pub path: PathBuf,
    /// Pins its hash domain, algorithm, complete extent and media type.
    pub content: ContentRef,
}

/// Declares the public source tuple selected by the independent fixture installer.
///
/// Parsing this data supplies no behavioral, source or execution authority. The
/// explicit installation call subsequently measures every pinned file, joins
/// the actual loader's executable/definition identities, and installs only the
/// finite collecting fixture. Ordinary accepted-class callbacks stay refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTypedReaderHostSource {
    /// Names the complete original implementation descriptor.
    pub descriptor: PathBuf,
    /// Pins that descriptor's complete content identity.
    pub package: ContentRef,
    /// Pins the closed twelve-role source prerequisite roster.
    pub roles: BTreeMap<String, SelectedTypedReaderPublicRole>,
}

impl SelectedTypedReaderHostSource {
    pub(super) fn measure(&self) -> Result<(), NodeObservedError> {
        super::super::programme::count(self, 64 * 1024).map_err(super::native)?;
        if self.roles.len() != ROLES.len() || self.roles.keys().map(String::as_str).ne(ROLES) {
            return Err(refused(
                "typed invocation public source role roster differs",
            ));
        }
        self.package.validate()?;
        super::super::package::Artifact {
            path: self.descriptor.clone(),
            content: self.package.clone(),
        }
        .measure()?;
        for original in self.roles.values() {
            super::super::package::Artifact {
                path: original.path.clone(),
                content: original.content.clone(),
            }
            .measure()?;
        }
        Ok(())
    }

    pub(super) fn role(
        &self,
        role: &str,
    ) -> Result<&SelectedTypedReaderPublicRole, NodeObservedError> {
        self.roles
            .get(role)
            .ok_or_else(|| refused("typed invocation source role absent"))
    }

    pub(super) fn authenticate_package(
        &self,
        package: &InstalledTypedReaderPackage,
    ) -> Result<(), NodeObservedError> {
        if package.identity() != &self.package {
            return Err(refused("typed invocation measured package differs"));
        }
        for (selected, declared) in [("provider", "provider"), ("native", "device")] {
            let original = self.role(selected)?;
            if package.artifact_content(declared)? != &original.content
                || package.executable(declared)? != original.path
            {
                return Err(refused("typed invocation original executable pin differs"));
            }
        }

        // Independent file measurement must also select the same original role
        // in the loaded package. A valid unrelated file cannot substitute a
        // source, recipe or contract merely because its own hash is correct.
        for name in ROLES
            .into_iter()
            .filter(|name| !matches!(*name, "provider" | "native"))
        {
            let selected = self.role(name)?;
            let (path, reference) = package.source_artifact(name)?;
            if path != selected.path || reference != &selected.content {
                return Err(refused("typed invocation original source role pin differs"));
            }
        }

        for name in ["event", "handler", "input", "namespace_publication", "stop"] {
            if !package
                .definition_objects()
                .contains_key(&self.role(name)?.content)
            {
                return Err(refused("typed invocation original definition pin differs"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Exercises role selection against the original measured installed package.

    use super::*;

    #[test]
    #[ignore = "requires the explicitly selected immutable 4ac package; data only"]
    fn actual_package_rejects_valid_assets_in_wrong_source_roles() -> Result<(), NodeObservedError>
    {
        let descriptor = PathBuf::from(
            "/nix/store/4ac8a9w60vm7w5lxsazp141znl44rkn2-crucible-reference-lineage-reader-typed-implementation-1/share/crucible/reference-lineage-reader-typed/implementation.json",
        );
        let reference: ContentRef = serde_json::from_str(
            r#"{"hash":{"algorithm":"blake3-256","digest":"7aa842518c587aed08662e0030c988d8c383d44f9d0fdfe22d11215065fb99ae","domain":"cnp.blob.v1"},"length":"5030","media_type":"application/json"}"#,
        ).map_err(|_| refused("selected fixture descriptor identity invalid"))?;
        let package = InstalledTypedReaderPackage::load(&descriptor, &reference)?;
        let mut roles = BTreeMap::new();
        for name in ROLES {
            let (path, content) = match name {
                "provider" => (
                    package.executable("provider")?,
                    package.artifact_content("provider")?,
                ),
                "native" => (
                    package.executable("device")?,
                    package.artifact_content("device")?,
                ),
                source => package.source_artifact(source)?,
            };
            roles.insert(
                name.to_owned(),
                SelectedTypedReaderPublicRole {
                    path: path.to_path_buf(),
                    content: content.clone(),
                },
            );
        }
        let mut selected = SelectedTypedReaderHostSource {
            descriptor,
            package: reference,
            roles,
        };
        selected.authenticate_package(&package)?;

        // This alternate executable is a genuine already-measured asset. Each
        // substitution has a valid path and full hash, yet belongs to the wrong
        // source role. The old caller incorrectly accepted the five unjoined
        // source roles; this control is expected to fail on that predecessor.
        for name in ROLES
            .into_iter()
            .filter(|name| !matches!(*name, "provider" | "native"))
        {
            let alternate = SelectedTypedReaderPublicRole {
                path: package.executable("provider")?.to_path_buf(),
                content: package.artifact_content("provider")?.clone(),
            };
            let original = selected
                .roles
                .insert(name.to_owned(), alternate)
                .ok_or_else(|| refused("selected fixture source role absent"))?;

            assert!(selected.authenticate_package(&package).is_err(), "{name}");

            selected.roles.insert(name.to_owned(), original);
        }
        selected.authenticate_package(&package)?;
        Ok(())
    }
}
