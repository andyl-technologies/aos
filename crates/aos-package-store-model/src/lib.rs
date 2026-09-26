//! Pure contracts for an authenticated package-store read view.
//!
//! The selected platform publishes a [`StoreViewLocator`] through the canonical
//! `aos.package-store.read-view` ability. Consumers retain the locator in their
//! checked inputs and map canonical package identities into that read-only view.
//! This crate performs no package selection, provider dispatch, or filesystem
//! mutation.

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// Names the version-1 selected package-store read-view locator.
pub const STORE_VIEW_LOCATOR_SCHEMA: &str = "aos.package-store.read-view-locator/v1";

/// Names the version-1 package-store read-view observation.
pub const STORE_VIEW_OBSERVATION_SCHEMA: &str = "aos.package-store.read-view-observation/v1";

/// Selects the one supported package-store read-view scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreViewScope {
    /// Selects the immutable package store embedded in the booted image.
    BootImage,
}

/// Requests one authenticated package-store read view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreViewRequest {
    /// Selects the boot-image package-store view.
    pub scope: StoreViewScope,
}

/// Reports the availability of one selected package-store read view.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreViewState {
    /// The selected read view is available for checked consumers.
    Available,
    /// The selected read view is known to be unavailable.
    Unavailable,
    /// The provider cannot yet establish availability.
    Unknown,
}

/// Locates canonical package identities and their immutable readable view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreViewLocator {
    /// Carries [`STORE_VIEW_LOCATOR_SCHEMA`].
    pub schema: String,
    /// Root under which package paths retain their canonical identities.
    pub identity_root: PathBuf,
    /// Root through which the same package objects are read without mutation.
    pub read_root: PathBuf,
    /// Canonical identity path of the selected host static contract document.
    pub static_contract: PathBuf,
}

impl StoreViewLocator {
    /// Decodes and validates one canonical serialized locator.
    ///
    /// # Errors
    ///
    /// Returns an error when `encoded` is not canonical AOS JSON or does not
    /// satisfy the closed locator schema and path invariants.
    pub fn from_canonical_json(encoded: &str) -> Result<Self> {
        let value = aos_contract::canonical::require_canonical(
            encoded.as_bytes(),
            "package-store read-view locator",
        )?;
        let locator: Self =
            serde_json::from_value(value).context("decoding package-store read-view locator")?;
        locator.validate()?;
        Ok(locator)
    }

    /// Constructs and validates one selected store-view locator.
    ///
    /// # Errors
    ///
    /// Returns an error when a path is relative or non-normalized, or the
    /// static contract is not the root document of one package object beneath
    /// the identity root.
    pub fn new(
        identity_root: PathBuf,
        read_root: PathBuf,
        static_contract: PathBuf,
    ) -> Result<Self> {
        let locator = Self {
            schema: STORE_VIEW_LOCATOR_SCHEMA.into(),
            identity_root,
            read_root,
            static_contract,
        };
        locator.validate()?;
        Ok(locator)
    }

    /// Validates the locator and the relation between its paths.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, unsafe paths, or a
    /// static-contract path outside one direct package object.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == STORE_VIEW_LOCATOR_SCHEMA,
            "unsupported package-store read-view locator schema"
        );
        validate_absolute_normal_path(&self.identity_root, "store identity root")?;
        validate_absolute_normal_path(&self.read_root, "store read root")?;
        validate_absolute_normal_path(&self.static_contract, "static contract")?;
        let relative = self
            .static_contract
            .strip_prefix(&self.identity_root)
            .context("static contract is outside the selected store identity root")?;
        let components = relative.components().collect::<Vec<_>>();
        ensure!(
            matches!(components.as_slice(), [Component::Normal(_), Component::Normal(file)] if *file == "contract.json"),
            "static contract must be contract.json at the root of one selected package object"
        );
        Ok(())
    }

    /// Maps one canonical identity path into the selected immutable read view.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is invalid or `identity` is outside
    /// the identity root, names the root itself, or contains unsafe components.
    pub fn read_path(&self, identity: &Path) -> Result<PathBuf> {
        self.validate()?;
        validate_absolute_normal_path(identity, "package identity path")?;
        let relative = identity
            .strip_prefix(&self.identity_root)
            .context("package identity path is outside the selected store root")?;
        ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
                && relative.components().next().is_some(),
            "package identity path must name an object beneath the selected store root"
        );
        Ok(self.read_root.join(relative))
    }

    /// Returns the selected readable static-contract document path.
    ///
    /// # Errors
    ///
    /// Returns an error when this locator is invalid.
    pub fn static_contract_read_path(&self) -> Result<PathBuf> {
        self.read_path(&self.static_contract)
    }
}

/// Carries one checked package-store read-view observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreViewObservation {
    /// Carries [`STORE_VIEW_OBSERVATION_SCHEMA`].
    pub schema: String,
    /// Repeats the exact checked request.
    pub expected: StoreViewRequest,
    /// Locates the selected immutable read view.
    pub locator: StoreViewLocator,
    /// Reports current availability.
    pub state: StoreViewState,
}

impl StoreViewObservation {
    /// Validates the observation and its nested locator.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported observation schema or invalid
    /// locator.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == STORE_VIEW_OBSERVATION_SCHEMA,
            "unsupported package-store read-view observation schema"
        );
        self.locator.validate()
    }
}

fn validate_absolute_normal_path(path: &Path, label: &str) -> Result<()> {
    let mut components = path.components();
    ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "{label} must be absolute"
    );
    ensure!(
        components.clone().next().is_some()
            && components.all(|component| matches!(component, Component::Normal(_))),
        "{label} must be a normalized non-root path"
    );
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        bail!("{label} contains a NUL byte");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator() -> StoreViewLocator {
        StoreViewLocator::new(
            "/identity/store".into(),
            "/read/store".into(),
            "/identity/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json".into(),
        )
        .expect("valid locator")
    }

    #[test]
    fn maps_identity_paths_without_backend_knowledge() {
        let locator = locator();
        assert_eq!(
            locator
                .read_path(Path::new(
                    "/identity/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-package/share/data"
                ))
                .expect("mapped path"),
            Path::new("/read/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-package/share/data")
        );
        assert_eq!(
            locator.static_contract_read_path().expect("contract path"),
            Path::new("/read/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json")
        );
    }

    #[test]
    fn supports_identical_identity_and_read_roots() {
        let locator = StoreViewLocator::new(
            "/store".into(),
            "/store".into(),
            "/store/hash-contract/contract.json".into(),
        )
        .expect("native immutable store view");

        assert_eq!(
            locator
                .read_path(Path::new("/store/hash-package/share/data"))
                .expect("mapped native path"),
            Path::new("/store/hash-package/share/data")
        );
    }

    #[test]
    fn rejects_unrelated_identity_paths() {
        assert!(
            locator()
                .read_path(Path::new("/another/store/object"))
                .is_err()
        );
    }

    #[test]
    fn rejects_static_contracts_outside_one_package_root() {
        assert!(
            StoreViewLocator::new(
                "/identity/store".into(),
                "/read/store".into(),
                "/identity/store/hash-contract/share/contract.json".into(),
            )
            .is_err()
        );
    }

    #[test]
    fn decodes_only_canonical_closed_locators() {
        let encoded = serde_json::json!({
            "identity_root": "/identity/store",
            "read_root": "/read/store",
            "schema": STORE_VIEW_LOCATOR_SCHEMA,
            "static_contract": "/identity/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json",
        });
        let encoded = String::from_utf8(
            aos_contract::canonical::canonical_json(&encoded).expect("canonical locator"),
        )
        .expect("UTF-8 locator");

        assert_eq!(
            StoreViewLocator::from_canonical_json(&encoded).expect("decoded locator"),
            locator()
        );
        assert!(StoreViewLocator::from_canonical_json(&format!("{encoded}\n")).is_err());
    }
}
