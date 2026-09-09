//! Authenticated registry catalogs for composition and transition planning.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aos_ability_model::{InterfaceDocument, PackageDocument, RequiredFeature};
use aos_ability_plan::RecursiveComposer;
use aos_ability_validate::ValidationContext;

use super::VerifiedAbilityPackageSet;

/// Supplies a composer from one complete authenticated registry package set.
///
/// The adapter owns the validated public interface catalog and exact package
/// documents together so callers cannot compose against an unrelated context.
pub struct VerifiedAbilityPlanningCatalog {
    context: ValidationContext,
    packages: Vec<PackageDocument>,
}

impl VerifiedAbilityPlanningCatalog {
    /// Returns a composer bound to the authenticated interface catalog.
    #[must_use]
    pub fn composer(&self) -> RecursiveComposer<'_> {
        RecursiveComposer::new(&self.context)
    }

    /// Returns the exact package documents in registry coordinate order.
    #[must_use]
    pub fn packages(&self) -> &[PackageDocument] {
        &self.packages
    }

    /// Returns the validated interface context for transition planning.
    #[must_use]
    pub const fn validation_context(&self) -> &ValidationContext {
        &self.context
    }
}

impl VerifiedAbilityPackageSet {
    /// Loads the exact public interfaces retained by these verified companions.
    ///
    /// Interface documents are addressed by the descriptors already committed
    /// in each package export. Equal duplicates are coalesced, while conflicting
    /// documents or missing descriptor files fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error when an interface file is missing, non-regular,
    /// non-canonical, unsupported, exceeds the version-1 bound, disagrees with
    /// its export key, or conflicts with another authenticated companion.
    pub fn planning_catalog(&self) -> Result<VerifiedAbilityPlanningCatalog> {
        let supported_features = BTreeSet::from([RequiredFeature::new("abilities-v1")
            .context("constructing the built-in ability feature")?]);
        let mut interfaces = BTreeMap::new();
        for sealed in &self.packages {
            let companion = Path::new(sealed.retention.companion_store_path());
            for export in &sealed.package.exports {
                let path = companion
                    .join("interfaces")
                    .join(format!("{}.json", export.interface.descriptor.hex()));
                let bytes = read_bounded_regular_file(&path, "ability interface document")?;
                let document = aos_ability_model::decode_canonical::<InterfaceDocument>(
                    &bytes,
                    aos_ability_model::ABILITY_LIMITS_V1,
                    &supported_features,
                )
                .with_context(|| format!("decoding ability interface {}", path.display()))?;
                let key = document
                    .interface_key()
                    .context("computing retained ability interface descriptor")?;
                if key != export.interface {
                    bail!(
                        "ability interface document {} does not match package export",
                        path.display()
                    );
                }
                if let Some(existing) = interfaces.insert(key.clone(), document.clone())
                    && existing != document
                {
                    bail!("conflicting authenticated ability interface {key:?}");
                }
            }
        }

        let context = ValidationContext::new(supported_features, interfaces.into_values())
            .context("validating authenticated registry ability interfaces")?;
        let packages = self
            .packages
            .iter()
            .map(|sealed| sealed.package.clone())
            .collect();
        Ok(VerifiedAbilityPlanningCatalog { context, packages })
    }
}

fn read_bounded_regular_file(path: &Path, owner: &str) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {owner} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading {owner} metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{owner} is not a regular file: {}", path.display());
    }
    let limit = aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes;
    if metadata.len() == 0 || metadata.len() > limit {
        bail!("{owner} size {} is outside 1..={limit}", metadata.len());
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {owner} {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        bail!("{owner} changed while reading: {}", path.display());
    }
    Ok(bytes)
}
