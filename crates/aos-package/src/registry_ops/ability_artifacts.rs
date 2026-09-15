//! Canonical realization of package ability artifact selectors.
//!
//! Publication resolves one selected Nix output through this module. The
//! resulting semantic reference and retention record come from the same store
//! graph inspection, so callers cannot compute or rewrite either identity on a
//! separate path.

use crate::ability_package::canonical_nar_hash;
use crate::registry::release::RegistryReleaseEntry;
use crate::registry_ops::store_paths::{
    introspect_closure_nars, introspect_direct_reference_hashes, introspect_store_path,
    nix_command, validate_store_path_release_policy,
};
use crate::types::{AbilityArtifactRetentionMeta, AbilityClosureMemberMeta};
use anyhow::{Context, Result, bail};
use aos_ability_model::{
    ArtifactClosureMemberInput, ArtifactReference, PackageDocument, artifact_closure_identity,
    artifact_content_identity, encode_canonical,
};
use aos_ability_validate::{
    PackageAbilityProjection, PackageOutputSelector, decode_package_projection,
    resolve_package_projection,
};
use aos_contract::Sha256Digest;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// An ability artifact reference and the exact closure retained for it.
pub(in crate::registry_ops) struct ResolvedAbilityArtifact {
    /// Semantic reference embedded in the checked package document.
    pub(in crate::registry_ops) reference: ArtifactReference,
    /// Complete realization metadata retained by the registry.
    pub(in crate::registry_ops) retention: AbilityArtifactRetentionMeta,
}

/// Exact release-entry inventory used to bind symbolic package outputs.
pub(crate) struct AbilitySelectorRegistry {
    outputs: BTreeMap<(String, String, String), Vec<(String, String)>>,
}

impl AbilitySelectorRegistry {
    /// Indexes exact planned outputs by package, platform, and output name.
    pub(crate) fn new(entries: &[RegistryReleaseEntry]) -> Self {
        let mut outputs = BTreeMap::new();
        for entry in entries {
            outputs
                .entry((
                    entry.name.clone(),
                    entry.platform.clone(),
                    entry.output.clone(),
                ))
                .or_insert_with(Vec::new)
                .push((entry.version.clone(), entry.store_path.clone()));
        }
        Self { outputs }
    }

    fn select(&self, owner: (&str, &str, &str), selector: &PackageOutputSelector) -> Result<&str> {
        let package = match selector.package.as_str() {
            "self" => owner.0,
            package => package,
        };
        let output = selector.output.as_str();
        if output == crate::types::ABILITY_MANIFEST_OUTPUT {
            bail!("ability projections cannot select another ability projection output");
        }
        let candidates = self
            .outputs
            .get(&(package.to_string(), owner.2.to_string(), output.to_string()))
            .into_iter()
            .flatten()
            .filter(|(version, _)| package != owner.0 || version == owner.1)
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [(_, store_path)] => Ok(store_path),
            [] => bail!(
                "ability selector ({}, {}) has no exact {} release output",
                selector.package.as_str(),
                output,
                owner.2
            ),
            _ => bail!(
                "ability selector ({}, {}) is ambiguous across release versions",
                selector.package.as_str(),
                output
            ),
        }
    }
}

/// Resolves one selected store output into its canonical ability identities.
///
/// # Errors
///
/// Returns an error when the store output is unavailable, violates release
/// policy, has malformed NAR metadata, or its complete closure cannot be
/// inspected and canonically encoded.
pub(in crate::registry_ops) fn resolve_store_artifact(
    store_path: &str,
) -> Result<ResolvedAbilityArtifact> {
    let artifact = introspect_store_path(store_path)
        .with_context(|| format!("introspecting ability artifact {store_path}"))?;
    validate_store_path_release_policy(&artifact)?;

    let nar_hash = canonical_nar_hash(&artifact.nar_hash)?;
    let nar_digest = Sha256Digest::parse(&nar_hash)
        .with_context(|| format!("parsing canonical NAR identity for {store_path}"))?;

    let mut closure = introspect_closure_nars(store_path)?
        .into_iter()
        .map(|member| {
            let references = introspect_direct_reference_hashes(&member.path)?;
            Ok(AbilityClosureMemberMeta {
                store_path: member.path,
                nar_hash: canonical_nar_hash(&member.nar_hash)?,
                nar_size: member.nar_size,
                references,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    closure.sort();

    if !closure.iter().any(|member| member.store_path == store_path) {
        bail!("ability artifact closure omits its root {store_path}");
    }

    let semantic_closure = closure
        .iter()
        .map(|member| {
            Ok(ArtifactClosureMemberInput {
                key: crate::registry::store_path_hash(&member.store_path).to_string(),
                nar_hash: Sha256Digest::parse(&member.nar_hash)?,
                references: member.references.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let closure_digest = artifact_closure_identity(
        crate::registry::store_path_hash(store_path),
        &semantic_closure,
    )?;
    let content = artifact_content_identity(&nar_digest);

    Ok(ResolvedAbilityArtifact {
        reference: ArtifactReference {
            content,
            store_path: store_path.to_string(),
            nar_hash: nar_digest,
            closure: closure_digest,
        },
        retention: AbilityArtifactRetentionMeta {
            content: content.to_string(),
            store_path: store_path.to_string(),
            nar_hash,
            nar_size: artifact.nar_size,
            closure_digest: closure_digest.to_string(),
            closure,
        },
    })
}

/// Reads and resolves a symbolic companion through one exact release inventory.
///
/// # Errors
///
/// Returns an error when the projection is malformed, its package coordinate
/// differs from the owning release, a selector is missing or ambiguous, or
/// canonical Nix artifact inspection fails.
pub(in crate::registry_ops) fn resolve_release_projection(
    projection_store_path: &str,
    package: &str,
    version: &str,
    platform: &str,
    primary_store_path: &str,
    source_store_path: &str,
    selectors: &AbilitySelectorRegistry,
) -> Result<(PackageDocument, Vec<Vec<u8>>)> {
    let projection_path = Path::new(projection_store_path);
    let projection_bytes = crate::ability_package::catalog::read_bounded_regular_file(
        &projection_path,
        "ability package projection",
    )?;
    let projection = decode_package_projection(&projection_bytes)?;
    validate_projection_coordinate(&projection, package, version)?;
    let interface_documents = projection.interface_documents.clone();

    let payload = resolve_store_artifact(primary_store_path)?.reference;
    let source = resolve_store_artifact(source_store_path)?.reference;
    let document = resolve_package_projection(projection, payload, source, |selector| {
        let path = selectors.select((package, version, platform), selector)?;
        Ok(resolve_store_artifact(path)?.reference)
    })?;
    let interfaces = read_projection_interfaces(&interface_documents, &document)?;
    Ok((document, interfaces))
}

fn validate_projection_coordinate(
    projection: &PackageAbilityProjection,
    package: &str,
    version: &str,
) -> Result<()> {
    if projection.package.name.as_str() != package {
        bail!(
            "ability projection package '{}' does not match release package '{package}'",
            projection.package.name.as_str()
        );
    }
    if projection.package.version != version {
        bail!(
            "ability projection version '{}' does not match release version '{version}'",
            projection.package.version
        );
    }
    Ok(())
}

fn read_projection_interfaces(
    interface_documents: &[aos_ability_validate::InterfaceDocumentProjection],
    _document: &PackageDocument,
) -> Result<Vec<Vec<u8>>> {
    interface_documents
        .iter()
        .map(|interface| {
            encode_canonical(&interface.document).context("encoding projected ability interface")
        })
        .collect()
}

/// Materializes the resolved package document and retained interfaces as one
/// canonical recursive fixed-output store object.
///
/// # Errors
///
/// Returns an error when canonical encoding, filesystem materialization,
/// fixed-output insertion, or resulting Nix-store introspection fails.
pub(in crate::registry_ops) fn materialize_resolved_companion(
    projection_store_path: &str,
    package: &str,
    version: &str,
    document: &PackageDocument,
    interfaces: &[Vec<u8>],
) -> Result<ResolvedAbilityArtifact> {
    let manifest = encode_canonical(document).context("encoding resolved ability package")?;
    let temporary = tempfile::tempdir().context("creating resolved ability companion input")?;
    let companion = temporary
        .path()
        .join(format!("{package}-{version}-abilities"));
    let interface_directory = companion.join("interfaces");
    fs::create_dir_all(&interface_directory)
        .context("creating resolved ability interface directory")?;
    fs::write(companion.join("package.json"), &manifest)
        .context("writing resolved ability package")?;

    let declared_interfaces = document
        .interfaces
        .values()
        .collect::<std::collections::BTreeSet<_>>();
    if interfaces.len() != declared_interfaces.len() {
        bail!("resolved ability interface count differs from package declarations");
    }
    for bytes in interfaces {
        let interface: aos_ability_model::InterfaceDocument =
            aos_contract::canonical::from_slice(bytes, "resolved ability interface")?;
        let identity = interface.interface_key()?;
        fs::write(
            interface_directory.join(format!("{}.json", identity.descriptor.hex())),
            bytes,
        )
        .context("writing resolved ability interface")?;
    }
    set_materialized_permissions(&companion)?;

    let output = nix_command("nix-store")
        .args(["--add-fixed", "--recursive", "sha256"])
        .arg(&companion)
        .output()
        .context("adding resolved ability companion to the Nix store")?;
    if !output.status.success() {
        bail!(
            "nix-store --add-fixed failed for resolved ability companion: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = String::from_utf8(output.stdout)
        .context("resolved ability companion store path is not UTF-8")?
        .trim()
        .to_string();
    if store_path == projection_store_path {
        bail!("resolved ability companion aliases its symbolic projection");
    }
    resolve_store_artifact(&store_path)
}

fn set_materialized_permissions(root: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(root.join("interfaces"), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(root.join("package.json"), fs::Permissions::from_mode(0o644))?;
        for entry in fs::read_dir(root.join("interfaces"))? {
            fs::set_permissions(entry?.path(), fs::Permissions::from_mode(0o644))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AbilitySelectorRegistry, PackageOutputSelector};
    use crate::registry::release::RegistryReleaseEntry;

    fn entry(package: &str, version: &str, output: &str, path: &str) -> RegistryReleaseEntry {
        RegistryReleaseEntry {
            id: format!("{package}-{version}-{output}"),
            name: package.to_string(),
            version: version.to_string(),
            platform: "x86_64-linux".to_string(),
            output: output.to_string(),
            store_path: path.to_string(),
        }
    }

    fn selector(package: &str, output: &str) -> PackageOutputSelector {
        PackageOutputSelector {
            package: aos_ability_model::LocalKey::new(package).unwrap(),
            output: aos_ability_model::LocalKey::new(output).unwrap(),
        }
    }

    #[test]
    fn selector_registry_binds_self_and_unique_foreign_outputs() {
        let registry = AbilitySelectorRegistry::new(&[
            entry("owner", "1", "bin", "/nix/store/owner-bin"),
            entry("provider", "7", "out", "/nix/store/provider-out"),
        ]);

        assert_eq!(
            registry
                .select(("owner", "1", "x86_64-linux"), &selector("owner", "bin"))
                .unwrap(),
            "/nix/store/owner-bin"
        );
        assert_eq!(
            registry
                .select(("owner", "1", "x86_64-linux"), &selector("provider", "out"))
                .unwrap(),
            "/nix/store/provider-out"
        );
    }

    #[test]
    fn selector_registry_rejects_missing_ambiguous_and_projection_outputs() {
        let registry = AbilitySelectorRegistry::new(&[
            entry("provider", "1", "out", "/nix/store/provider-v1"),
            entry("provider", "2", "out", "/nix/store/provider-v2"),
        ]);
        let owner = ("owner", "1", "x86_64-linux");

        assert!(registry.select(owner, &selector("missing", "out")).is_err());
        assert!(
            registry
                .select(owner, &selector("provider", "out"))
                .is_err()
        );
        assert!(
            registry
                .select(
                    owner,
                    &selector("owner", crate::types::ABILITY_MANIFEST_OUTPUT)
                )
                .is_err()
        );
    }

    #[test]
    fn owner_normalized_selector_selects_only_the_release_version() {
        let registry = AbilitySelectorRegistry::new(&[
            entry("owner", "1", "out", "/nix/store/owner-v1"),
            entry("owner", "2", "out", "/nix/store/owner-v2"),
        ]);

        assert_eq!(
            registry
                .select(("owner", "2", "x86_64-linux"), &selector("owner", "out"))
                .unwrap(),
            "/nix/store/owner-v2"
        );
    }
}
