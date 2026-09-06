//! Fixed-output hash refresh for maintainer-edited package definitions.
//!
//! The command supports the migration path for packages that do not yet have
//! a typed update contract. It finds literal hashes owned by known AOS fetch
//! and dependency materializers, replaces one hash at a time with the standard
//! impossible hash, and asks Nix for the resulting fixed-output derivation.
//! Every edit is restored if evaluation or realization fails.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::drv::parse_drv_for_fod;
use aos_core::nix::{NixCli, aos_nix_env};
use aos_maintain::envelope::InventoryEnvelopeV1;
use rnix::StrPart;
use rnix::types::{
    Apply, AttrSet, EntryHolder as _, Ident, Str, TokenWrapper as _, TypedNode as _,
};

use super::materialize::parse_hash_mismatch;

const FAKE_HASH: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const MAX_OWNER_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REFRESHABLE_HASHES: usize = 128;
const REFRESHABLE_BUILDERS: &[&str] = &[
    "fetchBazelDeps",
    "fetchCargoDeps",
    "fetchCargoVendor",
    "fetchGoModules",
    "fetchNpmDeps",
    "fetchurl",
];

/// Records one fixed-output hash inspected by a refresh operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RefreshedHash {
    /// Nix helper owning the literal hash.
    pub builder: String,
    /// Hash declared before the operation.
    pub previous: String,
    /// Hash produced by the fixed-output derivation.
    pub refreshed: String,
}

/// Summarizes one completed hash refresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HashRefreshOutcome {
    /// Repository-relative package owner.
    pub owner: String,
    /// Fixed-output literals evaluated in source order.
    pub hashes: Vec<RefreshedHash>,
    /// Whether refreshed source was retained.
    pub wrote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HashLocation {
    builder: String,
    start: usize,
    end: usize,
    value: String,
}

/// Refreshes every supported fixed-output hash in one update unit's owner.
///
/// # Errors
///
/// Returns an error if the unit or owner is ambiguous, the Nix source is not a
/// regular bounded file, a hash is dynamic, evaluation does not expose exactly
/// one corresponding fixed-output derivation, or realization does not report
/// one unambiguous SRI SHA-256 hash.
pub(super) fn execute(
    envelope: &InventoryEnvelopeV1,
    unit_id: &str,
    target: Option<&str>,
    check: bool,
    verbose: u8,
) -> Result<HashRefreshOutcome> {
    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| unit.unit_id.as_str() == unit_id)
        .ok_or_else(|| anyhow::anyhow!("unknown package update unit '{unit_id}'"))?;
    let owners = envelope
        .inventory
        .units
        .iter()
        .filter(|candidate| candidate.owner == unit.owner)
        .map(|candidate| candidate.unit_id.as_str())
        .collect::<Vec<_>>();
    if owners.len() != 1 {
        bail!(
            "package owner {} is shared by update units {}; add typed artifact contracts before refreshing it",
            unit.owner,
            owners.join(", ")
        );
    }
    let [member] = unit.members.as_slice() else {
        bail!("hash refresh requires an update unit with exactly one package member");
    };

    let root = Path::new(&envelope.repository_root);
    let owner = root.join(&unit.owner);
    let metadata = owner
        .symlink_metadata()
        .with_context(|| format!("inspecting package owner {}", unit.owner))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!(
            "package owner {} is not a regular non-symlink file",
            unit.owner
        );
    }
    if metadata.len() > MAX_OWNER_BYTES {
        bail!(
            "package owner {} exceeds the hash refresh size limit",
            unit.owner
        );
    }

    let original = fs::read_to_string(&owner)
        .with_context(|| format!("reading package owner {}", unit.owner))?;
    let locations = hash_locations(&original)?;
    if locations.is_empty() {
        bail!(
            "package owner {} has no literal refreshable hashes",
            unit.owner
        );
    }
    if locations.len() > MAX_REFRESHABLE_HASHES {
        bail!(
            "package owner {} has too many refreshable hashes",
            unit.owner
        );
    }

    let nix = NixCli::new(verbose);
    let package_attribute = format!("pkgs.{member}");
    let mut candidate = original.clone();
    let mut refreshed = Vec::with_capacity(locations.len());
    let result = (|| {
        for ordinal in 0..locations.len() {
            let current_locations = hash_locations(&candidate)?;
            let location = current_locations.get(ordinal).ok_or_else(|| {
                anyhow::anyhow!("refreshable hash ordering changed during update")
            })?;
            let previous = location.value.clone();
            candidate.replace_range(location.start..location.end, &format!("\"{FAKE_HASH}\""));
            replace_file(&owner, metadata.permissions().mode(), candidate.as_bytes())?;

            let package_drv = instantiate_package(
                &root.join("default.nix"),
                &package_attribute,
                target,
                verbose,
            )?;
            let artifact_drv = fake_hash_derivation(&nix, &package_drv)?;
            let hash = realize_hash_mismatch(&artifact_drv)?;

            let fake_location = hash_locations(&candidate)?
                .get(ordinal)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("temporary hash disappeared during update"))?;
            if fake_location.value != FAKE_HASH {
                bail!("temporary hash no longer identifies the selected materializer");
            }
            candidate.replace_range(
                fake_location.start..fake_location.end,
                &format!("\"{hash}\""),
            );
            replace_file(&owner, metadata.permissions().mode(), candidate.as_bytes())?;

            refreshed.push(RefreshedHash {
                builder: location.builder.clone(),
                previous,
                refreshed: hash,
            });
        }
        Ok(())
    })();

    if let Err(error) = result {
        replace_file(&owner, metadata.permissions().mode(), original.as_bytes())?;
        return Err(error);
    }
    if check {
        replace_file(&owner, metadata.permissions().mode(), original.as_bytes())?;
    }

    Ok(HashRefreshOutcome {
        owner: unit.owner.clone(),
        hashes: refreshed,
        wrote: !check,
    })
}

fn hash_locations(source: &str) -> Result<Vec<HashLocation>> {
    let parsed = rnix::parse(source);
    if !parsed.errors().is_empty() {
        bail!("package owner is not valid Nix syntax");
    }

    let mut locations = Vec::new();
    for apply in parsed.node().descendants().filter_map(Apply::cast) {
        let Some(lambda) = apply.lambda() else {
            continue;
        };
        let builder = lambda.to_string();
        let builder = builder.trim();
        if !REFRESHABLE_BUILDERS.contains(&builder) {
            continue;
        }
        let Some(arguments) = apply.value().and_then(AttrSet::cast) else {
            continue;
        };
        let hashes = arguments
            .entries()
            .filter_map(|entry| {
                let key = entry.key()?;
                let path = key
                    .path()
                    .filter_map(Ident::cast)
                    .map(|ident| ident.as_str().to_string())
                    .collect::<Vec<_>>();
                (path == ["hash"]).then(|| entry.value()).flatten()
            })
            .collect::<Vec<_>>();
        let [value] = hashes.as_slice() else {
            if hashes.is_empty() {
                bail!("{builder} has no literal hash field");
            }
            bail!("{builder} has more than one hash field");
        };
        let range = value.text_range();
        let value = string_literal(value)
            .ok_or_else(|| anyhow::anyhow!("{builder} hash is not a literal string"))?;
        if !valid_sha256(&value) {
            bail!("{builder} hash is not an SRI or Nix base32 SHA-256 value");
        }
        locations.push(HashLocation {
            builder: builder.to_string(),
            start: usize::from(range.start()),
            end: usize::from(range.end()),
            value,
        });
    }
    locations.sort_by_key(|location| location.start);
    if locations.windows(2).any(|pair| pair[0].end > pair[1].start) {
        bail!("refreshable hash ranges overlap");
    }
    Ok(locations)
}

fn string_literal(node: &rnix::SyntaxNode) -> Option<String> {
    let string = Str::cast(node.clone())?;
    match string.parts().as_slice() {
        [StrPart::Literal(value)] => Some(value.to_string()),
        _ => None,
    }
}

fn valid_sha256(value: &str) -> bool {
    if let Some(encoded) = value.strip_prefix("sha256-") {
        return encoded.len() == 44
            && encoded.ends_with('=')
            && encoded[..43]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'));
    }

    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    value.len() == 52 && value.bytes().all(|byte| NIX_BASE32.contains(&byte))
}

fn fake_hash_derivation(nix: &NixCli, package_drv: &Path) -> Result<PathBuf> {
    let package_drv = package_drv
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("package derivation path is not UTF-8"))?;
    let mut matches = BTreeSet::new();
    for path in nix.closure(package_drv)? {
        if !path.ends_with(".drv") {
            continue;
        }
        if parse_drv_for_fod(&path)?.is_some_and(|fod| fod.output_hash == FAKE_HASH) {
            matches.insert(path);
        }
    }
    let matches = matches.into_iter().collect::<Vec<_>>();
    let [derivation] = matches.as_slice() else {
        bail!("package evaluation did not expose exactly one fake-hash fixed-output derivation");
    };
    Ok(PathBuf::from(derivation))
}

fn instantiate_package(
    default_nix: &Path,
    attribute: &str,
    target: Option<&str>,
    verbose: u8,
) -> Result<PathBuf> {
    let mut command = Command::new("nix-instantiate");
    command
        .envs(aos_nix_env())
        .arg(default_nix)
        .arg("-A")
        .arg(attribute);
    if let Some(target) = target {
        command.args(["--argstr", "crossSystem", target]);
    }
    if verbose > 0 {
        command.arg("--show-trace");
    }
    let output = command
        .stderr(Stdio::piped())
        .output()
        .context("running nix-instantiate for hash refresh")?;
    if !output.status.success() {
        bail!(
            "Nix could not instantiate {attribute}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let derivation = String::from_utf8(output.stdout)
        .context("nix-instantiate emitted a non-UTF-8 derivation path")?;
    let derivation = derivation.trim();
    if !derivation.starts_with("/nix/store/") || !derivation.ends_with(".drv") {
        bail!("nix-instantiate emitted an invalid derivation path");
    }
    Ok(PathBuf::from(derivation))
}

fn realize_hash_mismatch(derivation: &Path) -> Result<String> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .arg("--realise")
        .arg(derivation)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("realizing fixed-output derivation {}", derivation.display()))?;
    if output.status.success() {
        bail!("fixed-output derivation unexpectedly accepted the impossible hash");
    }
    parse_hash_mismatch(&output.stderr)
}

fn replace_file(path: &Path, mode: u32, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("package owner has no parent directory"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating replacement for {}", path.display()))?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing package owner {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_supported_hashes_in_source_order() -> Result<()> {
        let source = r#"
let
  src = fetchurl {
    urls = ["https://example.test/source.tar.gz"];
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
  };
in mkGoPackage { inherit src goModules; }
"#;

        let locations = hash_locations(source)?;

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].builder, "fetchurl");
        assert_eq!(locations[1].builder, "fetchGoModules");
        assert_eq!(
            &source[locations[1].start..locations[1].end],
            format!("\"{}\"", locations[1].value)
        );
        Ok(())
    }

    #[test]
    fn rejects_dynamic_hashes() {
        let source = r#"fetchCargoDeps { inherit src; hash = upstream.hash; }"#;
        assert!(hash_locations(source).is_err());
    }

    #[test]
    fn accepts_legacy_nix_base32_hashes() -> Result<()> {
        let source = r#"fetchurl {
  url = "https://example.test/source.tar.gz";
  hash = "12hv193nj10hyzrqh39fpic1ibqjny9kqclzvrjsdxljmkg8wcnd";
}"#;

        let locations = hash_locations(source)?;

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].builder, "fetchurl");
        Ok(())
    }
}
