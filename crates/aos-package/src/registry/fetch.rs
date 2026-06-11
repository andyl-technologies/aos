//! Consumer-side object fetch resolution for the git-native registry.
//!
//! Given a target release, this module decides how to bring the release's
//! git objects into the local registry repo with the least transfer. Three
//! mechanisms are tried in order:
//!
//! 1. **AOS thin deltas** -- producer-published `delta-<base>.pack[.zst]`
//!    files under `releases/<release>/objects/pack/`, usable when the
//!    client retains the base release (see [`retained_set`]).
//! 2. **Full-pack anchors** -- a stock-git self-contained pack at the
//!    release's `X.Y.0` anchor, optionally followed by an anchor-to-target
//!    delta.
//! 3. **`git fetch` fallback** -- a plain tag fetch over the dumb-HTTP
//!    loose-object floor, which always works but transfers the most.
//!
//! [`plan_from_artifacts`] is the pure planning core; [`resolve_objects`]
//! performs the same decisions against a live origin and actually downloads
//! and indexes the packs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::download::join_cache_url;
use crate::gitcmd;
use crate::registry::pack;
use aos_core::output::Printer;

/// The ordered fetch steps chosen to materialize a target release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchPlan {
    /// The release the plan materializes.
    pub target: semver::Version,
    /// Steps to execute in order; later steps may depend on earlier ones
    /// (e.g. a delta applied on top of a full-pack anchor).
    pub steps: Vec<FetchStep>,
}

/// One step of a [`FetchPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchStep {
    /// Apply an AOS thin delta pack from `base` to `target`.
    Delta {
        /// Release the delta produces.
        target: semver::Version,
        /// Retained release the delta builds on.
        base: semver::Version,
        /// Whether the pack was fetched in zstd-compressed form.
        compressed: bool,
    },
    /// Download and index a self-contained full pack for `version`.
    Full {
        /// Release the pack covers.
        version: semver::Version,
        /// Pack filename (`pack-<hash>.pack`) under the release's pack dir.
        pack: String,
    },
    /// Fall back to `git fetch` of the release tag over the loose-object
    /// dumb-HTTP floor.
    GitFetchFallback {
        /// The `refs/tags/X.Y.Z:refs/tags/X.Y.Z` refspec that was fetched.
        refspec: String,
    },
}

/// Inventory of producer-published artifacts used by [`plan_from_artifacts`].
#[derive(Debug, Default, Clone)]
pub struct AvailableArtifacts {
    /// Published `(target, base)` thin-delta pairs.
    pub deltas: BTreeSet<(semver::Version, semver::Version)>,
    /// Published full packs, mapping release version to pack filename.
    pub full_packs: BTreeMap<semver::Version, String>,
}

/// Return the delta bases a producer publishes at `target`, nearest first.
///
/// Patch releases fan out to the previous three patches plus the `X.Y.0`
/// anchor; minor releases to the previous minor and `X.0.0`; major releases
/// to the previous major. This mirrors the producer scheme in
/// [`pack::scheme_deltas`].
pub fn deltas_at(target: &semver::Version) -> Vec<semver::Version> {
    let mut bases = Vec::new();
    if target.patch > 0 {
        for offset in 1..=3 {
            if target.patch >= offset {
                push_unique(
                    &mut bases,
                    semver::Version::new(target.major, target.minor, target.patch - offset),
                );
            }
        }
        push_unique(
            &mut bases,
            semver::Version::new(target.major, target.minor, 0),
        );
    } else if target.minor > 0 {
        push_unique(
            &mut bases,
            semver::Version::new(target.major, target.minor - 1, 0),
        );
        push_unique(&mut bases, semver::Version::new(target.major, 0, 0));
    } else if target.major > 0 {
        push_unique(&mut bases, semver::Version::new(target.major - 1, 0, 0));
    }
    bases
}

/// Return the minimum release set a client must retain for `target`.
///
/// Retaining `X.0.0`, `X.Y.0`, and the target itself guarantees a usable
/// delta base exists for the next release a channel can advance to.
pub fn retained_set(target: &semver::Version) -> Vec<semver::Version> {
    let mut retained = Vec::new();
    push_unique(&mut retained, semver::Version::new(target.major, 0, 0));
    push_unique(
        &mut retained,
        semver::Version::new(target.major, target.minor, 0),
    );
    push_unique(&mut retained, target.clone());
    retained
}

/// Parse the persisted `retained` release strings into semver versions.
///
/// # Errors
///
/// Returns an error if any entry is not valid semver.
pub fn parse_retained(retained: &[String]) -> Result<Vec<semver::Version>> {
    retained
        .iter()
        .map(|release| {
            semver::Version::parse(release)
                .with_context(|| format!("parsing retained release {release}"))
        })
        .collect()
}

/// Render a release version as its static origin path segment.
///
/// `1.2.3-rc.1+build.5` maps to `1/2/3-rc.1+build.5`; pre-release and build
/// metadata stay on the patch segment.
pub fn release_path(version: &semver::Version) -> String {
    let mut patch = version.patch.to_string();
    if !version.pre.is_empty() {
        patch.push('-');
        patch.push_str(version.pre.as_str());
    }
    if !version.build.is_empty() {
        patch.push('+');
        patch.push_str(version.build.as_str());
    }
    format!("{}/{}/{}", version.major, version.minor, patch)
}

/// Pure planner used by tests and by operators inspecting a registry layout.
///
/// Selects the cheapest plan from `artifacts` without touching the network:
/// a retained-base delta if one exists, otherwise the `X.Y.0` full-pack
/// anchor (plus an anchor-to-target delta when published), otherwise the
/// `git fetch` fallback.
pub fn plan_from_artifacts(
    target: &semver::Version,
    retained: &[semver::Version],
    artifacts: &AvailableArtifacts,
) -> FetchPlan {
    for base in deltas_at(target) {
        if retained.contains(&base) && artifacts.deltas.contains(&(target.clone(), base.clone())) {
            return FetchPlan {
                target: target.clone(),
                steps: vec![FetchStep::Delta {
                    target: target.clone(),
                    base,
                    compressed: false,
                }],
            };
        }
    }

    let anchor = anchor_for(target);
    if let Some(pack) = artifacts.full_packs.get(&anchor) {
        let mut steps = vec![FetchStep::Full {
            version: anchor.clone(),
            pack: pack.clone(),
        }];
        if anchor != *target && artifacts.deltas.contains(&(target.clone(), anchor.clone())) {
            steps.push(FetchStep::Delta {
                target: target.clone(),
                base: anchor,
                compressed: false,
            });
        }
        return FetchPlan {
            target: target.clone(),
            steps,
        };
    }

    FetchPlan {
        target: target.clone(),
        steps: vec![FetchStep::GitFetchFallback {
            refspec: release_refspec(target),
        }],
    }
}

/// Resolve and fetch objects for a target release.
///
/// The resolver first tries AOS-only thin deltas, then a stock-git full-pack
/// anchor, and finally delegates to `git fetch` for the dumb-HTTP loose-object
/// correctness floor. Unusable artifacts (corrupt download, failed index)
/// are reported as warnings and the next mechanism is tried; fetched packs
/// are written and indexed under the repo's `objects/pack/` directory.
///
/// # Errors
///
/// Returns an error when every mechanism fails, the final `git fetch`
/// fallback included, or when a fetched pack cannot be written to disk.
pub async fn resolve_objects(
    repo_dir: &Path,
    origin: &str,
    target: &semver::Version,
    retained: &[semver::Version],
    printer: &Printer,
) -> Result<FetchPlan> {
    for base in deltas_at(target) {
        if !retained.contains(&base) {
            continue;
        }
        match fetch_delta(repo_dir, origin, target, &base).await {
            Ok(Some(step)) => {
                printer.info(&format!(
                    "Fetched registry delta {base} -> {target} via AOS pack"
                ));
                return Ok(FetchPlan {
                    target: target.clone(),
                    steps: vec![step],
                });
            }
            Ok(None) => {}
            Err(err) => {
                printer.warning(&format!(
                    "Skipping unusable registry delta {base} -> {target}: {err:#}"
                ));
            }
        }
    }

    let anchor = anchor_for(target);
    match fetch_full_pack(repo_dir, origin, &anchor).await {
        Ok(Some(full_step)) => {
            let mut steps = vec![full_step];
            if anchor != *target {
                match fetch_delta(repo_dir, origin, target, &anchor).await {
                    Ok(Some(delta_step)) => steps.push(delta_step),
                    Ok(None) => {
                        let fallback = git_fetch_release(repo_dir, origin, target).await?;
                        steps.push(fallback);
                    }
                    Err(err) => {
                        printer.warning(&format!(
                            "Skipping unusable registry delta {anchor} -> {target}: {err:#}"
                        ));
                        let fallback = git_fetch_release(repo_dir, origin, target).await?;
                        steps.push(fallback);
                    }
                }
            }
            printer.info(&format!("Fetched registry full-pack anchor {anchor}"));
            return Ok(FetchPlan {
                target: target.clone(),
                steps,
            });
        }
        Ok(None) => {}
        Err(err) => {
            printer.warning(&format!(
                "Skipping unusable registry full-pack anchor {anchor}: {err:#}"
            ));
        }
    }

    let fallback = git_fetch_release(repo_dir, origin, target).await?;
    Ok(FetchPlan {
        target: target.clone(),
        steps: vec![fallback],
    })
}

/// Try to download and apply the `base -> target` thin delta pack.
///
/// Prefers the `.pack.zst` variant; returns `Ok(None)` when the producer
/// published neither variant.
async fn fetch_delta(
    repo_dir: &Path,
    origin: &str,
    target: &semver::Version,
    base: &semver::Version,
) -> Result<Option<FetchStep>> {
    let release = release_path(target);
    for compressed in [true, false] {
        let suffix = if compressed { ".pack.zst" } else { ".pack" };
        let relative = format!("releases/{release}/objects/pack/delta-{base}{suffix}");
        let Some(bytes) = get_optional(origin, &relative).await? else {
            continue;
        };
        let pack_bytes = if compressed {
            zstd::stream::decode_all(Cursor::new(bytes)).context("decompressing delta pack")?
        } else {
            bytes
        };
        let pack_path = local_pack_path(repo_dir, &format!("delta-{target}-from-{base}.pack"))?;
        tokio::fs::write(&pack_path, pack_bytes)
            .await
            .with_context(|| format!("writing {}", pack_path.display()))?;
        pack::index_pack_fix_thin(repo_dir, &pack_path).await?;
        return Ok(Some(FetchStep::Delta {
            target: target.clone(),
            base: base.clone(),
            compressed,
        }));
    }
    Ok(None)
}

/// Try to download and index the self-contained full pack for `version`.
///
/// Reads the release's `objects/info/packs` listing, downloads the first
/// pack (verifying or regenerating its `.idx`), and returns `Ok(None)` when
/// the release publishes no full pack.
async fn fetch_full_pack(
    repo_dir: &Path,
    origin: &str,
    version: &semver::Version,
) -> Result<Option<FetchStep>> {
    let release = release_path(version);
    let info_path = format!("releases/{release}/objects/info/packs");
    let Some(info) = get_optional(origin, &info_path).await? else {
        return Ok(None);
    };
    let info = String::from_utf8(info).context("release objects/info/packs is not UTF-8")?;
    let Some(pack_name) = parse_info_packs(&info).into_iter().next() else {
        return Ok(None);
    };

    let pack_relative = format!("releases/{release}/objects/pack/{pack_name}");
    let Some(pack_bytes) = get_optional(origin, &pack_relative).await? else {
        return Ok(None);
    };
    let pack_path = local_pack_path(repo_dir, &pack_name)?;
    tokio::fs::write(&pack_path, pack_bytes)
        .await
        .with_context(|| format!("writing {}", pack_path.display()))?;

    let idx_name = pack_name.trim_end_matches(".pack").to_string() + ".idx";
    let idx_relative = format!("releases/{release}/objects/pack/{idx_name}");
    if let Some(idx_bytes) = get_optional(origin, &idx_relative).await? {
        let idx_path = local_pack_path(repo_dir, &idx_name)?;
        tokio::fs::write(&idx_path, idx_bytes)
            .await
            .with_context(|| format!("writing {}", idx_path.display()))?;
        pack::verify_pack_index(repo_dir, &idx_path).await?;
    } else {
        pack::index_pack(repo_dir, &pack_path).await?;
    }

    Ok(Some(FetchStep::Full {
        version: version.clone(),
        pack: pack_name,
    }))
}

/// Fetch the release tag with plain `git fetch` (the correctness floor).
async fn git_fetch_release(
    repo_dir: &Path,
    origin: &str,
    target: &semver::Version,
) -> Result<FetchStep> {
    let refspec = release_refspec(target);
    let output = gitcmd::transport_async()
        .arg("-C")
        .arg(repo_dir)
        .args(["fetch", "--force", origin, &refspec])
        .output()
        .await
        .with_context(|| format!("running git fetch {refspec}"))?;
    if !output.status.success() {
        bail!(
            "git fetch fallback failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(FetchStep::GitFetchFallback { refspec })
}

/// GET a static origin file, mapping HTTP 404 to `Ok(None)`.
async fn get_optional(origin: &str, relative: &str) -> Result<Option<Vec<u8>>> {
    let url = join_cache_url(origin, relative);
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("fetching {url}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("GET {url} failed with {}", response.status());
    }
    Ok(Some(
        response
            .bytes()
            .await
            .with_context(|| format!("reading {url}"))?
            .to_vec(),
    ))
}

/// Parse pack names from a git `objects/info/packs` listing (`P <name>` lines).
fn parse_info_packs(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.trim().strip_prefix("P "))
        .filter(|name| name.starts_with("pack-") && name.ends_with(".pack"))
        .map(ToString::to_string)
        .collect()
}

/// Return (and create) the local `objects/pack/<name>` destination path.
fn local_pack_path(repo_dir: &Path, name: &str) -> Result<PathBuf> {
    let pack_dir = repo_dir.join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir)
        .with_context(|| format!("creating {}", pack_dir.display()))?;
    Ok(pack_dir.join(name))
}

/// Return the `X.Y.0` full-pack anchor release for a target.
fn anchor_for(target: &semver::Version) -> semver::Version {
    semver::Version::new(target.major, target.minor, 0)
}

/// Build the tag-to-tag refspec used by the `git fetch` fallback.
fn release_refspec(target: &semver::Version) -> String {
    format!("refs/tags/{target}:refs/tags/{target}")
}

fn push_unique(versions: &mut Vec<semver::Version>, version: semver::Version) {
    if !versions.contains(&version) {
        versions.push(version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(input: &str) -> semver::Version {
        semver::Version::parse(input).unwrap()
    }

    #[test]
    fn deltas_at_patch_bases() {
        assert_eq!(
            deltas_at(&version("1.4.5")),
            vec![
                version("1.4.4"),
                version("1.4.3"),
                version("1.4.2"),
                version("1.4.0"),
            ]
        );
    }

    #[test]
    fn deltas_at_minor_bases() {
        assert_eq!(
            deltas_at(&version("1.4.0")),
            vec![version("1.3.0"), version("1.0.0")]
        );
    }

    #[test]
    fn deltas_at_major_base() {
        assert_eq!(deltas_at(&version("2.0.0")), vec![version("1.0.0")]);
    }

    #[test]
    fn retained_set_dedups_when_minor_is_zero() {
        assert_eq!(retained_set(&version("1.0.0")), vec![version("1.0.0")]);
    }

    #[test]
    fn retained_set_three_distinct() {
        assert_eq!(
            retained_set(&version("1.4.2")),
            vec![version("1.0.0"), version("1.4.0"), version("1.4.2")]
        );
    }

    #[test]
    fn release_path_keeps_prerelease_and_build_on_patch_segment() {
        assert_eq!(
            release_path(&version("1.2.3-rc.1+build.5")),
            "1/2/3-rc.1+build.5"
        );
    }

    #[test]
    fn parse_info_packs_reads_git_format_lines() {
        assert_eq!(
            parse_info_packs("P pack-abc.pack\nP pack-def.idx\n\n"),
            vec!["pack-abc.pack".to_string()]
        );
    }

    #[test]
    fn plan_prefers_retained_delta() {
        let target = version("1.4.2");
        let mut artifacts = AvailableArtifacts::default();
        artifacts.deltas.insert((target.clone(), version("1.4.1")));
        artifacts
            .full_packs
            .insert(version("1.4.0"), "pack-full.pack".to_string());

        let plan = plan_from_artifacts(&target, &[version("1.4.1")], &artifacts);
        assert_eq!(
            plan.steps,
            vec![FetchStep::Delta {
                target,
                base: version("1.4.1"),
                compressed: false,
            }]
        );
    }

    #[test]
    fn plan_uses_full_anchor_then_delta_to_patch() {
        let target = version("1.4.2");
        let mut artifacts = AvailableArtifacts::default();
        artifacts
            .full_packs
            .insert(version("1.4.0"), "pack-full.pack".to_string());
        artifacts.deltas.insert((target.clone(), version("1.4.0")));

        let plan = plan_from_artifacts(&target, &[], &artifacts);
        assert_eq!(
            plan.steps,
            vec![
                FetchStep::Full {
                    version: version("1.4.0"),
                    pack: "pack-full.pack".to_string(),
                },
                FetchStep::Delta {
                    target,
                    base: version("1.4.0"),
                    compressed: false,
                },
            ]
        );
    }

    #[test]
    fn plan_falls_to_git_fetch_loose_floor() {
        let target = version("1.4.2");
        let plan = plan_from_artifacts(&target, &[], &AvailableArtifacts::default());
        assert_eq!(
            plan.steps,
            vec![FetchStep::GitFetchFallback {
                refspec: "refs/tags/1.4.2:refs/tags/1.4.2".to_string(),
            }]
        );
    }
}
