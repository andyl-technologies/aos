//! Consumer-side object fetch resolution for the git-native registry.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::download::join_cache_url;
use crate::registry::pack;
use aos_core::output::Printer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchPlan {
    pub target: semver::Version,
    pub steps: Vec<FetchStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchStep {
    Delta {
        target: semver::Version,
        base: semver::Version,
        compressed: bool,
    },
    Full {
        version: semver::Version,
        pack: String,
    },
    GitFetchFallback {
        refspec: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct AvailableArtifacts {
    pub deltas: BTreeSet<(semver::Version, semver::Version)>,
    pub full_packs: BTreeMap<semver::Version, String>,
}

/// Return the delta bases a producer publishes at `target`, nearest first.
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

pub fn parse_retained(retained: &[String]) -> Result<Vec<semver::Version>> {
    retained
        .iter()
        .map(|release| {
            semver::Version::parse(release)
                .with_context(|| format!("parsing retained release {release}"))
        })
        .collect()
}

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
/// correctness floor.
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
        if let Some(step) = fetch_delta(repo_dir, origin, target, &base).await? {
            printer.info(&format!(
                "Fetched registry delta {base} -> {target} via AOS pack"
            ));
            return Ok(FetchPlan {
                target: target.clone(),
                steps: vec![step],
            });
        }
    }

    let anchor = anchor_for(target);
    if let Some(full_step) = fetch_full_pack(repo_dir, origin, &anchor).await? {
        let mut steps = vec![full_step];
        if anchor != *target {
            if let Some(delta_step) = fetch_delta(repo_dir, origin, target, &anchor).await? {
                steps.push(delta_step);
            } else {
                let fallback = git_fetch_release(repo_dir, origin, target).await?;
                steps.push(fallback);
            }
        }
        printer.info(&format!("Fetched registry full-pack anchor {anchor}"));
        return Ok(FetchPlan {
            target: target.clone(),
            steps,
        });
    }

    let fallback = git_fetch_release(repo_dir, origin, target).await?;
    Ok(FetchPlan {
        target: target.clone(),
        steps: vec![fallback],
    })
}

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
    } else {
        pack::index_pack(repo_dir, &pack_path).await?;
    }

    Ok(Some(FetchStep::Full {
        version: version.clone(),
        pack: pack_name,
    }))
}

async fn git_fetch_release(
    repo_dir: &Path,
    origin: &str,
    target: &semver::Version,
) -> Result<FetchStep> {
    let refspec = release_refspec(target);
    let output = Command::new("git")
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

fn parse_info_packs(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.trim().strip_prefix("P "))
        .filter(|name| name.starts_with("pack-") && name.ends_with(".pack"))
        .map(ToString::to_string)
        .collect()
}

fn local_pack_path(repo_dir: &Path, name: &str) -> Result<PathBuf> {
    let pack_dir = repo_dir.join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir)
        .with_context(|| format!("creating {}", pack_dir.display()))?;
    Ok(pack_dir.join(name))
}

fn anchor_for(target: &semver::Version) -> semver::Version {
    semver::Version::new(target.major, target.minor, 0)
}

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
