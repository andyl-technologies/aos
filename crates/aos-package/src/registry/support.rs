//! Section-scoped writes of the `[support]` table in a registry's
//! `registry.toml`.
//!
//! `registry.toml` is operator-owned, and several source lines publish into
//! one registry, so a release may never rewrite the whole file. A release from
//! train `T` owns exactly one table, `[support.trains."T"]`, and a release
//! from the newest train additionally owns `[support.default]`. This module
//! replaces or appends those tables as text, leaving every other byte of the
//! file untouched, and verifies afterwards that nothing else changed.
//!
//! The written text is canonical so that an operator who computes the
//! expected policy digest for a transaction can reproduce it exactly:
//!
//! ```toml
//! [support.default]
//! kind = "standard"
//! superseded_after_trains = 2
//!
//! [support.trains."2026.9"]
//! kind = "lts"
//! supported_until = "2028-09-30"
//! ```

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_registry_surface::manifest::RegistryRootConfig;
use aos_registry_surface::support::{SupportDefault, SupportPolicy, SupportTrain, parse_train};
use serde::{Deserialize, Serialize};

/// The support tables one release publication is allowed to write.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportSectionWrite {
    /// The train this release belongs to, as `major.minor`.
    pub train: String,
    /// The train's own support statement.
    pub entry: SupportTrain,
    /// The rolling default, written only when this train is the newest one
    /// the registry knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<SupportDefault>,
}

impl SupportSectionWrite {
    /// Derives the write a release may make from its version and contract
    /// policy.
    ///
    /// The contract on a source line states only what that line owns: the
    /// entry for its own train, and `default` when it is the trunk. A
    /// contract naming any other train is refused, because that is the only
    /// way one branch could rewrite another train's promise.
    ///
    /// # Errors
    /// Returns an error when the version has no train, when the policy names
    /// a train other than the release's own, or when the policy is invalid.
    pub fn from_policy(version: &str, policy: &SupportPolicy) -> Result<Option<Self>> {
        policy
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid support policy: {error}"))?;
        let parsed = semver::Version::parse(version).context("parsing release version")?;
        let train = format!("{}.{}", parsed.major, parsed.minor);
        for key in policy.trains.keys() {
            if *key != train {
                bail!(
                    "release {version} belongs to train {train} but its contract states support for train {key}"
                );
            }
        }
        let Some(entry) = policy.trains.get(&train) else {
            return Ok(None);
        };
        Ok(Some(Self {
            train,
            entry: entry.clone(),
            default: Some(policy.default.clone()),
        }))
    }
}

/// Applies one release's support tables to `registry.toml` in `directory`.
///
/// Existing tables for the same train (and `default`, when written) are
/// removed and the canonical text is appended. The write refuses to publish
/// `default` unless the release's train is the newest train the file already
/// names, and it fails closed if the resulting file differs anywhere outside
/// the owned tables.
///
/// # Errors
/// Returns an error when the file is missing or invalid TOML, when the train
/// key is malformed, when `default` is written from a train that is not the
/// newest, or when the rewrite changed anything it does not own.
pub fn apply_support_section(directory: &Path, write: &SupportSectionWrite) -> Result<()> {
    let train = parse_train(&write.train)
        .with_context(|| format!("support train {:?} is not major.minor", write.train))?;
    let path = directory.join("registry.toml");
    let original = fs::read_to_string(&path)
        .with_context(|| format!("reading {} for the support policy", path.display()))?;
    let before: RegistryRootConfig = toml::from_str(&original)
        .with_context(|| format!("parsing {} before the support policy write", path.display()))?;

    if write.default.is_some() {
        let newest = before
            .support
            .as_ref()
            .into_iter()
            .flat_map(|policy| policy.trains.keys())
            .filter_map(|key| parse_train(key))
            .max()
            .unwrap_or(train);
        if newest > train {
            bail!(
                "release train {} may not write support.default while train {}.{} is newer",
                write.train,
                newest.0,
                newest.1
            );
        }
    }

    let mut text = strip_table(&original, &format!("support.trains.\"{}\"", write.train));
    if write.default.is_some() {
        text = strip_table(&text, "support.default");
    }
    let mut text = text.trim_end_matches('\n').to_string();
    if !text.is_empty() {
        text.push('\n');
    }
    if let Some(default) = &write.default {
        let _ = write!(
            text,
            "\n[support.default]\nkind = \"{}\"\nsuperseded_after_trains = {}\n",
            kind_token(default.kind),
            default.superseded_after_trains
        );
    }
    let _ = write!(
        text,
        "\n[support.trains.\"{}\"]\nkind = \"{}\"\n",
        write.train,
        kind_token(write.entry.kind)
    );
    if let Some(until) = &write.entry.supported_until {
        let _ = writeln!(text, "supported_until = \"{until}\"");
    }

    let after: RegistryRootConfig = toml::from_str(&text)
        .with_context(|| format!("parsing {} after the support policy write", path.display()))?;
    verify_owned_change(&before, &after, write)?;
    fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Checks that the rewrite changed only the tables the release owns.
fn verify_owned_change(
    before: &RegistryRootConfig,
    after: &RegistryRootConfig,
    write: &SupportSectionWrite,
) -> Result<()> {
    let mut expected = before.support.clone().unwrap_or_default();
    if let Some(default) = &write.default {
        expected.default = default.clone();
    }
    expected
        .trains
        .insert(write.train.clone(), write.entry.clone());
    let after_policy = after.support.clone().unwrap_or_default();
    if after_policy != expected {
        bail!("support policy write changed tables outside the release's own train");
    }
    let mut before_rest = toml::Value::try_from(before)?;
    let mut after_rest = toml::Value::try_from(after)?;
    for value in [&mut before_rest, &mut after_rest] {
        if let toml::Value::Table(table) = value {
            table.remove("support");
        }
    }
    if before_rest != after_rest {
        bail!("support policy write altered registry.toml outside the [support] table");
    }
    Ok(())
}

fn kind_token(kind: aos_registry_surface::support::SupportKind) -> &'static str {
    match kind {
        aos_registry_surface::support::SupportKind::Standard => "standard",
        aos_registry_surface::support::SupportKind::Lts => "lts",
    }
}

/// Removes one `[header]` table (its header line through the line before the
/// next table header) from TOML text, keeping everything else byte-identical.
fn strip_table(text: &str, header: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default()
                .trim();
            skipping = name == header;
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::support::SupportKind;

    const BASE: &str = "[registry]\nname = \"andyl/main\"\n# operator note\ndefault_release = \"2026.9.0\"\n\n[caches]\nendpoint = \"https://cache.example.com/\"\n";

    fn write(train: &str, default: bool) -> SupportSectionWrite {
        SupportSectionWrite {
            train: train.into(),
            entry: SupportTrain {
                kind: SupportKind::Lts,
                supported_until: Some("2028-09-30".into()),
            },
            default: default.then(SupportDefault::default),
        }
    }

    #[test]
    fn appends_owned_tables_and_keeps_the_rest_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("registry.toml"), BASE).unwrap();
        apply_support_section(dir.path(), &write("2026.9", true)).unwrap();
        let text = fs::read_to_string(dir.path().join("registry.toml")).unwrap();
        assert!(text.starts_with(BASE));
        assert!(text.ends_with(
            "\n[support.default]\nkind = \"standard\"\nsuperseded_after_trains = 2\n\n[support.trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-09-30\"\n"
        ));
        // A second write for the same train replaces only its table.
        let mut updated = write("2026.9", false);
        updated.entry.supported_until = Some("2029-01-31".into());
        apply_support_section(dir.path(), &updated).unwrap();
        let text = fs::read_to_string(dir.path().join("registry.toml")).unwrap();
        assert_eq!(text.matches("[support.trains.\"2026.9\"]").count(), 1);
        assert!(text.contains("superseded_after_trains = 2"));
        assert!(text.contains("supported_until = \"2029-01-31\""));
        assert!(text.contains("# operator note"));
    }

    #[test]
    fn older_trains_write_only_their_own_table() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("registry.toml"), BASE).unwrap();
        apply_support_section(dir.path(), &write("2026.9", true)).unwrap();
        let error = apply_support_section(dir.path(), &write("2026.3", true)).unwrap_err();
        assert!(error.to_string().contains("may not write support.default"));
        apply_support_section(dir.path(), &write("2026.3", false)).unwrap();
        let config: RegistryRootConfig =
            toml::from_str(&fs::read_to_string(dir.path().join("registry.toml")).unwrap()).unwrap();
        let policy = config.support.unwrap();
        assert_eq!(policy.trains.len(), 2);
        assert!(policy.trains.contains_key("2026.3"));
    }

    #[test]
    fn contracts_may_only_name_their_own_train() {
        let policy: SupportPolicy = toml::from_str(
            "[default]\nsuperseded_after_trains = 3\n[trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-09-30\"\n",
        )
        .unwrap();
        let write = SupportSectionWrite::from_policy("2026.9.4", &policy)
            .unwrap()
            .unwrap();
        assert_eq!(write.train, "2026.9");
        assert_eq!(write.default.unwrap().superseded_after_trains, 3);
        let error = SupportSectionWrite::from_policy("2026.3.7", &policy).unwrap_err();
        assert!(error.to_string().contains("train 2026.9"));
        let silent: SupportPolicy = toml::from_str("[default]\n").unwrap();
        assert!(
            SupportSectionWrite::from_policy("2026.3.7", &silent)
                .unwrap()
                .is_none()
        );
    }
}
