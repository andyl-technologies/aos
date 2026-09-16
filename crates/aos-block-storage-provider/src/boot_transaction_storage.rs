//! ESP-backed transaction storage admission for the initrd stage executor.

use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_provider_protocol::ResourceContext;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::{Backend, BackendObservation, ability_value};

const REALIZATION_SCHEMA: &str = "aos.boot.transaction-storage-realization/v1";
const CONTEXT_SCHEMA: &str = "aos.boot.transaction-storage-context/v1";
const OBSERVATION_SCHEMA: &str = "aos.boot.transaction-storage-observation/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    name: String,
    purpose: Purpose,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Purpose {
    InitrdStageJournal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    path: String,
}

/// Admits the exact package-owned ESP transaction-storage view.
pub struct BootTransactionStorageBackend;

impl Backend for BootTransactionStorageBackend {
    fn action_method(&self) -> &'static str {
        "materialize"
    }

    fn path_output(&self) -> &'static str {
        "storage-path"
    }

    fn admit_context(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        _resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        validate_desired(&decode(desired)?)?;
        let realization: Realization = decode(realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported boot transaction-storage realization"
        );
        validate_path(&realization.path)?;

        ability_value(serde_json::to_value(Context {
            schema: CONTEXT_SCHEMA.into(),
            path: realization.path,
        })?)
    }

    fn observe(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation> {
        let desired: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_desired(&desired)?;
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported boot transaction-storage context"
        );
        validate_path(&context.path)?;

        let ready = Path::new(&context.path).is_dir();
        Ok(BackendObservation {
            evidence: ability_value(json!({
                "schema": OBSERVATION_SCHEMA,
                "expected": desired,
                "realized": ready.then_some(context.path.clone()),
                "state": if ready { "ready" } else { "absent" },
            }))?,
            ready,
            released: false,
            path: ready.then_some(context.path),
            unknown: false,
        })
    }

    fn apply(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        context: &AbilityValue,
        _remaining_millis: u64,
    ) -> Result<()> {
        let desired: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_desired(&desired)?;
        validate_path(&context.path)?;
        ensure!(
            Path::new(&context.path).is_dir(),
            "boot transaction-storage view is not materialized"
        );
        Ok(())
    }

    fn release(
        &self,
        _desired: &AbilityValue,
        _realization: &AbilityValue,
        _target: &ResourceReference,
        _context: &AbilityValue,
        _remaining_millis: u64,
    ) -> Result<()> {
        bail!("initrd transaction storage remains retained through stage handoff")
    }
}

fn validate_desired(desired: &Desired) -> Result<()> {
    ensure!(
        !desired.name.is_empty()
            && desired.name.len() <= 128
            && desired
                .name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') }),
        "boot transaction-storage name is invalid"
    );
    ensure!(
        desired.purpose == Purpose::InitrdStageJournal,
        "unsupported boot transaction-storage purpose"
    );
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute(),
        "transaction-storage path is not absolute"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "transaction-storage path is not normalized"
    );
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone())
        .context("decoding boot transaction-storage value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_view_paths() {
        assert!(validate_path("/run/aos-boot-transaction-storage/journal").is_ok());
        assert!(validate_path("/run/../boot").is_err());
        assert!(validate_path("boot").is_err());
    }
}
