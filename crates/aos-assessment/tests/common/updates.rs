//! Shared exact update-candidate closure for planner and fleet qualification.

use anyhow::Result;
use aos_assessment::input::EvaluationData;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde_json::json;

/// Constructs a fresh exact source-unit update closure.
///
/// # Errors
/// Returns an error for invalid fixture records or timestamps.
pub fn data(now: Timestamp) -> Result<EvaluationData> {
    let mut data = super::fixture("1.2.0")?;
    let first = now.unix_seconds() - 4 * 86400;
    data.history = serde_json::from_value(json!([{
        "provider":"github-releases", "project":"example/fixture", "rawId":"v1.3.0",
        "firstObservedAt":Timestamp::from_unix_seconds(first)?,
    }]))?;
    data.upstream = serde_json::from_value(json!([{
        "componentRef":"component", "responseByteLength":3,
        "observation":{
            "schema":aos_assessment::UPSTREAM_OBSERVATION_V1,
            "provider":"github-releases", "project":"example/fixture",
            "retrievedAtUnix":now.unix_seconds(),
            "requestUrl":"https://api.github.com/repos/example/fixture/releases",
            "adapterVersion":"fixture-v1", "coverage":{"kind":"complete"},
            "responseDigest":Sha256Digest::of_bytes("raw"),
            "candidates":[{
                "rawId":"v1.3.0", "rawVersion":"1.3.0", "firstObservedAtUnix":first,
                "prerelease":false, "yanked":false, "licenses":[],
            }],
        },
    }]))?;
    Ok(data)
}

/// Constructs the corresponding local source-edit declaration without executing it.
///
/// # Errors
/// Returns an error for invalid fixture inventory or declaration associations.
pub fn maintenance_inventory() -> Result<aos_assessment::inventory::MaintenanceInventoryV1> {
    let data = data(super::evaluated_at()?)?;
    let definition = &data.definitions[0];
    let component = &definition.components[0];
    let inventory = json!({
        "schema":aos_assessment::MAINTENANCE_INVENTORY_V1,
        "units":[{
            "unitId":definition.unit_id, "family":definition.family, "stream":definition.stream,
            "classification":definition.classification,
            "package":{"currentVersion":"1.2.0", "versionProjection":definition.version_projection},
            "components":{
                "main":{
                    "current":component.current, "primary":component.discovery.primary,
                    "advisors":[], "releasePolicy":component.release_policy,
                    "sources":{"source":{
                        "fetcher":"fetchurl", "derivation":"/nix/store/00000000000000000000000000000000-source.drv",
                        "urlTemplates":[{
                            "scheme":"https", "authority":"example.org",
                            "path":[{"kind":"parts", "parts":[
                                {"kind":"literal", "value":"source-"},
                                {"kind":"component-field", "component":"main", "field":"comparisonVersion"},
                                {"kind":"literal", "value":".tar.gz"},
                            ]}],
                        }],
                        "hash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "hashMode":"flat", "allowedRedirectHosts":["example.org"],
                    }},
                },
            },
            "artifacts":{}, "owner":"pkgs/test/fixture.nix", "members":definition.members,
            "platforms":["x86_64-linux"], "policy":{"lifecycle":"supported", "riskFloor":"normal"},
        }],
    });
    aos_assessment::inventory::MaintenanceInventoryV1::from_slice(&serde_json::to_vec(&inventory)?)
}
