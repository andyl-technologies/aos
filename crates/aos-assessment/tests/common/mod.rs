//! Portable fixture closure shared by assessment conformance tests.

#[allow(dead_code)]
pub mod updates;

use anyhow::Result;
use aos_assessment::advisory::{
    ADVISORY_RECORD_V1, ADVISORY_SNAPSHOT_V1, AdvisoryRecordV1, AdvisorySnapshotSource,
    AdvisorySnapshotV1,
};
use aos_assessment::definition::{PACKAGE_SCAN_DEFINITION_V1, PackageScanDefinitionV1};
use aos_assessment::input::{ASSESSMENT_POLICY_V1, EvaluationData};
use aos_assessment::observation::{PROVIDER_OBSERVATION_V1, ProviderObservationV1};
use aos_assessment::scan_inventory::{ComponentInstance, SCAN_INVENTORY_V1};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde_json::json;

pub fn evaluated_at() -> Result<Timestamp> {
    Timestamp::parse("2026-10-09T12:00:00Z")
}

pub fn fixture(version: &str) -> Result<EvaluationData> {
    let source = Sha256Digest::of_bytes("exact fixture source bytes");
    let security = json!({
        "identities":[{"kind":"ecosystem", "ecosystem":"crates.io", "name":"fixture"}],
        "advisorySources":[{"provider":"osv", "project":"fixture"}],
        "versionScheme":"semver", "dependencyCoverage":{"state":"complete", "basis":"Fixture inclusion evidence"}
    });
    let current = json!({"upstreamId":format!("v{version}"), "comparisonVersion":version});
    let definition: PackageScanDefinitionV1 = serde_json::from_value(json!({
        "schema":PACKAGE_SCAN_DEFINITION_V1, "unitId":"fixture-1", "family":"fixture", "stream":"1",
        "classification":"automatic", "lifecycle":"supported", "members":["fixture"], "metadataOrigins":["fixture-publication"],
        "versionProjection":{"kind":"component-field", "component":"main", "field":"comparisonVersion"},
        "components":[{"componentId":"main", "current":current, "security":security,
            "discovery":{"primary":{"provider":"github-releases", "repository":"example/fixture", "tagPrefix":"v"}, "advisors":[]},
            "releasePolicy":{"strategy":"latest-in-series", "versionScheme":"semver", "seriesMajor":1, "minimumAgeDays":3}}]
    }))?;
    let definition_digest = definition.digest()?;
    let component: ComponentInstance = serde_json::from_value(json!({
        "componentRef":"component", "componentId":"main", "subjectRef":"subject", "current":current,
        "security":security, "scanDefinitionDigest":definition_digest, "sourceContentDigest":source
    }))?;
    let inventory = serde_json::from_value(json!({
        "schema":SCAN_INVENTORY_V1,
        "subjects":[{"subjectRef":"subject", "packageCoordinate":"fixture/example", "version":version,
            "platform":"x86_64-linux", "output":"source", "kind":"source", "sourceContentDigest":source,
            "scanDefinitionDigest":definition_digest, "componentInventoryDigest":component.digest()?}],
        "components":[component], "relationships":[{"fromRef":"subject", "kind":"contains", "toRef":"component"}],
        "coverage":{"state":"complete", "basis":"Fixture component inclusion"}
    }))?;
    let raw = Sha256Digest::of_bytes("retained raw advisory");
    let record: AdvisoryRecordV1 = serde_json::from_value(json!({
        "schema":ADVISORY_RECORD_V1, "provider":"osv", "id":"GHSA-fixture-one", "modified":"2026-10-09T01:00:00Z",
        "aliases":["CVE-2026-10001"], "related":["GHSA-fixture-related"], "upstream":["CVE-2026-10002"],
        "summary":"Fixture vulnerability", "sourceDigest":raw, "references":[],
        "affected":[{"identity":{"kind":"ecosystem", "ecosystem":"crates.io", "name":"fixture"},
            "versions":[], "ranges":[{"kind":"semver", "events":[{"kind":"introduced", "version":"0"},{"kind":"fixed", "version":"1.3.0"}]}]}],
        "severity":[{"source":"osv", "scheme":"CVSS_V3", "value":"source-reported", "baseScore":"9.8"}]
    }))?;
    let records = vec![record.digest()?];
    let observation: ProviderObservationV1 = serde_json::from_value(json!({
        "schema":PROVIDER_OBSERVATION_V1, "provider":"osv", "project":"fixture", "adapterVersion":"osv/fixture-v1",
        "requestIdentityDigest":Sha256Digest::of_bytes("fixture query"),
        "retrievedAt":"2026-10-09T02:00:00Z", "validatedAt":"2026-10-09T02:00:00Z", "expiresAt":"2026-10-10T02:00:00Z",
        "responseDigest":raw, "payloadDigest":Sha256Digest::of_canonical("aos.advisory-record-set/v1", &records)?,
        "coverage":{"state":"complete", "proof":"query-pagination-exhausted"},
        "sourceRefs":[{"digest":raw, "byteLength":21, "origin":"osv"}]
    }))?;
    Ok(EvaluationData {
        inventory,
        definitions: vec![definition],
        upstream: vec![],
        advisory_snapshot: Some(AdvisorySnapshotV1 {
            schema: ADVISORY_SNAPSHOT_V1.into(),
            exploit_catalog: None,
            sources: vec![AdvisorySnapshotSource {
                provider: "osv".into(),
                project: "fixture".into(),
                observation,
                record_digests: records,
            }],
        }),
        advisories: vec![record],
        dispositions: vec![],
        history: vec![],
        policy: serde_json::from_value(
            json!({"schema":ASSESSMENT_POLICY_V1, "upstreamMaxAgeSeconds":86400,
            "advisoryMaxAgeSeconds":86400, "requiredAdvisorySources":[], "requireDependencyCoverage":true}),
        )?,
    })
}
