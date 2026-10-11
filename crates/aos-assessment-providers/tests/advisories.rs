//! Exact upstream advisory, pagination and catalog normalization regressions.

use anyhow::Result;
use aos_assessment::advisory::RangeEvent;
use aos_assessment_providers::{kev, nvd, osv};
use aos_contract::Sha256Digest;
use serde_json::json;

fn osv_record() -> serde_json::Value {
    json!({
        "schema_version":"1.9.1", "id":"GHSA-fixture-one", "modified":"2026-10-09T01:02:03.456Z",
        "summary":"Fixture issue", "aliases":["CVE-2026-10001"],
        "related":["GHSA-fixture-related"], "upstream":["CVE-2026-10002"],
        "affected":[{"package":{"ecosystem":"crates.io","name":"fixture"},
            "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}],
        "references":[{"type":"ADVISORY","url":"https://example.invalid/advisory"}],
        "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

#[test]
fn osv_normalization_preserves_distinct_relationships_revision_and_raw_evidence() -> Result<()> {
    let raw = serde_json::to_vec(&osv_record())?;
    let record = osv::record(&raw)?;
    assert_eq!(record.source_digest, Sha256Digest::of_bytes(&raw));
    assert_eq!(record.modified, "2026-10-09T01:02:03.456Z");
    assert_eq!(record.aliases, ["CVE-2026-10001"]);
    assert_eq!(record.related, ["GHSA-fixture-related"]);
    assert_eq!(record.upstream, ["CVE-2026-10002"]);
    assert_eq!(
        record.affected[0].ranges[0].events[1],
        RangeEvent::Fixed("1.2.3".into())
    );
    assert!(record.severity[0].base_score.is_none());
    record.digest()?;
    Ok(())
}

#[test]
fn osv_batch_positions_and_per_query_continuations_cannot_be_lost() -> Result<()> {
    let raw = br#"{"results":[{"vulns":[{"id":"CVE-2026-10001","modified":"2026-10-09T01:00:00Z"}],"next_page_token":"remaining"},{}]}"#;
    let pages = osv::batch_pages(raw, 2)?;
    assert_eq!(pages[0].next_page_token.as_deref(), Some("remaining"));
    assert_eq!(pages[1].records.len(), 0);
    assert!(pages[1].next_page_token.is_none());
    assert!(osv::batch_pages(raw, 1).is_err());
    assert!(osv::query_page(br#"{"vulns":[],"vulns":[{}]}"#).is_err());
    let query = osv::Query::Purl {
        value: "pkg:cargo/fixture@1.2.0".into(),
    };
    let request = query.request(None)?;
    assert!(request.get("version").is_none());
    assert_eq!(request["package"]["purl"], "pkg:cargo/fixture@1.2.0");
    Ok(())
}

#[test]
fn unknown_osv_range_type_is_preserved_and_ambiguous_endpoint_is_rejected() -> Result<()> {
    let mut value = osv_record();
    value["affected"][0]["ranges"][0]["type"] = json!("FUTURE");
    let record = osv::record(&serde_json::to_vec(&value)?)?;
    assert_eq!(
        record.affected[0].ranges[0].kind,
        aos_assessment::advisory::RangeKind::Unsupported
    );
    value["affected"][0]["ranges"][0]["type"] = json!("SEMVER");
    value["affected"][0]["ranges"][0]["events"][1] = json!({"future_endpoint":"1.2.3"});
    let unknown = osv::record(&serde_json::to_vec(&value)?)?;
    assert!(unknown.affected[0].ranges.is_empty());
    assert_eq!(unknown.affected[0].unsupported, ["range-event-unsupported"]);
    value["affected"][0]["ranges"][0]["events"][0] = json!({"introduced":"0","fixed":"1.0.0"});
    assert!(osv::record(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

fn nvd_page() -> serde_json::Value {
    json!({"version":"2.0","startIndex":0,"resultsPerPage":1,"totalResults":2,
    "vulnerabilities":[{"cve":{
        "id":"CVE-2026-10001","lastModified":"2026-10-09T01:02:03.456","vulnStatus":"Analyzed",
        "descriptions":[{"lang":"en","value":"Fixture issue"}],
        "configurations":[{"operator":"AND","nodes":[
            {"operator":"OR","cpeMatch":[{"criteria":"cpe:2.3:a:example:product:*:*:*:*:*:*:*:*","vulnerable":true,"versionEndExcluding":"1.3.0"}]},
            {"operator":"OR","negate":true,"cpeMatch":[{"criteria":"cpe:2.3:o:example:os:*:*:*:*:*:*:*:*","vulnerable":false}]}
        ]}],
        "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}]}
    }}]})
}

#[test]
fn nvd_preserves_configuration_tree_and_decimal_scores_as_strings() -> Result<()> {
    let raw = serde_json::to_vec(&nvd_page())?;
    let page = nvd::page(&raw, 0)?;
    assert_eq!(page.next_start_index, Some(1));
    assert_eq!(page.total_results, 2);
    assert_eq!(
        page.records[0].severity[0].base_score.as_deref(),
        Some("9.8")
    );
    assert_eq!(page.records[0].source_digest, Sha256Digest::of_bytes(&raw));
    let configuration = serde_json::to_value(&page.records[0].configuration)?;
    assert_eq!(configuration["children"][0]["operator"], "and");
    assert_eq!(configuration["children"][0]["children"][1]["negate"], true);
    page.records[0].digest()?;
    assert!(nvd::page(&raw, 1).is_err());
    Ok(())
}

#[test]
fn nvd_rejection_is_an_explicit_revision_and_incomplete_pages_do_not_advance() -> Result<()> {
    let mut value = nvd_page();
    value["vulnerabilities"][0]["cve"]["vulnStatus"] = json!("Rejected");
    assert!(
        nvd::page(&serde_json::to_vec(&value)?, 0)?.records[0]
            .withdrawn
            .is_some()
    );
    value["vulnerabilities"] = json!([]);
    assert!(nvd::page(&serde_json::to_vec(&value)?, 0).is_err());
    Ok(())
}

#[test]
fn kev_uses_exact_identifiers_and_checks_full_catalog_counts() -> Result<()> {
    let mut value = json!({"catalogVersion":"2026.10.09","count":1,
        "vulnerabilities":[{"cveID":"CVE-2026-10001","dateAdded":"2026-10-09"}]});
    let records = kev::catalog(&serde_json::to_vec(&value)?)?;
    assert_eq!(records[0].cve_id, "CVE-2026-10001");
    value["count"] = json!(2);
    assert!(kev::catalog(&serde_json::to_vec(&value)?).is_err());
    assert!(!kev::is_cve_id("cve-2026-10001"));
    assert!(!kev::is_cve_id("CVE-2026-1"));
    assert!(!kev::is_cve_id("CVE-2026-10001-extra"));
    Ok(())
}

#[test]
fn nvd_envelope_refresh_does_not_change_advisory_meaning_or_lose_raw_evidence() -> Result<()> {
    let mut value = nvd_page();
    value["timestamp"] = json!("2026-10-09T02:00:00.000");
    let first_raw = serde_json::to_vec(&value)?;
    let first = nvd::page(&first_raw, 0)?.records.remove(0);

    value["timestamp"] = json!("2026-10-09T03:00:00.000");
    let later_raw = serde_json::to_vec_pretty(&value)?;
    let later = nvd::page(&later_raw, 0)?.records.remove(0);
    assert_eq!(first.source_digest, Sha256Digest::of_bytes(&first_raw));
    assert_eq!(later.source_digest, Sha256Digest::of_bytes(&later_raw));
    assert_ne!(first.digest()?, later.digest()?);
    assert_eq!(first.change_digest()?, later.change_digest()?);

    value["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] =
        json!(10.0);
    let changed = nvd::page(&serde_json::to_vec(&value)?, 0)?
        .records
        .remove(0);
    assert_ne!(changed.change_digest()?, first.change_digest()?);
    value["vulnerabilities"][0]["cve"]["vulnStatus"] = json!("Rejected");
    let rejected = nvd::page(&serde_json::to_vec(&value)?, 0)?
        .records
        .remove(0);
    assert_ne!(rejected.change_digest()?, changed.change_digest()?);
    Ok(())
}

#[test]
fn osv_reencoding_coalesces_only_when_exact_native_revision_and_assertions_match() -> Result<()> {
    let value = osv_record();
    let first = osv::record(&serde_json::to_vec(&value)?)?;
    let pretty = osv::record(&serde_json::to_vec_pretty(&value)?)?;
    assert_ne!(first.digest()?, pretty.digest()?);
    assert_eq!(first.change_digest()?, pretty.change_digest()?);

    let mut revised = value;
    revised["modified"] = json!("2026-10-09T01:02:03.457Z");
    let revised = osv::record(&serde_json::to_vec(&revised)?)?;
    assert_ne!(first.change_digest()?, revised.change_digest()?);
    Ok(())
}
