//! Owns the closed bootstrap JSON DTOs and their diagnostic label roster.
//!
//! Validation and runtime effects stay in the consuming service. Field names,
//! borrowing and Serde type names retain the existing wire contract.

use serde::Deserialize;
use serde::de::IgnoredAny;

/// Deserializes the closed Target wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target<'input> {
    /// Declares the schema.
    #[serde(borrow)]
    pub schema: &'input str,
    /// Declares the source record sha256.
    #[serde(borrow)]
    pub source_record_sha256: &'input str,
    /// Declares the geometry record sha256.
    #[serde(borrow)]
    pub geometry_record_sha256: &'input str,
    /// Declares the linked record sha256.
    #[serde(borrow)]
    pub linked_record_sha256: &'input str,
    /// Declares the glibc build record sha256.
    #[serde(borrow)]
    pub glibc_build_record_sha256: &'input str,
    /// Declares the sqlite.
    #[serde(borrow)]
    pub sqlite: Image<'input>,
    /// Declares the libc.
    #[serde(borrow)]
    pub libc: Image<'input>,
    /// Declares the stack records.
    #[serde(borrow)]
    pub stack_records: [StackRecord<'input>; 1],
    /// Declares the conditional main arena backing.
    #[serde(borrow)]
    pub conditional_main_arena_backing: BackingCase<'input>,
    /// Declares the case requirements.
    pub case_requirements: IgnoredAny,
}

/// Deserializes the closed Image wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image<'input> {
    /// Declares the path.
    #[serde(borrow)]
    pub path: &'input str,
    /// Declares the sha256.
    #[serde(borrow)]
    pub sha256: &'input str,
}

/// Deserializes the closed StackRecord wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackRecord<'input> {
    /// Declares the name.
    #[serde(borrow)]
    pub name: &'input str,
    /// Declares the sha256.
    #[serde(borrow)]
    pub sha256: &'input str,
}

/// Deserializes the closed BackingCase wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackingCase<'input> {
    /// Declares the case.
    #[serde(borrow)]
    pub case: &'input str,
    /// Declares the additional backing upper bytes.
    pub additional_backing_upper_bytes: u64,
    /// Declares the requests.
    pub requests: [Request; 2],
    /// Declares the required case.
    pub required_case: IgnoredAny,
}

/// Deserializes the closed Request wire object.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// Declares the request bytes.
    pub request_bytes: u64,
    /// Declares the chunk bytes.
    pub chunk_bytes: u64,
    /// Declares the ordinary growth upper bytes.
    pub ordinary_growth_upper_bytes: u64,
    /// Declares the additional backing upper bytes.
    pub additional_backing_upper_bytes: u64,
}

impl<'input> super::sealed::Sealed for Target<'input> {}

impl<'input> super::ClosedJsonProfile<'input> for Target<'input> {
    const DIAGNOSTIC_LABELS: &'static [&'static str] = &[
        "struct Target",
        "schema",
        "sourceRecordSha256",
        "geometryRecordSha256",
        "linkedRecordSha256",
        "glibcBuildRecordSha256",
        "sqlite",
        "libc",
        "stackRecords",
        "conditionalMainArenaBacking",
        "caseRequirements",
        "struct Image",
        "path",
        "sha256",
        "struct StackRecord",
        "name",
        "sha256",
        "struct BackingCase",
        "case",
        "additionalBackingUpperBytes",
        "requests",
        "requiredCase",
        "struct Request",
        "requestBytes",
        "chunkBytes",
        "ordinaryGrowthUpperBytes",
        "additionalBackingUpperBytes",
    ];
}
