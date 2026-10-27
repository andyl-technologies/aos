//! Prices the existing strict JSON claims and their pure validation models.
//!
//! Each decoded item/string consumes bytes in the actual JSON extent. Four
//! cells cover Vec's first nonzero capacity and a growth/sort frontier; nested
//! vectors and independent cloned model backing are listed separately.

use super::*;
use aos_sandbox_model::PathName;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use aos_sandbox_protocol::policy_data::canonical_model_receiving_bytes_v1;
use std::{collections::BTreeSet, mem::size_of};

fn cells<T>(bytes: usize) -> Option<usize> {
    bytes.checked_mul(4)?.checked_mul(size_of::<T>())
}

fn path_backing(bytes: usize) -> Option<usize> {
    cells::<PathName>(bytes)?.checked_add(bytes.checked_mul(4)?)
}

// This finite field/variant/visitor roster bounds generated expected-name
// text. It is not used to accept input; only the original serde decoder parses.
fn decoder_error_receiving_bytes_v1(encoded_bytes: usize) -> Option<usize> {
    let rosters: &[&[&str]] = &[
        &["NamespaceGraphSchemaV1", "V1"],
        &["ExecutableSourceClaims", "handle", "selector", "descriptor"],
        &[
            "LogicalSourceClaims",
            "handle",
            "resource_kind",
            "selector",
            "class",
            "execution_class",
            "executable_source",
        ],
        &["CompositionClaims", "output", "inputs"],
        &[
            "NamespaceRuleClaims",
            "Source",
            "Compose",
            "Include",
            "source",
            "prefix",
            "execution",
            "Exclude",
            "prefix",
            "Attach",
            "source",
            "destination",
            "mode",
            "execution",
            "Present",
            "prefix",
            "presentation",
        ],
        &[
            "AdvisoryActionClaims",
            "kind",
            "source",
            "resource_kind",
            "target",
            "bounded_value",
            "priority",
            "degradation",
        ],
        &[
            "AdvisoryDecisionClaims",
            "action",
            "status",
            "effective_value",
        ],
        &[
            "ExplanationEntryClaims",
            "stage",
            "decision",
            "reason",
            "source",
            "subject",
            "causes",
        ],
        &["ExplanationStageClaims", "stage", "entries"],
        &["ExplanationClaims", "commitment", "stages"],
        &[
            "ExplanationStageV1",
            "Normalize",
            "Authority",
            "Namespace",
            "HardResources",
            "BackendAdmission",
            "Advisory",
            "Lowering",
        ],
        &[
            "ExplanationDecisionV1",
            "Admitted",
            "Narrowed",
            "Rejected",
            "Required",
            "Degraded",
            "Frozen",
        ],
        &[
            "ExplanationReasonV1",
            "InputFrozen",
            "DefaultDeny",
            "AuthorityAdmitted",
            "OperationCeiling",
            "DelegationCeiling",
            "NamespaceSource",
            "DestinationAuthority",
            "NamespaceComposition",
            "NamespacePresentation",
            "NamespaceNoExecute",
            "NamespaceExecute",
            "ResourceProvenance",
            "CacheDomainCeiling",
            "RevocationCeiling",
            "BackendEnforcement",
            "BackendFeature",
            "EndpointAuthority",
            "AdvisorySelected",
            "AdvisoryDegraded",
            "PortableLowering",
        ],
        &[
            "InputSourceV1",
            "Node",
            "Site",
            "Project",
            "Ancestor",
            "ordinal",
            "Request",
            "Catalog",
            "Backend",
            "Compiler",
        ],
        &[
            "NamespaceSourceClassV1",
            "Immutable",
            "Live",
            "PrivateDelta",
            "Service",
        ],
        &[
            "NamespacePresentationFeatureV1",
            "PosixAcl",
            "AbsoluteSymlink",
            "ParentEscapeSymlink",
        ],
        &["ViewExecutionV1", "NoExecute", "AllowExecute"],
        &[
            "NamespaceExecutionClassV1",
            "DataOnly",
            "VerifiedPackageOrTool",
        ],
        &[
            "AdvisoryKindV1",
            "PrefetchMetadata",
            "PrefetchContent",
            "Readahead",
            "DirectoryIndex",
            "Passthrough",
            "Keepalive",
            "CacheWeight",
            "WorkerPooling",
        ],
        &["AdvisoryDegradationV1", "Omit"],
        &[
            "AdvisoryStatusV1",
            "Active",
            "OmittedByCeiling",
            "OmittedUnavailable",
            "Superseded",
        ],
        &[
            "ResourceKind",
            "sandbox",
            "execution",
            "snapshot",
            "tree",
            "live-export",
            "private-delta",
            "secret",
            "device",
            "network-endpoint",
            "ipc-service",
            "cache-read",
            "cache-publish",
            "environment",
            "attachment-slot",
            "child-delegation",
            "capability",
            "operation",
            "git-object-database",
        ],
        &["ObjectDescriptor", "media_type", "digest", "encoded_size"],
        &["FeatureRefWire", "namespace", "major", "minor"],
        &[
            "Selector", "Resource", "resource", "Tree", "tree", "Path", "export", "prefix",
            "Profile", "feature", "body",
        ],
        &[
            "ViewMutation",
            "ReadOnly",
            "ReadWrite",
            "PrivateCow",
            "AppendOnly",
            "Service",
        ],
    ];
    let expected = rosters.iter().try_fold(0_usize, |maximum, names| {
        let bytes = names.iter().try_fold(0_usize, |sum, name| {
            sum.checked_add(name.len())?.checked_add(4)
        })?;
        Some(maximum.max(bytes))
    })?;
    // Serde's fixed error prefixes, structural visitor words and actual
    // primitive numeric width are separate from the untrusted field/value.
    let prefix = "unknown variant , expected one of ; duplicate field ; missing field ; invalid type: , expected struct variant ; a byte string of length ..=; a bounded sequence of portable path names".len();
    let digits = usize::try_from(u64::MAX.ilog10()).ok()?.checked_add(1)?;
    let static_context = expected
        .checked_add(prefix)?
        .checked_add(digits.checked_mul(4)?)?;
    aos_sandbox_protocol::policy_data::canonical_json_decode_error_receiving_bytes_v1(
        encoded_bytes,
        static_context,
    )
}

/// Prices alternatives in the sole output loop, not simultaneous decoders.
pub(crate) fn receiving_bytes_v1(bytes: usize) -> Option<usize> {
    // Namespace claims remain borrowed while ordering rules and the canonical
    // sequence/DAG check own their actual separate model backing.
    let namespace = cells::<NamespaceRuleClaims>(bytes)?
        .checked_add(cells::<ResourceId>(bytes)?)?
        .checked_add(path_backing(bytes)?)?
        .checked_add(crate::namespace::portable_order_receiving_bytes_v1(bytes)?)?
        .checked_add(
            size_of::<(NamespaceGraphSchemaV1, Vec<NamespaceRuleClaims>)>().checked_mul(2)?,
        )?
        .checked_add(size_of::<
            Result<
                (NamespaceGraphSchemaV1, Vec<NamespaceRuleClaims>),
                PolicyCompilerJournalErrorV1,
            >,
        >())?;

    // The original action vector survives its clone's semantic-key set,
    // keyed sort and returned ordering. Actions move between keyed/output
    // cells; the four-cell allocation bound includes stable-sort scratch.
    type Key = (AdvisoryKindV1, u16, u16, ObjectDigest);
    let advisory = cells::<AdvisoryDecisionClaims>(bytes)?
        .checked_add(cells::<AdvisoryActionV1>(bytes)?.checked_mul(2)?)?
        .checked_add(cells::<(Key, AdvisoryActionV1)>(bytes)?)?
        .checked_add(nodes::<ObjectDigest, ()>(bytes)?)?
        .checked_add(path_backing(bytes)?.checked_mul(3)?)?
        .checked_add(size_of::<(
            Vec<AdvisoryDecisionClaims>,
            Vec<AdvisoryActionV1>,
            BTreeSet<ObjectDigest>,
            Vec<(Key, AdvisoryActionV1)>,
        )>())?
        .checked_add(size_of::<
            Result<Vec<AdvisoryActionV1>, crate::PolicyModelError>,
        >())?;
    let diagnostics = cells::<ExplanationStageClaims>(bytes)?
        .checked_add(cells::<ExplanationEntryClaims>(bytes)?)?
        .checked_add(cells::<InputSourceV1>(bytes)?)?
        .checked_add(size_of::<ExplanationClaims>().checked_mul(2)?)?
        .checked_add(size_of::<
            Result<ExplanationClaims, PolicyCompilerJournalErrorV1>,
        >())?;

    // Serde's omitted Option fields can be reintroduced as `,"field":null`
    // before the exact-byte comparison rejects that noncanonical input. Each
    // such struct consumes an encoded item. The two identifiers below are
    // the actual claim fields, not a new JSON encoder or format ceiling.
    let optional_field = stringify!(executable_source)
        .len()
        .max(stringify!(effective_value).len())
        .checked_add(8)?;
    let json_bound = bytes.checked_add(bytes.checked_mul(optional_field)?)?;
    let domain = NAMESPACE_DOMAIN
        .len()
        .max(ADVISORY_DOMAIN.len())
        .max(DIAGNOSTICS_DOMAIN.len())
        .max(b"aos.sandbox.executable-source-classification.v1".len());
    let canonical = canonical_model_receiving_bytes_v1(json_bound, domain)?;
    // Escaped-string scratch and the partial owned path/media strings are
    // distinct from typed vector cells and canonical output buffers.
    let controls = size_of::<serde_json::Deserializer<serde_json::de::SliceRead<'_>>>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<(), serde_json::Error>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<(), PolicyCompilerJournalErrorV1>>().checked_mul(2)?)?
        .checked_add(bytes.checked_mul(4)?)?;
    namespace
        .max(advisory)
        .max(diagnostics)
        .checked_add(canonical)?
        .checked_add(controls)?
        .checked_add(decoder_error_receiving_bytes_v1(bytes)?)
}
