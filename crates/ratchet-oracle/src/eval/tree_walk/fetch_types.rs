//! Fetch builtin argument/result types and flake-ref attr values
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;

#[derive(Clone, Debug)]
pub(crate) struct FetchUrlArguments {
    pub(crate) url: Vec<u8>,
    pub(crate) name: String,
    pub(crate) expected_sha256: Option<NixSha256Digest>,
}

#[derive(Clone, Debug)]
pub(crate) struct FetchTarballArguments {
    pub(crate) url: Vec<u8>,
    pub(crate) name: String,
    pub(crate) expected_sha256: Option<NixSha256Digest>,
}

#[derive(Clone, Debug)]
pub(crate) struct FetchGitArguments {
    pub(crate) url: Vec<u8>,
    pub(crate) transport_url: Option<Vec<u8>>,
    pub(crate) name: String,
    pub(crate) rev: Option<Vec<u8>>,
    pub(crate) reference: Option<Vec<u8>>,
    pub(crate) submodules: bool,
    pub(crate) shallow: bool,
    pub(crate) all_refs: bool,
    pub(crate) export_ignore: bool,
    pub(crate) extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct FetchMercurialArguments {
    pub(crate) url: Vec<u8>,
    pub(crate) rev: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct GitPublicKeyEntry {
    pub(crate) keytype: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct FetchGitResult {
    pub(crate) out_path: Vec<u8>,
    pub(crate) rev: String,
    pub(crate) dirty_rev: Option<String>,
    pub(crate) dirty_short_rev: Option<String>,
    pub(crate) rev_count: usize,
    pub(crate) last_modified: i64,
    pub(crate) last_modified_date: Vec<u8>,
    pub(crate) nar_hash: Vec<u8>,
    pub(crate) submodules: bool,
}

pub(crate) type FlakeRefAttrs = BTreeMap<Vec<u8>, FlakeRefAttrValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FlakeRefAttrValue {
    String(Vec<u8>),
    Int(u64),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub(crate) enum FetchTreeArguments {
    Path {
        path: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    File {
        url: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    Tarball {
        url: Vec<u8>,
        transport_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        last_modified_from_lock: bool,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    Forge {
        canonical_uri: Vec<u8>,
        archive_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        check_archive_url_access: bool,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Vec<u8>,
    },
    Git {
        args: FetchGitArguments,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        expected_rev_count: Option<usize>,
        dirty_rev: Option<Vec<u8>>,
        dirty_short_rev: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct FetchTreeResult {
    pub(crate) out_path: Vec<u8>,
    pub(crate) nar_hash: Vec<u8>,
    pub(crate) last_modified: Option<i64>,
    pub(crate) last_modified_date: Option<Vec<u8>>,
    pub(crate) rev: Option<Vec<u8>>,
    pub(crate) dirty_rev: Option<Vec<u8>>,
    pub(crate) dirty_short_rev: Option<Vec<u8>>,
    pub(crate) rev_count: Option<usize>,
    pub(crate) submodules: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FetchTarballCompression {
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}
