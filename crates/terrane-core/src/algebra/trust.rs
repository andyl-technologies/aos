//! Binds pure trust decisions to canonical selectors and verified receipts.
//!
//! Executable contexts own provenance evaluators backed by verified immutable
//! history. Recipe decoding preserves configuration evidence without admitting
//! it as runtime authority; callers must bind it to freshly verified evaluators.
//!
//! ```text
//! trust = {1: selector, 2: evaluator-version, 3: configuration, 4: receipts}
//! configuration = [[ours-context-bytes, theirs-context-bytes], preprocessing]
//! preprocessing = null / [base-root, original-root, filtered-root, excluded-paths,
//!                         ? preserved-domain]
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{self, Decoder};
use crate::identity::Digest;
use crate::tree_format::Entry;

/// A trust-context admission or deterministic preprocessing error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustError {
    /// A selector, configuration value, or version is malformed.
    Encoding(cbor::Error),
    /// The selector does not belong to the registered selector vocabulary.
    Selector,
    /// The evaluator algorithm version is empty.
    Version,
    /// Serialized evidence has not been bound to verified immutable history.
    Unverified,
    /// Verified evaluators do not match the recipe's recorded configuration.
    Context,
    /// The deterministic preprocessing transform failed final-map validation.
    Transform(crate::tree_builder::Error),
    /// Fold preprocessing lacks verified effective ownership evidence.
    Domain(super::DomainError),
}

impl core::fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(formatter),
            Self::Selector => formatter.write_str("invalid registered trust selector"),
            Self::Version => formatter.write_str("empty trust evaluator version"),
            Self::Unverified => formatter.write_str("trust evidence requires verification"),
            Self::Context => {
                formatter.write_str("verified trust context differs from recipe evidence")
            }
            Self::Transform(error) => error.fmt(formatter),
            Self::Domain(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::Transform(error) => Some(error),
            Self::Domain(error) => Some(error),
            _ => None,
        }
    }
}

/// An owned pair of verified policy evaluators or unauthenticated recipe evidence.
#[derive(Clone, Debug)]
pub struct TrustContext {
    selector: Vec<u8>,
    evaluator_version: String,
    configuration: Vec<u8>,
    accepted: Vec<Digest>,
    any: bool,
    timestamps: Vec<(Digest, u64)>,
    evaluators: Vec<crate::provenance::TrustContext>,
    authenticated: bool,
    filter: Option<FoldFilter>,
}

#[derive(Clone, Debug)]
struct FoldFilter {
    base: Digest,
    original: Digest,
    filtered: Digest,
    excluded: Vec<Vec<u8>>,
    domain: Option<Vec<u8>>,
}

fn encode_bindings(
    evaluators: &[crate::provenance::TrustContext],
    filter: Option<&FoldFilter>,
) -> Vec<u8> {
    let mut configuration = Vec::new();
    cbor::write_array(&mut configuration, 2);
    cbor::write_array(&mut configuration, evaluators.len());
    for evaluator in evaluators {
        cbor::write_bytes(&mut configuration, evaluator.canonical_context());
    }
    if let Some(filter) = filter {
        cbor::write_array(&mut configuration, 4 + usize::from(filter.domain.is_some()));
        for root in [filter.base, filter.original, filter.filtered] {
            cbor::write_bytes(&mut configuration, &root);
        }
        cbor::write_array(&mut configuration, filter.excluded.len());
        for path in &filter.excluded {
            cbor::write_bytes(&mut configuration, path);
        }
        if let Some(domain) = &filter.domain {
            configuration.extend_from_slice(domain);
        }
    } else {
        configuration.push(0xf6);
    }
    configuration
}

impl TrustContext {
    /// Constructs the registered `any` preset without verification receipts.
    ///
    /// This placeholder is usable for policies that do not inspect trust. It
    /// cannot authorize `prefer-trusted` or `prefer-newer` without a signed view.
    pub fn any() -> Self {
        Self {
            selector: b"\x82\x66preset\x63any".to_vec(),
            evaluator_version: String::from("terrane-preset-any/v1"),
            configuration: alloc::vec![0xf6],
            accepted: Vec::new(),
            any: true,
            timestamps: Vec::new(),
            evaluators: Vec::new(),
            authenticated: false,
            filter: None,
        }
    }

    /// Admits receipts previously verified by the repository's trusted authority.
    ///
    /// Receipt identities name introducing commits accepted by this selector.
    /// This function validates canonical syntax, not signatures or authority;
    /// untrusted callers must never manufacture the supplied receipt set.
    /// Every semantic input is preserved in the operation recipe.
    ///
    /// # Errors
    /// Rejects an invalid registered selector, noncanonical configuration CBOR,
    /// or an empty evaluator algorithm version.
    #[cfg(test)]
    pub fn verified(
        selector: Vec<u8>,
        evaluator_version: String,
        configuration: Vec<u8>,
        mut accepted: Vec<Digest>,
    ) -> Result<Self, TrustError> {
        if evaluator_version.is_empty() {
            return Err(TrustError::Version);
        }
        validate_selector(&selector)?;
        validate_configuration(&configuration)?;
        accepted.sort();
        accepted.dedup();
        let any = selector == b"\x82\x66preset\x63any";
        Ok(Self {
            selector,
            evaluator_version,
            configuration,
            accepted,
            any,
            timestamps: Vec::new(),
            evaluators: Vec::new(),
            authenticated: true,
            filter: None,
        })
    }

    /// Binds verified introducing-commit timestamps for `prefer-newer`.
    ///
    /// The repository must authenticate the referenced commits before supplying
    /// these advisory timestamps. They are included in canonical recipes.
    ///
    /// # Errors
    /// Rejects duplicate commit identities with ambiguous timestamp evidence.
    #[cfg(test)]
    pub fn with_verified_timestamps(
        mut self,
        mut timestamps: Vec<(Digest, u64)>,
    ) -> Result<Self, TrustError> {
        timestamps.sort_by_key(|(identity, _)| *identity);
        if timestamps.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TrustError::Encoding(cbor::Error::NonCanonical));
        }
        self.timestamps = timestamps;
        self.authenticated = true;
        Ok(self)
    }

    /// Creates executable merge policy from authenticated provenance evaluators.
    ///
    /// Each evaluator enforces its signed view's root policies and baseline.
    /// Evaluators are supplied in `[ours, theirs]` order and are retained in that
    /// order in the recipe. Each side has exactly one authenticated policy context.
    ///
    /// # Errors
    /// Rejects anything other than two ordered evaluators.
    pub fn from_verified(
        evaluators: Vec<crate::provenance::TrustContext>,
    ) -> Result<Self, TrustError> {
        if evaluators.len() != 2 {
            return Err(TrustError::Unverified);
        }
        let configuration = encode_bindings(&evaluators, None);
        Ok(Self {
            selector: b"\x82\x66preset\x63any".to_vec(),
            evaluator_version: String::from("terrane-verified-path/v1"),
            configuration,
            accepted: Vec::new(),
            any: false,
            timestamps: Vec::new(),
            evaluators,
            authenticated: true,
            filter: None,
        })
    }

    /// Binds decoded recipe evidence to matching authenticated provenance views.
    ///
    /// # Errors
    /// Rejects absent evaluators or configurations differing from the evidence.
    pub fn bind_verified(
        self,
        evaluators: Vec<crate::provenance::TrustContext>,
    ) -> Result<Self, TrustError> {
        let verified = Self::from_verified(evaluators)?;
        self.match_evidence(verified)
    }

    fn match_evidence(self, verified: Self) -> Result<Self, TrustError> {
        if self.selector != verified.selector
            || self.evaluator_version != verified.evaluator_version
            || self.configuration != verified.configuration
            || !self.accepted.is_empty()
            || !self.timestamps.is_empty()
        {
            return Err(TrustError::Context);
        }
        Ok(verified)
    }

    /// Rebinds recipe evidence after replaying its explicit fold exclusion transform.
    ///
    /// The original incoming tree must match the uniquely bound signed side.
    /// Each excluded key is restored from `base`; the complete resulting root
    /// must equal `filtered` before its original trust context becomes executable.
    ///
    /// # Errors
    /// Rejects unordered or duplicate exclusions, source/root mismatches, invalid
    /// final maps, or any difference from the recipe's canonical evidence.
    pub fn bind_fold_verified<'a>(
        self,
        evaluators: Vec<crate::provenance::TrustContext>,
        base: &crate::tree_builder::Tree<'a>,
        original: &crate::tree_builder::Tree<'a>,
        filtered: &crate::tree_builder::Tree<'a>,
        excluded: &[Vec<u8>],
    ) -> Result<Self, TrustError> {
        let verified = Self::from_verified(evaluators)?
            .with_fold_filter(base, original, filtered, excluded, None)?;
        self.match_evidence(verified)
    }

    /// Rebinds fold evidence with the source's trusted resolved ownership.
    ///
    /// # Errors
    /// Returns the errors of [`Self::bind_fold_verified`] and missing or
    /// different effective ownership for deterministic preprocessing.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_fold_verified_with_domains<'a>(
        self,
        evaluators: Vec<crate::provenance::TrustContext>,
        base: &crate::tree_builder::Tree<'a>,
        original: &crate::tree_builder::Tree<'a>,
        filtered: &crate::tree_builder::Tree<'a>,
        excluded: &[Vec<u8>],
        domains: &'a super::OperationDomains,
    ) -> Result<Self, TrustError> {
        let verified = Self::from_verified(evaluators)?.with_fold_filter(
            base,
            original,
            filtered,
            excluded,
            Some(domains),
        )?;
        self.match_evidence(verified)
    }

    pub(super) fn with_fold_filter<'a>(
        mut self,
        base: &crate::tree_builder::Tree<'a>,
        original: &crate::tree_builder::Tree<'a>,
        filtered: &crate::tree_builder::Tree<'a>,
        excluded: &[Vec<u8>],
        domains: Option<&'a super::OperationDomains>,
    ) -> Result<Self, TrustError> {
        if excluded.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TrustError::Context);
        }
        for path in excluded {
            let validation = if original.usage() == crate::tree_format::TreeUse::Index {
                crate::tree_format::validate_index_key(path)
            } else {
                crate::tree_format::validate_key(path)
            };
            validation.map_err(TrustError::Transform)?;
        }
        if self.evaluators.is_empty() {
            return Ok(self);
        }
        if self
            .evaluators
            .get(1)
            .map(|evaluator| evaluator.view_root())
            != Some(original.root_identity())
        {
            return Err(TrustError::Context);
        }

        let edits = excluded
            .iter()
            .map(|path| (path.clone(), base.get(path).cloned()))
            .collect::<Vec<_>>();
        let replayed = original
            .edit_entries(&edits)
            .map_err(TrustError::Transform)?
            .tree;
        let ownership =
            super::domain::preserve(original, replayed, domains).map_err(|error| match error {
                super::Error::DomainContext(error) => TrustError::Domain(error),
                super::Error::Build(error) => TrustError::Transform(error),
                _ => TrustError::Context,
            })?;
        let replayed = ownership.tree;
        if replayed.root_identity() != filtered.root_identity() {
            return Err(TrustError::Context);
        }
        let domain = if original.props() != filtered.props() {
            Some(
                filtered
                    .props()
                    .into_iter()
                    .flatten()
                    .find(|property| property.name == "domain")
                    .ok_or(TrustError::Context)?
                    .value
                    .to_vec(),
            )
        } else {
            None
        };
        let filter = FoldFilter {
            base: base.root_identity(),
            original: original.root_identity(),
            filtered: filtered.root_identity(),
            excluded: excluded.to_vec(),
            domain,
        };
        self.configuration = encode_bindings(&self.evaluators, Some(&filter));
        self.filter = Some(filter);
        Ok(self)
    }

    pub(super) fn bind_inputs(&self, roots: [Digest; 3]) -> Result<(), TrustError> {
        if self.evaluators.is_empty() {
            return Ok(());
        }
        let incoming = self
            .filter
            .as_ref()
            .map_or(roots[2], |filter| filter.original);
        if self
            .evaluators
            .first()
            .map(|evaluator| evaluator.view_root())
            != Some(roots[1])
            || self
                .evaluators
                .get(1)
                .map(|evaluator| evaluator.view_root())
                != Some(incoming)
            || self
                .filter
                .as_ref()
                .is_some_and(|filter| filter.filtered != roots[2] || filter.base != roots[0])
        {
            return Err(TrustError::Context);
        }
        Ok(())
    }

    pub(super) fn authorize_policies(
        &self,
        policies: &[super::MergePolicy],
    ) -> Result<(), TrustError> {
        if !self.authenticated
            && policies.iter().any(|policy| {
                matches!(
                    policy,
                    super::MergePolicy::PreferTrusted | super::MergePolicy::PreferNewer
                )
            })
        {
            return Err(TrustError::Unverified);
        }
        Ok(())
    }

    pub(super) fn accepts_path(
        &self,
        side: usize,
        root: Digest,
        path: &[u8],
        entry: &Entry<'_>,
    ) -> bool {
        if let Some(evaluator) = self.evaluators.get(side) {
            let source = if side == 1 {
                self.filter.as_ref().map_or(root, |filter| filter.original)
            } else {
                root
            };
            return evaluator.accepts_entry(source, path, entry);
        }
        self.authenticated && self.accepts_receipt(entry)
    }

    pub(super) fn timestamp_path(
        &self,
        side: usize,
        root: Digest,
        path: &[u8],
        entry: &Entry<'_>,
    ) -> Option<u64> {
        if let Some(evaluator) = self.evaluators.get(side) {
            let source = if side == 1 {
                self.filter.as_ref().map_or(root, |filter| filter.original)
            } else {
                root
            };
            return evaluator.producer_time_entry(source, path, entry);
        }
        self.authenticated.then(|| self.timestamp(entry)).flatten()
    }

    pub(super) fn timestamp(&self, entry: &Entry<'_>) -> Option<u64> {
        let identity = entry.provenance?;
        let index = self
            .timestamps
            .binary_search_by_key(&identity, |(identity, _)| *identity)
            .ok()?;
        self.timestamps.get(index).map(|(_, timestamp)| *timestamp)
    }

    fn accepts_receipt(&self, entry: &Entry<'_>) -> bool {
        self.authenticated
            && (self.any
                || entry
                    .provenance
                    .is_some_and(|identity| self.accepted.binary_search(&identity).is_ok()))
    }

    #[cfg(test)]
    pub(super) fn accepts(&self, entry: &Entry<'_>) -> bool {
        self.accepts_receipt(entry)
    }

    /// Returns the outer canonical selector envelope.
    ///
    /// Verified contexts retain each signed side's selector in the canonical
    /// evaluator configuration; the envelope does not replace those policies.
    pub fn selector(&self) -> &[u8] {
        &self.selector
    }

    pub(super) fn decode_from<'a>(
        decoder: &mut Decoder<'a>,
        bytes: &'a [u8],
    ) -> Result<Self, TrustError> {
        let malformed = || TrustError::Encoding(cbor::Error::NonCanonical);
        let fields = decoder.map(5).map_err(TrustError::Encoding)?;
        if !matches!(fields, 4 | 5) || decoder.uint().map_err(TrustError::Encoding)? != 1 {
            return Err(malformed());
        }
        let start = bytes.len() - decoder.remaining().len();
        read_selector(decoder, bytes)?;
        let selector = bytes[start..bytes.len() - decoder.remaining().len()].to_vec();
        if decoder.uint().map_err(TrustError::Encoding)? != 2 {
            return Err(malformed());
        }
        let evaluator_version =
            String::from(decoder.text(bytes.len()).map_err(TrustError::Encoding)?);
        if evaluator_version.is_empty() {
            return Err(TrustError::Version);
        }
        if decoder.uint().map_err(TrustError::Encoding)? != 3 {
            return Err(malformed());
        }
        let start = bytes.len() - decoder.remaining().len();
        read_configuration(decoder, bytes)?;
        let configuration = bytes[start..bytes.len() - decoder.remaining().len()].to_vec();
        if decoder.uint().map_err(TrustError::Encoding)? != 4 {
            return Err(malformed());
        }
        let count = decoder.array(bytes.len()).map_err(TrustError::Encoding)?;
        let mut accepted = Vec::new();
        for _ in 0..count {
            let identity: Digest = decoder
                .bytes(32)
                .map_err(TrustError::Encoding)?
                .try_into()
                .map_err(|_| malformed())?;
            if accepted
                .last()
                .is_some_and(|previous| *previous >= identity)
            {
                return Err(malformed());
            }
            accepted.push(identity);
        }
        let mut timestamps = Vec::new();
        if fields == 5 {
            if decoder.uint().map_err(TrustError::Encoding)? != 5 {
                return Err(malformed());
            }
            let count = decoder.array(bytes.len()).map_err(TrustError::Encoding)?;
            if count == 0 {
                return Err(malformed());
            }
            for _ in 0..count {
                if decoder.array(2).map_err(TrustError::Encoding)? != 2 {
                    return Err(malformed());
                }
                let identity: Digest = decoder
                    .bytes(32)
                    .map_err(TrustError::Encoding)?
                    .try_into()
                    .map_err(|_| malformed())?;
                let timestamp = decoder.uint().map_err(TrustError::Encoding)?;
                if timestamps
                    .last()
                    .is_some_and(|(previous, _)| *previous >= identity)
                {
                    return Err(malformed());
                }
                timestamps.push((identity, timestamp));
            }
        }
        let any = selector == b"\x82\x66preset\x63any";
        Ok(Self {
            selector,
            evaluator_version,
            configuration,
            accepted,
            any,
            timestamps,
            evaluators: Vec::new(),
            authenticated: false,
            filter: None,
        })
    }

    pub(super) fn encode(&self, output: &mut Vec<u8>) {
        cbor::write_map(output, 4 + usize::from(!self.timestamps.is_empty()));
        cbor::write_uint(output, 1);
        output.extend_from_slice(&self.selector);
        cbor::write_uint(output, 2);
        cbor::write_text(output, &self.evaluator_version);
        cbor::write_uint(output, 3);
        output.extend_from_slice(&self.configuration);
        cbor::write_uint(output, 4);
        cbor::write_array(output, self.accepted.len());
        for identity in &self.accepted {
            cbor::write_bytes(output, identity);
        }
        if !self.timestamps.is_empty() {
            cbor::write_uint(output, 5);
            cbor::write_array(output, self.timestamps.len());
            for (identity, timestamp) in &self.timestamps {
                cbor::write_array(output, 2);
                cbor::write_bytes(output, identity);
                cbor::write_uint(output, *timestamp);
            }
        }
    }
}

impl PartialEq for TrustContext {
    fn eq(&self, other: &Self) -> bool {
        self.selector == other.selector
            && self.evaluator_version == other.evaluator_version
            && self.configuration == other.configuration
            && self.accepted == other.accepted
            && self.timestamps == other.timestamps
            && self.authenticated == other.authenticated
    }
}

impl Eq for TrustContext {}

#[cfg(test)]
fn validate_selector(bytes: &[u8]) -> Result<(), TrustError> {
    let mut decoder = Decoder::new(bytes);
    read_selector(&mut decoder, bytes)?;
    decoder.finish().map_err(TrustError::Encoding)
}

fn read_selector(decoder: &mut Decoder<'_>, bytes: &[u8]) -> Result<(), TrustError> {
    let mut pending = 1usize;
    while pending != 0 {
        pending -= 1;
        let length = decoder.array(bytes.len()).map_err(TrustError::Encoding)?;
        let tag = decoder.text(bytes.len()).map_err(TrustError::Encoding)?;
        let children = match tag {
            "issuer" | "subject" | "group" | "source" | "signed-by-key" | "attested"
                if length == 2 =>
            {
                decoder.text(bytes.len()).map_err(TrustError::Encoding)?;
                0
            }
            "kind" if length == 2 => {
                if !matches!(
                    decoder.text(bytes.len()).map_err(TrustError::Encoding)?,
                    "human" | "workload" | "service"
                ) {
                    return Err(TrustError::Selector);
                }
                0
            }
            "preset" if length == 2 => {
                if !matches!(
                    decoder.text(bytes.len()).map_err(TrustError::Encoding)?,
                    "any" | "signed-baseline" | "strict" | "attested"
                ) {
                    return Err(TrustError::Selector);
                }
                0
            }
            "accepted-by" | "not" if length == 2 => 1,
            "attr-by" if length == 3 => {
                let name = decoder.text(255).map_err(TrustError::Encoding)?;
                if !crate::properties::registered_attribute(name) {
                    return Err(TrustError::Selector);
                }
                1
            }
            "all" | "any" if length == 2 => {
                let count = decoder.array(bytes.len()).map_err(TrustError::Encoding)?;
                if count == 0 {
                    return Err(TrustError::Selector);
                }
                count
            }
            _ => return Err(TrustError::Selector),
        };
        pending = pending
            .checked_add(children)
            .filter(|count| *count <= bytes.len())
            .ok_or(TrustError::Selector)?;
    }
    Ok(())
}

#[cfg(test)]
fn validate_configuration(bytes: &[u8]) -> Result<(), TrustError> {
    let mut decoder = Decoder::new(bytes);
    read_configuration(&mut decoder, bytes)?;
    decoder.finish().map_err(TrustError::Encoding)
}

fn read_configuration<'a>(decoder: &mut Decoder<'a>, bytes: &'a [u8]) -> Result<(), TrustError> {
    struct Frame<'a> {
        remaining: usize,
        map: bool,
        key: bool,
        previous: Option<&'a [u8]>,
    }
    let mut frames = alloc::vec![Frame {
        remaining: 1,
        map: false,
        key: false,
        previous: None
    }];
    while let Some(frame) = frames.last_mut() {
        if frame.remaining == 0 {
            frames.pop();
            continue;
        }
        frame.remaining -= 1;
        if frame.map && frame.key {
            let start = bytes.len() - decoder.remaining().len();
            match decoder.peek_major().map_err(TrustError::Encoding)? {
                0 => {
                    decoder.uint().map_err(TrustError::Encoding)?;
                }
                2 => {
                    decoder.bytes(bytes.len()).map_err(TrustError::Encoding)?;
                }
                3 => {
                    decoder.text(bytes.len()).map_err(TrustError::Encoding)?;
                }
                _ => return Err(TrustError::Encoding(cbor::Error::Unsupported)),
            }
            let end = bytes.len() - decoder.remaining().len();
            let key = &bytes[start..end];
            if frame.previous.is_some_and(|previous| key <= previous) {
                return Err(TrustError::Encoding(cbor::Error::NonCanonical));
            }
            frame.previous = Some(key);
            frame.key = false;
            continue;
        }
        if frame.map {
            frame.key = true;
        }
        match decoder.peek_major().map_err(TrustError::Encoding)? {
            0 => {
                decoder.uint().map_err(TrustError::Encoding)?;
            }
            1 => {
                decoder.negative_argument().map_err(TrustError::Encoding)?;
            }
            2 => {
                decoder.bytes(bytes.len()).map_err(TrustError::Encoding)?;
            }
            3 => {
                decoder.text(bytes.len()).map_err(TrustError::Encoding)?;
            }
            4 => {
                let count = decoder.array(bytes.len()).map_err(TrustError::Encoding)?;
                frames.push(Frame {
                    remaining: count,
                    map: false,
                    key: false,
                    previous: None,
                });
            }
            5 => {
                let count = decoder.map(bytes.len()).map_err(TrustError::Encoding)?;
                let remaining = count
                    .checked_mul(2)
                    .ok_or(TrustError::Encoding(cbor::Error::Limit))?;
                frames.push(Frame {
                    remaining,
                    map: true,
                    key: true,
                    previous: None,
                });
            }
            7 => {
                decoder.simple().map_err(TrustError::Encoding)?;
            }
            _ => return Err(TrustError::Encoding(cbor::Error::Unsupported)),
        }
    }
    Ok(())
}
