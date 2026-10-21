//! Retains one strict Hello Value and its actual allocating or scalar failure.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::retained_metadata::{
    BootstrapBodyMetadataProfileData, MetadataObserver, requested_metadata_backing_storage_data,
};
use crucible_node_format::canonical;

/// Owns the parser's output and failed DATA before any terminal follow-up.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    /// Retains the independently computed row before any parser allocation.
    pub(super) row: Option<[usize; 3]>,
    profile: Option<BootstrapBodyMetadataProfileData>,
    value: Option<Value>,
    failure: Option<Failure>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Quoting,
    Quoted,
    Parsing,
    Parsed,
    Complete,
    Failed,
}

// Retain the actual owned strict reason without formatting it again. serde's
// quoted-string syntax error is fixed DATA; its original raw token stays in
// the original body and journal. No private serde ErrorImpl survives this owner.
enum Failure {
    Grammar {
        field: &'static str,
        reason: String,
    },
    Json {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    Arithmetic,
}

impl Attempt {
    /// Constructs empty physical slots without allocating or parsing.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            row: None,
            profile: None,
            value: None,
            failure: None,
        }
    }

    /// Spends this actual parser occurrence before any original-guard failure.
    ///
    /// # Errors
    /// Refuses foreign custody or a previously spent occurrence.
    pub(super) fn start_data(&mut self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Quoting;
        Ok(())
    }

    /// Retains the actual row and lexical profile before allocating a Value.
    ///
    /// # Errors
    /// Refuses foreign custody, re-entry or missing original start.
    pub(super) fn quote_data(
        &mut self,
        row: [usize; 3],
        profile: BootstrapBodyMetadataProfileData,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Quoting || self.row.is_some() || self.profile.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.profile = Some(profile);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Retains the strict parser output or its actual owned/scalar failure.
    ///
    /// # Errors
    /// Refuses incomplete admission, stale custody or malformed strict JSON.
    pub(super) fn parse_data(&mut self, raw: &[u8], nesting: usize) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.profile.is_none()
            || self.value.is_some()
            || self.failure.is_some()
        {
            return Err(refused());
        }
        self.stage = Stage::Parsing;
        match canonical::parse_json_with_depth(raw, raw.len(), nesting) {
            Ok(value) => {
                self.value = Some(value);
                self.stage = Stage::Parsed;
            }
            Err(error) => {
                self.failure = Some(match error {
                    ContractError::Invalid { field, reason } => Failure::Grammar { field, reason },
                    ContractError::Json(error) => Failure::Json {
                        category: error.classify(),
                        line: error.line(),
                        column: error.column(),
                    },
                    ContractError::Overflow => Failure::Arithmetic,
                });
                self.stage = Stage::Failed;
                return Err(refused());
            }
        }
        self.owner.ensure_current()
    }

    /// Completes parsed DATA after the enclosing original terminal checks.
    ///
    /// # Errors
    /// Refuses stale custody, incomplete parsing or retained failure.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Parsed || self.value.is_none() || self.failure.is_some() {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Permanently refuses this occurrence while retaining initialized owners.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Borrows completed parsed DATA without granting negotiation authority.
    ///
    /// # Errors
    /// Refuses stale custody or an incomplete/refused parser occurrence.
    pub(in super::super) fn value_data(&self) -> Result<&Value, ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Complete {
            return Err(refused());
        }
        self.value.as_ref().ok_or_else(refused)
    }

    /// Counts actual surviving Value and owned diagnostic backing.
    ///
    /// # Errors
    /// Refuses foreign custody, missing profiles or capacity/population overflow.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            owner,
            stage: _,
            row: _,
            profile,
            value,
            failure,
        } = self;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(value) = value {
            observer
                .with_bootstrap_body_profile_data(profile.ok_or_else(refused)?, |observer| {
                    observer.observe(value)
                })?;
        }
        let mut bytes = requested_metadata_backing_storage_data(&observer.finish())?;
        if let Some(failure) = failure {
            match failure {
                Failure::Grammar { field: _, reason } => {
                    bytes = bytes.checked_add(reason.capacity()).ok_or_else(exhausted)?
                }
                Failure::Json {
                    category: _,
                    line: _,
                    column: _,
                }
                | Failure::Arithmetic => {}
            }
        }
        Ok(bytes)
    }

    /// Reports the actual retained row for constructor-boundary controls.
    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    /// Borrows an actual retained Value after terminal refusal for custody tests.
    #[cfg(test)]
    pub(in super::super) fn value_fixture_data(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    /// Names the actual parser, failure-classification and capacity controls.
    pub(super) fn counter_scratch_data() -> usize {
        storage::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<Stage>()
            + size_of::<Failure>()
            + size_of::<Option<Failure>>()
            + size_of::<Value>()
            + size_of::<Option<Value>>()
            + size_of::<Result<Value, ContractError>>()
            + size_of::<ContractError>()
            + size_of::<serde_json::error::Category>()
            + size_of::<usize>() * 2
            + size_of::<&[u8]>()
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 4
    }
}

#[cfg(test)]
// Deliberate fixture panics expose changed strict output and error ownership.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn quoted(raw: &[u8]) -> Attempt {
        let mut attempt = Attempt::empty_data();
        attempt.start_data().unwrap();
        let (row, profile) = storage::actual_data(raw, 268435456).unwrap();
        attempt.quote_data(row, profile).unwrap();
        attempt
    }

    #[test]
    fn strict_value_and_failure_owners_survive_refusal_without_parser_retry() {
        for raw in [
            br#"{"hello":"DATA"}"#.as_slice(),
            b"{\"k\":0,\"k\":1}",
            b"\"\\uD800\"",
        ] {
            let mut attempt = quoted(raw);
            let parsed = attempt.parse_data(raw, 64);
            assert_eq!(parsed.is_ok(), raw.starts_with(b"{\"hello"));
            assert!(attempt.retained_backing_data().unwrap() <= attempt.row.unwrap()[0]);
            let before = attempt.retained_backing_data().unwrap();
            if parsed.is_ok() {
                assert_eq!(attempt.value.as_ref().unwrap()["hello"], "DATA");
            } else if let Some(Failure::Grammar { field, reason }) = &attempt.failure {
                assert_eq!(*field, "json");
                assert!(reason.contains("duplicate object key"));
                assert!(reason.capacity() > 0);
            } else if let Some(Failure::Json {
                category,
                line,
                column,
            }) = &attempt.failure
            {
                assert!(matches!(category, serde_json::error::Category::Syntax));
                assert_eq!(*line, 1);
                assert!(*column > 0);
                assert_eq!(before, 0);
            } else {
                panic!("actual strict failure must be retained");
            }
            attempt.refuse_data();
            assert!(attempt.value_data().is_err());
            assert!(attempt.parse_data(raw, 64).is_err());
            assert!(attempt.start_data().is_err());
            assert_eq!(attempt.retained_backing_data().unwrap(), before);
        }
    }

    #[test]
    fn strict_tree_scope_counts_a_real_sixty_four_container_leaf() {
        let mut raw = vec![b'['; 64];
        raw.push(b'0');
        raw.extend(std::iter::repeat_n(b']', 64));
        let mut attempt = quoted(&raw);
        attempt.parse_data(&raw, 64).unwrap();
        assert!(attempt.retained_backing_data().unwrap() <= attempt.row.unwrap()[0]);
        attempt.complete_data().unwrap();
        assert!(attempt.value_data().unwrap().is_array());
        assert!(storage::actual_data(&raw, 1).is_err());
    }

    #[test]
    fn actual_strict_rows_fit_the_same_future_lexical_population_bound() {
        for raw in [
            br#"[{}, {}, {"s":"text"}, [0,1,2]]"#.as_slice(),
            b"[",
            b"{\"k\":0,\"k\":1}",
        ] {
            let (actual, _) = storage::actual_data(raw, 268435456).unwrap();
            let future = storage::maximum_data(raw.len(), 268435456).unwrap();
            assert!(actual[0] <= future[0]);
            assert!(actual[1] <= future[1]);
            assert!(actual[2] <= future[2]);
        }
    }
}
