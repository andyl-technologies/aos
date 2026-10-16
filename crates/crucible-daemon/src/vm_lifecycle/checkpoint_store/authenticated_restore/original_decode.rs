//! Retains explicit original decode custody and unformatted first failures.
//!
//! Both decoded continuations remain opaque until their comparison finishes.
//! Owning model fields cannot escape independently of their decode account.

use std::error::Error;
use std::fmt;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody};

use super::*;

/// Retains an authenticated modeled continuation under its original account.
///
/// The only model operation is comparison with another retained continuation.
/// Native RAM and device evidence remain separate. This owner grants no restore
/// admission and exposes no clonable configuration or scheduler reference.
#[must_use = "original decoded state retains its resource custody until dropped"]
pub struct OriginalDecodedProductionExactCheckpoint {
    decoded: Option<DecodedProductionExactCheckpoint>,
    original: DecodeBudget,
    _custody: DecodeCustody,
}

impl OriginalDecodedProductionExactCheckpoint {
    /// Authenticates a supplied complete modeled configuration without exposing it.
    ///
    /// The caller retains and pays its own configuration. Full equality to the
    /// actually decoded capture precedes any use of that supplied schedule for
    /// daemon choice provenance; a matching digest alone is insufficient.
    ///
    /// # Errors
    /// Returns the exact original refusal or a complete configuration mismatch.
    pub fn authenticate_configuration(
        &self,
        configuration: &Configuration,
    ) -> Result<(), OriginalCheckpointDecodeError> {
        verify_original(&self.original)?;
        let _scope = self.original.enter();
        let decoded = self.decoded.as_ref().ok_or_else(|| {
            OriginalCheckpointDecodeError::decoded(
                &self.original,
                loop_factory_error("original checkpoint has already been closed"),
            )
        })?;
        if &decoded.checkpoint.configuration != configuration {
            return Err(OriginalCheckpointDecodeError::decoded(
                &self.original,
                loop_factory_error("supplied configuration differs from complete capture state"),
            ));
        }
        verify_original(&self.original)
    }

    /// Compares both complete modeled continuations without extracting owners.
    ///
    /// Each original is checked before comparison and before accepting a healthy
    /// result. Both complete scenario definitions authenticate their own capture.
    ///
    /// # Errors
    /// Returns the first original refusal or a modeled-source authentication
    /// error. Physical native material is not authenticated by this comparison.
    pub fn same_modeled_continuation(
        &self,
        source: &ScenarioDefForm,
        other: &Self,
        other_source: &ScenarioDefForm,
    ) -> Result<bool, OriginalCheckpointDecodeError> {
        verify_original(&self.original)?;
        verify_original(&other.original)?;
        let _scope = self.original.enter();
        let decoded = self.decoded.as_ref().ok_or_else(|| {
            OriginalCheckpointDecodeError::decoded(
                &self.original,
                loop_factory_error("original checkpoint has already been closed"),
            )
        })?;
        let other_decoded = other.decoded.as_ref().ok_or_else(|| {
            OriginalCheckpointDecodeError::decoded(
                &other.original,
                loop_factory_error("original checkpoint has already been closed"),
            )
        })?;
        let equal = decoded
            .same_modeled_continuation(source, other_decoded, other_source)
            .map_err(|error| OriginalCheckpointDecodeError::decoded(&self.original, error))?;
        verify_original(&self.original)?;
        verify_original(&other.original)?;
        Ok(equal)
    }
}

impl Drop for OriginalDecodedProductionExactCheckpoint {
    fn drop(&mut self) {
        // Internal Vec, map and Arc allocations close before either account
        // alias or its final custody can return the corresponding credit.
        drop(self.decoded.take());
    }
}

impl fmt::Debug for OriginalDecodedProductionExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginalDecodedProductionExactCheckpoint")
            .field("retained", &self.decoded.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
enum FirstFailure {
    Admission,
    Boundary,
    Source,
    Decode,
}

/// Retains exact original and boundary causes beside the decoder's diagnostic.
///
/// Causes are borrowed rather than extracted. The same account outlives every
/// retained error payload; incoming provider errors also require the provider's
/// original payload custody. No separately observable reader-close error is
/// inferred from a Drop-only reader.
#[derive(Debug)]
pub struct OriginalCheckpointDecodeError {
    first: FirstFailure,
    admission: Option<DecodeAdmissionError>,
    boundary: Option<io::Error>,
    source: Option<io::Error>,
    decode: Option<LifecycleApiError>,
    _custody: DecodeCustody,
}

impl OriginalCheckpointDecodeError {
    /// Borrows the exact admission carrier retained by the original account.
    #[must_use]
    pub fn admission_failure(&self) -> Option<&DecodeAdmissionError> {
        self.admission.as_ref()
    }

    /// Borrows the actual boundary failure before relation formatting.
    #[must_use]
    pub fn boundary_failure(&self) -> Option<&io::Error> {
        self.boundary.as_ref()
    }

    /// Borrows the actual capture object I/O failure before relation formatting.
    #[must_use]
    pub fn source_failure(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }

    /// Borrows the remaining relation or modeled decoder diagnostic.
    #[must_use]
    pub fn decode_failure(&self) -> Option<&LifecycleApiError> {
        self.decode.as_ref()
    }

    fn admitted(original: &DecodeBudget, error: DecodeAdmissionError) -> Self {
        original.record_failure(error.clone());
        Self {
            first: FirstFailure::Admission,
            admission: Some(error),
            boundary: None,
            source: None,
            decode: None,
            _custody: original.custody(),
        }
    }

    fn decoded(original: &DecodeBudget, error: LifecycleApiError) -> Self {
        match original.check() {
            Err(admission) => Self {
                decode: Some(error),
                ..Self::admitted(original, admission)
            },
            Ok(()) => Self {
                first: FirstFailure::Decode,
                admission: None,
                boundary: None,
                source: None,
                decode: Some(error),
                _custody: original.custody(),
            },
        }
    }
}

impl fmt::Display for OriginalCheckpointDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Error::source(self) {
            Some(error) => fmt::Display::fmt(error, formatter),
            None => formatter.write_str("original checkpoint decoding refused"),
        }
    }
}

impl Error for OriginalCheckpointDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            FirstFailure::Admission => Some(self.admission.as_ref()?),
            FirstFailure::Boundary => Some(self.boundary.as_ref()?),
            FirstFailure::Source => Some(self.source.as_ref()?),
            FirstFailure::Decode => Some(self.decode.as_ref()?),
        }
    }
}

fn verify_original(original: &DecodeBudget) -> Result<(), OriginalCheckpointDecodeError> {
    original
        .verify_live()
        .map_err(|error| OriginalCheckpointDecodeError::admitted(original, error))
}

struct OriginalDecodeBoundary<'a, F> {
    original: &'a DecodeBudget,
    boundary: F,
    first: Option<FirstFailure>,
    admission: Option<DecodeAdmissionError>,
    failure: Option<io::Error>,
}

impl<F: FnMut() -> io::Result<()>> OriginalDecodeBoundary<'_, F> {
    fn check(&mut self) -> io::Result<()> {
        if self.first.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Err(error) = self.original.verify_live() {
            self.original.record_failure(error.clone());
            self.admission = Some(error);
            self.first = Some(FirstFailure::Admission);
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Err(error) = (self.boundary)() {
            self.failure = Some(error);
            self.first = Some(FirstFailure::Boundary);
            return Err(io::ErrorKind::Interrupted.into());
        }
        // A callback can record a refusal while returning success. Reconcile
        // it before the caller proceeds to a read or owning allocation.
        if let Err(error) = self.original.verify_live() {
            self.original.record_failure(error.clone());
            self.admission = Some(error);
            self.first = Some(FirstFailure::Admission);
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }

    fn finish(
        mut self,
        result: Result<DecodedProductionExactCheckpoint, LifecycleApiError>,
    ) -> Result<OriginalDecodedProductionExactCheckpoint, OriginalCheckpointDecodeError> {
        // A failed decoder has already chosen a primary. Only a healthy result
        // reaches a new original liveness cut; sticky nested admission is always
        // recovered before the legacy formatting loses its typed identity.
        let admission = match &result {
            Ok(_) => self.original.verify_live().err(),
            Err(_) => self.original.check().err(),
        };
        if self.admission.is_none() {
            self.admission = admission;
        }
        if self.first.is_none() && self.admission.is_some() {
            self.first = Some(FirstFailure::Admission);
        }
        let custody = self.original.custody();
        match (self.first, result) {
            (None, Ok(decoded)) => Ok(OriginalDecodedProductionExactCheckpoint {
                decoded: Some(decoded),
                original: self.original.clone(),
                _custody: custody,
            }),
            (first, result) => {
                let decode = result.err();
                if let Some(error) = &self.admission {
                    self.original.record_failure(error.clone());
                }
                Err(OriginalCheckpointDecodeError {
                    first: first.unwrap_or(FirstFailure::Decode),
                    admission: self.admission,
                    boundary: self.failure,
                    source: None,
                    decode,
                    _custody: custody,
                })
            }
        }
    }
}

// The original is a distinct authority input to the existing seven-argument
// format operation; combining it with a byte limit would conflate payment.
/// Decodes an authenticated closure while retaining its explicit original account.
///
/// The account is installed before RAM relations, semantic readers or owned
/// parsing. An exact boundary error is retained before the existing relation
/// decoder formats its downstream diagnostic. Successful ownership remains
/// opaque through comparison and physical container destruction.
///
/// Reader descriptors and source aliases must already carry their own original
/// authority. The byte limit remains a format limit, independently of account
/// admission. This function grants no native-source or complete-memory proof.
///
/// # Errors
/// Returns an exact original refusal, boundary failure, or malformed/noncanonical
/// relation and modeled continuation, retaining distinct causes and custody.
// crucible-lint: allow rust-allow -- The explicit original is distinct from format limits and the existing relation inputs.
#[allow(clippy::too_many_arguments)]
pub fn decode_authenticated_production_exact_checkpoint_under_original(
    closure: ExactCheckpointClosureBinding,
    identity: ContentHash,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    byte_limit: u64,
    boundary: impl FnMut() -> io::Result<()>,
    sources: ProductionExactCheckpointReadSources,
    original: &DecodeBudget,
) -> Result<OriginalDecodedProductionExactCheckpoint, OriginalCheckpointDecodeError> {
    verify_original(original)?;
    let _scope = original.enter();
    let mut boundary = OriginalDecodeBoundary {
        original,
        boundary,
        first: None,
        admission: None,
        failure: None,
    };
    let result = decode_authenticated_production_exact_checkpoint(
        closure,
        identity,
        scenario,
        source,
        byte_limit,
        || boundary.check(),
        sources,
    );
    boundary.finish(result)
}

mod captured;

#[cfg(test)]
mod tests;
