//! Retains private Native acceptance at the existing publication decode boundaries.
//!
//! The sole Protocol parser returns inert complete history and recovered artifacts.
//! These fixed functions project its errors into the existing flat Native variants
//! and enclose the result at the original private scope. They do not expose a public
//! raw-history acceptance factory, authenticate signatures or select Journal state.

use super::*;

pub(super) fn decode_current(bytes: &[u8]) -> Result<CurrentAuthorityPublicationV1, AuthorityPublicationError> {
    let decoded = publication_data::decode_current(bytes).map_err(AuthorityPublicationError::from)?;
    let (history, lease, templates) = decoded.into_parts();
    Ok(CurrentAuthorityPublicationV1 {
        prepared: PreparedAuthorityPublicationV1 { history },
        lease,
        templates,
    })
}

pub(super) fn decode_prepared(bytes: &[u8], expected_digest: ObjectDigest) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
    let history = publication_data::decode_prepared(bytes, expected_digest).map_err(AuthorityPublicationError::from)?;
    Ok(PreparedAuthorityPublicationV1 { history })
}

pub(super) fn decode_prepared_with_artifacts(bytes: &[u8], expected_digest: ObjectDigest) -> Result<(PreparedAuthorityPublicationV1, publication_data::RecoveredPublicationArtifactsV1), AuthorityPublicationError> {
    let (history, artifacts) = publication_data::decode_prepared_with_artifacts(bytes, expected_digest).map_err(AuthorityPublicationError::from)?;
    Ok((PreparedAuthorityPublicationV1 { history }, artifacts))
}
