//! Retains the selected Controller's fixed public TLS startup prefixes.
//!
//! Raw protected credentials and their finite bookends stay beside every
//! reached registration, PEM, key, root-store and TLS-construction result. The
//! ordinary constructor remains unchanged. No listener or authority is created
//! here, and the same Controller receiving owner pays before the first read.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, TrustAnchor};
use rustls::server::danger::ClientCertVerifier;
use tokio_rustls::TlsAcceptor;

use super::{
    PublicApiSessionAcceptor, PublicApiSessionError, certificates, credentials,
    registration, tls_configuration,
};
use super::credentials::{
    ControllerInitialCredentialCustodyV1, ControllerStartupCredentialGeometryV1,
};

/// Owns the initial public TLS native/typed prefixes until the normal handoff.
///
/// Empty construction performs no IO or allocation and proves no payment. The
/// fixed installed assembly calls this only after its actual Controller startup
/// has accepted the complete credential and parser representation demand.
#[doc(hidden)]
pub struct PublicApiSessionStartupV1 {
    native: ControllerInitialCredentialCustodyV1,
    credentials: Option<credentials::Credentials>,
    registrations: Option<Result<BTreeMap<[u8; 32], registration::Registration>, PublicApiSessionError>>,
    server_certificates: Option<Result<Vec<CertificateDer<'static>>, PublicApiSessionError>>,
    key: Option<Result<Option<PrivateKeyDer<'static>>, std::io::Error>>,
    root_certificates: Option<Result<Vec<CertificateDer<'static>>, PublicApiSessionError>>,
    pending_roots: Option<std::vec::IntoIter<CertificateDer<'static>>>,
    roots: Option<rustls::RootCertStore>,
    root_add: Option<Result<(), rustls::Error>>,
    configuration: Option<Result<(rustls::ServerConfig, Arc<dyn ClientCertVerifier>), PublicApiSessionError>>,
    preparation: Option<Result<(), PublicApiSessionError>>,
    entered: bool,
    taken: bool,
    closed: Option<PublicApiSessionError>,
    completed: Option<PublicApiSessionAcceptor>,
}

impl PublicApiSessionStartupV1 {
    /// Creates vacant fixed slots without loading a credential or binding a socket.
    #[must_use]
    pub fn new() -> Self {
        Self {
            native: ControllerInitialCredentialCustodyV1::public_tls(),
            credentials: None,
            registrations: None,
            server_certificates: None,
            key: None,
            root_certificates: None,
            pending_roots: None,
            roots: None,
            root_add: None,
            configuration: None,
            preparation: None,
            entered: false,
            taken: false,
            closed: None,
            completed: None,
        }
    }

    /// Returns passive requested raw, typed and native startup geometry.
    ///
    /// The bound covers dominant carriers and requested Vec growth rather than
    /// allocator metadata or opaque TLS-provider internals. The actual inline
    /// owner is included in the enclosing concrete parent representation.
    #[must_use]
    pub fn credential_geometry() -> Option<ControllerStartupCredentialGeometryV1> {
        const INPUT: usize = 1024 * 1024;
        let mut shape = ControllerInitialCredentialCustodyV1::public_tls_geometry()?;
        let (registrations, registration_entries) =
            registration::startup_representation_bound(INPUT)?;
        // A completed CERTIFICATE item needs at least its two PEM delimiters
        // (52 bytes even before content/newlines). Forty-eight is a conservative
        // divisor. Server/root Vecs and the owned root-anchor Vec each include
        // old/new requested allocation overlap and small nonempty Vec floors.
        let certificates = (INPUT / 48).checked_add(4)?;
        let certificate_cells = certificates.checked_mul(3)?.checked_mul(
            2 * std::mem::size_of::<CertificateDer<'static>>()
                + std::mem::size_of::<TrustAnchor<'static>>(),
        )?;
        // Server DER, private-key DER and owned root fields each remain bounded
        // by their encoded input. This conservative multiplier includes PEM
        // decoder scratch, simultaneous copies and their growth overlap.
        let encoded_models = INPUT.checked_mul(3)?.checked_mul(16)?;
        shape.memory_bytes = shape.memory_bytes.checked_add(registrations)?
            .checked_add(certificate_cells)?.checked_add(encoded_models)?;
        shape.metadata_entries = shape.metadata_entries.checked_add(registration_entries)?
            // Server certificates, root certificates and owned trust anchors
            // are three resident named certificate collections, not six
            // Rust fields per element.
            .checked_add(certificates.checked_mul(3)?)?;
        Some(shape)
    }

    /// Reports whether the prearmed destination has performed no work.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.entered && !self.taken && self.closed.is_none()
    }

    /// Captures the fixed four credentials and constructs their TLS state once.
    ///
    /// Every outer native/typed result is parked before later work. The final
    /// native bookend runs even after a typed parse or TLS-construction error.
    /// Opaque parser/library internals retain their existing consumption rules;
    /// no claim is made that they return every failed temporary to this owner.
    ///
    /// # Errors
    /// Returns the existing redacted class while [`Self::failure`] borrows the
    /// actual retained native, key-parser, root-store or semantic failure.
    pub fn capture_once(&mut self) -> Result<(), PublicApiSessionError> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert(PublicApiSessionError::Configuration);
            return Err(self.failure_class());
        }
        self.entered = true;
        if self.native.capture_once().is_ok() {
            self.preparation = Some(self.prepare());
        }
        let _ = self.native.recheck_once();
        if self.failure().is_none() && matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(self.failure_class())
        }
    }

    fn prepare(&mut self) -> Result<(), PublicApiSessionError> {
        self.credentials = self.native.public_tls_credentials();
        let bytes = self.native.bytes().ok_or(PublicApiSessionError::Configuration)?;

        self.registrations = Some(registration::decode(bytes[3]));
        if !matches!(self.registrations, Some(Ok(_))) {
            return Err(PublicApiSessionError::Configuration);
        }
        self.server_certificates = Some(certificates(bytes[0]));
        if !matches!(self.server_certificates, Some(Ok(_))) {
            return Err(PublicApiSessionError::Configuration);
        }
        let mut key_bytes = bytes[1];
        self.key = Some(rustls_pemfile::private_key(&mut key_bytes));
        if !matches!(self.key, Some(Ok(Some(_)))) {
            return Err(PublicApiSessionError::Configuration);
        }
        self.roots = Some(rustls::RootCertStore::empty());
        self.root_certificates = Some(certificates(bytes[2]));
        if !matches!(self.root_certificates, Some(Ok(_))) {
            return Err(PublicApiSessionError::Configuration);
        }

        self.pending_roots = Some(self.root_certificates.take().and_then(Result::ok)
            .ok_or(PublicApiSessionError::Configuration)?.into_iter());
        // Keep the remaining owned certificates in the same startup on a
        // failed root insertion. Only the existing add helper consumes the
        // particular certificate it was actually given.
        while let Some(certificate) = self.pending_roots.as_mut().and_then(Iterator::next) {
            let roots = self.roots.as_mut().ok_or(PublicApiSessionError::Configuration)?;
            self.root_add = Some(roots.add(certificate));
            if !matches!(self.root_add, Some(Ok(()))) {
                return Err(PublicApiSessionError::Configuration);
            }
        }
        let certificates = self.server_certificates.take().and_then(Result::ok)
            .ok_or(PublicApiSessionError::Configuration)?;
        let key = self.key.take().and_then(Result::ok).flatten()
            .ok_or(PublicApiSessionError::Configuration)?;
        let roots = self.roots.take().ok_or(PublicApiSessionError::Configuration)?;
        self.configuration = Some(tls_configuration(certificates, key, roots));
        if !matches!(self.configuration, Some(Ok(_))) {
            return Err(PublicApiSessionError::Configuration);
        }
        if self.credentials.is_none() {
            return Err(PublicApiSessionError::Configuration);
        }
        Ok(())
    }

    /// Moves the normal fixed acceptor after all local results and posts succeed.
    ///
    /// Only infallible field moves and the existing Arc/TLS adapter construction
    /// follow the complete occupancy check. No credential is reread or replaced.
    pub fn take_success(&mut self) -> Option<PublicApiSessionAcceptor> {
        if !self.entered || self.taken || self.failure().is_some()
            || !matches!(self.preparation, Some(Ok(())))
            || !matches!(self.configuration, Some(Ok(_)))
            || !matches!(self.registrations, Some(Ok(_)))
            || self.credentials.is_none()
        {
            return None;
        }
        self.taken = true;
        let (config, verifier) = self.configuration.take()?.ok()?;
        let credentials = self.credentials.take()?;
        let registrations = self.registrations.take()?.ok()?;
        self.completed = Some(PublicApiSessionAcceptor {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            verifier,
            credentials: Arc::new(credentials),
            registrations,
        });
        if self.native.settle_successful_native_once().is_err() {
            self.closed.get_or_insert(PublicApiSessionError::Configuration);
            return None;
        }
        self.completed.take()
    }

    /// Borrows the first reached failure while all native prefixes stay resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.capture_failure()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.registrations.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.server_certificates.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.key.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.root_certificates.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.root_add.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.configuration.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.preparation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.post_failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    fn failure_class(&self) -> PublicApiSessionError {
        if let Some(cause) = self.native.capture_failure() {
            return cause.legacy_projection();
        }
        if matches!(self.preparation, Some(Ok(()))) {
            if let Some(cause) = self.native.post_failure() {
                return cause.legacy_projection();
            }
        }
        PublicApiSessionError::Configuration
    }
}

impl Default for PublicApiSessionStartupV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_key_parser_failure_precedes_a_later_closed_state() {
        let mut input = b"-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----\n".as_slice();
        let parsed = rustls_pemfile::private_key(&mut input);
        assert!(parsed.is_err());

        // This exercises the actual returned parser cause, without claiming a
        // genuine protected credential capture or any Controller admission.
        let mut startup = PublicApiSessionStartupV1::new();
        startup.key = Some(parsed);
        let first = startup.key.as_ref().unwrap().as_ref().unwrap_err() as *const _;
        startup.closed = Some(PublicApiSessionError::Stale);

        let cause = startup.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(cause as *const _, first);
        assert!(matches!(startup.failure_class(), PublicApiSessionError::Configuration));
        assert!(startup.take_success().is_none());
    }
}
