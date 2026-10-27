//! Authenticates native Distribution calls before message decoding or dispatch.
//!
//! Bearer credentials contain unpadded base64url of canonical capability-token
//! bytes. Authentication establishes identity only. Handlers must pass the
//! original token to the repository guard for each operation's current policy.
//! The native interceptor runs after the transport's bounded body read and
//! decompression; it does not protect an unbounded HTTP body reader.

use std::{fmt, num::NonZeroUsize, sync::Arc, time::SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::interceptor::{
    Next, NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, RequestContext};
use terrane_format::auth::{self, IssuerKey};

use super::status::{Outcome, ProtocolError};
use crate::store::Clock;

/// Retains authenticated token bytes for independent repository authorization.
///
/// Only the authentication boundary constructs this request extension. Its
/// presence grants no operation, root, hash, upload, or publication authority.
/// Debug output omits the credential; callers must not log its bytes.
#[derive(Clone)]
pub struct RequestToken(Arc<[u8]>);

impl RequestToken {
    /// Borrows the canonical token for the guard's fresh operation checks.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RequestToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestToken([redacted])")
    }
}

/// Verifies capability headers with store-specific public keys and a live clock.
///
/// Every call rechecks the chain, time bounds, and issuer retirement. An absent
/// header is accepted only for the exact `Capabilities` method when explicitly
/// enabled. A supplied invalid credential is always rejected, including there.
pub struct CapabilityAuthentication<C> {
    clock: C,
    keys: Vec<IssuerKey>,
    max_header_bytes: NonZeroUsize,
    anonymous_capabilities: bool,
}

impl<C: Clock> CapabilityAuthentication<C> {
    /// Selects the trusted issuer keys, credential allocation bound, and clock.
    ///
    /// The header bound includes the authentication scheme and encoded token.
    /// It is independent of transport message and HTTP header timeout limits.
    pub fn new(
        clock: C,
        keys: Vec<IssuerKey>,
        max_header_bytes: NonZeroUsize,
        anonymous_capabilities: bool,
    ) -> Self {
        Self {
            clock,
            keys,
            max_header_bytes,
            anonymous_capabilities,
        }
    }

    fn authenticate(&self, context: &mut RequestContext) -> Result<(), ConnectError> {
        // Never inherit a credential extension from an earlier authentication
        // layer: this boundary independently verifies this request's header.
        context.extensions_mut().remove::<RequestToken>();
        let mut headers = context.headers().get_all("authorization").iter();
        let Some(header) = headers.next() else {
            return if self.anonymous_capabilities
                && context.path() == Some("/terrane.v1.TierService/Capabilities")
            {
                Ok(())
            } else {
                Err(unauthenticated())
            };
        };
        if headers.next().is_some() || header.as_bytes().len() > self.max_header_bytes.get() {
            return Err(unauthenticated());
        }

        let header = header.to_str().map_err(|_| unauthenticated())?;
        let (scheme, encoded) = header.split_once(' ').ok_or_else(unauthenticated)?;
        if !scheme.eq_ignore_ascii_case("Bearer") || encoded.is_empty() {
            return Err(unauthenticated());
        }
        let token = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| unauthenticated())?;
        let now = self
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| unauthenticated())?
            .as_secs();
        auth::verify(&token, &self.keys, now).map_err(|_| unauthenticated())?;

        context
            .extensions_mut()
            .insert(RequestToken(Arc::from(token)));
        Ok(())
    }
}

fn unauthenticated() -> ConnectError {
    ProtocolError::from_outcome(Outcome::Unauthenticated, "distribution-authentication").into()
}

#[connectrpc::async_trait]
impl<C: Clock + Send + Sync + 'static> Interceptor for CapabilityAuthentication<C> {
    async fn intercept_unary(
        &self,
        mut request: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        self.authenticate(&mut request.ctx)?;
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        mut request: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.authenticate(&mut request.ctx)?;
        next.run(request, inbound).await
    }
}
