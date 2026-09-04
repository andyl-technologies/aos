//! External signer boundary for image finalization.
//!
//! The finalizer constructs complete [`SigningRequestV1`] values and supplies
//! exact input and output paths. Implementations may speak to a hardware token,
//! PKCS#11 provider, or remote signing service, but never expose private-key
//! material to this crate.

use std::path::Path;

use anyhow::Result;
use aos_release::signing::{SignatureResponseV1, SigningRequestV1};
use async_trait::async_trait;

/// Bounded transformations and detached signatures supplied by a key provider.
#[async_trait]
pub trait ImageSigner: Send + Sync {
    /// Transforms one exact input into a signed output without replacing files.
    ///
    /// The implementation must bind its response to `request`, refuse an
    /// existing `output`, enforce `maximum_output_bytes`, and durably install a
    /// single-linked regular output file. The finalizer independently verifies
    /// the resulting signature before accepting the response.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy refuses the request, input capture
    /// changes, output limits are exceeded, or response verification fails.
    async fn transform(
        &self,
        request: &SigningRequestV1,
        input: &Path,
        output: &Path,
        maximum_output_bytes: u64,
    ) -> Result<SignatureResponseV1>;

    /// Produces a detached signature over one exact regular input file.
    ///
    /// The returned response carries the detached signature in
    /// `signature_base64` and no transformed output digest. The finalizer
    /// independently verifies it using assembly-captured public material.
    ///
    /// # Errors
    ///
    /// Returns an error when provider policy refuses the request, input capture
    /// changes, or response verification fails.
    async fn sign_detached(
        &self,
        request: &SigningRequestV1,
        input: &Path,
    ) -> Result<SignatureResponseV1>;
}
