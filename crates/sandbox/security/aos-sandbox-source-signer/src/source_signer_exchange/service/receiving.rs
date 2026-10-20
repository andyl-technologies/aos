//! Retains selected Source startup beside its sole genuine Native spender.
//!
//! The private key stays in this executable. Native accepts only the compiled
//! upper representation size for its fixed credential recipe, never an account,
//! caller pathname, vector, signer callback or independent allowance.

use std::error::Error;
use std::path::Path;

use aos_sandbox_source::signer::{SourceReceivingClosedV1, SourceSignerServiceOriginalV1};
use aos_sandbox_model::{AccountingError, ResourceDimension};

use crate::source_signer_credential::{SourceSignerCredentialCaptureV1, SourceSignerCredentialErrorV1};

use super::CREDENTIAL_DIRECTORY;

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Representation,
    Reservation,
    Credential,
    Post,
    PeerInputs,
    Receive,
    Finish,
    Closed,
}

/// Retains the actual Source original and the whole paid credential prefix.
pub(super) struct SourceServiceReceivingV1 {
    credentials: SourceSignerCredentialCaptureV1,
    native: Option<Result<(), SourceReceivingClosedV1>>,
    representation: Option<Result<usize, AccountingError>>,
    reservation: Option<Result<(), SourceReceivingClosedV1>>,
    credential: Option<Result<(), SourceSignerCredentialErrorV1>>,
    post: Option<Result<(), SourceReceivingClosedV1>>,
    peer_inputs: Option<Result<(), SourceReceivingClosedV1>>,
    receive: Option<Result<(), SourceReceivingClosedV1>>,
    finish: Option<Result<(), SourceReceivingClosedV1>>,
    first: Option<Failure>,
    entered: bool,
    refused: SourceSignerCredentialErrorV1,
    original: SourceSignerServiceOriginalV1,
}

impl SourceServiceReceivingV1 {
    /// Creates inert fixed storage without capturing or observing an input.
    pub(super) fn new() -> Self {
        Self {
            credentials: SourceSignerCredentialCaptureV1::new(),
            native: None,
            representation: None,
            reservation: None,
            credential: None,
            post: None,
            peer_inputs: None,
            receive: None,
            finish: None,
            first: None,
            entered: false,
            refused: SourceSignerCredentialErrorV1,
            original: SourceSignerServiceOriginalV1::new(),
        }
    }

    /// Captures the genuine original, pays, then retains the fixed credential read.
    ///
    /// # Errors
    /// Retains the earliest Native, accounting or credential failure. A reached
    /// private read always receives its independent Native post, including on
    /// failure. Reentry never recaptures an original or replaces a first cause.
    pub(super) fn capture_credentials_once(&mut self) -> Result<(), SourceSignerCredentialErrorV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Closed);
            return Err(SourceSignerCredentialErrorV1);
        }
        self.entered = true;
        self.native = Some(self.original.capture_once());
        if !matches!(self.native, Some(Ok(()))) {
            return Err(self.fail(Failure::Native));
        }
        self.representation = Some(std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<SourceSignerServiceOriginalV1>())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: ResourceDimension::MemoryBytes }));
        let resident = match self.representation.as_ref() {
            Some(Ok(resident)) => *resident,
            _ => return Err(self.fail(Failure::Representation)),
        };
        self.reservation = Some(self.original.reserve_source_credential_capture_once_v1(resident));
        if !matches!(self.reservation, Some(Ok(()))) {
            return Err(self.fail(Failure::Reservation));
        }

        self.credential = Some(self.credentials.capture_once(Path::new(CREDENTIAL_DIRECTORY)));
        if !matches!(self.credential, Some(Ok(()))) {
            self.fail(Failure::Credential);
        }
        self.post = Some(self.original.post_source_credential_capture_once_v1());
        if !matches!(self.post, Some(Ok(()))) {
            self.fail(Failure::Post);
        }
        if self.first.is_some() {
            return Err(SourceSignerCredentialErrorV1);
        }
        Ok(())
    }

    fn serve_selected(&mut self) -> ! {
        self.peer_inputs = Some(self.original.prepare_source_readonly_peer_inputs_once_v1());
        if !matches!(self.peer_inputs, Some(Ok(()))) {
            self.fail(Failure::PeerInputs);
            std::process::abort();
        }
        loop {
            self.receive = Some(self.original.receive_source_readonly_request_once_v1());
            if !matches!(self.receive, Some(Ok(()))) {
                self.fail(Failure::Receive);
                std::process::abort();
            }
            // The actual independent pin capture remains in this executable.
            // A key is borrowed only after the same resident request passed its
            // closed 14-family framing/Root/EOF admission. No key crosses for16.
            let Some((key, generation)) = self.credentials.signing_inputs() else {
                self.fail(Failure::Credential);
                std::process::abort();
            };
            self.finish = Some(self.original.finish_source_readonly_request_once_v1(key, generation));
            if !matches!(self.finish, Some(Ok(()))) {
                self.fail(Failure::Finish);
                std::process::abort();
            }
            // Native already disposed the complete positive connection and
            // view after all actual posts; these are only coarse upper Results.
            self.receive = None;
            self.finish = None;
        }
    }

    /// Borrows the first actual cause while the whole original prefix remains owned.
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            Failure::Native | Failure::Reservation | Failure::Post
            | Failure::PeerInputs | Failure::Receive | Failure::Finish => self.original.failure(),
            Failure::Representation => self.representation.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as _),
            Failure::Credential => self.credentials.failure(),
            Failure::Closed => None,
        };
        cause.or(Some(&self.refused))
    }

    fn fail(&mut self, site: Failure) -> SourceSignerCredentialErrorV1 {
        self.first.get_or_insert(site);
        SourceSignerCredentialErrorV1
    }
}

impl Drop for SourceServiceReceivingV1 {
    fn drop(&mut self) {
        // This outer fence runs before key/read fields and Native original drop.
        // Successful service startup is a resident owner, never a return token.
        if self.entered {
            std::process::abort();
        }
    }
}

// This actual installed entry has no environment/descriptor-based legacy
// fallback. Its original remains on the stack through every refusal/abort.
pub(super) fn run_selected() -> ! {
    let mut receiving = SourceServiceReceivingV1::new();
    if receiving.capture_credentials_once().is_err() {
        std::process::abort();
    }
    receiving.serve_selected()
}
