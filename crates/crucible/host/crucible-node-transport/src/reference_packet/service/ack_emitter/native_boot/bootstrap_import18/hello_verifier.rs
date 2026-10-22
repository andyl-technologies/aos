//! Authenticates initial SDK callbacks against original Native18 field custody.
//!
//! The enclosing root must authenticate its complete immutable input graph and
//! admit all callback construction before borrowing these fields. Every callback
//! checks the actual inherited parent/UID, completed original public stream and
//! nonrenewing cut before and after inspection. Successful callbacks authorize
//! only SDK negotiation; they grant no model, ACK, policy or opaque Initial.

use super::super::measure_original_restore_controller_executable;
use super::channel_custody::BorrowedCustody;
use crate::ProviderError;
use crate::client::OriginalNativePublicBirthChannel;
use crate::handshake::{
    HelloRequest, HelloResult, ResumedOperation, TrustedHandshakeVerifier, TrustedInstallation,
};
use crate::native_hello::RetainedOriginalNativeHelloExchange;
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    NATIVE_IMPORT18_CONNECTION_ID, PacketNativeImport18HelloSelectionData,
};
use crucible_node_format::{ContentRef, Id, IdSet, ProviderManifest, SchemaRef};

type OriginalExchange = RetainedOriginalNativeHelloExchange<OriginalNativePublicBirthChannel>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Fresh,
    Authenticated,
    Selected,
    Refused,
}

/// Borrows original root fields for one initial-only SDK callback sequence.
///
/// The caller supplies the actual immutable owners after its complete original
/// guards. This view creates no descriptor, deadline, claim or installation.
pub(super) struct Verifier<'a> {
    custody: BorrowedCustody<'a>,
    launch: &'a PacketNative5SourceLaunch,
    selection: &'a PacketNativeImport18HelloSelectionData,
    request: &'a HelloRequest,
    result: &'a HelloResult,
    exchange: &'a OriginalExchange,
    cut: OperationalDeadline,
    stage: Stage,
}

impl<'a> Verifier<'a> {
    /// Borrows the same original fields without authenticating or allocating.
    ///
    /// The enclosing root separately admits measurement, complete value
    /// comparisons and callback controls before invoking the SDK. The callback
    /// identity checks below require its exact original request/result objects.
    pub(super) fn new_data(
        custody: BorrowedCustody<'a>,
        launch: &'a PacketNative5SourceLaunch,
        selection: &'a PacketNativeImport18HelloSelectionData,
        request: &'a HelloRequest,
        result: &'a HelloResult,
        exchange: &'a OriginalExchange,
        cut: OperationalDeadline,
    ) -> Self {
        Self {
            custody,
            launch,
            selection,
            request,
            result,
            exchange,
            cut,
            stage: Stage::Fresh,
        }
    }

    fn guard_data(&self) -> Result<(), ProviderError> {
        self.custody.authenticate_controller_data(self.launch)?;
        self.exchange
            .with_exchange_data(|exchange| exchange.original_stream_data().completed_data(self.cut))
    }

    fn measure_controller_data(&self) -> Result<(), ProviderError> {
        let actual = measure_original_restore_controller_executable(self.launch.controller_pid)?;
        if actual != self.launch.controller_executable {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_current(
        &self,
        connection: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        self.guard_data()?;
        let [binding] = self.launch.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        if connection.as_str() != NATIVE_IMPORT18_CONNECTION_ID
            || !std::ptr::eq(request, self.request)
            || !std::ptr::eq(result, self.result)
            || request.resume_session.is_some()
            || result.resume_token.0.is_some()
            || !result.resumed_operations.is_empty()
            || installation.session_id != binding.authority.session_id
            || installation.incarnation_id != binding.authority.incarnation_id
            || installation.measured_implementation != self.launch.selection.provider.implementation
            || installation.launch_receipt != self.launch.selection.admission_receipt
            || !same_token_data(
                &installation.admission_token,
                self.launch.admission_token.as_slice(),
            )
        {
            return Err(refused());
        }
        self.measure_controller_data()
    }

    fn select_current(
        &self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.guard_data()?;
        let [binding] = self.launch.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        // The exact definitions and original launch graph were authenticated by
        // the enclosing root. A copied manifest or a feature-name lookalike
        // cannot substitute for that same original completed result here.
        if !std::ptr::eq(manifest, &self.result.provider_identity)
            || !std::ptr::eq(features, &self.result.selected_features)
            || features != &self.selection.0
            || !schemas.is_empty()
            || guarantees != &binding.compatibility.guarantees_ref
        {
            return Err(refused());
        }
        self.measure_controller_data()
    }
}

impl TrustedHandshakeVerifier for Verifier<'_> {
    fn authenticate_exchange(
        &mut self,
        connection: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        let fresh = self.stage == Stage::Fresh;
        // Spend before any fallible check. A failed callback cannot be retried
        // against the same borrowed custody, even if the SDK returns early.
        self.stage = Stage::Refused;
        let outcome = if fresh {
            self.authenticate_current(connection, installation, request, result)
        } else {
            Err(refused())
        };
        let terminal = self.guard_data();
        outcome.and(terminal)?;
        self.stage = Stage::Authenticated;
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let authenticated = self.stage == Stage::Authenticated;
        self.stage = Stage::Refused;
        let outcome = if authenticated {
            self.select_current(manifest, features, schemas, guarantees)
        } else {
            Err(refused())
        };
        let terminal = self.guard_data();
        outcome.and(terminal)?;
        self.stage = Stage::Selected;
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        self.stage = Stage::Refused;
        let terminal = self.guard_data();
        terminal?;
        Err(refused())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        self.stage = Stage::Refused;
        let terminal = self.guard_data();
        terminal?;
        Err(refused())
    }
}

fn same_token_data(actual: &[u8; 32], original: &[u8]) -> bool {
    original.len() == actual.len()
        && actual
            .iter()
            .zip(original)
            .fold(0u8, |difference, (actual, original)| {
                difference | (actual ^ original)
            })
            == 0
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello verifier refused")
}
