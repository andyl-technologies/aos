//! Quotes genuine startup service roots under the separately admitted Prepare.
//!
//! All mutable Connection authority/containment checks precede token references
//! and registrar/service loans. Numeric facts grant no input, MAC or adoption
//! right; the actual verifier retains this same opaque quote after those gates.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalNativePrepareStartupAllocation;
use crate::retained_metadata::NativeCaptureMetadataRoots;

impl OriginalNativeCaptureContext<'_> {
    pub(crate) fn quote_original_startup_restore_service_allocation(
        &self,
        connection: &mut Connection<DeadlineStream>,
        blobs: &BlobReceiver,
        startup: &OriginalNativePrepareStartupAllocation,
    ) -> Result<NativeRestoreServiceAllocationQuote, ProviderError> {
        startup.authenticate_active(connection)?;
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        connection
            .observe_original_current_connection_unique_metadata(&mut roots, &mut observer)?;
        let token = connection.original_native_owned11_admission()?;
        blobs
            .borrowed_owned11_protocol_view(&token.authority)?
            .observe_unique_capture_metadata(&mut roots, &mut observer)?;
        // These are the additional real strong edges retained by the returned
        // quote. Their actual children are already reached by Connection/service.
        roots.observe_shared_edge(
            &mut observer,
            MetadataSharedKind::NativeBoot,
            token.boot.as_ref(),
        )?;
        roots.observe_shared_edge(
            &mut observer,
            MetadataSharedKind::NativePolicy,
            token.policy.as_ref(),
        )?;
        let cut = {
            let loan = self.borrow_current_original_protocol_data(connection, blobs)?;
            loan.observe_unique_capture_metadata(&mut roots, &mut observer)?;
            loan.original_cut()
        };
        roots.finish()?;
        startup.authenticate_active(connection)?;
        let quote = NativeRestoreServiceAllocationQuote {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            boot: Rc::clone(&token.boot),
            policy: Rc::clone(&token.policy),
            cut,
            facts: observer.finish(),
        };
        quote.authenticate_original(connection, &token.boot, &token.policy)?;
        Ok(quote)
    }
}
