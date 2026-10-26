//! Decodes only the same Source-paid initial producer's captured public record.
//!
//! The canonical normal-owner AOSBTD01 decoder has one implementation. This
//! owner retains its actual result alongside the genuine readback loan and
//! checks role/node against that same Source. It neither adopts the resource
//! epoch as the deployment epoch nor creates a writer or physical TPM permit.

use aos_sandbox_broker::receiving::{
    Method46InitialOriginComparisonDataV1, Method46InitialServiceRoleV1,
};
use aos_sandbox_controller_domain::method46_initial_startup::{
    METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1, Method46InitialProvisionReadbackLoanV1,
    Method46InitialStartupClosedV1,
};

use super::{Method46InitialDataErrorV1, Method46InitialPurposeV1};
use crate::tpm_nv_custody::{FloorEndpointV1, FloorErrorV1, FloorProfileV1};

/// Retains the canonical decode of an original initial-job public credential.
///
/// The consumed loan was issued once, only after genuine Source prepayment and
/// native credential admission. The actual codec result remains resident even
/// on refusal. Matching role/node and canonical bytes is comparison only;
/// independent endpoint/key provenance, stopped owners, writer custody, signed
/// intent durability and authenticated physical TPM operations remain required.
#[must_use = "retain the canonical result and its actual original readback loan"]
pub struct Method46InitialProvisionDecodeOriginalV1<'owner> {
    readback: Method46InitialProvisionReadbackLoanV1<'owner>,
    origin: Option<Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1>>,
    read: Option<Result<(), Method46InitialStartupClosedV1>>,
    decoded: Option<Result<(FloorProfileV1, [u8; 34]), FloorErrorV1>>,
    node_matches: Option<bool>,
}

// The same Source pays this fixed allowance before the result owner exists.
// A future larger carrier must increase that real invoice before compilation.
const _: () = assert!(
    2 * std::mem::size_of::<Method46InitialProvisionDecodeOriginalV1<'static>>()
        <= METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1
);

impl<'owner> Method46InitialProvisionDecodeOriginalV1<'owner> {
    /// Consumes the genuine sole readback loan and parks its canonical result.
    ///
    /// This performs no IO, copies no private index auth and cannot reopen or
    /// replace a credential. Refusal fences the same startup before any effect;
    /// independently owed native posts still run on the original owner.
    pub fn decode_captured_v1(readback: Method46InitialProvisionReadbackLoanV1<'owner>) -> Self {
        let mut original = Self {
            readback,
            origin: None,
            read: None,
            decoded: None,
            node_matches: None,
        };
        original.decode();
        if !original.admitted() {
            original.readback.refuse_decode_v1();
        }
        original
    }

    fn decode(&mut self) {
        self.origin = Some(self.readback.origin_data_v1());
        let Some(Ok(origin)) = self.origin.as_ref() else {
            return;
        };
        let bytes = match self.readback.provision_bytes_v1() {
            Ok(bytes) => {
                self.read = Some(Ok(()));
                bytes
            }
            Err(error) => {
                self.read = Some(Err(error));
                return;
            }
        };
        let endpoint = match origin.role {
            Method46InitialServiceRoleV1::ControllerStorageClient => {
                FloorEndpointV1::ControllerStorageClient
            }
            Method46InitialServiceRoleV1::StorageBroker => FloorEndpointV1::StorageBroker,
        };
        self.decoded = Some(crate::recovery::decode_initial_provision_data_v1(
            &bytes, endpoint,
        ));
        self.node_matches = self
            .decoded
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|(profile, _)| profile.node() == origin.node);
    }

    fn admitted(&self) -> bool {
        matches!(self.origin, Some(Ok(_)))
            && matches!(self.read, Some(Ok(())))
            && matches!(self.decoded, Some(Ok(_)))
            && self.node_matches == Some(true)
    }

    /// Returns the compared fixed purpose as DATA while the Source is current.
    ///
    /// This does not issue approval, writer, initial-Extend or checkpoint rights.
    ///
    /// # Errors
    /// Refuses a failed canonical decode, role/node mismatch or ended Source.
    pub fn purpose_data_v1(&self) -> Result<Method46InitialPurposeV1, Method46InitialDataErrorV1> {
        if !self.admitted() {
            return Err(Method46InitialDataErrorV1::Encoding);
        }
        self.readback
            .origin_data_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        let Some(Ok((profile, _))) = self.decoded.as_ref() else {
            return Err(Method46InitialDataErrorV1::Encoding);
        };
        Ok(match profile.endpoint() {
            FloorEndpointV1::ControllerStorageClient => {
                Method46InitialPurposeV1::ControllerStorageClient
            }
            FloorEndpointV1::StorageBroker => Method46InitialPurposeV1::StorageBroker,
        })
    }
}
