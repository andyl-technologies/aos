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

use super::{
    METHOD46_INITIAL_REQUEST_BYTES_V1, Method46InitialDataErrorV1,
    Method46InitialMainCutOriginalV1, Method46InitialPurposeV1, Method46InitialRequestDataV1,
};
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
        + 2 * std::mem::size_of::<Method46InitialRequestDataV1>()
        + METHOD46_INITIAL_REQUEST_BYTES_V1
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

    /// Derives initial request DATA from this credential and the same main owner.
    ///
    /// Both genuine loans must continuously borrow the exact same startup.
    /// The provisioning profile and salt come from the retained canonical
    /// decoder, and the cut comes from the original canonical hash and native
    /// after. No profile, sequence, digest or amount enters from the caller.
    ///
    /// This supplies the exact preimage for independent approval, without
    /// establishing endpoint/key independence, Session schema, job exclusion,
    /// durable intent or physical TPM authority. Its finite return carriers
    /// were paid with this original's decode allowance before construction.
    ///
    /// # Errors
    /// Refuses an ended, failed or foreign original, a failed canonical decode
    /// or cut, or a noncanonical initial request. Equal copied origin fields
    /// cannot join different startups.
    pub fn request_for_main_original_data_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1> {
        if !self.admitted() {
            return Err(Method46InitialDataErrorV1::Encoding);
        }
        let cut = main.cut_for_provision_original_data_v1(&self.readback)?;
        let Some(Ok((profile, salt_name))) = self.decoded.as_ref() else {
            return Err(Method46InitialDataErrorV1::Encoding);
        };
        let profile_bytes = profile.encode();
        Method46InitialRequestDataV1::new(
            self.purpose_data_v1()?,
            profile.node(),
            profile_bytes[32..48]
                .try_into()
                .map_err(|_| Method46InitialDataErrorV1::Encoding)?,
            profile.stable_endpoint(),
            *salt_name,
            cut.sequence(),
            cut.head(),
        )
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

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use aos_sandbox_controller_domain::method46_initial_startup::Method46InitialStartupOriginalV1;

    use super::*;

    // This compiles the public simultaneous-borrow contract. A real installed
    // caller first completes the mutable startup admission on this same owner.
    fn request_from_originals(
        startup: &Method46InitialStartupOriginalV1,
    ) -> Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1> {
        let provision = startup
            .lend_provisioning_readback_once_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        let decoded = Method46InitialProvisionDecodeOriginalV1::decode_captured_v1(provision);
        startup
            .capture_initial_main_writer_once_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        let main_loan = startup
            .lend_initial_main_readback_once_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        let main = Method46InitialMainCutOriginalV1::hash_captured_v1(main_loan);
        decoded.request_for_main_original_data_v1(&main)
    }

    #[test]
    fn method46_initial_request_cannot_be_derived_from_an_inert_startup() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(request_from_originals(&startup).is_err());
            assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());
        }
    }
}
