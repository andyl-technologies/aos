//! Decodes only the same Source-paid initial producer's captured public record.
//!
//! The canonical normal-owner AOSBTD01 decoder has one implementation. This
//! owner retains its actual result alongside the genuine readback loan and
//! checks role/node against that same Source. It neither adopts the resource
//! epoch as the deployment epoch nor creates a writer or physical TPM permit.
//! The same owner retains the canonical public Storage manifest, compares its
//! stable identity and excludes its pins and the captured mandatory Host,
//! Mount, Network and configured optional pins from approval. Full endpoint
//! provenance, Nix floor-authority/Root key separation and durable publication remain owed
//! alongside one strict approval signature verification.

use std::cell::RefCell;

use aos_sandbox_broker::receiving::{
    Method46InitialOriginComparisonDataV1, Method46InitialServiceRoleV1,
};
use aos_sandbox_controller_domain::method46_initial_startup::{
    METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1, METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1,
    Method46InitialProvisionReadbackLoanV1, Method46InitialStartupClosedV1,
};

mod root_public;
use root_public::RootPublicKeyOriginal;

mod controller_nix_floor;
use controller_nix_floor::ControllerNixFloorIssuerOriginal;

mod approval;
use approval::ApprovalVerificationOriginal;
mod normal_manifest;
use normal_manifest::NormalManifestOriginal;
mod other_normal_manifests;
use other_normal_manifests::{OtherNormalManifestOriginal, PROTOCOLS};

use super::{
    METHOD46_INITIAL_INTENT_BYTES_V1, METHOD46_INITIAL_REQUEST_BYTES_V1,
    Method46InitialDataErrorV1, Method46InitialIntentDataV1, Method46InitialMainCutOriginalV1,
    Method46InitialPurposeV1, Method46InitialRequestDataV1,
};
use crate::tpm_nv_custody::{FloorEndpointV1, FloorErrorV1, FloorProfileV1};

/// Retains the canonical decode of an original initial-job public credential.
///
/// The consumed loan was issued once, only after genuine Source prepayment and
/// native credential admission. The actual codec result remains resident even
/// on refusal. Matching role/node and canonical bytes is comparison only;
/// complete endpoint provenance, Nix/Root key separation, continued stopped
/// owners, writer custody, signed intent durability and authenticated physical
/// TPM operations remain required.
#[must_use = "retain the canonical result and its actual original readback loan"]
pub struct Method46InitialProvisionDecodeOriginalV1<'owner> {
    readback: Method46InitialProvisionReadbackLoanV1<'owner>,
    origin: Option<Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1>>,
    read: Option<Result<(), Method46InitialStartupClosedV1>>,
    decoded: Option<Result<(FloorProfileV1, [u8; 34]), FloorErrorV1>>,
    node_matches: Option<bool>,
    approval_read: Option<Result<(), Method46InitialStartupClosedV1>>,
    approval_pin: Option<Result<[u8; 32], Method46InitialDataErrorV1>>,
    normal_read: Option<Result<(), Method46InitialStartupClosedV1>>,
    normal: NormalManifestOriginal,
    other_normal_reads: [Option<Result<(), Method46InitialStartupClosedV1>>; PROTOCOLS.len()],
    other_normal: [OtherNormalManifestOriginal; PROTOCOLS.len()],
    controller_nix_floor_read: Option<Result<(), Method46InitialStartupClosedV1>>,
    controller_nix_floor: ControllerNixFloorIssuerOriginal,
    root_public_reads: [Option<Result<(), Method46InitialStartupClosedV1>>; 5],
    root_public: [RootPublicKeyOriginal; 5],
    approval: RefCell<ApprovalVerificationOriginal>,
}

// The same Source pays this fixed allowance before the result owner exists.
// A future larger carrier must increase that real invoice before compilation.
const _: () = assert!(
    2 * std::mem::size_of::<Method46InitialProvisionDecodeOriginalV1<'static>>()
        + 2 * std::mem::size_of::<Method46InitialRequestDataV1>()
        + 2 * std::mem::size_of::<Method46InitialIntentDataV1>()
        + std::mem::size_of::<ed25519_dalek::VerifyingKey>()
        + 2 * std::mem::size_of::<
            aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1,
        >()
        + 2 * aos_sandbox_broker_session_protocol::manifest::BROKER_SESSION_MANIFEST_BYTES
        + METHOD46_INITIAL_REQUEST_BYTES_V1
        + METHOD46_INITIAL_INTENT_BYTES_V1
        + 64
        + root_public::DECODE_SCRATCH_BYTES
        <= METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1
);
const _: () = assert!(
    METHOD46_INITIAL_REQUEST_BYTES_V1
        == aos_sandbox_linux::seqpacket::initial_approval::INITIAL_APPROVAL_REQUEST_BYTES_V1
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
            approval_read: None,
            approval_pin: None,
            normal_read: None,
            normal: NormalManifestOriginal::new(),
            other_normal_reads: std::array::from_fn(|_| None),
            other_normal: std::array::from_fn(|_| OtherNormalManifestOriginal::new()),
            controller_nix_floor_read: None,
            controller_nix_floor: ControllerNixFloorIssuerOriginal::new(),
            root_public_reads: std::array::from_fn(|_| None),
            root_public: std::array::from_fn(|_| RootPublicKeyOriginal::new()),
            approval: RefCell::new(ApprovalVerificationOriginal::new()),
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
        drop(bytes);
        if self.node_matches != Some(true) {
            return;
        }

        let public = match self.readback.approval_public_key_bytes_v1() {
            Ok(public) => {
                self.approval_read = Some(Ok(()));
                public
            }
            Err(error) => {
                self.approval_read = Some(Err(error));
                return;
            }
        };
        self.approval_pin =
            Some(<[u8; 32]>::try_from(&*public).map_err(|_| Method46InitialDataErrorV1::Approval));
        drop(public);
        let Some(Ok(approval)) = self.approval_pin else {
            return;
        };
        let bytes = match self.readback.normal_storage_manifest_bytes_v1() {
            Ok(bytes) => {
                self.normal_read = Some(Ok(()));
                bytes
            }
            Err(error) => {
                self.normal_read = Some(Err(error));
                return;
            }
        };
        let Some(Ok((profile, _))) = self.decoded.as_ref() else {
            return;
        };
        self.normal
            .observe_once(&bytes, origin.role, origin.node, *profile, approval);
        drop(bytes);
        if !self.normal.admitted() {
            return;
        }

        for (index, protocol) in PROTOCOLS.into_iter().enumerate() {
            use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;

            let readback = match protocol {
                BrokerSessionProtocolV1::MountFuse | BrokerSessionProtocolV1::Nix => self
                    .readback
                    .optional_normal_endpoint_manifest_bytes_v1(protocol),
                _ => self
                    .readback
                    .normal_endpoint_manifest_bytes_v1(protocol)
                    .map(Some),
            };
            let bytes = match readback {
                Ok(bytes) => {
                    self.other_normal_reads[index] = Some(Ok(()));
                    bytes
                }
                Err(error) => {
                    self.other_normal_reads[index] = Some(Err(error));
                    return;
                }
            };
            match bytes {
                Some(bytes) => {
                    self.other_normal[index].observe_once(&bytes, protocol, origin.node, approval)
                }
                None => self.other_normal[index].observe_optional_absence_once(protocol),
            }
            if !self.other_normal[index].admitted() {
                return;
            }
        }

        let bytes = match self.readback.controller_nix_floor_issuer_bytes_v1() {
            Ok(bytes) => {
                self.controller_nix_floor_read = Some(Ok(()));
                bytes
            }
            Err(error) => {
                self.controller_nix_floor_read = Some(Err(error));
                return;
            }
        };
        self.controller_nix_floor
            .observe_once(bytes.as_deref(), approval);
        drop(bytes);
        if !self.controller_nix_floor.admitted() {
            return;
        }

        for (index, member) in METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1
            .into_iter()
            .enumerate()
        {
            let bytes = match self.readback.normal_root_public_key_bytes_v1(member) {
                Ok(bytes) => {
                    self.root_public_reads[index] = Some(Ok(()));
                    bytes
                }
                Err(error) => {
                    self.root_public_reads[index] = Some(Err(error));
                    return;
                }
            };
            self.root_public[index].observe_once(member, bytes.as_deref(), approval);
            if !self.root_public[index].admitted() {
                return;
            }
        }
    }

    fn admitted(&self) -> bool {
        matches!(self.origin, Some(Ok(_)))
            && matches!(self.read, Some(Ok(())))
            && matches!(self.decoded, Some(Ok(_)))
            && self.node_matches == Some(true)
            && matches!(self.approval_read, Some(Ok(())))
            && matches!(self.approval_pin, Some(Ok(_)))
            && matches!(self.normal_read, Some(Ok(())))
            && self.normal.admitted()
            && matches!(self.controller_nix_floor_read, Some(Ok(())))
            && self.controller_nix_floor.admitted()
            && self
                .root_public_reads
                .iter()
                .all(|read| matches!(read, Some(Ok(()))))
            && self.root_public.iter().all(RootPublicKeyOriginal::admitted)
            && self
                .other_normal_reads
                .iter()
                .all(|read| matches!(read, Some(Ok(()))))
            && self
                .other_normal
                .iter()
                .all(OtherNormalManifestOriginal::admitted)
    }

    /// Borrows the original admitted manifest only for this startup's held main.
    ///
    /// # Errors
    /// Refuses foreign or ended genuine loans and any failed credential decode.
    pub(crate) fn schema_manifest_for_main_v1(
        &self,
        main: &aos_sandbox_controller_domain::method46_initial_startup::Method46InitialMainReadbackLoanV1<'_>,
    ) -> Result<
        &aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1,
        Method46InitialDataErrorV1,
    > {
        main.require_same_provisioning_original_v1(&self.readback)
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        if !self.admitted() {
            return Err(Method46InitialDataErrorV1::Encoding);
        }
        self.normal
            .manifest()
            .ok_or(Method46InitialDataErrorV1::Encoding)
    }

    /// Copies the same admitted original's fixed endpoint role for schema DATA.
    ///
    /// # Errors
    /// Refuses foreign/ended loans or an incomplete original canonical decode.
    pub(crate) fn schema_endpoint_for_main_v1(
        &self,
        main: &aos_sandbox_controller_domain::method46_initial_startup::Method46InitialMainReadbackLoanV1<'_>,
    ) -> Result<
        aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1,
        Method46InitialDataErrorV1,
    > {
        self.schema_manifest_for_main_v1(main)?;
        match self
            .readback
            .origin_data_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?
            .role
        {
            Method46InitialServiceRoleV1::ControllerStorageClient => {
                Ok(aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client)
            }
            Method46InitialServiceRoleV1::StorageBroker => {
                Ok(aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker)
            }
        }
    }

    /// Derives initial request DATA from this credential and the same main owner.
    ///
    /// Both genuine loans must continuously borrow the exact same startup.
    /// The provisioning profile and salt come from the retained canonical
    /// decoder, and the cut comes from the original canonical hash, complete
    /// Session schema comparison and native after. No profile, sequence, digest
    /// or amount enters from the caller.
    ///
    /// This supplies the exact preimage for independent approval, without
    /// establishing complete endpoint/key independence, job exclusion,
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

    /// Exchanges and verifies approval through this startup's original listener.
    ///
    /// The exact canonical request is derived from the same held main cut, then
    /// sent through the Source-prepaid one-shot native exchange. The returned
    /// signature is verified using the captured public pin and the current
    /// same-owner request. No request, signature, key, descriptor or deadline
    /// enters from the caller. Fresh input, cold intents and this exchange share
    /// the same strict verification attempt; its native originals remain with
    /// the startup alongside the signature and canonical decode results here.
    ///
    /// This returns signed comparison DATA. Complete endpoint provenance,
    /// Nix/Root key separation, Session schema, job exclusion, durable intent
    /// and physical TPM custody remain required before publication or Extend.
    ///
    /// # Errors
    /// Refuses failed/foreign/ended originals, prior approval, busy custody,
    /// native transport failure or a strict signature/current-request mismatch.
    /// Refusal fences this startup without suppressing its independent posts.
    pub fn exchange_captured_approval_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        let result = (|| {
            let mut approval = self
                .approval
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            approval.require_fresh()?;
            let request = self.request_for_main_original_data_v1(main)?;
            let signature = self
                .readback
                .exchange_approval_request_data_once_v1(request.encode())
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            approval.verify_once(
                self.request_for_main_original_data_v1(main),
                signature,
                self.approval_pin
                    .unwrap_or(Err(Method46InitialDataErrorV1::Approval)),
            )
        })();
        if result.is_err() {
            self.readback.refuse_decode_v1();
        }
        result
    }

    /// Verifies one signature using this original's held public credential.
    ///
    /// The canonical request is derived from the same original main and the
    /// signature is checked by the sole initial-intent codec. No request, cut
    /// or public key enters from the caller. The signature, request and actual
    /// verification result remain resident, including after refusal or reentry.
    /// Their bounded carriers were paid by this original's decode allowance.
    ///
    /// This returns comparison DATA only. The delivered Storage pins have been
    /// compared, but full endpoint provenance and separation from Nix/Root keys
    /// remain required alongside job exclusion, durable intent and physical TPM
    /// custody before any publication or Extend.
    ///
    /// # Errors
    /// Refuses an ended/foreign main original, failed credential admission,
    /// invalid strict signature, repeated attempt or busy verification owner.
    /// Refusal fences this startup without suppressing its owed native posts.
    pub fn verify_captured_pin_signature_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
        signature: [u8; 64],
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        let result = (|| {
            let mut approval = self
                .approval
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            approval.verify_once(
                self.request_for_main_original_data_v1(main),
                signature,
                self.approval_pin
                    .unwrap_or(Err(Method46InitialDataErrorV1::Approval)),
            )
        })();
        if result.is_err() {
            self.readback.refuse_decode_v1();
        }
        result
    }

    /// Revalidates one encoded initial intent under the original public pin.
    ///
    /// The sole canonical decoder reverifies the signature, then compares the
    /// enclosed request with the current same-owner main cut. Fresh signatures
    /// and cold intents share one attempt; neither route can heal the other.
    /// The exact input and decoder result remain resident even when the current
    /// request differs. No public key, request or digest enters from the caller.
    ///
    /// The fixed input is comparison DATA. This does not authenticate a durable
    /// intent file or normal-key separation and grants no recovery operation.
    ///
    /// # Errors
    /// Refuses a foreign/ended original, malformed framing, invalid signature,
    /// changed current request, busy owner or repeated attempt. Refusal fences
    /// this startup while its independent native posts remain owed.
    pub fn decode_captured_pin_intent_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
        bytes: [u8; METHOD46_INITIAL_INTENT_BYTES_V1],
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        let result = (|| {
            let mut approval = self
                .approval
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            approval.decode_once(
                self.request_for_main_original_data_v1(main),
                bytes,
                self.approval_pin
                    .unwrap_or(Err(Method46InitialDataErrorV1::Approval)),
            )
        })();
        if result.is_err() {
            self.readback.refuse_decode_v1();
        }
        result
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
