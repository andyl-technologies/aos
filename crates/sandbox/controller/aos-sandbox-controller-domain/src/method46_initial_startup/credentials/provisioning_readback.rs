//! Lends the same captured public provisioning bytes to the canonical codec.
//!
//! One genuine Source prepays the bounded decode carrier before issuing its
//! sole readback loan. The loan neither extracts private index authentication
//! nor grants writer, approval, physical TPM or publication authority.

use aos_sandbox_linux::seqpacket::initial_approval::{
    INITIAL_APPROVAL_REQUEST_BYTES_V1, INITIAL_APPROVAL_SIGNATURE_BYTES_V1,
};
use std::cell::Ref;

use super::*;

/// Bounds the provisioning and selected manifest decoders and one approval verification.
///
/// Security checks its compiled retained layouts and fixed wire carriers
/// against this prepaid bound, including four mandatory and two optional
/// normal public manifests, the signature and public pin.
/// Actual credential buffers and original native observations are paid by the
/// enclosing file owner separately. This size alone authenticates no payer.
pub const METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1: usize = 32 * 1024;

/// Lists the existing normal-Root public signer members in their fixed read order.
///
/// Deployment and Project are required; Cache, Controller and Source are optional
/// only when the actual Root and initial-unit deliveries agree on their absence.
pub const METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1:
    [aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1; 5] = {
    use aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1 as Member;
    [
        Member::DeploymentKey,
        Member::ProjectKey,
        Member::CachePin,
        Member::ControllerPin,
        Member::SourcePin,
    ]
};

/// Borrows one Source-paid original public provisioning readback for decoding.
///
/// Only the actual startup owner constructs this loan after unit and credential
/// admission and the stopped owners' manifest-source comparisons. The
/// original files remain resident; all reached posts are still owed. Neither
/// this loan nor a decoded public record authorizes an effect.
#[must_use = "retain the original readback loan with its canonical decode result"]
pub struct Method46InitialProvisionReadbackLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
}

impl Method46InitialProvisionReadbackLoanV1<'_> {
    fn require_current(&self) -> Result<(), Method46InitialStartupClosedV1> {
        if self.startup.first.get().is_some() || self.startup.after_attempted.get() {
            return Err(self.startup.closed);
        }
        self.startup
            .source
            .try_borrow()
            .map_err(|_| self.startup.closed)?
            .require_current_v1()
            .map_err(|_| self.startup.closed)
    }

    pub(in crate::method46_initial_startup) fn require_same_startup_v1(
        &self,
        startup: &Method46InitialStartupOriginalV1,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        // Equal copied identity fields cannot substitute for the original payer.
        if !std::ptr::eq(self.startup, startup) {
            return Err(self.startup.closed);
        }
        self.require_current()
    }

    /// Borrows the actual public bytes while their original custody is current.
    ///
    /// This performs no IO or copying. Holding this borrow through a credential
    /// post makes that post refuse; the independent Source after remains owed.
    ///
    /// # Errors
    /// Refuses a completed/failed Source, busy owner, missing original readback
    /// or already entered post. It never replaces or reopens a credential.
    pub fn provision_bytes_v1(&self) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        self.public_bytes(0)
    }

    /// Borrows the public approval pin from the same admitted credential owner.
    ///
    /// The native capture already compared this public file with the measured
    /// startup profile. This loan exposes neither private index authentication
    /// nor a caller-selected credential. Separation from normal signing keys
    /// remains a distinct admission requirement.
    ///
    /// # Errors
    /// Refuses an ended Source, busy credential owner, missing original public
    /// readback or entered post. No credential is reopened or copied.
    pub fn approval_public_key_bytes_v1(
        &self,
    ) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        self.public_bytes(2)
    }

    /// Borrows the held public manifest selected for this normal Storage role.
    ///
    /// Issuance of this loan requires the genuine stopped-owner samples to
    /// match this credential's system source with the normal owner's actual
    /// PID1 delivery properties. This supplies public readback DATA, without
    /// authenticating a live normal endpoint or replacing its image admission.
    ///
    /// # Errors
    /// Refuses ended Source custody, busy or incomplete credential admission,
    /// missing original readback or an entered post. No file is reopened.
    pub fn normal_storage_manifest_bytes_v1(
        &self,
    ) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        self.public_bytes(3)
    }

    /// Borrows a mandatory normal endpoint's original public manifest.
    ///
    /// The stopped Controller's PID1 delivery samples must independently match
    /// each fixed public source before this loan is issued. Optional Nix and
    /// Mount FUSE manifests are outside this mandatory roster and refuse here.
    /// No normal endpoint or signing material is constructed.
    ///
    /// # Errors
    /// Refuses another protocol, ended Source custody, busy credentials, missing
    /// original readback or an entered post. No file is reopened or copied.
    pub fn normal_endpoint_manifest_bytes_v1(
        &self,
        protocol: aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
    ) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;

        let slot = match protocol {
            BrokerSessionProtocolV1::Storage => 3,
            BrokerSessionProtocolV1::Host => 4,
            BrokerSessionProtocolV1::Mount => 5,
            BrokerSessionProtocolV1::Network => 6,
            BrokerSessionProtocolV1::MountFuse | BrokerSessionProtocolV1::Nix => {
                return Err(self.startup.closed);
            }
        };
        self.public_bytes(slot)
    }

    /// Borrows a configured optional endpoint's original public manifest.
    ///
    /// Only Mount FUSE and Nix are accepted. The Source-bound initial unit and
    /// actual stopped-Controller delivery sample must agree on each optional
    /// source before this loan exists. `None` reports their compared absence,
    /// also required by the original exact credential-directory enumeration.
    /// It is not a caller-selected skip of key separation. Named and held
    /// credential posts and the second Controller sample remain owed.
    ///
    /// # Errors
    /// Refuses a mandatory protocol, an ended Source, busy or incomplete
    /// credential custody, an entered post or a missing configured readback.
    pub fn optional_normal_endpoint_manifest_bytes_v1(
        &self,
        protocol: aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;

        let slot = match protocol {
            BrokerSessionProtocolV1::MountFuse => 7,
            BrokerSessionProtocolV1::Nix => 8,
            _ => return Err(self.startup.closed),
        };
        self.optional_public_bytes(slot)
    }

    /// Borrows the normal Controller's configured ONLINE floor issuer pin.
    ///
    /// The raw public key ID and Ed25519 pin are 48 bytes. Presence is tied to
    /// the Nix endpoint in this Source's admitted unit and the actual normal
    /// Controller credential delivery. `None` requires their compared absence.
    /// This loan grants neither issuer nor floor authority; all posts stay owed.
    ///
    /// # Errors
    /// Refuses an ended or missing Source, incomplete custody, an entered post
    /// or a missing configured issuer readback.
    pub fn controller_nix_floor_issuer_bytes_v1(
        &self,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        self.optional_public_bytes(9)
    }

    /// Borrows the normal Nix owner's configured ONLINE floor issuer pin.
    ///
    /// The actual Nix owner's PID1 delivery must match this Source's captured
    /// raw48 public credential. Presence is coupled to the Controller's Nix
    /// endpoint; `None` requires its compared disabled configuration. This does
    /// not assert that an unrelated Nix unit is absent or authorize a floor.
    /// Both native configuration samples and credential posts remain owed.
    ///
    /// # Errors
    /// Refuses a missing/ended Source, incomplete original custody, an entered
    /// post or a missing configured issuer readback. No credential is reopened.
    pub fn owner_nix_floor_issuer_bytes_v1(
        &self,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        self.optional_public_bytes(15)
    }

    /// Borrows a fixed normal recipe or policy authority's public key.
    ///
    /// The original Controller or Nix-owner PID1 delivery must match this
    /// Source's captured raw32 public credential. Controller ownership and
    /// broker-plan keys are always required. Its recipe issuer and Nix-owner
    /// keys may be absent only with the compared disabled Nix endpoint. This
    /// lends no signing seed, policy authority or caller-selected file.
    ///
    /// # Errors
    /// Refuses missing/ended Source custody, incomplete original admission,
    /// an entered post or a missing configured public readback.
    pub fn normal_policy_public_key_bytes_v1(
        &self,
        owner: Method46InitialPublicPinOwnerV1,
        member: Method46InitialPublicPinMemberV1,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        self.optional_public_bytes(member.slot(owner))
    }

    /// Borrows one original public signer credential delivered to normal Root.
    ///
    /// Only the five members in [`METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1`]
    /// are accepted. A public loan requires the actual Root configuration sample
    /// to match this admitted initial unit's selected source or optional absence.
    /// No policy input, signing seed or native Root authority is exposed.
    /// All credential and Root configuration after observations remain owed.
    ///
    /// # Errors
    /// Refuses another member, a missing/ended Source, incomplete custody, an
    /// entered post or a missing configured original credential readback.
    pub fn normal_root_public_key_bytes_v1(
        &self,
        member: aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        let index = METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1
            .iter()
            .position(|expected| *expected == member)
            .ok_or(self.startup.closed)?;
        self.optional_public_bytes(10 + index)
    }

    fn optional_public_bytes(
        &self,
        slot: usize,
    ) -> Result<Option<Ref<'_, [u8]>>, Method46InitialStartupClosedV1> {
        self.require_current()?;
        let credentials = self
            .startup
            .body
            .as_ref()
            .ok_or(self.startup.closed)?
            .credentials
            .try_borrow()
            .map_err(|_| self.startup.closed)?;
        if !credentials.admitted_before_post() || !credentials.decode_loan_issued {
            return Err(self.startup.closed);
        }
        if !credentials.selected[slot] {
            return Ok(None);
        }
        drop(credentials);
        self.public_bytes(slot).map(Some)
    }

    /// Exchanges fixed public request DATA through the same original listener.
    ///
    /// This Source prepays native carriers and retained descriptor slots before
    /// accepting one child, sending the request and receiving one signature.
    /// All three stages share a sixty-second boot-time deadline. The original
    /// child is shut down, with its descriptor retained, before success returns.
    /// Source currentness is checked on both sides of the complete exchange.
    ///
    /// This does not decode the supplied request or verify the signature. The
    /// canonical Security owner independently derives its request from the same
    /// held main cut and verifies approval under the same captured public pin.
    /// No descriptor, amount, path, public key or deadline comes from the caller.
    ///
    /// # Errors
    /// Refuses ended Source custody, missing original listener admission,
    /// reentry, exhausted prepayment, deadline expiry or native exchange failure.
    /// Reached native originals and all independently owed posts stay resident.
    pub fn exchange_approval_request_data_once_v1(
        &self,
        request: [u8; INITIAL_APPROVAL_REQUEST_BYTES_V1],
    ) -> Result<[u8; INITIAL_APPROVAL_SIGNATURE_BYTES_V1], Method46InitialStartupClosedV1> {
        self.require_current()?;
        let signature = self.startup.exchange_initial_approval_data_once(request)?;
        self.require_current()
            .map_err(|_| self.startup.fail(First::ApprovalListener))?;
        Ok(signature)
    }

    // Only the fixed public accessors above select slots. The private auth
    // credential has no readback accessor across this ownership boundary.
    fn public_bytes(&self, slot: usize) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        self.require_current()?;
        let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
        let credentials = body
            .credentials
            .try_borrow()
            .map_err(|_| self.startup.closed)?;
        if !credentials.completed || credentials.post_entered || !credentials.decode_loan_issued {
            return Err(self.startup.closed);
        }
        Ref::filter_map(credentials, |credentials| {
            credentials.credentials[slot].bytes[0]
                .as_deref()
                .map(|bytes| bytes.as_slice())
        })
        .map_err(|_| self.startup.closed)
    }

    /// Copies comparison identity from this same genuine Source original.
    ///
    /// The resource-policy epoch is not the TPM deployment epoch. These fields
    /// remain comparison DATA and cannot construct another loan or payer.
    ///
    /// # Errors
    /// Refuses a failed, completed or missing original Source interval.
    pub fn origin_data_v1(
        &self,
    ) -> Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1> {
        self.require_current()?;
        self.startup.origin.ok_or(self.startup.closed)
    }

    /// Fences this same startup after a canonical provisioning decode refusal.
    ///
    /// Native credentials and decode originals stay with their owners. Fencing
    /// does not suppress their independently owed posts or heal earlier failure.
    pub fn refuse_decode_v1(&self) {
        self.startup.fail(First::Credentials);
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Prepays and lends the original public provisioning readback once.
    ///
    /// The finite codec allowance comes from this same actual Source before
    /// the Security result carrier exists. No supplied bytes, amount, purpose
    /// or descriptor can manufacture the returned loan. Private auth stays in
    /// the credential owner; independent key and protected writer admission
    /// remain separate obligations. The shared startup borrow allows this
    /// original to coexist with its same-owner main-map readback loan.
    /// The selected stopped owner's command and immutable runtime inventory
    /// must have passed their original native comparisons first.
    ///
    /// # Errors
    /// Refuses missing unit/credential, stopped-owner or normal-image admission, repeated
    /// issuance, busy native custody, an ended Source or exhausted genuine
    /// receiving allocation.
    pub fn lend_provisioning_readback_once_v1(
        &self,
    ) -> Result<Method46InitialProvisionReadbackLoanV1<'_>, Method46InitialStartupClosedV1> {
        let ready = self.body.as_ref().is_some_and(|body| {
            body.unit.initial_admitted()
                && body.unit.stopped_units_before_completed()
                && body.normal_runtime.completed()
                && body.credentials.try_borrow().is_ok_and(|credentials| {
                    credentials.completed
                        && !credentials.post_entered
                        && !credentials.decode_loan_issued
                })
        });
        if !ready {
            return Err(self.fail(First::Order));
        }
        self.source
            .try_borrow()
            .map_err(|_| self.closed)?
            .require_current_v1()
            .map_err(|_| self.closed)?;
        self.fund_additional(Some(ResourceVector::ZERO.with(
            D::MemoryBytes,
            METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1 as u64,
        )))?;
        self.body
            .as_ref()
            .ok_or(self.closed)?
            .credentials
            .try_borrow_mut()
            .map_err(|_| self.closed)?
            .decode_loan_issued = true;
        Ok(Method46InitialProvisionReadbackLoanV1 { startup: self })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn initial_provision_decode_requires_actual_credential_admission_before_funding() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));

        assert!(startup.lend_provisioning_readback_once_v1().is_err());

        let credentials = startup.body.as_ref().unwrap().credentials.borrow();
        assert!(!credentials.decode_loan_issued);
        assert!(!credentials.entered);
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
    }

    #[test]
    fn initial_provision_decode_refusal_keeps_the_source_after_owed() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        // Private test-only construction exercises failure dispatch. It has no
        // source or successful credential, and therefore cannot lend any bytes.
        let loan = Method46InitialProvisionReadbackLoanV1 { startup: &startup };
        assert!(loan.provision_bytes_v1().is_err());
        assert!(loan.approval_public_key_bytes_v1().is_err());
        assert!(loan.normal_storage_manifest_bytes_v1().is_err());
        assert!(loan.controller_nix_floor_issuer_bytes_v1().is_err());
        assert!(loan.owner_nix_floor_issuer_bytes_v1().is_err());
        for owner in [
            Method46InitialPublicPinOwnerV1::Controller,
            Method46InitialPublicPinOwnerV1::NixBroker,
        ] {
            for member in Method46InitialPublicPinMemberV1::ALL {
                assert!(
                    loan.normal_policy_public_key_bytes_v1(owner, member)
                        .is_err()
                );
            }
        }
        for member in aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1::ALL {
            assert!(loan.normal_root_public_key_bytes_v1(member).is_err());
        }
        for protocol in [
            aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::MountFuse,
            aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Nix,
        ] {
            assert!(
                loan.optional_normal_endpoint_manifest_bytes_v1(protocol)
                    .is_err()
            );
        }
        assert!(
            loan.exchange_approval_request_data_once_v1([0; INITIAL_APPROVAL_REQUEST_BYTES_V1])
                .is_err()
        );
        assert!(loan.origin_data_v1().is_err());
        loan.refuse_decode_v1();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(matches!(startup.first.get(), Some(First::Credentials)));
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
    }

    #[test]
    fn original_approval_exchange_requires_a_current_source_before_funding() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        let loan = Method46InitialProvisionReadbackLoanV1 { startup: &startup };

        assert!(
            loan.exchange_approval_request_data_once_v1([0; INITIAL_APPROVAL_REQUEST_BYTES_V1])
                .is_err()
        );

        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
    }
}
