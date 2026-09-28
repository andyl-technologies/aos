//! Bounded certificate-profile checks for the existing OpenSSH gate callback.
//!
//! sshd supplies its actual certificate as `%t %k`. Validation binds the
//! certificate's original identity, mandatory command, CA, lifetime, and
//! extension profile to the protected public gate claim. The claim does not
//! retain a holder key or certificate digest, so this check cannot establish
//! exact-ticket custody, current Controller authorization, or one-use I/O
//! transfer. Those remain the responsibility of the protected owners.

use aos_sandbox_core::public_attach_route::{
    PUBLIC_ATTACH_CERTIFICATE_MAXIMUM_SECONDS_V1, PUBLIC_ATTACH_CERTIFICATE_TYPE_V1,
    public_attach_certificate_key_id_v1, public_attach_force_command_v1,
    valid_public_attach_user_v1,
};
use ssh_key::{Algorithm, Certificate, HashAlg, PublicKey, certificate::CertType};

use crate::openssh_gate::OpenSshGateClaimV1;

use aos_sandbox_core::public_attach_ticket::PUBLIC_ATTACH_TICKET_MAXIMUM_CERTIFICATE_BYTES_V2 as MAXIMUM_CERTIFICATE_BYTES;

/// Checks the actual sshd certificate against the protected v1 gate profile.
///
/// The returned login is safe for the callback's single principal line. This
/// function does not contact the process bridge, read private keys, consume an
/// attach, issue credentials, or authorize a new request.
///
/// # Errors
///
/// Returns an opaque rejection for malformed or noncanonical certificates,
/// mismatched route identity, CA, command, lifetime, or extension profile.
pub fn validate_openssh_attach_certificate_v1<'a>(
    claim: &'a OpenSshGateClaimV1,
    certificate_type: &str,
    certificate_base64: &str,
    now_seconds: u64,
) -> Result<&'a str, OpenSshAttachCertificateErrorV1> {
    checked_openssh_attach_certificate_v1(
        claim,
        certificate_type,
        certificate_base64,
        now_seconds,
    )?;
    Ok(&claim.binding.user)
}

pub(crate) fn checked_openssh_attach_certificate_v1(
    claim: &OpenSshGateClaimV1,
    certificate_type: &str,
    certificate_base64: &str,
    now_seconds: u64,
) -> Result<Certificate, OpenSshAttachCertificateErrorV1> {
    let rejected = OpenSshAttachCertificateErrorV1;
    claim.validate().map_err(|_| rejected)?;
    if certificate_type != PUBLIC_ATTACH_CERTIFICATE_TYPE_V1
        || certificate_base64.is_empty()
        || certificate_type.len() + 1 + certificate_base64.len() > MAXIMUM_CERTIFICATE_BYTES
        || !certificate_base64
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        || !valid_public_attach_user_v1(&claim.binding.user)
    {
        return Err(rejected);
    }

    let encoded = format!("{certificate_type} {certificate_base64}");
    let certificate = Certificate::from_openssh(&encoded).map_err(|_| rejected)?;
    let ca =
        PublicKey::from_openssh(&claim.binding.trusted_user_ca_public_key).map_err(|_| rejected)?;
    if certificate.to_openssh().map_err(|_| rejected)? != encoded
        || certificate.algorithm() != Algorithm::Ed25519
        || certificate.cert_type() != CertType::User
        || ca.algorithm() != Algorithm::Ed25519
        || ca.to_openssh().map_err(|_| rejected)? != claim.binding.trusted_user_ca_public_key
        || certificate.signature_key() != ca.key_data()
    {
        return Err(rejected);
    }

    let binding = &claim.binding;
    let command = public_attach_force_command_v1(
        &binding.attach_operation_id,
        &binding.execution_id,
        &binding.incarnation_id,
        binding.assignment_epoch,
        &binding.principal_id,
        &binding.audit_id,
    );
    let key_id = public_attach_certificate_key_id_v1(
        &binding.attach_operation_id,
        &binding.execution_id,
        &binding.incarnation_id,
        &binding.principal_id,
        &binding.audit_id,
    );
    let expiry = u64::try_from(binding.expires_at).map_err(|_| rejected)?;
    certificate
        .valid_before()
        .checked_sub(certificate.valid_after())
        .filter(|seconds| {
            *seconds > 0 && *seconds <= u64::from(PUBLIC_ATTACH_CERTIFICATE_MAXIMUM_SECONDS_V1)
        })
        .ok_or(rejected)?;
    if certificate.valid_after() == 0
        || certificate.valid_before() > expiry
        || now_seconds >= expiry
        || certificate.key_id() != key_id
        || certificate.valid_principals() != [binding.user.as_str()]
        || certificate.critical_options().len() != 1
        || certificate.critical_options().get("force-command") != Some(&command)
    {
        return Err(rejected);
    }

    let extensions = certificate.extensions();
    let extensions_match = if claim.pty {
        extensions.len() == 1 && extensions.get("permit-pty").is_some_and(String::is_empty)
    } else {
        extensions.is_empty()
    };
    if !extensions_match {
        return Err(rejected);
    }
    certificate
        .validate_at(now_seconds, [&ca.fingerprint(HashAlg::Sha256)])
        .map_err(|_| rejected)?;

    Ok(certificate)
}

/// Reports a rejected certificate without exposing credential bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("OpenSSH attach certificate profile was rejected")]
pub struct OpenSshAttachCertificateErrorV1;

#[cfg(all(test, target_os = "linux"))]
mod qualification;

#[cfg(test)]
pub(crate) mod tests {
    use ssh_key::{PrivateKey, certificate::Builder, private::Ed25519Keypair};

    use super::*;
    use crate::openssh_gate::OpenSshGateBindingV1;

    pub(crate) fn key(seed: u8) -> PrivateKey {
        PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap()
    }

    pub(crate) fn claim() -> OpenSshGateClaimV1 {
        OpenSshGateClaimV1 {
            binding: OpenSshGateBindingV1 {
                attach_operation_id: [1; 16],
                execution_id: [2; 16],
                incarnation_id: [3; 16],
                assignment_epoch: 4,
                principal_id: [5; 16],
                audit_id: [6; 16],
                user: "aos_exec".to_owned(),
                port: 2222,
                host_public_key: key(7).public_key().to_openssh().unwrap(),
                trusted_user_ca_public_key: key(8).public_key().to_openssh().unwrap(),
                expires_at: 1300,
                gate_config_digest: [9; 32],
            },
            route_digest: [10; 32],
            runtime_identity: [11; 32],
            process_pid: 12,
            process_start_ticks: 13,
            sshd_pid: 14,
            sshd_start_ticks: 15,
            pty: true,
        }
    }

    pub(crate) fn builder(claim: &OpenSshGateClaimV1, holder: u8) -> Builder {
        let binding = &claim.binding;
        let mut builder = Builder::new(
            [16; 32],
            key(holder).public_key().key_data().clone(),
            1000,
            1300,
        )
        .unwrap();
        builder
            .key_id(public_attach_certificate_key_id_v1(
                &binding.attach_operation_id,
                &binding.execution_id,
                &binding.incarnation_id,
                &binding.principal_id,
                &binding.audit_id,
            ))
            .unwrap();
        builder.valid_principal(&binding.user).unwrap();
        builder
    }

    pub(crate) fn command(claim: &OpenSshGateClaimV1) -> String {
        let binding = &claim.binding;
        public_attach_force_command_v1(
            &binding.attach_operation_id,
            &binding.execution_id,
            &binding.incarnation_id,
            binding.assignment_epoch,
            &binding.principal_id,
            &binding.audit_id,
        )
    }

    pub(crate) fn certificate(builder: Builder, authority: u8) -> String {
        builder.sign(&key(authority)).unwrap().to_openssh().unwrap()
    }

    fn check(claim: &OpenSshGateClaimV1, encoded: &str, now: u64) -> bool {
        let (kind, base64) = encoded.split_once(' ').unwrap();
        validate_openssh_attach_certificate_v1(claim, kind, base64, now).is_ok()
    }

    fn profiled(claim: &OpenSshGateClaimV1, holder: u8) -> Builder {
        let mut builder = builder(claim, holder);
        builder
            .critical_option("force-command", command(claim))
            .unwrap();
        if claim.pty {
            builder.extension("permit-pty", "").unwrap();
        }
        builder
    }

    #[test]
    fn v2_rejects_another_same_profile_certificate_and_retained_holder_substitution() {
        use crate::openssh_ticket::{
            validate_original_ticket_certificate_v2, validate_ticket_profile_v2,
        };
        use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
        let claim = claim();
        let original = certificate(profiled(&claim, 17), 8);
        let cert = Certificate::from_openssh(&original).unwrap();
        let mut receipt = [0; 416];
        receipt[..8].copy_from_slice(b"AOSAPG01");
        receipt[8..24].copy_from_slice(&claim.binding.attach_operation_id);
        receipt[24..40].copy_from_slice(&claim.binding.execution_id);
        let ticket = PublicAttachTicketBindingV2 {
            operation_id: claim.binding.attach_operation_id,
            execution_id: claim.binding.execution_id,
            incarnation_id: claim.binding.incarnation_id,
            principal_id: claim.binding.principal_id,
            audit_id: claim.binding.audit_id,
            assignment_epoch: claim.binding.assignment_epoch,
            valid_after: cert.valid_after(),
            expires_at: cert.valid_before(),
            holder_public_key: cert.public_key().ed25519().unwrap().0,
            request_digest: [18; 32],
            decision_digest: [19; 32],
            pending_grant: receipt,
            base_route_digest: claim.route_digest,
            certificate: original.as_bytes().to_vec(),
        };
        let encoded = ticket.encode().unwrap();
        let (kind, base64) = original.split_once(' ').unwrap();
        validate_original_ticket_certificate_v2(&claim, &encoded, kind, base64, 1100).unwrap();
        let other_holder = certificate(profiled(&claim, 20), 8);
        let mut new_serial = profiled(&claim, 17);
        new_serial.serial(999).unwrap();
        for alternate in [other_holder, certificate(new_serial, 8)] {
            assert!(check(&claim, &alternate, 1100));
            let (kind, base64) = alternate.split_once(' ').unwrap();
            assert!(
                validate_original_ticket_certificate_v2(&claim, &encoded, kind, base64, 1100)
                    .is_err()
            );
        }
        let mut substituted = ticket.clone();
        substituted.holder_public_key = [21; 32];
        assert!(validate_ticket_profile_v2(&claim, &substituted, 1100).is_err());
        substituted = ticket.clone();
        substituted.base_route_digest = [22; 32];
        assert!(validate_ticket_profile_v2(&claim, &substituted, 1100).is_err());
        assert!(validate_ticket_profile_v2(&claim, &ticket, 999).is_err());
        assert!(validate_ticket_profile_v2(&claim, &ticket, 1300).is_err());
        assert_eq!(ticket.certificate, original.as_bytes());
    }

    #[test]
    fn exact_profiles_accept_pty_and_stream_without_consuming_anything() {
        let mut claim = claim();
        assert!(check(&claim, &certificate(profiled(&claim, 17), 8), 1000));

        claim.pty = false;
        assert!(check(&claim, &certificate(profiled(&claim, 17), 8), 1299));
    }

    #[test]
    fn mandatory_command_is_not_inherited_from_admin_force_command() {
        let claim = claim();
        let mut missing = builder(&claim, 17);
        missing.extension("permit-pty", "").unwrap();
        assert!(!check(&claim, &certificate(missing, 8), 1100));

        let mut wrong = builder(&claim, 17);
        wrong.critical_option("force-command", "true").unwrap();
        wrong.extension("permit-pty", "").unwrap();
        assert!(!check(&claim, &certificate(wrong, 8), 1100));
    }

    #[test]
    fn same_ca_and_login_do_not_allow_foreign_original_route_identity() {
        let claim = claim();
        for field in 0..6 {
            let mut foreign = claim.clone();
            match field {
                0 => foreign.binding.attach_operation_id = [21; 16],
                1 => foreign.binding.execution_id = [22; 16],
                2 => foreign.binding.incarnation_id = [23; 16],
                3 => foreign.binding.assignment_epoch += 1,
                4 => foreign.binding.principal_id = [24; 16],
                _ => foreign.binding.audit_id = [25; 16],
            }
            assert!(!check(
                &claim,
                &certificate(profiled(&foreign, 17), 8),
                1100
            ));
        }
    }

    #[test]
    fn unexpected_critical_options_and_extensions_are_closed() {
        let claim = claim();
        let mut critical = profiled(&claim, 17);
        critical
            .critical_option("source-address", "127.0.0.1")
            .unwrap();
        assert!(!check(&claim, &certificate(critical, 8), 1100));

        let mut extension = profiled(&claim, 17);
        extension.extension("permit-port-forwarding", "").unwrap();
        assert!(!check(&claim, &certificate(extension, 8), 1100));

        assert!(!check(&claim, &certificate(builder(&claim, 17), 8), 1100));
        let mut nonempty = builder(&claim, 17);
        nonempty
            .critical_option("force-command", command(&claim))
            .unwrap();
        nonempty.extension("permit-pty", "yes").unwrap();
        assert!(!check(&claim, &certificate(nonempty, 8), 1100));

        let mut stream = claim.clone();
        stream.pty = false;
        assert!(!check(&stream, &certificate(profiled(&claim, 17), 8), 1100));
    }

    #[test]
    fn wrong_ca_type_login_and_expired_or_future_time_are_closed() {
        let claim = claim();
        let encoded = certificate(profiled(&claim, 17), 8);
        assert!(!check(&claim, &encoded, 999));
        assert!(!check(&claim, &encoded, 1300));
        assert!(!check(&claim, &certificate(profiled(&claim, 17), 18), 1100));

        let mut host = profiled(&claim, 17);
        host.cert_type(CertType::Host).unwrap();
        assert!(!check(&claim, &certificate(host, 8), 1100));

        let mut extra_login = profiled(&claim, 17);
        extra_login.valid_principal("other").unwrap();
        assert!(!check(&claim, &certificate(extra_login, 8), 1100));

        let mut shortened = claim.clone();
        shortened.binding.expires_at = 1200;
        assert!(!check(&shortened, &encoded, 1100));
    }

    #[test]
    fn canonical_encoding_does_not_replace_signature_verification() {
        let claim = claim();
        let encoded = certificate(profiled(&claim, 17), 8);
        let mut bytes = Certificate::from_openssh(&encoded)
            .unwrap()
            .to_bytes()
            .unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = Certificate::from_bytes(&bytes)
            .unwrap()
            .to_openssh()
            .unwrap();
        assert!(!check(&claim, &tampered, 1100));
    }

    #[test]
    fn bounded_canonical_arguments_reject_comments_whitespace_and_substitution() {
        let claim = claim();
        let encoded = certificate(profiled(&claim, 17), 8);
        let (_, base64) = encoded.split_once(' ').unwrap();
        for input in [
            format!("{base64} comment"),
            format!("{base64}\n"),
            format!(" {base64}"),
            format!("{base64}="),
            "A".repeat(MAXIMUM_CERTIFICATE_BYTES),
            String::new(),
        ] {
            assert!(
                validate_openssh_attach_certificate_v1(
                    &claim,
                    PUBLIC_ATTACH_CERTIFICATE_TYPE_V1,
                    &input,
                    1100
                )
                .is_err()
            );
        }
        assert!(
            validate_openssh_attach_certificate_v1(&claim, "ssh-ed25519", base64, 1100).is_err()
        );
    }

    #[test]
    fn profile_is_not_a_missing_holder_or_exact_certificate_commitment() {
        let claim = claim();
        let first = certificate(profiled(&claim, 17), 8);
        let second = certificate(profiled(&claim, 18), 8);
        assert_ne!(first, second);
        assert!(check(&claim, &first, 1100));
        assert!(check(&claim, &second, 1100));
    }

    #[test]
    fn overlong_lifetime_and_zero_valid_after_are_closed() {
        let claim = claim();
        for (after, before) in [(999, 1300), (0, 300)] {
            let mut builder = Builder::new(
                [16; 32],
                key(17).public_key().key_data().clone(),
                after,
                before,
            )
            .unwrap();
            builder
                .key_id(public_attach_certificate_key_id_v1(
                    &claim.binding.attach_operation_id,
                    &claim.binding.execution_id,
                    &claim.binding.incarnation_id,
                    &claim.binding.principal_id,
                    &claim.binding.audit_id,
                ))
                .unwrap();
            builder.valid_principal(&claim.binding.user).unwrap();
            builder
                .critical_option("force-command", command(&claim))
                .unwrap();
            builder.extension("permit-pty", "").unwrap();
            assert!(!check(&claim, &certificate(builder, 8), after.max(1)));
        }
    }
}
