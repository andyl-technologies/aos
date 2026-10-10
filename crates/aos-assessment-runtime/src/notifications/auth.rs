//! Purpose-separated executor authentication and timestamp-bound callback signatures.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    NOTIFICATION_WORK_PATH, NotificationBodyV1, NotificationDestinationV1, NotificationWorkPlanV1,
    NotificationWorkReceiptV1,
};
use crate::validation::{decode, encoded, text};

/// Carries safe callback headers without revealing resolved destination credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CallbackSignature {
    /// Exact signature algorithm/profile discriminator.
    pub version: String,
    /// Immutable signing-key version used for receiver rotation overlap.
    pub key_version: String,
    /// Fresh physical-attempt timestamp bound into the signature.
    pub timestamp: Timestamp,
    /// Lowercase hexadecimal HMAC-SHA-256 value.
    pub signature: String,
}

impl CallbackSignature {
    /// Signs exact callback bytes and physical-attempt metadata using a resolved versioned key.
    ///
    /// # Errors
    /// Returns an error for altered body, wrong destination, weak/mismatched key or invalid work.
    pub fn sign(
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        bytes: &[u8],
        secret: &[u8],
    ) -> Result<Self> {
        plan.validate_at(&plan.issued_at)?;
        plan.require_destination(destination)?;
        ensure!(
            plan.body.to_bytes()? == bytes,
            "callback bytes differ from the pinned body"
        );
        ensure!(
            secret.len() >= 32
                && Sha256Digest::of_bytes(secret) == destination.credential_fingerprint,
            "notification signing key does not match its immutable reference"
        );
        let mut value = Self {
            version: "aos.notification-signature/hmac-sha256-v1".into(),
            key_version: destination.secret_version_reference.clone(),
            timestamp: plan.issued_at.clone(),
            signature: String::new(),
        };
        value.signature = hex::encode(
            value
                .mac(bytes, &plan.body.delivery_id, secret)?
                .finalize()
                .into_bytes(),
        );
        Ok(value)
    }

    /// Verifies timestamp freshness and exact callback bytes before a receiver acts.
    ///
    /// Receivers still deduplicate by delivery identity and original event identities.
    /// An authenticated callback conveys facts; it grants no Hub action permission.
    ///
    /// # Errors
    /// Returns an error for unknown profile/key, stale/future timestamp or invalid signature/body.
    pub fn verify(
        &self,
        bytes: &[u8],
        expected_key_version: &str,
        secret: &[u8],
        now: &Timestamp,
    ) -> Result<NotificationBodyV1> {
        ensure!(
            self.version == "aos.notification-signature/hmac-sha256-v1"
                && self.key_version == expected_key_version
                && secret.len() >= 32,
            "unsupported callback signing profile or key version"
        );
        let time = self.timestamp.unix_seconds();
        ensure!(
            time <= now.unix_seconds().saturating_add(30)
                && now.unix_seconds() <= time.saturating_add(300),
            "callback timestamp exceeds the verification window"
        );
        let body = NotificationBodyV1::from_slice(bytes)?;
        ensure!(
            body.to_bytes()? == bytes,
            "callback body is not the exact canonical disclosure contract"
        );
        let signature = decode_signature(&self.signature)?;
        self.mac(bytes, &body.delivery_id, secret)?
            .verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("callback authentication failed"))?;
        Ok(body)
    }

    fn mac(&self, body: &[u8], delivery_id: &str, secret: &[u8]) -> Result<Hmac<Sha256>> {
        ensure!(
            body.len() <= 131_072,
            "callback body exceeds the physical disclosure limit"
        );
        text(&self.key_version, 128, "callback signing-key version")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .map_err(|_| anyhow::anyhow!("invalid callback signing key"))?;
        for field in [
            b"aos-assessment-callback-v1".as_slice(),
            self.version.as_bytes(),
            self.key_version.as_bytes(),
            self.timestamp.as_str().as_bytes(),
            delivery_id.as_bytes(),
            body,
        ] {
            framed(&mut mac, field);
        }
        Ok(mac)
    }
}

/// Authenticates notification attempts independently of provider, ingress and storage work.
pub struct NotificationWorkAuth {
    secret: Zeroizing<Vec<u8>>,
    deployment: String,
    issuer: String,
    audience: String,
}

impl NotificationWorkAuth {
    /// Creates an explicitly paired notification signer with an independently installed key.
    ///
    /// # Errors
    /// Returns an error for a weak secret or malformed installed service identities.
    pub fn new(
        secret: Vec<u8>,
        deployment: String,
        issuer: String,
        audience: String,
    ) -> Result<Self> {
        ensure!(
            secret.len() >= 32,
            "notification work requires an independent strong secret"
        );
        for field in [&deployment, &issuer, &audience] {
            text(field, 128, "notification service pairing")?;
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
            deployment,
            issuer,
            audience,
        })
    }

    /// Signs one current exact attempt in the notification-plan domain.
    ///
    /// # Errors
    /// Returns an error for wrong pairing, expired work or envelope bounds.
    pub fn sign_plan(
        &self,
        plan: &NotificationWorkPlanV1,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.pairing(plan)?;
        plan.validate_at(now)?;
        let bytes = encoded(plan)?;
        let signature = hex::encode(
            self.mac(b"aos-assessment-notification-plan-v1", &bytes)?
                .finalize()
                .into_bytes(),
        );
        Ok((bytes, signature))
    }

    /// Authenticates exact bytes before decoding or resolving a destination/key.
    ///
    /// # Errors
    /// Returns an error for wrong MAC/domain, expired authority or malformed work.
    pub fn verify_plan(
        &self,
        bytes: &[u8],
        signature: &str,
        now: &Timestamp,
    ) -> Result<NotificationWorkPlanV1> {
        self.verify(b"aos-assessment-notification-plan-v1", bytes, signature)?;
        let plan = NotificationWorkPlanV1::from_slice(bytes, now)?;
        self.pairing(&plan)?;
        Ok(plan)
    }

    /// Signs compact receipt facts in the separate notification-receipt domain.
    ///
    /// # Errors
    /// Returns an error for wrong pairing, unrelated receipt or expired attempt.
    pub fn sign_receipt(
        &self,
        receipt: &NotificationWorkReceiptV1,
        plan: &NotificationWorkPlanV1,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.pairing(plan)?;
        receipt.validate_for(plan, now)?;
        let bytes = encoded(receipt)?;
        let signature = hex::encode(
            self.mac(b"aos-assessment-notification-receipt-v1", &bytes)?
                .finalize()
                .into_bytes(),
        );
        Ok((bytes, signature))
    }

    /// Verifies compact receipt bytes before current-claim admission by the coordinator.
    ///
    /// # Errors
    /// Returns an error for invalid MAC, wrong pairing, altered body or expired claim.
    pub fn verify_receipt(
        &self,
        bytes: &[u8],
        signature: &str,
        plan: &NotificationWorkPlanV1,
        now: &Timestamp,
    ) -> Result<NotificationWorkReceiptV1> {
        self.pairing(plan)?;
        self.verify(b"aos-assessment-notification-receipt-v1", bytes, signature)?;
        let receipt: NotificationWorkReceiptV1 = decode(bytes, "notification receipt")?;
        receipt.validate_for(plan, now)?;
        Ok(receipt)
    }

    fn pairing(&self, plan: &NotificationWorkPlanV1) -> Result<()> {
        ensure!(
            plan.deployment_id == self.deployment
                && plan.issuer == self.issuer
                && plan.audience == self.audience,
            "notification service pairing differs from installation"
        );
        Ok(())
    }

    fn mac(&self, domain: &[u8], body: &[u8]) -> Result<Hmac<Sha256>> {
        ensure!(
            body.len() <= 262_144,
            "notification authentication body exceeds limit"
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| anyhow::anyhow!("invalid notification work key"))?;
        for field in [
            domain,
            b"POST",
            NOTIFICATION_WORK_PATH.as_bytes(),
            self.deployment.as_bytes(),
            self.issuer.as_bytes(),
            self.audience.as_bytes(),
            body,
        ] {
            framed(&mut mac, field);
        }
        Ok(mac)
    }

    fn verify(&self, domain: &[u8], body: &[u8], signature: &str) -> Result<()> {
        let signature = decode_signature(signature)?;
        self.mac(domain, body)?
            .verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("notification work authentication failed"))?;
        Ok(())
    }
}

fn framed(mac: &mut Hmac<Sha256>, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

fn decode_signature(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid notification signature encoding"
    );
    Ok(hex::decode(value)?)
}
