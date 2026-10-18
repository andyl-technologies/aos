//! Structured deployment-wide instance-settings sections.

use serde::{Deserialize, Serialize};

use super::iam::validate_dns_name;
use super::primitives::{Actor, ControlError, Generation, Revision, StableId};

/// The independently reviewed instance-settings sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceSettingsSection {
    /// Signup, session, and authentication policy.
    IdentityAndSignup,
    /// Defaults inherited by newly created resources.
    ResourceDefaults,
    /// Product name, support, and legal presentation.
    Branding,
}

impl InstanceSettingsSection {
    /// Returns the singleton stable identity for this section.
    ///
    /// # Errors
    ///
    /// Returns an identity validation error only if a compile-time identity is
    /// changed to an invalid value.
    pub fn stable_id(self) -> Result<StableId, ControlError> {
        StableId::new(match self {
            Self::IdentityAndSignup => "instance-settings:identity-and-signup",
            Self::ResourceDefaults => "instance-settings:resource-defaults",
            Self::Branding => "instance-settings:branding",
        })
    }
}

/// Whether unaffiliated users may create an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupPolicy {
    /// Any authenticated email may create an account.
    Open,
    /// Account creation requires an invitation.
    InvitationOnly,
}

/// Immutable identity-and-signup settings contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityAndSignupSettings {
    /// Instance signup policy.
    pub signup_policy: SignupPolicy,
    /// Canonically sorted lowercase domains allowed for signup.
    pub allowed_signup_domains: Vec<String>,
    /// Maximum session lifetime in seconds.
    pub session_lifetime_secs: u64,
    /// Whether password authentication is enabled.
    pub password_authentication: bool,
}

impl IdentityAndSignupSettings {
    /// Validates canonical identity-and-signup settings.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an out-of-range session lifetime
    /// or non-canonical, duplicate, or malformed domains.
    pub fn validate(&self) -> Result<(), ControlError> {
        if !(300..=30 * 24 * 60 * 60).contains(&self.session_lifetime_secs) {
            return Err(invalid(
                "session_lifetime_secs",
                "must be between five minutes and thirty days",
            ));
        }
        validate_domains(&self.allowed_signup_domains)
    }
}

/// Supported default cache compression policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultCompression {
    /// Zstandard compression.
    Zstd,
    /// XZ compression.
    Xz,
    /// No compression.
    None,
}

/// Immutable defaults inherited by newly created Hub resources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceDefaultsSettings {
    /// Whether new registries are public by default.
    pub registries_public: bool,
    /// Whether new binary caches are public by default.
    pub binary_caches_public: bool,
    /// Default Nix substituter priority.
    pub nix_priority: u32,
    /// Default binary-cache compression.
    pub compression: DefaultCompression,
    /// Whether new binary caches answer mass queries.
    pub want_mass_query: bool,
}

impl ResourceDefaultsSettings {
    /// Validates resource defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the Nix priority exceeds the
    /// bounded control-plane representation.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.nix_priority > 10_000 {
            return Err(invalid("nix_priority", "must not exceed 10000"));
        }
        Ok(())
    }
}

/// Immutable instance branding and support links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BrandingSettings {
    /// Product name displayed in the shell.
    pub product_name: String,
    /// Optional absolute HTTPS logo URL.
    pub logo_url: Option<String>,
    /// Optional absolute HTTPS support URL.
    pub support_url: Option<String>,
    /// Optional absolute HTTPS terms URL.
    pub terms_url: Option<String>,
    /// Optional absolute HTTPS privacy URL.
    pub privacy_url: Option<String>,
}

impl BrandingSettings {
    /// Validates branding text and links.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an empty/oversized name or a link
    /// that is not an absolute HTTPS URL without embedded credentials.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.product_name.trim().is_empty() || self.product_name.len() > 80 {
            return Err(invalid(
                "product_name",
                "must contain 1-80 non-whitespace bytes",
            ));
        }
        for (field, value) in [
            ("logo_url", self.logo_url.as_deref()),
            ("support_url", self.support_url.as_deref()),
            ("terms_url", self.terms_url.as_deref()),
            ("privacy_url", self.privacy_url.as_deref()),
        ] {
            if let Some(value) = value {
                let url = url::Url::parse(value).map_err(|_| invalid(field, "must be an URL"))?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return Err(invalid(
                        field,
                        "must be an absolute HTTPS URL without credentials",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The typed immutable contents of one instance-settings revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "section", content = "settings", rename_all = "snake_case")]
pub enum InstanceSettingsContents {
    /// Identity-and-signup settings.
    IdentityAndSignup(IdentityAndSignupSettings),
    /// Resource defaults.
    ResourceDefaults(ResourceDefaultsSettings),
    /// Branding settings.
    Branding(BrandingSettings),
}

impl InstanceSettingsContents {
    /// Returns the section owned by these contents.
    #[must_use]
    pub fn section(&self) -> InstanceSettingsSection {
        match self {
            Self::IdentityAndSignup(_) => InstanceSettingsSection::IdentityAndSignup,
            Self::ResourceDefaults(_) => InstanceSettingsSection::ResourceDefaults,
            Self::Branding(_) => InstanceSettingsSection::Branding,
        }
    }

    /// Validates section-specific invariants.
    ///
    /// # Errors
    ///
    /// Returns the validation error produced by the selected settings section.
    pub fn validate(&self) -> Result<(), ControlError> {
        match self {
            Self::IdentityAndSignup(settings) => settings.validate(),
            Self::ResourceDefaults(settings) => settings.validate(),
            Self::Branding(settings) => settings.validate(),
        }
    }
}

/// Creates one immutable instance-settings revision under its singleton id.
///
/// # Errors
///
/// Returns a settings validation, identity, or canonical serialization error.
pub fn new_revision(
    generation: Generation,
    contents: InstanceSettingsContents,
    actor: Actor,
    authored_at: i64,
) -> Result<Revision<InstanceSettingsContents>, ControlError> {
    contents.validate()?;
    Revision::new(
        contents.section().stable_id()?,
        generation,
        contents,
        actor,
        authored_at,
    )
}

fn validate_domains(domains: &[String]) -> Result<(), ControlError> {
    if domains.len() > 256 || domains.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "allowed_signup_domains",
            "must contain at most 256 strictly sorted, duplicate-free domains",
        ));
    }
    for domain in domains {
        if validate_dns_name(domain).is_err() {
            return Err(invalid(
                "allowed_signup_domains",
                "must contain canonical lowercase DNS names",
            ));
        }
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_control::primitives::ActorKind;

    #[test]
    fn section_identity_is_derived_not_caller_supplied() {
        let revision = new_revision(
            Generation::new(1).unwrap(),
            InstanceSettingsContents::Branding(BrandingSettings {
                product_name: "AOS".into(),
                logo_url: Some("https://assets.example.test/aos.svg".into()),
                support_url: None,
                terms_url: None,
                privacy_url: None,
            }),
            Actor::new(ActorKind::User, Some(1), "admin@example.test").unwrap(),
            1,
        )
        .unwrap();
        assert_eq!(revision.stable_id.as_str(), "instance-settings:branding");
    }

    #[test]
    fn domains_are_canonical_ordered_inputs() {
        let settings = IdentityAndSignupSettings {
            signup_policy: SignupPolicy::Open,
            allowed_signup_domains: vec!["z.example".into(), "a.example".into()],
            session_lifetime_secs: 3600,
            password_authentication: true,
        };
        assert!(settings.validate().is_err());
    }
}
