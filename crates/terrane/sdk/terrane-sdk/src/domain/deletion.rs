//! Orders domain deletion behind complete root authority and durable audit.
//!
//! Audit events are ordinary signed commits in a separate retained repository;
//! this module defines no new on-disk format. Native deletion uses
//! `Repository::delete_domain` to compare complete current
//! authority under retained exclusion before removing domain-owned records.

use terrane_format::auth::Verb;
use terrane_format::identity::Identity;
use terrane_format::properties::Domain;

use super::{DomainAccess, DomainBinding};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Carries domain administration from its verified registered route authority.
///
/// The guard and administrative repository validate the exact domain-to-control
/// ref association and signed routing state before constructing this request.
/// Ordinary admin permission on an unrelated audit ref cannot create it.
#[derive(Clone, Debug)]
pub struct DomainAdminRequest {
    domain: String,
    route_authority: DomainAccess,
    #[cfg(feature = "std")]
    configured_route: super::ConfiguredDomainRoute,
}

impl DomainAdminRequest {
    /// Binds an already-verified registered route decision to its target domain.
    ///
    /// The native factory must have checked the actual administrative backend
    /// against this operator-configured route. The caller then verifies the
    /// exact registered control ref, its
    /// signed event's domain binding, and current route policy before this call.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for an unsupported domain or `Denied` without
    /// an admin decision carrying the exact current authority record for the
    /// target domain's deterministic control ref.
    #[cfg(feature = "std")]
    pub(crate) fn from_route_authority(
        configured: &super::ConfiguredDomainRoute,
        route_authority: DomainAccess,
    ) -> Result<Self, StoreFailure> {
        let domain = configured.target().domain.clone();
        if !matches!(
            Domain::parse(&domain),
            Ok(Domain::Private(_) | Domain::Tenant(_))
        ) {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload { rule_id: "DOM-20" },
            )));
        }
        if route_authority.verb() != Verb::Admin
            || route_authority.reference_record().is_none()
            || route_authority.binding().reference != configured.control_ref()
            || route_authority.binding().domain != configured.audit().domain
        {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "admin",
                pattern: route_authority.binding().reference.clone(),
            }));
        }

        Ok(Self {
            domain,
            route_authority,
            configured_route: configured.clone(),
        })
    }

    /// Returns the canonical domain governed by the verified registration.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the exact configured physical target and audit association.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn configured_route(&self) -> &super::ConfiguredDomainRoute {
        &self.configured_route
    }

    /// Returns the verified administrative route decision and authority record.
    #[must_use]
    pub fn route_authority(&self) -> &DomainAccess {
        &self.route_authority
    }
}

/// Describes one authenticated deletion for the administrative commit trail.
#[derive(Clone, Debug)]
pub struct DomainDeletionEvent {
    /// Canonical private or tenant domain being removed.
    pub domain: String,
    /// Complete authoritative inventory of roots assigned to that domain.
    pub roots: Vec<DomainBinding>,
    /// Authenticated actor holding admin over every affected root.
    pub subject: String,
    /// Authority token identifier used for audit correlation.
    pub token_id: [u8; 16],
}

/// Records deletion using normal guarded commits outside the removed namespace.
///
/// Implementations retain both records through authoritative refs under a forever
/// retention policy and fail closed if that durable signed trail is unavailable.
/// The audit root's ACL must restrict its readers to administrators authorized
/// for the recorded domain; audit commits must not disclose private names into
/// an open repository.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait DomainDeletionAudit {
    /// Checks the exact retained audit ref before routing or reopening a domain.
    ///
    /// Pending and completed deletion both return true. Only a verified,
    /// registered active-state commit permits false. An absent authoritative
    /// head, LIST, malformed events, or unverifiable signatures cannot establish
    /// that a domain is enabled.
    ///
    /// # Errors
    ///
    /// Returns a specified verification or read failure, which disables routing.
    async fn domain_deleted(&self, domain: &str) -> Result<bool, StoreFailure>;

    /// Durably commits the intent before any data can be removed.
    ///
    /// # Errors
    ///
    /// Returns the ordinary authorization, signing, admission, or ref failure.
    async fn record_intent(&self, event: &DomainDeletionEvent) -> Result<Identity, StoreFailure>;

    /// Durably commits completion linked to the retained intent commit.
    ///
    /// # Errors
    ///
    /// Returns a specified commit failure; the intent remains the audit record.
    async fn record_completion(
        &self,
        event: &DomainDeletionEvent,
        intent: &Identity,
    ) -> Result<Identity, StoreFailure>;
}

#[cfg(all(test, feature = "std"))]
mod admin_request_tests {
    //! Checks the request's structural binding after route verification.

    #![allow(
        clippy::unwrap_used,
        reason = "Test fixture failures intentionally panic."
    )]

    use terrane_format::identity::{IdentityKind, TERRANE_V1};
    use terrane_format::refs::{Locality, RefRecord};

    use super::*;
    use crate::domain::{
        ConfiguredDomainRoute, DomainAuditRoute, DomainNamespace, DomainNamespaces,
    };

    fn configured_route(domain: &str) -> ConfiguredDomainRoute {
        let namespaces = DomainNamespaces::with_audit_routes(
            vec![
                DomainNamespace {
                    domain: domain.into(),
                    root: "/target-bucket".into(),
                },
                DomainNamespace {
                    domain: "private:audit".into(),
                    root: "/audit-bucket".into(),
                },
            ],
            vec![DomainAuditRoute {
                target_domain: domain.into(),
                audit_domain: "private:audit".into(),
            }],
        )
        .unwrap();

        namespaces
            .audit_route(Domain::parse(domain).unwrap())
            .unwrap()
            .clone()
    }

    fn access(domain: &str, reference: &str, verb: Verb) -> DomainAccess {
        let root = TERRANE_V1.calculate(IdentityKind::Node, b"root").unwrap();

        DomainAccess::authorized(
            DomainBinding {
                domain: domain.into(),
                reference: reference.into(),
                root,
                path: b"/".to_vec(),
            },
            verb,
            "administrator".into(),
            [1; 16],
        )
        .unwrap()
    }

    fn current_record() -> RefRecord {
        RefRecord {
            commit: TERRANE_V1
                .calculate(IdentityKind::Commit, b"current")
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            seq: 7,
            writer_epoch: 3,
            home: Locality::default(),
            policy: None,
            candidate_id: None,
        }
    }

    #[test]
    fn domain_admin_request_preserves_exact_configured_route_and_current_record() {
        for domain in ["private:alice", "tenant:acme"] {
            let configured = configured_route(domain);
            let record = current_record();
            let authority = access("private:audit", configured.control_ref(), Verb::Admin)
                .with_reference_record(record.clone());

            let request = DomainAdminRequest::from_route_authority(&configured, authority).unwrap();

            assert_eq!(request.domain(), domain);
            assert_eq!(request.configured_route().target(), configured.target());
            assert_eq!(request.configured_route().audit(), configured.audit());
            assert_eq!(
                request.configured_route().control_ref(),
                configured.control_ref()
            );
            assert_eq!(request.route_authority().reference_record(), Some(&record));
            assert_eq!(request.route_authority().verb(), Verb::Admin);
        }
    }

    #[test]
    fn domain_admin_request_rejects_non_deletable_target_domains() {
        for domain in ["public", "group:team"] {
            let configured = configured_route(domain);
            let authority = access("private:audit", configured.control_ref(), Verb::Admin)
                .with_reference_record(current_record());

            let error =
                DomainAdminRequest::from_route_authority(&configured, authority).unwrap_err();

            assert_eq!(
                error.kind(),
                &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DOM-20" })
            );
        }
    }

    #[test]
    fn domain_admin_request_rejects_non_admin_route_decisions() {
        let configured = configured_route("tenant:acme");
        for verb in [Verb::Read, Verb::Fork, Verb::Commit, Verb::Tag] {
            let authority = access("private:audit", configured.control_ref(), verb)
                .with_reference_record(current_record());

            let error =
                DomainAdminRequest::from_route_authority(&configured, authority).unwrap_err();

            assert!(
                matches!(error.kind(), StoreErrorKind::Denied { .. }),
                "{verb:?}"
            );
        }
    }

    #[test]
    fn domain_admin_request_rejects_missing_current_record_or_unrelated_audit_binding() {
        let configured = configured_route("tenant:acme");
        let invalid_authorities = [
            access("private:audit", configured.control_ref(), Verb::Admin),
            access("private:audit", "refs/heads/unrelated", Verb::Admin)
                .with_reference_record(current_record()),
            access("private:other-audit", configured.control_ref(), Verb::Admin)
                .with_reference_record(current_record()),
        ];

        for authority in invalid_authorities {
            let reference = authority.binding().reference.clone();

            let error =
                DomainAdminRequest::from_route_authority(&configured, authority).unwrap_err();

            assert_eq!(
                error.kind(),
                &StoreErrorKind::Denied {
                    verb: "admin",
                    pattern: reference,
                }
            );
        }
    }
}
