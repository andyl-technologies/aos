//! Supplies identity-bound disclosure and graft metadata to the pure admission validator.

use std::collections::BTreeSet;

use terrane_format::identity::Digest;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::{
    self, CommitContext, Domain, EffectiveProperties, Error, PropertyName,
};
use terrane_format::tree_format::{Entry, EntryKind, Property};

use crate::domain::DomainRecord;

/// Supplies exact reference-domain and graft evidence to pure candidate validation.
pub(crate) struct AdmissionContext<'a> {
    /// Borrows existing identity-bound domain records.
    pub(crate) records: &'a [DomainRecord],
    /// Borrows identities staged in the configured destination storage domain.
    pub(crate) staged: &'a BTreeSet<Digest>,
    /// Names the physical domain assigned to staged content.
    pub(crate) storage_domain: &'a str,
    /// Retains exact target identities, overrides and resolved occurrence policies.
    pub(crate) grafts: Vec<(Digest, Option<Vec<Property<'a>>>, EffectiveProperties<'a>)>,
    /// Reports the current Admin decision independently established by admission.
    pub(crate) administrator: bool,
    /// Borrows the candidate's exact interpretation used for policy resolution.
    pub(crate) property_selection: &'a Selection,
}

impl CommitContext for AdmissionContext<'_> {
    fn reference_domain(&mut self, identity: Digest) -> Result<Domain<'_>, Error> {
        if self.staged.contains(&identity) {
            return Domain::parse(self.storage_domain);
        }
        let mut matching = self
            .records
            .iter()
            .filter(|record| record.identity().digest() == identity);
        let record = matching.next().ok_or(Error::IncompleteContext)?;
        if matching.any(|other| other.domain() != record.domain()) {
            return Err(Error::IncompleteContext);
        }
        Domain::parse(record.domain())
    }

    fn graft_policy(
        &self,
        entry: &Entry<'_>,
        _parent: &EffectiveProperties<'_>,
    ) -> Result<&EffectiveProperties<'_>, Error> {
        let EntryKind::Tree { root, props } = &entry.kind else {
            return Err(Error::InvalidValue);
        };
        self.grafts
            .iter()
            .find(|(identity, overrides, _)| {
                identity == root
                    && overrides.as_deref().unwrap_or(&[]) == props.as_deref().unwrap_or(&[])
            })
            .map(|(_, _, effective)| effective)
            .ok_or(Error::IncompleteContext)
    }

    fn ancestor_admin(&self, _parent: &EffectiveProperties<'_>) -> bool {
        self.administrator
    }

    fn property_selection(&self) -> Option<&Selection> {
        Some(self.property_selection)
    }
}

impl AdmissionContext<'_> {
    /// Checks raw graft obligations after the owning comparison proves retention.
    ///
    /// The caller must prove the descriptor and effective ACL/domain on both
    /// sides match the authenticated prior view. That existing delegation needs
    /// no new Admin decision. The supplied target belongs to the exact matched
    /// occurrence, including repeated roots at different paths. Other child
    /// policy changes remain independently governed by the canonical plan and
    /// ordinary child-entry validation.
    ///
    /// # Errors
    /// Rejects malformed descriptors, strict attributes, selected override
    /// placement, absent reference metadata or unsafe domain relationships.
    pub(super) fn validate_retained_graft(
        &mut self,
        entry: &Entry<'_>,
        parent: &EffectiveProperties<'_>,
        target: &EffectiveProperties<'_>,
    ) -> Result<(), Error> {
        let EntryKind::Tree { root, props } = &entry.kind else {
            return Err(Error::InvalidValue);
        };
        if entry.attrs.len() > terrane_format::tree_format::MAX_ATTRIBUTES {
            return Err(Error::Limit);
        }
        for property in [PropertyName::Hashes, PropertyName::Classify] {
            // These requirements apply to file content, but their policy rows
            // must exist just as in the ordinary changed-entry validator.
            parent.get(property).ok_or(Error::InvalidValue)?;
        }
        if properties::completeness(&[(entry, parent)], PropertyName::StrictAttrs, &[], &[])?
            .incomplete
            != 0
        {
            return Err(Error::UnknownAttribute);
        }
        if let Some(props) = props {
            match self.property_selection {
                Selection::Legacy => properties::semantics::RecordedContext::new(1, 1, &[])?
                    .validate_graft_overrides(props)?,
                Selection::Active => properties::semantics::RecordedContext::new(3, 3, &[])?
                    .validate_graft_overrides(props)?,
                Selection::Recorded(context) => context.validate_graft_overrides(props)?,
            }
        }
        if !parent
            .domain()?
            .permits_reference(self.reference_domain(*root)?)
        {
            return Err(Error::Domain);
        }
        if !target.domain()?.permits_reference(parent.domain()?) {
            return Err(Error::Domain);
        }
        Ok(())
    }
}
