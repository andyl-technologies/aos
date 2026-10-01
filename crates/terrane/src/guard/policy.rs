//! Supplies identity-bound disclosure and graft metadata to the pure admission validator.

use std::collections::BTreeSet;

use terrane_core::identity::Digest;
use terrane_core::properties::{CommitContext, Domain, EffectiveProperties, Error};
use terrane_core::tree_format::{Entry, EntryKind, Property};

use crate::domain::DomainRecord;

pub(crate) struct AdmissionContext<'a> {
    pub(crate) records: &'a [DomainRecord],
    pub(crate) staged: &'a BTreeSet<Digest>,
    pub(crate) storage_domain: &'a str,
    pub(crate) grafts: Vec<(Digest, Option<Vec<Property<'a>>>, EffectiveProperties<'a>)>,
    pub(crate) administrator: bool,
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
}
