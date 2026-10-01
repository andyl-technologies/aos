//! Indexes authoritative attribute records without reading object plaintext.
//!
//! Index keys retain function versions and producer commits. Quarantine removes
//! corrupt records from serving while preserving their immutable identities for
//! diagnostics and later scrub. Catalog enumeration must follow the backend's
//! selected live pack/index generation; object-store LIST is not such evidence.

use super::{Error, PlaintextObject, compute};
use crate::store::{ContentStore, ContentUpload, MetaUpload, StoreErrorKind};
use std::collections::BTreeMap;
use terrane_core::{
    derived::{AttrRecord, AttributeName, AttributeValue, Function, VerifiedAttributeEvidence},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};

/// Enumerates attribute identities in an authoritative live storage catalog.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait AttributeCatalog {
    /// Returns live Attribute identities from verified pack/index membership.
    ///
    /// Catalog structure and membership are verified independently of record
    /// bodies so a corrupt record can be quarantined without hiding good ones.
    ///
    /// # Errors
    /// Returns a storage failure when authoritative membership cannot be read.
    async fn attribute_identities(&self) -> Result<Vec<Identity>, Error>;
}

/// Durably excludes a corrupt attribute from authoritative catalog generations.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait AttributeQuarantine {
    /// Publishes an exact-identity tombstone while retaining immutable pack bytes.
    ///
    /// Exclusion must survive reopening and ordinary deduplicating uploads must
    /// not restore the excluded identity. Other records in its pack remain live.
    ///
    /// # Errors
    /// Returns a storage failure when durable exclusion cannot be established.
    async fn exclude_attribute(&self, identity: &Identity) -> Result<(), Error>;
}

/// The provenance status used to exclude untrusted derived records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trust {
    /// No verified producing-commit evidence exists, or the function is unsupported.
    Untrusted,
    /// Verified evidence binds the producer commit to this attribute value.
    VerifiedProducer,
}

/// Verified provenance attached to one exact immutable record.
#[derive(Clone, Debug)]
pub struct ProducerEvidence {
    verified: VerifiedAttributeEvidence,
}

impl ProducerEvidence {
    /// Binds a record to its signed producer and canonical tree/attribute witness.
    ///
    /// # Errors
    /// Returns a format, unsupported function, or producer-evidence error when
    /// verified history cannot bind this exact object and attribute value,
    /// including incomplete disclosure or original root-scope validation.
    pub fn from_history(
        record: &AttrRecord,
        history: &terrane_core::provenance::VerifiedHistory,
        location: &terrane_core::provenance::EntryLocation,
    ) -> Result<Self, Error> {
        Ok(Self {
            verified: terrane_core::derived::verify_record_producer(record, history, location)?,
        })
    }

    /// Returns the verified producing commit identity.
    pub const fn producer(&self) -> &Digest {
        self.verified.producer()
    }

    /// Returns the exact record identity bound by this evidence.
    pub fn record(&self) -> &Identity {
        self.verified.record()
    }

    /// Borrows the exact checked record, function, value, and producer witness.
    ///
    /// A repository can bind this proof to its separately verified reading view,
    /// canonical full paths, and effective disclosure domains. Authenticated
    /// producer evidence alone does not authorize the view or reader.
    pub fn as_verified(&self) -> &VerifiedAttributeEvidence {
        &self.verified
    }
}

/// Verifies production evidence under configured commit and trust policy.
///
/// Implementations must validate signed commit/token evidence and bind the
/// object, attribute value, exact function version, and producer to that
/// evidence. A signature on an unrelated commit is insufficient.
pub trait ProducerVerifier {
    /// Returns verified evidence for this exact record, or no trusted evidence.
    ///
    /// # Errors
    /// Returns an error for unavailable, incomplete, contradictory or invalid
    /// production evidence, or a failure of the configured producer policy.
    fn verify(&self, record: &AttrRecord) -> Result<Option<ProducerEvidence>, Error>;
}

/// A quarantined immutable attribute and the reason it is excluded.
#[derive(Clone, Debug)]
pub struct Quarantine {
    /// The excluded record identity.
    pub identity: Identity,
    /// A stable explanation of the verification failure.
    pub reason: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    object: Digest,
    name: AttributeName,
    function: Function,
    producer: Digest,
    record: Vec<u8>,
}

impl Key {
    fn record(record: &AttrRecord, identity: &Identity) -> Self {
        Self {
            object: record.object,
            name: record.value.name(),
            function: record.function.clone(),
            producer: record.producer,
            record: identity.digest().to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
struct Stored {
    identity: Identity,
    record: AttrRecord,
    trust: Trust,
    evidence: Option<ProducerEvidence>,
}

/// A rebuildable per-object side table retaining all versions and producers.
#[derive(Default)]
pub struct SideTable {
    records: BTreeMap<Key, Stored>,
    quarantined: Vec<Quarantine>,
}

impl SideTable {
    /// Creates an empty advisory table without installing a persistence format.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds from verified live catalog membership and immutable meta objects.
    ///
    /// Corrupt records are quarantined individually. Catalog and retrieval
    /// failures remain errors so incomplete catalog reads cannot appear complete.
    ///
    /// # Errors
    /// Returns authoritative catalog, content retrieval, or producer policy failures.
    pub async fn rebuild<S: ContentStore, C: AttributeCatalog, V: ProducerVerifier>(
        store: &S,
        catalog: &C,
        verifier: &V,
    ) -> Result<Self, Error> {
        let mut table = Self::new();
        for identity in catalog.attribute_identities().await? {
            if identity.kind() != IdentityKind::Attribute {
                return Err(Error::InvalidProducer);
            }
            let bytes = match store.get(&identity, None).await {
                Ok(bytes) => bytes,
                Err(error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)) => {
                    table.quarantined.push(Quarantine {
                        identity,
                        reason: error.to_string(),
                    });
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let record = match TERRANE_V1
                .verify(&identity, &bytes)
                .map_err(Error::from)
                .and_then(|()| AttrRecord::decode(&bytes).map_err(Error::from))
            {
                Ok(record) => record,
                Err(error) => {
                    table.quarantined.push(Quarantine {
                        identity,
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            let evidence = if record.function.supported(record.value.name()) {
                verifier.verify(&record)
            } else {
                Ok(None)
            };
            if let Err(error) = evidence
                .and_then(|evidence| table.insert_evidence(identity.clone(), record, evidence))
            {
                // Failed evidence retrieval does not establish a bad immutable
                // record. Durable exclusion needs a conclusive schema, value,
                // signature, or producer contradiction.
                if !matches!(
                    error,
                    Error::InvalidProducer
                        | Error::Derived(
                            terrane_core::derived::Error::Cbor(_)
                                | terrane_core::derived::Error::UnknownAttribute
                                | terrane_core::derived::Error::InvalidValue
                                | terrane_core::derived::Error::InvalidFunction
                                | terrane_core::derived::Error::InlineDisagreement
                                | terrane_core::derived::Error::InvalidProvenance
                        )
                ) {
                    return Err(error);
                }
                table.quarantined.push(Quarantine {
                    identity,
                    reason: error.to_string(),
                });
            }
        }
        Ok(table)
    }

    /// Rebuilds metadata and durably excludes every malformed catalog record.
    ///
    /// # Errors
    /// Returns catalog, content, producer-policy, or durable quarantine failures.
    pub async fn rebuild_durable<
        S: ContentStore,
        C: AttributeCatalog + AttributeQuarantine,
        V: ProducerVerifier,
    >(
        store: &S,
        catalog: &C,
        verifier: &V,
    ) -> Result<Self, Error> {
        let table = Self::rebuild(store, catalog, verifier).await?;
        for quarantined in &table.quarantined {
            catalog.exclude_attribute(&quarantined.identity).await?;
        }
        Ok(table)
    }

    fn insert_evidence(
        &mut self,
        identity: Identity,
        record: AttrRecord,
        evidence: Option<ProducerEvidence>,
    ) -> Result<(), Error> {
        let trust = if let Some(evidence) = &evidence {
            if evidence.record() != &identity || evidence.producer() != &record.producer {
                return Err(Error::InvalidProducer);
            }
            if record.function.supported(record.value.name()) {
                Trust::VerifiedProducer
            } else {
                Trust::Untrusted
            }
        } else {
            Trust::Untrusted
        };
        // Signed and unsigned forms are distinct immutable records, even when
        // their object, function, value, and producer agree.
        let key = Key::record(&record, &identity);
        self.records.insert(
            key,
            Stored {
                identity,
                record,
                trust,
                evidence,
            },
        );
        Ok(())
    }

    /// Stores a canonical record through the configured meta-pack content store.
    ///
    /// The producer is an already finalized commit identity. The resulting
    /// record ID is advisory and must not be embedded back into that commit.
    ///
    /// # Errors
    /// Returns format, storage, identity disagreement, or producer-policy errors.
    pub async fn put<S: ContentStore, V: ProducerVerifier>(
        &mut self,
        store: &S,
        record: AttrRecord,
        verifier: &V,
    ) -> Result<Identity, Error> {
        let bytes = record.encode()?;
        let expected = TERRANE_V1.calculate(IdentityKind::Attribute, &bytes)?;
        if self
            .quarantined
            .iter()
            .any(|record| record.identity == expected)
        {
            return Err(terrane_core::derived::Error::InvalidValue.into());
        }

        // Verify before publication; untrusted provenance is explicitly retained.
        let evidence = if record.function.supported(record.value.name()) {
            verifier.verify(&record)?
        } else {
            None
        };
        if evidence
            .as_ref()
            .is_some_and(|e| e.record() != &expected || e.producer() != &record.producer)
        {
            return Err(Error::InvalidProducer);
        }
        let identity = store
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Attribute,
                &bytes,
            )?))
            .await?;
        if identity != expected {
            return Err(Error::InvalidProducer);
        }
        self.insert_evidence(identity.clone(), record, evidence)?;
        Ok(identity)
    }

    /// Looks up one exact version and producer entirely from metadata.
    ///
    /// A trust-requiring caller cannot receive an unsupported function or an
    /// unverified producing commit. A hit performs no storage or plaintext I/O.
    pub fn lookup(
        &self,
        object: Digest,
        name: AttributeName,
        function: &Function,
        producer: Digest,
        require_trusted: bool,
    ) -> Option<&AttrRecord> {
        let lower = Key {
            object,
            name,
            function: function.clone(),
            producer,
            record: Vec::new(),
        };
        self.records
            .range(lower..)
            .take_while(|(key, _)| {
                key.object == object
                    && key.name == name
                    && &key.function == function
                    && key.producer == producer
            })
            .map(|(_, stored)| stored)
            .find(|stored| !require_trusted || stored.trust == Trust::VerifiedProducer)
            .map(|stored| &stored.record)
    }

    /// Looks up an implemented initial-version record from any eligible producer.
    pub fn current(
        &self,
        object: Digest,
        name: AttributeName,
        require_trusted: bool,
    ) -> Option<&AttrRecord> {
        self.records_for(object, name)
            .find(|stored| {
                stored.record.function.supported(name)
                    && (!require_trusted || stored.trust == Trust::VerifiedProducer)
            })
            .map(|stored| &stored.record)
    }

    fn records_for(&self, object: Digest, name: AttributeName) -> impl Iterator<Item = &Stored> {
        let lower = Key {
            object,
            name,
            function: Function {
                name: String::new(),
                version: String::new(),
            },
            producer: [0; 32],
            record: Vec::new(),
        };

        self.records
            .range(lower..)
            .take_while(move |(key, _)| key.object == object && key.name == name)
            .map(|(_, stored)| stored)
    }

    /// Reports the producer-evidence status of an exact record identity.
    pub fn trust(&self, identity: &Identity) -> Option<Trust> {
        self.records
            .values()
            .find(|stored| &stored.identity == identity)
            .map(|stored| stored.trust)
    }

    /// Borrows the authenticated producer proof for an exact serving record.
    ///
    /// Repositories bind this chosen immutable record to their checked reading
    /// view, paths, and effective domains before evaluating attribute selectors.
    /// Untrusted, unknown-version, and quarantined records expose no proof.
    pub fn producer_evidence(&self, identity: &Identity) -> Option<&VerifiedAttributeEvidence> {
        self.records
            .values()
            .find(|stored| &stored.identity == identity && stored.trust == Trust::VerifiedProducer)
            .and_then(|stored| stored.evidence.as_ref())
            .map(ProducerEvidence::as_verified)
    }

    /// Returns quarantined identities excluded from lookup and serving.
    pub fn quarantined(&self) -> &[Quarantine] {
        &self.quarantined
    }

    /// Recomputes an implemented record and quarantines any mismatching value.
    ///
    /// # Errors
    /// Returns read or producer errors. Unsupported versions remain retained
    /// and untrusted; mismatch removes the exact record before returning failure.
    pub async fn verify<O: PlaintextObject + Sync>(
        &mut self,
        identity: &Identity,
        object: &O,
    ) -> Result<(), Error> {
        let Some((key, record)) = self
            .records
            .iter()
            .find(|(_, stored)| &stored.identity == identity)
            .map(|(key, stored)| (key.clone(), stored.record.clone()))
        else {
            return Err(Error::InvalidProducer);
        };
        if object.digest() != record.object {
            return Err(Error::InvalidProducer);
        }
        if record.value.name() == AttributeName::ZstdDictionary
            || !record.function.supported(record.value.name())
        {
            return Err(terrane_core::derived::Error::UnsupportedFunction.into());
        }
        let result = match compute(object, &[record.value.name()]).await {
            Ok(computed) => computed
                .first()
                .ok_or(Error::InvalidRead)
                .and_then(|value| record.verify_value(value).map_err(Error::from)),
            Err(error @ Error::Derived(_)) => Err(error),
            Err(error) => return Err(error),
        };
        if let Err(error) = result {
            self.records.remove(&key);
            self.quarantined.push(Quarantine {
                identity: identity.clone(),
                reason: error.to_string(),
            });
            return Err(error);
        }
        Ok(())
    }

    /// Recomputes a record and durably quarantines a detected value mismatch.
    ///
    /// Read failures and unsupported versions do not retire immutable records.
    /// On a mismatch, local serving stops before the durable tombstone is written.
    ///
    /// # Errors
    /// Returns recomputation or storage failures. A quarantine-write failure is
    /// reported explicitly; it never establishes successful durable exclusion.
    pub async fn verify_durable<O: PlaintextObject + Sync, Q: AttributeQuarantine>(
        &mut self,
        identity: &Identity,
        object: &O,
        quarantine: &Q,
    ) -> Result<(), Error> {
        let result = self.verify(identity, object).await;
        if result.is_err()
            && self
                .quarantined
                .iter()
                .any(|record| &record.identity == identity)
        {
            quarantine.exclude_attribute(identity).await?;
        }
        result
    }

    /// Checks an inline value against every serving record for the same version.
    ///
    /// # Errors
    /// Returns a typed inline disagreement or malformed value failure.
    pub fn agree_inline(
        &self,
        object: Digest,
        name: AttributeName,
        function: &Function,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let inline = AttributeValue::decode(name, bytes)?;
        for stored in self
            .records_for(object, name)
            .filter(|s| &s.record.function == function)
        {
            if stored.record.value != inline {
                return Err(terrane_core::derived::Error::InlineDisagreement.into());
            }
        }
        Ok(())
    }
}
