//! Canonical commit records and their nested provenance and profile fields.
//!
//! The required map keys and optional map keys match the `commit` CDDL map.
//! Unknown fields fail decoding so new wire fields require an explicit version.
//!
//! The required fields have this CBOR diagnostic shape; digest placeholders
//! stand for 32-byte byte strings and nested maps follow the v1 CDDL:
//!
//! ```text
//! {1: tree_digest, 2: [parent_digest, ...], 3: provenance,
//!  4: timestamp, 5: message, 6: profile_pair}
//! ```

use super::entry_receipts::{self, EntryReceipt};
use super::token_shape::validate_token;
use super::{
    Locality, RecordError, read_bool, read_digest, read_key, read_nested_value, read_raw_value,
    write_bool,
};
use crate::cbor::{self, Decoder};
use crate::identity::Digest;
use crate::identity::{IdentityError, IdentityKind, TERRANE_V1};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

const MAX_PARENTS: usize = 256;

/// The principal category asserted by commit provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    /// A human principal.
    Human,
    /// An identified workload.
    Workload,
    /// A service principal.
    Service,
}

impl PrincipalKind {
    fn code(self) -> u64 {
        match self {
            Self::Human => 1,
            Self::Workload => 2,
            Self::Service => 3,
        }
    }

    fn from_code(code: u64) -> Result<Self, RecordError> {
        match code {
            1 => Ok(Self::Human),
            2 => Ok(Self::Workload),
            3 => Ok(Self::Service),
            _ => Err(RecordError::Schema),
        }
    }
}

/// The closed vocabulary for how a commit's tree was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitSource {
    /// Built from inputs.
    Built,
    /// Uploaded by a principal.
    Uploaded,
    /// Imported from another system.
    Imported,
    /// Merged from parent commits.
    Merged,
    /// Materialized from a derivation.
    Derived,
    /// Migrated into this format.
    Migrated,
}

impl CommitSource {
    fn code(self) -> u64 {
        match self {
            Self::Built => 1,
            Self::Uploaded => 2,
            Self::Imported => 3,
            Self::Merged => 4,
            Self::Derived => 5,
            Self::Migrated => 6,
        }
    }

    fn from_code(code: u64) -> Result<Self, RecordError> {
        match code {
            1 => Ok(Self::Built),
            2 => Ok(Self::Uploaded),
            3 => Ok(Self::Imported),
            4 => Ok(Self::Merged),
            5 => Ok(Self::Derived),
            6 => Ok(Self::Migrated),
            _ => Err(RecordError::Schema),
        }
    }
}

/// The claim set bound into a commit and its detached signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    /// Identifier of the token issuer.
    pub issuer: String,
    /// Sixteen-byte token identifier.
    pub token_id: [u8; 16],
    /// Name of the subject principal.
    pub subject: String,
    /// Human, workload, or service principal.
    pub kind: PrincipalKind,
    /// Optional workload identity claim.
    pub workload_identity: Option<String>,
    /// Process descriptor asserted by the committer.
    pub process: String,
    /// Advisory commit time observed by the signer.
    pub observed_at: u64,
    /// Writer fencing epoch at commit.
    pub writer_epoch: u64,
    /// How the tree was produced.
    pub source: CommitSource,
    /// Optional canonical CBOR public token chain.
    pub embedded_token: Option<Vec<u8>>,
}

impl Provenance {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        if let Some(token) = &self.embedded_token {
            validate_token(token)?;
        }
        cbor::write_map(
            output,
            8 + usize::from(self.workload_identity.is_some())
                + usize::from(self.embedded_token.is_some()),
        );
        cbor::write_uint(output, 1);
        cbor::write_text(output, &self.issuer);
        cbor::write_uint(output, 2);
        cbor::write_bytes(output, &self.token_id);
        cbor::write_uint(output, 3);
        cbor::write_text(output, &self.subject);
        cbor::write_uint(output, 4);
        cbor::write_uint(output, self.kind.code());
        if let Some(workload) = &self.workload_identity {
            cbor::write_uint(output, 5);
            cbor::write_text(output, workload);
        }
        cbor::write_uint(output, 6);
        cbor::write_text(output, &self.process);
        cbor::write_uint(output, 7);
        cbor::write_uint(output, self.observed_at);
        cbor::write_uint(output, 8);
        cbor::write_uint(output, self.writer_epoch);
        cbor::write_uint(output, 9);
        cbor::write_uint(output, self.source.code());
        if let Some(token) = &self.embedded_token {
            cbor::write_uint(output, 10);
            output.extend_from_slice(token);
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        let count = decoder.map(10)?;
        if !(8..=10).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        require_key(decoder, &mut previous, 1, 10)?;
        let issuer = decoder.text(decoder.remaining().len())?.to_string();
        require_key(decoder, &mut previous, 2, 10)?;
        let token_id = decoder
            .bytes(16)?
            .try_into()
            .map_err(|_| RecordError::Schema)?;
        require_key(decoder, &mut previous, 3, 10)?;
        let subject = decoder.text(decoder.remaining().len())?.to_string();
        require_key(decoder, &mut previous, 4, 10)?;
        let kind = PrincipalKind::from_code(decoder.uint()?)?;
        let mut next = read_key(decoder, &mut previous, 10)?;
        let workload_identity = if next == 5 {
            let identity = decoder.text(decoder.remaining().len())?.to_string();
            next = read_key(decoder, &mut previous, 10)?;
            Some(identity)
        } else {
            None
        };
        if next != 6 {
            return Err(RecordError::Schema);
        }
        let process = decoder.text(decoder.remaining().len())?.to_string();
        require_key(decoder, &mut previous, 7, 10)?;
        let observed_at = decoder.uint()?;
        require_key(decoder, &mut previous, 8, 10)?;
        let writer_epoch = decoder.uint()?;
        require_key(decoder, &mut previous, 9, 10)?;
        let source = CommitSource::from_code(decoder.uint()?)?;
        let embedded_token = if count == 10 || (count == 9 && workload_identity.is_none()) {
            require_key(decoder, &mut previous, 10, 10)?;
            let token = read_raw_value(decoder)?.to_vec();
            validate_token(&token)?;
            Some(token)
        } else {
            None
        };
        Ok(Self {
            issuer,
            token_id,
            subject,
            kind,
            workload_identity,
            process,
            observed_at,
            writer_epoch,
            source,
            embedded_token,
        })
    }
}

/// A lease snapshot recorded at commit time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    /// Principal or job holding the lease.
    pub owner: String,
    /// Advisory expiry time in Unix seconds.
    pub expiry: u64,
}

/// The format and chunk profile recorded by a commit.
///
/// The store's identity profile is fixed by its `CAPABILITIES` record and is
/// therefore not duplicated in this CDDL map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePair {
    /// Tree-format version; one for the initial format.
    pub tree_format: u64,
    /// Registered chunk profile name.
    pub chunk_profile: String,
    /// Canonical CBOR recipe when a composite was materialized.
    pub recipe: Option<Vec<u8>>,
    /// Whether the tree contains a conflict value.
    pub conflicted: Option<bool>,
    /// Optional job or exposure lease snapshot.
    pub lease: Option<Lease>,
    /// Canonical CBOR required-property snapshot.
    pub required_properties: Option<Vec<u8>>,
    /// Signed root/path receipts resolving entry and attribute introductions.
    pub entry_receipts: Option<Vec<EntryReceipt>>,
}

/// A sealed pack first referenced by a commit and its writing locality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackLocation {
    /// The pack's sixteen-byte random identifier.
    pub pack_id: [u8; 16],
    /// The locality where the pack was sealed.
    pub locality: Locality,
}

/// An immutable signed binding of one tree root to ordered parent commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit {
    /// Exactly one tree root identity.
    pub tree: Digest,
    /// Ordered commit parents, with ours first for a merge or fold.
    pub parents: Vec<Digest>,
    /// Claims of the committing principal and process.
    pub provenance: Provenance,
    /// Advisory Unix seconds asserted by the committer.
    pub timestamp: u64,
    /// UTF-8 message, which may be empty.
    pub message: String,
    /// Format and chunk profile in effect.
    pub profile_pair: ProfilePair,
    /// Packs this commit first referenced and their source localities.
    pub packs: Option<Vec<PackLocation>>,
    /// Detached Ed25519 signature over the map with key 8 absent.
    pub signature: Option<[u8; 64]>,
}

/// A commit could not be encoded or hashed under the v1 identity profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitIdentityError {
    /// The commit is invalid under its canonical schema.
    Record(RecordError),
    /// The configured identity profile rejected the bytes.
    Identity(IdentityError),
}

impl fmt::Display for CommitIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => fmt::Display::fmt(error, formatter),
            Self::Identity(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl core::error::Error for CommitIdentityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            Self::Identity(error) => Some(error),
        }
    }
}

impl Commit {
    /// Computes the v1 commit identity over the signed canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`CommitIdentityError::Record`] for invalid fields or
    /// [`CommitIdentityError::Identity`] if the identity profile fails.
    pub fn identity(&self) -> Result<Digest, CommitIdentityError> {
        let bytes = self.encode().map_err(CommitIdentityError::Record)?;
        TERRANE_V1
            .calculate(IdentityKind::Commit, &bytes)
            .and_then(|identity| identity.terrane_v1_digest())
            .map_err(CommitIdentityError::Identity)
    }

    /// Encodes the canonical CBOR commit, including its signature when set.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Schema`] for an invalid profile, nested map,
    /// empty pack list, or collection above its decoder limit.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut output = Vec::new();
        self.encode_into(&mut output, true)?;
        Ok(output)
    }

    /// Encodes the signature preimage with the signature field absent.
    ///
    /// # Errors
    ///
    /// Returns the same validation failures as [`Self::encode`].
    pub fn signature_preimage(&self) -> Result<Vec<u8>, RecordError> {
        let mut output = Vec::new();
        self.encode_into(&mut output, false)?;
        Ok(output)
    }

    fn encode_into(
        &self,
        output: &mut Vec<u8>,
        include_signature: bool,
    ) -> Result<(), RecordError> {
        if self.parents.len() > MAX_PARENTS
            || self.packs.as_ref().is_some_and(|packs| packs.is_empty())
        {
            return Err(RecordError::Schema);
        }
        let count = 6
            + usize::from(self.packs.is_some())
            + usize::from(include_signature && self.signature.is_some());
        cbor::write_map(output, count);
        cbor::write_uint(output, 1);
        cbor::write_bytes(output, &self.tree);
        cbor::write_uint(output, 2);
        cbor::write_array(output, self.parents.len());
        for parent in &self.parents {
            cbor::write_bytes(output, parent);
        }
        cbor::write_uint(output, 3);
        self.provenance.encode_into(output)?;
        cbor::write_uint(output, 4);
        cbor::write_uint(output, self.timestamp);
        cbor::write_uint(output, 5);
        cbor::write_text(output, &self.message);
        cbor::write_uint(output, 6);
        self.profile_pair.encode_into(output)?;
        if let Some(packs) = &self.packs {
            cbor::write_uint(output, 7);
            cbor::write_array(output, packs.len());
            for pack in packs {
                cbor::write_array(output, 2);
                cbor::write_bytes(output, &pack.pack_id);
                pack.locality.encode_into(output);
            }
        }
        if include_signature && let Some(signature) = &self.signature {
            cbor::write_uint(output, 8);
            cbor::write_bytes(output, signature);
        }
        Ok(())
    }

    /// Decodes one canonical CBOR `commit` map.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical encoding, unknown or mistyped fields, schema
    /// limit violations, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder.map(8)?;
        if !(6..=8).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        require_key(&mut decoder, &mut previous, 1, 8)?;
        let tree = read_digest(&mut decoder)?;
        require_key(&mut decoder, &mut previous, 2, 8)?;
        let parent_count = decoder.array(MAX_PARENTS)?;
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(read_digest(&mut decoder)?);
        }
        require_key(&mut decoder, &mut previous, 3, 8)?;
        let provenance = Provenance::decode_from(&mut decoder)?;
        require_key(&mut decoder, &mut previous, 4, 8)?;
        let timestamp = decoder.uint()?;
        require_key(&mut decoder, &mut previous, 5, 8)?;
        let message = decoder.text(decoder.remaining().len())?.to_string();
        require_key(&mut decoder, &mut previous, 6, 8)?;
        let profile_pair = ProfilePair::decode_from(&mut decoder)?;

        let mut packs = None;
        let mut signature = None;
        for _ in 6..count {
            match read_key(&mut decoder, &mut previous, 8)? {
                7 => {
                    let count = decoder.array(decoder.remaining().len())?;
                    if count == 0 {
                        return Err(RecordError::Schema);
                    }
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        if decoder.array(2)? != 2 {
                            return Err(RecordError::Schema);
                        }
                        let pack_id = decoder
                            .bytes(16)?
                            .try_into()
                            .map_err(|_| RecordError::Schema)?;
                        let locality = Locality::decode_from(&mut decoder)?;
                        values.push(PackLocation { pack_id, locality });
                    }
                    packs = Some(values);
                }
                8 => {
                    signature = Some(
                        decoder
                            .bytes(64)?
                            .try_into()
                            .map_err(|_| RecordError::Schema)?,
                    );
                }
                _ => return Err(RecordError::Schema),
            }
        }
        decoder.finish()?;
        Ok(Self {
            tree,
            parents,
            provenance,
            timestamp,
            message,
            profile_pair,
            packs,
            signature,
        })
    }
}

impl ProfilePair {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.tree_format != 1 || self.chunk_profile.is_empty() {
            return Err(RecordError::Schema);
        }
        if let Some(recipe) = &self.recipe {
            validate_recipe(recipe)?;
        }
        if let Some(properties) = &self.required_properties {
            validate_properties(properties)?;
        }

        let count = 2
            + usize::from(self.recipe.is_some())
            + usize::from(self.conflicted.is_some())
            + usize::from(self.lease.is_some())
            + usize::from(self.required_properties.is_some())
            + usize::from(self.entry_receipts.is_some());
        cbor::write_map(output, count);
        cbor::write_uint(output, 1);
        cbor::write_uint(output, self.tree_format);
        cbor::write_uint(output, 2);
        cbor::write_text(output, &self.chunk_profile);
        if let Some(recipe) = &self.recipe {
            cbor::write_uint(output, 3);
            output.extend_from_slice(recipe);
        }
        if let Some(conflicted) = self.conflicted {
            cbor::write_uint(output, 4);
            write_bool(output, conflicted);
        }
        if let Some(lease) = &self.lease {
            cbor::write_uint(output, 5);
            cbor::write_map(output, 2);
            cbor::write_uint(output, 1);
            cbor::write_text(output, &lease.owner);
            cbor::write_uint(output, 2);
            cbor::write_uint(output, lease.expiry);
        }
        if let Some(properties) = &self.required_properties {
            cbor::write_uint(output, 6);
            output.extend_from_slice(properties);
        }
        if let Some(receipts) = &self.entry_receipts {
            cbor::write_uint(output, 7);
            entry_receipts::encode_into(receipts, output)?;
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        let count = decoder.map(7)?;
        if !(2..=7).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        require_key(decoder, &mut previous, 1, 7)?;
        let tree_format = decoder.uint()?;
        if tree_format != 1 {
            return Err(RecordError::Schema);
        }
        require_key(decoder, &mut previous, 2, 7)?;
        let chunk_profile = decoder.text(decoder.remaining().len())?.to_string();
        if chunk_profile.is_empty() {
            return Err(RecordError::Schema);
        }
        let mut recipe = None;
        let mut conflicted = None;
        let mut lease = None;
        let mut required_properties = None;
        let mut entry_receipts = None;

        for _ in 2..count {
            match read_key(decoder, &mut previous, 7)? {
                3 => {
                    let bytes = read_raw_value(decoder)?.to_vec();
                    validate_recipe(&bytes)?;
                    recipe = Some(bytes);
                }
                4 => conflicted = Some(read_bool(decoder)?),
                5 => {
                    if decoder.map(2)? != 2 || decoder.uint()? != 1 {
                        return Err(RecordError::Schema);
                    }
                    let owner = decoder.text(decoder.remaining().len())?.to_string();
                    if decoder.uint()? != 2 {
                        return Err(RecordError::Schema);
                    }
                    lease = Some(Lease {
                        owner,
                        expiry: decoder.uint()?,
                    });
                }
                6 => {
                    let bytes = read_raw_value(decoder)?.to_vec();
                    validate_properties(&bytes)?;
                    required_properties = Some(bytes);
                }
                7 => entry_receipts = Some(entry_receipts::decode_from(decoder)?),
                _ => return Err(RecordError::Schema),
            }
        }
        Ok(Self {
            tree_format,
            chunk_profile,
            recipe,
            conflicted,
            lease,
            required_properties,
            entry_receipts,
        })
    }
}

fn validate_recipe(bytes: &[u8]) -> Result<(), RecordError> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(3)?;
    if !(2..=3).contains(&count) || decoder.uint()? != 1 {
        return Err(RecordError::Schema);
    }
    let operation = decoder.text(32)?;
    if !matches!(
        operation,
        "graft"
            | "split"
            | "flatten"
            | "overlay"
            | "merge"
            | "filter"
            | "map"
            | "union"
            | "difference"
            | "intersection"
            | "index"
            | "realize"
    ) || decoder.uint()? != 2
    {
        return Err(RecordError::Schema);
    }
    let inputs = decoder.array(decoder.remaining().len())?;
    for _ in 0..inputs {
        read_digest(&mut decoder)?;
    }
    if count == 3 {
        if decoder.uint()? != 3 {
            return Err(RecordError::Schema);
        }
        let arguments = read_raw_value(&mut decoder)?;
        validate_text_map(arguments)?;
    }
    decoder.finish()?;
    Ok(())
}

fn validate_text_map(bytes: &[u8]) -> Result<(), RecordError> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(decoder.remaining().len())?;
    let mut previous = None;
    for _ in 0..count {
        let start = decoder.position();
        decoder.text(decoder.remaining().len())?;
        let key = decoder.slice(start, decoder.position())?;
        if previous.is_some_and(|prior: &[u8]| key <= prior) {
            return Err(RecordError::Schema);
        }
        previous = Some(key);
        read_raw_value(&mut decoder)?;
    }
    decoder.finish()?;
    Ok(())
}

fn validate_properties(bytes: &[u8]) -> Result<(), RecordError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.peek_major()? != 5 {
        return Err(RecordError::Schema);
    }
    read_nested_value(&mut decoder, true)?;
    decoder.finish()?;
    Ok(())
}

fn require_key(
    decoder: &mut Decoder<'_>,
    previous: &mut u64,
    expected: u64,
    max: u64,
) -> Result<(), RecordError> {
    if read_key(decoder, previous, max)? == expected {
        Ok(())
    } else {
        Err(RecordError::Schema)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "invalid golden vectors must fail the test"
)]
mod tests {
    use super::*;

    fn root_commit() -> Commit {
        Commit {
            tree: [1; 32],
            parents: Vec::new(),
            provenance: Provenance {
                issuer: "issuer".into(),
                token_id: [2; 16],
                subject: "principal".into(),
                kind: PrincipalKind::Workload,
                workload_identity: None,
                process: "process".into(),
                observed_at: 1,
                writer_epoch: 1,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 1,
            message: String::new(),
            profile_pair: ProfilePair {
                tree_format: 1,
                chunk_profile: "cdc-1m".into(),
                recipe: None,
                conflicted: None,
                lease: None,
                required_properties: None,
                entry_receipts: None,
            },
            packs: None,
            signature: None,
        }
    }

    #[test]
    fn commit_entry_receipts_extend_profile_without_changing_absent_encoding() {
        use super::super::{EntryOrigin, EntryReceipt};

        let mut commit = root_commit();
        let original = commit.encode().unwrap();
        commit.profile_pair.entry_receipts = Some(alloc::vec![EntryReceipt {
            root: commit.tree,
            path: alloc::vec![0xff],
            origin: EntryOrigin::Current,
            attributes: None,
            reintroduced_from: None,
            disclosure_proof: None,
        }]);

        let extended = commit.encode().unwrap();
        assert_eq!(Commit::decode(&extended).unwrap(), commit);
        assert_ne!(extended, original);
        commit.profile_pair.entry_receipts = None;
        assert_eq!(commit.encode().unwrap(), original);
    }

    #[test]
    fn commit_round_trips_unbounded_message_and_principal() {
        let mut commit = root_commit();
        commit.message = "m".repeat((1 << 20) + 1);
        commit.provenance.subject = "p".repeat(65537);
        commit.packs = Some(alloc::vec![
            PackLocation { pack_id: [3; 16], locality: Locality::default() };
            4097
        ]);

        let encoded = commit.encode().unwrap();

        assert_eq!(Commit::decode(&encoded).unwrap(), commit);
    }

    #[test]
    fn nested_recipe_and_properties_round_trip_without_depth_cap() {
        let mut nested = alloc::vec![0x81; 128];
        cbor::write_text(&mut nested, &"v".repeat((1 << 20) + 1));

        let mut properties = Vec::new();
        cbor::write_map(&mut properties, 1);
        cbor::write_text(&mut properties, "retention");
        properties.extend_from_slice(&nested);

        let mut recipe = Vec::new();
        cbor::write_map(&mut recipe, 3);
        cbor::write_uint(&mut recipe, 1);
        cbor::write_text(&mut recipe, "overlay");
        cbor::write_uint(&mut recipe, 2);
        cbor::write_array(&mut recipe, 257);
        for _ in 0..257 {
            cbor::write_bytes(&mut recipe, &[4; 32]);
        }
        cbor::write_uint(&mut recipe, 3);
        cbor::write_map(&mut recipe, 1);
        cbor::write_text(&mut recipe, "arguments");
        recipe.extend_from_slice(&nested);

        let mut commit = root_commit();
        commit.profile_pair.recipe = Some(recipe);
        commit.profile_pair.required_properties = Some(properties);

        let encoded = commit.encode().unwrap();

        assert_eq!(Commit::decode(&encoded).unwrap(), commit);
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn commit_and_signature_preimage_match_normative_vectors() {
        let unsigned = hex_bytes(concat!(
            "a60158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c",
            "20bbc392028003a8016e6973737565722e6578616d706c650250010203040506",
            "0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c",
            "692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961",
            "6c06a2010102666364632d316d"
        ));
        let signed = hex_bytes(concat!(
            "a70158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c",
            "20bbc392028003a8016e6973737565722e6578616d706c650250010203040506",
            "0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c",
            "692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961",
            "6c06a2010102666364632d316d0858400b1b8d248ff55846868046c342ee3ae5",
            "ca049862cec1c4c8ad9207f6fab19e73a6f5013337b587370634e366d70998ed",
            "715d1105f7ba505f6f519bd967dd710d"
        ));
        let commit = Commit::decode(&signed).unwrap();
        assert_eq!(commit.encode().unwrap(), signed);
        assert_eq!(commit.signature_preimage().unwrap(), unsigned);
        assert!(commit.parents.is_empty());
        assert_eq!(commit.timestamp, 1_760_000_000);
        assert_eq!(commit.profile_pair.tree_format, 1);
        assert_eq!(
            commit.identity().unwrap().to_vec(),
            hex_bytes("c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6")
        );

        let mut excessive_parents = commit;
        excessive_parents.parents = alloc::vec![[0; 32]; MAX_PARENTS + 1];
        assert_eq!(excessive_parents.encode(), Err(RecordError::Schema));
    }
}
