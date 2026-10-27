//! Authenticates frozen chunk and manifest identities against staged plaintext.

use std::io::{self, Read};

use terrane_format::chunking::ChunkProfile;
use terrane_format::derived::PlaintextHashes;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_format::manifest::Manifest;
use terrane_format::properties::Domain;

/// Supplies the immutable witness for a whole-file publication.
#[derive(Clone, Debug)]
pub enum PublicationRecipe {
    /// Identifies plaintext represented directly by an inline chunk.
    Inline {
        /// The registered chunk descriptor, whose size is plaintext size.
        chunk: Descriptor,
    },
    /// Identifies plaintext through an authenticated canonical manifest.
    Manifest {
        /// The manifest descriptor, whose size is encoded metadata size.
        object: Descriptor,
        /// The original canonical manifest bytes retained outside state.
        canonical_manifest: Vec<u8>,
    },
}

/// Binds a validated identity witness to one disclosure domain.
#[derive(Clone, Debug)]
pub struct PublicationClaim {
    domain: String,
    descriptor: Descriptor,
    manifest: Option<Manifest>,
    canonical_manifest: Option<Vec<u8>>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl PublicationClaim {
    /// Validates an immutable witness under the configured chunk profile.
    ///
    /// # Errors
    /// Rejects invalid domains, descriptors, canonical manifests or inline
    /// representation choices. Unsupported whole-file hashes fail closed.
    pub fn new(
        domain: String,
        recipe: PublicationRecipe,
        profile: &ChunkProfile,
    ) -> io::Result<Self> {
        Domain::parse(&domain).map_err(source)?;

        let (descriptor, manifest, canonical_manifest) = match recipe {
            PublicationRecipe::Inline { chunk } => {
                Descriptor::decode(&TERRANE_V1, &chunk.encode()).map_err(source)?;
                if chunk.domain() != TERRANE_V1.domain(IdentityKind::Chunk).map_err(source)?
                    || chunk.size() > profile.minimum() as u64
                {
                    return Err(invalid("invalid inline publication descriptor"));
                }
                (chunk, None, None)
            }
            PublicationRecipe::Manifest {
                object,
                canonical_manifest,
            } => {
                object
                    .verify_bytes(&TERRANE_V1, IdentityKind::Manifest, &canonical_manifest)
                    .map_err(source)?;
                let manifest = Manifest::decode(&canonical_manifest, profile).map_err(source)?;
                if manifest.size <= profile.minimum() as u64 {
                    return Err(invalid("inline content cannot use a manifest publication"));
                }
                (object, Some(manifest), Some(canonical_manifest))
            }
        };

        Ok(Self {
            domain,
            descriptor,
            manifest,
            canonical_manifest,
        })
    }

    /// Returns the validated disclosure-domain label.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the frozen immutable descriptor used for canonical naming.
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Returns the exact assembled plaintext length.
    pub fn plaintext_size(&self) -> u64 {
        self.manifest
            .as_ref()
            .map_or(self.descriptor.size(), |manifest| manifest.size)
    }

    /// Returns the authenticated reconstruction manifest when one is required.
    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    /// Borrows the original canonical reconstruction metadata.
    pub fn canonical_manifest(&self) -> Option<&[u8]> {
        self.canonical_manifest.as_deref()
    }

    /// Verifies exact plaintext length, ordered chunks and whole-file hashes.
    ///
    /// Memory use is bounded by one chunk. The reader must start at offset zero.
    ///
    /// # Errors
    /// Rejects short, long, reordered or modified plaintext and reader failures.
    pub fn verify_reader(&self, reader: &mut impl Read) -> io::Result<()> {
        let mut whole = blake3::Hasher::new();
        let mut secondary = PlaintextHashes::new(self.plaintext_size());
        if let Some(manifest) = &self.manifest {
            for chunk in &manifest.chunks {
                let size = usize::try_from(chunk.length).map_err(source)?;
                let mut bytes = vec![0; size];
                reader.read_exact(&mut bytes)?;
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Chunk, &bytes)
                    .map_err(source)?;
                if identity.digest() != chunk.digest {
                    return Err(invalid("assembled chunk identity mismatch"));
                }
                whole.update(&bytes);
                secondary.update(&bytes).map_err(source)?;
            }
            let secondary = secondary.finish().map_err(source)?;
            let blake3 = whole.finalize();
            for (name, expected) in &manifest.hashes {
                let actual: &[u8] = match name.as_str() {
                    "blake3" => blake3.as_bytes(),
                    "sha256" => &secondary.sha256,
                    "sha512" => &secondary.sha512,
                    "git-blob-sha1" => &secondary.git_blob_sha1,
                    "git-blob-sha256" => &secondary.git_blob_sha256,
                    _ => return Err(invalid("unregistered whole-file hash")),
                };
                if actual != expected {
                    return Err(invalid("assembled whole-file hash mismatch"));
                }
            }
        } else {
            let size = usize::try_from(self.descriptor.size()).map_err(source)?;
            let mut bytes = vec![0; size];
            reader.read_exact(&mut bytes)?;
            self.descriptor
                .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, &bytes)
                .map_err(source)?;
        }
        let mut extra = [0];
        if reader.read(&mut extra)? != 0 {
            return Err(invalid("assembled plaintext has trailing bytes"));
        }
        Ok(())
    }
}
