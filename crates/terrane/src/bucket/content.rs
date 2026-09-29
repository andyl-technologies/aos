//! Validates opaque admissions and verifies complete bodies before ranged reads.

use std::collections::{BTreeMap,BTreeSet};
use terrane_core::codec::{Codec,parse_envelope};
use terrane_core::identity::{Identity,IdentityKind,TERRANE_V1};
use crate::pack::{EntryKind,MergedEntry,NativeBodyDecoder,PackClass,PackId,PackIndexSnapshot,PackReader,PackWriter,RecordState};
use crate::store::{ByteRange,ChunkPosition,Clock,ContentStore,ContentUpload,ContentValidator,CorruptSubject,IdentityPrefix,InvalidReason,LocalFs,MetaUpload,StoreErrorKind,StoreFailure};
use super::{BucketBinding,FileBucket,files};
use super::catalog::{Catalog,registered};

fn corrupt(identity:&Identity)->StoreFailure {StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())))}

fn invalid(rule_id:&'static str)->StoreFailure {StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {rule_id}))}

fn invalid_chunk(error: crate::codec::FrameError) -> StoreFailure {
    use crate::codec::FrameError;
    use terrane_core::codec::CodecError;

    let rule_id = match &error {
        FrameError::Envelope(CodecError::DeclaredLengthTooLarge) | FrameError::NonfinalChunkTooShort => "CDC-15",
        FrameError::BoundaryMismatch => "CDC-16",
        FrameError::MissingDictionary | FrameError::WrongDictionary => "CDC-9",
        FrameError::WrongIdentityKind | FrameError::Identity(_) => "CDC-14",
        FrameError::ContentSizeMismatch | FrameError::PlaintextLengthMismatch => "CDC-12",
        _ => "CDC-7",
    };
    StoreFailure::with_source(StoreErrorKind::Invalid(InvalidReason::Upload {rule_id}),error)
}

fn entry_kind(kind:IdentityKind)->Result<EntryKind,StoreFailure> {
    match kind {
        IdentityKind::Chunk=>Ok(EntryKind::Chunk),
        IdentityKind::Manifest=>Ok(EntryKind::Manifest),
        IdentityKind::Node=>Ok(EntryKind::Node),
        IdentityKind::Commit=>Ok(EntryKind::Commit),
        IdentityKind::Bundle=>Ok(EntryKind::Bundle),
        IdentityKind::Filter=>Ok(EntryKind::Filter),
        IdentityKind::Index=>Ok(EntryKind::Index),
        IdentityKind::Attribute=>Ok(EntryKind::Attribute),
        IdentityKind::Policy=>Ok(EntryKind::Policy),
        IdentityKind::Memo=>Ok(EntryKind::Memo),
        IdentityKind::Pack=>Err(invalid("STORE-33")),
    }
}

fn empty_chunk()->Result<Identity,StoreFailure> {TERRANE_V1.calculate(IdentityKind::Chunk,b"").map_err(|_| files::malformed())}

impl<F:LocalFs+BucketBinding,C:Clock+BucketBinding,V:ContentValidator+BucketBinding> FileBucket<F,C,V> {
    fn location<'a>(&self,catalog:&'a Catalog,identity:&Identity)->Result<&'a MergedEntry,StoreFailure> {
        if identity.profile()!=TERRANE_V1.name() {return Err(files::malformed());}
        let hash=identity.terrane_v1_digest().map_err(|_| files::malformed())?;
        let kind=entry_kind(identity.kind())?;
        let location=catalog.shards.iter().find(|shard|shard.shard()==hash[0]).and_then(|shard|shard.entries().binary_search_by_key(&hash,|record|*record.entry().hash()).ok().map(|position|&shard.entries()[position]));
        match location {
            Some(location) if location.state()==RecordState::Live && location.entry().kind()==kind=>Ok(location),
            _=>Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone()))),
        }
    }

    async fn encoded_body(&self,catalog:&Catalog,identity:&Identity)->Result<(Vec<u8>,usize),StoreFailure> {
        let location=self.location(catalog,identity)?;
        let id=location.pack();
        let bytes=self.read_optional(&registered(&id.pack_key())?).await?.ok_or_else(|| corrupt(identity))?;
        let index=self.read_optional(&registered(&id.index_key())?).await?.ok_or_else(|| corrupt(identity))?;
        let reader=PackReader::open(&bytes).map_err(|_| corrupt(identity))?;
        if reader.header().id()!=id {return Err(corrupt(identity));}
        reader.check_index_object(&index).map_err(|_| corrupt(identity))?;
        let entry=reader.entries().iter().find(|entry|entry.hash()==location.entry().hash()).ok_or_else(|| corrupt(identity))?;
        if entry!=location.entry() {return Err(corrupt(identity));}
        let start=usize::try_from(entry.offset()).map_err(|_| corrupt(identity))?;
        let end=start.checked_add(entry.body_len() as usize).ok_or_else(|| corrupt(identity))?;
        let encoded=bytes.get(start..end).ok_or_else(|| corrupt(identity))?.to_vec();
        Ok((encoded,entry.plaintext_len() as usize))
    }

    pub(super) async fn verified_body(&self,catalog:&Catalog,identity:&Identity)->Result<Vec<u8>,StoreFailure> {
        if identity==&empty_chunk()? {return Ok(vec![0]);}
        let (encoded,length)=self.encoded_body(catalog,identity).await?;
        if identity.kind()!=IdentityKind::Chunk {
            let upload=MetaUpload::new(identity.kind(),&encoded).map_err(|_| corrupt(identity))?;
            self.inner.validator.validate_meta(&upload).map_err(|_| corrupt(identity))?;
            if length!=encoded.len() {return Err(corrupt(identity));}
            TERRANE_V1.verify(identity,&encoded).map_err(|_| corrupt(identity))?;
            return Ok(encoded);
        }

        // Resolve dictionary chains iteratively so hostile envelopes cannot
        // consume the call stack. Each dictionary has its own verified identity.
        let mut seen=BTreeSet::new();
        let mut chain=Vec::new();
        let mut current=identity.clone();
        let mut body=encoded.clone();
        let mut plaintext_len=length;
        loop {
            let hash=current.terrane_v1_digest().map_err(|_| corrupt(identity))?;
            if !seen.insert(hash) {return Err(corrupt(identity));}
            let envelope=parse_envelope(&body).map_err(|_| corrupt(identity))?;
            let dictionary=match envelope.codec {Codec::ZstdDictionary(hash)=>Some(hash),_=>None};
            chain.push((current,body,plaintext_len));
            let Some(hash)=dictionary else {break;};
            current=TERRANE_V1.from_digest(IdentityKind::Chunk,&hash).map_err(|_| corrupt(identity))?;
            if current==empty_chunk()? {body=vec![0];plaintext_len=0;} else {
                (body,plaintext_len)=self.encoded_body(catalog,&current).await.map_err(|_| corrupt(identity))?;
            }
        }
        let mut dictionary=None;
        for (current,body,plaintext_len) in chain.into_iter().rev() {
            let verified=crate::codec::decode_verified(&body,plaintext_len,&self.inner.config.chunk_profile,true,&current,dictionary.as_deref()).map_err(|_| corrupt(identity))?;
            dictionary=Some(verified.plaintext().to_vec());
        }
        Ok(encoded)
    }

    async fn dictionary_plaintext(&self,catalog:&Catalog,hash:&[u8;32])->Result<Vec<u8>,StoreFailure> {
        let identity=TERRANE_V1.from_digest(IdentityKind::Chunk,hash).map_err(|_| invalid("CDC-9"))?;
        let encoded=self.verified_body(catalog,&identity).await.map_err(|_| invalid("CDC-9"))?;
        // Dictionary chunks may themselves name a dictionary. The chain has
        // already been verified above; decode its authoritative encoded body
        // using the same iterative resolver for plaintext assembly.
        let mut chain=Vec::new();
        let mut current=identity;
        let mut body=encoded;
        loop {
            let length=if current==empty_chunk()? {0} else {self.location(catalog,&current)?.entry().plaintext_len() as usize};
            let next=match parse_envelope(&body).map_err(|_| invalid("CDC-9"))?.codec {Codec::ZstdDictionary(hash)=>Some(hash),_=>None};
            chain.push((current,body,length));
            let Some(next)=next else {break;};
            current=TERRANE_V1.from_digest(IdentityKind::Chunk,&next).map_err(|_| invalid("CDC-9"))?;
            body=self.verified_body(catalog,&current).await.map_err(|_| invalid("CDC-9"))?;
        }
        let mut dictionary=None;
        for (identity,body,length) in chain.into_iter().rev() {
            let decoded=crate::codec::decode_verified(&body,length,&self.inner.config.chunk_profile,true,&identity,dictionary.as_deref()).map_err(|_| invalid("CDC-9"))?;
            dictionary=Some(decoded.plaintext().to_vec());
        }
        dictionary.ok_or_else(|| invalid("CDC-9"))
    }
}

#[cfg_attr(feature="send",async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F:LocalFs+BucketBinding,C:Clock+BucketBinding,V:ContentValidator+BucketBinding> ContentStore for FileBucket<F,C,V> {
    async fn put(&self,upload:ContentUpload<'_>)->Result<Identity,StoreFailure> {
        let _guard=self.exclusive().await?;
        let catalog=self.catalog().await?;
        let mut dictionaries=BTreeMap::new();
        let identity=match upload {
            ContentUpload::Chunk(chunk)=>{
                if chunk.profile!=&self.inner.config.chunk_profile {return Err(invalid("CDC-3"));}
                let envelope=parse_envelope(chunk.encoded).map_err(|_| invalid("CDC-7"))?;
                if let Codec::ZstdDictionary(hash)=envelope.codec {
                    dictionaries.insert(hash,self.dictionary_plaintext(&catalog,&hash).await?);
                }
                let dictionary=match envelope.codec {Codec::ZstdDictionary(hash)=>dictionaries.get(&hash).map(Vec::as_slice),_=>None};
                crate::codec::decode_verified(chunk.encoded,chunk.declared_plaintext_len,chunk.profile,chunk.position==ChunkPosition::Final,chunk.identity,dictionary).map_err(invalid_chunk)?;
                chunk.identity.clone()
            }
            ContentUpload::Meta(meta)=>{
                self.inner.validator.validate_meta(&meta)?;
                TERRANE_V1.calculate(meta.kind(),meta.bytes()).map_err(|_| invalid("STORE-33"))?
            }
        };

        // Admission context is checked even on a dedup hit. Final admission
        // never supplies evidence for a later nonfinal offer of the same bytes.
        if identity==empty_chunk()? || self.location(&catalog,&identity).is_ok() {return Ok(identity);}
        let id=PackId::generate(&self.inner.fs).await.map_err(files::io_failure)?;
        let writer=match upload {
            ContentUpload::Chunk(chunk)=>{
                let mut writer=PackWriter::new(id,PackClass::Data,false);
                let hash=identity.terrane_v1_digest().map_err(|_| invalid("CDC-14"))?;
                let length=u32::try_from(chunk.declared_plaintext_len).map_err(|_| invalid("CDC-12"))?;
                let decoder=NativeBodyDecoder::new(chunk.profile,&dictionaries);
                writer.append_chunk(hash,chunk.encoded,length,0,&decoder).map_err(|_| invalid("STORE-33"))?;
                writer
            }
            ContentUpload::Meta(meta)=>{
                let mut writer=PackWriter::new(id,PackClass::Meta,false);
                writer.append_raw(entry_kind(meta.kind())?,meta.bytes()).map_err(|_| invalid("STORE-33"))?;
                writer
            }
        };
        let sealed=writer.seal().map_err(|_| invalid("STORE-33"))?;
        self.immutable(&registered(&id.pack_key())?,sealed.bytes()).await?;
        self.immutable(&registered(&id.index_key())?,sealed.index_object()).await?;
        let generation=catalog.capabilities.generation.unwrap_or(0).checked_add(1).ok_or_else(files::layout_corrupt)?;
        let index=PackIndexSnapshot::decode(sealed.index_object(),generation).map_err(|_| files::layout_corrupt())?;
        self.publish_pack_catalog(catalog,index).await?;
        Ok(identity)
    }

    async fn get(&self,identity:&Identity,range:Option<ByteRange>)->Result<Vec<u8>,StoreFailure> {
        let _guard=self.exclusive().await?;
        let catalog=self.catalog().await?;
        let bytes=self.verified_body(&catalog,identity).await?;
        let Some(range)=range else {return Ok(bytes);};
        let end=range.start.checked_add(range.length).ok_or_else(|| StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range))))?;
        if end>bytes.len() as u64 {return Err(StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range))));}
        let start=usize::try_from(range.start).map_err(|_| files::malformed())?;
        let end=usize::try_from(end).map_err(|_| files::malformed())?;
        Ok(bytes[start..end].to_vec())
    }

    async fn has(&self,identities:&[Identity])->Result<Vec<bool>,StoreFailure> {
        let _guard=self.exclusive().await?;
        let catalog=self.catalog().await?;
        let mut results=Vec::with_capacity(identities.len());
        for identity in identities {
            match self.verified_body(&catalog,identity).await {
                Ok(_)=>results.push(true),
                Err(error) if matches!(error.kind(),StoreErrorKind::Absent(_))=>results.push(false),
                Err(error)=>return Err(error),
            }
        }
        Ok(results)
    }

    async fn list(&self,prefix:&IdentityPrefix)->Result<Vec<Identity>,StoreFailure> {
        let identities=self.live_identities(prefix.kind).await?;
        Ok(identities.into_iter().filter(|identity|identity.digest().starts_with(&prefix.digest_prefix)).collect())
    }
}
