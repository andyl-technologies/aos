//! Selects and verifies authoritative index generations without directory listing.

use std::collections::{BTreeMap,BTreeSet};
use terrane_core::bucket::{BucketCapabilities,BucketKey,GenerationManifest,GenerationShard,Mutability};
use terrane_core::identity::{Identity,IdentityKind,TERRANE_V1};
use crate::pack::{MergedShard,PackId,PackIndexSnapshot,RecordState};
use crate::store::{Clock,ContentValidator,LocalFs,StoreFailure};
use super::{BucketBinding,FileBucket,files};

pub(super) struct Catalog {
    pub capabilities:BucketCapabilities,
    pub capability_bytes:Vec<u8>,
    pub shards:Vec<MergedShard>,
}

impl<F:LocalFs+BucketBinding,C:Clock+BucketBinding,V:ContentValidator+BucketBinding> FileBucket<F,C,V> {
    pub(super) async fn catalog(&self)->Result<Catalog,StoreFailure> {
        let key=BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let capability_bytes=self.read_optional(&key).await?.ok_or_else(files::layout_corrupt)?;
        let capabilities=BucketCapabilities::decode(&capability_bytes).map_err(|_| files::layout_corrupt())?;
        if capabilities.profile!=self.profile() {return Err(files::layout_corrupt());}
        let mut shards=Vec::new();
        if let Some(generation)=capabilities.generation {
            let key=registered(&format!("objects/index/{generation}/MANIFEST"))?;
            let bytes=self.read_optional(&key).await?.ok_or_else(files::layout_corrupt)?;
            let manifest=GenerationManifest::decode(&bytes).map_err(|_| files::layout_corrupt())?;
            if manifest.generation!=generation {return Err(files::layout_corrupt());}
            for entry in &manifest.shards {
                let shard=u8::try_from(entry.shard).map_err(|_| files::layout_corrupt())?;
                let bytes=self.verified_artifact(generation,entry.shard,"idx",IdentityKind::Index,entry.index_hash,entry.index_size).await?;
                if let Some((hash,size))=entry.filter {
                    self.verified_artifact(generation,entry.shard,"flt",IdentityKind::Filter,hash,size).await?;
                }
                shards.push(MergedShard::decode(&bytes,generation,shard).map_err(|_| files::layout_corrupt())?);
            }
        }
        Ok(Catalog {capabilities,capability_bytes,shards})
    }

    async fn verified_artifact(&self,generation:u64,shard:u64,suffix:&str,kind:IdentityKind,hash:[u8;32],size:u64)->Result<Vec<u8>,StoreFailure> {
        let key=registered(&format!("objects/index/{generation}/{shard}.{suffix}"))?;
        let bytes=self.read_optional(&key).await?.ok_or_else(files::layout_corrupt)?;
        let identity=TERRANE_V1.from_digest(kind,&hash).map_err(|_| files::layout_corrupt())?;
        if bytes.len() as u64!=size {return Err(files::layout_corrupt());}
        TERRANE_V1.verify(&identity,&bytes).map_err(|_| files::layout_corrupt())?;
        Ok(bytes)
    }

    pub(super) async fn immutable(&self,key:&BucketKey,bytes:&[u8])->Result<(),StoreFailure> {
        if key.mutability()!=Mutability::Immutable {return Err(files::malformed());}
        if !self.install(key,bytes,false).await? {
            let current=self.read_optional(key).await?.ok_or_else(files::layout_corrupt)?;
            if current!=bytes {return Err(files::layout_corrupt());}
        }
        Ok(())
    }

    pub(super) async fn publish_pack_catalog(&self,catalog:Catalog,new:PackIndexSnapshot)->Result<(),StoreFailure> {
        let mut generation=catalog.capabilities.generation.unwrap_or(0).checked_add(1).ok_or_else(files::layout_corrupt)?;
        // Shard zero is always installed first. A crashed unpublished attempt
        // reserves its generation without making listing authoritative.
        loop {
            let first=registered(&format!("objects/index/{generation}/0.idx"))?;
            let manifest=registered(&format!("objects/index/{generation}/MANIFEST"))?;
            if self.read_optional(&first).await?.is_none() && self.read_optional(&manifest).await?.is_none() {break;}
            generation=generation.checked_add(1).ok_or_else(files::layout_corrupt)?;
        }

        let mut packs=BTreeMap::new();
        let mut tombstoned=BTreeSet::new();
        let mut prefixes=BTreeSet::from([0]);
        for shard in &catalog.shards {
            prefixes.insert(shard.shard());
            for record in shard.entries() {
                let id=record.pack();
                if record.state()==RecordState::Tombstone {tombstoned.insert(id);continue;}
                if let std::collections::btree_map::Entry::Vacant(slot)=packs.entry(id) {
                    let bytes=self.read_optional(&registered(&id.index_key())?).await?.ok_or_else(files::layout_corrupt)?;
                    let index=PackIndexSnapshot::decode(&bytes,generation).map_err(|_| files::layout_corrupt())?;
                    if index.header().id()!=id {return Err(files::layout_corrupt());}
                    slot.insert(index);
                }
            }
        }
        for entry in new.entries() {prefixes.insert(entry.hash()[0]);}
        packs.insert(new.header().id(),new);
        let packs:Vec<_>=packs.into_values().collect();
        let mut shards=Vec::new();
        for prefix in prefixes {
            let previous=catalog.shards.iter().find(|shard|shard.shard()==prefix);
            shards.push(MergedShard::rebuild(prefix,generation,&packs,&tombstoned,previous,&BTreeSet::new()).map_err(|_| files::layout_corrupt())?);
        }
        self.publish_shards(catalog,generation,&shards).await
    }

    async fn publish_shards(&self,mut catalog:Catalog,generation:u64,shards:&[MergedShard])->Result<(),StoreFailure> {
        let mut entries=Vec::new();
        for shard in shards {
            let bytes=shard.encode();
            let identity=TERRANE_V1.calculate(IdentityKind::Index,&bytes).map_err(|_| files::layout_corrupt())?;
            let hash=identity.terrane_v1_digest().map_err(|_| files::layout_corrupt())?;
            let key=registered(&format!("objects/index/{generation}/{}.idx",shard.shard()))?;
            self.immutable(&key,&bytes).await?;
            // Verify durable bytes before the manifest can promise them.
            self.verified_artifact(generation,u64::from(shard.shard()),"idx",IdentityKind::Index,hash,bytes.len() as u64).await?;
            entries.push(GenerationShard {shard:u64::from(shard.shard()),index_hash:hash,index_size:bytes.len() as u64,filter:None});
        }
        let timestamp=self.inner.clock.now().duration_since(std::time::SystemTime::UNIX_EPOCH).map_err(|_| files::malformed())?.as_secs();
        let manifest=GenerationManifest {generation,shards:entries,written_at:timestamp,cycle:0};
        let bytes=manifest.encode().map_err(|_| files::malformed())?;
        let key=registered(&format!("objects/index/{generation}/MANIFEST"))?;
        self.immutable(&key,&bytes).await?;
        catalog.capabilities.generation=Some(generation);
        let bytes=catalog.capabilities.encode().map_err(|_| files::malformed())?;
        let key=registered("CAPABILITIES")?;
        if !self.replace_conditionally(&key,Some(&catalog.capability_bytes),&bytes).await? {return Err(files::layout_corrupt());}
        Ok(())
    }

    /// Enumerates verified live content identities from the selected generation.
    ///
    /// # Errors
    /// Returns corruption or unavailable I/O if the catalog or a live body cannot
    /// be verified. Directory listing never selects authoritative content.
    pub async fn live_identities(&self,kind:IdentityKind)->Result<Vec<Identity>,StoreFailure> {
        let _guard=self.exclusive().await?;
        let catalog=self.catalog().await?;
        let mut identities=Vec::new();
        for shard in &catalog.shards {
            for record in shard.entries() {
                if record.state()==RecordState::Live && record.entry().kind().identity_kind()==kind {
                    let identity=TERRANE_V1.from_digest(kind,record.entry().hash()).map_err(|_| files::layout_corrupt())?;
                    self.verified_body(&catalog,&identity).await?;
                    identities.push(identity);
                }
            }
        }
        Ok(identities)
    }
}

pub(super) fn registered(key:&str)->Result<BucketKey,StoreFailure> {BucketKey::parse(key).map_err(|_| files::malformed())}
