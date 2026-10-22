//! Checks actual signed root selection around real physical index admission.

use super::{
    Result, config,
    repository_fixture::{MAIN, RepositoryFixture},
};
use std::{fs, io};
use terrane_format::surface::{View, ViewTarget};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_linux::structural_index::Kind;
use terrane_sdk::{
    repository::{Error, RootNodeLimits},
    store::StoreErrorKind,
};

#[path = "scoped/files.rs"]
mod files;

fn limits() -> RootNodeLimits {
    RootNodeLimits {
        max_entries: 16,
        max_metadata_bytes: 65536,
        max_path_bytes: 4096,
    }
}

pub(super) async fn verify(owner: &NativeMetadataOwner, inputs: &config::Inputs) -> Result<()> {
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture.commit(b"signed surface source").await?;
    let target = ViewTarget::Ref(MAIN.parse()?);
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let root = selection.metadata().root();
    let commit = selection.metadata().commit();

    let admitted = owner.prepare_surface_index(selection).await?;
    admitted.check_native_backing()?;
    if admitted.key().root() != root {
        return Err("actual signed root differs from admitted surface key".into());
    }

    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let mapped = owner.prepare_surface_mapping(selection).await?;
    mapped.check_native_backing()?;
    if mapped.commit() != commit
        || mapped.key() != admitted.key()
        || mapped.index().root_hash() != root
    {
        return Err("mapped index differs from original signed commit and admitted key".into());
    }
    let entry = mapped
        .index()
        .lookup(b"file")
        .ok_or("signed mapped file absent")?;
    if !matches!(entry.kind(), Kind::File { size, .. } if size == b"signed surface source".len() as u64)
    {
        return Err("mapped index lost actual signed file metadata".into());
    }

    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let view = View::parse(MAIN)?;
    let backing = files::admit(owner, &mapped, &fixture, &view, None).await?;
    let file_selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let mapping_selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    fixture.commit(b"actual later policy head").await?;
    if !matches!(owner.prepare_surface_index(selection).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("surface index escaped a changed actual policy head".into());
    }
    if !matches!(owner.prepare_surface_mapping(mapping_selection).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("mapped index escaped a changed actual policy head".into());
    }
    if !matches!(owner.prepare_surface_file_backing(&mapped, file_selection, files::deadline()?).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("surface backing escaped a changed actual policy head".into());
    }
    let selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let policy = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy)?;
    if !matches!(
        owner
            .prepare_surface_file_backing(&mapped, selection, files::deadline()?)
            .await,
        Err(Error::Denied)
    ) || fs::read(&policy)? != before
    {
        return Err("another served commit reached physical surface pin effects".into());
    }
    files::check(&backing)?;
    owner.release_sealed_object_lease(backing.lease()).await?;
    files::check(&backing)?;
    drop(backing);
    admitted.check_native_backing()?;
    let first_key = admitted.key();
    drop(admitted);
    let before = fs::read(&policy)?;
    if !matches!(owner.evict_surface_index(first_key).await,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        || fs::read(&policy)? != before
        || mapped.index().lookup(b"file").is_none()
    {
        return Err("live mapped root failed to retain original cache receipt".into());
    }
    drop(mapped);
    if !owner.evict_surface_index(first_key).await? {
        return Err("signed original index absent from actual cache".into());
    }
    // Keep the existing original cache entry used by malformed-cold controls;
    // retire only this independently signed root's actual physical job.
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let latest = owner.prepare_surface_mapping(selection).await?;
    let latest_key = latest.key();
    drop(latest);
    if !owner.evict_surface_index(latest_key).await? {
        return Err("signed latest index absent from actual cache".into());
    }

    let foreign = RepositoryFixture::new("tenant:foreign-surface").await?;
    foreign.commit(b"signed surface source").await?;
    let selection = foreign
        .repository
        .prepare_root_read(&target, foreign.authority.token(), "sdk", limits())
        .await?;
    let before = fs::read(&policy)?;
    if owner.prepare_surface_mapping(selection).await.is_ok() || fs::read(policy)? != before {
        return Err("foreign signed root changed original physical cache policy".into());
    }
    println!(
        "PASS actual signed root admits canonical index; changed policy denies disclosure and foreign domain causes no physical mutation"
    );
    println!(
        "PASS signed-root mapping retains original sealed cache custody, refuses changed policy before disclosure and blocks warm retirement until drop"
    );
    println!(
        "PASS mapped signed root scopes actual sealed file backing; another commit is denied before pin effects and changed policy denies disclosure"
    );
    Ok(())
}

pub(super) async fn admit_exposure_file(
    owner: &NativeMetadataOwner,
    served: &terrane_linux::host_cache::NativeRootIndex,
    fixture: &RepositoryFixture,
    exposure: &terrane_linux::host_cache::NativeExposureLease,
    expires: u64,
) -> Result<terrane_linux::host_cache::NativeFileBacking> {
    files::admit(
        owner,
        served,
        fixture,
        &View::parse(MAIN)?,
        Some((exposure, expires)),
    )
    .await
}
