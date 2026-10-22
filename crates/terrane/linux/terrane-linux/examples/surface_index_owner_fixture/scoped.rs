//! Checks actual signed root selection around real physical index admission.

use super::{
    Result, config,
    repository_fixture::{MAIN, RepositoryFixture},
};
use std::fs;
use terrane_format::surface::ViewTarget;
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    repository::{Error, RootNodeLimits},
    store::StoreErrorKind,
};

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

    let admitted = owner.prepare_surface_index(selection).await?;
    admitted.check_native_backing()?;
    if admitted.key().root() != root {
        return Err("actual signed root differs from admitted surface key".into());
    }

    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    fixture.commit(b"actual later policy head").await?;
    if !matches!(owner.prepare_surface_index(selection).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("surface index escaped a changed actual policy head".into());
    }
    admitted.check_native_backing()?;
    let first_key = admitted.key();
    drop(admitted);
    if !owner.evict_surface_index(first_key).await? {
        return Err("signed original index absent from actual cache".into());
    }
    // Keep the existing original cache entry used by malformed-cold controls;
    // retire only this independently signed root's actual physical job.
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let latest = owner.prepare_surface_index(selection).await?;
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
    let policy = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy)?;
    if owner.prepare_surface_index(selection).await.is_ok() || fs::read(policy)? != before {
        return Err("foreign signed root changed original physical cache policy".into());
    }
    println!(
        "PASS actual signed root admits canonical index; changed policy denies disclosure and foreign domain causes no physical mutation"
    );
    Ok(())
}
