//! Test-only D-Bus manager that faults only the post-mutation snapshot.

// zbus generates HashMap-backed method and property dispatch tables for these
// fixture-only interfaces. No production custody state uses those tables.
#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context as _, Result, bail};
use zbus::zvariant::OwnedObjectPath;

const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/aos_2dnetd_2eservice";

type StoreRow = (String, u32, u32, u32, u64, u32, u32, String, u32);

#[derive(Clone, Copy)]
enum FaultMode {
    Denied,
    Malformed,
    Oversized,
}

impl FaultMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "denied" => Ok(Self::Denied),
            "malformed" => Ok(Self::Malformed),
            "oversized" => Ok(Self::Oversized),
            _ => bail!("fake manager mode must be denied, malformed, or oversized"),
        }
    }

    const fn post_fault_count(self) -> u32 {
        match self {
            Self::Denied => 0,
            Self::Malformed => 1,
            Self::Oversized => 1_025,
        }
    }
}

struct FakeManager {
    mode: FaultMode,
    dump_calls: Arc<AtomicU32>,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeManager {
    #[zbus(name = "DumpUnitFileDescriptorStore")]
    fn dump_unit_file_descriptor_store(&self, unit: &str) -> zbus::fdo::Result<Vec<StoreRow>> {
        if unit != "aos-netd.service" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "fixture accepts only aos-netd.service".to_owned(),
            ));
        }
        let call = self.dump_calls.fetch_add(1, Ordering::SeqCst);
        if call < 2 {
            return Ok(Vec::new());
        }

        match self.mode {
            FaultMode::Denied => Err(zbus::fdo::Error::AccessDenied(
                "fixture denies the post-mutation dump".to_owned(),
            )),
            FaultMode::Malformed => Ok(vec![(
                "not-a-canonical-network-store-name".to_owned(),
                0o100444,
                0,
                4,
                101,
                0,
                0,
                "net:[101]".to_owned(),
                0,
            )]),
            FaultMode::Oversized => Ok((1_u64..=1_025)
                .map(|inode| {
                    (
                        format!("aos-network-netns-v1-{inode:064x}"),
                        0o100444,
                        0,
                        4,
                        inode,
                        0,
                        0,
                        format!("net:[{inode}]"),
                        0,
                    )
                })
                .collect()),
        }
    }

    #[zbus(name = "GetUnit")]
    fn get_unit(&self, unit: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if unit != "aos-netd.service" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "fixture accepts only aos-netd.service".to_owned(),
            ));
        }
        OwnedObjectPath::try_from(UNIT_PATH)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }
}

struct FakeService {
    mode: FaultMode,
    dump_calls: Arc<AtomicU32>,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl FakeService {
    #[zbus(property, name = "FileDescriptorStoreMax")]
    fn file_descriptor_store_max(&self) -> u32 {
        2
    }

    #[zbus(property, name = "NFileDescriptorStore")]
    fn n_file_descriptor_store(&self) -> u32 {
        if self.dump_calls.load(Ordering::SeqCst) >= 3 {
            self.mode.post_fault_count()
        } else {
            0
        }
    }
}

/// Serves valid preflight state followed by a denied, malformed, or oversized dump.
pub(crate) fn serve(address: &str, mode: &str, ready_path: &std::path::Path) -> Result<()> {
    let mode = FaultMode::parse(mode)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("build fake-manager runtime")?;
    runtime.block_on(async move {
        let calls = Arc::new(AtomicU32::new(0));
        let connection = zbus::connection::Builder::address(address)?
            .name("org.freedesktop.systemd1")?
            .serve_at(
                "/org/freedesktop/systemd1",
                FakeManager {
                    mode,
                    dump_calls: Arc::clone(&calls),
                },
            )?
            .serve_at(
                UNIT_PATH,
                FakeService {
                    mode,
                    dump_calls: calls,
                },
            )?
            .build()
            .await
            .context("connect and publish fake systemd manager")?;
        std::fs::write(ready_path, b"ready\n").context("publish fake-manager readiness")?;

        std::future::pending::<()>().await;
        drop(connection);
        #[allow(unreachable_code)]
        Ok(())
    })
}
