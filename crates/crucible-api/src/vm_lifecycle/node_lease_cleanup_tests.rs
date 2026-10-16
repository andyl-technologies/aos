//! Component checks for lease custody across refused physical cleanup.
//!
//! Private descriptor identity proves object retention and close ordering;
//! these checks do not stand in for native Source or child-reap qualification.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    LifecycleApiError, NodeId, ProductionVmNodeGeneration, ProductionVmNodeLease,
    finish_reaped_node_lease_map, loop_factory_error,
};

struct LeaseProbe {
    attempts: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    descriptor: i32,
    device: u64,
    inode: u64,
}

impl LeaseProbe {
    fn retains_descriptor(&self) -> bool {
        std::fs::metadata(format!("/proc/self/fd/{}", self.descriptor))
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
    }
}

struct RetainedLease {
    identity: ProductionVmNodeGeneration,
    failures: usize,
    file: Option<File>,
    attempts: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Drop for RetainedLease {
    fn drop(&mut self) {
        drop(self.file.take());
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl ProductionVmNodeLease for RetainedLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn open_checkpoint_root_overlay(&self) -> Result<File, LifecycleApiError> {
        Err(loop_factory_error(
            "component lease grants no checkpoint authority",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.failures != 0 {
            self.failures -= 1;
            return Err(loop_factory_error("component lease retains its descriptor"));
        }
        Ok(())
    }
}

fn node(name: &str) -> NodeId {
    NodeId { name: name.into() }
}

fn lease(
    node: &NodeId,
    generation: u64,
    failures: usize,
) -> Result<(Box<dyn ProductionVmNodeLease>, LeaseProbe), Box<dyn std::error::Error>> {
    let file = tempfile::tempfile()?;
    let metadata = file.metadata()?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let probe = LeaseProbe {
        attempts: Arc::clone(&attempts),
        drops: Arc::clone(&drops),
        descriptor: file.as_raw_fd(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let lease = RetainedLease {
        identity: ProductionVmNodeGeneration::new(node.clone(), generation)?,
        failures,
        file: Some(file),
        attempts,
        drops,
    };
    Ok((Box::new(lease), probe))
}

#[test]
fn refused_cleanup_retains_the_same_lease_and_still_attempts_its_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let first = node("first");
    let second = node("second");
    let (retained, retained_probe) = lease(&first, 1, 1)?;
    let (peer, peer_probe) = lease(&second, 1, 0)?;
    let mut leases = BTreeMap::from([(first.clone(), retained), (second.clone(), peer)]);
    let generations = BTreeMap::from([(first.clone(), 1), (second.clone(), 1)]);
    let selected = [first.clone(), second.clone()];

    assert!(finish_reaped_node_lease_map(&generations, &mut leases, &selected).is_err());

    assert!(leases.contains_key(&first));
    assert!(!leases.contains_key(&second));
    assert!(retained_probe.retains_descriptor());
    assert_eq!(retained_probe.drops.load(Ordering::SeqCst), 0);
    assert_eq!(retained_probe.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(peer_probe.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(peer_probe.drops.load(Ordering::SeqCst), 1);
    assert!(!peer_probe.retains_descriptor());

    finish_reaped_node_lease_map(&generations, &mut leases, &[first])?;

    assert!(leases.is_empty());
    assert_eq!(retained_probe.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(retained_probe.drops.load(Ordering::SeqCst), 1);
    assert!(!retained_probe.retains_descriptor());
    Ok(())
}

#[test]
fn unauthenticated_generation_never_drops_or_finishes_the_retained_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = node("selected");
    let (retained, probe) = lease(&selected, 7, 0)?;
    let mut leases = BTreeMap::from([(selected.clone(), retained)]);

    for generations in [BTreeMap::new(), BTreeMap::from([(selected.clone(), 8)])] {
        assert!(
            finish_reaped_node_lease_map(
                &generations,
                &mut leases,
                std::slice::from_ref(&selected)
            )
            .is_err()
        );
        assert!(leases.contains_key(&selected));
        assert_eq!(probe.attempts.load(Ordering::SeqCst), 0);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
        assert!(probe.retains_descriptor());
    }

    let generations = BTreeMap::from([(selected.clone(), 7)]);
    finish_reaped_node_lease_map(&generations, &mut leases, &[selected])?;

    assert!(leases.is_empty());
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert!(!probe.retains_descriptor());
    Ok(())
}
