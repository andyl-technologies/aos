//! Actual outstanding-read bounds, ordered completion and drop cleanup.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use anyhow::Result;

#[derive(Default)]
struct Observed {
    active: Cell<usize>,
    peak: Cell<usize>,
    dropped: RefCell<Vec<usize>>,
}

#[derive(Default)]
struct Readiness {
    ready: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Readiness {
    fn set(&self, ready: bool) {
        self.ready.set(ready);
        if ready {
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
        }
    }
}

struct Read {
    index: usize,
    ready: Rc<Readiness>,
    fail: bool,
    started: bool,
    observed: Rc<Observed>,
}

impl Future for Read {
    type Output = Result<usize>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;
            let active = self.observed.active.get() + 1;
            self.observed.active.set(active);
            self.observed.peak.set(self.observed.peak.get().max(active));
        }
        if !self.ready.ready.get() {
            self.ready.waker.replace(Some(context.waker().clone()));
            return Poll::Pending;
        }
        Poll::Ready(if self.fail {
            Err(anyhow::anyhow!("actual selected read failed"))
        } else {
            Ok(self.index)
        })
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        if self.started {
            self.observed.active.set(self.observed.active.get() - 1);
            self.observed.dropped.borrow_mut().push(self.index);
        }
    }
}

fn reads(observed: &Rc<Observed>, ready: &[Rc<Readiness>], failed: Option<usize>) -> Vec<Read> {
    ready
        .iter()
        .enumerate()
        .map(|(index, ready)| Read {
            index,
            ready: Rc::clone(ready),
            fail: failed == Some(index),
            started: false,
            observed: Rc::clone(observed),
        })
        .collect()
}

#[test]
fn shard_and_fallback_bounds_preserve_order_and_drop_pending_reads() {
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    for maximum in [1, 2] {
        let observed = Rc::new(Observed::default());
        let ready: Vec<_> = (0..4).map(|_| Rc::new(Readiness::default())).collect();
        let mut batch = Box::pin(super::collect(reads(&observed, &ready, None), maximum));
        assert!(batch.as_mut().poll(&mut context).is_pending());
        assert_eq!(observed.active.get(), maximum);

        // A later completion cannot reorder compact results or start the
        // remaining unbounded group while the first selected source waits.
        if maximum == 2 {
            ready[1].set(true);
            assert!(batch.as_mut().poll(&mut context).is_pending());
            assert!(observed.peak.get() <= maximum);
        }
        for state in &ready {
            state.set(true);
        }
        assert!(matches!(
            batch.as_mut().poll(&mut context),
            Poll::Ready(Ok(ref values)) if values == &[0, 1, 2, 3]
        ));
        assert!(observed.peak.get() <= maximum);
        assert_eq!(observed.active.get(), 0);

        let observed = Rc::new(Observed::default());
        for state in &ready {
            state.set(false);
        }
        let mut cancelled = Box::pin(super::collect(reads(&observed, &ready, None), maximum));
        assert!(cancelled.as_mut().poll(&mut context).is_pending());
        drop(cancelled);
        assert_eq!(observed.active.get(), 0);
        assert_eq!(observed.dropped.borrow().len(), maximum);

        let observed = Rc::new(Observed::default());
        ready[0].set(true);
        let mut failed = Box::pin(super::collect(reads(&observed, &ready, Some(0)), maximum));
        assert!(matches!(
            failed.as_mut().poll(&mut context),
            Poll::Ready(Err(_))
        ));
        assert_eq!(observed.active.get(), 0);
        assert!(observed.peak.get() <= maximum);
    }
}

#[test]
fn projection_inflation_preserves_exact_reply_limit_and_oid_refusal() {
    use aos_registry_surface::object::{self, ObjectKind};

    let maximum = aos_hub_core::storage_work::MAX_GIT_INSPECTION_CONTENT_BYTES;
    let content = vec![b'a'; maximum];
    let oid = object::hash_object(ObjectKind::Blob, &content);
    let loose = object::encode_loose(ObjectKind::Blob, &content).unwrap();
    let (kind, decoded) = super::decode_projection(&loose, oid).unwrap();
    assert_eq!(kind, ObjectKind::Blob);
    assert_eq!(decoded, content);
    let foreign_oid = object::hash_object(ObjectKind::Blob, b"foreign source");
    assert!(super::decode_projection(&loose, foreign_oid).is_err());

    let oversized = vec![b'a'; maximum * 2];
    let oid = object::hash_object(ObjectKind::Blob, &oversized);
    let loose = object::encode_loose(ObjectKind::Blob, &oversized).unwrap();
    assert!(super::decode_projection(&loose, oid).is_err());
}
