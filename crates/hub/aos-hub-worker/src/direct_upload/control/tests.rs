//! Authenticated deadline failures at the initial provider-dispatch boundary.

use std::{cell::Cell, rc::Rc};

use super::*;

const DEPLOYMENT: &str = "fixture-deployment";
const ORIGIN: &str = "https://executor.example";

struct NativeReply {
    clock: Rc<Cell<u64>>,
    elapsed: u64,
    wrong_key: bool,
    changed_context: bool,
    calls: Cell<usize>,
}

#[async_trait(?Send)]
impl Transport for NativeReply {
    async fn post(&self, phase: &str, signed: SignedDirectControl) -> Result<SignedDirectControl> {
        assert_eq!(phase, "admission");
        self.calls.set(self.calls.get() + 1);
        let key = StorageWorkKey::new([7; 32])?;
        let request = verify_direct_logical_request(
            &key,
            &signed.signature,
            &signed.body,
            DEPLOYMENT,
            ORIGIN,
            self.clock.get(),
        )?;
        let mut reply = DirectLogicalReplyEnvelope {
            context: request.context,
            reply: DirectUploadLogicalReply {
                admissions: vec![],
                sessions: vec![],
                session_summaries: vec![],
                authorizations: vec![],
                baseline_permissions: vec![],
                errors: vec![],
            },
        };
        if self.changed_context {
            reply.context.request_nonce = "de".repeat(32);
        }
        let signing_key = if self.wrong_key {
            StorageWorkKey::new([8; 32])?
        } else {
            key
        };
        let signed = sign_direct_logical_reply(&signing_key, &reply)?;
        self.clock.set(self.clock.get() + self.elapsed);
        Ok(signed)
    }
}

fn context(now: u64, invocation: &str) -> DirectRequestContext {
    DirectRequestContext {
        deployment_id: DEPLOYMENT.into(),
        executor_public_origin: ORIGIN.into(),
        public_authority: "registry.example".into(),
        foreground: DirectForegroundBudget {
            invocation_id: invocation.repeat(32),
            issued_at: WireInteger::new(now),
            expires_at: WireInteger::new(now + 30),
        },
        request_nonce: "ab".repeat(32),
        request_body_sha256: "cd".repeat(32),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/BeginBatch".into(),
        issued_at: WireInteger::new(now),
        expires_at: WireInteger::new(now + 30),
    }
}

fn admission() -> DirectUploadLogicalRequest {
    let retained = crate::direct_guard::fixture::reservation(
        DEPLOYMENT,
        ".aos-direct-guard-fixture/begin-expiry",
    );
    DirectUploadLogicalRequest::Admission {
        intents: vec![retained.admission.intent],
    }
}

#[tokio::test]
async fn expired_begin_reply_retries_same_intent_with_a_new_invocation_before_effects() {
    let clock = Rc::new(Cell::new(100));
    let transport = NativeReply {
        clock: Rc::clone(&clock),
        elapsed: 30,
        wrong_key: false,
        changed_context: false,
        calls: Cell::new(0),
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let original = admission();
    let expired = exchange(
        &transport,
        &key,
        &context(100, "aa"),
        original.clone(),
        || Ok(clock.get()),
    )
    .await
    .map_err(before_begin);
    let error = expired.err().unwrap();
    assert!(error.is::<BeginReplyExpiredBeforeEffects>());
    assert_eq!(transport.calls.get(), 1);

    // A new public invocation preserves the exact business intent. The expired
    // reply supplies no authority for entering provider work in either attempt.
    let fresh = NativeReply {
        elapsed: 1,
        ..transport
    };
    let accepted = exchange(&fresh, &key, &context(clock.get(), "bb"), original, || {
        Ok(clock.get())
    })
    .await;
    assert!(accepted.is_ok());
    assert_eq!(fresh.calls.get(), 2);
}

#[tokio::test]
async fn expired_reply_without_the_begin_boundary_is_not_marked_retryable() {
    let clock = Rc::new(Cell::new(100));
    let transport = NativeReply {
        clock: Rc::clone(&clock),
        elapsed: 30,
        wrong_key: false,
        changed_context: false,
        calls: Cell::new(0),
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let result = exchange(&transport, &key, &context(100, "aa"), admission(), || {
        Ok(clock.get())
    })
    .await;

    let error = result.err().unwrap();
    assert!(error.is::<DirectLogicalReplyExpired>());
    assert!(!error.is::<BeginReplyExpiredBeforeEffects>());
}

#[tokio::test]
async fn expired_unauthenticated_or_changed_context_reply_never_becomes_retryable() {
    for (wrong_key, changed_context) in [(true, false), (false, true)] {
        let clock = Rc::new(Cell::new(100));
        let transport = NativeReply {
            clock: Rc::clone(&clock),
            elapsed: 30,
            wrong_key,
            changed_context,
            calls: Cell::new(0),
        };
        let key = StorageWorkKey::new([7; 32]).unwrap();
        let result = exchange(&transport, &key, &context(100, "aa"), admission(), || {
            Ok(clock.get())
        })
        .await
        .map_err(before_begin);

        let error = result.err().unwrap();
        assert!(!error.is::<BeginReplyExpiredBeforeEffects>());
        assert_eq!(transport.calls.get(), 1);
    }
}
